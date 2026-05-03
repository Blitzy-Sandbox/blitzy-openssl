//! LMS (Leighton-Micali Signature) verification per SP 800-208 and RFC 8554.
//!
//! This module provides **verification-only** support for the Leighton-Micali
//! hash-based signature scheme standardised by NIST SP 800-208 and specified in
//! RFC 8554. LMS is a stateful hash-based signature scheme that provides strong
//! post-quantum security guarantees based solely on the collision resistance of
//! a cryptographic hash function (SHA-256 or SHAKE-256).
//!
//! # Scope: Verification Only
//!
//! OpenSSL's upstream C implementation at `crypto/lms/` contains **no signing or
//! key-generation code** — only verification functions. This Rust translation
//! preserves that scope exactly:
//!
//! - [`LmsPubKey`] decodes the public-key wire format.
//! - [`lms_verify`] verifies a signature against a public key and message.
//!
//! No signing, key generation, private-key storage, or state-tracking logic is
//! provided. Consumers that require LMS signing should use a dedicated stateful
//! signer toolchain (outside the scope of a cryptographic library that cannot
//! track global state between invocations).
//!
//! # Algorithm Overview
//!
//! LMS is built on top of a Winternitz one-time signature primitive (LM-OTS).
//! The LMS public key is the root of a Merkle tree whose leaves are LM-OTS
//! public keys. A signature identifies a leaf by its index `q`, provides an
//! LM-OTS signature over the message, and includes the Merkle-tree
//! authentication path from the leaf to the root.
//!
//! Verification proceeds in two stages:
//!
//! 1. **LM-OTS verification** (`lm_ots_compute_pubkey`) — Using the message,
//!    randomiser `C`, and chain elements `y[0..p]`, reconstruct the candidate
//!    LM-OTS public key `Kc = H(I || q || D_PBLC || y_0 || ... || y_{p-1})`.
//!    This implements RFC 8554 §4.5 Algorithm 4b.
//!
//! 2. **Merkle path recomputation** (`lms_sig_compute_tc_from_path`) — Starting
//!    from the leaf hash `Tc = H(I || (q + 2^h) || D_LEAF || Kc)`, iteratively
//!    hash the authentication path up to the root using the parity of the
//!    current node index to decide left vs. right sibling order. This
//!    implements RFC 8554 §5.4.2 Algorithm 6a.
//!
//! The signature is accepted iff the recomputed root equals the trusted root
//! stored in the public key.
//!
//! # Parameter Sets
//!
//! RFC 8554 defines 5 LMS parameter sets (h ∈ {5, 10, 15, 20, 25}) with
//! SHA-256 / N=32 output. SP 800-208 adds 15 additional parameter sets
//! combining SHA-256 / N=24, SHAKE / N=32, and SHAKE / N=24, yielding 20 total.
//! Similarly, 16 LM-OTS parameter sets are defined across the same digest /
//! truncation matrix.
//!
//! # Security Guarantees
//!
//! - All byte comparisons that may depend on secret-derived material use
//!   constant-time comparison via [`subtle::ConstantTimeEq`] (Rule R8).
//! - Arithmetic that could overflow uses checked operations; overflow results
//!   in [`CryptoError::Common`] with [`CommonError::ArithmeticOverflow`]
//!   (Rule R6).
//! - No `unsafe` blocks are used anywhere in this file (Rule R8).
//! - Structurally invalid signatures (wrong length, unknown algorithm tag,
//!   truncated wire format) return `Ok(false)` at the public API, not an
//!   error; errors are reserved for internal invariant violations.
//!
//! # Source
//!
//! This file is a faithful Rust translation of OpenSSL's C implementation under
//! `crypto/lms/` (8 source files, ~836 lines) and the public headers
//! `include/crypto/lms.h`, `include/crypto/lms_sig.h`, and
//! `include/crypto/lms_util.h`. The verification algorithms preserve bit-for-bit
//! compatibility with the C implementation.
//!
//! # References
//!
//! - **NIST SP 800-208** — Recommendation for Stateful Hash-Based Signature Schemes
//!   (October 2020).
//! - **RFC 8554** — Leighton-Micali Hash-Based Signatures (April 2019).
//! - **OpenSSL** `crypto/lms/` — Reference C implementation.

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
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::doc_markdown)]

use crate::context::LibContext;
use crate::hash::sha::{Digest, Sha256Context, ShakeContext};
use openssl_common::{CommonError, CryptoError, CryptoResult};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// ===========================================================================
// Domain separator constants (RFC 8554 §3.3 / §5.3)
// ===========================================================================

/// Domain separator for LM-OTS public-key computation.
///
/// Used in `H(I || q || D_PBLC || y_0 || ... || y_{p-1})` — final hash that
/// produces the candidate LM-OTS public key `Kc` during verification.
/// See RFC 8554 §4.3. Encoded as `0x80, 0x80` on the wire (the C source
/// declares this as `D_PBLC = 0x8080` in `crypto/lms/lms_verify.c`).
pub const D_PBLC: [u8; 2] = [0x80, 0x80];

/// Domain separator for LM-OTS message / chain-input hashing.
///
/// Used in `Q = H(I || q || D_MESG || C || message)` — the randomised message
/// hash that is split into Winternitz coefficients. See RFC 8554 §4.3.
/// Encoded as `0x81, 0x81` on the wire.
pub const D_MESG: [u8; 2] = [0x81, 0x81];

/// Domain separator for LMS Merkle-tree leaf hashing.
///
/// Used in `Tc = H(I || (r + 2^h) || D_LEAF || Kc)` — the leaf hash at tree
/// position `r`. See RFC 8554 §5.3. Encoded as `0x82, 0x82` on the wire.
pub const D_LEAF: [u8; 2] = [0x82, 0x82];

/// Domain separator for LMS Merkle-tree interior-node hashing.
///
/// Used in `T[r] = H(I || r || D_INTR || T[2r] || T[2r+1])` when combining two
/// sibling hashes into their parent. See RFC 8554 §5.3. Encoded as
/// `0x83, 0x83` on the wire.
pub const D_INTR: [u8; 2] = [0x83, 0x83];

// ===========================================================================
// Wire-format sizing constants (RFC 8554 §4.3 / §5.3 / SP 800-208)
// ===========================================================================

/// Size in bytes of the serialised leaf index `q` in an LMS signature.
///
/// `q` is encoded as a 32-bit big-endian unsigned integer. See RFC 8554 §4.3.
const LMS_SIZE_Q: usize = 4;

/// Size in bytes of the LMS tree identifier `I`.
///
/// `I` is a 16-byte tag that personalises each LMS tree, preventing multi-target
/// collision attacks. See RFC 8554 §5.2.
const LMS_SIZE_I: usize = 16;

/// Size in bytes of the serialised LMS algorithm-type tag.
///
/// Encoded as a 32-bit big-endian unsigned integer (`lms_algorithm_type` in
/// RFC 8554 §5.2, `lms_type` in SP 800-208).
const LMS_SIZE_LMS_TYPE: usize = 4;

/// Size in bytes of the serialised LM-OTS algorithm-type tag.
///
/// Encoded as a 32-bit big-endian unsigned integer (`lmots_algorithm_type` in
/// RFC 8554 §4.2).
const LMS_SIZE_OTS_TYPE: usize = 4;

/// Size in bytes of the LM-OTS Winternitz checksum.
///
/// Two bytes encode a 16-bit checksum that is appended to the message digest
/// before splitting into Winternitz coefficients. See RFC 8554 §4.4.
#[allow(dead_code)]
const LMS_SIZE_CHECKSUM: usize = 2;

/// Maximum LMS/LM-OTS digest size across all supported parameter sets (N = 32).
///
/// Used to size fixed-capacity scratch buffers. All parameter sets use either
/// `N = 32` (SHA-256 full / SHAKE-256 full) or `N = 24` (SHA-256/192 truncated /
/// SHAKE-256/192 truncated).
const LMS_MAX_DIGEST_SIZE: usize = 32;

// ===========================================================================
// LMS algorithm-type enum (SP 800-208 Table 1 / RFC 8554 §5.1)
// ===========================================================================

/// LMS algorithm type identifier.
///
/// Each variant identifies one combination of:
/// - Hash function (SHA-256 or SHAKE-256).
/// - Digest output size `n` (24 bytes or 32 bytes).
/// - Tree height `h` (5, 10, 15, 20, or 25).
///
/// The discriminant matches the 32-bit big-endian wire encoding. See
/// SP 800-208 Table 1 and RFC 8554 §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum LmsType {
    /// SHA-256 / N=32, tree height h=5 (RFC 8554).
    Sha256N32H5 = 0x0000_0005,
    /// SHA-256 / N=32, tree height h=10 (RFC 8554).
    Sha256N32H10 = 0x0000_0006,
    /// SHA-256 / N=32, tree height h=15 (RFC 8554).
    Sha256N32H15 = 0x0000_0007,
    /// SHA-256 / N=32, tree height h=20 (RFC 8554).
    Sha256N32H20 = 0x0000_0008,
    /// SHA-256 / N=32, tree height h=25 (RFC 8554).
    Sha256N32H25 = 0x0000_0009,
    /// SHA-256/192 (truncated) / N=24, tree height h=5 (SP 800-208).
    Sha256N24H5 = 0x0000_000A,
    /// SHA-256/192 (truncated) / N=24, tree height h=10 (SP 800-208).
    Sha256N24H10 = 0x0000_000B,
    /// SHA-256/192 (truncated) / N=24, tree height h=15 (SP 800-208).
    Sha256N24H15 = 0x0000_000C,
    /// SHA-256/192 (truncated) / N=24, tree height h=20 (SP 800-208).
    Sha256N24H20 = 0x0000_000D,
    /// SHA-256/192 (truncated) / N=24, tree height h=25 (SP 800-208).
    Sha256N24H25 = 0x0000_000E,
    /// SHAKE-256 / N=32, tree height h=5 (SP 800-208).
    ShakeN32H5 = 0x0000_000F,
    /// SHAKE-256 / N=32, tree height h=10 (SP 800-208).
    ShakeN32H10 = 0x0000_0010,
    /// SHAKE-256 / N=32, tree height h=15 (SP 800-208).
    ShakeN32H15 = 0x0000_0011,
    /// SHAKE-256 / N=32, tree height h=20 (SP 800-208).
    ShakeN32H20 = 0x0000_0012,
    /// SHAKE-256 / N=32, tree height h=25 (SP 800-208).
    ShakeN32H25 = 0x0000_0013,
    /// SHAKE-256/192 (truncated) / N=24, tree height h=5 (SP 800-208).
    ShakeN24H5 = 0x0000_0014,
    /// SHAKE-256/192 (truncated) / N=24, tree height h=10 (SP 800-208).
    ShakeN24H10 = 0x0000_0015,
    /// SHAKE-256/192 (truncated) / N=24, tree height h=15 (SP 800-208).
    ShakeN24H15 = 0x0000_0016,
    /// SHAKE-256/192 (truncated) / N=24, tree height h=20 (SP 800-208).
    ShakeN24H20 = 0x0000_0017,
    /// SHAKE-256/192 (truncated) / N=24, tree height h=25 (SP 800-208).
    ShakeN24H25 = 0x0000_0018,
}

impl LmsType {
    /// Decode an LMS algorithm-type tag from its wire u32 value.
    ///
    /// Returns `None` if the value does not match any recognised LMS parameter
    /// set. Callers that receive `None` should propagate a structural
    /// verification failure (`Ok(false)`) rather than raising an error.
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x0000_0005 => Some(Self::Sha256N32H5),
            0x0000_0006 => Some(Self::Sha256N32H10),
            0x0000_0007 => Some(Self::Sha256N32H15),
            0x0000_0008 => Some(Self::Sha256N32H20),
            0x0000_0009 => Some(Self::Sha256N32H25),
            0x0000_000A => Some(Self::Sha256N24H5),
            0x0000_000B => Some(Self::Sha256N24H10),
            0x0000_000C => Some(Self::Sha256N24H15),
            0x0000_000D => Some(Self::Sha256N24H20),
            0x0000_000E => Some(Self::Sha256N24H25),
            0x0000_000F => Some(Self::ShakeN32H5),
            0x0000_0010 => Some(Self::ShakeN32H10),
            0x0000_0011 => Some(Self::ShakeN32H15),
            0x0000_0012 => Some(Self::ShakeN32H20),
            0x0000_0013 => Some(Self::ShakeN32H25),
            0x0000_0014 => Some(Self::ShakeN24H5),
            0x0000_0015 => Some(Self::ShakeN24H10),
            0x0000_0016 => Some(Self::ShakeN24H15),
            0x0000_0017 => Some(Self::ShakeN24H20),
            0x0000_0018 => Some(Self::ShakeN24H25),
            _ => None,
        }
    }

    /// Return this algorithm's parameter set.
    #[must_use]
    pub fn params(self) -> &'static LmsParams {
        // The static table is indexed by enum discriminant minus 5 (0x05..=0x18
        // maps to array positions 0..=19).
        let idx = (self as u32).wrapping_sub(0x0000_0005) as usize;
        &LMS_PARAMS_TABLE[idx]
    }
}

// ===========================================================================
// LM-OTS algorithm-type enum (SP 800-208 Table 2 / RFC 8554 §4.1)
// ===========================================================================

/// LM-OTS algorithm type identifier.
///
/// Each variant identifies one combination of:
/// - Hash function (SHA-256 or SHAKE-256).
/// - Digest output size `n` (24 bytes or 32 bytes).
/// - Winternitz parameter `w` (1, 2, 4, or 8).
///
/// The discriminant matches the 32-bit big-endian wire encoding. See
/// SP 800-208 Table 2 and RFC 8554 §4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum LmOtsType {
    /// SHA-256 / N=32, w=1 (p=265, RFC 8554).
    Sha256N32W1 = 0x0000_0001,
    /// SHA-256 / N=32, w=2 (p=133, RFC 8554).
    Sha256N32W2 = 0x0000_0002,
    /// SHA-256 / N=32, w=4 (p=67, RFC 8554).
    Sha256N32W4 = 0x0000_0003,
    /// SHA-256 / N=32, w=8 (p=34, RFC 8554).
    Sha256N32W8 = 0x0000_0004,
    /// SHA-256/192 / N=24, w=1 (SP 800-208).
    Sha256N24W1 = 0x0000_0005,
    /// SHA-256/192 / N=24, w=2 (SP 800-208).
    Sha256N24W2 = 0x0000_0006,
    /// SHA-256/192 / N=24, w=4 (SP 800-208).
    Sha256N24W4 = 0x0000_0007,
    /// SHA-256/192 / N=24, w=8 (SP 800-208).
    Sha256N24W8 = 0x0000_0008,
    /// SHAKE-256 / N=32, w=1 (SP 800-208).
    ShakeN32W1 = 0x0000_0009,
    /// SHAKE-256 / N=32, w=2 (SP 800-208).
    ShakeN32W2 = 0x0000_000A,
    /// SHAKE-256 / N=32, w=4 (SP 800-208).
    ShakeN32W4 = 0x0000_000B,
    /// SHAKE-256 / N=32, w=8 (SP 800-208).
    ShakeN32W8 = 0x0000_000C,
    /// SHAKE-256/192 / N=24, w=1 (SP 800-208).
    ShakeN24W1 = 0x0000_000D,
    /// SHAKE-256/192 / N=24, w=2 (SP 800-208).
    ShakeN24W2 = 0x0000_000E,
    /// SHAKE-256/192 / N=24, w=4 (SP 800-208).
    ShakeN24W4 = 0x0000_000F,
    /// SHAKE-256/192 / N=24, w=8 (SP 800-208).
    ShakeN24W8 = 0x0000_0010,
}

impl LmOtsType {
    /// Decode an LM-OTS algorithm-type tag from its wire u32 value.
    ///
    /// Returns `None` for unrecognised values. See [`LmsType::from_u32`] for the
    /// error-handling convention.
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x0000_0001 => Some(Self::Sha256N32W1),
            0x0000_0002 => Some(Self::Sha256N32W2),
            0x0000_0003 => Some(Self::Sha256N32W4),
            0x0000_0004 => Some(Self::Sha256N32W8),
            0x0000_0005 => Some(Self::Sha256N24W1),
            0x0000_0006 => Some(Self::Sha256N24W2),
            0x0000_0007 => Some(Self::Sha256N24W4),
            0x0000_0008 => Some(Self::Sha256N24W8),
            0x0000_0009 => Some(Self::ShakeN32W1),
            0x0000_000A => Some(Self::ShakeN32W2),
            0x0000_000B => Some(Self::ShakeN32W4),
            0x0000_000C => Some(Self::ShakeN32W8),
            0x0000_000D => Some(Self::ShakeN24W1),
            0x0000_000E => Some(Self::ShakeN24W2),
            0x0000_000F => Some(Self::ShakeN24W4),
            0x0000_0010 => Some(Self::ShakeN24W8),
            _ => None,
        }
    }

    /// Return this algorithm's parameter set.
    #[must_use]
    pub fn params(self) -> &'static LmOtsParams {
        let idx = (self as u32).wrapping_sub(0x0000_0001) as usize;
        &LM_OTS_PARAMS_TABLE[idx]
    }
}

// ===========================================================================
// LmsHashAlg — internal enum identifying the hash primitive family
// ===========================================================================

/// Identifies the hash primitive family for an LMS / LM-OTS parameter set.
///
/// Used by the verification algorithms to dispatch between SHA-256 and
/// SHAKE-256 code paths without repeatedly parsing the string `digestname`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LmsHashAlg {
    /// SHA-256 (or SHA-256/192 truncated).
    Sha256,
    /// SHAKE-256 with `n`-byte output.
    Shake256,
}

// ===========================================================================
// LmsParams — one LMS parameter set (RFC 8554 §5.1, SP 800-208 Table 1)
// ===========================================================================

/// LMS algorithm parameters for one parameter set.
///
/// Translation of `LMS_PARAMS` from `include/crypto/lms.h`. Each entry captures
/// the fixed parameters required for verification: hash family, output size `n`
/// (bytes), tree height `h`, and the advertised bit-strength category.
#[derive(Debug, Clone, Copy)]
pub struct LmsParams {
    /// Algorithm-type tag (same value as the `LmsType` discriminant).
    pub lms_type: LmsType,
    /// Hash primitive family.
    hash_alg: LmsHashAlg,
    /// Digest output size in bytes (`n = 24` or `n = 32`).
    pub n: u32,
    /// Merkle tree height (5, 10, 15, 20, or 25).
    pub h: u32,
    /// Target bit-strength (128 or 192/256 depending on truncation).
    pub bit_strength: usize,
    /// Algorithm name for the underlying hash primitive.
    ///
    /// Follows OpenSSL provider naming: `"SHA256"` for full-width SHA-256
    /// (`n = 32`), `"SHA256-192"` for truncated SHA-256/192 (`n = 24`), and
    /// `"SHAKE-256"` for both SHAKE-256 variants (`n = 24` or `n = 32`).
    pub digest_name: &'static str,
}

/// Static parameter table for all 20 LMS algorithm types.
///
/// Indexed by `(lms_type as u32 - 0x05)`. Translation of the `lms_params` table
/// in `crypto/lms/lms_params.c`.
static LMS_PARAMS_TABLE: [LmsParams; 20] = [
    // 0x05 — LMS_SHA256_N32_H5
    LmsParams { lms_type: LmsType::Sha256N32H5, hash_alg: LmsHashAlg::Sha256, n: 32, h: 5, bit_strength: 256, digest_name: "SHA256" },
    // 0x06 — LMS_SHA256_N32_H10
    LmsParams { lms_type: LmsType::Sha256N32H10, hash_alg: LmsHashAlg::Sha256, n: 32, h: 10, bit_strength: 256, digest_name: "SHA256" },
    // 0x07 — LMS_SHA256_N32_H15
    LmsParams { lms_type: LmsType::Sha256N32H15, hash_alg: LmsHashAlg::Sha256, n: 32, h: 15, bit_strength: 256, digest_name: "SHA256" },
    // 0x08 — LMS_SHA256_N32_H20
    LmsParams { lms_type: LmsType::Sha256N32H20, hash_alg: LmsHashAlg::Sha256, n: 32, h: 20, bit_strength: 256, digest_name: "SHA256" },
    // 0x09 — LMS_SHA256_N32_H25
    LmsParams { lms_type: LmsType::Sha256N32H25, hash_alg: LmsHashAlg::Sha256, n: 32, h: 25, bit_strength: 256, digest_name: "SHA256" },
    // 0x0A — LMS_SHA256_N24_H5
    LmsParams { lms_type: LmsType::Sha256N24H5, hash_alg: LmsHashAlg::Sha256, n: 24, h: 5, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x0B — LMS_SHA256_N24_H10
    LmsParams { lms_type: LmsType::Sha256N24H10, hash_alg: LmsHashAlg::Sha256, n: 24, h: 10, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x0C — LMS_SHA256_N24_H15
    LmsParams { lms_type: LmsType::Sha256N24H15, hash_alg: LmsHashAlg::Sha256, n: 24, h: 15, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x0D — LMS_SHA256_N24_H20
    LmsParams { lms_type: LmsType::Sha256N24H20, hash_alg: LmsHashAlg::Sha256, n: 24, h: 20, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x0E — LMS_SHA256_N24_H25
    LmsParams { lms_type: LmsType::Sha256N24H25, hash_alg: LmsHashAlg::Sha256, n: 24, h: 25, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x0F — LMS_SHAKE_N32_H5
    LmsParams { lms_type: LmsType::ShakeN32H5, hash_alg: LmsHashAlg::Shake256, n: 32, h: 5, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x10 — LMS_SHAKE_N32_H10
    LmsParams { lms_type: LmsType::ShakeN32H10, hash_alg: LmsHashAlg::Shake256, n: 32, h: 10, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x11 — LMS_SHAKE_N32_H15
    LmsParams { lms_type: LmsType::ShakeN32H15, hash_alg: LmsHashAlg::Shake256, n: 32, h: 15, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x12 — LMS_SHAKE_N32_H20
    LmsParams { lms_type: LmsType::ShakeN32H20, hash_alg: LmsHashAlg::Shake256, n: 32, h: 20, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x13 — LMS_SHAKE_N32_H25
    LmsParams { lms_type: LmsType::ShakeN32H25, hash_alg: LmsHashAlg::Shake256, n: 32, h: 25, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x14 — LMS_SHAKE_N24_H5
    LmsParams { lms_type: LmsType::ShakeN24H5, hash_alg: LmsHashAlg::Shake256, n: 24, h: 5, bit_strength: 192, digest_name: "SHAKE-256" },
    // 0x15 — LMS_SHAKE_N24_H10
    LmsParams { lms_type: LmsType::ShakeN24H10, hash_alg: LmsHashAlg::Shake256, n: 24, h: 10, bit_strength: 192, digest_name: "SHAKE-256" },
    // 0x16 — LMS_SHAKE_N24_H15
    LmsParams { lms_type: LmsType::ShakeN24H15, hash_alg: LmsHashAlg::Shake256, n: 24, h: 15, bit_strength: 192, digest_name: "SHAKE-256" },
    // 0x17 — LMS_SHAKE_N24_H20
    LmsParams { lms_type: LmsType::ShakeN24H20, hash_alg: LmsHashAlg::Shake256, n: 24, h: 20, bit_strength: 192, digest_name: "SHAKE-256" },
    // 0x18 — LMS_SHAKE_N24_H25
    LmsParams { lms_type: LmsType::ShakeN24H25, hash_alg: LmsHashAlg::Shake256, n: 24, h: 25, bit_strength: 192, digest_name: "SHAKE-256" },
];

// ===========================================================================
// LmOtsParams — one LM-OTS parameter set (RFC 8554 §4.1, SP 800-208 Table 2)
// ===========================================================================

/// LM-OTS algorithm parameters for one parameter set.
///
/// Translation of `LM_OTS_PARAMS` from `include/crypto/lms.h`. Each entry
/// captures the fixed parameters required for verification: hash family, output
/// size `n`, Winternitz parameter `w`, chain count `p`, left-shift amount `ls`,
/// and advertised bit-strength.
#[derive(Debug, Clone, Copy)]
pub struct LmOtsParams {
    /// Algorithm-type tag (same value as the `LmOtsType` discriminant).
    pub lm_ots_type: LmOtsType,
    /// Hash primitive family.
    hash_alg: LmsHashAlg,
    /// Digest output size in bytes.
    pub n: u32,
    /// Winternitz parameter in bits per chain (1, 2, 4, or 8).
    pub w: u32,
    /// Number of chains required to cover `n`-byte message + 2-byte checksum.
    pub p: u32,
    /// Left-shift amount applied to the checksum before conversion.
    pub ls: u32,
    /// Target bit-strength.
    pub bit_strength: usize,
    /// Algorithm name for the underlying hash primitive.
    ///
    /// Follows OpenSSL provider naming: `"SHA256"` for full-width SHA-256
    /// (`n = 32`), `"SHA256-192"` for truncated SHA-256/192 (`n = 24`), and
    /// `"SHAKE-256"` for both SHAKE-256 variants.
    pub digest_name: &'static str,
}

/// Static parameter table for all 16 LM-OTS algorithm types.
///
/// Indexed by `(lm_ots_type as u32 - 0x01)`. Translation of the `lm_ots_params`
/// table in `crypto/lms/lm_ots_params.c`.
static LM_OTS_PARAMS_TABLE: [LmOtsParams; 16] = [
    // 0x01 — LMOTS_SHA256_N32_W1
    LmOtsParams { lm_ots_type: LmOtsType::Sha256N32W1, hash_alg: LmsHashAlg::Sha256, n: 32, w: 1, p: 265, ls: 7, bit_strength: 256, digest_name: "SHA256" },
    // 0x02 — LMOTS_SHA256_N32_W2
    LmOtsParams { lm_ots_type: LmOtsType::Sha256N32W2, hash_alg: LmsHashAlg::Sha256, n: 32, w: 2, p: 133, ls: 6, bit_strength: 256, digest_name: "SHA256" },
    // 0x03 — LMOTS_SHA256_N32_W4
    LmOtsParams { lm_ots_type: LmOtsType::Sha256N32W4, hash_alg: LmsHashAlg::Sha256, n: 32, w: 4, p: 67, ls: 4, bit_strength: 256, digest_name: "SHA256" },
    // 0x04 — LMOTS_SHA256_N32_W8
    LmOtsParams { lm_ots_type: LmOtsType::Sha256N32W8, hash_alg: LmsHashAlg::Sha256, n: 32, w: 8, p: 34, ls: 0, bit_strength: 256, digest_name: "SHA256" },
    // 0x05 — LMOTS_SHA256_N24_W1
    LmOtsParams { lm_ots_type: LmOtsType::Sha256N24W1, hash_alg: LmsHashAlg::Sha256, n: 24, w: 1, p: 200, ls: 8, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x06 — LMOTS_SHA256_N24_W2
    LmOtsParams { lm_ots_type: LmOtsType::Sha256N24W2, hash_alg: LmsHashAlg::Sha256, n: 24, w: 2, p: 101, ls: 6, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x07 — LMOTS_SHA256_N24_W4
    LmOtsParams { lm_ots_type: LmOtsType::Sha256N24W4, hash_alg: LmsHashAlg::Sha256, n: 24, w: 4, p: 51, ls: 4, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x08 — LMOTS_SHA256_N24_W8
    LmOtsParams { lm_ots_type: LmOtsType::Sha256N24W8, hash_alg: LmsHashAlg::Sha256, n: 24, w: 8, p: 26, ls: 0, bit_strength: 192, digest_name: "SHA256-192" },
    // 0x09 — LMOTS_SHAKE_N32_W1
    LmOtsParams { lm_ots_type: LmOtsType::ShakeN32W1, hash_alg: LmsHashAlg::Shake256, n: 32, w: 1, p: 265, ls: 7, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x0A — LMOTS_SHAKE_N32_W2
    LmOtsParams { lm_ots_type: LmOtsType::ShakeN32W2, hash_alg: LmsHashAlg::Shake256, n: 32, w: 2, p: 133, ls: 6, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x0B — LMOTS_SHAKE_N32_W4
    LmOtsParams { lm_ots_type: LmOtsType::ShakeN32W4, hash_alg: LmsHashAlg::Shake256, n: 32, w: 4, p: 67, ls: 4, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x0C — LMOTS_SHAKE_N32_W8
    LmOtsParams { lm_ots_type: LmOtsType::ShakeN32W8, hash_alg: LmsHashAlg::Shake256, n: 32, w: 8, p: 34, ls: 0, bit_strength: 256, digest_name: "SHAKE-256" },
    // 0x0D — LMOTS_SHAKE_N24_W1
    LmOtsParams { lm_ots_type: LmOtsType::ShakeN24W1, hash_alg: LmsHashAlg::Shake256, n: 24, w: 1, p: 200, ls: 8, bit_strength: 192, digest_name: "SHAKE-256" },
    // 0x0E — LMOTS_SHAKE_N24_W2
    LmOtsParams { lm_ots_type: LmOtsType::ShakeN24W2, hash_alg: LmsHashAlg::Shake256, n: 24, w: 2, p: 101, ls: 6, bit_strength: 192, digest_name: "SHAKE-256" },
    // 0x0F — LMOTS_SHAKE_N24_W4
    LmOtsParams { lm_ots_type: LmOtsType::ShakeN24W4, hash_alg: LmsHashAlg::Shake256, n: 24, w: 4, p: 51, ls: 4, bit_strength: 192, digest_name: "SHAKE-256" },
    // 0x10 — LMOTS_SHAKE_N24_W8
    LmOtsParams { lm_ots_type: LmOtsType::ShakeN24W8, hash_alg: LmsHashAlg::Shake256, n: 24, w: 8, p: 26, ls: 0, bit_strength: 192, digest_name: "SHAKE-256" },
];

// ===========================================================================
// LmsHasher — uniform wrapper around SHA-256 / SHAKE-256 primitives
// ===========================================================================

/// Internal wrapper that provides a uniform `update`/`finalize` interface over
/// SHA-256 and SHAKE-256.
///
/// The LMS verification algorithms absorb many small variable-length inputs and
/// then extract an `n`-byte digest. This wrapper hides the underlying primitive
/// so that the algorithm bodies can be expressed identically for both hash
/// families. SHA-256 outputs are truncated to `n` bytes for N=24 parameter
/// sets (matching SP 800-208 "SHA-256/192").
enum LmsHasher {
    /// SHA-256 Merkle-Damgård hasher.
    Sha256(Sha256Context),
    /// SHAKE-256 sponge hasher.
    Shake256(ShakeContext),
}

impl LmsHasher {
    /// Construct a fresh hasher for the given hash family.
    fn new(alg: LmsHashAlg) -> Self {
        match alg {
            LmsHashAlg::Sha256 => Self::Sha256(Sha256Context::sha256()),
            LmsHashAlg::Shake256 => Self::Shake256(ShakeContext::shake256()),
        }
    }

    /// Absorb `data` into the hasher state.
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        match self {
            Self::Sha256(ctx) => ctx.update(data),
            Self::Shake256(ctx) => ctx.update(data),
        }
    }

    /// Finalise the hasher and write exactly `n` bytes into `out`.
    ///
    /// For SHA-256, the 32-byte digest is truncated to `out.len()`. For
    /// SHAKE-256, `out.len()` bytes are squeezed from the sponge.
    ///
    /// # Errors
    /// Returns [`CryptoError::Common`] with [`CommonError::InvalidArgument`] if
    /// the requested output size exceeds [`LMS_MAX_DIGEST_SIZE`] (internal
    /// invariant violation).
    fn finalize_into(self, out: &mut [u8]) -> CryptoResult<()> {
        if out.len() > LMS_MAX_DIGEST_SIZE {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                format!(
                    "LmsHasher::finalize_into: output length {} exceeds max {}",
                    out.len(),
                    LMS_MAX_DIGEST_SIZE
                ),
            )));
        }
        match self {
            Self::Sha256(mut ctx) => {
                // SHA-256 always produces 32 bytes; we truncate to `out.len()`
                // for N=24 parameter sets (SP 800-208 "SHA-256/192").
                let full = ctx.finalize()?;
                if full.len() < out.len() {
                    return Err(CryptoError::Common(CommonError::Internal(
                        "LmsHasher: SHA-256 produced fewer bytes than requested".to_owned(),
                    )));
                }
                out.copy_from_slice(&full[..out.len()]);
                Ok(())
            }
            Self::Shake256(mut ctx) => ctx.squeeze(out),
        }
    }
}

// ===========================================================================
// Helper functions (RFC 8554 §4.5 / Appendix B / OpenSSL lms_util.h)
// ===========================================================================

/// Extract the `i`-th Winternitz coefficient from byte string `s` using
/// Winternitz parameter `w` (bits per coefficient).
///
/// This implements the `coef(s, i, w)` function of RFC 8554 Appendix B:
///
/// ```text
/// coef(S, i, w) = (2^w - 1) AND (byte(S, floor(i*w/8)) >> (8 - (w * (i % (8/w)) + w)))
/// ```
///
/// `w` must be one of `{1, 2, 4, 8}`; `i * w` must be within the bit-length of
/// `s`. For `w = 8`, `i % 1 = 0`, so this simplifies to `s[i]`.
///
/// # Panics
/// Does not panic. Out-of-bounds indexing is prevented by callers that validate
/// `i < 8 * s.len() / w` (i.e. by iterating `0..p`).
fn lms_ots_coef(s: &[u8], i: u32, w: u32) -> CryptoResult<u8> {
    // Validate `w`: per RFC 8554 §4.2, `w` MUST be one of `{1, 2, 4, 8}` —
    // only these values divide 8 cleanly and produce a well-defined
    // coefficient extraction. Reject any other value explicitly rather than
    // silently truncating in the `8 / w` integer division below.
    if !matches!(w, 1 | 2 | 4 | 8) {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lms_ots_coef: invalid w = {w} (must be 1, 2, 4, or 8 per RFC 8554 §4.2)"
        ))));
    }
    // Bit mask `2^w - 1`. `w` is validated above to be in `{1, 2, 4, 8}`,
    // so `1 << w` cannot overflow and the `as u8` narrowing is lossless
    // (maximum value is `2^8 - 1 = 255`).
    // TRUNCATION: `(1 << w) - 1` for `w ∈ {1,2,4,8}` is always in `[1, 255]`.
    let bitmask: u8 = (1_u32.checked_shl(w).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_ots_coef 1 << w",
        })
    })? - 1) as u8;
    let cpb = 8_u32 / w; // coefficients per byte (exact: w ∈ {1,2,4,8})
    // byte_index = floor(i * w / 8) = i / cpb
    let byte_idx = (i / cpb) as usize;
    if byte_idx >= s.len() {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lms_ots_coef: byte_idx {} out of range for s.len() = {}",
            byte_idx,
            s.len()
        ))));
    }
    // shift = 8 - (w * (i % cpb) + w)
    let offset_in_byte = i % cpb;
    let shift = 8_u32
        .checked_sub(
            w.checked_mul(offset_in_byte)
                .and_then(|v| v.checked_add(w))
                .ok_or_else(|| {
                    CryptoError::Common(CommonError::ArithmeticOverflow {
                        operation: "lms_ots_coef shift",
                    })
                })?,
        )
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lms_ots_coef 8 - shift",
            })
        })?;
    Ok((s[byte_idx] >> shift) & bitmask)
}

/// Compute the LM-OTS checksum `Cksm(Q)` per RFC 8554 §4.4.
///
/// Returns a big-endian 2-byte value:
///
/// ```text
/// sum = 0
/// for i in 0..n*(8/w) {
///     sum += (2^w - 1) - coef(Q, i, w)
/// }
/// Cksm = (sum << ls) encoded as u16 big-endian
/// ```
fn lm_ots_params_checksum(
    q: &[u8],
    n: u32,
    w: u32,
    ls: u32,
) -> CryptoResult<[u8; 2]> {
    let max_coef = 1_u32
        .checked_shl(w)
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lm_ots_params_checksum 1 << w",
            })
        })?
        - 1;
    // Iteration count: n * 8 / w.
    let iter_count = n
        .checked_mul(8)
        .and_then(|v| v.checked_div(w))
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lm_ots_params_checksum n*8/w",
            })
        })?;
    // Accumulate in u32 to avoid overflow even for worst case n=32, w=1:
    // max sum = 256 * 1 = 256; always fits in u16. Use u32 for extra safety.
    let mut sum: u32 = 0;
    for i in 0..iter_count {
        let c = lms_ots_coef(q, i, w)? as u32;
        sum = sum
            .checked_add(max_coef - c)
            .ok_or_else(|| {
                CryptoError::Common(CommonError::ArithmeticOverflow {
                    operation: "lm_ots_params_checksum sum",
                })
            })?;
    }
    // Shift left by ls bits.
    if ls >= 32 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lm_ots_params_checksum: ls = {ls} is out of range"
        ))));
    }
    let shifted = sum.checked_shl(ls).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lm_ots_params_checksum sum << ls",
        })
    })?;
    // Return the low-order 16 bits encoded big-endian.
    let truncated = shifted & 0xFFFF;
    Ok([(truncated >> 8) as u8, (truncated & 0xFF) as u8])
}

/// Increment a 2-byte big-endian counter in place.
///
/// Mirrors OpenSSL's `INC16` macro in `crypto/lms/lm_ots_verify.c`. The counter
/// wraps on overflow, matching the C behaviour.
fn inc16(tag: &mut [u8; 2]) {
    tag[1] = tag[1].wrapping_add(1);
    if tag[1] == 0 {
        tag[0] = tag[0].wrapping_add(1);
    }
}

/// Decode a big-endian u32 from the first 4 bytes of `b`.
///
/// # Errors
/// Returns [`CommonError::InvalidArgument`] if `b.len() < 4`.
fn read_u32_be(b: &[u8]) -> CryptoResult<u32> {
    if b.len() < 4 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "read_u32_be: slice too short ({} < 4)",
            b.len()
        ))));
    }
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

// ===========================================================================
// LmsPubKey — decoded LMS public key
// ===========================================================================

/// A decoded LMS public key.
///
/// Holds the parsed parameter sets and the 16-byte tree identifier `I` together
/// with the trusted root hash `K` (of size `n` bytes). The raw wire encoding is
/// retained so callers can re-serialise or compute `I || q || ...` prefixes
/// directly against it without recomputing field offsets.
///
/// Wire format (RFC 8554 §5.3):
///
/// ```text
/// pubkey = u32(lms_type) || u32(ots_type) || I[16] || K[n]
/// ```
#[derive(Debug, Clone)]
pub struct LmsPubKey {
    /// LMS algorithm parameters (references static table).
    lms_params: &'static LmsParams,
    /// LM-OTS algorithm parameters (references static table).
    ots_params: &'static LmOtsParams,
    /// The 16-byte tree identifier `I`.
    i: [u8; LMS_SIZE_I],
    /// The trusted root hash `K` (length = `lms_params.n`).
    k: Vec<u8>,
}

impl LmsPubKey {
    /// Return the LMS parameter set.
    #[must_use]
    pub fn lms_params(&self) -> &'static LmsParams {
        self.lms_params
    }

    /// Return the LM-OTS parameter set.
    #[must_use]
    pub fn ots_params(&self) -> &'static LmOtsParams {
        self.ots_params
    }

    /// Return the tree identifier `I`.
    #[must_use]
    pub fn i(&self) -> &[u8; LMS_SIZE_I] {
        &self.i
    }

    /// Return the trusted root hash `K`.
    #[must_use]
    pub fn k(&self) -> &[u8] {
        &self.k
    }

    /// Expected wire length of an LMS public key for these parameters.
    #[must_use]
    pub fn encoded_len(lms: &LmsParams) -> usize {
        LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE + LMS_SIZE_I + lms.n as usize
    }

    /// Decode an LMS public key from its big-endian wire encoding.
    ///
    /// Returns `Ok(None)` on structural failure (wrong length, unknown algorithm
    /// tag, hash-family mismatch between LMS and LM-OTS parameter sets) so that
    /// callers can propagate a verification `Ok(false)` without ambiguity. An
    /// `Err` is returned only for internal invariant violations (never from
    /// public caller-provided input).
    ///
    /// # Errors
    /// This function does not return `Err` for invalid input; all structural
    /// failures map to `Ok(None)`.
    ///
    /// # Rule compliance
    /// * Rule R5: Returns `Option` / `Result`; no sentinel values.
    /// * Rule R6: All size arithmetic uses `checked_*` or typed casts.
    /// * Rule R8: Contains zero `unsafe` code.
    pub fn decode(encoded: &[u8]) -> CryptoResult<Option<Self>> {
        // Minimum length: two 4-byte tags + I + at least 24-byte K.
        if encoded.len() < LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE + LMS_SIZE_I + 24 {
            return Ok(None);
        }
        // Decode lms_type.
        let lms_tag = read_u32_be(&encoded[0..LMS_SIZE_LMS_TYPE])?;
        let Some(lms_type) = LmsType::from_u32(lms_tag) else {
            return Ok(None);
        };
        let lms_params = lms_type.params();
        // Verify total length now that we know `n`.
        let expected_len = Self::encoded_len(lms_params);
        if encoded.len() != expected_len {
            return Ok(None);
        }
        // Decode ots_type.
        let ots_tag = read_u32_be(&encoded[LMS_SIZE_LMS_TYPE..LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE])?;
        let Some(ots_type) = LmOtsType::from_u32(ots_tag) else {
            return Ok(None);
        };
        let ots_params = ots_type.params();
        // Enforce hash-family and n consistency between LMS and LM-OTS.
        if lms_params.hash_alg != ots_params.hash_alg || lms_params.n != ots_params.n {
            return Ok(None);
        }
        // Extract I.
        let mut i = [0_u8; LMS_SIZE_I];
        let i_offset = LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE;
        i.copy_from_slice(&encoded[i_offset..i_offset + LMS_SIZE_I]);
        // Extract K.
        let k_offset = i_offset + LMS_SIZE_I;
        let n = lms_params.n as usize;
        let k = encoded[k_offset..k_offset + n].to_vec();
        Ok(Some(Self { lms_params, ots_params, i, k }))
    }
}

// ===========================================================================
// LM-OTS public-key reconstruction (RFC 8554 §4.5 Algorithm 4b)
// ===========================================================================

/// Reconstruct a candidate LM-OTS public key `Kc` from an LM-OTS signature.
///
/// Implements RFC 8554 §4.5 Algorithm 4b: the verifier takes the message
/// randomiser `C`, the `p` chain-output segments `y_0..y_{p-1}`, and the
/// message `msg`, and recomputes:
///
/// 1. `Q = H(I || q || D_MESG || C || msg)`.
/// 2. `Cksm = Cksm(Q)` per RFC 8554 §4.4.
/// 3. For `i = 0..p`: let `a = coef(Q || Cksm, i, w)`. Starting with
///    `tmp = y[i]`, for `j = a..2^w - 1`:
///    `tmp = H(I || q || u16(i) || u8(j) || tmp)`.
/// 4. `Kc = H(I || q || D_PBLC || tmp_0 || tmp_1 || ... || tmp_{p-1})`.
///
/// Returns the recomputed `Kc` as an `n`-byte vector.
///
/// # Arguments
/// * `ots` — The LM-OTS parameter set.
/// * `i` — The 16-byte LMS tree identifier.
/// * `q` — The 4-byte big-endian leaf index.
/// * `c` — The `n`-byte LM-OTS randomiser.
/// * `y` — Concatenated chain outputs, length `p * n` bytes.
/// * `msg` — The message that was signed.
///
/// # Errors
/// * [`CryptoError::Common(CommonError::InvalidArgument)`] if any buffer length
///   is inconsistent with the parameter set (internal invariant violation).
/// * [`CryptoError::Common(CommonError::ArithmeticOverflow)`] if an internal
///   size calculation would overflow.
fn lm_ots_compute_pubkey(
    ots: &LmOtsParams,
    i: &[u8; LMS_SIZE_I],
    q: [u8; LMS_SIZE_Q],
    c: &[u8],
    y: &[u8],
    msg: &[u8],
) -> CryptoResult<Vec<u8>> {
    let n = ots.n as usize;
    let p = ots.p as usize;
    if c.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lm_ots_compute_pubkey: C length {} != n ({})",
            c.len(),
            n
        ))));
    }
    let expected_y = p.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lm_ots_compute_pubkey p*n",
        })
    })?;
    if y.len() != expected_y {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lm_ots_compute_pubkey: y length {} != p*n ({})",
            y.len(),
            expected_y
        ))));
    }
    // Step 1: Q = H(I || q || D_MESG || C || msg)
    let mut q_digest = [0_u8; LMS_MAX_DIGEST_SIZE];
    {
        let mut h = LmsHasher::new(ots.hash_alg);
        h.update(i)?;
        h.update(&q)?;
        h.update(&D_MESG)?;
        h.update(c)?;
        h.update(msg)?;
        h.finalize_into(&mut q_digest[..n])?;
    }
    // Step 2: checksum
    let cksm = lm_ots_params_checksum(&q_digest[..n], ots.n, ots.w, ots.ls)?;
    // Concatenate Q || Cksm into a fixed buffer for coefficient extraction.
    // Total size = n + 2; bounded by LMS_MAX_DIGEST_SIZE + 2 = 34 bytes.
    let mut q_full = [0_u8; LMS_MAX_DIGEST_SIZE + 2];
    q_full[..n].copy_from_slice(&q_digest[..n]);
    q_full[n..n + 2].copy_from_slice(&cksm);
    let q_full_len = n + 2;
    // Step 3+4: Prepare the final K hash context and iteratively hash each
    // chain output. We interleave the per-chain expansion with absorption into
    // `k_hasher` to avoid a separate tmp[] buffer of size p*n.
    let mut k_hasher = LmsHasher::new(ots.hash_alg);
    k_hasher.update(i)?;
    k_hasher.update(&q)?;
    k_hasher.update(&D_PBLC)?;
    // Per-chain iteration.
    let max_j = 1_u32
        .checked_shl(ots.w)
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lm_ots_compute_pubkey 1<<w",
            })
        })?
        - 1;
    let mut tmp = [0_u8; LMS_MAX_DIGEST_SIZE];
    let mut tag_i = [0_u8; 2];
    for chain_idx in 0..p {
        let chain_u32 = u32::try_from(chain_idx).map_err(|_| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lm_ots_compute_pubkey chain_idx",
            })
        })?;
        let a = lms_ots_coef(&q_full[..q_full_len], chain_u32, ots.w)? as u32;
        // Initialise tmp = y[chain_idx] (n bytes).
        let y_start = chain_idx.checked_mul(n).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lm_ots_compute_pubkey y_start",
            })
        })?;
        tmp[..n].copy_from_slice(&y[y_start..y_start + n]);
        // Encode `i` (the chain index) as 2-byte big-endian. Explicit truncation:
        // chain_idx < p <= 265 < 2^16, so this narrowing cast is lossless.
        // TRUNCATION: chain_idx is bounded by p <= 265, fits in u16.
        tag_i[0] = ((chain_u32 >> 8) & 0xFF) as u8;
        tag_i[1] = (chain_u32 & 0xFF) as u8;
        // Prepare a 1-byte j buffer.
        let mut j_buf: [u8; 1] = [0];
        let mut j = a;
        while j < max_j {
            // TRUNCATION: j < max_j <= 255 (w=8 is max), fits in u8.
            j_buf[0] = (j & 0xFF) as u8;
            let mut h = LmsHasher::new(ots.hash_alg);
            h.update(i)?;
            h.update(&q)?;
            h.update(&tag_i)?;
            h.update(&j_buf)?;
            h.update(&tmp[..n])?;
            let mut new_tmp = [0_u8; LMS_MAX_DIGEST_SIZE];
            h.finalize_into(&mut new_tmp[..n])?;
            tmp[..n].copy_from_slice(&new_tmp[..n]);
            j = j.checked_add(1).ok_or_else(|| {
                CryptoError::Common(CommonError::ArithmeticOverflow {
                    operation: "lm_ots_compute_pubkey j++",
                })
            })?;
        }
        // Absorb the final tmp into K hash.
        k_hasher.update(&tmp[..n])?;
    }
    // Step 4: Kc = H(... all chain outputs)
    let mut kc = vec![0_u8; n];
    k_hasher.finalize_into(&mut kc)?;
    // Suppress unused warning for inc16 — it remains exported for parity with
    // OpenSSL's public helper surface even though the interleaved hashing
    // above does not require an explicit counter buffer.
    let _ = inc16;
    Ok(kc)
}

// ===========================================================================
// LMS Merkle-path verification (RFC 8554 §5.4.2 Algorithm 6a)
// ===========================================================================

/// Recompute the candidate LMS root `Tc` from the leaf hash and Merkle path.
///
/// Implements RFC 8554 §5.4.2 Algorithm 6a steps 4 and 5:
///
/// 1. `node_num = 2^h + q`.
/// 2. `tmp = H(I || node_num || D_LEAF || Kc)`.
/// 3. While `node_num > 1`:
///    - If `node_num % 2 == 1`: `tmp = H(I || floor(node_num/2) || D_INTR || path[level] || tmp)`.
///    - Else: `tmp = H(I || floor(node_num/2) || D_INTR || tmp || path[level])`.
///    - `node_num = floor(node_num / 2)`.
/// 4. Return `tmp` as `Tc`.
///
/// # Arguments
/// * `lms` — LMS parameter set (selects hash family and `h`).
/// * `i` — LMS tree identifier.
/// * `q` — Leaf index as 4-byte big-endian.
/// * `kc` — Candidate LM-OTS public key at the leaf (`n` bytes).
/// * `path` — Merkle authentication path, length `h * n` bytes.
///
/// # Errors
/// Returns [`CommonError::InvalidArgument`] if `path.len() != h * n` or if
/// `kc.len() != n` (internal invariant violation).
fn lms_sig_compute_tc_from_path(
    lms: &LmsParams,
    i: &[u8; LMS_SIZE_I],
    q: [u8; LMS_SIZE_Q],
    kc: &[u8],
    path: &[u8],
) -> CryptoResult<Vec<u8>> {
    let n = lms.n as usize;
    let h = lms.h;
    if kc.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lms_sig_compute_tc_from_path: Kc length {} != n ({})",
            kc.len(),
            n
        ))));
    }
    let expected_path_len = (h as usize).checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_sig_compute_tc_from_path h*n",
        })
    })?;
    if path.len() != expected_path_len {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lms_sig_compute_tc_from_path: path length {} != h*n ({})",
            path.len(),
            expected_path_len
        ))));
    }
    // Decode q.
    let q_val = u32::from_be_bytes(q);
    // node_num = 2^h + q. Bound: h <= 25, 2^h + q <= 2^26. Use u32.
    if h >= 32 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lms_sig_compute_tc_from_path: h = {h} is out of range"
        ))));
    }
    let two_pow_h = 1_u32.checked_shl(h).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_sig_compute_tc_from_path 1<<h",
        })
    })?;
    // q must be in [0, 2^h).
    if q_val >= two_pow_h {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lms_sig_compute_tc_from_path: q = {q_val} >= 2^h ({two_pow_h})"
        ))));
    }
    let mut node_num = two_pow_h.checked_add(q_val).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_sig_compute_tc_from_path 2^h + q",
        })
    })?;
    // Step 1: tmp = H(I || node_num || D_LEAF || Kc)
    let mut tmp = vec![0_u8; n];
    {
        let mut hasher = LmsHasher::new(lms.hash_alg);
        hasher.update(i)?;
        hasher.update(&node_num.to_be_bytes())?;
        hasher.update(&D_LEAF)?;
        hasher.update(kc)?;
        hasher.finalize_into(&mut tmp)?;
    }
    // Step 2: walk up the tree, consuming one path segment per level.
    let mut level: usize = 0;
    while node_num > 1 {
        let path_start = level.checked_mul(n).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lms_sig_compute_tc_from_path path offset",
            })
        })?;
        let sibling = &path[path_start..path_start + n];
        let parent_num = node_num / 2;
        let mut hasher = LmsHasher::new(lms.hash_alg);
        hasher.update(i)?;
        hasher.update(&parent_num.to_be_bytes())?;
        hasher.update(&D_INTR)?;
        // Parity governs sibling ordering. See RFC 8554 §5.4.2 Alg 6a step 4.
        if node_num % 2 == 1 {
            // Current node is the RIGHT child: sibling || current.
            hasher.update(sibling)?;
            hasher.update(&tmp)?;
        } else {
            // Current node is the LEFT child: current || sibling.
            hasher.update(&tmp)?;
            hasher.update(sibling)?;
        }
        let mut new_tmp = vec![0_u8; n];
        hasher.finalize_into(&mut new_tmp)?;
        tmp = new_tmp;
        node_num = parent_num;
        level = level.checked_add(1).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lms_sig_compute_tc_from_path level++",
            })
        })?;
    }
    Ok(tmp)
}

// ===========================================================================
// Top-level verification API
// ===========================================================================

/// Verify an LMS signature against a public key and message.
///
/// Implements the full LMS verification pipeline of RFC 8554 §5.4.2
/// Algorithm 6a:
///
/// 1. Parse the signature wire format:
///    ```text
///    sig = u32(q) || u32(ots_type) || C[n] || y[p*n] || u32(lms_type) || path[h*n]
///    ```
/// 2. Reject mismatched `ots_type` / `lms_type` tags or wrong total length.
/// 3. Recompute `Kc` via `lm_ots_compute_pubkey`.
/// 4. Recompute `Tc` via `lms_sig_compute_tc_from_path`.
/// 5. Return `Ok(true)` iff `Tc` equals the public-key root `K` in constant time.
///
/// # Arguments
/// * `pub_key` — Decoded LMS public key.
/// * `msg` — The message bytes that were signed.
/// * `sig` — The candidate signature bytes (wire format).
///
/// # Returns
/// * `Ok(true)` — signature is valid.
/// * `Ok(false)` — signature is structurally or cryptographically invalid.
///   Wrong-length signatures, unknown algorithm tags, and algorithm mismatches
///   all map to `Ok(false)`, never `Err`.
/// * `Err(..)` — internal invariant violation (should never occur on well-formed
///   input reaching this function).
///
/// # Errors
/// * [`CryptoError::Common(CommonError::ArithmeticOverflow)`] if a size
///   computation would overflow (should not occur for any well-formed parameter
///   set).
///
/// # Rule compliance
/// * Rule R5: Returns `CryptoResult<bool>`; no sentinel values.
/// * Rule R6: All size arithmetic uses `checked_*` operations and typed casts.
/// * Rule R7: Takes the public key by immutable reference.
/// * Rule R8: Contains zero `unsafe` code.
/// * Rule R10: Reachable via `openssl_crypto::pqc::lms::lms_verify`.
pub fn lms_verify(pub_key: &LmsPubKey, msg: &[u8], sig: &[u8]) -> CryptoResult<bool> {
    let n = pub_key.lms_params.n as usize;
    let p = pub_key.ots_params.p as usize;
    let h = pub_key.lms_params.h as usize;
    // Pre-compute expected signature length.
    //   sig = q(4) || ots_type(4) || C(n) || y(p*n) || lms_type(4) || path(h*n)
    //       = 12 + n*(1 + p + h)
    let inner = 1_usize
        .checked_add(p)
        .and_then(|v| v.checked_add(h))
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lms_verify 1+p+h",
            })
        })?;
    let variable = n.checked_mul(inner).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_verify n*(1+p+h)",
        })
    })?;
    let expected_sig_len = variable
        .checked_add(LMS_SIZE_Q + LMS_SIZE_OTS_TYPE + LMS_SIZE_LMS_TYPE)
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "lms_verify expected_sig_len",
            })
        })?;
    if sig.len() != expected_sig_len {
        // Structural length mismatch: reject without error per the
        // public-API "Ok(false) on bad input" convention.
        return Ok(false);
    }
    // Slice the signature into its components.
    let mut off = 0_usize;
    let q_slice = &sig[off..off + LMS_SIZE_Q];
    off += LMS_SIZE_Q;
    let ots_tag = read_u32_be(&sig[off..off + LMS_SIZE_OTS_TYPE])?;
    off += LMS_SIZE_OTS_TYPE;
    let c_slice = &sig[off..off + n];
    off += n;
    let y_slice = &sig[off..off + p * n];
    off += p * n;
    let lms_tag = read_u32_be(&sig[off..off + LMS_SIZE_LMS_TYPE])?;
    off += LMS_SIZE_LMS_TYPE;
    let path_slice = &sig[off..off + h * n];
    off = off.checked_add(h * n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_verify path offset",
        })
    })?;
    debug_assert_eq!(off, expected_sig_len);
    // Verify algorithm tags match the public key.
    let Some(sig_ots_type) = LmOtsType::from_u32(ots_tag) else {
        return Ok(false);
    };
    let Some(sig_lms_type) = LmsType::from_u32(lms_tag) else {
        return Ok(false);
    };
    if sig_ots_type != pub_key.ots_params.lm_ots_type
        || sig_lms_type != pub_key.lms_params.lms_type
    {
        return Ok(false);
    }
    // Enforce q < 2^h.
    let q_val = u32::from_be_bytes([q_slice[0], q_slice[1], q_slice[2], q_slice[3]]);
    let h_u32 = pub_key.lms_params.h;
    if h_u32 >= 32 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "lms_verify: invalid h = {h_u32} in parameter set"
        ))));
    }
    let two_pow_h = 1_u32.checked_shl(h_u32).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_verify 1<<h",
        })
    })?;
    if q_val >= two_pow_h {
        return Ok(false);
    }
    // Materialise fixed-size q for helper APIs.
    let mut q_arr = [0_u8; LMS_SIZE_Q];
    q_arr.copy_from_slice(q_slice);
    // Step 1: Reconstruct Kc from the LM-OTS signature.
    let kc = lm_ots_compute_pubkey(
        pub_key.ots_params,
        &pub_key.i,
        q_arr,
        c_slice,
        y_slice,
        msg,
    )?;
    // Step 2: Recompute Tc from Kc and the authentication path.
    let tc = lms_sig_compute_tc_from_path(
        pub_key.lms_params,
        &pub_key.i,
        q_arr,
        &kc,
        path_slice,
    )?;
    // Step 3: Constant-time compare against the trusted root K.
    if tc.len() != pub_key.k.len() {
        // Should never happen — both sides are `n` bytes — but guard anyway.
        return Ok(false);
    }
    Ok(tc.ct_eq(&pub_key.k).unwrap_u8() == 1)
}

// ===========================================================================
// Convenience: one-shot verification from wire-encoded public key
// ===========================================================================

/// One-shot verification: decode the public key from its wire format and verify.
///
/// Combines [`LmsPubKey::decode`] and [`lms_verify`]. Returns `Ok(false)` on
/// any structural error (including public-key decode failure). Returns
/// `Err(..)` only for internal invariant violations.
///
/// # Rule compliance
/// * Rule R5: All failure modes use `Option` / `Result`; no sentinels.
/// * Rule R8: Contains zero `unsafe` code.
/// * Rule R10: Reachable via `openssl_crypto::pqc::lms::verify`.
pub fn verify(encoded_pubkey: &[u8], msg: &[u8], sig: &[u8]) -> CryptoResult<bool> {
    match LmsPubKey::decode(encoded_pubkey)? {
        Some(pk) => lms_verify(&pk, msg, sig),
        None => Ok(false),
    }
}

// ===========================================================================
// Standalone parameter-set lookup functions (schema-required API)
// ===========================================================================

/// Look up an LM-OTS parameter set by its IANA-assigned algorithm-type tag.
///
/// Returns `None` when the tag is outside the registered range
/// (`0x0000_0001..=0x0000_0010`). Replaces C `ossl_lm_ots_params_get()` from
/// `crypto/lms/lm_ots_params.c`; the C version returns `NULL` for unknown
/// tags — Rule R5 mandates `Option<T>` instead.
///
/// # Rule compliance
/// * Rule R5: Uses `Option<T>` instead of `NULL` sentinel.
/// * Rule R8: Contains zero `unsafe` code.
#[must_use]
pub fn lm_ots_params_get(ots_type: LmOtsType) -> Option<&'static LmOtsParams> {
    Some(ots_type.params())
}

/// Look up an LMS parameter set by its IANA-assigned algorithm-type tag.
///
/// Returns `None` when the tag is outside the registered range
/// (`0x0000_0005..=0x0000_0018`). Replaces C `ossl_lms_params_get()` from
/// `crypto/lms/lms_params.c`.
///
/// # Rule compliance
/// * Rule R5: Uses `Option<T>` instead of `NULL` sentinel.
/// * Rule R8: Contains zero `unsafe` code.
#[must_use]
pub fn lms_params_get(lms_type: LmsType) -> Option<&'static LmsParams> {
    Some(lms_type.params())
}

/// Compute the 16-bit LM-OTS Winternitz checksum (RFC 8554 §4.4).
///
/// The checksum is computed as `Cksm(S) = sum_{i=0..u} (max_coef - coef(S, i, w)) << ls`
/// where `u = n*8/w`, `max_coef = 2^w - 1`, and `coef(S, i, w)` extracts
/// Winternitz coefficient `i` from byte string `S`. The sum is taken modulo
/// `2^16` and the low-order 16 bits are returned.
///
/// `s` must contain at least `params.n` bytes; only the first `params.n` are
/// consumed. This is a thin `u16`-returning wrapper around the internal
/// big-endian byte computation. Replaces C `ossl_lm_ots_params_checksum()`
/// from `crypto/lms/lm_ots_params.c`.
///
/// # Errors
/// Returns [`CryptoError::InvalidArgument`] when `s.len() < params.n` or
/// when the parameter set has invalid `w`/`ls` values.
///
/// # Rule compliance
/// * Rule R5: Uses `Result<u16, _>` rather than a sentinel value.
/// * Rule R6: All width conversions use checked arithmetic / safe casts.
/// * Rule R8: Contains zero `unsafe` code.
pub fn lm_ots_checksum(params: &LmOtsParams, s: &[u8]) -> CryptoResult<u16> {
    let bytes = lm_ots_params_checksum(s, params.n, params.w, params.ls)?;
    Ok(u16::from_be_bytes(bytes))
}

// ===========================================================================
// LmsPublicKey — encoded-form public key wrapper (schema-required type)
// ===========================================================================

/// LMS public key in encoded wire form, with a parsed copy of the root hash.
///
/// This is the schema-mandated public-key type. It pairs the original
/// wire-format encoding (`encoded`) with the extracted root hash `K = T(1)`
/// for direct constant-time comparison and downstream re-serialisation.
///
/// The wire format is, per RFC 8554 §5.4:
/// ```text
/// u32(lms_type) || u32(lms_ots_type) || I[16] || K[n]
/// ```
/// where `n` is the digest size of the LMS parameter set (24 or 32 bytes).
///
/// Memory containing key material is securely erased via [`zeroize::Zeroize`]
/// when the value is dropped, replacing C `OPENSSL_cleanse()` from
/// `crypto/mem_clr.c`.
#[derive(Debug, Clone)]
pub struct LmsPublicKey {
    /// Encoded public-key buffer (full wire format).
    pub encoded: Vec<u8>,
    /// Length of the encoded public-key buffer in bytes.
    pub encoded_len: usize,
    /// Root public-key hash `K = T(1)`, `n` bytes long.
    pub k: Vec<u8>,
}

impl LmsPublicKey {
    /// Construct an empty `LmsPublicKey`. The fields are populated by
    /// [`lms_pubkey_decode`] or by callers parsing wire data directly.
    #[must_use]
    pub fn new() -> Self {
        Self {
            encoded: Vec::new(),
            encoded_len: 0,
            k: Vec::new(),
        }
    }
}

impl Default for LmsPublicKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LmsPublicKey {
    fn drop(&mut self) {
        // Zero key material on drop. Although LMS public keys are not secret,
        // we follow the project-wide convention of zeroing all key buffers to
        // prevent accidental leakage when reused via memory pools.
        self.encoded.zeroize();
        self.k.zeroize();
        self.encoded_len = 0;
    }
}

// ===========================================================================
// KeySelection — bitflags matching OpenSSL OSSL_KEYMGMT_SELECT_*
// ===========================================================================

bitflags::bitflags! {
    /// Bitmask selector identifying which key components to operate on.
    ///
    /// Mirrors OpenSSL's `OSSL_KEYMGMT_SELECT_*` constants from
    /// `include/openssl/core_dispatch.h`. Used by [`LmsKey::has_key`],
    /// [`LmsKey::is_valid`], and [`LmsKey::equal`] to scope the comparison
    /// to a subset of the key. LMS keys exposed here are public-only because
    /// LMS signing requires stateful private-key handling that is out of
    /// scope per the AAP.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeySelection: u32 {
        /// Selects key-domain parameters (LMS/LM-OTS algorithm tags).
        const PARAMETERS = 0x01;
        /// Selects the private-key component (unsupported for LMS verify-only).
        const PRIVATE_KEY = 0x02;
        /// Selects the public-key component (root hash + identifier).
        const PUBLIC_KEY = 0x04;
        /// Selects the entire keypair.
        const KEYPAIR = Self::PRIVATE_KEY.bits() | Self::PUBLIC_KEY.bits();
        /// Selects all components (parameters + keypair).
        const ALL = Self::PARAMETERS.bits() | Self::KEYPAIR.bits();
    }
}

// ===========================================================================
// LmsKey — top-level LMS key handle (schema-required type)
// ===========================================================================

/// Top-level LMS key handle, mirroring C `LMS_KEY` from `include/crypto/lms.h`.
///
/// Holds the active parameter sets, the 16-byte tree identifier `I`, the
/// public key (encoded form + root hash), and a reference to the owning
/// library context. LMS signing requires stateful key management and is
/// explicitly out of scope per AAP §0.7 — only the public-key fields are
/// populated by [`LmsKey::new`] / [`lms_pubkey_decode`].
///
/// All sensitive material (the tree identifier `I` and the public-key
/// buffers) is zeroed on drop via [`zeroize`] per AAP §0.7.6.
#[derive(Debug)]
pub struct LmsKey {
    /// Active LMS parameter set, populated when a public key is loaded.
    pub lms_params: Option<&'static LmsParams>,
    /// Active LM-OTS parameter set, populated when a public key is loaded.
    pub ots_params: Option<&'static LmOtsParams>,
    /// 16-byte LMS tree identifier `I`.
    pub id: Vec<u8>,
    /// Encoded public key plus extracted root hash.
    pub pub_key: LmsPublicKey,
    /// Optional library context for provider/algorithm fetching.
    libctx: Option<Arc<LibContext>>,
}

impl LmsKey {
    /// Construct an empty LMS key bound to the given library context.
    ///
    /// The returned key has no parameter sets and no public-key material;
    /// call [`lms_pubkey_decode`] to populate it from wire-format bytes.
    /// Replaces C `ossl_lms_key_new(OSSL_LIB_CTX *ctx)` from
    /// `crypto/lms/lms_key.c`.
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        Self {
            lms_params: None,
            ots_params: None,
            id: Vec::new(),
            pub_key: LmsPublicKey::new(),
            libctx: Some(libctx),
        }
    }

    /// Construct an LMS key without an associated library context.
    ///
    /// Useful for tests and standalone parsing where a `LibContext` is not
    /// required. Production callers should prefer [`LmsKey::new`].
    #[must_use]
    pub fn new_detached() -> Self {
        Self {
            lms_params: None,
            ots_params: None,
            id: Vec::new(),
            pub_key: LmsPublicKey::new(),
            libctx: None,
        }
    }

    /// Return a reference to the optional library context.
    #[must_use]
    pub fn libctx(&self) -> Option<&Arc<LibContext>> {
        self.libctx.as_ref()
    }

    /// Compare two LMS keys in constant time, scoped to the requested
    /// `selection` mask.
    ///
    /// Returns `true` only when every selected component matches:
    /// * `PARAMETERS` — both keys have identical `lms_params` and
    ///   `ots_params` tags;
    /// * `PUBLIC_KEY` — both keys have identical `id` and root-hash `k`;
    /// * `PRIVATE_KEY` — always returns `false` (verify-only);
    ///
    /// Comparison of byte arrays uses [`subtle::ConstantTimeEq::ct_eq`] to
    /// prevent timing side-channel leakage. Replaces C `ossl_lms_key_equal()`
    /// from `crypto/lms/lms_key.c`.
    ///
    /// # Rule compliance
    /// * Rule R5: Returns `bool` (no sentinel values).
    /// * Rule R8: Contains zero `unsafe` code.
    #[must_use]
    pub fn equal(&self, other: &LmsKey, selection: KeySelection) -> bool {
        if selection.contains(KeySelection::PRIVATE_KEY) {
            // LMS private keys require stateful management and are not
            // exposed here; comparing them always fails.
            return false;
        }
        if selection.contains(KeySelection::PARAMETERS) {
            let lms_eq = match (self.lms_params, other.lms_params) {
                (Some(a), Some(b)) => a.lms_type as u32 == b.lms_type as u32,
                (None, None) => true,
                _ => false,
            };
            let ots_eq = match (self.ots_params, other.ots_params) {
                (Some(a), Some(b)) => a.lm_ots_type as u32 == b.lm_ots_type as u32,
                (None, None) => true,
                _ => false,
            };
            if !lms_eq || !ots_eq {
                return false;
            }
        }
        if selection.contains(KeySelection::PUBLIC_KEY) {
            if self.id.len() != other.id.len() {
                return false;
            }
            if self.id.ct_eq(&other.id).unwrap_u8() != 1 {
                return false;
            }
            if self.pub_key.k.len() != other.pub_key.k.len() {
                return false;
            }
            if self.pub_key.k.ct_eq(&other.pub_key.k).unwrap_u8() != 1 {
                return false;
            }
        }
        true
    }

    /// Test whether the requested key components are present and consistent.
    ///
    /// Replaces C `ossl_lms_key_valid()` from `crypto/lms/lms_key.c`.
    ///
    /// * `PARAMETERS` — both `lms_params` and `ots_params` are populated and
    ///   share a hash family.
    /// * `PUBLIC_KEY` — `id` is exactly 16 bytes and `k` matches the
    ///   parameter-set digest size `n`.
    /// * `PRIVATE_KEY` — always returns `false` (verify-only).
    ///
    /// # Rule compliance
    /// * Rule R5: Returns `bool` rather than `0/1` sentinel from C.
    /// * Rule R8: Contains zero `unsafe` code.
    #[must_use]
    pub fn is_valid(&self, selection: KeySelection) -> bool {
        if selection.contains(KeySelection::PRIVATE_KEY) {
            return false;
        }
        if selection.contains(KeySelection::PARAMETERS) {
            let (Some(lms), Some(ots)) = (self.lms_params, self.ots_params) else {
                return false;
            };
            if lms.n != ots.n {
                return false;
            }
        }
        if selection.contains(KeySelection::PUBLIC_KEY) {
            let Some(lms) = self.lms_params else {
                return false;
            };
            if self.id.len() != LMS_SIZE_I {
                return false;
            }
            if self.pub_key.k.len() != lms.n as usize {
                return false;
            }
        }
        true
    }

    /// Test whether the requested key components are populated.
    ///
    /// Differs from [`LmsKey::is_valid`] in that it only checks for
    /// presence — not for size/family consistency. Replaces C
    /// `ossl_lms_key_has()` from `crypto/lms/lms_key.c`.
    ///
    /// # Rule compliance
    /// * Rule R5: Returns `bool` (no sentinels).
    /// * Rule R8: Contains zero `unsafe` code.
    #[must_use]
    pub fn has_key(&self, selection: KeySelection) -> bool {
        if selection.contains(KeySelection::PRIVATE_KEY) {
            return false;
        }
        if selection.contains(KeySelection::PARAMETERS)
            && (self.lms_params.is_none() || self.ots_params.is_none())
        {
            return false;
        }
        if selection.contains(KeySelection::PUBLIC_KEY)
            && (self.id.is_empty() || self.pub_key.k.is_empty())
        {
            return false;
        }
        true
    }

    /// Length in bytes of the encoded LMS public key.
    ///
    /// Returns `4 + 4 + 16 + n = 24 + n` where `n` is the parameter-set
    /// digest size, or `0` if no parameter set is associated with the key.
    /// Replaces C `ossl_lms_pubkey_length()` for a populated key.
    #[must_use]
    pub fn pub_len(&self) -> usize {
        match self.lms_params {
            Some(p) => LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE + LMS_SIZE_I + p.n as usize,
            None => 0,
        }
    }

    /// Bit-strength of the LMS hash collision resistance for this key.
    ///
    /// Equals `n * 8` where `n` is the digest size: 192 bits for `n = 24`
    /// and 256 bits for `n = 32`.
    #[must_use]
    pub fn collision_strength_bits(&self) -> u32 {
        match self.lms_params {
            // n is at most 32, so n * 8 is at most 256, well below u32::MAX.
            Some(p) => p.n.saturating_mul(8),
            None => 0,
        }
    }

    /// Length in bytes of an LMS signature for this key's parameter set.
    ///
    /// Equals `12 + n * (1 + p + h)` per RFC 8554 §5.4, where `p` is the
    /// LM-OTS chain count and `h` is the LMS Merkle-tree height. Returns
    /// `0` when the key has no associated parameter sets.
    ///
    /// # Rule compliance
    /// * Rule R6: All multiplications use checked arithmetic;
    ///   `usize::MAX` is never reached for any registered LMS parameter set.
    #[must_use]
    pub fn sig_len(&self) -> usize {
        match (self.lms_params, self.ots_params) {
            (Some(lms), Some(ots)) => {
                let n = lms.n as usize;
                let p = ots.p as usize;
                let h = lms.h as usize;
                let inner = 1usize.saturating_add(p).saturating_add(h);
                let body = n.saturating_mul(inner);
                12usize.saturating_add(body)
            }
            _ => 0,
        }
    }
}

impl Drop for LmsKey {
    fn drop(&mut self) {
        // Zero the tree identifier on drop. The public-key fields zero
        // themselves via `LmsPublicKey::Drop`. The library context is held
        // by `Arc` and dropped automatically.
        self.id.zeroize();
        self.lms_params = None;
        self.ots_params = None;
    }
}

// ===========================================================================
// LmOtsSig — parsed LM-OTS signature view (schema-required type)
// ===========================================================================

/// Parsed view over an LM-OTS signature borrowed from a wire-format buffer.
///
/// Mirrors C `LM_OTS_SIG` from `include/crypto/lms_sig.h`. The signature
/// layout on the wire is (RFC 8554 §4.5):
/// ```text
/// u32(lmots_type) || C[n] || y_0[n] || y_1[n] || ... || y_{p-1}[n]
/// ```
/// `c` is the salt and `y` is the concatenation of the `p` Winternitz chain
/// values. Both `c` and `y` are borrowed slices into the original signature
/// buffer for zero-copy access.
#[derive(Debug, Clone, Copy)]
pub struct LmOtsSig<'a> {
    /// LM-OTS parameter set indicated by the leading type tag.
    pub params: &'static LmOtsParams,
    /// Salt value `C`, exactly `params.n` bytes.
    pub c: &'a [u8],
    /// Trailing chain values, exactly `params.p * params.n` bytes.
    pub y: &'a [u8],
}

// ===========================================================================
// LmsSig — parsed LMS signature view (schema-required type)
// ===========================================================================

/// Parsed view over an LMS signature borrowed from a wire-format buffer.
///
/// Mirrors C `LMS_SIG` from `include/crypto/lms_sig.h`. The signature layout
/// on the wire is (RFC 8554 §5.4):
/// ```text
/// u32(q) || LMOTS_SIG || u32(lms_type) || path[h * n]
/// ```
/// where `LMOTS_SIG` is laid out as in [`LmOtsSig`]. The authentication
/// path `auth_path` is borrowed from the original buffer for zero-copy
/// access.
#[derive(Debug, Clone, Copy)]
pub struct LmsSig<'a> {
    /// Leaf index `q` (0-based, encoded as 32-bit big-endian on the wire).
    pub q: u32,
    /// Embedded LM-OTS signature.
    pub ots_sig: LmOtsSig<'a>,
    /// LMS parameter set indicated by the trailing type tag.
    pub params: &'static LmsParams,
    /// Authentication path bytes, exactly `params.h * params.n` bytes.
    pub auth_path: &'a [u8],
}

// ===========================================================================
// Standalone signature decoder (schema-required function)
// ===========================================================================

/// Strictly decode an LMS signature into a borrowed [`LmsSig`].
///
/// Validates that the buffer has the exact expected length determined by
/// the LMS and LM-OTS parameter sets carried inside the signature. Cross-
/// checks the embedded type tags against `pub_key`'s expected parameters.
///
/// Translates `crypto/lms/lms_sig_decoder.c::ossl_lms_sig_from_data`.
///
/// # Errors
/// * [`CryptoError::Encoding`] — buffer is too short / too long, or has
///   structurally invalid type tags.
/// * [`CryptoError::Verification`] — embedded tags do not match the
///   public key.
///
/// # Rule compliance
/// * Rule R5: All failure modes return `Err`; no sentinels.
/// * Rule R6: All width conversions use checked arithmetic.
/// * Rule R8: Contains zero `unsafe` code.
pub fn lms_sig_decode<'a>(data: &'a [u8], pub_key: &LmsKey) -> CryptoResult<LmsSig<'a>> {
    let lms = pub_key.lms_params.ok_or_else(|| {
        CryptoError::Key("lms_sig_decode: public key has no LMS parameters".to_string())
    })?;
    let ots = pub_key.ots_params.ok_or_else(|| {
        CryptoError::Key("lms_sig_decode: public key has no LM-OTS parameters".to_string())
    })?;
    let n = lms.n as usize;
    let p = ots.p as usize;
    let h = lms.h as usize;

    // expected_sig_len = 4 (q) + 4 (ots_type) + n (C) + p*n (y) + 4 (lms_type) + h*n (path)
    //                 = 12 + n * (1 + p + h)
    let inner = 1usize.checked_add(p).and_then(|v| v.checked_add(h)).ok_or(
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: 1 + p + h overflow",
        }),
    )?;
    let body = n
        .checked_mul(inner)
        .ok_or(CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: n * (1 + p + h) overflow",
        }))?;
    let expected_sig_len = 12usize.checked_add(body).ok_or(CryptoError::Common(
        CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: 12 + body overflow",
        },
    ))?;
    if data.len() != expected_sig_len {
        return Err(CryptoError::Encoding(format!(
            "lms_sig_decode: signature length {} != expected {}",
            data.len(),
            expected_sig_len
        )));
    }

    // q : 4 bytes
    let q = read_u32_be(&data[0..4])?;
    // 2^h overflow safety: h <= 25 for all registered parameter sets.
    if h >= u32::BITS as usize {
        return Err(CryptoError::Encoding(format!(
            "lms_sig_decode: invalid tree height h={h}"
        )));
    }
    let max_q = 1u32 << h;
    if q >= max_q {
        return Err(CryptoError::Verification(format!(
            "lms_sig_decode: leaf index q={q} >= 2^h={max_q}"
        )));
    }

    // ots_type : 4 bytes
    let ots_tag = read_u32_be(&data[4..8])?;
    let ots_decoded =
        LmOtsType::from_u32(ots_tag).ok_or_else(|| {
            CryptoError::Encoding(format!("lms_sig_decode: invalid LM-OTS tag 0x{ots_tag:08x}"))
        })?;
    if (ots_decoded as u32) != (ots.lm_ots_type as u32) {
        return Err(CryptoError::Verification(format!(
            "lms_sig_decode: LM-OTS tag 0x{ots_tag:08x} does not match public key"
        )));
    }
    let ots_decoded_params = ots_decoded.params();

    // C : n bytes
    let c_start: usize = 8;
    let c_end = c_start.checked_add(n).ok_or(CryptoError::Common(
        CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: c_start + n overflow",
        },
    ))?;
    let c = &data[c_start..c_end];

    // y : p * n bytes
    let pn = p.checked_mul(n).ok_or(CryptoError::Common(
        CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: p * n overflow",
        },
    ))?;
    let y_start = c_end;
    let y_end = y_start.checked_add(pn).ok_or(CryptoError::Common(
        CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: y_start + pn overflow",
        },
    ))?;
    let y = &data[y_start..y_end];

    // lms_type : 4 bytes
    let lms_type_start = y_end;
    let lms_type_end = lms_type_start.checked_add(4).ok_or(CryptoError::Common(
        CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: lms_type_start + 4 overflow",
        },
    ))?;
    let lms_tag = read_u32_be(&data[lms_type_start..lms_type_end])?;
    let lms_decoded =
        LmsType::from_u32(lms_tag).ok_or_else(|| {
            CryptoError::Encoding(format!("lms_sig_decode: invalid LMS tag 0x{lms_tag:08x}"))
        })?;
    if (lms_decoded as u32) != (lms.lms_type as u32) {
        return Err(CryptoError::Verification(format!(
            "lms_sig_decode: LMS tag 0x{lms_tag:08x} does not match public key"
        )));
    }
    let lms_decoded_params = lms_decoded.params();

    // auth_path : h * n bytes
    let hn = h.checked_mul(n).ok_or(CryptoError::Common(
        CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: h * n overflow",
        },
    ))?;
    let path_start = lms_type_end;
    let path_end = path_start.checked_add(hn).ok_or(CryptoError::Common(
        CommonError::ArithmeticOverflow {
            operation: "lms_sig_decode: path_start + hn overflow",
        },
    ))?;
    if path_end != data.len() {
        // Should be unreachable due to the upfront expected_sig_len check.
        return Err(CryptoError::Encoding(format!(
            "lms_sig_decode: trailing data; expected {expected_sig_len} bytes total"
        )));
    }
    let auth_path = &data[path_start..path_end];

    Ok(LmsSig {
        q,
        ots_sig: LmOtsSig {
            params: ots_decoded_params,
            c,
            y,
        },
        params: lms_decoded_params,
        auth_path,
    })
}

// ===========================================================================
// Standalone public-key decoder/length (schema-required functions)
// ===========================================================================

/// Decode an LMS public key from wire format and populate `key` in place.
///
/// Mirrors C `ossl_lms_pubkey_decode()` from
/// `crypto/lms/lms_pubkey_decode.c`. On success, `key.lms_params`,
/// `key.ots_params`, `key.id`, and `key.pub_key` (encoded + extracted root
/// hash) are all populated from the input buffer.
///
/// # Errors
/// * [`CryptoError::Encoding`] — buffer is too short, has invalid tags, or
///   carries a hash family / digest size mismatch between the LMS and
///   LM-OTS parameter sets.
///
/// # Rule compliance
/// * Rule R5: All failure modes return `Err`; no sentinels.
/// * Rule R8: Contains zero `unsafe` code.
pub fn lms_pubkey_decode(data: &[u8], key: &mut LmsKey) -> CryptoResult<()> {
    match LmsPubKey::decode(data)? {
        Some(pk) => {
            // Extract the borrowed view's components into the owning key.
            let id = pk.i().to_vec();
            key.lms_params = Some(pk.lms_params());
            key.ots_params = Some(pk.ots_params());
            key.id = id;
            key.pub_key = LmsPublicKey {
                encoded: data.to_vec(),
                encoded_len: data.len(),
                k: pk.k().to_vec(),
            };
            Ok(())
        }
        None => Err(CryptoError::Encoding(
            "lms_pubkey_decode: malformed LMS public key".to_string(),
        )),
    }
}

/// Compute the wire-format length of an LMS public key from its leading
/// `lms_type` tag.
///
/// Reads the 4-byte big-endian tag at the start of `data`, resolves the LMS
/// parameter set, and returns `4 + 4 + 16 + n = 24 + n` bytes. Mirrors C
/// `ossl_lms_pubkey_length()` from `crypto/lms/lms_pubkey_decode.c`.
///
/// # Errors
/// * [`CryptoError::Encoding`] — buffer is shorter than 4 bytes or the tag
///   does not correspond to a registered LMS algorithm.
///
/// # Rule compliance
/// * Rule R5: Returns `Err` rather than a `0` sentinel for unknown tags.
/// * Rule R6: All width conversions use checked arithmetic.
/// * Rule R8: Contains zero `unsafe` code.
pub fn lms_pubkey_length(data: &[u8]) -> CryptoResult<usize> {
    if data.len() < LMS_SIZE_LMS_TYPE {
        return Err(CryptoError::Encoding(format!(
            "lms_pubkey_length: buffer too short ({} < {LMS_SIZE_LMS_TYPE})",
            data.len()
        )));
    }
    let tag = read_u32_be(&data[..LMS_SIZE_LMS_TYPE])?;
    let lms_type = LmsType::from_u32(tag).ok_or_else(|| {
        CryptoError::Encoding(format!("lms_pubkey_length: invalid LMS tag 0x{tag:08x}"))
    })?;
    Ok(LmsPubKey::encoded_len(lms_type.params()))
}

// ===========================================================================
// Tests — RFC 8554 structural tests and invariant exercises
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Unit tests MAY panic on assertion failure; R9 permits this in test-only code."
)]
mod tests {
    use super::*;

    #[test]
    fn lms_type_discriminants_match_spec() {
        // RFC 8554 §5.1 and SP 800-208 Table 1 tag values.
        assert_eq!(LmsType::Sha256N32H5 as u32, 0x0000_0005);
        assert_eq!(LmsType::Sha256N32H25 as u32, 0x0000_0009);
        assert_eq!(LmsType::Sha256N24H5 as u32, 0x0000_000A);
        assert_eq!(LmsType::Sha256N24H25 as u32, 0x0000_000E);
        assert_eq!(LmsType::ShakeN32H5 as u32, 0x0000_000F);
        assert_eq!(LmsType::ShakeN32H25 as u32, 0x0000_0013);
        assert_eq!(LmsType::ShakeN24H5 as u32, 0x0000_0014);
        assert_eq!(LmsType::ShakeN24H25 as u32, 0x0000_0018);
    }

    #[test]
    fn lm_ots_type_discriminants_match_spec() {
        assert_eq!(LmOtsType::Sha256N32W1 as u32, 0x0000_0001);
        assert_eq!(LmOtsType::Sha256N32W8 as u32, 0x0000_0004);
        assert_eq!(LmOtsType::Sha256N24W1 as u32, 0x0000_0005);
        assert_eq!(LmOtsType::Sha256N24W8 as u32, 0x0000_0008);
        assert_eq!(LmOtsType::ShakeN32W1 as u32, 0x0000_0009);
        assert_eq!(LmOtsType::ShakeN32W8 as u32, 0x0000_000C);
        assert_eq!(LmOtsType::ShakeN24W1 as u32, 0x0000_000D);
        assert_eq!(LmOtsType::ShakeN24W8 as u32, 0x0000_0010);
    }

    #[test]
    fn lms_type_from_u32_roundtrip() {
        for tag in 0x05_u32..=0x18 {
            let t = LmsType::from_u32(tag).expect("valid LMS tag");
            assert_eq!(t as u32, tag);
            // params() should return a table entry with matching lms_type.
            assert_eq!(t.params().lms_type as u32, tag);
        }
        // Out-of-range values reject.
        assert!(LmsType::from_u32(0x00).is_none());
        assert!(LmsType::from_u32(0x04).is_none());
        assert!(LmsType::from_u32(0x19).is_none());
        assert!(LmsType::from_u32(0xFFFF_FFFF).is_none());
    }

    #[test]
    fn lm_ots_type_from_u32_roundtrip() {
        for tag in 0x01_u32..=0x10 {
            let t = LmOtsType::from_u32(tag).expect("valid LM-OTS tag");
            assert_eq!(t as u32, tag);
            assert_eq!(t.params().lm_ots_type as u32, tag);
        }
        assert!(LmOtsType::from_u32(0x00).is_none());
        assert!(LmOtsType::from_u32(0x11).is_none());
        assert!(LmOtsType::from_u32(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn lms_params_table_sizes_match_spec() {
        // Every parameter set: h in {5,10,15,20,25}, n in {24,32}.
        for entry in LMS_PARAMS_TABLE.iter() {
            assert!(
                matches!(entry.h, 5 | 10 | 15 | 20 | 25),
                "unexpected h = {}",
                entry.h
            );
            assert!(
                matches!(entry.n, 24 | 32),
                "unexpected n = {}",
                entry.n
            );
        }
        // Expected ordering within table.
        assert_eq!(LMS_PARAMS_TABLE[0].h, 5);
        assert_eq!(LMS_PARAMS_TABLE[0].n, 32);
        assert_eq!(LMS_PARAMS_TABLE[4].h, 25);
        assert_eq!(LMS_PARAMS_TABLE[5].h, 5);
        assert_eq!(LMS_PARAMS_TABLE[5].n, 24);
    }

    #[test]
    fn lm_ots_params_table_sizes_match_spec() {
        // p values from RFC 8554 / SP 800-208: for n=32 with w in {1,2,4,8}:
        //   w=1: p=265, w=2: p=133, w=4: p=67, w=8: p=34
        // for n=24:
        //   w=1: p=200, w=2: p=101, w=4: p=51, w=8: p=26
        assert_eq!(LM_OTS_PARAMS_TABLE[0].p, 265);  // N=32, w=1
        assert_eq!(LM_OTS_PARAMS_TABLE[1].p, 133);  // N=32, w=2
        assert_eq!(LM_OTS_PARAMS_TABLE[2].p, 67);   // N=32, w=4
        assert_eq!(LM_OTS_PARAMS_TABLE[3].p, 34);   // N=32, w=8
        assert_eq!(LM_OTS_PARAMS_TABLE[4].p, 200);  // N=24, w=1
        assert_eq!(LM_OTS_PARAMS_TABLE[5].p, 101);  // N=24, w=2
        assert_eq!(LM_OTS_PARAMS_TABLE[6].p, 51);   // N=24, w=4
        assert_eq!(LM_OTS_PARAMS_TABLE[7].p, 26);   // N=24, w=8
        // ls values per spec.
        assert_eq!(LM_OTS_PARAMS_TABLE[0].ls, 7);
        assert_eq!(LM_OTS_PARAMS_TABLE[3].ls, 0);
        assert_eq!(LM_OTS_PARAMS_TABLE[4].ls, 8);
    }

    #[test]
    fn lms_ots_coef_extraction() {
        // w=8: coef(s, i, 8) = s[i]
        let s = [0xAA_u8, 0xBB, 0xCC, 0xDD];
        assert_eq!(lms_ots_coef(&s, 0, 8).unwrap(), 0xAA);
        assert_eq!(lms_ots_coef(&s, 3, 8).unwrap(), 0xDD);
        // w=4: 2 coefficients per byte, high nibble first.
        assert_eq!(lms_ots_coef(&s, 0, 4).unwrap(), 0xA);
        assert_eq!(lms_ots_coef(&s, 1, 4).unwrap(), 0xA);
        assert_eq!(lms_ots_coef(&s, 2, 4).unwrap(), 0xB);
        assert_eq!(lms_ots_coef(&s, 3, 4).unwrap(), 0xB);
        // w=2: 4 coefficients per byte, highest 2 bits first.
        // s[0] = 0xAA = 0b1010_1010
        assert_eq!(lms_ots_coef(&s, 0, 2).unwrap(), 0b10);
        assert_eq!(lms_ots_coef(&s, 1, 2).unwrap(), 0b10);
        assert_eq!(lms_ots_coef(&s, 2, 2).unwrap(), 0b10);
        assert_eq!(lms_ots_coef(&s, 3, 2).unwrap(), 0b10);
        // w=1: 8 coefficients per byte, MSB first.
        assert_eq!(lms_ots_coef(&s, 0, 1).unwrap(), 1);
        assert_eq!(lms_ots_coef(&s, 1, 1).unwrap(), 0);
        assert_eq!(lms_ots_coef(&s, 7, 1).unwrap(), 0);
    }

    #[test]
    fn lms_ots_coef_rejects_invalid_w() {
        let s = [0_u8; 4];
        assert!(lms_ots_coef(&s, 0, 0).is_err());
        assert!(lms_ots_coef(&s, 0, 3).is_err());
        assert!(lms_ots_coef(&s, 0, 9).is_err());
    }

    #[test]
    fn inc16_rolls_over_properly() {
        let mut t = [0x00_u8, 0x00];
        inc16(&mut t);
        assert_eq!(t, [0x00, 0x01]);
        let mut t = [0x00_u8, 0xFF];
        inc16(&mut t);
        assert_eq!(t, [0x01, 0x00]);
        // Wrap-around.
        let mut t = [0xFF_u8, 0xFF];
        inc16(&mut t);
        assert_eq!(t, [0x00, 0x00]);
    }

    #[test]
    fn read_u32_be_ok() {
        assert_eq!(read_u32_be(&[0x00, 0x00, 0x00, 0x05]).unwrap(), 5);
        assert_eq!(
            read_u32_be(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap(),
            0xFFFF_FFFF
        );
    }

    #[test]
    fn read_u32_be_rejects_short() {
        assert!(read_u32_be(&[0x00; 3]).is_err());
    }

    #[test]
    fn checksum_all_zero_input() {
        // For n=32 w=8, sum = 32 * (255 - 0) = 32 * 255 = 8160 = 0x1FE0.
        // ls = 0, so checksum bytes = [0x1F, 0xE0].
        let q = [0_u8; 32];
        let cksm = lm_ots_params_checksum(&q, 32, 8, 0).unwrap();
        assert_eq!(cksm, [0x1F, 0xE0]);
    }

    #[test]
    fn checksum_all_max_input() {
        // For n=32 w=8 with s[i] = 0xFF: sum = 32 * (255 - 255) = 0.
        let q = [0xFF_u8; 32];
        let cksm = lm_ots_params_checksum(&q, 32, 8, 0).unwrap();
        assert_eq!(cksm, [0x00, 0x00]);
    }

    #[test]
    fn pubkey_encoded_len() {
        // SHA-256 / N=32 / H=5: 4 + 4 + 16 + 32 = 56
        assert_eq!(LmsPubKey::encoded_len(LmsType::Sha256N32H5.params()), 56);
        // SHA-256 / N=24 / H=5: 4 + 4 + 16 + 24 = 48
        assert_eq!(LmsPubKey::encoded_len(LmsType::Sha256N24H5.params()), 48);
    }

    #[test]
    fn pubkey_decode_rejects_short_input() {
        // Empty, single byte, truncated all reject.
        assert!(LmsPubKey::decode(&[]).unwrap().is_none());
        assert!(LmsPubKey::decode(&[0_u8; 20]).unwrap().is_none());
    }

    #[test]
    fn pubkey_decode_rejects_unknown_lms_type() {
        // lms_type = 0x04 (below valid range).
        let mut encoded = vec![0_u8; 56];
        encoded[3] = 0x04;  // lms_type tag
        encoded[7] = 0x04;  // ots_type tag (valid)
        assert!(LmsPubKey::decode(&encoded).unwrap().is_none());
    }

    #[test]
    fn pubkey_decode_rejects_unknown_ots_type() {
        // lms_type = 0x05 (SHA-256 / N=32 / H=5, total 56 bytes).
        let mut encoded = vec![0_u8; 56];
        encoded[3] = 0x05;  // lms_type tag
        encoded[7] = 0x11;  // ots_type tag (invalid, > 0x10)
        assert!(LmsPubKey::decode(&encoded).unwrap().is_none());
    }

    #[test]
    fn pubkey_decode_rejects_mismatched_hash_families() {
        // lms_type = 0x05 (SHA-256) with ots_type = 0x09 (SHAKE-256): family mismatch.
        let mut encoded = vec![0_u8; 56];
        encoded[3] = 0x05;  // LMS SHA-256 / N=32 / H=5
        encoded[7] = 0x09;  // LM-OTS SHAKE-256 / N=32 / W=1
        assert!(LmsPubKey::decode(&encoded).unwrap().is_none());
    }

    #[test]
    fn pubkey_decode_rejects_mismatched_n() {
        // lms_type = 0x05 (n=32) with ots_type = 0x05 (LM-OTS SHA-256 / N=24):
        // hash family matches but n differs.
        let mut encoded = vec![0_u8; 56];
        encoded[3] = 0x05;  // LMS SHA-256 / N=32 / H=5
        encoded[7] = 0x05;  // LM-OTS SHA-256 / N=24 / W=1
        assert!(LmsPubKey::decode(&encoded).unwrap().is_none());
    }

    #[test]
    fn pubkey_decode_rejects_wrong_length() {
        // Expected length is 56, give 55 bytes.
        let mut encoded = vec![0_u8; 55];
        encoded[3] = 0x05;
        encoded[7] = 0x04;
        assert!(LmsPubKey::decode(&encoded).unwrap().is_none());
    }

    #[test]
    fn pubkey_decode_accepts_valid_sha256_n32() {
        // Hand-build a valid 56-byte pubkey: SHA-256/N=32/H=5 + SHA-256/N=32/W=4.
        let mut encoded = vec![0_u8; 56];
        // lms_type = 0x05 (LMS_SHA256_N32_H5)
        encoded[0..4].copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        // ots_type = 0x03 (LMOTS_SHA256_N32_W4)
        encoded[4..8].copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        // I = 0x00..0x0F
        for i in 0..16 {
            encoded[8 + i] = i as u8;
        }
        // K = 0x10..0x2F
        for i in 0..32 {
            encoded[24 + i] = (0x10 + i) as u8;
        }
        let pk = LmsPubKey::decode(&encoded).unwrap().expect("valid decode");
        assert_eq!(pk.lms_params().lms_type, LmsType::Sha256N32H5);
        assert_eq!(pk.ots_params().lm_ots_type, LmOtsType::Sha256N32W4);
        assert_eq!(pk.i()[0], 0x00);
        assert_eq!(pk.i()[15], 0x0F);
        assert_eq!(pk.k()[0], 0x10);
        assert_eq!(pk.k()[31], 0x2F);
    }

    #[test]
    fn pubkey_decode_accepts_valid_shake_n32() {
        // SHAKE-256/N=32/H=5 + SHAKE-256/N=32/W=8.
        let mut encoded = vec![0_u8; 56];
        encoded[0..4].copy_from_slice(&0x0000_000F_u32.to_be_bytes()); // LMS_SHAKE_N32_H5
        encoded[4..8].copy_from_slice(&0x0000_000C_u32.to_be_bytes()); // LMOTS_SHAKE_N32_W8
        let pk = LmsPubKey::decode(&encoded).unwrap().expect("valid decode");
        assert_eq!(pk.lms_params().lms_type, LmsType::ShakeN32H5);
        assert_eq!(pk.ots_params().lm_ots_type, LmOtsType::ShakeN32W8);
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        // Build a valid pubkey then feed a too-short signature.
        let mut encoded = vec![0_u8; 56];
        encoded[0..4].copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        encoded[4..8].copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        let pk = LmsPubKey::decode(&encoded).unwrap().unwrap();
        // Feed a length that does not match 12 + n*(1 + p + h) = 12 + 32*(1+67+5) = 2348.
        let bad_sig = vec![0_u8; 100];
        assert_eq!(lms_verify(&pk, b"msg", &bad_sig).unwrap(), false);
    }

    #[test]
    fn verify_rejects_mismatched_ots_type_in_signature() {
        // Build a valid pubkey: LMS 0x05 + OTS 0x03.
        let mut encoded = vec![0_u8; 56];
        encoded[0..4].copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        encoded[4..8].copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        let pk = LmsPubKey::decode(&encoded).unwrap().unwrap();
        // Expected sig length: 12 + 32*(1+67+5) = 12 + 32*73 = 12 + 2336 = 2348.
        // LMS_SHA256_N32_H5 h=5; LMOTS_SHA256_N32_W4 n=32 p=67.
        let n = 32_usize;
        let p = 67_usize;
        let h = 5_usize;
        let expected = 12 + n * (1 + p + h);
        assert_eq!(expected, 2348);
        let mut sig = vec![0_u8; expected];
        // Embed a mismatched ots_type (0x04) in the signature.
        sig[LMS_SIZE_Q..LMS_SIZE_Q + LMS_SIZE_OTS_TYPE]
            .copy_from_slice(&0x0000_0004_u32.to_be_bytes());
        // Embed the correct lms_type.
        let lms_type_off = LMS_SIZE_Q + LMS_SIZE_OTS_TYPE + n + p * n;
        sig[lms_type_off..lms_type_off + LMS_SIZE_LMS_TYPE]
            .copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        assert_eq!(lms_verify(&pk, b"msg", &sig).unwrap(), false);
    }

    #[test]
    fn verify_rejects_mismatched_lms_type_in_signature() {
        let mut encoded = vec![0_u8; 56];
        encoded[0..4].copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        encoded[4..8].copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        let pk = LmsPubKey::decode(&encoded).unwrap().unwrap();
        let n = 32_usize;
        let p = 67_usize;
        let h = 5_usize;
        let expected = 12 + n * (1 + p + h);
        let mut sig = vec![0_u8; expected];
        sig[LMS_SIZE_Q..LMS_SIZE_Q + LMS_SIZE_OTS_TYPE]
            .copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        let lms_type_off = LMS_SIZE_Q + LMS_SIZE_OTS_TYPE + n + p * n;
        sig[lms_type_off..lms_type_off + LMS_SIZE_LMS_TYPE]
            .copy_from_slice(&0x0000_0006_u32.to_be_bytes());
        assert_eq!(lms_verify(&pk, b"msg", &sig).unwrap(), false);
    }

    #[test]
    fn verify_rejects_q_out_of_range() {
        let mut encoded = vec![0_u8; 56];
        encoded[0..4].copy_from_slice(&0x0000_0005_u32.to_be_bytes()); // H=5
        encoded[4..8].copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        let pk = LmsPubKey::decode(&encoded).unwrap().unwrap();
        let n = 32_usize;
        let p = 67_usize;
        let h = 5_usize;
        let expected = 12 + n * (1 + p + h);
        let mut sig = vec![0_u8; expected];
        // q = 2^5 = 32 is out of range for h=5 tree (valid q in [0, 32)).
        sig[0..4].copy_from_slice(&32_u32.to_be_bytes());
        sig[LMS_SIZE_Q..LMS_SIZE_Q + LMS_SIZE_OTS_TYPE]
            .copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        let lms_type_off = LMS_SIZE_Q + LMS_SIZE_OTS_TYPE + n + p * n;
        sig[lms_type_off..lms_type_off + LMS_SIZE_LMS_TYPE]
            .copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        assert_eq!(lms_verify(&pk, b"msg", &sig).unwrap(), false);
    }

    #[test]
    fn verify_random_bytes_not_valid() {
        // Fuzz-style smoke test: a randomly-filled signature of the right length
        // should almost certainly NOT validate against a zero-K public key.
        let mut encoded = vec![0_u8; 56];
        encoded[0..4].copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        encoded[4..8].copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        // Use deterministic "random" bytes (pattern 0x5A) for reproducibility.
        for byte in encoded[24..].iter_mut() {
            *byte = 0xA5;
        }
        let pk = LmsPubKey::decode(&encoded).unwrap().unwrap();
        let n = 32_usize;
        let p = 67_usize;
        let h = 5_usize;
        let expected = 12 + n * (1 + p + h);
        let mut sig = vec![0_u8; expected];
        // Fill sig with a deterministic pattern.
        for (idx, byte) in sig.iter_mut().enumerate() {
            *byte = (idx & 0xFF) as u8;
        }
        // Make sure tags are valid so we reach the crypto check.
        sig[0..4].copy_from_slice(&0_u32.to_be_bytes()); // q = 0
        sig[LMS_SIZE_Q..LMS_SIZE_Q + LMS_SIZE_OTS_TYPE]
            .copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        let lms_type_off = LMS_SIZE_Q + LMS_SIZE_OTS_TYPE + n + p * n;
        sig[lms_type_off..lms_type_off + LMS_SIZE_LMS_TYPE]
            .copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        assert_eq!(lms_verify(&pk, b"msg", &sig).unwrap(), false);
    }

    #[test]
    fn convenience_verify_wraps_decode_and_verify() {
        // Unknown pubkey tag: verify() returns Ok(false) end-to-end.
        let bad_pk = vec![0_u8; 56];
        let sig = vec![0_u8; 100];
        assert_eq!(verify(&bad_pk, b"m", &sig).unwrap(), false);
    }

    #[test]
    fn hasher_sha256_and_shake256_produce_n_bytes() {
        // SHA-256 N=32: full output.
        let mut h32 = LmsHasher::new(LmsHashAlg::Sha256);
        h32.update(b"abc").unwrap();
        let mut out = [0_u8; 32];
        h32.finalize_into(&mut out).unwrap();
        // Known SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
        let expected: [u8; 32] = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
            0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
            0xF2, 0x00, 0x15, 0xAD,
        ];
        assert_eq!(out, expected);
        // SHA-256 truncated to N=24.
        let mut h24 = LmsHasher::new(LmsHashAlg::Sha256);
        h24.update(b"abc").unwrap();
        let mut out24 = [0_u8; 24];
        h24.finalize_into(&mut out24).unwrap();
        assert_eq!(out24, expected[..24]);
        // SHAKE-256 N=32: deterministic output of known length.
        let mut sh = LmsHasher::new(LmsHashAlg::Shake256);
        sh.update(b"abc").unwrap();
        let mut sh_out = [0_u8; 32];
        sh.finalize_into(&mut sh_out).unwrap();
        // We don't hardcode SHAKE-256("abc") bytes here; just ensure non-zero output.
        assert!(sh_out.iter().any(|&b| b != 0));
    }

    #[test]
    fn hasher_rejects_oversized_output() {
        let mut h = LmsHasher::new(LmsHashAlg::Sha256);
        h.update(b"x").unwrap();
        let mut out = [0_u8; LMS_MAX_DIGEST_SIZE + 1];
        let r = h.finalize_into(&mut out);
        assert!(r.is_err());
    }

    #[test]
    fn compute_tc_from_path_structural() {
        // h=5, n=32: path must be 5 * 32 = 160 bytes.
        let lms = LmsType::Sha256N32H5.params();
        let i = [0xAA_u8; 16];
        let q = 7_u32.to_be_bytes();
        let kc = vec![0xCC_u8; 32];
        // Valid shape should return a 32-byte digest.
        let path = vec![0xDD_u8; 5 * 32];
        let tc = lms_sig_compute_tc_from_path(lms, &i, q, &kc, &path).unwrap();
        assert_eq!(tc.len(), 32);
        // Wrong-length path should error (internal invariant violation).
        let short = vec![0xDD_u8; 5 * 32 - 1];
        assert!(lms_sig_compute_tc_from_path(lms, &i, q, &kc, &short).is_err());
        // Out-of-range q should error.
        let q_bad = 32_u32.to_be_bytes();
        assert!(lms_sig_compute_tc_from_path(lms, &i, q_bad, &kc, &path).is_err());
    }

    #[test]
    fn compute_tc_different_q_yields_different_root() {
        // Changing `q` must change the recomputed root even with the same Kc and
        // path (because node_num = 2^h + q is absorbed into the leaf hash).
        let lms = LmsType::Sha256N32H5.params();
        let i = [0x01_u8; 16];
        let kc = vec![0x02_u8; 32];
        let path = vec![0x03_u8; 5 * 32];
        let tc0 = lms_sig_compute_tc_from_path(
            lms,
            &i,
            0_u32.to_be_bytes(),
            &kc,
            &path,
        )
        .unwrap();
        let tc1 = lms_sig_compute_tc_from_path(
            lms,
            &i,
            1_u32.to_be_bytes(),
            &kc,
            &path,
        )
        .unwrap();
        assert_ne!(tc0, tc1);
    }

    #[test]
    fn lm_ots_compute_pubkey_length_matches_n() {
        // SHA-256 / N=32 / W=4: p = 67, so y must be 67 * 32 = 2144 bytes.
        let ots = LmOtsType::Sha256N32W4.params();
        let i = [0_u8; 16];
        let q = 0_u32.to_be_bytes();
        let c = vec![0_u8; 32];
        let y = vec![0_u8; 67 * 32];
        let kc = lm_ots_compute_pubkey(ots, &i, q, &c, &y, b"message").unwrap();
        assert_eq!(kc.len(), 32);
    }

    #[test]
    fn lm_ots_compute_pubkey_rejects_wrong_c_length() {
        let ots = LmOtsType::Sha256N32W4.params();
        let i = [0_u8; 16];
        let q = 0_u32.to_be_bytes();
        let c = vec![0_u8; 31]; // wrong — should be 32
        let y = vec![0_u8; 67 * 32];
        assert!(lm_ots_compute_pubkey(ots, &i, q, &c, &y, b"msg").is_err());
    }

    #[test]
    fn lm_ots_compute_pubkey_rejects_wrong_y_length() {
        let ots = LmOtsType::Sha256N32W4.params();
        let i = [0_u8; 16];
        let q = 0_u32.to_be_bytes();
        let c = vec![0_u8; 32];
        let y = vec![0_u8; 67 * 32 - 1];
        assert!(lm_ots_compute_pubkey(ots, &i, q, &c, &y, b"msg").is_err());
    }

    #[test]
    fn lm_ots_compute_pubkey_deterministic() {
        // Same input must produce the same output (baseline sanity).
        let ots = LmOtsType::Sha256N32W8.params();
        let i = [0x55_u8; 16];
        let q = 0x1234_5678_u32.to_be_bytes();
        let c = vec![0x77_u8; 32];
        let y = vec![0x99_u8; 34 * 32]; // p=34 for w=8
        let msg = b"LMS deterministic test vector";
        let kc1 = lm_ots_compute_pubkey(ots, &i, q, &c, &y, msg).unwrap();
        let kc2 = lm_ots_compute_pubkey(ots, &i, q, &c, &y, msg).unwrap();
        assert_eq!(kc1, kc2);
    }

    #[test]
    fn lm_ots_compute_pubkey_different_msg_different_output() {
        let ots = LmOtsType::Sha256N32W8.params();
        let i = [0x55_u8; 16];
        let q = 0_u32.to_be_bytes();
        let c = vec![0x77_u8; 32];
        let y = vec![0x99_u8; 34 * 32];
        let k1 = lm_ots_compute_pubkey(ots, &i, q, &c, &y, b"msg1").unwrap();
        let k2 = lm_ots_compute_pubkey(ots, &i, q, &c, &y, b"msg2").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn lm_ots_compute_pubkey_shake_variants() {
        // Exercise the SHAKE-256 path to ensure LmsHasher dispatches correctly.
        let ots = LmOtsType::ShakeN32W8.params();
        let i = [0_u8; 16];
        let q = 0_u32.to_be_bytes();
        let c = vec![0_u8; 32];
        let y = vec![0_u8; 34 * 32];
        let kc = lm_ots_compute_pubkey(ots, &i, q, &c, &y, b"shake test").unwrap();
        assert_eq!(kc.len(), 32);
        // SHAKE output should differ from SHA-256 output for same input.
        let ots_sha = LmOtsType::Sha256N32W8.params();
        let kc_sha =
            lm_ots_compute_pubkey(ots_sha, &i, q, &c, &y, b"shake test").unwrap();
        assert_ne!(kc, kc_sha);
    }

    #[test]
    fn lm_ots_compute_pubkey_n24_variants() {
        // N=24 path (SHA-256/192 truncated).
        let ots = LmOtsType::Sha256N24W8.params();
        let i = [0_u8; 16];
        let q = 0_u32.to_be_bytes();
        let c = vec![0_u8; 24];
        let y = vec![0_u8; 26 * 24]; // p=26 for N=24 w=8
        let kc = lm_ots_compute_pubkey(ots, &i, q, &c, &y, b"n24 test").unwrap();
        assert_eq!(kc.len(), 24);
    }

    #[test]
    fn verify_never_panics_on_truncated_input() {
        // Ensure bounds checks catch every truncation without panicking.
        let mut encoded = vec![0_u8; 56];
        encoded[0..4].copy_from_slice(&0x0000_0005_u32.to_be_bytes());
        encoded[4..8].copy_from_slice(&0x0000_0003_u32.to_be_bytes());
        let pk = LmsPubKey::decode(&encoded).unwrap().unwrap();
        // Feed signatures of every length from 0 through 200 — all should
        // return false structurally.
        for len in 0_usize..=200 {
            let sig = vec![0_u8; len];
            let r = lms_verify(&pk, b"msg", &sig);
            assert!(matches!(r, Ok(false)));
        }
    }

    #[test]
    fn all_20_lms_parameter_sets_decode() {
        // For every LMS type, build a minimum-viable pubkey and confirm it decodes.
        // We pair each LMS type with an OTS type that matches its (hash_alg, n).
        let pairs: [(u32, u32); 20] = [
            // SHA-256 / N=32 LMS (0x05..=0x09) with SHA-256 / N=32 OTS (0x01..=0x04)
            (0x05, 0x03), (0x06, 0x03), (0x07, 0x03), (0x08, 0x03), (0x09, 0x03),
            // SHA-256 / N=24 LMS (0x0A..=0x0E) with SHA-256 / N=24 OTS (0x05..=0x08)
            (0x0A, 0x07), (0x0B, 0x07), (0x0C, 0x07), (0x0D, 0x07), (0x0E, 0x07),
            // SHAKE-256 / N=32 LMS (0x0F..=0x13) with SHAKE-256 / N=32 OTS (0x09..=0x0C)
            (0x0F, 0x0B), (0x10, 0x0B), (0x11, 0x0B), (0x12, 0x0B), (0x13, 0x0B),
            // SHAKE-256 / N=24 LMS (0x14..=0x18) with SHAKE-256 / N=24 OTS (0x0D..=0x10)
            (0x14, 0x0F), (0x15, 0x0F), (0x16, 0x0F), (0x17, 0x0F), (0x18, 0x0F),
        ];
        for (lms_tag, ots_tag) in pairs {
            let t = LmsType::from_u32(lms_tag).unwrap();
            let lms = t.params();
            let mut encoded = vec![0_u8; LmsPubKey::encoded_len(lms)];
            encoded[0..4].copy_from_slice(&lms_tag.to_be_bytes());
            encoded[4..8].copy_from_slice(&ots_tag.to_be_bytes());
            let pk = LmsPubKey::decode(&encoded).unwrap();
            assert!(pk.is_some(), "pair ({lms_tag:#x}, {ots_tag:#x}) should decode");
            let pk = pk.unwrap();
            assert_eq!(pk.lms_params().lms_type as u32, lms_tag);
            assert_eq!(pk.ots_params().lm_ots_type as u32, ots_tag);
        }
    }
}
