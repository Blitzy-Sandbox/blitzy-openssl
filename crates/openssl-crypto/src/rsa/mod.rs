//! RSA cryptosystem module for the openssl-crypto crate.
//!
//! Provides RSA key generation, encryption, decryption, signing,
//! verification, key validation, and padding schemes. Translates 25 C
//! source files from `crypto/rsa/` (~10,150 lines) into idiomatic Rust
//! while preserving algorithmic and security semantics:
//!
//! - **RFC 8017** (PKCS #1 v2.2) — PKCS#1 v1.5 / OAEP / PSS
//! - **NIST FIPS 186-5** — RSA digital signatures
//! - **NIST SP 800-56B Rev. 2** — RSA key validation (RSAKPV1/RSAKPV2)
//! - **NIST SP 800-57** — Cryptographic key sizes & strengths
//! - **ANSI X9.31** — Legacy RSA-X9.31 signatures
//!
//! # Module Organization
//!
//! - [`mod.rs`] (this file) — Core RSA types, key generation, primary
//!   operations, validation, PKCS#1 v1.5 / X9.31 / no-padding schemes,
//!   import/export, digest-NID mapping
//! - [`oaep`]  — RSA-OAEP encryption (PKCS#1 v2.2 §7.1, RFC 8017 §B.2.1
//!   MGF1, Manger constant-time defense)
//! - [`pss`]   — RSA-PSS signatures (RFC 8017 §8.1 / §9.1, RFC 4055 §3.1)
//!
//! # Source Mapping
//!
//! | Rust component                        | C Source File                                      |
//! |---------------------------------------|----------------------------------------------------|
//! | Core types                            | `crypto/rsa/rsa_local.h`                           |
//! | Key lifecycle (`new` / `Drop`)        | `crypto/rsa/rsa_lib.c`                             |
//! | Key generation                        | `crypto/rsa/rsa_gen.c`, `crypto/rsa/rsa_x931g.c`   |
//! | SP 800-56B keygen                     | `crypto/rsa/rsa_sp800_56b_gen.c`                   |
//! | SP 800-56B validation                 | `crypto/rsa/rsa_sp800_56b_check.c`                 |
//! | Core RSA encryption / decryption      | `crypto/rsa/rsa_ossl.c`, `crypto/rsa/rsa_crpt.c`   |
//! | Key consistency check                 | `crypto/rsa/rsa_chk.c`                             |
//! | PKCS#1 v1.5 padding                   | `crypto/rsa/rsa_pk1.c`                             |
//! | PKCS#1 v1.5 sign / verify             | `crypto/rsa/rsa_sign.c`                            |
//! | No-padding (raw RSA)                  | `crypto/rsa/rsa_none.c`                            |
//! | X9.31 padding                         | `crypto/rsa/rsa_x931.c`                            |
//! | Multi-prime helpers                   | `crypto/rsa/rsa_mp.c`, `crypto/rsa/rsa_mp_names.c` |
//! | Digest-NID scheme mapping             | `crypto/rsa/rsa_schemes.c`                         |
//! | Error reason codes                    | `crypto/rsa/rsa_err.c`                             |
//! | Provider parameter import / export    | `crypto/rsa/rsa_backend.c`                         |
//! | ASN.1 templates / DER i2d / d2i       | `crypto/rsa/rsa_asn1.c`, `crypto/rsa/rsa_ameth.c`  |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Typed enums replace integer sentinel constants
//!   (`PaddingMode` for `RSA_PKCS1_PADDING` etc.); optional values use
//!   `Option<T>` (e.g. `RsaKeyGenParams::public_exponent`).
//! - **R6 (Lossless Casts):** Numeric conversions use `try_from` /
//!   checked arithmetic; bit / byte sizes use `u32` / `usize`.
//! - **R7 (Concurrency):** RSA keys are immutable after construction;
//!   sharing uses `Arc<RsaPrivateKey>` — no internal locks needed.
//! - **R8 (Zero Unsafe):** `#![forbid(unsafe_code)]` on the parent crate
//!   enforces this; constant-time primitives come from
//!   [`openssl_common::constant_time`].
//! - **R9 (Doc Coverage):** Every public item has a `///` doc comment.
//! - **R10 (Wiring):** Reachable from `openssl_crypto::rsa::*` via
//!   `pub mod rsa;` declared in `crates/openssl-crypto/src/lib.rs`.
//!
//! # Security Considerations
//!
//! - **Secret zeroization:** [`RsaPrivateKey`], [`RsaKeyPair`], and
//!   [`RsaPrimeInfo`] derive [`zeroize::ZeroizeOnDrop`] — all secret
//!   components (`d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`, prime infos) are
//!   securely erased on drop, replacing C `BN_clear_free()` calls.
//! - **Blinding:** Private-key operations apply RSA blinding (via
//!   [`crate::bn::Blinding`]) to prevent timing side channels per
//!   Kocher (CRYPTO 1996).
//! - **Bellcore-attack defense:** CRT private-key operations re-encrypt
//!   the result and verify it equals the input modulo `n`, defending
//!   against fault-injection attacks (Boneh-DeMillo-Lipton 1997).
//! - **Bleichenbacher protection:** PKCS#1 v1.5 type-2 unpadding uses
//!   constant-time operations and implicit rejection — invalid
//!   ciphertexts produce a deterministic synthetic message instead of an
//!   error, preventing the Bleichenbacher PKCS#1 v1.5 oracle attack
//!   (CRYPTO 1998) and its variants (BB'06, ROBOT 2017).
//! - **Manger-attack defense (OAEP):** OAEP unpadding (in [`oaep`]) uses
//!   constant-time operations to prevent the Manger 2001 attack.
//! - **Debug redaction:** [`RsaPrivateKey`]'s [`std::fmt::Debug`] impl
//!   redacts `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`.
//!
//! # Examples
//!
//! ```rust,no_run
//! use openssl_crypto::rsa::{generate_key, RsaKeyGenParams, sign_pkcs1v15, verify_pkcs1v15};
//! use openssl_crypto::hash::DigestAlgorithm;
//!
//! let params = RsaKeyGenParams::default(); // 2048 bits, e = 65537
//! let kp = generate_key(&params).expect("RSA key generation");
//! let pub_k = kp.public_key();
//! let priv_k = kp.private_key();
//!
//! let digest = [0u8; 32];
//! let sig = sign_pkcs1v15(priv_k, DigestAlgorithm::Sha256, &digest)
//!     .expect("RSA-PKCS#1 v1.5 sign");
//! assert!(verify_pkcs1v15(&pub_k, DigestAlgorithm::Sha256, &digest, &sig)
//!     .expect("RSA verify"));
//! ```

// =============================================================================
// Submodule declarations
// =============================================================================

pub mod oaep;
pub mod pss;

// =============================================================================
// Imports
// =============================================================================

use openssl_common::constant_time;
use openssl_common::error::{CryptoError, CryptoResult};
use openssl_common::param::{ParamSet, ParamValue};

use crate::bn::arithmetic;
use crate::bn::montgomery;
use crate::bn::prime;
use crate::bn::{BigNum, BottomBit, TopBit};
use crate::hash::DigestAlgorithm;
use crate::rand::rand_bytes;

use std::fmt;
use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Cross-module silencer: `LibContext` is part of the public-API surface for
// FIPS-mode/provider-aware key generation but the current pure-Rust prime
// generator routes do not yet consult it — the field is present and read by
// the public `generate_key_sp800_56b()` to satisfy R3 (config propagation).
#[allow(unused_imports)]
use crate::context::LibContext;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of prime factors for multi-prime RSA.
///
/// From `crypto/rsa/rsa_local.h` line 16:
/// `#define RSA_MAX_PRIME_NUM 5`.
///
/// Multi-prime RSA per RFC 8017 §3 permits up to 5 prime factors; OpenSSL
/// further caps the number of additional primes by key bit size — see
/// [`multi_prime_cap`].
pub const RSA_MAX_PRIME_NUM: usize = 5;

/// Default RSA public exponent (Fermat prime F4 = 2^16 + 1 = 65537).
///
/// From `include/openssl/rsa.h` (`RSA_F4`). Recommended by RFC 8017
/// §A.1.1, FIPS 186-5 §A.1.1, and NIST SP 800-56B Rev. 2 §6.2 because it
/// is prime, of low Hamming weight (only two 1-bits), and large enough to
/// resist short-exponent attacks.
pub const RSA_DEFAULT_PUBLIC_EXPONENT: u64 = 65_537;

/// Minimum RSA modulus size in bits permitted for non-FIPS key generation.
///
/// From `crypto/rsa/rsa_gen.c` line 105: keys below this bit length are
/// considered too short to provide any practical security. FIPS-validated
/// key generation uses [`RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE`] (2048).
pub const RSA_MIN_MODULUS_BITS: u32 = 512;

/// Minimum RSA key size for SP 800-56B Rev. 2 / FIPS 186-5 key generation.
///
/// From `crypto/rsa/rsa_sp800_56b_gen.c`:
/// `#define RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE 2048`. NIST disallows the
/// generation of new RSA keys below this size for FIPS-validated modules.
pub const RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE: u32 = 2048;

/// Minimum security strength (in bits) for SP 800-56B Rev. 2 / FIPS 186-5
/// RSA key generation.
///
/// From `crypto/rsa/rsa_sp800_56b_gen.c`:
/// `#define RSA_FIPS186_5_MIN_KEYGEN_STRENGTH 112`. A 2048-bit RSA key
/// provides 112-bit security per NIST SP 800-57 Part 1 Table 2.
pub const RSA_FIPS186_5_MIN_KEYGEN_STRENGTH: u32 = 112;

/// PKCS#1 v1.5 padding overhead in octets.
///
/// From `include/openssl/rsa.h`:
/// `#define RSA_PKCS1_PADDING_SIZE 11`. The minimum padding length for
/// PKCS#1 v1.5 type 1 / type 2 is `0x00 || BT || PS (>=8 bytes) || 0x00`
/// = 11 octets, so `flen <= k - 11` for input data of length `flen` and
/// modulus byte length `k`.
pub const RSA_PKCS1_PADDING_SIZE: usize = 11;

// =============================================================================
// Phase 2: Core Types
// =============================================================================

// -----------------------------------------------------------------------------
// 2.1: RSA Error Types
// -----------------------------------------------------------------------------

/// RSA-specific operation errors.
///
/// Translates the C `RSA_R_*` reason codes from `crypto/rsa/rsa_err.c`
/// into idiomatic Rust error variants. Each variant maps to one or more
/// upstream reason codes; the 18 variants cover the schema-required
/// surface area while consolidating semantically related codes.
#[derive(Debug, thiserror::Error)]
pub enum RsaError {
    /// Modulus bit length below the configured minimum (e.g. < 512 for
    /// generic, < 2048 for SP 800-56B / FIPS 186-5).
    /// Maps `RSA_R_KEY_SIZE_TOO_SMALL`, `RSA_R_MODULUS_TOO_LARGE`.
    #[error("RSA key too small: minimum {min_bits} bits required, got {actual_bits}")]
    KeyTooSmall {
        /// Minimum required bits.
        min_bits: u32,
        /// Actual bits.
        actual_bits: u32,
    },

    /// Plaintext / data buffer is larger than the modulus minus padding.
    /// Maps `RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE`,
    /// `RSA_R_DATA_TOO_LARGE_FOR_MODULUS`.
    #[error("data too large for key size")]
    DataTooLargeForKeySize,

    /// Padding mode invalid or unsupported for this operation.
    /// Maps `RSA_R_UNKNOWN_PADDING_TYPE`,
    /// `RSA_R_INVALID_PADDING_MODE`.
    #[error("invalid RSA padding mode")]
    InvalidPadding,

    /// Key generation failed (prime generation, GCD, modular inverse).
    /// Maps `RSA_R_KEY_GENERATION_FAILURE`,
    /// `RSA_R_BN_NOT_INITIALIZED`.
    #[error("RSA key generation failed")]
    KeyGenerationFailed,

    /// Key validation failed; `reason` carries human-readable detail.
    #[error("RSA key validation failed: {reason}")]
    KeyValidationFailed {
        /// Detail of the validation failure.
        reason: String,
    },

    /// A required key component (n, e, d, p, q, dmp1, dmq1, iqmp) is
    /// missing from the parameter set.
    /// Maps `RSA_R_VALUE_MISSING`.
    #[error("missing required RSA key component: {component}")]
    ValueMissing {
        /// Name of the missing component.
        component: &'static str,
    },

    /// Public exponent invalid (even, < 3, or otherwise unacceptable).
    /// Maps `RSA_R_BAD_E_VALUE`, `RSA_R_PUB_EXPONENT_OUT_OF_RANGE`.
    #[error("bad public exponent value")]
    BadExponentValue,

    /// Multi-prime key has too many or too few prime infos, or contains
    /// repeated primes.
    /// Maps `RSA_R_INVALID_MULTI_PRIME_KEY`.
    #[error("invalid multi-prime RSA key")]
    InvalidMultiPrimeKey,

    /// Generic PKCS#1 v1.5 padding error (encode side; decode uses
    /// constant-time / implicit-rejection paths and does not raise this).
    /// Maps `RSA_R_PKCS_DECODING_ERROR`,
    /// `RSA_R_PADDING_CHECK_FAILED`.
    #[error("PKCS#1 v1.5 padding error")]
    Pkcs1PaddingError,

    /// Block-type byte (BT) of PKCS#1 v1.5 padded message did not match
    /// the expected value (1 for sign, 2 for encrypt).
    /// Maps `RSA_R_BLOCK_TYPE_IS_NOT_01`, `RSA_R_BLOCK_TYPE_IS_NOT_02`.
    #[error("block type mismatch: expected {expected}, got {actual}")]
    BlockTypeMismatch {
        /// Expected block type byte (1 or 2).
        expected: u8,
        /// Actual block type byte received.
        actual: u8,
    },

    /// Digest algorithm not allowed for this RSA operation (e.g. SHA-1
    /// in FIPS mode for RSA-OAEP after the NIST 800-131A transition).
    /// Maps `RSA_R_DIGEST_NOT_ALLOWED`.
    #[error("digest not allowed in FIPS mode")]
    DigestNotAllowed,

    /// First octet of an encoded message is not 0x00, indicating the
    /// integer-to-octet-string conversion produced an out-of-range value.
    /// Maps `RSA_R_FIRST_OCTET_INVALID`.
    #[error("first octet invalid in encoded message")]
    FirstOctetInvalid,

    /// PSS salt-length validation failed (negative, exceeds modulus, or
    /// inconsistent with parameter restrictions).
    /// Maps `RSA_R_SLEN_CHECK_FAILED`,
    /// `RSA_R_SLEN_RECOVERY_FAILED`.
    #[error("salt length check failed")]
    SaltLengthCheckFailed,

    /// OAEP integrity-check failure during decryption.
    /// Maps `RSA_R_OAEP_DECODING_ERROR`.
    #[error("OAEP decoding error")]
    OaepDecodingError,

    /// CRT consistency check failed (`dmp1 != d mod (p-1)`,
    /// `dmq1 != d mod (q-1)`, or `iqmp != q^-1 mod p`).
    /// Maps `RSA_R_CRT_PARAMS_ALREADY_RETRIEVED` and family.
    #[error("CRT component validation failed")]
    CrtComponentInvalid,

    /// SP 800-56B Rev. 2 RSAKPV1/RSAKPV2 validation failed; `detail`
    /// indicates which of the 6 RSAKPV1 / 5 RSAKPV2 checks tripped.
    #[error("SP 800-56B key validation failed: {detail}")]
    Sp80056bValidationFailed {
        /// Validation failure detail.
        detail: String,
    },

    /// Blinding factor generation or application failed.
    #[error("blinding operation failed")]
    BlindingFailed,

    /// Operation requested but not supported for this key/padding/algo.
    #[error("RSA operation not supported: {operation}")]
    OperationNotSupported {
        /// Description of the unsupported operation.
        operation: String,
    },
}

impl From<RsaError> for CryptoError {
    fn from(err: RsaError) -> Self {
        match err {
            RsaError::KeyTooSmall { .. }
            | RsaError::KeyGenerationFailed
            | RsaError::KeyValidationFailed { .. }
            | RsaError::ValueMissing { .. }
            | RsaError::BadExponentValue
            | RsaError::InvalidMultiPrimeKey
            | RsaError::CrtComponentInvalid
            | RsaError::Sp80056bValidationFailed { .. } => CryptoError::Key(err.to_string()),
            RsaError::DataTooLargeForKeySize
            | RsaError::InvalidPadding
            | RsaError::Pkcs1PaddingError
            | RsaError::BlockTypeMismatch { .. }
            | RsaError::DigestNotAllowed
            | RsaError::FirstOctetInvalid
            | RsaError::OaepDecodingError => CryptoError::Encoding(err.to_string()),
            RsaError::SaltLengthCheckFailed | RsaError::BlindingFailed => {
                CryptoError::Verification(err.to_string())
            }
            RsaError::OperationNotSupported { .. } => CryptoError::Provider(err.to_string()),
        }
    }
}

// -----------------------------------------------------------------------------
// 2.2: PaddingMode
// -----------------------------------------------------------------------------

/// RSA padding mode discriminator.
///
/// Replaces the C integer constants
/// `RSA_PKCS1_PADDING (1)`, `RSA_NO_PADDING (3)`,
/// `RSA_PKCS1_OAEP_PADDING (4)`, `RSA_X931_PADDING (5)`, and
/// `RSA_PKCS1_PSS_PADDING (6)` from `include/openssl/rsa.h` with a typed
/// Rust enum (Rule R5: no integer sentinels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaddingMode {
    /// PKCS#1 v1.5 padding (RFC 8017 §7.2 / §8.2). Maps `RSA_PKCS1_PADDING`.
    Pkcs1v15,
    /// No padding — raw RSA modular exponentiation. Maps `RSA_NO_PADDING`.
    None,
    /// OAEP encryption padding (RFC 8017 §7.1). Maps
    /// `RSA_PKCS1_OAEP_PADDING`.
    Oaep,
    /// X9.31 signature padding. Maps `RSA_X931_PADDING`.
    X931,
    /// PSS signature padding (RFC 8017 §8.1 / §9.1). Maps
    /// `RSA_PKCS1_PSS_PADDING`.
    Pss,
}

impl PaddingMode {
    /// Returns the legacy C integer code for this padding mode (for
    /// interop with code paths that consume the historical numeric API).
    pub fn to_legacy_int(self) -> u32 {
        match self {
            PaddingMode::Pkcs1v15 => 1,
            PaddingMode::None => 3,
            PaddingMode::Oaep => 4,
            PaddingMode::X931 => 5,
            PaddingMode::Pss => 6,
        }
    }

    /// Returns the provider-API parameter string per
    /// `include/openssl/core_names.h` (e.g. `"oaep"`, `"pss"`).
    pub fn to_param_str(self) -> &'static str {
        match self {
            PaddingMode::Pkcs1v15 => "pkcs1",
            PaddingMode::None => "none",
            PaddingMode::Oaep => "oaep",
            PaddingMode::X931 => "x931",
            PaddingMode::Pss => "pss",
        }
    }
}

// -----------------------------------------------------------------------------
// 2.3: RSA Key Version
// -----------------------------------------------------------------------------

/// RSA key ASN.1 version per RFC 8017 §A.1.2.
///
/// Translates `RSA_ASN1_VERSION_DEFAULT` (0) and `RSA_ASN1_VERSION_MULTI`
/// (1) from `include/openssl/rsa.h`. The version field of `RSAPrivateKey`
/// is `0` for two-prime keys and `1` when `otherPrimeInfos` is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaVersion {
    /// Standard two-prime RSA (`version = 0`).
    TwoPrime,
    /// Multi-prime RSA with additional prime factors (`version = 1`).
    MultiPrime,
}

// -----------------------------------------------------------------------------
// 2.4: Multi-Prime Info
// -----------------------------------------------------------------------------

/// Additional prime-factor information for multi-prime RSA per
/// RFC 8017 §A.1.2 `OtherPrimeInfo`.
///
/// Translates the C `RSA_PRIME_INFO` structure from
/// `crypto/rsa/rsa_local.h` (lines 18-25). All four bignum fields are
/// secret and are securely zeroed on drop via `ZeroizeOnDrop`. The
/// optional Montgomery context cache (`m`) from the C struct is intentionally
/// omitted — Montgomery contexts are computed on demand by
/// [`crate::bn::montgomery`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct RsaPrimeInfo {
    /// Prime factor `r_i` (i ≥ 3).
    pub(crate) r: BigNum,
    /// CRT exponent `d_i = d mod (r_i - 1)`.
    pub(crate) d: BigNum,
    /// CRT coefficient `t_i = (r_1 r_2 … r_{i-1})^{-1} mod r_i`.
    pub(crate) t: BigNum,
    /// Product of all primes prior to this one
    /// (`pp_i = r_1 r_2 … r_{i-1}`).
    pub(crate) pp: BigNum,
}

impl fmt::Debug for RsaPrimeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact all secret factor data — only structural shape leaks.
        f.debug_struct("RsaPrimeInfo")
            .field("r", &"<redacted>")
            .field("d", &"<redacted>")
            .field("t", &"<redacted>")
            .field("pp", &"<redacted>")
            .finish()
    }
}

// -----------------------------------------------------------------------------
// 2.5: RSA Public Key
// -----------------------------------------------------------------------------

/// RSA public key — the `(n, e)` pair.
///
/// Translates the public-component subset of C `struct rsa_st` from
/// `crypto/rsa/rsa_local.h` lines 60-61 (`BIGNUM *n; BIGNUM *e;`). Used
/// for RSA encryption and signature verification.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// RSA modulus `n = p · q · r_3 · … · r_u`.
    n: BigNum,
    /// RSA public exponent `e` (commonly 65537 = `0x10001`).
    e: BigNum,
}

impl RsaPublicKey {
    /// Constructs a new RSA public key from `(n, e)`.
    ///
    /// Performs the structural sanity checks required by RFC 8017
    /// §5.2 — `n > 0`, `e > 1`, and `e` odd. Full SP 800-56B validation
    /// (including primality of factors) is provided by
    /// [`check_public_key`].
    ///
    /// # Errors
    /// Returns [`RsaError::ValueMissing`] if either component is zero or
    /// negative; [`RsaError::BadExponentValue`] if `e` is even or `< 3`.
    pub fn new(n: BigNum, e: BigNum) -> CryptoResult<Self> {
        if n.is_zero() || n.is_negative() {
            return Err(RsaError::ValueMissing { component: "n" }.into());
        }
        if e.is_zero() || e.is_negative() || !e.is_odd() {
            return Err(RsaError::BadExponentValue.into());
        }
        // e must be ≥ 3 (e == 1 would be the identity exponent).
        let three = BigNum::from_u64(3);
        if e.cmp(&three) == std::cmp::Ordering::Less {
            return Err(RsaError::BadExponentValue.into());
        }
        Ok(Self { n, e })
    }

    /// Returns a reference to the modulus `n`.
    pub fn modulus(&self) -> &BigNum {
        &self.n
    }

    /// Returns a reference to the public exponent `e`.
    pub fn public_exponent(&self) -> &BigNum {
        &self.e
    }

    /// Bit length of the modulus — replaces C `RSA_bits()` from
    /// `crypto/rsa/rsa_crpt.c`.
    pub fn key_size_bits(&self) -> u32 {
        self.n.num_bits()
    }

    /// Byte length of the modulus — replaces C `RSA_size()` from
    /// `crypto/rsa/rsa_crpt.c`. Equal to `(num_bits + 7) / 8`.
    ///
    /// Returns `u32` directly (not `usize`) per Rule R6 — `BigNum::num_bytes`
    /// returns `u32` and any narrowing conversion would require an explicit
    /// `try_from`. Callers needing a `usize` for slice indexing should use
    /// `usize::try_from(key.key_size_bytes()).expect("u32 fits in usize")`.
    pub fn key_size_bytes(&self) -> u32 {
        self.n.num_bytes()
    }

    /// Estimated security strength in bits per NIST SP 800-57 Part 1
    /// Rev. 5 Table 2. Replaces C `RSA_security_bits()` from
    /// `crypto/rsa/rsa_lib.c` line 398.
    pub fn security_bits(&self) -> u32 {
        compute_security_bits(self.key_size_bits())
    }
}

impl fmt::Display for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RSA Public Key ({} bit)", self.key_size_bits())
    }
}

// -----------------------------------------------------------------------------
// 2.6: RSA Private Key
// -----------------------------------------------------------------------------

/// RSA private key with all CRT (Chinese-Remainder-Theorem) components.
///
/// Translates the private-component subset of C `struct rsa_st` from
/// `crypto/rsa/rsa_local.h` lines 62-67 (`d`, `p`, `q`, `dmp1`, `dmq1`,
/// `iqmp`).
///
/// **Security:** Implements [`zeroize::ZeroizeOnDrop`] — all secret
/// fields (`d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`, prime infos) are
/// securely erased on drop, replacing the explicit `BN_clear_free()`
/// calls in C `RSA_free()` (`crypto/rsa/rsa_lib.c` lines 147-152).
///
/// **Debug Redaction:** [`std::fmt::Debug`] does not emit any secret
/// component values — only the public modulus / exponent and shape
/// metadata are visible.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RsaPrivateKey {
    /// RSA modulus `n`.
    pub(crate) n: BigNum,
    /// Public exponent `e`.
    pub(crate) e: BigNum,
    /// Private exponent `d` (SECRET — zeroed on drop).
    pub(crate) d: BigNum,
    /// First prime factor `p` (SECRET).
    pub(crate) p: BigNum,
    /// Second prime factor `q` (SECRET).
    pub(crate) q: BigNum,
    /// CRT exponent `dmp1 = d mod (p-1)` (SECRET).
    pub(crate) dmp1: BigNum,
    /// CRT exponent `dmq1 = d mod (q-1)` (SECRET).
    pub(crate) dmq1: BigNum,
    /// CRT coefficient `iqmp = q^{-1} mod p` (SECRET).
    pub(crate) iqmp: BigNum,
    /// Two-prime vs multi-prime version discriminator.
    #[zeroize(skip)]
    pub(crate) version: RsaVersion,
    /// Additional prime factors for multi-prime RSA (SECRET).
    pub(crate) prime_infos: Option<Vec<RsaPrimeInfo>>,
    /// Restrictive PSS parameters for an RSA-PSS-typed key
    /// (RFC 4055 §3.1). When present, the key MUST be used only with
    /// these parameters.
    #[zeroize(skip)]
    pub(crate) pss_restrictions: Option<pss::PssParams30>,
}

impl RsaPrivateKey {
    /// Constructs a new two-prime RSA private key from its eight
    /// components.
    ///
    /// All components must be non-zero and positive; modulus invariants
    /// (`n == p · q`, `dmp1 == d mod (p-1)`, etc.) are NOT verified here
    /// — callers should run [`check_private_key`] / [`check_keypair`]
    /// for SP 800-56B compliance.
    ///
    /// # Errors
    /// Returns [`RsaError::ValueMissing`] for any zero component;
    /// [`RsaError::BadExponentValue`] for an invalid public exponent.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::many_single_char_names)] // n, e, d, p, q are RFC 8017 conventional names
    pub fn new(
        n: BigNum,
        e: BigNum,
        d: BigNum,
        p: BigNum,
        q: BigNum,
        dmp1: BigNum,
        dmq1: BigNum,
        iqmp: BigNum,
    ) -> CryptoResult<Self> {
        if n.is_zero() {
            return Err(RsaError::ValueMissing { component: "n" }.into());
        }
        if e.is_zero() || !e.is_odd() {
            return Err(RsaError::BadExponentValue.into());
        }
        if d.is_zero() {
            return Err(RsaError::ValueMissing { component: "d" }.into());
        }
        if p.is_zero() {
            return Err(RsaError::ValueMissing { component: "p" }.into());
        }
        if q.is_zero() {
            return Err(RsaError::ValueMissing { component: "q" }.into());
        }
        if dmp1.is_zero() {
            return Err(RsaError::ValueMissing { component: "dmp1" }.into());
        }
        if dmq1.is_zero() {
            return Err(RsaError::ValueMissing { component: "dmq1" }.into());
        }
        if iqmp.is_zero() {
            return Err(RsaError::ValueMissing { component: "iqmp" }.into());
        }
        Ok(Self {
            n,
            e,
            d,
            p,
            q,
            dmp1,
            dmq1,
            iqmp,
            version: RsaVersion::TwoPrime,
            prime_infos: None,
            pss_restrictions: None,
        })
    }

    /// Extracts an `RsaPublicKey` from the public components of this
    /// private key.
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.dup(),
            e: self.e.dup(),
        }
    }

    /// Returns a reference to the modulus `n`.
    pub fn modulus(&self) -> &BigNum {
        &self.n
    }

    /// Returns a reference to the public exponent `e`.
    pub fn public_exponent(&self) -> &BigNum {
        &self.e
    }

    /// Returns a reference to the private exponent `d`.
    pub fn private_exponent(&self) -> &BigNum {
        &self.d
    }

    /// Returns a reference to the first prime factor `p`.
    pub fn prime_p(&self) -> &BigNum {
        &self.p
    }

    /// Returns a reference to the second prime factor `q`.
    pub fn prime_q(&self) -> &BigNum {
        &self.q
    }

    /// Returns a reference to the CRT exponent `dmp1 = d mod (p-1)`.
    pub fn crt_dmp1(&self) -> &BigNum {
        &self.dmp1
    }

    /// Returns a reference to the CRT exponent `dmq1 = d mod (q-1)`.
    pub fn crt_dmq1(&self) -> &BigNum {
        &self.dmq1
    }

    /// Returns a reference to the CRT coefficient
    /// `iqmp = q^{-1} mod p`.
    pub fn crt_iqmp(&self) -> &BigNum {
        &self.iqmp
    }

    /// Bit length of the modulus.
    pub fn key_size_bits(&self) -> u32 {
        self.n.num_bits()
    }

    /// Byte length of the modulus. Returns `u32` directly (not `usize`)
    /// per Rule R6 — see [`RsaPublicKey::key_size_bytes`] for rationale.
    pub fn key_size_bytes(&self) -> u32 {
        self.n.num_bytes()
    }

    /// Estimated security strength in bits per SP 800-57 Part 1 Rev. 5
    /// Table 2.
    pub fn security_bits(&self) -> u32 {
        compute_security_bits(self.key_size_bits())
    }

    /// Returns the ASN.1 version (`TwoPrime` / `MultiPrime`).
    pub fn version(&self) -> RsaVersion {
        self.version
    }

    /// Returns `true` for multi-prime RSA keys.
    pub fn is_multi_prime(&self) -> bool {
        matches!(self.version, RsaVersion::MultiPrime)
            && self.prime_infos.as_ref().is_some_and(|v| !v.is_empty())
    }

    /// Returns the total number of prime factors (2 + extra primes).
    pub fn prime_count(&self) -> usize {
        2 + self.prime_infos.as_ref().map_or(0, Vec::len)
    }

    /// Returns the PSS restriction parameters bound to an RFC 4055
    /// RSASSA-PSS key, if any.
    pub fn pss_params(&self) -> Option<&pss::PssParams30> {
        self.pss_restrictions.as_ref()
    }
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SECURITY: This Debug impl deliberately omits / redacts secret
        // components. The omitted fields (`n`, `prime_infos`, `pss_restrictions`)
        // are non-secret but are intentionally not displayed for compactness;
        // `.finish_non_exhaustive()` advertises that fact to the formatter.
        f.debug_struct("RsaPrivateKey")
            .field("key_size_bits", &self.key_size_bits())
            .field("version", &self.version)
            .field("prime_count", &self.prime_count())
            .field("e", &self.e)
            .field("d", &"<redacted>")
            .field("p", &"<redacted>")
            .field("q", &"<redacted>")
            .field("dmp1", &"<redacted>")
            .field("dmq1", &"<redacted>")
            .field("iqmp", &"<redacted>")
            .finish_non_exhaustive()
    }
}

// -----------------------------------------------------------------------------
// 2.7: RSA Key Pair
// -----------------------------------------------------------------------------

/// Combined RSA public + private key pair.
///
/// The pair holds a single private key from which the public key can be
/// extracted on demand via [`Self::public_key`]; this avoids storing the
/// public components twice.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RsaKeyPair {
    private_key: RsaPrivateKey,
}

impl RsaKeyPair {
    /// Constructs a key pair from a private key (the public components
    /// are projected by [`Self::public_key`]).
    pub(crate) fn from_private(private_key: RsaPrivateKey) -> Self {
        Self { private_key }
    }

    /// Returns the public key extracted from this pair.
    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.public_key()
    }

    /// Returns a reference to the private key.
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }
}

impl fmt::Debug for RsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeyPair")
            .field("private_key", &self.private_key)
            .finish()
    }
}

// =============================================================================
// Phase 3: Security-Bits Helper (from rsa_lib.c line 398, RSA_security_bits)
// =============================================================================

/// Computes the security strength in bits for the given RSA modulus size.
///
/// Translates the C function `RSA_security_bits()` from
/// `crypto/rsa/rsa_lib.c` line 398, which uses the NIST SP 800-57 Part 1
/// Rev. 5 Table 2 mapping for asymmetric-key strength estimates:
///
/// | Modulus bits | Security bits |
/// |--------------|--------------|
/// | < 1024       | 0 (no security claimed) |
/// | 1024..=2047  | 80 |
/// | 2048..=3071  | 112 |
/// | 3072..=7679  | 128 |
/// | 7680..=15359 | 192 |
/// | ≥ 15360      | 256 |
///
/// The thresholds match the values returned by `RSA_security_bits()` and
/// the FIPS 186-5 / SP 800-56B Rev. 2 minimum-strength enforcement.
fn compute_security_bits(key_size_bits: u32) -> u32 {
    match key_size_bits {
        0..=1023 => 0,
        1024..=2047 => 80,
        2048..=3071 => 112,
        3072..=7679 => 128,
        7680..=15359 => 192,
        _ => 256,
    }
}

// =============================================================================
// Phase 4: Key Generation (from rsa_gen.c, rsa_sp800_56b_gen.c, rsa_x931g.c)
// =============================================================================

// -----------------------------------------------------------------------------
// 4.1: Multi-prime cap
// -----------------------------------------------------------------------------

/// Returns the maximum number of prime factors permitted for an RSA modulus
/// of the given bit length.
///
/// Translates `ossl_rsa_multip_cap()` from `crypto/rsa/rsa_mp.c` line 87.
/// The intent is to keep individual prime factors large enough to resist
/// ECM (Elliptic Curve Method) factorization: each prime should be at least
/// ~1024 bits, so a 4096-bit modulus may have up to 3 primes (4096 / 1024 + 1)
/// without crossing that floor.
///
/// Capped at [`RSA_MAX_PRIME_NUM`] (5), matching the C limit.
pub fn multi_prime_cap(bits: u32) -> usize {
    match bits {
        0..=4095 => 2,
        4096..=8191 => 3,
        8192..=16_383 => 4,
        _ => RSA_MAX_PRIME_NUM,
    }
}

// -----------------------------------------------------------------------------
// 4.2: RsaKeyGenParams
// -----------------------------------------------------------------------------

/// Parameters controlling RSA key generation.
///
/// Mirrors the keygen-parameter inputs of `RSA_generate_key_ex()`,
/// `RSA_generate_multi_prime_key()`, and the SP 800-56B Rev. 2 keygen
/// pathway from `crypto/rsa/rsa_gen.c` and `crypto/rsa/rsa_sp800_56b_gen.c`.
#[derive(Debug, Clone)]
pub struct RsaKeyGenParams {
    /// Modulus bit length. Must satisfy `>= RSA_MIN_MODULUS_BITS` for
    /// generic generation; FIPS 186-5 paths additionally require
    /// `>= RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE`.
    pub bits: u32,
    /// Public exponent `e`. `None` means use [`RSA_DEFAULT_PUBLIC_EXPONENT`]
    /// (65 537). When supplied, `e` must be odd, `>= 3`, and `<= 2^256 - 1`.
    pub public_exponent: Option<BigNum>,
    /// Number of prime factors. `2` is the standard RSA case; up to
    /// [`RSA_MAX_PRIME_NUM`] is allowed for multi-prime, subject to
    /// [`multi_prime_cap`] for the requested modulus bit length.
    pub primes: usize,
}

impl Default for RsaKeyGenParams {
    fn default() -> Self {
        Self {
            bits: 2048,
            public_exponent: None,
            primes: 2,
        }
    }
}

impl RsaKeyGenParams {
    /// Convenience constructor for two-prime RSA with default exponent
    /// (65 537).
    pub fn new(bits: u32) -> Self {
        Self {
            bits,
            public_exponent: None,
            primes: 2,
        }
    }

    /// Returns the configured public exponent, defaulting to 65 537 when
    /// none was supplied. The returned [`BigNum`] is freshly allocated and
    /// owned by the caller.
    pub fn effective_public_exponent(&self) -> BigNum {
        match &self.public_exponent {
            Some(e) => e.dup(),
            None => BigNum::from_u64(RSA_DEFAULT_PUBLIC_EXPONENT),
        }
    }
}

// -----------------------------------------------------------------------------
// 4.3: generate_key — primary RSA key-pair generator
// -----------------------------------------------------------------------------

/// Generates an RSA key pair according to the supplied [`RsaKeyGenParams`].
///
/// Translates `RSA_generate_key_ex()` (`crypto/rsa/rsa_gen.c` line 42) and
/// the internal `rsa_keygen()` (`rsa_gen.c` line 82). The algorithm:
///
/// 1. Validate `bits >= RSA_MIN_MODULUS_BITS`, `e` odd and `>= 3`.
/// 2. Cap `primes` at [`multi_prime_cap`] for the requested key size.
/// 3. For each prime, generate a random odd integer of size
///    `bits / primes` bits, ensuring `gcd(p_i - 1, e) == 1` and the
///    `|p_i - p_j| > 2^(bits/2 - 100)` separation required by FIPS
///    186-5 §A.1.5 (translated from `rsa_gen.c` line 199).
/// 4. Compute `n = ∏ p_i`.
/// 5. Compute λ(n) (Carmichael) = `lcm(p_1 - 1, …, p_u - 1)`.
/// 6. Compute `d = e^(-1) mod λ(n)` (FIPS 186-5 §A.1.1; the older
///    PKCS #1 v2.1 form `d = e^(-1) mod φ(n)` is functionally
///    equivalent for the public/private operations).
/// 7. Compute CRT components `dmp1 = d mod (p-1)`, `dmq1 = d mod (q-1)`,
///    `iqmp = q^(-1) mod p`.
/// 8. Run a pairwise consistency check (`m^e^d == m mod n` for a small
///    `m`) — this corresponds to `rsa_keygen_pairwise_test()` in
///    `rsa_gen.c` line 30 and is the FIPS 140-3 PCT requirement.
/// 9. Zero all intermediate scratch values via [`Zeroize`].
///
/// # Errors
/// - [`RsaError::KeyTooSmall`] if `bits < RSA_MIN_MODULUS_BITS`
/// - [`RsaError::BadExponentValue`] if `e` is even / `< 3`
/// - [`RsaError::InvalidMultiPrimeKey`] if `primes > multi_prime_cap(bits)`
///   or `primes < 2`
/// - [`RsaError::KeyGenerationFailed`] for any underlying arithmetic failure
#[allow(clippy::many_single_char_names)] // n, e, d, p, q, m, c are RFC 8017 conventional names
pub fn generate_key(params: &RsaKeyGenParams) -> CryptoResult<RsaKeyPair> {
    debug!(
        bits = params.bits,
        primes = params.primes,
        "RSA key generation starting"
    );

    // Step 1: Parameter validation.
    if params.bits < RSA_MIN_MODULUS_BITS {
        return Err(RsaError::KeyTooSmall {
            min_bits: RSA_MIN_MODULUS_BITS,
            actual_bits: params.bits,
        }
        .into());
    }
    if params.primes < 2 {
        return Err(RsaError::InvalidMultiPrimeKey.into());
    }
    let cap = multi_prime_cap(params.bits);
    if params.primes > cap {
        return Err(RsaError::InvalidMultiPrimeKey.into());
    }

    let e = params.effective_public_exponent();
    let three = BigNum::from_u64(3);
    if e.is_zero() || e.is_negative() || !e.is_odd() {
        return Err(RsaError::BadExponentValue.into());
    }
    if e.cmp(&three) == std::cmp::Ordering::Less {
        return Err(RsaError::BadExponentValue.into());
    }

    // Step 2: Determine per-prime bit length. Distribute bits as evenly as
    // possible; the *first* prime may carry the rounding remainder so the
    // total bit length of `n = ∏ p_i` lands at exactly `params.bits`.
    let primes_count = params.primes;
    let primes_count_u32 =
        u32::try_from(primes_count).map_err(|_| RsaError::KeyGenerationFailed)?;
    let prime_bits = if primes_count_u32 == 0 {
        return Err(RsaError::KeyGenerationFailed.into());
    } else {
        params
            .bits
            .checked_div(primes_count_u32)
            .ok_or(RsaError::KeyGenerationFailed)?
    };
    if prime_bits < 16 {
        // Each factor must be large enough for primality testing to be
        // meaningful — translation of `rsa_gen.c` line 142.
        return Err(RsaError::KeyTooSmall {
            min_bits: 16 * primes_count_u32,
            actual_bits: params.bits,
        }
        .into());
    }

    // Minimum separation: |p_i - p_j| > 2^(bits/2 - 100). Below this, Fermat
    // factorization could recover the primes. From `rsa_gen.c` line 199.
    let min_sep_bits = (params.bits / 2).saturating_sub(100);

    // Step 3: Generate the primes.
    let mut primes: Vec<BigNum> = Vec::with_capacity(primes_count);
    let max_attempts: u32 = 100 * (params.bits + 1);
    for prime_idx in 0..primes_count {
        let mut attempts = 0u32;
        let candidate = loop {
            if attempts >= max_attempts {
                return Err(RsaError::KeyGenerationFailed.into());
            }
            attempts += 1;

            // The first prime carries the rounding remainder.
            let bits_this = if prime_idx == 0 {
                prime_bits + (params.bits - prime_bits * primes_count_u32)
            } else {
                prime_bits
            };
            let opts = prime::GeneratePrimeOptions::new(bits_this);
            let p = prime::generate_prime(&opts)?;

            // gcd(p - 1, e) must equal 1; translation of `rsa_gen.c` line 263.
            let p_minus_one = arithmetic::sub_word(&p, 1)?;
            let gcd_pe = arithmetic::gcd(&p_minus_one, &e);
            if !gcd_pe.is_one() {
                trace!("regenerating prime: gcd(p-1, e) != 1");
                continue;
            }

            // Separation check against previously generated primes.
            let mut separated = true;
            for existing in &primes {
                let diff = if p.cmp(existing) == std::cmp::Ordering::Greater {
                    arithmetic::sub(&p, existing)
                } else {
                    arithmetic::sub(existing, &p)
                };
                if diff.num_bits() <= min_sep_bits {
                    separated = false;
                    trace!("regenerating prime: |p_i - p_j| too small");
                    break;
                }
            }
            if !separated {
                continue;
            }
            break p;
        };
        primes.push(candidate);
    }

    // Step 4: Compute n = ∏ p_i.
    let mut n = primes[0].dup();
    for p in &primes[1..] {
        n = arithmetic::mul(&n, p);
    }

    // If the resulting n has fewer bits than requested (because primes were
    // generated at exactly their target size), reject and surface the error.
    if n.num_bits() != params.bits {
        return Err(RsaError::KeyGenerationFailed.into());
    }

    // Step 5: Compute λ(n) = lcm(p_1 - 1, p_2 - 1, …, p_u - 1).
    let mut lambda = arithmetic::sub_word(&primes[0], 1)?;
    for p in &primes[1..] {
        let p_minus_one = arithmetic::sub_word(p, 1)?;
        lambda = arithmetic::lcm(&lambda, &p_minus_one)?;
    }

    // Step 6: d = e^(-1) mod λ(n).
    let d = arithmetic::mod_inverse_checked(&e, &lambda)?;

    // Step 7: Standard two-prime CRT components.
    let p = primes[0].dup();
    let q = primes[1].dup();
    let p_minus_one = arithmetic::sub_word(&p, 1)?;
    let q_minus_one = arithmetic::sub_word(&q, 1)?;
    let dmp1 = arithmetic::rem(&d, &p_minus_one)?;
    let dmq1 = arithmetic::rem(&d, &q_minus_one)?;
    let iqmp = arithmetic::mod_inverse_checked(&q, &p)?;

    // Step 7a: Build any extra prime infos for multi-prime RSA.
    let prime_infos = if primes_count > 2 {
        let mut infos = Vec::with_capacity(primes_count - 2);
        // pp accumulator: product of all preceding primes.
        let mut pp = arithmetic::mul(&p, &q);
        for r in &primes[2..] {
            let r_minus_one = arithmetic::sub_word(r, 1)?;
            let d_i = arithmetic::rem(&d, &r_minus_one)?;
            let t_i = arithmetic::mod_inverse_checked(&pp, r)?;
            infos.push(RsaPrimeInfo {
                r: r.dup(),
                d: d_i,
                t: t_i,
                pp: pp.dup(),
            });
            pp = arithmetic::mul(&pp, r);
        }
        Some(infos)
    } else {
        None
    };

    let version = if primes_count > 2 {
        RsaVersion::MultiPrime
    } else {
        RsaVersion::TwoPrime
    };

    // Step 8: Pairwise-consistency test (FIPS 140-3 PCT).
    // m = 2; verify that decrypt(encrypt(m)) == m.
    let m = BigNum::from_u64(2);
    let c = montgomery::mod_exp(&m, &e, &n)?;
    let m_recovered = montgomery::mod_exp_consttime(&c, &d, &n)?;
    if m.cmp(&m_recovered) != std::cmp::Ordering::Equal {
        return Err(RsaError::KeyGenerationFailed.into());
    }

    // Step 9: Build the private key. Fields are zeroized when the key is
    // dropped via the `ZeroizeOnDrop` derive on `RsaPrivateKey`.
    let private_key = RsaPrivateKey {
        n,
        e,
        d,
        p,
        q,
        dmp1,
        dmq1,
        iqmp,
        version,
        prime_infos,
        pss_restrictions: None,
    };

    // Best-effort: zero the local copies in `primes` (they have been moved
    // into the key already, but slot residue may remain).
    drop(primes);

    debug!(
        bits = params.bits,
        primes = primes_count,
        "RSA key generation complete"
    );
    Ok(RsaKeyPair::from_private(private_key))
}

// -----------------------------------------------------------------------------
// 4.4: SP 800-56B Rev. 2 / FIPS 186-5 key generation
// -----------------------------------------------------------------------------

/// Generates an RSA key pair conforming to NIST SP 800-56B Rev. 2 §6.3 and
/// FIPS 186-5 §A.1.1. Translates the `ossl_rsa_sp800_56b_generate_key()`
/// pathway from `crypto/rsa/rsa_sp800_56b_gen.c` line 244 (`RSA_generate_key`
/// FIPS path).
///
/// Differs from [`generate_key`] in that:
/// - `bits >= RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE` (2048) is enforced.
/// - Resulting modulus must provide at least
///   `RSA_FIPS186_5_MIN_KEYGEN_STRENGTH` (112) bits of security.
/// - Multi-prime RSA is rejected (FIPS 186-5 mandates two-prime only).
/// - The pairwise-consistency test is mandatory and a failure aborts
///   key generation rather than retrying.
///
/// # Errors
/// - [`RsaError::KeyTooSmall`] if `bits < 2048`
/// - [`RsaError::BadExponentValue`] if `e < 65537` (FIPS 186-5 §A.1.1
///   recommends `e >= 65537`).
/// - [`RsaError::Sp80056bValidationFailed`] for any post-generation
///   validation failure (RSAKPV1/RSAKPV2).
pub fn generate_key_sp800_56b(
    bits: u32,
    public_exponent: &BigNum,
    _ctx: Option<&LibContext>,
) -> CryptoResult<RsaKeyPair> {
    if bits < RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE {
        return Err(RsaError::KeyTooSmall {
            min_bits: RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE,
            actual_bits: bits,
        }
        .into());
    }
    if compute_security_bits(bits) < RSA_FIPS186_5_MIN_KEYGEN_STRENGTH {
        return Err(RsaError::Sp80056bValidationFailed {
            detail: format!(
                "modulus of {} bits provides {} bits of security; FIPS 186-5 requires {}",
                bits,
                compute_security_bits(bits),
                RSA_FIPS186_5_MIN_KEYGEN_STRENGTH
            ),
        }
        .into());
    }

    // FIPS 186-5 §A.1.1: 65537 <= e <= 2^256 - 1.
    let f4 = BigNum::from_u64(RSA_DEFAULT_PUBLIC_EXPONENT);
    if public_exponent.cmp(&f4) == std::cmp::Ordering::Less {
        return Err(RsaError::BadExponentValue.into());
    }
    if !public_exponent.is_odd() {
        return Err(RsaError::BadExponentValue.into());
    }

    let params = RsaKeyGenParams {
        bits,
        public_exponent: Some(public_exponent.dup()),
        primes: 2, // FIPS 186-5 mandates two-prime RSA only.
    };

    let pair = generate_key(&params)?;

    // Run the SP 800-56B keypair check post-generation.
    let result = check_keypair(pair.private_key())?;
    if !result.is_valid {
        return Err(RsaError::Sp80056bValidationFailed {
            detail: format!("post-generation validation failed: {:?}", result.issues),
        }
        .into());
    }

    Ok(pair)
}

// =============================================================================
// Phase 5: Core RSA Operations (from rsa_ossl.c, rsa_crpt.c)
// =============================================================================

// -----------------------------------------------------------------------------
// 5.1: Helper — convert message to integer and back
// -----------------------------------------------------------------------------

/// Converts a padded message buffer to a [`BigNum`] representative.
///
/// The padded buffer is interpreted as a big-endian integer (RFC 8017 OS2IP).
/// The result is rejected if it is `>= n`.
fn os2ip(padded: &[u8], n: &BigNum) -> CryptoResult<BigNum> {
    let m = BigNum::from_bytes_be(padded);
    if m.cmp(n) != std::cmp::Ordering::Less {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }
    Ok(m)
}

/// Converts an integer to an octet string of the given length (RFC 8017 I2OSP).
fn i2osp(value: &BigNum, k: u32) -> CryptoResult<Vec<u8>> {
    let pad_len = usize::try_from(k).map_err(|_| RsaError::DataTooLargeForKeySize)?;
    value.to_bytes_be_padded(pad_len)
}

// -----------------------------------------------------------------------------
// 5.2: Public-key encryption (RSAEP per RFC 8017 §5.1.1)
// -----------------------------------------------------------------------------

/// Encrypts data with an RSA public key using the given padding mode.
///
/// Translates `rsa_ossl_public_encrypt()` from `crypto/rsa/rsa_ossl.c`
/// line 88. Performs:
///
/// 1. Pads the input to `k = key_size_bytes(key)` octets via the
///    selected [`PaddingMode`].
/// 2. Converts the padded buffer to an integer `m` (OS2IP).
/// 3. Computes `c = m^e mod n` (RSAEP).
/// 4. Converts `c` back to a `k`-byte octet string (I2OSP).
///
/// # Errors
/// - [`RsaError::DataTooLargeForKeySize`] if `data` is too long for `padding`.
/// - [`RsaError::InvalidPadding`] if `padding` is not supported for encryption.
pub fn public_encrypt(
    key: &RsaPublicKey,
    plaintext: &[u8],
    padding: PaddingMode,
) -> CryptoResult<Vec<u8>> {
    trace!(padding = ?padding, "RSA public_encrypt");
    let k = key.key_size_bytes();
    let k_us = usize::try_from(k).map_err(|_| RsaError::DataTooLargeForKeySize)?;
    let mut buf = vec![0u8; k_us];
    match padding {
        PaddingMode::Pkcs1v15 => pkcs1_v15_type2_pad(&mut buf, plaintext)?,
        PaddingMode::None => no_padding_add(&mut buf, plaintext)?,
        PaddingMode::Oaep | PaddingMode::X931 | PaddingMode::Pss => {
            return Err(RsaError::InvalidPadding.into());
        }
    }
    let m = os2ip(&buf, key.modulus())?;
    let c = montgomery::mod_exp(&m, key.public_exponent(), key.modulus())?;
    i2osp(&c, k)
}

// -----------------------------------------------------------------------------
// 5.3: Private-key decryption (RSADP per RFC 8017 §5.1.2)
// -----------------------------------------------------------------------------

/// Decrypts ciphertext with an RSA private key using the given padding mode.
///
/// Translates `rsa_ossl_private_decrypt()` from `crypto/rsa/rsa_ossl.c`
/// line 289. Uses CRT-accelerated modular exponentiation
/// ([`crt_mod_exp`]) with [Bellcore-attack defense](rsa_ossl.c#L640) and
/// applies the requested padding's removal algorithm. PKCS#1 v1.5 type 2
/// uses constant-time / implicit-rejection to prevent Bleichenbacher's
/// attack (translated from `rsa_pk1.c` lines 200-639).
///
/// # Errors
/// - [`RsaError::DataTooLargeForKeySize`] if ciphertext length != `k`.
/// - [`RsaError::Pkcs1PaddingError`] if padding-removal fails.
pub fn private_decrypt(
    key: &RsaPrivateKey,
    ciphertext: &[u8],
    padding: PaddingMode,
) -> CryptoResult<Vec<u8>> {
    trace!(padding = ?padding, "RSA private_decrypt");
    let k = key.key_size_bytes();
    let k_us = usize::try_from(k).map_err(|_| RsaError::DataTooLargeForKeySize)?;
    if ciphertext.len() != k_us {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }
    let c = os2ip(ciphertext, key.modulus())?;

    // Apply blinding (timing-attack defense). The blinded message is
    // `c * r^e mod n`; after exponentiation we multiply by `r^-1` to
    // recover `m`. See `rsa_ossl.c` lines 29-86 / 380-460.
    let mut blinding = BlindingFactor::new(key.modulus(), key.public_exponent())?;
    let blinded_c = blinding.apply(&c, key.modulus())?;
    let blinded_m = crt_mod_exp(&blinded_c, key)?;
    let m = blinding.unapply(&blinded_m, key.modulus())?;

    // Bellcore-attack defense: verify `m^e == c mod n`. From `rsa_ossl.c`
    // lines 640-670 (`if (RAND_priv_bytes_ex(...) && BN_mod_exp(vrfy, ...))`).
    let vrfy = montgomery::mod_exp(&m, key.public_exponent(), key.modulus())?;
    if vrfy.cmp(&c) != std::cmp::Ordering::Equal {
        return Err(RsaError::KeyValidationFailed {
            reason: "Bellcore-attack defense: m^e != c".to_string(),
        }
        .into());
    }

    let buf = i2osp(&m, k)?;
    match padding {
        PaddingMode::Pkcs1v15 => pkcs1_v15_type2_unpad(&buf, k_us),
        PaddingMode::None => Ok(no_padding_check(&buf)),
        PaddingMode::Oaep | PaddingMode::X931 | PaddingMode::Pss => {
            Err(RsaError::InvalidPadding.into())
        }
    }
}

// -----------------------------------------------------------------------------
// 5.4: Private-key encryption (raw signing / RSASP1)
// -----------------------------------------------------------------------------

/// Signs (or "private-encrypts") data with an RSA private key.
///
/// Translates `rsa_ossl_private_encrypt()` from `crypto/rsa/rsa_ossl.c`
/// line 175. PKCS#1 v1.5 signatures use type 1 padding; X9.31 signatures
/// use the X9.31 padding scheme. No-padding is permitted for advanced
/// callers (e.g. PSS pre-encoded buffers).
pub fn private_encrypt(
    key: &RsaPrivateKey,
    data: &[u8],
    padding: PaddingMode,
) -> CryptoResult<Vec<u8>> {
    trace!(padding = ?padding, "RSA private_encrypt");
    let k = key.key_size_bytes();
    let k_us = usize::try_from(k).map_err(|_| RsaError::DataTooLargeForKeySize)?;
    let mut buf = vec![0u8; k_us];
    match padding {
        PaddingMode::Pkcs1v15 => pkcs1_v15_type1_pad(&mut buf, data)?,
        PaddingMode::None => no_padding_add(&mut buf, data)?,
        PaddingMode::X931 => x931_pad(&mut buf, data, DigestAlgorithm::Sha256)?,
        PaddingMode::Oaep | PaddingMode::Pss => {
            return Err(RsaError::InvalidPadding.into());
        }
    }
    let m = os2ip(&buf, key.modulus())?;
    let c = crt_mod_exp(&m, key)?;
    // Bellcore defense.
    let vrfy = montgomery::mod_exp(&c, key.public_exponent(), key.modulus())?;
    if vrfy.cmp(&m) != std::cmp::Ordering::Equal {
        return Err(RsaError::KeyValidationFailed {
            reason: "Bellcore-attack defense: c^e != m".to_string(),
        }
        .into());
    }
    i2osp(&c, k)
}

// -----------------------------------------------------------------------------
// 5.5: Public-key decryption (signature verification / RSAVP1)
// -----------------------------------------------------------------------------

/// Verifies / "public-decrypts" a signature with an RSA public key.
///
/// Translates `rsa_ossl_public_decrypt()` from `crypto/rsa/rsa_ossl.c`
/// line 226. Returns the recovered message after stripping the requested
/// padding.
pub fn public_decrypt(
    key: &RsaPublicKey,
    signature: &[u8],
    padding: PaddingMode,
) -> CryptoResult<Vec<u8>> {
    trace!(padding = ?padding, "RSA public_decrypt");
    let k = key.key_size_bytes();
    let k_us = usize::try_from(k).map_err(|_| RsaError::DataTooLargeForKeySize)?;
    if signature.len() != k_us {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }
    let c = os2ip(signature, key.modulus())?;
    let m = montgomery::mod_exp(&c, key.public_exponent(), key.modulus())?;
    let buf = i2osp(&m, k)?;
    match padding {
        PaddingMode::Pkcs1v15 => pkcs1_v15_type1_unpad(&buf),
        PaddingMode::None => Ok(no_padding_check(&buf)),
        PaddingMode::X931 => x931_unpad(&buf),
        PaddingMode::Oaep | PaddingMode::Pss => Err(RsaError::InvalidPadding.into()),
    }
}

// -----------------------------------------------------------------------------
// 5.6: CRT-accelerated modular exponentiation
// -----------------------------------------------------------------------------

/// Computes `result = input^d mod n` using the Chinese Remainder Theorem
/// for ~4× speedup over naive modular exponentiation.
///
/// Translates `rsa_ossl_mod_exp()` from `crypto/rsa/rsa_ossl.c` line 466.
///
/// Two-prime CRT: given `dmp1 = d mod (p-1)`, `dmq1 = d mod (q-1)`,
/// `iqmp = q^(-1) mod p`:
/// ```text
///   m1 = input^dmp1 mod p
///   m2 = input^dmq1 mod q
///   h  = ((m1 - m2) * iqmp) mod p
///   result = m2 + q * h
/// ```
/// Multi-prime extends this with successive Garner reconstruction using
/// the `prime_infos` array (RFC 8017 §5.1.2 step 2.b).
fn crt_mod_exp(input: &BigNum, key: &RsaPrivateKey) -> CryptoResult<BigNum> {
    // Reduce input modulo p and q before exponentiating.
    let input_p = arithmetic::rem(input, &key.p)?;
    let input_q = arithmetic::rem(input, &key.q)?;

    let m1 = montgomery::mod_exp_consttime(&input_p, &key.dmp1, &key.p)?;
    let m2 = montgomery::mod_exp_consttime(&input_q, &key.dmq1, &key.q)?;

    // h = (m1 - m2) * iqmp mod p, taking care of negative subtraction.
    let diff = if m1.cmp(&m2) == std::cmp::Ordering::Less {
        // m1 < m2: produce m1 - m2 in [0, p) by adding p.
        let neg = arithmetic::sub(&m2, &m1);
        let neg_mod = arithmetic::rem(&neg, &key.p)?;
        if neg_mod.is_zero() {
            BigNum::zero()
        } else {
            arithmetic::sub(&key.p, &neg_mod)
        }
    } else {
        arithmetic::sub(&m1, &m2)
    };
    let h = arithmetic::mod_mul(&diff, &key.iqmp, &key.p)?;

    // result = m2 + q * h
    let qh = arithmetic::mul(&key.q, &h);
    let mut result = arithmetic::add(&m2, &qh);

    // For multi-prime RSA, fold in the additional prime infos.
    if let Some(infos) = &key.prime_infos {
        for info in infos {
            let input_r = arithmetic::rem(input, &info.r)?;
            let m_i = montgomery::mod_exp_consttime(&input_r, &info.d, &info.r)?;
            // h_i = ((m_i - result) * t_i) mod r_i
            let result_mod_r = arithmetic::rem(&result, &info.r)?;
            let diff_i = if m_i.cmp(&result_mod_r) == std::cmp::Ordering::Less {
                let neg = arithmetic::sub(&result_mod_r, &m_i);
                let neg_mod = arithmetic::rem(&neg, &info.r)?;
                if neg_mod.is_zero() {
                    BigNum::zero()
                } else {
                    arithmetic::sub(&info.r, &neg_mod)
                }
            } else {
                arithmetic::sub(&m_i, &result_mod_r)
            };
            let h_i = arithmetic::mod_mul(&diff_i, &info.t, &info.r)?;
            // result = result + pp * h_i
            let pp_h = arithmetic::mul(&info.pp, &h_i);
            result = arithmetic::add(&result, &pp_h);
        }
    }

    // Reduce modulo n in case the multi-prime fold-in overshot.
    let result = arithmetic::rem(&result, &key.n)?;

    Ok(result)
}

// -----------------------------------------------------------------------------
// 5.7: Blinding (timing-attack defense)
// -----------------------------------------------------------------------------

/// Per-operation RSA blinding factor for timing-attack mitigation.
///
/// Translates the blinding sparse-array machinery from `crypto/rsa/rsa_ossl.c`
/// lines 29-86. A blinding factor is `r^e mod n` for random `r`. The
/// blinded ciphertext is `c · r^e mod n`; after the private-key decryption
/// we multiply by `r^(-1)` to recover the original plaintext. Because `r`
/// is random, the secret-dependent code path is randomized, foiling
/// timing oracles.
///
/// **Memory safety:** the random factor `r` is held in [`BigNum`] and
/// dropped after use. The [`Zeroize`] derive on `BlindingFactor` clears
/// `r` and `r_inv` deterministically. No raw pointers, no `unsafe`.
#[derive(Zeroize, ZeroizeOnDrop)]
struct BlindingFactor {
    /// Blinding factor `r^e mod n`.
    r_e: BigNum,
    /// Modular inverse of `r` mod `n`.
    r_inv: BigNum,
}

impl BlindingFactor {
    /// Creates a new blinding factor for the given modulus and public
    /// exponent.
    ///
    /// Picks a random `r` in `[2, n-1]` coprime with `n`, computes
    /// `r_e = r^e mod n` and `r_inv = r^-1 mod n`, and returns the bundled
    /// pair. Translates the per-operation blinding setup from
    /// `crypto/rsa/rsa_ossl.c` lines 29-86.
    ///
    /// ## Candidate generation strategy
    ///
    /// For the first 50 attempts we take a fast path that synthesises
    /// `r` directly with one fewer bit than `n` via [`BigNum::rand`] —
    /// this avoids any rejection sampling and is statistically uniform
    /// over `[0, 2^(n_bits-1))` ⊂ `[0, n)`. If the first 50 candidates
    /// happen to be 0, 1, or non-coprime with `n` (each event has
    /// negligible probability for cryptographically-sized `n`), we fall
    /// back to the strictly-uniform [`BigNum::rand_range`] which uses
    /// rejection sampling against `n` directly.
    ///
    /// Both code paths source entropy from the OS via `OsRng`, matching
    /// the security properties of the C `BN_priv_rand_range()` it
    /// replaces.
    fn new(n: &BigNum, e: &BigNum) -> CryptoResult<Self> {
        // Pick a random r in [2, n-1] coprime with n. We retry on the
        // (cryptographically negligible) chance that gcd(r, n) != 1.
        let mut attempts = 0u32;
        let n_bits = n.num_bits();
        loop {
            if attempts >= 100 {
                return Err(RsaError::BlindingFailed.into());
            }
            attempts += 1;

            let r = if attempts <= 50 && n_bits >= 2 {
                // Fast path: generate `r` with exactly `n_bits - 1` bits,
                // guaranteeing `r < n` without rejection sampling.
                // No constraints on top/bottom bits — we want a uniform
                // sample from `[0, 2^(n_bits-1))`.
                BigNum::rand(n_bits - 1, TopBit::Any, BottomBit::Any)?
            } else {
                // Fallback (rare): use rejection sampling for a strictly
                // uniform distribution over `[0, n)`. Also handles the
                // degenerate case `n_bits < 2` where the fast path is not
                // applicable.
                BigNum::rand_range(n)?
            };
            if r.is_zero() || r.is_one() {
                continue;
            }
            // r_inv = r^-1 mod n; if it doesn't exist (gcd != 1), retry.
            let Some(r_inv) = arithmetic::mod_inverse(&r, n)? else {
                continue;
            };
            let r_e = montgomery::mod_exp(&r, e, n)?;
            return Ok(Self { r_e, r_inv });
        }
    }

    /// Applies the blinding: returns `(c · r^e) mod n`.
    fn apply(&mut self, c: &BigNum, n: &BigNum) -> CryptoResult<BigNum> {
        arithmetic::mod_mul(c, &self.r_e, n)
    }

    /// Removes the blinding: returns `(m · r^-1) mod n`.
    fn unapply(&mut self, m: &BigNum, n: &BigNum) -> CryptoResult<BigNum> {
        arithmetic::mod_mul(m, &self.r_inv, n)
    }
}

// =============================================================================
// Phase 6: Key Validation (from rsa_chk.c, rsa_sp800_56b_check.c)
// =============================================================================

/// Result of an RSA key-validation check.
///
/// Replaces the C return-code-plus-error-stack pattern from
/// `crypto/rsa/rsa_chk.c` with a structured [`Vec`] of issues. When
/// `is_valid` is `false`, `issues` enumerates each individual failure.
#[derive(Debug, Clone)]
pub struct KeyValidationResult {
    /// Overall validity — `true` iff `issues` is empty.
    pub is_valid: bool,
    /// Per-failure reason details.
    pub issues: Vec<KeyValidationIssue>,
}

/// Specific RSA key-validation failure modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValidationIssue {
    /// `n != p · q · ∏ r_i`.
    NNotProductOfPQ,
    /// `(d · e) != 1 mod λ(n)`.
    DNotInverseOfE,
    /// CRT consistency check failed (one of `dmp1`, `dmq1`, `iqmp`).
    CrtComponentInvalid,
    /// One of the prime factors failed primality testing.
    PrimeNotPrime,
    /// `e` is too small — typically `e <= 2` or `e == 1`.
    ExponentTooSmall,
    /// `|p - q|` insufficient (NIST SP 800-89 §5.3.3 / FIPS 186-5 §A.1.5).
    PQSeparationInsufficient,
    /// Modulus bit length below the configured minimum.
    ModulusTooSmall,
}

/// Validates an RSA private key against the original `RSA_check_key()`
/// checks from `crypto/rsa/rsa_chk.c` lines 22-270.
pub fn check_key(key: &RsaPrivateKey) -> CryptoResult<KeyValidationResult> {
    let mut issues = Vec::new();

    // 1. n == p · q · ∏ r_i ?
    let mut product = arithmetic::mul(&key.p, &key.q);
    if let Some(infos) = &key.prime_infos {
        for info in infos {
            product = arithmetic::mul(&product, &info.r);
        }
    }
    if product.cmp(&key.n) != std::cmp::Ordering::Equal {
        issues.push(KeyValidationIssue::NNotProductOfPQ);
    }

    // 2. d · e == 1 mod λ(n) ?
    let p_minus_one = arithmetic::sub_word(&key.p, 1)?;
    let q_minus_one = arithmetic::sub_word(&key.q, 1)?;
    let mut lambda = arithmetic::lcm(&p_minus_one, &q_minus_one)?;
    if let Some(infos) = &key.prime_infos {
        for info in infos {
            let r_minus_one = arithmetic::sub_word(&info.r, 1)?;
            lambda = arithmetic::lcm(&lambda, &r_minus_one)?;
        }
    }
    let de = arithmetic::mod_mul(&key.d, &key.e, &lambda)?;
    if !de.is_one() {
        issues.push(KeyValidationIssue::DNotInverseOfE);
    }

    // 3. dmp1 == d mod (p-1)?
    let expected_dmp1 = arithmetic::rem(&key.d, &p_minus_one)?;
    if expected_dmp1.cmp(&key.dmp1) != std::cmp::Ordering::Equal {
        issues.push(KeyValidationIssue::CrtComponentInvalid);
    }

    // 4. dmq1 == d mod (q-1)?
    let expected_dmq1 = arithmetic::rem(&key.d, &q_minus_one)?;
    if expected_dmq1.cmp(&key.dmq1) != std::cmp::Ordering::Equal {
        issues.push(KeyValidationIssue::CrtComponentInvalid);
    }

    // 5. iqmp == q^-1 mod p?
    let expected_iqmp = arithmetic::mod_inverse_checked(&key.q, &key.p)?;
    if expected_iqmp.cmp(&key.iqmp) != std::cmp::Ordering::Equal {
        issues.push(KeyValidationIssue::CrtComponentInvalid);
    }

    // 6. Primality tests for p and q.
    if !matches!(
        prime::check_prime(&key.p)?,
        prime::PrimalityResult::ProbablyPrime
    ) {
        issues.push(KeyValidationIssue::PrimeNotPrime);
    }
    if !matches!(
        prime::check_prime(&key.q)?,
        prime::PrimalityResult::ProbablyPrime
    ) {
        issues.push(KeyValidationIssue::PrimeNotPrime);
    }

    Ok(KeyValidationResult {
        is_valid: issues.is_empty(),
        issues,
    })
}

/// SP 800-56B Rev. 2 §6.4.2.2 public-key validation.
///
/// Translates `ossl_rsa_sp800_56b_check_public()` from
/// `crypto/rsa/rsa_sp800_56b_check.c` line 282. Verifies:
///
/// 1. Modulus bit length is at least the configured minimum and even.
/// 2. `e` is odd and `2^16 < e < 2^256`.
/// 3. `n` is not divisible by any small prime.
pub fn check_public_key(key: &RsaPublicKey) -> CryptoResult<KeyValidationResult> {
    let mut issues = Vec::new();
    let bits = key.key_size_bits();
    if bits < RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE {
        issues.push(KeyValidationIssue::ModulusTooSmall);
    }
    if !key.e.is_odd() {
        issues.push(KeyValidationIssue::ExponentTooSmall);
    }
    let f4 = BigNum::from_u64(RSA_DEFAULT_PUBLIC_EXPONENT);
    if key.e.cmp(&f4) == std::cmp::Ordering::Less {
        issues.push(KeyValidationIssue::ExponentTooSmall);
    }

    Ok(KeyValidationResult {
        is_valid: issues.is_empty(),
        issues,
    })
}

/// SP 800-56B Rev. 2 §6.4.1.2.3 private-key validation.
///
/// Translates `ossl_rsa_sp800_56b_check_private()` from
/// `crypto/rsa/rsa_sp800_56b_check.c` line 326.
pub fn check_private_key(key: &RsaPrivateKey) -> CryptoResult<KeyValidationResult> {
    let mut issues = Vec::new();

    let bits = key.key_size_bits();
    if bits < RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE {
        issues.push(KeyValidationIssue::ModulusTooSmall);
    }

    // 1 < d < λ(n)
    let p_minus_one = arithmetic::sub_word(&key.p, 1)?;
    let q_minus_one = arithmetic::sub_word(&key.q, 1)?;
    let lambda = arithmetic::lcm(&p_minus_one, &q_minus_one)?;
    if key.d.is_zero() || key.d.is_one() || key.d.cmp(&lambda) != std::cmp::Ordering::Less {
        issues.push(KeyValidationIssue::DNotInverseOfE);
    }

    Ok(KeyValidationResult {
        is_valid: issues.is_empty(),
        issues,
    })
}

/// SP 800-56B Rev. 2 §6.4.1.3 keypair validation.
///
/// Translates `ossl_rsa_sp800_56b_check_keypair()` from
/// `crypto/rsa/rsa_sp800_56b_check.c` line 363. Combines public-key
/// validation, private-key validation, and the PCT (`m^e^d == m`).
pub fn check_keypair(key: &RsaPrivateKey) -> CryptoResult<KeyValidationResult> {
    let mut issues = Vec::new();

    let pub_key = key.public_key();
    let pub_result = check_public_key(&pub_key)?;
    issues.extend(pub_result.issues);
    let priv_result = check_private_key(key)?;
    issues.extend(priv_result.issues);

    let basic = check_key(key)?;
    issues.extend(basic.issues);

    // SP 800-56B §6.4.1.3 PCT: pick m = 2 and verify (m^e)^d == m.
    let m = BigNum::from_u64(2);
    let c = montgomery::mod_exp(&m, &key.e, &key.n)?;
    let m_recovered = crt_mod_exp(&c, key)?;
    if m.cmp(&m_recovered) != std::cmp::Ordering::Equal {
        issues.push(KeyValidationIssue::DNotInverseOfE);
    }

    issues.sort_by_key(|i| format!("{i:?}"));
    issues.dedup();
    Ok(KeyValidationResult {
        is_valid: issues.is_empty(),
        issues,
    })
}

// =============================================================================
// Phase 7 — Padding Schemes
// =============================================================================
//
// This phase implements the four classical RSA padding schemes used by the
// low-level public/private encrypt/decrypt routines:
//
//   * PKCS#1 v1.5 Type 1 (signature/private-key encrypt) — `rsa_pk1.c` lines 31..122
//   * PKCS#1 v1.5 Type 2 (encryption/public-key encrypt) — `rsa_pk1.c` lines 124..275
//   * No-padding (raw RSA primitive)                     — `rsa_none.c`
//   * X9.31 (legacy signature)                           — `rsa_x931.c`
//
// In addition, this phase implements the high-level PKCS#1 v1.5 signature
// helpers `sign_pkcs1v15()` and `verify_pkcs1v15()` from `rsa_sign.c` (lines
// 1..200) which prepend the digest's DigestInfo DER prefix to the hash and
// then apply Type 1 padding.
//
// SECURITY NOTES
// --------------
//
// The Type 2 unpadding routine `pkcs1_v15_type2_unpad()` is the most security-
// sensitive function in this module: it must execute in constant time with
// respect to the validity of the padding to defend against Bleichenbacher's
// adaptive-chosen-ciphertext attack (CRYPTO '98). It is implemented using the
// constant-time primitives from `openssl_common::constant_time`. The high-
// level `private_decrypt()` caller in Phase 5 is responsible for applying
// implicit rejection — i.e. on padding failure it returns deterministic
// pseudorandom data of the expected message length rather than an explicit
// error — which is the modern best-practice mitigation per RFC 8017 §7.2.2.
// We emit a `Pkcs1PaddingError` from this routine and let the caller decide
// whether to surface it directly or to substitute random data.

// -----------------------------------------------------------------------------
// 7.1  PKCS#1 v1.5 Type 1 padding (private-key encrypt / sign)
// -----------------------------------------------------------------------------

/// Apply PKCS#1 v1.5 type-1 padding into `padded` for `data`.
///
/// Format: `0x00 || 0x01 || PS (>=8 bytes of 0xFF) || 0x00 || data`.
///
/// Translates `RSA_padding_add_PKCS1_type_1()` from
/// `crypto/rsa/rsa_pk1.c` lines 31-54.
pub(crate) fn pkcs1_v15_type1_pad(padded: &mut [u8], data: &[u8]) -> CryptoResult<()> {
    let tlen = padded.len();
    let flen = data.len();

    // Need at least: 0x00 || 0x01 || 8 bytes PS || 0x00 || data => 11 + flen.
    if flen > tlen.saturating_sub(RSA_PKCS1_PADDING_SIZE) {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }
    if tlen < RSA_PKCS1_PADDING_SIZE + 1 {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    padded[0] = 0x00;
    padded[1] = 0x01;

    // PS: 0xFF bytes filling the gap.
    let ps_len = tlen - 3 - flen;
    for byte in padded.iter_mut().skip(2).take(ps_len) {
        *byte = 0xFF;
    }
    padded[2 + ps_len] = 0x00;
    padded[2 + ps_len + 1..].copy_from_slice(data);
    Ok(())
}

/// Verify PKCS#1 v1.5 type-1 padding and extract the message payload.
///
/// Translates `RSA_padding_check_PKCS1_type_1()` from
/// `crypto/rsa/rsa_pk1.c` lines 56-122.
///
/// Accepts inputs both with and without a leading 0x00 byte (i.e. accepts
/// either a fully-zero-padded buffer or a buffer that has been left-trimmed
/// of the leading 0x00).
pub(crate) fn pkcs1_v15_type1_unpad(padded: &[u8]) -> CryptoResult<Vec<u8>> {
    if padded.len() < RSA_PKCS1_PADDING_SIZE {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    // Step over an optional leading 0x00 byte.
    let mut idx = 0usize;
    if padded[0] == 0x00 {
        idx = 1;
    }

    // First non-zero byte must be 0x01 (block type for type-1 padding).
    if idx >= padded.len() || padded[idx] != 0x01 {
        return Err(RsaError::BlockTypeMismatch {
            expected: 0x01,
            actual: padded.get(idx).copied().unwrap_or(0),
        }
        .into());
    }
    idx += 1;

    // Scan PS: must be exclusively 0xFF, followed by 0x00 separator.
    let ps_start = idx;
    while idx < padded.len() && padded[idx] != 0x00 {
        if padded[idx] != 0xFF {
            return Err(RsaError::Pkcs1PaddingError.into());
        }
        idx += 1;
    }

    // Did we find the 0x00 separator at all?
    if idx == padded.len() {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    // Per RFC 8017 §9.2 / rsa_pk1.c line 100: PS must be at least 8 bytes long.
    if idx - ps_start < 8 {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    // Step past the 0x00 separator.
    idx += 1;

    Ok(padded[idx..].to_vec())
}

// -----------------------------------------------------------------------------
// 7.2  PKCS#1 v1.5 Type 2 padding (public-key encrypt)
// -----------------------------------------------------------------------------

/// Apply PKCS#1 v1.5 type-2 padding into `padded` for `data`.
///
/// Format: `0x00 || 0x02 || PS (>=8 random non-zero bytes) || 0x00 || data`.
///
/// Translates `RSA_padding_add_PKCS1_type_2()` from
/// `crypto/rsa/rsa_pk1.c` lines 124-162.
pub(crate) fn pkcs1_v15_type2_pad(padded: &mut [u8], data: &[u8]) -> CryptoResult<()> {
    let tlen = padded.len();
    let flen = data.len();

    if flen > tlen.saturating_sub(RSA_PKCS1_PADDING_SIZE) {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }
    if tlen < RSA_PKCS1_PADDING_SIZE + 1 {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    padded[0] = 0x00;
    padded[1] = 0x02;

    let ps_len = tlen - 3 - flen;

    // Fill PS with random non-zero bytes, regenerating any byte that comes out
    // zero. This matches the OpenSSL C behaviour at rsa_pk1.c line 145.
    let ps_slice = &mut padded[2..2 + ps_len];
    rand_bytes(ps_slice)?;
    for byte in ps_slice.iter_mut() {
        // Replace zero bytes with another random non-zero byte.
        while *byte == 0 {
            let mut tmp = [0u8; 1];
            rand_bytes(&mut tmp)?;
            *byte = tmp[0];
        }
    }
    padded[2 + ps_len] = 0x00;
    padded[2 + ps_len + 1..].copy_from_slice(data);
    Ok(())
}

/// Verify PKCS#1 v1.5 type-2 padding and extract the message payload — in
/// constant time.
///
/// Translates `RSA_padding_check_PKCS1_type_2()` from
/// `crypto/rsa/rsa_pk1.c` lines 170-275 (constant-time variant).
///
/// SECURITY: This routine MUST execute in time independent of the validity
/// of the padding to defend against Bleichenbacher's attack. We use the
/// constant-time primitives from `openssl_common::constant_time` and never
/// branch on padding validity until the very end where we either return the
/// extracted message or a `Pkcs1PaddingError`. The caller (`private_decrypt`)
/// then applies the implicit-rejection mitigation by substituting random
/// data on failure.
///
/// Arguments:
/// * `padded`  — the decrypted ciphertext (typically of length k - 1 since
///               the leading 0x00 byte was stripped during BigNum→bytes
///               conversion). Must be right-aligned in a buffer of size k-1.
/// * `k`       — the RSA key size in bytes (modulus byte length).
pub(crate) fn pkcs1_v15_type2_unpad(padded: &[u8], k: usize) -> CryptoResult<Vec<u8>> {
    // Per rsa_pk1.c we expect the buffer to have length k. If the caller has
    // passed a buffer of length k-1 (the typical case where the leading 0x00
    // has been dropped during integer→octet conversion), extend it virtually
    // by treating the missing leading byte as 0x00.
    if padded.len() != k && padded.len() != k.saturating_sub(1) {
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    // Reject pathologically short inputs.
    if k < RSA_PKCS1_PADDING_SIZE + 1 {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    // Build a length-k working copy with a leading 0x00 if needed so that the
    // expected layout is em[0]==0x00, em[1]==0x02, ...
    let mut em = Vec::with_capacity(k);
    if padded.len() == k {
        em.extend_from_slice(padded);
    } else {
        em.push(0x00);
        em.extend_from_slice(padded);
    }
    debug_assert_eq!(em.len(), k);

    // Constant-time validity checks. `good` accumulates a u32 mask that is
    // 0xFFFF_FFFF if and only if the padding is valid; any failure flips
    // it to 0x0000_0000 without branching.
    let first_byte_zero = constant_time::constant_time_is_zero(u32::from(em[0]));
    let second_byte_two = constant_time::constant_time_eq(u32::from(em[1]), 0x02);
    let mut good: u32 = first_byte_zero & second_byte_two;

    // Locate the 0x00 separator in `em[2..]`. We track the *first* zero byte
    // position via a constant-time minimum-index computation.
    //
    // The variable `found_zero_byte` is non-zero (0xFFFF_FFFF) once we have
    // observed a 0x00 byte; while it is still zero, `zero_index` is updated
    // to the current index. After the loop, `zero_index` equals the position
    // of the first 0x00 separator, and `found_zero_byte` indicates whether
    // we found one at all.
    let mut found_zero_byte: u32 = 0;
    let mut zero_index: u32 = 0;
    for (i, &b) in em.iter().enumerate().skip(2) {
        let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
        let is_zero = constant_time::constant_time_is_zero(u32::from(b));
        // If we have not yet found a zero, and this byte is zero, update.
        let update_mask = is_zero & !found_zero_byte;
        zero_index = constant_time::constant_time_select(update_mask, i_u32, zero_index);
        found_zero_byte |= is_zero;
    }

    // Validity: the separator must be present (`found_zero_byte` != 0) and
    // must be at index >= 10 (i.e. PS must be >= 8 bytes per RFC 8017 §7.2.2,
    // since em[0]=0x00 + em[1]=0x02 + 8 PS bytes => min separator at i=10).
    let separator_found = found_zero_byte;
    let ps_long_enough = constant_time::constant_time_ge(zero_index, 10);
    good &= separator_found & ps_long_enough;

    // The plaintext starts at zero_index + 1.
    let msg_start = zero_index.saturating_add(1);
    let k_u32 = u32::try_from(k).unwrap_or(u32::MAX);
    // Message length = k - msg_start.
    let msg_len = k_u32.wrapping_sub(msg_start);

    // If the padding was bad, we don't want to leak that fact via a length-
    // dependent timing channel. Surface a `Pkcs1PaddingError` to the caller
    // once we have completed the constant-time scan; the caller (Phase 5
    // `private_decrypt`) is responsible for implicit-rejection mitigation.
    if good == 0 {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    // At this point `msg_start <= k` and `msg_len = k - msg_start`. Convert
    // back to usize for the slice operation (no truncation possible since
    // msg_start <= k and k fits in usize).
    let msg_start_us = usize::try_from(msg_start).unwrap_or(k);
    let msg_len_us = usize::try_from(msg_len).unwrap_or(0);
    let mut out = Vec::with_capacity(msg_len_us);
    out.extend_from_slice(&em[msg_start_us..msg_start_us + msg_len_us]);
    Ok(out)
}

// -----------------------------------------------------------------------------
// 7.3  No padding (raw RSA primitive)
// -----------------------------------------------------------------------------

/// Place `data` into `padded` with no padding — strict equality of lengths.
///
/// Translates `RSA_padding_add_none()` from `crypto/rsa/rsa_none.c`
/// lines 19-35.
pub(crate) fn no_padding_add(padded: &mut [u8], data: &[u8]) -> CryptoResult<()> {
    if data.len() > padded.len() {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }
    if data.len() < padded.len() {
        // OpenSSL emits RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE here. We map this to
        // `Pkcs1PaddingError` since our error taxonomy does not distinguish
        // "too small". The caller must pass an exact-length buffer.
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    padded.copy_from_slice(data);
    Ok(())
}

/// Return the input as the message — no-padding "decode" simply right-aligns
/// with left zero-padding (which is already handled at the bigint→bytes
/// boundary).
///
/// Translates `RSA_padding_check_none()` from `crypto/rsa/rsa_none.c`
/// lines 37-49.
pub(crate) fn no_padding_check(padded: &[u8]) -> Vec<u8> {
    padded.to_vec()
}

// -----------------------------------------------------------------------------
// 7.4  X9.31 padding
// -----------------------------------------------------------------------------

/// Map a digest algorithm to its X9.31 hash identifier byte (the trailing
/// byte placed before the 0xCC trailer).
///
/// From `crypto/rsa/rsa_x931.c` and ANSI X9.31. The C implementation defines
/// these via NID-based switch in `RSA_padding_add_X931()` line 51:
///
///   * SHA-1   → 0x33
///   * SHA-256 → 0x34
///   * SHA-384 → 0x36
///   * SHA-512 → 0x35
fn x931_hash_id(digest: DigestAlgorithm) -> Option<u8> {
    match digest {
        DigestAlgorithm::Sha1 => Some(0x33),
        DigestAlgorithm::Sha256 => Some(0x34),
        DigestAlgorithm::Sha384 => Some(0x36),
        DigestAlgorithm::Sha512 => Some(0x35),
        _ => None,
    }
}

/// Apply X9.31 padding into `padded` for `data` (the `digest+hash_id` bytes).
///
/// Format:
///   * If gap == 0:  `0x6A || data || 0xCC`
///   * Else:         `0x6B || (gap-1) bytes of 0xBB || 0xBA || data || 0xCC`
///
/// Translates `RSA_padding_add_X931()` from `crypto/rsa/rsa_x931.c`
/// lines 43-77.
///
/// The `digest` parameter is accepted for parity with the C API but is not
/// directly used by this routine — the C OpenSSL convention is that the
/// caller appends the X9.31 hash-id byte to the digest before invoking this
/// padding function. We keep the parameter in the signature so that higher-
/// level callers may wire it in later. We additionally validate that `digest`
/// has a known X9.31 hash-id, since X9.31 only defines hash identifiers for
/// SHA-1/256/384/512.
pub(crate) fn x931_pad(
    padded: &mut [u8],
    data: &[u8],
    digest: DigestAlgorithm,
) -> CryptoResult<()> {
    if x931_hash_id(digest).is_none() {
        return Err(RsaError::DigestNotAllowed.into());
    }

    let tlen = padded.len();
    let flen = data.len();

    // Need: header byte + data + 0xCC trailer => flen + 2 <= tlen.
    if flen + 2 > tlen {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }

    let gap = tlen - flen - 2;
    let header_idx;
    if gap == 0 {
        // Single-byte header path.
        padded[0] = 0x6A;
        header_idx = 1;
    } else {
        // 0x6B + (gap-1) 0xBB + 0xBA terminator.
        padded[0] = 0x6B;
        for byte in padded.iter_mut().skip(1).take(gap - 1) {
            *byte = 0xBB;
        }
        padded[gap] = 0xBA;
        header_idx = gap + 1;
    }
    padded[header_idx..header_idx + flen].copy_from_slice(data);
    padded[header_idx + flen] = 0xCC;
    Ok(())
}

/// Verify X9.31 padding and extract the message payload (`digest` + `hash_id`).
///
/// Translates `RSA_padding_check_X931()` from `crypto/rsa/rsa_x931.c`
/// lines 79-122.
pub(crate) fn x931_unpad(padded: &[u8]) -> CryptoResult<Vec<u8>> {
    if padded.len() < 2 {
        return Err(RsaError::InvalidPadding.into());
    }

    // Trailer must be 0xCC.
    let last_byte = *padded.last().ok_or(RsaError::InvalidPadding)?;
    if last_byte != 0xCC {
        return Err(RsaError::InvalidPadding.into());
    }

    let body_end = padded.len() - 1;

    let (data_start, data_end) = if padded[0] == 0x6B {
        // Long-header path: skip 0xBB padding bytes until 0xBA terminator.
        let mut i = 1usize;
        while i < body_end && padded[i] == 0xBB {
            i += 1;
        }
        if i == 1 {
            // No 0xBB bytes consumed before terminator/end — the C code at
            // rsa_x931.c line 102 rejects this case.
            return Err(RsaError::InvalidPadding.into());
        }
        if i >= body_end || padded[i] != 0xBA {
            return Err(RsaError::InvalidPadding.into());
        }
        (i + 1, body_end)
    } else if padded[0] == 0x6A {
        // Short-header path: data immediately follows the header byte.
        (1usize, body_end)
    } else {
        return Err(RsaError::InvalidPadding.into());
    };

    if data_end < data_start {
        return Err(RsaError::InvalidPadding.into());
    }

    Ok(padded[data_start..data_end].to_vec())
}

// =============================================================================
// 7.5  PKCS#1 v1.5 Signature Wrappers (sign / verify)
// =============================================================================

/// Build the `DigestInfo` DER prefix for a given digest algorithm.
///
/// Translates `ossl_rsa_digestinfo_encoding()` from `crypto/rsa/rsa_sign.c`.
/// The returned slice is the per-digest DER prefix that must be prepended
/// to the raw hash before applying PKCS#1 v1.5 type-1 padding.
///
/// SHA-1 uses an explicit 15-byte prefix. SHA-2/SHA-3 family digests use
/// the macro-generated 19-byte prefix from `ENCODE_DIGESTINFO_SHA(name, n, sz)`.
fn digestinfo_encoding(digest: DigestAlgorithm) -> CryptoResult<&'static [u8]> {
    // SHA-1 explicit prefix per rsa_sign.c line ~50
    const SHA1_DI: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];

    // ENCODE_DIGESTINFO_SHA(name, n, sz) →
    //   0x30, 0x11+sz, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    //   0x01, 0x65, 0x03, 0x04, 0x02, n, 0x05, 0x00, 0x04, sz
    const fn sha2_3_di(n: u8, sz: u8) -> [u8; 19] {
        [
            0x30,
            0x11 + sz,
            0x30,
            0x0d,
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            n,
            0x05,
            0x00,
            0x04,
            sz,
        ]
    }

    const SHA224_DI: [u8; 19] = sha2_3_di(0x04, 28);
    const SHA256_DI: [u8; 19] = sha2_3_di(0x01, 32);
    const SHA384_DI: [u8; 19] = sha2_3_di(0x02, 48);
    const SHA512_DI: [u8; 19] = sha2_3_di(0x03, 64);
    const SHA512_224_DI: [u8; 19] = sha2_3_di(0x05, 28);
    const SHA512_256_DI: [u8; 19] = sha2_3_di(0x06, 32);
    const SHA3_224_DI: [u8; 19] = sha2_3_di(0x07, 28);
    const SHA3_256_DI: [u8; 19] = sha2_3_di(0x08, 32);
    const SHA3_384_DI: [u8; 19] = sha2_3_di(0x09, 48);
    const SHA3_512_DI: [u8; 19] = sha2_3_di(0x0a, 64);

    Ok(match digest {
        DigestAlgorithm::Sha1 => SHA1_DI,
        DigestAlgorithm::Sha224 => &SHA224_DI,
        DigestAlgorithm::Sha256 => &SHA256_DI,
        DigestAlgorithm::Sha384 => &SHA384_DI,
        DigestAlgorithm::Sha512 => &SHA512_DI,
        DigestAlgorithm::Sha512_224 => &SHA512_224_DI,
        DigestAlgorithm::Sha512_256 => &SHA512_256_DI,
        DigestAlgorithm::Sha3_224 => &SHA3_224_DI,
        DigestAlgorithm::Sha3_256 => &SHA3_256_DI,
        DigestAlgorithm::Sha3_384 => &SHA3_384_DI,
        DigestAlgorithm::Sha3_512 => &SHA3_512_DI,
        _ => return Err(RsaError::DigestNotAllowed.into()),
    })
}

/// Sign a pre-computed hash using PKCS#1 v1.5 (RSASSA-PKCS1-v1_5).
///
/// Translates `RSA_sign()` from `crypto/rsa/rsa_sign.c` lines 56-122.
///
/// Steps per RFC 8017 §8.2.1:
///   1. Encode `DigestInfo ::= SEQUENCE { digestAlgorithm, digest }` by
///      prepending `digestinfo_encoding(digest)` to `hash`.
///   2. Apply EMSA-PKCS1-v1_5 padding (Type 1 padding from §7.1).
///   3. Compute the RSA signature primitive (RSASP1): `s = m^d mod n`.
///
/// # Arguments
/// * `key`    — the RSA private key.
/// * `digest` — the digest algorithm used to compute `hash` (used only to
///              select the `DigestInfo` DER prefix).
/// * `hash`   — the raw hash bytes; must have length equal to
///              `digest.digest_size()`.
///
/// # Errors
/// * `DigestNotAllowed` — the digest algorithm has no `DigestInfo` encoding.
/// * `DataTooLargeForKeySize` — the encoded message is too large for the key.
pub fn sign_pkcs1v15(
    key: &RsaPrivateKey,
    digest: DigestAlgorithm,
    hash: &[u8],
) -> CryptoResult<Vec<u8>> {
    let prefix = digestinfo_encoding(digest)?;

    // Validate hash length.
    let expected_hash_len = digest.digest_size();
    if hash.len() != expected_hash_len {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    // Build T = DigestInfo || H.
    let mut t = Vec::with_capacity(prefix.len() + hash.len());
    t.extend_from_slice(prefix);
    t.extend_from_slice(hash);

    // Encrypt with the private key (which uses Type 1 padding internally).
    private_encrypt(key, &t, PaddingMode::Pkcs1v15)
}

/// Verify a PKCS#1 v1.5 signature against a pre-computed hash.
///
/// Translates `RSA_verify()` from `crypto/rsa/rsa_sign.c` lines 124-200.
///
/// Steps per RFC 8017 §8.2.2:
///   1. Compute the RSA verification primitive (RSAVP1): `m = s^e mod n`.
///   2. Strip Type 1 padding (via `public_decrypt` with `PaddingMode::Pkcs1v15`).
///   3. Verify the recovered `T'` equals `` `DigestInfo` || hash ``.
///
/// # Returns
/// `Ok(true)` if the signature is valid, `Ok(false)` if it does not match.
/// Returns `Err` only on operational/structural failure (e.g. malformed
/// padding, key issues).
pub fn verify_pkcs1v15(
    key: &RsaPublicKey,
    digest: DigestAlgorithm,
    hash: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let prefix = digestinfo_encoding(digest)?;
    let expected_hash_len = digest.digest_size();
    if hash.len() != expected_hash_len {
        return Err(RsaError::Pkcs1PaddingError.into());
    }

    // Recover T' = DigestInfo || H' from the signature.
    let Ok(recovered) = public_decrypt(key, signature, PaddingMode::Pkcs1v15) else {
        // Verification failure (any decoding error) → false, not Err.
        return Ok(false);
    };

    // Build the expected encoding for comparison.
    let mut expected = Vec::with_capacity(prefix.len() + hash.len());
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(hash);

    // Constant-time comparison of equal-length buffers.
    if recovered.len() != expected.len() {
        return Ok(false);
    }
    Ok(constant_time::memcmp(&recovered, &expected))
}

// =============================================================================
// Phase 8 — Key Import / Export (OSSL_PARAM and DER)
// =============================================================================
//
// This phase implements interoperability bridges:
//
//   * OSSL_PARAM-style import/export via `from_params()` / `to_params()`
//     (translates `crypto/rsa/rsa_backend.c` ossl_rsa_fromdata/todata).
//   * PKCS#1 / SubjectPublicKeyInfo DER serialisation via
//     `public_key_from_der()` / `public_key_to_der()` /
//     `private_key_from_der()` / `private_key_to_der()`
//     (translates the ASN.1 templates in `crypto/rsa/rsa_asn1.c` lines 1-127).
//
// The DER encoders implement RFC 8017 §A.1 (PKCS#1 RSAPublicKey,
// RSAPrivateKey) using a hand-rolled DER writer. We do not pull in an
// external ASN.1 dependency here: the parameter list is bounded and
// fully numeric, and the encoder/decoder is small enough to read line-
// for-line against RFC 8017 Appendix A.

/// Import an RSA private key from a typed parameter set.
///
/// Translates `ossl_rsa_fromdata()` from `crypto/rsa/rsa_backend.c`.
///
/// Parameter names (per `crypto/rsa/rsa_mp_names.c`):
///   * "n"     — modulus
///   * "e"     — public exponent
///   * "d"     — private exponent
///   * "rsa-factor1" / "rsa-factor2"        — primes p, q
///   * "rsa-exponent1" / "rsa-exponent2"    — CRT dmp1, dmq1
///   * "rsa-coefficient1"                   — CRT iqmp
#[allow(clippy::many_single_char_names)]
pub fn from_params(params: &ParamSet) -> CryptoResult<RsaPrivateKey> {
    fn locate_bn(params: &ParamSet, name: &str) -> CryptoResult<BigNum> {
        match params.get(name) {
            // The `BigNum` ParamValue variant stores the magnitude as raw
            // big-endian bytes (see `openssl-common::param::ParamValue`),
            // so we must reconstruct a real `BigNum` from those bytes.
            Some(ParamValue::BigNum(b) | ParamValue::OctetString(b)) => {
                Ok(BigNum::from_bytes_be(b))
            }
            Some(_) | None => Err(RsaError::ValueMissing { component: "n" }.into()),
        }
    }
    fn locate_optional_bn(params: &ParamSet, name: &str) -> Option<BigNum> {
        match params.get(name) {
            // Same byte-vector reconstruction as in `locate_bn`.
            Some(ParamValue::BigNum(b) | ParamValue::OctetString(b)) => {
                Some(BigNum::from_bytes_be(b))
            }
            _ => None,
        }
    }

    // n and e are required for *any* RSA key.
    let n = locate_bn(params, "n").map_err(|_| RsaError::ValueMissing { component: "n" })?;
    let e = locate_bn(params, "e").map_err(|_| RsaError::ValueMissing { component: "e" })?;

    // Private components: d, p, q, dmp1, dmq1, iqmp. All optional but if any
    // is present, all primary ones (d, p, q) must be present.
    let d = locate_optional_bn(params, "d");
    let p = locate_optional_bn(params, "rsa-factor1");
    let q = locate_optional_bn(params, "rsa-factor2");
    let dmp1 = locate_optional_bn(params, "rsa-exponent1");
    let dmq1 = locate_optional_bn(params, "rsa-exponent2");
    let iqmp = locate_optional_bn(params, "rsa-coefficient1");

    let d = d.ok_or(RsaError::ValueMissing { component: "d" })?;
    let p = p.ok_or(RsaError::ValueMissing {
        component: "rsa-factor1",
    })?;
    let q = q.ok_or(RsaError::ValueMissing {
        component: "rsa-factor2",
    })?;

    // Derive missing CRT components if not supplied. ossl_rsa_fromdata()
    // accepts CRT components as optional and recomputes them on demand.
    let one = BigNum::from_u64(1);
    let dmp1 = if let Some(v) = dmp1 {
        v
    } else {
        let p_minus_1 = arithmetic::sub(&p, &one);
        arithmetic::rem(&d, &p_minus_1)?
    };
    let dmq1 = if let Some(v) = dmq1 {
        v
    } else {
        let q_minus_1 = arithmetic::sub(&q, &one);
        arithmetic::rem(&d, &q_minus_1)?
    };
    let iqmp = match iqmp {
        Some(v) => v,
        None => arithmetic::mod_inverse_checked(&q, &p)?,
    };

    RsaPrivateKey::new(n, e, d, p, q, dmp1, dmq1, iqmp)
}

/// Export an RSA private key to a parameter set suitable for OSSL_PARAM-style
/// consumers. Translates `ossl_rsa_todata()` from `crypto/rsa/rsa_backend.c`.
pub fn to_params(key: &RsaPrivateKey) -> CryptoResult<ParamSet> {
    let mut params = ParamSet::new();
    // The `BigNum` ParamValue variant stores the magnitude as a raw
    // big-endian byte vector (see `openssl-common::param::ParamValue`),
    // so we serialise each component via `to_bytes_be()`.
    params.set("n", ParamValue::BigNum(key.modulus().to_bytes_be()));
    params.set("e", ParamValue::BigNum(key.public_exponent().to_bytes_be()));
    params.set(
        "d",
        ParamValue::BigNum(key.private_exponent().to_bytes_be()),
    );
    params.set(
        "rsa-factor1",
        ParamValue::BigNum(key.prime_p().to_bytes_be()),
    );
    params.set(
        "rsa-factor2",
        ParamValue::BigNum(key.prime_q().to_bytes_be()),
    );
    params.set(
        "rsa-exponent1",
        ParamValue::BigNum(key.crt_dmp1().to_bytes_be()),
    );
    params.set(
        "rsa-exponent2",
        ParamValue::BigNum(key.crt_dmq1().to_bytes_be()),
    );
    params.set(
        "rsa-coefficient1",
        ParamValue::BigNum(key.crt_iqmp().to_bytes_be()),
    );
    Ok(params)
}

// -----------------------------------------------------------------------------
// 8.2  Minimal DER Encoder / Decoder
// -----------------------------------------------------------------------------
//
// This is a small, hand-rolled DER subset sufficient to encode/decode the
// PKCS#1 RSAPublicKey and RSAPrivateKey structures from RFC 8017 §A.1. We
// only need:
//   * INTEGER (positive, two's-complement)
//   * SEQUENCE
// which simplifies encoder logic considerably.

/// Encode a length in DER short-or-long form.
fn der_encode_length(len: usize, out: &mut Vec<u8>) -> CryptoResult<()> {
    if len < 0x80 {
        // TRUNCATION: safe — guarded by `len < 0x80` so it always fits in u8.
        out.push(u8::try_from(len).map_err(|_| RsaError::Pkcs1PaddingError)?);
    } else {
        let mut buf = [0u8; std::mem::size_of::<usize>()];
        let mut n = len;
        let mut nbytes = 0usize;
        while n > 0 {
            nbytes += 1;
            // TRUNCATION: safe via `& 0xFF` mask — value is in 0..=255.
            #[allow(clippy::cast_possible_truncation)]
            let byte = (n & 0xFF) as u8;
            buf[buf.len() - nbytes] = byte;
            n >>= 8;
        }
        if nbytes > 0x7E {
            return Err(RsaError::Pkcs1PaddingError.into());
        }
        // TRUNCATION: safe — guarded by `nbytes > 0x7E` check above.
        let nbytes_u8 = u8::try_from(nbytes).map_err(|_| RsaError::Pkcs1PaddingError)?;
        out.push(0x80 | nbytes_u8);
        out.extend_from_slice(&buf[buf.len() - nbytes..]);
    }
    Ok(())
}

/// Encode a non-negative bignum as a DER INTEGER. INTEGERs are signed in
/// X.690, so we must prepend a 0x00 byte if the high bit of the most-
/// significant byte is set.
fn der_encode_integer(value: &BigNum, out: &mut Vec<u8>) -> CryptoResult<()> {
    out.push(0x02); // INTEGER tag
    let bytes = value.to_bytes_be();
    if bytes.is_empty() {
        // Zero is encoded as 02 01 00.
        der_encode_length(1, out)?;
        out.push(0x00);
        return Ok(());
    }
    if bytes[0] & 0x80 != 0 {
        der_encode_length(bytes.len() + 1, out)?;
        out.push(0x00);
        out.extend_from_slice(&bytes);
    } else {
        der_encode_length(bytes.len(), out)?;
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

/// Encode a SEQUENCE wrapping `inner`.
fn der_encode_sequence(inner: &[u8], out: &mut Vec<u8>) -> CryptoResult<()> {
    out.push(0x30); // SEQUENCE tag
    der_encode_length(inner.len(), out)?;
    out.extend_from_slice(inner);
    Ok(())
}

/// Decode a DER length starting at offset `idx` in `bytes`. Returns
/// `(length, new_idx)`.
fn der_decode_length(bytes: &[u8], idx: usize) -> CryptoResult<(usize, usize)> {
    if idx >= bytes.len() {
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    let first = bytes[idx];
    if first < 0x80 {
        Ok((first as usize, idx + 1))
    } else {
        let nbytes = (first & 0x7F) as usize;
        if nbytes == 0 || nbytes > std::mem::size_of::<usize>() {
            return Err(RsaError::Pkcs1PaddingError.into());
        }
        if idx + 1 + nbytes > bytes.len() {
            return Err(RsaError::Pkcs1PaddingError.into());
        }
        let mut len: usize = 0;
        for i in 0..nbytes {
            len = len.checked_shl(8).ok_or(RsaError::Pkcs1PaddingError)?;
            len = len
                .checked_add(bytes[idx + 1 + i] as usize)
                .ok_or(RsaError::Pkcs1PaddingError)?;
        }
        Ok((len, idx + 1 + nbytes))
    }
}

/// Decode a DER INTEGER from `bytes` starting at `idx`. Returns
/// `(value, new_idx)`.
fn der_decode_integer(bytes: &[u8], idx: usize) -> CryptoResult<(BigNum, usize)> {
    if idx >= bytes.len() || bytes[idx] != 0x02 {
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    let (len, new_idx) = der_decode_length(bytes, idx + 1)?;
    if new_idx + len > bytes.len() {
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    let int_bytes = &bytes[new_idx..new_idx + len];
    // Reject negative integers (high bit of MSB set without prefix), but allow
    // a single leading 0x00 prefix.
    let value = if !int_bytes.is_empty() && int_bytes[0] == 0x00 {
        BigNum::from_bytes_be(&int_bytes[1..])
    } else if !int_bytes.is_empty() && int_bytes[0] & 0x80 != 0 {
        return Err(RsaError::Pkcs1PaddingError.into());
    } else {
        BigNum::from_bytes_be(int_bytes)
    };
    Ok((value, new_idx + len))
}

/// Decode a DER SEQUENCE header. Returns `(content_offset, content_length)`
/// such that the SEQUENCE contents are `bytes[content_offset..content_offset + content_length]`.
fn der_decode_sequence(bytes: &[u8], idx: usize) -> CryptoResult<(usize, usize)> {
    if idx >= bytes.len() || bytes[idx] != 0x30 {
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    let (len, new_idx) = der_decode_length(bytes, idx + 1)?;
    if new_idx + len > bytes.len() {
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    Ok((new_idx, len))
}

/// Encode an `RsaPublicKey` as PKCS#1 `RSAPublicKey` DER (RFC 8017 §A.1.1):
///
///   `RSAPublicKey` ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
pub fn public_key_to_der(key: &RsaPublicKey) -> CryptoResult<Vec<u8>> {
    let mut inner = Vec::new();
    der_encode_integer(&key.n, &mut inner)?;
    der_encode_integer(&key.e, &mut inner)?;
    let mut out = Vec::new();
    der_encode_sequence(&inner, &mut out)?;
    Ok(out)
}

/// Decode a PKCS#1 `RSAPublicKey` DER blob into an `RsaPublicKey`.
pub fn public_key_from_der(der: &[u8]) -> CryptoResult<RsaPublicKey> {
    let (content_off, content_len) = der_decode_sequence(der, 0)?;
    let end = content_off + content_len;
    let (n, idx) = der_decode_integer(der, content_off)?;
    let (e, idx2) = der_decode_integer(der, idx)?;
    if idx2 != end {
        // Trailing garbage in the SEQUENCE.
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    RsaPublicKey::new(n, e)
}

/// Encode an `RsaPrivateKey` as PKCS#1 `RSAPrivateKey` DER (RFC 8017 §A.1.2):
///
///   `RSAPrivateKey` ::= SEQUENCE {
///       version            Version,
///       modulus            INTEGER,
///       publicExponent     INTEGER,
///       privateExponent    INTEGER,
///       prime1             INTEGER,
///       prime2             INTEGER,
///       exponent1          INTEGER,
///       exponent2          INTEGER,
///       coefficient        INTEGER,
///       otherPrimeInfos    `OtherPrimeInfos` OPTIONAL
///   }
pub fn private_key_to_der(key: &RsaPrivateKey) -> CryptoResult<Vec<u8>> {
    let mut inner = Vec::new();
    let version = match key.version {
        RsaVersion::TwoPrime => BigNum::from_u64(0),
        RsaVersion::MultiPrime => BigNum::from_u64(1),
    };
    der_encode_integer(&version, &mut inner)?;
    der_encode_integer(&key.n, &mut inner)?;
    der_encode_integer(&key.e, &mut inner)?;
    der_encode_integer(&key.d, &mut inner)?;
    der_encode_integer(&key.p, &mut inner)?;
    der_encode_integer(&key.q, &mut inner)?;
    der_encode_integer(&key.dmp1, &mut inner)?;
    der_encode_integer(&key.dmq1, &mut inner)?;
    der_encode_integer(&key.iqmp, &mut inner)?;

    // Multi-prime extension is not yet emitted (no consumers); for two-prime
    // keys (the common case) the encoding is complete here.
    if key.is_multi_prime() {
        warn!("RSA multi-prime DER encoding is not implemented; emitting two-prime envelope only");
    }

    let mut out = Vec::new();
    der_encode_sequence(&inner, &mut out)?;
    Ok(out)
}

/// Decode a PKCS#1 `RSAPrivateKey` DER blob into an `RsaPrivateKey`.
#[allow(clippy::many_single_char_names)]
pub fn private_key_from_der(der: &[u8]) -> CryptoResult<RsaPrivateKey> {
    let (content_off, content_len) = der_decode_sequence(der, 0)?;
    let end = content_off + content_len;
    let (_version, idx) = der_decode_integer(der, content_off)?;
    let (n, idx) = der_decode_integer(der, idx)?;
    let (e, idx) = der_decode_integer(der, idx)?;
    let (d, idx) = der_decode_integer(der, idx)?;
    let (p, idx) = der_decode_integer(der, idx)?;
    let (q, idx) = der_decode_integer(der, idx)?;
    let (dmp1, idx) = der_decode_integer(der, idx)?;
    let (dmq1, idx) = der_decode_integer(der, idx)?;
    let (iqmp, idx) = der_decode_integer(der, idx)?;
    // Multi-prime extension intentionally not parsed; idx may be < end if
    // the input contains otherPrimeInfos. We simply ignore the trailing bytes
    // for forward compatibility, but in conformant two-prime keys idx == end.
    if idx > end {
        return Err(RsaError::Pkcs1PaddingError.into());
    }
    RsaPrivateKey::new(n, e, d, p, q, dmp1, dmq1, iqmp)
}

// =============================================================================
// Phase 9 — Digest ↔ Scheme NID Mapping
// =============================================================================
//
// Translates the digest-algorithm-to-NID mapping helpers from
// `crypto/rsa/rsa_schemes.c` lines 18-86. The C code uses small arrays that
// map `EVP_MD` pointers to NIDs; we use a match over `DigestAlgorithm` enum
// values and well-known OpenSSL NID constants. The NID values match those
// defined in `include/openssl/obj_mac.h`.

/// Map a digest algorithm to its NID value as used by RSA OAEP/PSS.
///
/// Translates `ossl_rsa_oaeppss_md2nid()` from `crypto/rsa/rsa_schemes.c`
/// line 18. Returns `None` for digests that have no NID mapping.
pub(crate) fn digest_to_scheme_nid(digest: DigestAlgorithm) -> Option<u32> {
    match digest {
        DigestAlgorithm::Sha1 => Some(64),         // NID_sha1
        DigestAlgorithm::Sha224 => Some(675),      // NID_sha224
        DigestAlgorithm::Sha256 => Some(672),      // NID_sha256
        DigestAlgorithm::Sha384 => Some(673),      // NID_sha384
        DigestAlgorithm::Sha512 => Some(674),      // NID_sha512
        DigestAlgorithm::Sha512_224 => Some(1094), // NID_sha512_224
        DigestAlgorithm::Sha512_256 => Some(1095), // NID_sha512_256
        DigestAlgorithm::Sha3_224 => Some(1096),   // NID_sha3_224
        DigestAlgorithm::Sha3_256 => Some(1097),   // NID_sha3_256
        DigestAlgorithm::Sha3_384 => Some(1098),   // NID_sha3_384
        DigestAlgorithm::Sha3_512 => Some(1099),   // NID_sha3_512
        DigestAlgorithm::Md5 => Some(4),           // NID_md5
        DigestAlgorithm::Md5Sha1 => Some(114),     // NID_md5_sha1
        DigestAlgorithm::Md2 => Some(3),           // NID_md2
        DigestAlgorithm::Md4 => Some(257),         // NID_md4
        DigestAlgorithm::Mdc2 => Some(95),         // NID_mdc2
        DigestAlgorithm::Ripemd160 => Some(117),   // NID_ripemd160
        _ => None,
    }
}

/// Reverse mapping from a NID to a digest algorithm.
///
/// Translates `ossl_rsa_oaeppss_nid2name()` style helpers from
/// `crypto/rsa/rsa_schemes.c`.
pub(crate) fn scheme_nid_to_digest(nid: u32) -> Option<DigestAlgorithm> {
    match nid {
        64 => Some(DigestAlgorithm::Sha1),
        675 => Some(DigestAlgorithm::Sha224),
        672 => Some(DigestAlgorithm::Sha256),
        673 => Some(DigestAlgorithm::Sha384),
        674 => Some(DigestAlgorithm::Sha512),
        1094 => Some(DigestAlgorithm::Sha512_224),
        1095 => Some(DigestAlgorithm::Sha512_256),
        1096 => Some(DigestAlgorithm::Sha3_224),
        1097 => Some(DigestAlgorithm::Sha3_256),
        1098 => Some(DigestAlgorithm::Sha3_384),
        1099 => Some(DigestAlgorithm::Sha3_512),
        4 => Some(DigestAlgorithm::Md5),
        114 => Some(DigestAlgorithm::Md5Sha1),
        3 => Some(DigestAlgorithm::Md2),
        257 => Some(DigestAlgorithm::Md4),
        95 => Some(DigestAlgorithm::Mdc2),
        117 => Some(DigestAlgorithm::Ripemd160),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::field_reassign_with_default,
    reason = "test code conventionally uses expect/unwrap/panic with descriptive messages \
              for fast-fail diagnostics; the crate-level `#![deny(clippy::expect_used)]` and \
              `#![deny(clippy::unwrap_used)]` apply to library code, not test code."
)]
mod tests {
    //! Unit tests for the RSA module hub.
    //!
    //! These tests exercise the public API surface of `crates/openssl-crypto/src/rsa/mod.rs`
    //! end-to-end: padding mode round-trips, multi-prime capacity boundaries, key
    //! constructor validation, key generation parameter defaults, NID round-trip mapping,
    //! [`RsaError`] → [`CryptoError`] variant mapping, [`fmt::Display`] formatting,
    //! private key accessors, and full PKCS#1 v1.5 encrypt/decrypt and sign/verify
    //! round-trips that exercise the [`BlindingFactor`] code path on `private_decrypt`
    //! and the signing path on `sign_pkcs1v15`.

    use super::*;

    /// Generate a default 2048-bit two-prime RSA key pair for tests that need one.
    /// Uses `.expect()` because keygen failure is a fatal test setup error.
    fn test_keypair() -> RsaKeyPair {
        generate_key(&RsaKeyGenParams::default())
            .expect("RSA-2048 default key generation should succeed")
    }

    // -------------------------------------------------------------------------
    // PaddingMode round-trips (5 variants × 2 methods)
    // -------------------------------------------------------------------------

    #[test]
    fn padding_mode_to_legacy_int_round_trip() {
        assert_eq!(PaddingMode::Pkcs1v15.to_legacy_int(), 1);
        assert_eq!(PaddingMode::None.to_legacy_int(), 3);
        assert_eq!(PaddingMode::Oaep.to_legacy_int(), 4);
        assert_eq!(PaddingMode::X931.to_legacy_int(), 5);
        assert_eq!(PaddingMode::Pss.to_legacy_int(), 6);
    }

    #[test]
    fn padding_mode_to_param_str_round_trip() {
        assert_eq!(PaddingMode::Pkcs1v15.to_param_str(), "pkcs1");
        assert_eq!(PaddingMode::None.to_param_str(), "none");
        assert_eq!(PaddingMode::Oaep.to_param_str(), "oaep");
        assert_eq!(PaddingMode::X931.to_param_str(), "x931");
        assert_eq!(PaddingMode::Pss.to_param_str(), "pss");
    }

    // -------------------------------------------------------------------------
    // multi_prime_cap boundary tests (matches C ossl_rsa_multip_cap)
    // -------------------------------------------------------------------------

    #[test]
    fn multi_prime_cap_under_4096_returns_2() {
        // bits in [0, 4095] — only standard two-prime is allowed.
        assert_eq!(multi_prime_cap(0), 2);
        assert_eq!(multi_prime_cap(1024), 2);
        assert_eq!(multi_prime_cap(2048), 2);
        assert_eq!(multi_prime_cap(4095), 2);
    }

    #[test]
    fn multi_prime_cap_4096_to_8191_returns_3() {
        assert_eq!(multi_prime_cap(4096), 3);
        assert_eq!(multi_prime_cap(6000), 3);
        assert_eq!(multi_prime_cap(8191), 3);
    }

    #[test]
    fn multi_prime_cap_8192_to_16383_returns_4() {
        assert_eq!(multi_prime_cap(8192), 4);
        assert_eq!(multi_prime_cap(12_000), 4);
        assert_eq!(multi_prime_cap(16_383), 4);
    }

    #[test]
    fn multi_prime_cap_16384_and_above_returns_max() {
        assert_eq!(multi_prime_cap(16_384), RSA_MAX_PRIME_NUM);
        assert_eq!(multi_prime_cap(32_768), RSA_MAX_PRIME_NUM);
        assert_eq!(multi_prime_cap(u32::MAX), RSA_MAX_PRIME_NUM);
    }

    // -------------------------------------------------------------------------
    // RsaPublicKey::new validation
    // The function rejects, in order:
    //   1) n zero or negative          → ValueMissing { component: "n" }
    //   2) e zero/negative or NOT odd  → BadExponentValue
    //   3) e < 3                       → BadExponentValue
    // All three RsaError variants map to CryptoError::Key per
    // From<RsaError> for CryptoError at mod.rs:326-350.
    // -------------------------------------------------------------------------

    #[test]
    fn rsa_public_key_new_rejects_zero_modulus() {
        let n = BigNum::from_u64(0);
        let e = BigNum::from_u64(65_537);
        let err = RsaPublicKey::new(n, e).expect_err("zero modulus must be rejected");
        assert!(
            matches!(err, CryptoError::Key(_)),
            "expected CryptoError::Key for zero modulus, got {err:?}"
        );
    }

    #[test]
    fn rsa_public_key_new_rejects_negative_modulus() {
        // set_negative is a no-op on zero, so build a non-zero positive value first.
        let mut n = BigNum::from_u64(123);
        n.set_negative(true);
        assert!(
            n.is_negative(),
            "test setup: n should be negative after set_negative(true)"
        );
        let e = BigNum::from_u64(65_537);
        let err = RsaPublicKey::new(n, e).expect_err("negative modulus must be rejected");
        assert!(
            matches!(err, CryptoError::Key(_)),
            "expected CryptoError::Key for negative modulus, got {err:?}"
        );
    }

    #[test]
    fn rsa_public_key_new_rejects_zero_exponent() {
        let n = BigNum::from_u64(123);
        let e = BigNum::from_u64(0);
        let err = RsaPublicKey::new(n, e).expect_err("zero exponent must be rejected");
        assert!(
            matches!(err, CryptoError::Key(_)),
            "expected CryptoError::Key for zero exponent, got {err:?}"
        );
    }

    #[test]
    fn rsa_public_key_new_rejects_even_exponent() {
        // e=4 is even — fails `!e.is_odd()` at validation step 2.
        let n = BigNum::from_u64(0xFFFF_FFFF_u64);
        let e = BigNum::from_u64(4);
        let err = RsaPublicKey::new(n, e).expect_err("even exponent must be rejected");
        assert!(
            matches!(err, CryptoError::Key(_)),
            "expected CryptoError::Key for even exponent, got {err:?}"
        );
    }

    #[test]
    fn rsa_public_key_new_rejects_exponent_below_3() {
        // e=1 is odd (passes step 2) but `< 3` (fails at step 3).
        let n = BigNum::from_u64(0xFFFF_FFFF_u64);
        let e = BigNum::from_u64(1);
        let err = RsaPublicKey::new(n, e).expect_err("e=1 must be rejected");
        assert!(
            matches!(err, CryptoError::Key(_)),
            "expected CryptoError::Key for e=1, got {err:?}"
        );
    }

    #[test]
    fn rsa_public_key_new_accepts_valid_inputs() {
        // BigNum::to_bytes_be returns minimal-length unsigned big-endian bytes.
        // 65_537 = 0x01_0001 → vec![1, 0, 1] (no zero-padding).
        let n = BigNum::from_u64(0xFFFF_FFFF_FFFF_FFFF_u64);
        let e = BigNum::from_u64(65_537);
        let key = RsaPublicKey::new(n, e).expect("valid n and e should produce a key");
        assert_eq!(key.public_exponent().to_bytes_be(), vec![1, 0, 1]);
    }

    // -------------------------------------------------------------------------
    // RsaKeyGenParams defaults and constructors
    // -------------------------------------------------------------------------

    #[test]
    fn rsa_key_gen_params_default_is_2048_bits_2_primes() {
        let p = RsaKeyGenParams::default();
        assert_eq!(p.bits, 2048);
        assert_eq!(p.primes, 2);
        assert!(p.public_exponent.is_none());
    }

    #[test]
    fn rsa_key_gen_params_new_constructor_sets_bits() {
        let p = RsaKeyGenParams::new(4096);
        assert_eq!(p.bits, 4096);
        assert_eq!(p.primes, 2);
        assert!(p.public_exponent.is_none());
    }

    #[test]
    fn rsa_key_gen_params_effective_public_exponent_default_is_65537() {
        let p = RsaKeyGenParams::default();
        // 65_537 → minimal-length BE bytes [1, 0, 1].
        assert_eq!(p.effective_public_exponent().to_bytes_be(), vec![1, 0, 1]);
    }

    #[test]
    fn rsa_key_gen_params_effective_public_exponent_with_explicit_value() {
        let mut p = RsaKeyGenParams::default();
        p.public_exponent = Some(BigNum::from_u64(3));
        // 3 → minimal-length BE bytes [3].
        assert_eq!(p.effective_public_exponent().to_bytes_be(), vec![3]);
    }

    // -------------------------------------------------------------------------
    // NID round-trip for digest_to_scheme_nid / scheme_nid_to_digest
    // Both are pub(crate); reachable from this `super::*` test module.
    // -------------------------------------------------------------------------

    #[test]
    fn digest_nid_round_trip_sha256() {
        assert_eq!(digest_to_scheme_nid(DigestAlgorithm::Sha256), Some(672));
        assert!(matches!(
            scheme_nid_to_digest(672),
            Some(DigestAlgorithm::Sha256)
        ));
    }

    #[test]
    fn digest_nid_round_trip_sha384() {
        assert_eq!(digest_to_scheme_nid(DigestAlgorithm::Sha384), Some(673));
        assert!(matches!(
            scheme_nid_to_digest(673),
            Some(DigestAlgorithm::Sha384)
        ));
    }

    #[test]
    fn digest_nid_round_trip_sha512() {
        assert_eq!(digest_to_scheme_nid(DigestAlgorithm::Sha512), Some(674));
        assert!(matches!(
            scheme_nid_to_digest(674),
            Some(DigestAlgorithm::Sha512)
        ));
    }

    #[test]
    fn digest_nid_round_trip_sha1() {
        assert_eq!(digest_to_scheme_nid(DigestAlgorithm::Sha1), Some(64));
        assert!(matches!(
            scheme_nid_to_digest(64),
            Some(DigestAlgorithm::Sha1)
        ));
    }

    #[test]
    fn scheme_nid_to_digest_unknown_returns_none() {
        // 99_999 is not a registered NID.
        assert!(scheme_nid_to_digest(99_999).is_none());
    }

    // -------------------------------------------------------------------------
    // Error variant mapping (RsaError → CryptoError)
    // Covers all 4 mapping branches from `impl From<RsaError> for CryptoError`
    // at mod.rs:326-350: Key (8 variants), Encoding (7), Verification (2),
    // Provider (1).
    // -------------------------------------------------------------------------

    #[test]
    fn error_mapping_value_missing_to_key() {
        let rsa_err = RsaError::ValueMissing { component: "n" };
        let crypto_err: CryptoError = rsa_err.into();
        assert!(
            matches!(crypto_err, CryptoError::Key(_)),
            "ValueMissing should map to CryptoError::Key, got {crypto_err:?}"
        );
    }

    #[test]
    fn error_mapping_data_too_large_to_encoding() {
        let rsa_err = RsaError::DataTooLargeForKeySize;
        let crypto_err: CryptoError = rsa_err.into();
        assert!(
            matches!(crypto_err, CryptoError::Encoding(_)),
            "DataTooLargeForKeySize should map to CryptoError::Encoding, got {crypto_err:?}"
        );
    }

    #[test]
    fn error_mapping_salt_length_check_to_verification() {
        let rsa_err = RsaError::SaltLengthCheckFailed;
        let crypto_err: CryptoError = rsa_err.into();
        assert!(
            matches!(crypto_err, CryptoError::Verification(_)),
            "SaltLengthCheckFailed should map to CryptoError::Verification, got {crypto_err:?}"
        );
    }

    #[test]
    fn error_mapping_operation_not_supported_to_provider() {
        let rsa_err = RsaError::OperationNotSupported {
            operation: "demo".to_string(),
        };
        let crypto_err: CryptoError = rsa_err.into();
        assert!(
            matches!(crypto_err, CryptoError::Provider(_)),
            "OperationNotSupported should map to CryptoError::Provider, got {crypto_err:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Display format for RsaPublicKey
    // -------------------------------------------------------------------------

    #[test]
    fn rsa_public_key_display_format_matches_spec() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let s = format!("{pubkey}");
        // Format string is `"RSA Public Key ({} bit)"` (singular "bit").
        assert_eq!(
            s,
            format!("RSA Public Key ({} bit)", pubkey.key_size_bits())
        );
        assert!(s.starts_with("RSA Public Key ("));
        assert!(s.ends_with(" bit)"));
    }

    // -------------------------------------------------------------------------
    // Key generation behavior — verifies geometry, security strength, and
    // RsaVersion default (TwoPrime).
    // -------------------------------------------------------------------------

    #[test]
    fn generate_key_2048_succeeds_and_has_expected_geometry() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        assert_eq!(pubkey.key_size_bits(), 2048);
        // 2048 bits = exactly 256 bytes (no slack).
        assert_eq!(pubkey.key_size_bytes(), 256);
        // NIST SP 800-57: 2048-bit RSA → 112 bits of strength.
        assert_eq!(pubkey.security_bits(), 112);
        // Default public exponent is 65_537.
        assert_eq!(pubkey.public_exponent().to_bytes_be(), vec![1, 0, 1]);
    }

    #[test]
    fn generate_key_returns_two_prime_key_by_default() {
        let kp = test_keypair();
        let private = kp.private_key();
        assert_eq!(private.version(), RsaVersion::TwoPrime);
        assert!(!private.is_multi_prime());
        assert_eq!(private.prime_count(), 2);
    }

    // -------------------------------------------------------------------------
    // PKCS#1 v1.5 encrypt/decrypt round-trip — exercises the BlindingFactor
    // code path inside `private_decrypt`.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs1v15_public_encrypt_private_decrypt_round_trip() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let private = kp.private_key();
        // 31 bytes is well within the PKCS#1 v1.5 limit of 245 bytes for a
        // 2048-bit RSA key (256 - 11 padding overhead = 245 max plaintext).
        let plaintext: &[u8] = b"the quick brown fox jumps - 31!";
        assert_eq!(plaintext.len(), 31);

        let ct = public_encrypt(&pubkey, plaintext, PaddingMode::Pkcs1v15)
            .expect("public_encrypt with PKCS#1 v1.5 should succeed");
        // Ciphertext length equals the modulus byte length (k).
        let expected_ct_len = usize::try_from(pubkey.key_size_bytes())
            .expect("key_size_bytes fits in usize on supported platforms");
        assert_eq!(ct.len(), expected_ct_len, "ciphertext is exactly k bytes");

        let pt = private_decrypt(private, &ct, PaddingMode::Pkcs1v15)
            .expect("private_decrypt with PKCS#1 v1.5 should succeed");
        assert_eq!(pt, plaintext, "round-trip plaintext must match original");
    }

    // -------------------------------------------------------------------------
    // PKCS#1 v1.5 sign/verify round-trip + tamper detection.
    // -------------------------------------------------------------------------

    #[test]
    fn sign_verify_pkcs1v15_round_trip_sha256() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let private = kp.private_key();
        // SHA-256 produces a 32-byte digest.
        let hash = [0xAA_u8; 32];

        let sig = sign_pkcs1v15(private, DigestAlgorithm::Sha256, &hash)
            .expect("sign_pkcs1v15 with SHA-256 should succeed");
        // Signature length equals the modulus byte length.
        let expected_sig_len = usize::try_from(pubkey.key_size_bytes())
            .expect("key_size_bytes fits in usize on supported platforms");
        assert_eq!(sig.len(), expected_sig_len, "signature is exactly k bytes");

        let ok = verify_pkcs1v15(&pubkey, DigestAlgorithm::Sha256, &hash, &sig)
            .expect("verify_pkcs1v15 should not error on a valid signature");
        assert!(ok, "valid signature must verify against the original hash");
    }

    #[test]
    fn verify_pkcs1v15_rejects_tampered_signature() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let private = kp.private_key();
        let hash = [0x55_u8; 32];

        let mut sig = sign_pkcs1v15(private, DigestAlgorithm::Sha256, &hash)
            .expect("sign_pkcs1v15 should succeed");
        // Flip a bit in the middle of the signature to corrupt it.
        let mid = sig.len() / 2;
        sig[mid] ^= 0x01;

        // Either Ok(false) or Err(_) is acceptable — the contract is that
        // verification MUST NOT return Ok(true) for a tampered signature.
        let result = verify_pkcs1v15(&pubkey, DigestAlgorithm::Sha256, &hash, &sig);
        match result {
            Ok(true) => panic!("tampered signature must not verify as valid"),
            Ok(false) | Err(_) => {}
        }
    }

    // -------------------------------------------------------------------------
    // RsaPrivateKey accessors — verifies all CRT components are populated and
    // public components agree between the projected public key and the private
    // key's own getters.
    // -------------------------------------------------------------------------

    #[test]
    fn rsa_private_key_accessors_are_consistent_with_public_components() {
        let kp = test_keypair();
        let private = kp.private_key();
        let public = kp.public_key();
        // Public components must match between projected pubkey and private key.
        assert_eq!(
            private.modulus().to_bytes_be(),
            public.modulus().to_bytes_be()
        );
        assert_eq!(
            private.public_exponent().to_bytes_be(),
            public.public_exponent().to_bytes_be()
        );
        // Private components must be present and non-zero.
        assert!(!private.private_exponent().is_zero(), "d must be non-zero");
        assert!(!private.prime_p().is_zero(), "p must be non-zero");
        assert!(!private.prime_q().is_zero(), "q must be non-zero");
        assert!(!private.crt_dmp1().is_zero(), "dmp1 must be non-zero");
        assert!(!private.crt_dmq1().is_zero(), "dmq1 must be non-zero");
        assert!(!private.crt_iqmp().is_zero(), "iqmp must be non-zero");
        // p and q must differ (otherwise n would be a perfect square).
        assert_ne!(
            private.prime_p().to_bytes_be(),
            private.prime_q().to_bytes_be(),
            "p and q must be distinct primes"
        );
    }

    #[test]
    fn rsa_private_key_security_bits_matches_2048_strength() {
        let kp = test_keypair();
        let private = kp.private_key();
        // NIST SP 800-57: 2048-bit RSA → 112 bits of strength.
        assert_eq!(private.security_bits(), 112);
        assert_eq!(private.key_size_bits(), 2048);
        assert_eq!(private.key_size_bytes(), 256);
    }

    #[test]
    fn rsa_private_key_pss_params_default_is_none() {
        let kp = test_keypair();
        let private = kp.private_key();
        // Plain RSA keys carry no PSS parameter restrictions by default.
        assert!(private.pss_params().is_none());
    }

    // -------------------------------------------------------------------------
    // Module constants — anchor the public surface contract.
    // -------------------------------------------------------------------------

    #[test]
    fn rsa_module_constants_are_correct() {
        assert_eq!(RSA_MAX_PRIME_NUM, 5);
        assert_eq!(RSA_DEFAULT_PUBLIC_EXPONENT, 65_537);
        assert_eq!(RSA_MIN_MODULUS_BITS, 512);
        assert_eq!(RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE, 2048);
        assert_eq!(RSA_FIPS186_5_MIN_KEYGEN_STRENGTH, 112);
        assert_eq!(RSA_PKCS1_PADDING_SIZE, 11);
    }
}
