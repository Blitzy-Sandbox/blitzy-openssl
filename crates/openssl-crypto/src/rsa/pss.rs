// crates/openssl-crypto/src/rsa/pss.rs
//
// PSS (Probabilistic Signature Scheme) implementation per RFC 8017 §8.1 / §9.1.
//
// Translates the C implementation from `crypto/rsa/rsa_pss.c` (424 lines)
// into idiomatic, safe Rust. Provides EMSA-PSS encoding and verification
// with configurable hash functions, MGF1, and salt lengths, plus the small
// PKCS#1 v1.5 DigestInfo helpers shared with `crypto/rsa/rsa_sign.c`.

// `unsafe_code` is `forbid`den at the crate root (see
// `crates/openssl-crypto/src/lib.rs`); we therefore omit the per-module
// `#![deny(unsafe_code)]` to satisfy E0453 ("deny incompatible with
// previous forbid"). Cast lints below remain active.
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]

//! PSS (Probabilistic Signature Scheme) implementation per RFC 8017 §8.1/§9.1.
//!
//! Translates the C implementation from `crypto/rsa/rsa_pss.c` (424 lines).
//! Provides EMSA-PSS encoding and verification with configurable hash
//! functions, MGF1, and salt lengths, plus auxiliary types for PSS-restricted
//! keys and PKCS#1 v1.5 signature scheme support.
//!
//! # PSS Signature Workflow
//!
//! 1. **Sign:** `Hash(M)` → [`pss_encode`] → `RSA private op` → signature
//! 2. **Verify:** signature → `RSA public op` → [`pss_verify`]
//!
//! # Salt Length Special Values
//!
//! The C code defines several special salt-length sentinels (negative
//! integers). In Rust they are encoded as variants of [`PssSaltLength`] (Rule
//! R5: nullability over sentinels).
//!
//! | C constant                            | Numeric | Rust variant                      |
//! |---------------------------------------|---------|-----------------------------------|
//! | `RSA_PSS_SALTLEN_DIGEST`              | -1      | [`PssSaltLength::DigestLength`]   |
//! | `RSA_PSS_SALTLEN_AUTO`                | -2      | [`PssSaltLength::Auto`]           |
//! | `RSA_PSS_SALTLEN_MAX`                 | -3      | [`PssSaltLength::Max`]            |
//! | `RSA_PSS_SALTLEN_AUTO_DIGEST_MAX`     | -4      | [`PssSaltLength::AutoDigestMax`]  |
//! | (any non-negative integer)            | ≥ 0     | [`PssSaltLength::Fixed`]          |
//!
//! # EM Layout (RFC 8017 §9.1.1)
//!
//! ```text
//! EM = maskedDB || H || 0xBC
//! maskedDB = DB ⊕ MGF1(H, len(DB))
//! DB       = PS (zero bytes) || 0x01 || salt
//! H        = Hash(0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 || mHash || salt)
//! ```
//!
//! # Source Map
//!
//! | Rust item                       | C source                                              |
//! |---------------------------------|-------------------------------------------------------|
//! | [`PssSaltLength`]               | `RSA_PSS_SALTLEN_*` macros (`include/openssl/rsa.h`)  |
//! | [`PssParams`]                   | parameter bag in `ossl_rsa_padding_add_PKCS1_PSS_*`   |
//! | [`PssParams30`]                 | `RSA_PSS_PARAMS_30` (`crypto/rsa/rsa_local.h`)        |
//! | [`DEFAULT_PSS_PARAMS_30`]       | `ossl_rsa_default_pss_params` defaults                |
//! | [`pss_encode`]                  | `ossl_rsa_padding_add_PKCS1_PSS_mgf1_ex` (`rsa_pss.c`)|
//! | [`pss_verify`]                  | `ossl_rsa_verify_PKCS1_PSS_mgf1` (`rsa_pss.c`)        |
//! | [`Pkcs1v15SignParams`]          | parameter bundle for `RSA_sign` (`rsa_sign.c`)        |
//! | [`digest_info_prefix`]          | `ossl_rsa_digestinfo_encoding` (`rsa_sign.c`)         |
//!
//! # Security & Implementation Notes
//!
//! - All random salt bytes come from [`crate::rand::rand_bytes`] (Rule R5/R6).
//! - The trailer-byte and first-octet checks fail fast before any
//!   cryptographic comparison.
//! - All intermediate buffers (salt, derived-block, masked DB) implement
//!   [`Zeroize`] and are wiped explicitly. (See AAP §0.7.6.)
//! - The final `H == H'` comparison uses
//!   [`openssl_common::constant_time::memcmp`], which is implemented with
//!   `subtle::ConstantTimeEq` to avoid timing oracles.
//! - Per Rule R8 the crate root forbids `unsafe_code` (`#![forbid(unsafe_code)]`
//!   in `crates/openssl-crypto/src/lib.rs`); not a single `unsafe` block exists
//!   in this module.
//! - Per Rule R6 every length / offset arithmetic uses `checked_add` /
//!   `checked_sub`; surviving casts (`u32` ↔ `u8` for the MS-bit shift,
//!   `i32` round-trip for legacy integer codes) are width-bounded and
//!   carry inline justifications.
//!
//! # References
//!
//! - RFC 8017 §8.1: RSASSA-PSS
//! - RFC 8017 §9.1: EMSA-PSS-Encode / EMSA-PSS-Verify
//! - RFC 8017 §B.2.1: MGF1
//! - RFC 4055: PSS-restricted RSA keys (the `RSA_PSS_PARAMS_30` schema)

// =============================================================================
// Imports
// =============================================================================

use openssl_common::constant_time;
use openssl_common::error::{CryptoError, CryptoResult};
use zeroize::Zeroize;

use crate::hash::{create_digest, Digest, DigestAlgorithm};
use crate::rand::rand_bytes;

use super::oaep::mgf1;

// =============================================================================
// Constants
// =============================================================================

/// Numeric identifier for the MGF1 mask-generation function.
///
/// Mirrors `NID_mgf1` from OpenSSL's NID table. Used as the
/// [`PssMaskGen::algorithm_nid`] value when the default MGF1 is selected.
pub const NID_MGF1: u32 = 911;

/// PSS trailer byte per RFC 8017 §9.1.1 step 11.
///
/// The encoded message must end with this byte: `EM[emLen-1] == 0xBC`.
const PSS_TRAILER_BYTE: u8 = 0xBC;

/// Default `trailerField` per RFC 4055.
///
/// `1` is the only value the standard permits and indicates the trailer
/// byte `0xBC` shown above.
const DEFAULT_TRAILER_FIELD: i32 = 1;

/// Default salt length when none is specified, per RFC 4055.
///
/// 20 bytes matches the SHA-1 output size and is the historical default
/// inherited from the RFC 4055 schema.
const DEFAULT_SALT_LEN: i32 = 20;

// =============================================================================
// PssError — typed error enum for PSS-specific failures
// =============================================================================

/// Errors that can occur during PSS encoding, decoding, verification, and
/// parameter validation.
///
/// Replaces the C `ERR_raise(ERR_LIB_RSA, RSA_R_*)` pattern from
/// `crypto/rsa/rsa_pss.c`. Each variant maps to one or more `RSA_R_*` reason
/// codes:
///
/// | Variant                              | C reason code                          |
/// |--------------------------------------|----------------------------------------|
/// | [`PssError::SaltLengthCheckFailed`]  | `RSA_R_SLEN_CHECK_FAILED`              |
/// | [`PssError::DataTooLargeForKeySize`] | `RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE`    |
/// | [`PssError::InvalidPssParameters`]   | `RSA_R_INVALID_PSS_PARAMETERS`         |
/// | [`PssError::PssVerificationFailed`]  | EMSA-PSS-Verify hash mismatch          |
/// | [`PssError::FirstOctetInvalid`]      | `RSA_R_FIRST_OCTET_INVALID`            |
/// | [`PssError::LastOctetInvalid`]       | `RSA_R_LAST_OCTET_INVALID`             |
/// | [`PssError::InvalidPadding`]         | `RSA_R_INVALID_PADDING` / `BAD_E_VALUE`|
///
/// `PssError` converts into [`CryptoError`] via the implemented [`From`]
/// impl so call sites can return `CryptoResult<T>` directly using the `?`
/// operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PssError {
    /// The recovered salt length does not match the expected length
    /// (`RSA_R_SLEN_CHECK_FAILED`, `rsa_pss.c` line 78).
    SaltLengthCheckFailed,

    /// The encoded-message length is shorter than `hLen + sLen + 2` so PSS
    /// cannot proceed for the given key size
    /// (`RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE`, `rsa_pss.c` lines 230-234).
    DataTooLargeForKeySize,

    /// The PSS parameters are inconsistent (e.g. zero-sized digest, an
    /// invalid trailer field, or unsupported algorithm combination).
    InvalidPssParameters,

    /// The recovered hash `H'` did not equal the supplied `H` field; the
    /// signature is rejected.
    PssVerificationFailed,

    /// The leftmost byte of the encoded message is not `0x00` after
    /// clearing the high bits (`RSA_R_FIRST_OCTET_INVALID`,
    /// `rsa_pss.c` lines 89-100).
    FirstOctetInvalid,

    /// The trailer byte is not `0xBC` (`RSA_R_LAST_OCTET_INVALID`,
    /// `rsa_pss.c` lines 101-104).
    LastOctetInvalid,

    /// The padding string `PS` does not consist of zero bytes terminated by
    /// `0x01`, or some other DB-region invariant has been violated.
    InvalidPadding,
}

impl core::fmt::Display for PssError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PssError::SaltLengthCheckFailed => f.write_str("PSS salt-length check failed"),
            PssError::DataTooLargeForKeySize => f.write_str("PSS data too large for key size"),
            PssError::InvalidPssParameters => f.write_str("invalid PSS parameters"),
            PssError::PssVerificationFailed => f.write_str("PSS verification failed"),
            PssError::FirstOctetInvalid => f.write_str("PSS first octet invalid"),
            PssError::LastOctetInvalid => f.write_str("PSS last octet invalid (trailer != 0xBC)"),
            PssError::InvalidPadding => f.write_str("invalid PSS padding"),
        }
    }
}

impl std::error::Error for PssError {}

/// Maps a typed [`PssError`] into the unified [`CryptoError`] enum.
///
/// The mapping mirrors the C error category: encoding-time failures map to
/// [`CryptoError::Encoding`], verification-time failures map to
/// [`CryptoError::Verification`].
impl From<PssError> for CryptoError {
    fn from(value: PssError) -> Self {
        match value {
            PssError::DataTooLargeForKeySize
            | PssError::InvalidPssParameters
            | PssError::FirstOctetInvalid
            | PssError::LastOctetInvalid
            | PssError::InvalidPadding => CryptoError::Encoding(value.to_string()),
            PssError::SaltLengthCheckFailed | PssError::PssVerificationFailed => {
                CryptoError::Verification(value.to_string())
            }
        }
    }
}

// =============================================================================
// PssSaltLength — typed salt-length specification (Rule R5)
// =============================================================================

/// PSS salt-length specification.
///
/// Replaces the C `RSA_PSS_SALTLEN_*` integer sentinels (`-1` … `-4`) with
/// a typed enum, satisfying Rule R5 ("nullability over sentinels"). The
/// numeric round-trip helpers [`PssSaltLength::as_legacy_int`] /
/// [`PssSaltLength::from_legacy_int`] preserve interoperability with the
/// integer-based `OSSL_PARAM` API.
///
/// | C macro                              | Numeric | Variant                |
/// |--------------------------------------|---------|------------------------|
/// | `RSA_PSS_SALTLEN_DIGEST`             | -1      | [`Self::DigestLength`] |
/// | `RSA_PSS_SALTLEN_AUTO`               | -2      | [`Self::Auto`]         |
/// | `RSA_PSS_SALTLEN_MAX`                | -3      | [`Self::Max`]          |
/// | `RSA_PSS_SALTLEN_AUTO_DIGEST_MAX`    | -4      | [`Self::AutoDigestMax`]|
/// | (any non-negative integer)           | ≥ 0     | [`Self::Fixed`]        |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PssSaltLength {
    /// Salt length equals the hash output length
    /// (C: `RSA_PSS_SALTLEN_DIGEST` = -1).
    DigestLength,

    /// Auto-recover the salt length from the signature during verify.
    /// On the encoding side this behaves identically to [`Self::Max`]
    /// (C: `RSA_PSS_SALTLEN_AUTO` = -2 / `RSA_PSS_SALTLEN_MAX_SIGN` = -2).
    Auto,

    /// Use the maximum salt length permitted by the modulus
    /// (C: `RSA_PSS_SALTLEN_MAX` = -3).
    Max,

    /// Auto-recover for verify, but cap at the digest length when encoding
    /// (FIPS 186-4 compliant default — C: `RSA_PSS_SALTLEN_AUTO_DIGEST_MAX`
    /// = -4).
    AutoDigestMax,

    /// Explicit salt length in bytes.
    Fixed(usize),
}

impl PssSaltLength {
    /// Encodes this variant into the corresponding legacy `int` sentinel.
    ///
    /// The returned value matches the C macros declared in
    /// `include/openssl/rsa.h` and is suitable for round-tripping through
    /// `OSSL_PARAM` parameter bags.
    pub fn as_legacy_int(self) -> i32 {
        match self {
            PssSaltLength::DigestLength => -1,
            PssSaltLength::Auto => -2,
            PssSaltLength::Max => -3,
            PssSaltLength::AutoDigestMax => -4,
            // BOUNDED: callers that exceed `i32::MAX` are out of spec; an
            // overflow truncation would yield a negative value which would
            // collide with one of the sentinels above. Use saturation so the
            // value is preserved as `i32::MAX` instead.
            PssSaltLength::Fixed(n) => i32::try_from(n).unwrap_or(i32::MAX),
        }
    }

    /// Decodes a legacy integer sentinel back into the typed variant.
    ///
    /// Returns [`PssError::InvalidPssParameters`] if the value falls outside
    /// the documented range (`< -4`).
    pub fn from_legacy_int(value: i32) -> Result<Self, PssError> {
        match value {
            -1 => Ok(PssSaltLength::DigestLength),
            -2 => Ok(PssSaltLength::Auto),
            -3 => Ok(PssSaltLength::Max),
            -4 => Ok(PssSaltLength::AutoDigestMax),
            n if n >= 0 => {
                // BOUNDED: `n >= 0` means the cast cannot wrap; further
                // narrowing into `usize` is safe on every supported target
                // (32- and 64-bit pointers).
                Ok(PssSaltLength::Fixed(n.unsigned_abs() as usize))
            }
            _ => Err(PssError::InvalidPssParameters),
        }
    }
}

// =============================================================================
// PssMaskGen — mask-generation algorithm specification
// =============================================================================

/// Mask-generation algorithm (currently always MGF1) and its hash function.
///
/// Mirrors the inner `mask_gen` field of the C `RSA_PSS_PARAMS_30` struct
/// from `crypto/rsa/rsa_local.h`:
///
/// ```text
/// struct {
///     int algorithm_nid;     /* always NID_mgf1 */
///     int hash_algorithm_nid;
/// } mask_gen;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssMaskGen {
    /// Numeric identifier of the mask-generation algorithm. Currently the
    /// only supported value is [`NID_MGF1`].
    pub algorithm_nid: u32,

    /// Hash function used by the mask-generation function. `None` means
    /// "inherit the message digest" — this is the unrestricted default.
    pub hash_algorithm: Option<DigestAlgorithm>,
}

impl PssMaskGen {
    /// Returns the canonical default `MGF1` mask-generation specification
    /// inheriting the message digest.
    ///
    /// Equivalent to the C struct initialiser `{NID_mgf1, NID_undef}` —
    /// callers resolve the unset hash via [`PssParams30::resolved_mgf1_hash`].
    pub const fn default_mgf1() -> Self {
        Self {
            algorithm_nid: NID_MGF1,
            hash_algorithm: None,
        }
    }
}

impl Default for PssMaskGen {
    fn default() -> Self {
        Self::default_mgf1()
    }
}

// =============================================================================
// PssParams30 — RFC 4055 PSS-restricted parameter bundle
// =============================================================================

/// PSS-restricted parameter bundle, mirroring the C `RSA_PSS_PARAMS_30`
/// struct.
///
/// All fields use [`Option`] (Rule R5) so an "unrestricted" parameter set is
/// represented by `None` everywhere. The C code uses the integer `0` /
/// `NID_undef` as the unset sentinel — the Rust translation makes this
/// explicit at the type level.
///
/// `Copy` is implemented because the consumer in
/// `crates/openssl-provider/src/implementations/keymgmt/rsa.rs::absorb_pss_params`
/// dereference-copies a `&PssParams30` into a mutable local before applying
/// setter mutations.
///
/// # Source map
///
/// | Method                                | C function                                |
/// |---------------------------------------|-------------------------------------------|
/// | `set_hash_algorithm`                  | `ossl_rsa_pss_params_30_set_hashalg`      |
/// | `set_mgf1_hash_algorithm`             | `ossl_rsa_pss_params_30_set_maskgenhashalg` |
/// | `set_salt_len`                        | `ossl_rsa_pss_params_30_set_saltlen`      |
/// | `set_trailer_field`                   | `ossl_rsa_pss_params_30_set_trailerfield` |
/// | `set_defaults`                        | `ossl_rsa_pss_params_30_set_defaults`     |
/// | `is_unrestricted`                     | `ossl_rsa_pss_params_30_is_unrestricted`  |
/// | `resolved_hash`                       | `ossl_rsa_pss_params_30_hashalg`          |
/// | `resolved_mgf1_hash`                  | `ossl_rsa_pss_params_30_maskgenhashalg`   |
/// | `resolved_salt_len`                   | `ossl_rsa_pss_params_30_saltlen`          |
/// | `resolved_trailer_field`              | `ossl_rsa_pss_params_30_trailerfield`     |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PssParams30 {
    /// Hash algorithm for the message digest.
    /// `None` means "unrestricted" — callers should fall back to the
    /// default [`DEFAULT_PSS_PARAMS_30`] hash.
    pub hash_algorithm: Option<DigestAlgorithm>,

    /// Mask-generation algorithm and its hash function.
    pub mask_gen_algorithm: PssMaskGen,

    /// Explicit salt length in bytes.
    /// `None` means "unrestricted"; the resolved value falls back to the
    /// RFC 4055 default of 20 bytes.
    pub salt_length: Option<i32>,

    /// `trailerField` per RFC 4055 (always 1 in valid encodings).
    /// `None` means "unrestricted".
    pub trailer_field: Option<i32>,
}

/// The canonical default PSS parameter set per RFC 4055 §A.2.3.
///
/// Mirrors the C `default_RSASSA_PSS_params` static at `rsa_pss.c:314-322`:
///
/// ```text
/// {
///     hashAlgorithm    = sha1,
///     maskGenAlgorithm = mgf1SHA1,
///     saltLength       = 20,
///     trailerField     = 1   (encodes as 0xBC)
/// }
/// ```
pub const DEFAULT_PSS_PARAMS_30: PssParams30 = PssParams30 {
    hash_algorithm: Some(DigestAlgorithm::Sha1),
    mask_gen_algorithm: PssMaskGen {
        algorithm_nid: NID_MGF1,
        hash_algorithm: Some(DigestAlgorithm::Sha1),
    },
    salt_length: Some(DEFAULT_SALT_LEN),
    trailer_field: Some(DEFAULT_TRAILER_FIELD),
};

impl PssParams30 {
    /// Constructs a fully-unrestricted parameter set (every field `None`).
    ///
    /// This is the "no PSS restriction" state; callers querying any
    /// `resolved_*` accessor receive the RFC 4055 defaults.
    pub const fn new() -> Self {
        Self {
            hash_algorithm: None,
            mask_gen_algorithm: PssMaskGen {
                algorithm_nid: NID_MGF1,
                hash_algorithm: None,
            },
            salt_length: None,
            trailer_field: None,
        }
    }

    /// Replaces this parameter bundle with the canonical defaults.
    ///
    /// Translates `ossl_rsa_pss_params_30_set_defaults` (rsa_pss.c:324-330).
    pub fn set_defaults(&mut self) {
        *self = DEFAULT_PSS_PARAMS_30;
    }

    /// Returns `true` when every field is unset (`None`).
    ///
    /// Translates `ossl_rsa_pss_params_30_is_unrestricted`
    /// (rsa_pss.c:332-342). The C version checks for "all-zero" structs;
    /// in Rust the typed `Option` representation makes this trivial.
    pub fn is_unrestricted(&self) -> bool {
        self.hash_algorithm.is_none()
            && self.mask_gen_algorithm.hash_algorithm.is_none()
            && self.salt_length.is_none()
            && self.trailer_field.is_none()
    }

    /// Sets the message-digest algorithm.
    ///
    /// Translates `ossl_rsa_pss_params_30_set_hashalg` (rsa_pss.c:351-358).
    pub fn set_hash_algorithm(&mut self, alg: DigestAlgorithm) {
        self.hash_algorithm = Some(alg);
    }

    /// Sets the MGF1 hash algorithm.
    ///
    /// Translates `ossl_rsa_pss_params_30_set_maskgenhashalg`
    /// (rsa_pss.c:360-367).
    pub fn set_mgf1_hash_algorithm(&mut self, alg: DigestAlgorithm) {
        self.mask_gen_algorithm.hash_algorithm = Some(alg);
    }

    /// Sets the salt length.
    ///
    /// Translates `ossl_rsa_pss_params_30_set_saltlen` (rsa_pss.c:369-376).
    /// The C accessor takes a signed `int` and stores any value, even the
    /// negative sentinels — this Rust port preserves that contract for
    /// round-trip compatibility with `OSSL_PARAM`-based callers.
    pub fn set_salt_len(&mut self, salt_len: i32) {
        self.salt_length = Some(salt_len);
    }

    /// Sets the trailer field.
    ///
    /// Translates `ossl_rsa_pss_params_30_set_trailerfield`
    /// (rsa_pss.c:378-385).
    pub fn set_trailer_field(&mut self, trailer: i32) {
        self.trailer_field = Some(trailer);
    }

    /// Returns the resolved message-digest algorithm, falling back to the
    /// RFC 4055 default of SHA-1 when unset.
    ///
    /// Translates `ossl_rsa_pss_params_30_hashalg` (rsa_pss.c:387-392).
    pub fn resolved_hash(&self) -> DigestAlgorithm {
        self.hash_algorithm
            .or(DEFAULT_PSS_PARAMS_30.hash_algorithm)
            .unwrap_or(DigestAlgorithm::Sha1)
    }

    /// Returns the resolved MGF1 hash algorithm, falling back to the
    /// message digest default of SHA-1 when unset.
    ///
    /// Translates `ossl_rsa_pss_params_30_maskgenhashalg`
    /// (rsa_pss.c:401-406).
    pub fn resolved_mgf1_hash(&self) -> DigestAlgorithm {
        self.mask_gen_algorithm
            .hash_algorithm
            .or(DEFAULT_PSS_PARAMS_30.mask_gen_algorithm.hash_algorithm)
            .unwrap_or(DigestAlgorithm::Sha1)
    }

    /// Returns the resolved salt length, falling back to the RFC 4055
    /// default of 20.
    ///
    /// Translates `ossl_rsa_pss_params_30_saltlen` (rsa_pss.c:408-413).
    pub fn resolved_salt_len(&self) -> i32 {
        self.salt_length.unwrap_or(DEFAULT_SALT_LEN)
    }

    /// Returns the resolved trailer field, falling back to `1`
    /// (encoded as `0xBC`).
    ///
    /// Translates `ossl_rsa_pss_params_30_trailerfield` (rsa_pss.c:415-420).
    pub fn resolved_trailer_field(&self) -> i32 {
        self.trailer_field.unwrap_or(DEFAULT_TRAILER_FIELD)
    }
}

// =============================================================================
// PssParams — lightweight runtime parameter bundle for encode/verify
// =============================================================================

/// Lightweight PSS signature parameter bundle for one-shot encode / verify
/// calls.
///
/// Distinct from [`PssParams30`], which models the long-lived RFC 4055
/// parameter restrictions that travel with a key. This struct is the bag
/// of arguments that the C function
/// `ossl_rsa_padding_add_PKCS1_PSS_mgf1_ex()` takes (digest, MGF1 hash, salt
/// length). It is intended to be constructed at the call site, populated, and
/// consumed.
///
/// All fields are typed (no integer sentinels) per Rule R5: the nullable
/// MGF1 digest is `Option<DigestAlgorithm>` and the salt length is the
/// [`PssSaltLength`] enum.
///
/// `Copy` is derived so callers can pass `PssParams` by value cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssParams {
    /// Hash function used to digest the message (`Hash` in RFC 8017).
    pub digest: DigestAlgorithm,

    /// Hash function used by MGF1. `None` means "inherit `digest`" — this
    /// matches the C contract where `mgf1Hash == NULL` falls back to
    /// `Hash` (`rsa_pss.c` line 62 / 195).
    pub mgf1_digest: Option<DigestAlgorithm>,

    /// Salt-length specification.
    pub salt_length: PssSaltLength,

    /// Trailer field; the only spec-compliant value is `1`, which encodes
    /// as the byte `0xBC`.
    pub trailer_field: u8,
}

impl PssParams {
    /// Constructs a new `PssParams` with the given digest, defaults for
    /// MGF1 (inherited) and salt length (`DigestLength`), and the standard
    /// trailer byte.
    ///
    /// Mirrors the common C call pattern: pick the message digest, leave
    /// MGF1 NULL (inherit), default sLen to hLen.
    pub const fn new(digest: DigestAlgorithm) -> Self {
        Self {
            digest,
            mgf1_digest: None,
            salt_length: PssSaltLength::DigestLength,
            trailer_field: 1,
        }
    }

    /// Builder-style setter: explicitly choose the MGF1 hash function.
    #[must_use]
    pub const fn with_mgf1_hash(mut self, mgf1: DigestAlgorithm) -> Self {
        self.mgf1_digest = Some(mgf1);
        self
    }

    /// Builder-style setter: choose the salt-length specification.
    #[must_use]
    pub const fn with_salt_length(mut self, salt: PssSaltLength) -> Self {
        self.salt_length = salt;
        self
    }

    /// Returns the effective MGF1 hash, falling back to [`Self::digest`].
    ///
    /// Translates the C pattern: `if (mgf1Hash == NULL) mgf1Hash = Hash;`
    /// (`rsa_pss.c` lines 62 and 195).
    pub fn effective_mgf1_digest(&self) -> DigestAlgorithm {
        self.mgf1_digest.unwrap_or(self.digest)
    }

    /// Backwards-compatible alias for [`Self::effective_mgf1_digest`]; some
    /// callers reach for the longer name `resolved_mgf1_digest`.
    pub fn resolved_mgf1_digest(&self) -> DigestAlgorithm {
        self.effective_mgf1_digest()
    }

    /// Validates the parameter bundle for internal consistency.
    ///
    /// Returns [`PssError::InvalidPssParameters`] when:
    /// - the trailer field is not `1` (the only RFC-compliant value), or
    /// - the digest has zero output size (e.g. an unsupported algorithm).
    pub fn validate(&self) -> CryptoResult<()> {
        if self.trailer_field != 1 {
            return Err(PssError::InvalidPssParameters.into());
        }
        if self.digest.digest_size() == 0 {
            return Err(PssError::InvalidPssParameters.into());
        }
        if self.effective_mgf1_digest().digest_size() == 0 {
            return Err(PssError::InvalidPssParameters.into());
        }
        Ok(())
    }

    /// Returns `true` if this parameter set is fully default and so is
    /// equivalent to the canonical [`DEFAULT_PSS_PARAMS_30`] setting.
    pub fn is_unrestricted(&self) -> bool {
        matches!(self.digest, DigestAlgorithm::Sha1)
            && self.mgf1_digest.is_none()
            && matches!(self.salt_length, PssSaltLength::DigestLength)
            && self.trailer_field == 1
    }

    /// Resolves the salt length in bytes for the encoding side, given the
    /// available encoded-message length and digest size.
    ///
    /// Implements the salt-length resolution logic from `rsa_pss.c` lines
    /// 198-238 in a self-contained, side-effect-free way.
    pub fn resolve_salt_length(&self, em_len: usize, hash_len: usize) -> CryptoResult<usize> {
        resolve_salt_len_encode(self.salt_length, em_len, hash_len)
    }
}

impl Default for PssParams {
    fn default() -> Self {
        Self {
            // RFC 8017 default per Appendix A.2.3.
            digest: DigestAlgorithm::Sha1,
            mgf1_digest: None,
            salt_length: PssSaltLength::DigestLength,
            trailer_field: 1,
        }
    }
}

// =============================================================================
// PKCS#1 v1.5 signature support
// =============================================================================

/// PKCS#1 v1.5 signature parameter bundle (RSASSA-PKCS1-v1_5).
///
/// Used for legacy `RSA_sign` / `RSA_verify` operations that prepend a
/// DER-encoded `DigestInfo` structure to the message digest before the
/// RSA private key operation.
///
/// This struct only holds the digest algorithm because PKCS#1 v1.5
/// signatures have no other tunable parameters — unlike PSS, there is
/// no salt and no MGF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pkcs1v15SignParams {
    /// Hash algorithm whose digest is being signed.
    pub digest: DigestAlgorithm,
}

impl Pkcs1v15SignParams {
    /// Constructs a new parameter bundle for the given digest.
    pub const fn new(digest: DigestAlgorithm) -> Self {
        Self { digest }
    }
}

// -----------------------------------------------------------------------------
// DigestInfo prefix tables (mirrors `crypto/rsa/rsa_sign.c` lines 40-200)
// -----------------------------------------------------------------------------
//
// These constant byte arrays are the DER-encoded `DigestInfo` ASN.1
// structures *minus* the hash bytes themselves. The C header file
// pre-encodes these as `static const unsigned char` arrays via the
// `ENCODE_DIGESTINFO_SHA` and `ENCODE_DIGESTINFO_MD` macros and exports
// them through `ossl_rsa_digestinfo_encoding()`.
//
// ASN.1 type byte references:
//   ASN1_SEQUENCE      = 0x30
//   ASN1_OID           = 0x06
//   ASN1_NULL          = 0x05
//   ASN1_OCTET_STRING  = 0x04
//
// For each algorithm the format is:
//   SEQUENCE {
//     SEQUENCE {
//       OID <hash algorithm>,
//       NULL
//     },
//     OCTET STRING <hash bytes — appended at runtime>
//   }
//
// The byte sequence ends with `[0x04, <hash_len>]` so the caller can
// concatenate `prefix || hash` to get the full DigestInfo.

/// SHA-1 `DigestInfo` DER prefix (15 bytes, OID 1.3.14.3.2.26).
const DIGEST_INFO_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];

/// SHA-224 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.4).
const DIGEST_INFO_SHA224: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c,
];

/// SHA-256 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.1).
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// SHA-384 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.2).
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];

/// SHA-512 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.3).
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// SHA-512/224 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.5).
/// Output size matches SHA-224 (28 bytes).
const DIGEST_INFO_SHA512_224: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05,
    0x00, 0x04, 0x1c,
];

/// SHA-512/256 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.6).
/// Output size matches SHA-256 (32 bytes).
const DIGEST_INFO_SHA512_256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05,
    0x00, 0x04, 0x20,
];

/// SHA3-224 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.7).
const DIGEST_INFO_SHA3_224: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
    0x00, 0x04, 0x1c,
];

/// SHA3-256 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.8).
const DIGEST_INFO_SHA3_256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
    0x00, 0x04, 0x20,
];

/// SHA3-384 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.9).
const DIGEST_INFO_SHA3_384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
    0x00, 0x04, 0x30,
];

/// SHA3-512 `DigestInfo` DER prefix (19 bytes, OID 2.16.840.1.101.3.4.2.10).
const DIGEST_INFO_SHA3_512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
    0x00, 0x04, 0x40,
];

/// MD5 `DigestInfo` DER prefix (18 bytes, OID 1.2.840.113549.2.5).
const DIGEST_INFO_MD5: &[u8] = &[
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
    0x04, 0x10,
];

/// MD2 `DigestInfo` DER prefix (18 bytes, OID 1.2.840.113549.2.2).
const DIGEST_INFO_MD2: &[u8] = &[
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00,
    0x04, 0x10,
];

/// MD4 `DigestInfo` DER prefix (18 bytes).
///
/// Note: the OID's final octet is `0x03`, mirroring the
/// `ENCODE_DIGESTINFO_MD(md4, 0x03, ...)` macro invocation from
/// `crypto/rsa/rsa_sign.c` line 104. This deviates from RFC 1320
/// (which assigns MD4 the OID 1.2.840.113549.2.4) but matches what
/// the upstream OpenSSL implementation emits on the wire — required
/// for behavioral parity with existing FFI consumers.
const DIGEST_INFO_MD4: &[u8] = &[
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x03, 0x05, 0x00,
    0x04, 0x10,
];

/// MDC-2 `DigestInfo` DER prefix (14 bytes, OID 2.5.8.3.101).
const DIGEST_INFO_MDC2: &[u8] = &[
    0x30, 0x1c, 0x30, 0x08, 0x06, 0x04, 0x55, 0x08, 0x03, 0x65, 0x05, 0x00, 0x04, 0x10,
];

/// RIPEMD-160 `DigestInfo` DER prefix (15 bytes, OID 1.3.36.3.2.1).
const DIGEST_INFO_RIPEMD160: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14,
];

/// SM3 `DigestInfo` DER prefix (18 bytes, OID 1.2.156.10197.1.401).
const DIGEST_INFO_SM3: &[u8] = &[
    0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x78, 0x05, 0x00,
    0x04, 0x20,
];

/// Returns the DER-encoded `DigestInfo` prefix bytes for the given hash
/// algorithm, or `None` if the algorithm has no defined PKCS#1 v1.5
/// encoding.
///
/// The caller appends `digest.digest_size()` bytes of hash output to the
/// returned prefix to form the complete `DigestInfo` to be RSA-signed.
///
/// Mirrors the switch in `ossl_rsa_digestinfo_encoding(int md_nid, ...)`
/// from `crypto/rsa/rsa_sign.c` lines 145-200.
pub fn digest_info_prefix(digest: DigestAlgorithm) -> Option<&'static [u8]> {
    match digest {
        DigestAlgorithm::Sha1 => Some(DIGEST_INFO_SHA1),
        DigestAlgorithm::Sha224 => Some(DIGEST_INFO_SHA224),
        DigestAlgorithm::Sha256 => Some(DIGEST_INFO_SHA256),
        DigestAlgorithm::Sha384 => Some(DIGEST_INFO_SHA384),
        DigestAlgorithm::Sha512 => Some(DIGEST_INFO_SHA512),
        DigestAlgorithm::Sha512_224 => Some(DIGEST_INFO_SHA512_224),
        DigestAlgorithm::Sha512_256 => Some(DIGEST_INFO_SHA512_256),
        DigestAlgorithm::Sha3_224 => Some(DIGEST_INFO_SHA3_224),
        DigestAlgorithm::Sha3_256 => Some(DIGEST_INFO_SHA3_256),
        DigestAlgorithm::Sha3_384 => Some(DIGEST_INFO_SHA3_384),
        DigestAlgorithm::Sha3_512 => Some(DIGEST_INFO_SHA3_512),
        DigestAlgorithm::Md5 => Some(DIGEST_INFO_MD5),
        DigestAlgorithm::Md2 => Some(DIGEST_INFO_MD2),
        DigestAlgorithm::Md4 => Some(DIGEST_INFO_MD4),
        DigestAlgorithm::Mdc2 => Some(DIGEST_INFO_MDC2),
        DigestAlgorithm::Ripemd160 => Some(DIGEST_INFO_RIPEMD160),
        DigestAlgorithm::Sm3 => Some(DIGEST_INFO_SM3),
        // No standard PKCS#1 v1.5 DigestInfo encoding for these:
        DigestAlgorithm::Md5Sha1
        | DigestAlgorithm::Whirlpool
        | DigestAlgorithm::Shake128
        | DigestAlgorithm::Shake256
        | DigestAlgorithm::Blake2b256
        | DigestAlgorithm::Blake2b512
        | DigestAlgorithm::Blake2s256 => None,
    }
}

// =============================================================================
// EMSA-PSS — salt length resolution helper (encode side)
// =============================================================================

/// Resolves the salt length in bytes for the encoding (signing) side of
/// EMSA-PSS, mirroring the C sentinel handling at `rsa_pss.c` lines 198-238.
///
/// This helper is module-private and consumed by both [`PssParams::
/// resolve_salt_length`] and [`pss_encode`]. The verification side uses a
/// different resolution path because [`PssSaltLength::Auto`] and
/// [`PssSaltLength::AutoDigestMax`] mean *recover from the signature*
/// rather than *use the maximum*.
///
/// # Algorithm (RFC 8017 §9.1.1 / OpenSSL `rsa_pss.c`):
///
/// | Variant            | Resolved length                                 |
/// |--------------------|-------------------------------------------------|
/// | `DigestLength`     | `hash_len`                                      |
/// | `Auto`             | `em_len - hash_len - 2` (same as `Max`)         |
/// | `Max`              | `em_len - hash_len - 2`                         |
/// | `AutoDigestMax`    | `min(em_len - hash_len - 2, hash_len)`          |
/// | `Fixed(n)`         | `n` if `n <= em_len - hash_len - 2`, else error |
///
/// # Errors
///
/// Returns [`PssError::DataTooLargeForKeySize`] (mapped to
/// [`CryptoError::Encoding`]) when:
///   * `em_len < hash_len + 2` — modulus too small for any PSS encoding, or
///   * an explicit `Fixed(n)` exceeds the maximum permitted by the modulus.
///
/// # Rule R6 — Lossless Casts
///
/// All length arithmetic uses `checked_sub` to guard against modulus values
/// that would underflow `usize`.
fn resolve_salt_len_encode(
    salt: PssSaltLength,
    em_len: usize,
    hash_len: usize,
) -> CryptoResult<usize> {
    // Precondition shared by every variant: the EM block must hold at
    // least the hash output and the trailer (`0xBC`) plus the leading
    // `0x01` separator.  Equivalent to the C check
    // `if (emLen < hLen + 2) goto err;` at `rsa_pss.c:228`.
    let max_salt = em_len
        .checked_sub(hash_len)
        .and_then(|v| v.checked_sub(2))
        .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;

    match salt {
        // -1 ⇒ sLen = hLen
        PssSaltLength::DigestLength => Ok(hash_len),

        // -2 / -3 ⇒ maximize.  C source maps `MAX_SIGN`/`AUTO`/`MAX`
        // all to `RSA_PSS_SALTLEN_MAX` before the size check.
        PssSaltLength::Auto | PssSaltLength::Max => Ok(max_salt),

        // -4 ⇒ FIPS 186-4 default: maximize, but cap at hLen so the
        // resulting encoding stays within the bound `0 <= sLen <= hLen`
        // mandated by FIPS.  C source: `if (sLenMax >= 0 && sLen >
        // sLenMax) sLen = sLenMax;`
        PssSaltLength::AutoDigestMax => Ok(max_salt.min(hash_len)),

        // Explicit value: must fit the modulus.
        PssSaltLength::Fixed(n) => {
            if n > max_salt {
                Err(CryptoError::from(PssError::DataTooLargeForKeySize))
            } else {
                Ok(n)
            }
        }
    }
}

// =============================================================================
// EMSA-PSS — encode (sign side)
// =============================================================================

/// Eight zero bytes prepended to `mHash` during the `M'` construction
/// (RFC 8017 §9.1.1 step 5):
///
/// ```text
/// M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
/// ```
///
/// Mirrors the C constant `static const unsigned char zeroes[] = {0,0,...}`
/// declared at the top of `rsa_pss.c`.
const PSS_M_PRIME_PREFIX: [u8; 8] = [0u8; 8];

/// EMSA-PSS encoding per RFC 8017 §9.1.1.
///
/// Translates `ossl_rsa_padding_add_PKCS1_PSS_mgf1()` from `crypto/rsa/
/// rsa_pss.c` lines 173-282.  Produces an encoded message `EM` of length
/// `ceil(emBits / 8)` bytes which can then be turned into a signature via
/// the RSA private-key primitive.
///
/// # Arguments
///
/// * `em` — output buffer of length **exactly** `ceil(em_bits / 8)`.
///   Filled with the encoded message.
/// * `em_bits` — intended length of `EM` in bits, **typically
///   `modBits - 1`** where `modBits` is the bit-length of the RSA modulus.
/// * `m_hash` — the message hash `Hash(M)`. Must be exactly
///   `params.digest.digest_size()` bytes.
/// * `params` — PSS parameter bundle (digest, MGF1 digest, salt length,
///   trailer byte).
///
/// # Errors
///
/// * [`PssError::InvalidPssParameters`] — `params` invalid (e.g. trailer
///   field not `1`, zero-size digest selected).
/// * [`PssError::DataTooLargeForKeySize`] — `em` too short for the chosen
///   parameter set (`emLen < hLen + sLen + 2`).
/// * [`PssError::PssVerificationFailed`] — `m_hash` length differs from
///   the digest size (caller bug).
///
/// # RFC 8017 §9.1.1 algorithm
///
/// ```text
/// 1.  if mHash.len() != hLen, error
/// 2.  if emLen < hLen + sLen + 2, error
/// 3.  generate random salt of sLen bytes
/// 4.  M' = 0x00 00 00 00 00 00 00 00 || mHash || salt
/// 5.  H  = Hash(M')
/// 6.  PS = (emLen − sLen − hLen − 2) zero bytes
/// 7.  DB = PS || 0x01 || salt
/// 8.  dbMask = MGF1(H, emLen − hLen − 1)
/// 9.  maskedDB = DB XOR dbMask
/// 10. clear leftmost (8 · emLen − emBits) bits of maskedDB[0]
/// 11. EM = maskedDB || H || 0xBC
/// ```
///
/// # Security Notes
///
/// * The salt is generated with the cryptographic DRBG via
///   [`crate::rand::rand_bytes`] and is zeroized after use per
///   AAP §0.7.6.
/// * `M'`, `dbMask`, and the salt buffer are all passed through
///   [`Zeroize::zeroize`] before they leave scope.
pub fn pss_encode(
    em: &mut [u8],
    em_bits: usize,
    m_hash: &[u8],
    params: &PssParams,
) -> CryptoResult<()> {
    // -----------------------------------------------------------------
    // Step 0 — parameter validation (rsa_pss.c:184-218 sentinel handling)
    // -----------------------------------------------------------------
    params.validate()?;

    let hash_alg = params.digest;
    let mgf1_alg = params.effective_mgf1_digest();
    let h_len = hash_alg.digest_size();

    // Caller bug if the hash slice does not match the announced digest
    // size — every legitimate caller funnels `m_hash` through
    // `hash::digest()` whose output length is exactly `hash.digest_size()`.
    if m_hash.len() != h_len {
        return Err(CryptoError::from(PssError::InvalidPssParameters));
    }

    // -----------------------------------------------------------------
    // Step 1 — compute the leftmost-bit mask (`MSBits`) and adjust EM.
    //
    // `em_bits` represents the intended bit length of EM, which is one
    // less than the modulus bit-length.  When `em_bits` is a multiple
    // of 8 we have `MSBits = 0` and the C code prepends a `0x00` byte
    // before continuing with `emLen-1` octets of "real" EM.
    // -----------------------------------------------------------------
    // Rule R6: `em_bits & 0x7` always fits a `u8`; we keep it as `u32`
    // for the arithmetic below.
    let ms_bits: u32 = u32::try_from(em_bits & 0x7).unwrap_or(0);
    let full_em_len = em.len();

    // emLen as defined in RFC 8017 = ceil(em_bits / 8) = full_em_len
    // when MSBits != 0, or full_em_len - 1 when MSBits == 0 (the leading
    // 0x00 has already been counted in `em.len()`).
    let (em_slice, em_len): (&mut [u8], usize) = if ms_bits == 0 {
        if full_em_len == 0 {
            return Err(CryptoError::from(PssError::DataTooLargeForKeySize));
        }
        em[0] = 0;
        let (_lead, rest) = em.split_at_mut(1);
        let len = rest.len();
        (rest, len)
    } else {
        let len = full_em_len;
        (em, len)
    };

    // -----------------------------------------------------------------
    // Step 2 — resolve the salt length (rsa_pss.c:228-238)
    // -----------------------------------------------------------------
    if em_len < h_len.saturating_add(2) {
        return Err(CryptoError::from(PssError::DataTooLargeForKeySize));
    }
    let s_len = resolve_salt_len_encode(params.salt_length, em_len, h_len)?;

    // -----------------------------------------------------------------
    // Step 3 — generate the random salt (rsa_pss.c:241-247)
    // -----------------------------------------------------------------
    let mut salt: Vec<u8> = vec![0u8; s_len];
    if s_len > 0 {
        rand_bytes(&mut salt)?;
    }

    // -----------------------------------------------------------------
    // Step 4 — compute H = Hash(0x00...00 || mHash || salt)
    //   (rsa_pss.c:248-258)
    // -----------------------------------------------------------------
    // maskedDBLen = emLen − hLen − 1
    let masked_db_len = em_len
        .checked_sub(h_len)
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;

    let mut h_buf: Vec<u8> = {
        let mut ctx: Box<dyn Digest> = create_digest(hash_alg)?;
        ctx.update(&PSS_M_PRIME_PREFIX)?;
        ctx.update(m_hash)?;
        if s_len > 0 {
            ctx.update(&salt)?;
        }
        ctx.finalize()?
    };

    if h_buf.len() != h_len {
        // Defensive: digest implementations must produce `digest_size()`
        // bytes.  If this ever fires we treat it as a parameter error.
        h_buf.zeroize();
        salt.zeroize();
        return Err(CryptoError::from(PssError::InvalidPssParameters));
    }

    // -----------------------------------------------------------------
    // Step 5 — generate dbMask in EM[0..maskedDBLen] via MGF1
    //   (rsa_pss.c:260-262)
    // -----------------------------------------------------------------
    {
        let (db_region, h_region) = em_slice.split_at_mut(masked_db_len);
        // Copy H to its slot so subsequent steps can safely view it via
        // the shared slice; we still hold the raw bytes in `h_buf` for
        // potential debugging but those will be wiped at the end.
        h_region[..h_len].copy_from_slice(&h_buf);
        // MGF1(H, maskedDBLen) → dbMask.
        mgf1(db_region, &h_buf, mgf1_alg)?;

        // ---------------------------------------------------------
        // Step 6 — XOR 0x01 marker and salt into the masked DB
        //   (rsa_pss.c:266-274)
        //
        // PS is implicit (zeros XOR with mask = mask), so we only
        // touch the trailing `1 + sLen` bytes of `db_region`.
        // ---------------------------------------------------------
        // Offset of the `0x01` marker = emLen − sLen − hLen − 2
        let one_offset = em_len
            .checked_sub(s_len)
            .and_then(|v| v.checked_sub(h_len))
            .and_then(|v| v.checked_sub(2))
            .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;

        // XOR the 0x01 separator
        db_region[one_offset] ^= 0x01;

        // XOR the salt bytes that follow the 0x01 marker
        if s_len > 0 {
            // BOUNDED: `one_offset + 1 + s_len == masked_db_len` by the
            // size invariants we already checked (em_len ≥ s_len + h_len + 2).
            // Note: `salt` was allocated with `vec![0u8; s_len]`, so its
            // length is exactly `s_len` and `.iter().enumerate()` yields
            // exactly the same `s_len` indices as the original `0..s_len`
            // range-based loop while satisfying clippy::needless_range_loop.
            let salt_offset = one_offset
                .checked_add(1)
                .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;
            for (i, &salt_byte) in salt.iter().enumerate() {
                let idx = salt_offset
                    .checked_add(i)
                    .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;
                db_region[idx] ^= salt_byte;
            }
        }

        // ---------------------------------------------------------
        // Step 7 — clear leftmost (8·emLen − em_bits) bits in
        //   maskedDB[0]  (rsa_pss.c:278-279)
        //
        // When MSBits == 0 the mask is `0xFF >> 8` which is 0,
        // matching the C code which conditions this on MSBits.
        // ---------------------------------------------------------
        if ms_bits != 0 {
            // BOUNDED: `8 - ms_bits` ranges 1..=7, so the right shift
            // is well within the `u8` width.
            let shift = 8u32.saturating_sub(ms_bits);
            // Rule R6: shift only fits 0..=7; cast through `u8` after
            // masking the lower nibble defensively.
            let mask: u8 = 0xFFu8 >> (shift & 0x7);
            db_region[0] &= mask;
        }

        // ---------------------------------------------------------
        // Step 8 — set the trailer byte EM[emLen-1] = 0xBC
        //   (rsa_pss.c:284-285)
        // ---------------------------------------------------------
        // BOUNDED: `em_len >= 2` so `em_len - 1` is in range.
        let trailer_idx = em_len
            .checked_sub(1)
            .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;
        h_region[trailer_idx - masked_db_len] = PSS_TRAILER_BYTE;
    }

    // -----------------------------------------------------------------
    // Step 9 — secure cleanup of intermediate buffers
    // -----------------------------------------------------------------
    h_buf.zeroize();
    salt.zeroize();

    Ok(())
}

// =============================================================================
// EMSA-PSS — verify side
// =============================================================================

/// EMSA-PSS verification per RFC 8017 §9.1.2.
///
/// Translates `ossl_rsa_verify_PKCS1_PSS_mgf1()` from `crypto/rsa/rsa_pss.c`
/// lines 44-160.  Given the encoded message recovered from a signature
/// via the RSA public-key primitive, this function checks that the
/// encoding is consistent with the supplied message hash.
///
/// # Arguments
///
/// * `em` — encoded message recovered from the signature.
/// * `em_bits` — intended length of `EM` in bits (modBits − 1).
/// * `m_hash` — the original message hash, exactly `digest.digest_size()`
///   bytes.
/// * `params` — PSS parameters used during signing.
///
/// # Errors
///
/// All failure modes from RFC 8017 §9.1.2 are surfaced as [`PssError`]
/// variants:
///
/// * [`PssError::FirstOctetInvalid`]   — leftmost bit-mask check failed.
/// * [`PssError::LastOctetInvalid`]    — trailer byte ≠ `0xBC`.
/// * [`PssError::DataTooLargeForKeySize`] — `emLen < hLen + sLen + 2`.
/// * [`PssError::SaltLengthCheckFailed`] — salt length does not match
///   the explicitly requested length.
/// * [`PssError::InvalidPadding`]      — leftmost bits of `DB[0]` not zero,
///   or PS bytes corrupted, or `0x01` separator missing.
/// * [`PssError::PssVerificationFailed`] — final hash mismatch.
///
/// # Constant-Time Guarantees
///
/// The H ?= H′ comparison uses [`openssl_common::constant_time::memcmp`]
/// (a wrapper around `subtle::ConstantTimeEq`), preventing timing-based
/// signature forgery.  Earlier checks (trailer byte, leftmost bits, PS
/// scan) are *not* constant-time; they cannot be because they short-circuit
/// on structural validity rather than on secret-dependent data.  This
/// matches the behaviour of OpenSSL's C reference.
pub fn pss_verify(
    em: &[u8],
    em_bits: usize,
    m_hash: &[u8],
    params: &PssParams,
) -> CryptoResult<()> {
    // -----------------------------------------------------------------
    // Step 0 — parameter & input validation
    // -----------------------------------------------------------------
    params.validate()?;

    let hash_alg = params.digest;
    let mgf1_alg = params.effective_mgf1_digest();
    let h_len = hash_alg.digest_size();

    if m_hash.len() != h_len {
        return Err(CryptoError::from(PssError::InvalidPssParameters));
    }

    // -----------------------------------------------------------------
    // Step 1 — handle the leftmost zero byte when MSBits == 0
    //   (rsa_pss.c:80-100)
    // -----------------------------------------------------------------
    // Rule R6: `em_bits & 0x7` is in 0..=7 and fits any integer type.
    let ms_bits: u32 = u32::try_from(em_bits & 0x7).unwrap_or(0);

    if em.is_empty() {
        return Err(CryptoError::from(PssError::DataTooLargeForKeySize));
    }

    // Check the leftmost-bit constraint: EM[0] must have its top
    // (8 − MSBits) bits zero.  The C code computes
    // `if (EM[0] & (0xFF << MSBits))`.
    if ms_bits == 0 {
        // C: if EM[0] != 0 → first-octet violation (then EM++; emLen--).
        if em[0] != 0 {
            return Err(CryptoError::from(PssError::FirstOctetInvalid));
        }
    } else {
        // BOUNDED: ms_bits in 1..=7 — shift width is safe.
        // Mask of the bits that *must* be zero (the high (8 - ms_bits)
        // bits of the first byte).
        let shift = 8u32.saturating_sub(ms_bits);
        // `0xFF << ms_bits` → bits [ms_bits..7] in the C version.
        // We get the equivalent by inverting `(0xFF >> (8-ms_bits))`.
        let allowed_low: u8 = 0xFFu8 >> (shift & 0x7);
        let high_mask: u8 = !allowed_low;
        if em[0] & high_mask != 0 {
            return Err(CryptoError::from(PssError::FirstOctetInvalid));
        }
    }

    // Determine the working slice and its effective length.
    let (work, em_len): (&[u8], usize) = if ms_bits == 0 {
        // Skip the leading 0x00 byte
        let rest = &em[1..];
        (rest, rest.len())
    } else {
        (em, em.len())
    };

    if em_len < h_len.saturating_add(2) {
        return Err(CryptoError::from(PssError::DataTooLargeForKeySize));
    }

    // -----------------------------------------------------------------
    // Step 2 — resolve / sanity-check the salt length
    //   (rsa_pss.c:69-78, 102-110)
    // -----------------------------------------------------------------
    // The signing-side maximum permitted by the modulus.
    let max_s_len = em_len
        .checked_sub(h_len)
        .and_then(|v| v.checked_sub(2))
        .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;

    // Initial value:
    //   * `Some(n)` for explicit / digest-length specifications,
    //   * `None` for auto-recovery modes which figure out the salt
    //     length from the position of the 0x01 separator.
    let mut declared_s_len: Option<usize> = match params.salt_length {
        PssSaltLength::DigestLength => Some(h_len),
        PssSaltLength::Auto | PssSaltLength::AutoDigestMax => None,
        PssSaltLength::Max => {
            // C code unconditionally sets sLen = emLen - hLen - 2 in
            // this branch (rsa_pss.c:103-104); treat it as an explicit
            // length equal to the maximum.
            Some(max_s_len)
        }
        PssSaltLength::Fixed(n) => Some(n),
    };

    if let Some(n) = declared_s_len {
        if n > max_s_len {
            return Err(CryptoError::from(PssError::DataTooLargeForKeySize));
        }
    }

    // -----------------------------------------------------------------
    // Step 3 — verify trailer byte EM[emLen-1] == 0xBC
    //   (rsa_pss.c:111-114)
    // -----------------------------------------------------------------
    let last_idx = em_len
        .checked_sub(1)
        .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;
    if work[last_idx] != PSS_TRAILER_BYTE {
        return Err(CryptoError::from(PssError::LastOctetInvalid));
    }

    // -----------------------------------------------------------------
    // Step 4 — split EM into maskedDB || H || 0xBC
    //   (rsa_pss.c:115-117)
    // -----------------------------------------------------------------
    let masked_db_len = em_len
        .checked_sub(h_len)
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| CryptoError::from(PssError::DataTooLargeForKeySize))?;
    // BOUNDED: `masked_db_len + h_len + 1 == em_len` by construction.
    let masked_db = &work[..masked_db_len];
    let h_slice = &work[masked_db_len..masked_db_len + h_len];

    // -----------------------------------------------------------------
    // Step 5 — compute dbMask = MGF1(H, maskedDBLen)
    //   (rsa_pss.c:118-120)
    // -----------------------------------------------------------------
    let mut db: Vec<u8> = vec![0u8; masked_db_len];
    mgf1(&mut db, h_slice, mgf1_alg)?;

    // -----------------------------------------------------------------
    // Step 6 — DB = maskedDB XOR dbMask  (rsa_pss.c:124-125)
    // -----------------------------------------------------------------
    for i in 0..masked_db_len {
        db[i] ^= masked_db[i];
    }

    // -----------------------------------------------------------------
    // Step 7 — clear leftmost bits of DB[0]  (rsa_pss.c:127)
    // -----------------------------------------------------------------
    if ms_bits != 0 && !db.is_empty() {
        // BOUNDED: ms_bits ∈ 1..=7 — shift is safe.
        let shift = 8u32.saturating_sub(ms_bits);
        let mask: u8 = 0xFFu8 >> (shift & 0x7);
        db[0] &= mask;
    }

    // -----------------------------------------------------------------
    // Step 8 — find the 0x01 separator after PS  (rsa_pss.c:129-138)
    //
    // Skip leading zeros until we hit a non-zero byte; that byte must
    // be 0x01.  Anything else means the padding was tampered with.
    // -----------------------------------------------------------------
    let mut idx: usize = 0;
    while idx < masked_db_len.saturating_sub(1) && db[idx] == 0 {
        // BOUNDED: bounded by masked_db_len which is bounded by em_len
        idx = if let Some(v) = idx.checked_add(1) {
            v
        } else {
            db.zeroize();
            return Err(CryptoError::from(PssError::InvalidPadding));
        };
    }
    if idx >= masked_db_len || db[idx] != 0x01 {
        db.zeroize();
        return Err(CryptoError::from(PssError::InvalidPadding));
    }
    // BOUNDED: idx < masked_db_len, so idx + 1 ≤ masked_db_len.
    let salt_start = idx
        .checked_add(1)
        .ok_or_else(|| CryptoError::from(PssError::InvalidPadding))?;

    // Recovered salt length = remaining bytes after the 0x01 marker.
    // BOUNDED: salt_start ≤ masked_db_len so subtraction never wraps.
    let recovered_s_len = masked_db_len
        .checked_sub(salt_start)
        .ok_or_else(|| CryptoError::from(PssError::InvalidPadding))?;

    // -----------------------------------------------------------------
    // Step 9 — salt-length cross-check  (rsa_pss.c:139-149)
    // -----------------------------------------------------------------
    if let Some(expected) = declared_s_len {
        if recovered_s_len != expected {
            db.zeroize();
            return Err(CryptoError::from(PssError::SaltLengthCheckFailed));
        }
    }
    declared_s_len = Some(recovered_s_len);

    // -----------------------------------------------------------------
    // Step 10 — recompute H' = Hash(0x00...00 || mHash || salt)
    //   (rsa_pss.c:150-158)
    // -----------------------------------------------------------------
    let mut h_prime: Vec<u8> = {
        let mut ctx: Box<dyn Digest> = create_digest(hash_alg)?;
        ctx.update(&PSS_M_PRIME_PREFIX)?;
        ctx.update(m_hash)?;
        if recovered_s_len > 0 {
            // BOUNDED: salt_start + recovered_s_len == masked_db_len.
            ctx.update(&db[salt_start..salt_start + recovered_s_len])?;
        }
        ctx.finalize()?
    };

    // -----------------------------------------------------------------
    // Step 11 — constant-time H' == H comparison  (rsa_pss.c:159)
    // -----------------------------------------------------------------
    let matches = constant_time::memcmp(&h_prime, h_slice);

    // Secure cleanup before returning either branch.
    h_prime.zeroize();
    db.zeroize();

    if matches {
        // `declared_s_len` is `Some(recovered_s_len)` at this point;
        // the C version writes back `*sLenOut = sLen`.  We don't expose
        // that as an out-parameter — callers can re-derive it from the
        // signature by re-running the verify if they care.
        let _ = declared_s_len;
        Ok(())
    } else {
        Err(CryptoError::from(PssError::PssVerificationFailed))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // PssError → CryptoError mapping
    // ---------------------------------------------------------------------

    #[test]
    fn pss_error_display_strings_are_descriptive() {
        // Every variant must produce a non-empty, human-readable message.
        for err in [
            PssError::SaltLengthCheckFailed,
            PssError::DataTooLargeForKeySize,
            PssError::InvalidPssParameters,
            PssError::PssVerificationFailed,
            PssError::FirstOctetInvalid,
            PssError::LastOctetInvalid,
            PssError::InvalidPadding,
        ] {
            let s = format!("{}", err);
            assert!(!s.is_empty(), "Display string empty for {:?}", err);
            assert!(
                s.len() > 5,
                "Display string too short for {:?}: {:?}",
                err,
                s
            );
        }
    }

    #[test]
    fn pss_error_maps_encoding_failures_to_encoding_variant() {
        // Encoding-time errors should map to CryptoError::Encoding.
        for err in [
            PssError::DataTooLargeForKeySize,
            PssError::InvalidPssParameters,
            PssError::FirstOctetInvalid,
            PssError::LastOctetInvalid,
            PssError::InvalidPadding,
        ] {
            let mapped: CryptoError = err.clone().into();
            assert!(
                matches!(mapped, CryptoError::Encoding(_)),
                "Expected Encoding for {:?}, got {:?}",
                err,
                mapped
            );
        }
    }

    #[test]
    fn pss_error_maps_verification_failures_to_verification_variant() {
        for err in [
            PssError::SaltLengthCheckFailed,
            PssError::PssVerificationFailed,
        ] {
            let mapped: CryptoError = err.clone().into();
            assert!(
                matches!(mapped, CryptoError::Verification(_)),
                "Expected Verification for {:?}, got {:?}",
                err,
                mapped
            );
        }
    }

    // ---------------------------------------------------------------------
    // PssSaltLength legacy-int round-trip
    // ---------------------------------------------------------------------

    #[test]
    fn salt_length_sentinels_match_c_macros() {
        assert_eq!(PssSaltLength::DigestLength.as_legacy_int(), -1);
        assert_eq!(PssSaltLength::Auto.as_legacy_int(), -2);
        assert_eq!(PssSaltLength::Max.as_legacy_int(), -3);
        assert_eq!(PssSaltLength::AutoDigestMax.as_legacy_int(), -4);
        assert_eq!(PssSaltLength::Fixed(0).as_legacy_int(), 0);
        assert_eq!(PssSaltLength::Fixed(32).as_legacy_int(), 32);
    }

    #[test]
    fn salt_length_round_trip_through_legacy_int() {
        for v in [
            PssSaltLength::DigestLength,
            PssSaltLength::Auto,
            PssSaltLength::Max,
            PssSaltLength::AutoDigestMax,
            PssSaltLength::Fixed(0),
            PssSaltLength::Fixed(20),
            PssSaltLength::Fixed(64),
        ] {
            let n = v.as_legacy_int();
            let back = PssSaltLength::from_legacy_int(n).unwrap();
            assert_eq!(v, back, "round-trip failed for {:?}", v);
        }
    }

    #[test]
    fn salt_length_from_legacy_int_rejects_out_of_range() {
        assert!(PssSaltLength::from_legacy_int(-5).is_err());
        assert!(PssSaltLength::from_legacy_int(-100).is_err());
        // Non-negative values always succeed (Fixed)
        assert!(PssSaltLength::from_legacy_int(0).is_ok());
        assert!(PssSaltLength::from_legacy_int(1024).is_ok());
    }

    // ---------------------------------------------------------------------
    // PssMaskGen / PssParams30 default behaviour
    // ---------------------------------------------------------------------

    #[test]
    fn mask_gen_default_is_mgf1_with_no_explicit_hash() {
        let mg = PssMaskGen::default_mgf1();
        assert_eq!(mg.algorithm_nid, NID_MGF1);
        assert!(mg.hash_algorithm.is_none());
        // Default impl matches default_mgf1
        assert_eq!(PssMaskGen::default(), mg);
    }

    #[test]
    fn pss_params30_new_is_unrestricted() {
        let p = PssParams30::new();
        assert!(p.is_unrestricted());
        // resolved_* falls back to RFC 4055 defaults
        assert_eq!(p.resolved_hash(), DigestAlgorithm::Sha1);
        assert_eq!(p.resolved_mgf1_hash(), DigestAlgorithm::Sha1);
        assert_eq!(p.resolved_salt_len(), DEFAULT_SALT_LEN);
        assert_eq!(p.resolved_trailer_field(), DEFAULT_TRAILER_FIELD);
    }

    #[test]
    fn pss_params30_set_defaults_yields_default_constant() {
        let mut p = PssParams30::new();
        p.set_hash_algorithm(DigestAlgorithm::Sha256);
        p.set_mgf1_hash_algorithm(DigestAlgorithm::Sha256);
        p.set_salt_len(32);
        p.set_trailer_field(1);
        // Should no longer be unrestricted
        assert!(!p.is_unrestricted());
        // Reset to defaults — equals the published constant.
        p.set_defaults();
        assert_eq!(p, DEFAULT_PSS_PARAMS_30);
    }

    #[test]
    fn pss_params30_resolved_methods_use_set_values() {
        let mut p = PssParams30::new();
        p.set_hash_algorithm(DigestAlgorithm::Sha384);
        p.set_mgf1_hash_algorithm(DigestAlgorithm::Sha512);
        p.set_salt_len(48);
        p.set_trailer_field(1);
        assert_eq!(p.resolved_hash(), DigestAlgorithm::Sha384);
        assert_eq!(p.resolved_mgf1_hash(), DigestAlgorithm::Sha512);
        assert_eq!(p.resolved_salt_len(), 48);
        assert_eq!(p.resolved_trailer_field(), 1);
    }

    #[test]
    fn pss_params30_is_copy() {
        // Compile-time check that the type is Copy.
        let p = PssParams30::new();
        let _q = p; // copy
        let _r = p; // copy again — would not compile if not Copy
    }

    // ---------------------------------------------------------------------
    // PssParams (lightweight) defaults & resolution
    // ---------------------------------------------------------------------

    #[test]
    fn pss_params_default_matches_rfc8017() {
        let p = PssParams::default();
        assert_eq!(p.digest, DigestAlgorithm::Sha1);
        assert!(p.mgf1_digest.is_none());
        assert_eq!(p.salt_length, PssSaltLength::DigestLength);
        assert_eq!(p.trailer_field, 1);
        assert!(p.is_unrestricted());
    }

    #[test]
    fn pss_params_effective_mgf1_falls_back_to_digest() {
        let p = PssParams::new(DigestAlgorithm::Sha256);
        assert_eq!(p.effective_mgf1_digest(), DigestAlgorithm::Sha256);
        assert_eq!(p.resolved_mgf1_digest(), DigestAlgorithm::Sha256);

        let q = PssParams::new(DigestAlgorithm::Sha256).with_mgf1_hash(DigestAlgorithm::Sha384);
        assert_eq!(q.effective_mgf1_digest(), DigestAlgorithm::Sha384);
    }

    #[test]
    fn pss_params_validate_rejects_invalid_trailer() {
        let mut p = PssParams::new(DigestAlgorithm::Sha256);
        p.trailer_field = 2;
        let err = p.validate().unwrap_err();
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn pss_params_resolve_salt_length_for_each_variant() {
        // For SHA-256: hLen = 32.  For a 2048-bit modulus emLen = 256.
        let h = 32;
        let em = 256;

        // DigestLength → hLen
        let p = PssParams::new(DigestAlgorithm::Sha256);
        assert_eq!(p.resolve_salt_length(em, h).unwrap(), h);

        // Max → emLen − hLen − 2
        let p = PssParams::new(DigestAlgorithm::Sha256).with_salt_length(PssSaltLength::Max);
        assert_eq!(p.resolve_salt_length(em, h).unwrap(), em - h - 2);

        // Auto behaves like Max on encoding
        let p = PssParams::new(DigestAlgorithm::Sha256).with_salt_length(PssSaltLength::Auto);
        assert_eq!(p.resolve_salt_length(em, h).unwrap(), em - h - 2);

        // AutoDigestMax → min(max, hLen)
        let p =
            PssParams::new(DigestAlgorithm::Sha256).with_salt_length(PssSaltLength::AutoDigestMax);
        assert_eq!(p.resolve_salt_length(em, h).unwrap(), h);

        // Fixed(n) within range
        let p = PssParams::new(DigestAlgorithm::Sha256).with_salt_length(PssSaltLength::Fixed(64));
        assert_eq!(p.resolve_salt_length(em, h).unwrap(), 64);

        // Fixed(n) too large rejected
        let p = PssParams::new(DigestAlgorithm::Sha256)
            .with_salt_length(PssSaltLength::Fixed(em - h - 1));
        assert!(matches!(
            p.resolve_salt_length(em, h),
            Err(CryptoError::Encoding(_))
        ));
    }

    #[test]
    fn pss_params_resolve_salt_length_rejects_undersized_modulus() {
        // emLen = 30, hLen = 32 — fails the `emLen >= hLen + 2` check.
        let p = PssParams::new(DigestAlgorithm::Sha256);
        assert!(matches!(
            p.resolve_salt_length(30, 32),
            Err(CryptoError::Encoding(_))
        ));
    }

    // ---------------------------------------------------------------------
    // resolve_salt_len_encode helper
    // ---------------------------------------------------------------------

    #[test]
    fn resolve_salt_len_encode_handles_all_variants() {
        let em = 256;
        let h = 32;
        assert_eq!(
            resolve_salt_len_encode(PssSaltLength::DigestLength, em, h).unwrap(),
            32
        );
        assert_eq!(
            resolve_salt_len_encode(PssSaltLength::Max, em, h).unwrap(),
            em - h - 2
        );
        assert_eq!(
            resolve_salt_len_encode(PssSaltLength::Auto, em, h).unwrap(),
            em - h - 2
        );
        assert_eq!(
            resolve_salt_len_encode(PssSaltLength::AutoDigestMax, em, h).unwrap(),
            h
        );
        assert_eq!(
            resolve_salt_len_encode(PssSaltLength::Fixed(20), em, h).unwrap(),
            20
        );
    }

    // ---------------------------------------------------------------------
    // Pkcs1v15SignParams
    // ---------------------------------------------------------------------

    #[test]
    fn pkcs1v15_sign_params_constructor_preserves_digest() {
        let p = Pkcs1v15SignParams::new(DigestAlgorithm::Sha384);
        assert_eq!(p.digest, DigestAlgorithm::Sha384);
        // Copy works
        let q = p;
        assert_eq!(p, q);
    }

    // ---------------------------------------------------------------------
    // digest_info_prefix — at least the SHA family must round-trip
    // ---------------------------------------------------------------------

    #[test]
    fn digest_info_prefix_returns_some_for_standard_hashes() {
        // Every hash listed in the C `ossl_rsa_digestinfo_encoding` switch
        // must yield a non-empty DER prefix.  We list them explicitly so
        // a missing arm is caught at compile time.
        let cases = [
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
            DigestAlgorithm::Md2,
            DigestAlgorithm::Md4,
            DigestAlgorithm::Mdc2,
            DigestAlgorithm::Ripemd160,
            DigestAlgorithm::Sm3,
        ];
        for alg in cases {
            let p = digest_info_prefix(alg);
            assert!(p.is_some(), "missing DigestInfo prefix for {:?}", alg);
            let bytes = p.unwrap();
            assert!(!bytes.is_empty(), "empty prefix for {:?}", alg);
            // Every prefix begins with 0x30 (SEQUENCE).
            assert_eq!(bytes[0], 0x30, "bad SEQUENCE byte for {:?}", alg);
        }
    }

    #[test]
    fn digest_info_prefix_returns_none_for_unsupported_hashes() {
        let cases = [
            DigestAlgorithm::Md5Sha1,
            DigestAlgorithm::Whirlpool,
            DigestAlgorithm::Shake128,
            DigestAlgorithm::Shake256,
            DigestAlgorithm::Blake2b256,
            DigestAlgorithm::Blake2b512,
            DigestAlgorithm::Blake2s256,
        ];
        for alg in cases {
            assert!(
                digest_info_prefix(alg).is_none(),
                "unexpected DigestInfo prefix for {:?}",
                alg
            );
        }
    }

    // ---------------------------------------------------------------------
    // pss_encode → pss_verify round-trip
    // ---------------------------------------------------------------------

    /// Helper: 2048-bit modulus has 256-byte EM and `em_bits = 2047`.
    fn rfc8017_2048_em_bits() -> usize {
        2047
    }

    #[test]
    fn pss_round_trip_sha256_default_salt() {
        // mHash for an arbitrary input — actual hash value is irrelevant
        // for the round-trip; encode + verify use the same value.
        let mut hasher: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        hasher
            .update(b"OpenSSL -> Rust PSS round-trip test")
            .unwrap();
        let m_hash = hasher.finalize().unwrap();

        let params = PssParams::new(DigestAlgorithm::Sha256);
        let em_bits = rfc8017_2048_em_bits();
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        pss_encode(&mut em, em_bits, &m_hash, &params).unwrap();

        // Trailer must be 0xBC.
        assert_eq!(*em.last().unwrap(), 0xBC);
        // Top bit of EM[0] must be zero (em_bits is 2047 → MSBits = 7,
        // so the leftmost bit is forbidden).
        assert_eq!(em[0] & 0x80, 0);

        // Verify succeeds for the same params.
        pss_verify(&em, em_bits, &m_hash, &params).unwrap();
    }

    #[test]
    fn pss_round_trip_with_explicit_mgf1_hash() {
        let mut hasher: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        hasher.update(b"distinct mgf1 hash").unwrap();
        let m_hash = hasher.finalize().unwrap();

        let params =
            PssParams::new(DigestAlgorithm::Sha256).with_mgf1_hash(DigestAlgorithm::Sha384);
        let em_bits = rfc8017_2048_em_bits();
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        pss_encode(&mut em, em_bits, &m_hash, &params).unwrap();
        pss_verify(&em, em_bits, &m_hash, &params).unwrap();
    }

    #[test]
    fn pss_round_trip_with_max_salt_length() {
        let mut hasher: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        hasher.update(b"max salt length").unwrap();
        let m_hash = hasher.finalize().unwrap();

        let params = PssParams::new(DigestAlgorithm::Sha256).with_salt_length(PssSaltLength::Max);
        let em_bits = rfc8017_2048_em_bits();
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        pss_encode(&mut em, em_bits, &m_hash, &params).unwrap();
        pss_verify(&em, em_bits, &m_hash, &params).unwrap();
    }

    #[test]
    fn pss_round_trip_with_zero_salt_length() {
        let mut hasher: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        hasher.update(b"zero salt length").unwrap();
        let m_hash = hasher.finalize().unwrap();

        let params =
            PssParams::new(DigestAlgorithm::Sha256).with_salt_length(PssSaltLength::Fixed(0));
        let em_bits = rfc8017_2048_em_bits();
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        pss_encode(&mut em, em_bits, &m_hash, &params).unwrap();
        pss_verify(&em, em_bits, &m_hash, &params).unwrap();
    }

    #[test]
    fn pss_round_trip_sha384_modbits_3072() {
        // 3072-bit modulus → emLen = 384, em_bits = 3071.
        let mut hasher: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha384).unwrap();
        hasher.update(b"sha-384 round-trip").unwrap();
        let m_hash = hasher.finalize().unwrap();

        let params = PssParams::new(DigestAlgorithm::Sha384);
        let em_bits = 3071;
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        pss_encode(&mut em, em_bits, &m_hash, &params).unwrap();
        pss_verify(&em, em_bits, &m_hash, &params).unwrap();
    }

    #[test]
    fn pss_verify_detects_tampered_trailer() {
        let mut hasher: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        hasher.update(b"tamper").unwrap();
        let m_hash = hasher.finalize().unwrap();

        let params = PssParams::new(DigestAlgorithm::Sha256);
        let em_bits = rfc8017_2048_em_bits();
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        pss_encode(&mut em, em_bits, &m_hash, &params).unwrap();
        // Corrupt the trailer
        let last = em.len() - 1;
        em[last] ^= 0x01;

        let err = pss_verify(&em, em_bits, &m_hash, &params).unwrap_err();
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn pss_verify_detects_corrupted_hash() {
        let mut hasher: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        hasher.update(b"flip-bit").unwrap();
        let m_hash = hasher.finalize().unwrap();

        let params = PssParams::new(DigestAlgorithm::Sha256);
        let em_bits = rfc8017_2048_em_bits();
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        pss_encode(&mut em, em_bits, &m_hash, &params).unwrap();
        // Flip a middle byte (in the H portion).
        let mid = em.len() / 2;
        em[mid] ^= 0xFF;

        let err = pss_verify(&em, em_bits, &m_hash, &params).unwrap_err();
        // Could be PssVerificationFailed or InvalidPadding depending on
        // which check fires first — both indicate a forged signature.
        assert!(
            matches!(err, CryptoError::Verification(_) | CryptoError::Encoding(_)),
            "Unexpected error variant: {:?}",
            err
        );
    }

    #[test]
    fn pss_verify_rejects_wrong_message_hash() {
        let params = PssParams::new(DigestAlgorithm::Sha256);
        let em_bits = rfc8017_2048_em_bits();
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        // Encode for one message…
        let mut h1: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        h1.update(b"message A").unwrap();
        let m_hash_a = h1.finalize().unwrap();
        pss_encode(&mut em, em_bits, &m_hash_a, &params).unwrap();

        // …verify against a different message.
        let mut h2: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        h2.update(b"message B").unwrap();
        let m_hash_b = h2.finalize().unwrap();

        let err = pss_verify(&em, em_bits, &m_hash_b, &params).unwrap_err();
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn pss_encode_rejects_wrong_hash_length() {
        let params = PssParams::new(DigestAlgorithm::Sha256);
        let em_bits = rfc8017_2048_em_bits();
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        // Pass a 5-byte "hash" — should be 32.
        let bogus = [0u8; 5];
        let err = pss_encode(&mut em, em_bits, &bogus, &params).unwrap_err();
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn pss_encode_rejects_too_small_modulus() {
        let params = PssParams::new(DigestAlgorithm::Sha256);
        // 256-bit modulus → emLen = 32 but hLen = 32, sLen = 32 → fails
        // the `emLen >= hLen + sLen + 2` check.
        let em_bits = 255;
        let em_len = (em_bits + 7) / 8;
        let mut em = vec![0u8; em_len];

        let m_hash = vec![0u8; 32];
        let err = pss_encode(&mut em, em_bits, &m_hash, &params).unwrap_err();
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn pss_round_trip_with_msbits_zero() {
        // em_bits divisible by 8 → MSBits = 0 case (rsa_pss.c:88).
        // Use 2056-bit modulus, em_bits = 2056 → MSBits = 0.
        let em_bits = 2056;
        let em_len = (em_bits + 7) / 8 + 1; // +1 for the leading 0x00
        let mut hasher: Box<dyn Digest> = create_digest(DigestAlgorithm::Sha256).unwrap();
        hasher.update(b"msbits zero case").unwrap();
        let m_hash = hasher.finalize().unwrap();

        let params = PssParams::new(DigestAlgorithm::Sha256);
        let mut em = vec![0u8; em_len];

        pss_encode(&mut em, em_bits, &m_hash, &params).unwrap();
        // Leading byte should be 0x00 because MSBits == 0.
        assert_eq!(em[0], 0x00);
        pss_verify(&em, em_bits, &m_hash, &params).unwrap();
    }
}
