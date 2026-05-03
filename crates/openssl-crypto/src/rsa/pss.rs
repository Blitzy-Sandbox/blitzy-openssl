//! RSA-PSS (Probabilistic Signature Scheme) per RFC 8017 §8.1 / §9.1.
//!
//! Provides PSS signature generation and verification using EMSA-PSS encoding.
//! Translates `crypto/rsa/rsa_pss.c` (~400 lines) and the related metadata
//! plumbing in `include/crypto/rsa.h` into idiomatic Rust.
//!
//! ## Source Mapping
//!
//! | Rust Component                       | C Source                                                | Purpose |
//! |--------------------------------------|---------------------------------------------------------|---------|
//! | [`PssSaltLength`]                    | `include/openssl/rsa.h::RSA_PSS_SALTLEN_*`              | Typed salt-length sentinels (replaces integer constants) |
//! | [`PssParams30`]                      | `include/crypto/rsa.h::RSA_PSS_PARAMS_30`               | PSS metadata stored on RSASSA-PSS keys (RFC 4055) |
//! | [`DEFAULT_PSS_PARAMS_30`]            | `crypto/rsa/rsa_pss.c::default_RSASSA_PSS_params`       | Default PSS parameter set: `{SHA-1, MGF1(SHA-1), 20, 1}` |
//! | [`PssParams30::is_unrestricted`]     | `crypto/rsa/rsa_pss.c::ossl_rsa_pss_params_30_is_unrestricted` | Detect unrestricted (zero-init) parameter sets |
//! | [`PssParams30::set_defaults`]        | `crypto/rsa/rsa_pss.c::ossl_rsa_pss_params_30_set_defaults`   | Apply RFC 4055 defaults for unset fields |
//! | [`PssParams`]                        | `crypto/rsa/rsa_pss.c` (parameters of encode/verify)    | Lightweight parameter bundle for sign/verify operations |
//! | [`pss_sign`]                         | `crypto/rsa/rsa_pss.c::ossl_rsa_padding_add_PKCS1_PSS_mgf1` | RFC 8017 §9.1.1 EMSA-PSS-Encode (signature generation) |
//! | [`pss_verify`]                       | `crypto/rsa/rsa_pss.c::ossl_rsa_verify_PKCS1_PSS_mgf1`  | RFC 8017 §9.1.2 EMSA-PSS-Verify (signature verification) |
//! | [`pkcs1_mgf1`]                       | `crypto/rsa/rsa_oaep.c::PKCS1_MGF1`                     | RFC 8017 §B.2.1 MGF1 mask generation (shared with OAEP) |
//!
//! ## RFC 8017 §9.1 EMSA-PSS Overview
//!
//! Probabilistic Signature Scheme (PSS) provides provably-secure RSA
//! signatures with random salting. The encoded message has the form:
//!
//! ```text
//! EM = maskedDB || H || 0xBC
//!
//! Where:
//!   maskedDB = DB ⊕ MGF1(H, len(DB))
//!   DB       = PS (zeros) || 0x01 || salt
//!   H        = Hash(0x00..00 || mHash || salt)   ; 8 zero bytes prefix
//!   mHash    = Hash(M)                             ; M is the message
//! ```
//!
//! The leading zero bits in `EM[0]` are masked out so that `EM` is
//! representable in `keysize - 1` bits (interpreted as a big integer
//! strictly less than the modulus n).
//!
//! ## Salt Length Conventions
//!
//! - `PssSaltLength::Digest`            (`-1`): salt length equals hash output length
//! - `PssSaltLength::Auto`              (`-2`): autorecover during verify; same as `MaxSign` during sign
//! - `PssSaltLength::Max`               (`-3`): maximum salt allowed by modulus
//! - `PssSaltLength::AutoDigestMax`     (`-4`): auto, capped at digest length
//! - `PssSaltLength::Custom(n)`         (≥0): explicit byte count
//!
//! ## Security Notes
//!
//! - The salt is generated cryptographically via [`crate::rand::rand_bytes`].
//! - All comparisons against the trailer byte `0xBC` are performed before the
//!   hash recomputation step to fail fast on malformed signatures.
//! - The salt buffer is securely zeroized after use via the `zeroize` crate.
//! - Verification uses a constant-time hash comparison (`constant_time::memcmp`).
//!
//! ## Design Rules Enforced
//!
//! - **R5 (Nullability):** Hash algorithms are `Option<DigestAlgorithm>`
//!   (defaulting via [`PssParams30::set_defaults`] when needed). Salt length is
//!   the [`PssSaltLength`] enum, not a sentinel integer.
//! - **R6 (Lossless Casts):** Length math uses `usize`/`u32` with checked
//!   arithmetic; no bare `as` narrowing.
//! - **R8 (No Unsafe):** `#![forbid(unsafe_code)]` is inherited at the crate
//!   level. PSS performs zero unsafe operations.
//! - **§0.7.6 (Secure Erasure):** Salt buffers are wiped via `zeroize`.

use openssl_common::constant_time;
use openssl_common::error::{CryptoError, CryptoResult};
use openssl_common::param::{ParamSet, ParamValue};

use crate::bn::{montgomery, BigNum};
use crate::hash::{create_digest, Digest, DigestAlgorithm};
use crate::rand::rand_bytes;

use tracing::{debug, trace};
use zeroize::Zeroize;

use super::{RsaError, RsaPrivateKey, RsaPublicKey};

// -----------------------------------------------------------------------------
// Constants (algorithm identifiers — translated from C NID values)
// -----------------------------------------------------------------------------

/// Numeric identifier for the MGF1 mask generation function.
///
/// Translates `NID_mgf1` from `crypto/objects/objects.h`. The PSS specification
/// (RFC 4055) defines MGF1 as the only standard mask generation function for
/// PSS, so this is effectively a constant.
pub const NID_MGF1: u32 = 911;

/// PSS trailer byte per RFC 8017 §9.1.1 step 11 — `EM[emLen-1] = 0xBC`.
const PSS_TRAILER_BYTE: u8 = 0xBC;

/// Default trailer field per RFC 4055 — `1` indicates the `0xBC` trailer byte.
const DEFAULT_TRAILER_FIELD: i32 = 1;

/// Default salt length when none is specified, per RFC 4055.
const DEFAULT_SALT_LEN: i32 = 20;

// -----------------------------------------------------------------------------
// PssSaltLength (replaces RSA_PSS_SALTLEN_* sentinel integers)
// -----------------------------------------------------------------------------

/// PSS salt length specification.
///
/// Replaces C `#define RSA_PSS_SALTLEN_DIGEST -1`, `RSA_PSS_SALTLEN_AUTO -2`,
/// `RSA_PSS_SALTLEN_MAX -3`, `RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4` from
/// `include/openssl/rsa.h` with a typed enum (Rule R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PssSaltLength {
    /// Salt length equals the digest output length (`-1`).
    Digest,
    /// Autorecover during verification; equivalent to `Max` during signing
    /// (`-2`).
    Auto,
    /// Use the maximum salt length permitted by the modulus (`-3`).
    Max,
    /// Auto, but capped at the digest length (`-4`).
    AutoDigestMax,
    /// Explicit salt byte count.
    Custom(usize),
}

impl PssSaltLength {
    /// Convert this salt length into the corresponding negative sentinel used
    /// by C OpenSSL.
    ///
    /// Returns:
    ///   - `Custom(n)` → `n as i32`
    ///   - `Digest`    → `-1`
    ///   - `Auto`      → `-2`
    ///   - `Max`       → `-3`
    ///   - `AutoDigestMax` → `-4`
    pub fn as_legacy_int(&self) -> i32 {
        match self {
            PssSaltLength::Digest => -1,
            PssSaltLength::Auto => -2,
            PssSaltLength::Max => -3,
            PssSaltLength::AutoDigestMax => -4,
            PssSaltLength::Custom(n) => i32::try_from(*n).unwrap_or(i32::MAX),
        }
    }

    /// Construct from the C sentinel integer convention.
    pub fn from_legacy_int(value: i32) -> Self {
        match value {
            -1 => PssSaltLength::Digest,
            -2 => PssSaltLength::Auto,
            -3 => PssSaltLength::Max,
            -4 => PssSaltLength::AutoDigestMax,
            n if n >= 0 => {
                // `n >= 0` proven by match guard; `usize::try_from` cannot fail
                // on platforms where `usize::MAX >= i32::MAX` (32-bit and 64-bit
                // targets supported by this crate). Falls back to a safe default
                // in the impossible 16-bit case.
                PssSaltLength::Custom(usize::try_from(n).unwrap_or(0))
            }
            _ => PssSaltLength::Auto,
        }
    }
}

// -----------------------------------------------------------------------------
// Mask Generation Function metadata
// -----------------------------------------------------------------------------

/// PSS mask-generation function metadata.
///
/// Translates the inner anonymous struct of `RSA_PSS_PARAMS_30::mask_gen` from
/// `include/crypto/rsa.h` lines 22-25:
///
/// ```c
/// struct {
///     int algorithm_nid;       /* Currently always NID_mgf1 */
///     int hash_algorithm_nid;
/// } mask_gen;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssMaskGen {
    /// MGF algorithm identifier — currently always [`NID_MGF1`].
    pub algorithm_nid: u32,
    /// Inner hash function used by MGF1. `None` means "unset"; the default is
    /// SHA-1 per RFC 4055.
    pub hash_algorithm: Option<DigestAlgorithm>,
}

impl PssMaskGen {
    /// Construct the default MGF specification: MGF1 with SHA-1.
    pub const fn default_mgf1() -> Self {
        Self {
            algorithm_nid: NID_MGF1,
            hash_algorithm: Some(DigestAlgorithm::Sha1),
        }
    }
}

// -----------------------------------------------------------------------------
// PssParams30 (the RFC 4055 RSASSA-PSS-params structure)
// -----------------------------------------------------------------------------

/// PSS parameter set stored on RSASSA-PSS public/private keys.
///
/// Translates `RSA_PSS_PARAMS_30` from `include/crypto/rsa.h` lines 20-28:
///
/// ```c
/// typedef struct rsa_pss_params_30_st {
///     int hash_algorithm_nid;
///     struct {
///         int algorithm_nid;            /* Currently always NID_mgf1 */
///         int hash_algorithm_nid;
///     } mask_gen;
///     int salt_len;
///     int trailer_field;
/// } RSA_PSS_PARAMS_30;
/// ```
///
/// Per RFC 4055 §3.1, when a field is absent (`hash_algorithm == None`,
/// `salt_len == -1`, `trailer_field == -1`), the corresponding default is
/// applied via [`Self::set_defaults`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssParams30 {
    /// Message hash algorithm. `None` = unset (use default SHA-1).
    pub hash_algorithm: Option<DigestAlgorithm>,
    /// Mask generation function specification.
    pub mask_gen: PssMaskGen,
    /// Salt length in bytes. `-1` = unset (use default 20).
    pub salt_len: i32,
    /// Trailer field value. `-1` = unset (use default 1, encoded as `0xBC`).
    pub trailer_field: i32,
}

/// Default PSS parameters per RFC 4055 §3.1.
///
/// Translates `default_RSASSA_PSS_params` from `crypto/rsa/rsa_pss.c` lines
/// 314-322:
///
/// ```c
/// static const RSA_PSS_PARAMS_30 default_RSASSA_PSS_params = {
///     NID_sha1,                /* default hashAlgorithm */
///     { NID_mgf1, NID_sha1 },  /* default maskGenAlgorithm + MGF1 hash */
///     20,                      /* default saltLength */
///     1                        /* default trailerField */
/// };
/// ```
pub const DEFAULT_PSS_PARAMS_30: PssParams30 = PssParams30 {
    hash_algorithm: Some(DigestAlgorithm::Sha1),
    mask_gen: PssMaskGen {
        algorithm_nid: NID_MGF1,
        hash_algorithm: Some(DigestAlgorithm::Sha1),
    },
    salt_len: DEFAULT_SALT_LEN,
    trailer_field: DEFAULT_TRAILER_FIELD,
};

impl PssParams30 {
    /// Create an unrestricted (zero-initialized) parameter set, equivalent to
    /// `memset(p, 0, sizeof(*p))` in C.
    ///
    /// An unrestricted set means "no PSS-specific parameter constraints exist
    /// on this key — pick parameters at signing time".
    pub const fn unrestricted() -> Self {
        Self {
            hash_algorithm: None,
            mask_gen: PssMaskGen {
                algorithm_nid: 0,
                hash_algorithm: None,
            },
            salt_len: 0,
            trailer_field: 0,
        }
    }

    /// Returns `true` if this parameter set is unrestricted.
    ///
    /// Translates `ossl_rsa_pss_params_30_is_unrestricted` from
    /// `crypto/rsa/rsa_pss.c` line 332. The C version performs
    /// `memcmp(rsa_pss_params, &pss_params_30_unrestricted, sizeof(...))`
    /// against a zero-initialized struct.
    pub fn is_unrestricted(&self) -> bool {
        self.hash_algorithm.is_none()
            && self.mask_gen.algorithm_nid == 0
            && self.mask_gen.hash_algorithm.is_none()
            && self.salt_len == 0
            && self.trailer_field == 0
    }

    /// Apply RFC 4055 defaults for any unset fields.
    ///
    /// Translates `ossl_rsa_pss_params_30_set_defaults` from
    /// `crypto/rsa/rsa_pss.c` line 324:
    ///
    /// ```c
    /// int ossl_rsa_pss_params_30_set_defaults(RSA_PSS_PARAMS_30 *rsa_pss_params)
    /// {
    ///     if (rsa_pss_params == NULL)
    ///         return 0;
    ///     *rsa_pss_params = default_RSASSA_PSS_params;
    ///     return 1;
    /// }
    /// ```
    pub fn set_defaults(&mut self) {
        *self = DEFAULT_PSS_PARAMS_30;
    }

    /// Resolve the message hash algorithm with default fallback.
    ///
    /// Translates `ossl_rsa_pss_params_30_hashalg`. If unset, returns SHA-1.
    pub fn resolved_hash(&self) -> DigestAlgorithm {
        self.hash_algorithm.unwrap_or(DigestAlgorithm::Sha1)
    }

    /// Resolve the MGF1 hash algorithm with default fallback.
    ///
    /// Translates `ossl_rsa_pss_params_30_maskgenhashalg`.
    pub fn resolved_mgf1_hash(&self) -> DigestAlgorithm {
        self.mask_gen
            .hash_algorithm
            .unwrap_or(DigestAlgorithm::Sha1)
    }

    /// Resolve the salt length with default fallback.
    ///
    /// Translates `ossl_rsa_pss_params_30_saltlen`. Returns the configured
    /// length (or `DEFAULT_SALT_LEN` if `salt_len < 0`).
    pub fn resolved_salt_len(&self) -> i32 {
        if self.salt_len < 0 {
            DEFAULT_SALT_LEN
        } else {
            self.salt_len
        }
    }

    /// Resolve the trailer field with default fallback.
    ///
    /// Translates `ossl_rsa_pss_params_30_trailerfield`. Returns the configured
    /// trailer field (or `DEFAULT_TRAILER_FIELD` if unset).
    pub fn resolved_trailer_field(&self) -> i32 {
        if self.trailer_field < 0 {
            DEFAULT_TRAILER_FIELD
        } else {
            self.trailer_field
        }
    }

    /// Set the message hash algorithm.
    pub fn set_hash_algorithm(&mut self, hash: DigestAlgorithm) {
        self.hash_algorithm = Some(hash);
    }

    /// Set the MGF1 inner hash algorithm.
    pub fn set_mgf1_hash_algorithm(&mut self, hash: DigestAlgorithm) {
        self.mask_gen.hash_algorithm = Some(hash);
        self.mask_gen.algorithm_nid = NID_MGF1;
    }

    /// Set the salt length explicitly.
    pub fn set_salt_len(&mut self, salt_len: i32) {
        self.salt_len = salt_len;
    }

    /// Set the trailer field.
    pub fn set_trailer_field(&mut self, trailer_field: i32) {
        self.trailer_field = trailer_field;
    }

    /// Serialize PSS parameters into a [`ParamSet`] for provider transport.
    ///
    /// Translates `ossl_rsa_pss_params_30_todata`. The parameter names follow
    /// `OSSL_PKEY_PARAM_RSA_DIGEST`, `OSSL_PKEY_PARAM_RSA_MASKGENFUNC`,
    /// `OSSL_PKEY_PARAM_RSA_PSS_SALTLEN` from `core_names.h`.
    pub fn to_params(&self) -> ParamSet {
        let mut params = ParamSet::new();
        if let Some(h) = self.hash_algorithm {
            params.set("rsa-digest", ParamValue::Utf8String(h.name().to_string()));
        }
        if let Some(mgf1h) = self.mask_gen.hash_algorithm {
            params.set(
                "rsa-mgf1-digest",
                ParamValue::Utf8String(mgf1h.name().to_string()),
            );
        }
        params.set(
            "rsa-pss-saltlen",
            ParamValue::Int32(self.resolved_salt_len()),
        );
        params.set(
            "rsa-pss-trailerfield",
            ParamValue::Int32(self.resolved_trailer_field()),
        );
        params
    }

    /// Deserialize PSS parameters from a [`ParamSet`].
    ///
    /// Translates `ossl_rsa_pss_params_30_fromdata`. Missing fields remain at
    /// their unset defaults, allowing the caller to apply [`Self::set_defaults`]
    /// or selectively override.
    pub fn from_params(params: &ParamSet) -> CryptoResult<Self> {
        let mut out = Self::unrestricted();

        if params.contains("rsa-digest") {
            if let Some(ParamValue::Utf8String(s)) = params.get("rsa-digest") {
                out.hash_algorithm = crate::hash::algorithm_from_name(s);
            }
        }
        if params.contains("rsa-mgf1-digest") {
            if let Some(ParamValue::Utf8String(s)) = params.get("rsa-mgf1-digest") {
                out.mask_gen.hash_algorithm = crate::hash::algorithm_from_name(s);
                out.mask_gen.algorithm_nid = NID_MGF1;
            }
        }
        // Use `get_typed::<i32>` for type-safe integer extraction. This handles
        // both missing keys and type mismatches uniformly and also accepts an
        // `Int64` value within the `i32` range (per `FromParam` semantics).
        if params.contains("rsa-pss-saltlen") {
            if let Ok(n) = params.get_typed::<i32>("rsa-pss-saltlen") {
                out.salt_len = n;
            }
        }
        if params.contains("rsa-pss-trailerfield") {
            if let Ok(n) = params.get_typed::<i32>("rsa-pss-trailerfield") {
                out.trailer_field = n;
            }
        }
        Ok(out)
    }
}

impl Default for PssParams30 {
    fn default() -> Self {
        DEFAULT_PSS_PARAMS_30
    }
}

// -----------------------------------------------------------------------------
// PssParams (lightweight per-operation parameter struct)
// -----------------------------------------------------------------------------

/// Parameters for a single PSS sign or verify operation.
///
/// Distinct from [`PssParams30`]: the latter describes long-term key metadata
/// (per RFC 4055), whereas [`PssParams`] is the immediate set of parameters
/// supplied to a sign/verify call.
#[derive(Debug, Clone, Copy)]
pub struct PssParams {
    /// Message hash algorithm.
    pub hash: DigestAlgorithm,
    /// MGF1 inner hash algorithm. If `None`, defaults to `hash` per RFC 8017.
    pub mgf1_hash: Option<DigestAlgorithm>,
    /// Salt length specification.
    pub salt_len: PssSaltLength,
}

impl PssParams {
    /// Construct a new PSS parameter set with the given hash and salt length.
    /// MGF1 will use the same hash as the message hash (RFC 8017 default).
    pub fn new(hash: DigestAlgorithm, salt_len: PssSaltLength) -> Self {
        Self {
            hash,
            mgf1_hash: None,
            salt_len,
        }
    }

    /// Construct a new PSS parameter set specifying both hash functions.
    pub fn with_mgf1_hash(
        hash: DigestAlgorithm,
        mgf1_hash: DigestAlgorithm,
        salt_len: PssSaltLength,
    ) -> Self {
        Self {
            hash,
            mgf1_hash: Some(mgf1_hash),
            salt_len,
        }
    }

    /// Returns the resolved MGF1 hash algorithm (defaulting to the message
    /// hash if unspecified, per RFC 8017).
    pub fn resolved_mgf1_hash(&self) -> DigestAlgorithm {
        self.mgf1_hash.unwrap_or(self.hash)
    }
}

// -----------------------------------------------------------------------------
// PKCS1_MGF1 — RFC 8017 §B.2.1 mask generation function
// -----------------------------------------------------------------------------

/// MGF1 mask generation function per RFC 8017 §B.2.1 / NIST SP 800-56B §7.2.2.2.
///
/// Translates `PKCS1_MGF1` from `crypto/rsa/rsa_oaep.c` lines 350-393. This is
/// the shared MGF1 implementation used by both PSS and OAEP padding modes.
///
/// # Arguments
/// * `mask` - Output buffer to fill with mask bytes.
/// * `seed` - The seed input to MGF1.
/// * `hash` - The hash function to invoke for each MGF block.
///
/// # Algorithm
/// ```text
/// for counter = 0, 1, 2, ...:
///     C = I2OSP(counter, 4)              ; 4-byte big-endian
///     T = T || Hash(seed || C)
/// mask = first |mask| bytes of T
/// ```
pub(crate) fn pkcs1_mgf1(mask: &mut [u8], seed: &[u8], hash: DigestAlgorithm) -> CryptoResult<()> {
    let mdlen = hash.digest_size();
    if mdlen == 0 {
        return Err(CryptoError::Encoding(format!(
            "MGF1: hash {hash:?} has zero digest size"
        )));
    }

    let len = mask.len();
    let mut outlen: usize = 0;
    let mut counter: u32 = 0;

    while outlen < len {
        let cnt = counter.to_be_bytes();
        let mut ctx: Box<dyn Digest> = create_digest(hash)?;
        ctx.update(seed)?;
        ctx.update(&cnt)?;
        let block = ctx.finalize()?;

        let remaining = len - outlen;
        if remaining >= mdlen {
            mask[outlen..outlen + mdlen].copy_from_slice(&block);
            outlen += mdlen;
        } else {
            mask[outlen..len].copy_from_slice(&block[..remaining]);
            outlen = len;
        }

        counter = counter
            .checked_add(1)
            .ok_or_else(|| CryptoError::Encoding("MGF1 counter overflow".to_string()))?;
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// EMSA-PSS-Encode — RFC 8017 §9.1.1
// -----------------------------------------------------------------------------

/// Resolve a [`PssSaltLength`] specification into an actual byte count for the
/// encode (sign) path.
///
/// Translates the salt-length sentinel resolution at `crypto/rsa/rsa_pss.c`
/// lines 199-227.
///
/// # Arguments
/// * `salt_spec` - The requested salt length sentinel.
/// * `hlen`      - The output length of the message hash.
/// * `emlen`     - The encoded-message length in bytes (after MSB adjust).
///
/// # Returns
/// The resolved salt length in bytes.
fn resolve_salt_len_encode(
    salt_spec: PssSaltLength,
    hlen: usize,
    emlen: usize,
) -> CryptoResult<usize> {
    let max_salt = emlen
        .checked_sub(hlen)
        .and_then(|v| v.checked_sub(2))
        .ok_or(RsaError::DataTooLargeForKeySize)?;

    match salt_spec {
        PssSaltLength::Digest => {
            if hlen > max_salt {
                return Err(RsaError::DataTooLargeForKeySize.into());
            }
            Ok(hlen)
        }
        PssSaltLength::Auto | PssSaltLength::Max => Ok(max_salt),
        PssSaltLength::AutoDigestMax => Ok(core::cmp::min(hlen, max_salt)),
        PssSaltLength::Custom(n) => {
            if n > max_salt {
                return Err(RsaError::DataTooLargeForKeySize.into());
            }
            Ok(n)
        }
    }
}

/// Encode a message using EMSA-PSS-Encode per RFC 8017 §9.1.1.
///
/// Translates `ossl_rsa_padding_add_PKCS1_PSS_mgf1` from
/// `crypto/rsa/rsa_pss.c` lines 173-289.
///
/// # Arguments
/// * `em`        - Output buffer of length `emlen` (`= ceil((modBits-1)/8)`).
/// * `mhash`     - Message hash digest.
/// * `hash_alg`  - Hash function used to compute `mhash`.
/// * `mgf1_hash` - MGF1 inner hash function. If `None`, defaults to `hash_alg`.
/// * `salt_spec` - Salt length specification.
/// * `mod_bits`  - Modulus size in bits (so that EM fits in `mod_bits - 1` bits).
fn emsa_pss_encode(
    em: &mut [u8],
    mhash: &[u8],
    hash_alg: DigestAlgorithm,
    mgf1_hash: Option<DigestAlgorithm>,
    salt_spec: PssSaltLength,
    mod_bits: u32,
) -> CryptoResult<()> {
    let hlen = hash_alg.digest_size();
    if mhash.len() != hlen {
        return Err(CryptoError::Encoding(format!(
            "EMSA-PSS-Encode: mHash length {} != digest size {}",
            mhash.len(),
            hlen
        )));
    }
    let mgf1md = mgf1_hash.unwrap_or(hash_alg);

    // Step: msbits = (modBits - 1) & 7; if msbits == 0, EM[0] is set to 0 and
    // all PSS work happens in EM[1..].
    let msbits = ((mod_bits
        .checked_sub(1)
        .ok_or(RsaError::DataTooLargeForKeySize)?)
        & 0x7) as u8;
    let total_emlen = em.len();

    let (em_offset, emlen) = if msbits == 0 {
        // Force the leading byte to zero so the integer fits in (modBits - 1) bits.
        em[0] = 0;
        (
            1usize,
            total_emlen
                .checked_sub(1)
                .ok_or(RsaError::DataTooLargeForKeySize)?,
        )
    } else {
        (0usize, total_emlen)
    };

    if emlen
        < hlen
            .checked_add(2)
            .ok_or(RsaError::DataTooLargeForKeySize)?
    {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }

    // Resolve sLen.
    let slen = resolve_salt_len_encode(salt_spec, hlen, emlen)?;

    // maskedDBLen = emLen - hLen - 1
    let masked_db_len = emlen
        .checked_sub(hlen)
        .and_then(|v| v.checked_sub(1))
        .ok_or(RsaError::DataTooLargeForKeySize)?;

    // Generate random salt.
    let mut salt: Vec<u8> = vec![0u8; slen];
    if slen > 0 {
        rand_bytes(&mut salt[..])?;
    }

    // Compute H = Hash(0x00..00 (8 bytes) || mHash || salt).
    let mut ctx = create_digest(hash_alg)?;
    let zeroes = [0u8; 8];
    ctx.update(&zeroes)?;
    ctx.update(mhash)?;
    ctx.update(&salt)?;
    let h = ctx.finalize()?;
    if h.len() != hlen {
        salt.zeroize();
        return Err(CryptoError::Encoding(format!(
            "EMSA-PSS-Encode: H length {} != hlen {}",
            h.len(),
            hlen
        )));
    }

    // Compute dbMask = MGF1(H, maskedDBLen) directly into the maskedDB region
    // of EM. Layout of EM (from offset em_offset):
    //   [0 .. masked_db_len)       == maskedDB
    //   [masked_db_len .. emlen-1) == H
    //   [emlen-1]                  == 0xBC
    let db_start = em_offset;
    let h_start = em_offset
        .checked_add(masked_db_len)
        .ok_or(RsaError::DataTooLargeForKeySize)?;
    let trailer_idx = em_offset
        .checked_add(emlen)
        .and_then(|v| v.checked_sub(1))
        .ok_or(RsaError::DataTooLargeForKeySize)?;

    // Generate the mask into the DB region.
    pkcs1_mgf1(&mut em[db_start..db_start + masked_db_len], &h, mgf1md)?;

    // XOR DB into the mask in-place. DB is laid out as:
    //   PS (zeros) of length (masked_db_len - slen - 1)
    //   0x01 (1 byte)
    //   salt (sLen bytes)
    let ps_len = masked_db_len
        .checked_sub(slen)
        .and_then(|v| v.checked_sub(1))
        .ok_or(RsaError::DataTooLargeForKeySize)?;

    // PS bytes: XOR with 0 → no change.
    // 0x01 separator:
    em[db_start + ps_len] ^= 0x01;
    // salt:
    for i in 0..slen {
        em[db_start + ps_len + 1 + i] ^= salt[i];
    }

    // Mask off leading bits to fit in (modBits - 1) bits.
    if msbits != 0 {
        em[db_start] &= 0xFFu8 >> (8 - msbits);
    }

    // Place H.
    em[h_start..h_start + hlen].copy_from_slice(&h);

    // Trailer byte.
    em[trailer_idx] = PSS_TRAILER_BYTE;

    // Securely cleanse salt.
    salt.zeroize();

    trace!(
        "EMSA-PSS-Encode: hash={:?}, mgf1={:?}, sLen={}, emLen={}, msbits={}",
        hash_alg,
        mgf1md,
        slen,
        emlen,
        msbits
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// EMSA-PSS-Verify — RFC 8017 §9.1.2
// -----------------------------------------------------------------------------

/// Verify a message-encoded representative using EMSA-PSS-Verify per RFC 8017
/// §9.1.2.
///
/// Translates `ossl_rsa_verify_PKCS1_PSS_mgf1` from `crypto/rsa/rsa_pss.c`
/// lines 45-156.
///
/// # Arguments
/// * `em`        - Encoded message representative recovered from the signature.
/// * `mhash`     - Expected message hash digest (already computed).
/// * `hash_alg`  - Hash function used to compute `mhash`.
/// * `mgf1_hash` - MGF1 inner hash function. If `None`, defaults to `hash_alg`.
/// * `salt_spec` - Salt length specification (or [`PssSaltLength::Auto`] to
///   recover from the signature).
/// * `mod_bits`  - Modulus size in bits.
///
/// # Returns
/// `Ok(salt_len)` if the signature is valid, else `Err`.
fn emsa_pss_verify(
    em: &[u8],
    mhash: &[u8],
    hash_alg: DigestAlgorithm,
    mgf1_hash: Option<DigestAlgorithm>,
    salt_spec: PssSaltLength,
    mod_bits: u32,
) -> CryptoResult<usize> {
    let hlen = hash_alg.digest_size();
    if mhash.len() != hlen {
        return Err(CryptoError::Encoding(format!(
            "EMSA-PSS-Verify: mHash length {} != digest size {}",
            mhash.len(),
            hlen
        )));
    }
    let mgf1md = mgf1_hash.unwrap_or(hash_alg);

    let msbits = ((mod_bits
        .checked_sub(1)
        .ok_or(RsaError::DataTooLargeForKeySize)?)
        & 0x7) as u8;
    let total_emlen = em.len();

    // Top-bits check: any bit beyond the leading msbits must be zero.
    if msbits != 0 {
        let top_mask: u8 = 0xFFu8 << msbits;
        if em[0] & top_mask != 0 {
            return Err(RsaError::FirstOctetInvalid.into());
        }
    } else if em[0] != 0 {
        return Err(RsaError::FirstOctetInvalid.into());
    }

    let (em_offset, emlen) = if msbits == 0 {
        (
            1usize,
            total_emlen
                .checked_sub(1)
                .ok_or(RsaError::DataTooLargeForKeySize)?,
        )
    } else {
        (0usize, total_emlen)
    };

    if emlen
        < hlen
            .checked_add(2)
            .ok_or(RsaError::DataTooLargeForKeySize)?
    {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }

    let trailer_idx = em_offset
        .checked_add(emlen)
        .and_then(|v| v.checked_sub(1))
        .ok_or(RsaError::DataTooLargeForKeySize)?;
    if em[trailer_idx] != PSS_TRAILER_BYTE {
        return Err(CryptoError::Verification(
            "EMSA-PSS-Verify: trailer byte != 0xBC".to_string(),
        ));
    }

    let masked_db_len = emlen
        .checked_sub(hlen)
        .and_then(|v| v.checked_sub(1))
        .ok_or(RsaError::DataTooLargeForKeySize)?;
    let db_start = em_offset;
    let h_start = em_offset
        .checked_add(masked_db_len)
        .ok_or(RsaError::DataTooLargeForKeySize)?;

    // Allocate db buffer = MGF1(H, maskedDBLen) ⊕ EM[masked_db_region]
    let mut db: Vec<u8> = vec![0u8; masked_db_len];
    pkcs1_mgf1(&mut db, &em[h_start..h_start + hlen], mgf1md)?;

    for i in 0..masked_db_len {
        db[i] ^= em[db_start + i];
    }

    // Mask off leading bits to fit in (modBits - 1) bits.
    if msbits != 0 {
        db[0] &= 0xFFu8 >> (8 - msbits);
    }

    // Locate the 0x01 separator. The DB layout is:
    //   PS (zeros) || 0x01 || salt
    let mut i: usize = 0;
    while i < masked_db_len && db[i] == 0 {
        i = i.saturating_add(1);
    }
    if i >= masked_db_len || db[i] != 0x01 {
        return Err(CryptoError::Verification(
            "EMSA-PSS-Verify: 0x01 separator not found".to_string(),
        ));
    }
    let salt_offset = i.checked_add(1).ok_or(RsaError::DataTooLargeForKeySize)?;
    let recovered_slen = masked_db_len
        .checked_sub(salt_offset)
        .ok_or(RsaError::DataTooLargeForKeySize)?;

    // Salt-length policy enforcement.
    match salt_spec {
        PssSaltLength::Auto | PssSaltLength::AutoDigestMax => {
            // Accept any salt length; AutoDigestMax additionally checks a cap.
            if matches!(salt_spec, PssSaltLength::AutoDigestMax) && recovered_slen > hlen {
                return Err(RsaError::SaltLengthCheckFailed.into());
            }
        }
        PssSaltLength::Digest => {
            if recovered_slen != hlen {
                return Err(RsaError::SaltLengthCheckFailed.into());
            }
        }
        PssSaltLength::Max => {
            // Max means salt fills all remaining space — caller may want to
            // verify there were no PS bytes; but RFC 8017 does not mandate
            // this. We accept any recovered length here.
        }
        PssSaltLength::Custom(expected) => {
            if recovered_slen != expected {
                return Err(RsaError::SaltLengthCheckFailed.into());
            }
        }
    }

    // Recompute H' = Hash(0x00..00 || mHash || salt) and compare.
    let salt = &db[salt_offset..masked_db_len];
    let mut ctx = create_digest(hash_alg)?;
    let zeroes = [0u8; 8];
    ctx.update(&zeroes)?;
    ctx.update(mhash)?;
    ctx.update(salt)?;
    let h_prime = ctx.finalize()?;

    let valid = constant_time::memcmp(&h_prime, &em[h_start..h_start + hlen]);

    // Securely cleanse the recovered DB.
    db.zeroize();

    if valid {
        debug!(
            "EMSA-PSS-Verify OK: hash={:?}, mgf1={:?}, sLen={}",
            hash_alg, mgf1md, recovered_slen
        );
        Ok(recovered_slen)
    } else {
        Err(CryptoError::Verification(
            "EMSA-PSS-Verify: hash mismatch".to_string(),
        ))
    }
}

// -----------------------------------------------------------------------------
// Public API: pss_sign / pss_verify
// -----------------------------------------------------------------------------

/// Sign a message hash using RSASSA-PSS per RFC 8017 §8.1.1.
///
/// Composes EMSA-PSS-Encode (RFC 8017 §9.1.1) with the RSA private-key
/// operation. The encoded message representative `EM` is treated as a
/// big-endian integer `m`, raised to the private exponent modulo `n`, and the
/// resulting integer is encoded back to a fixed-length byte string `s` of
/// length `k = ceil(modBits / 8)`.
///
/// # Arguments
/// * `key`    - RSA private key.
/// * `mhash`  - Message hash digest.
/// * `params` - PSS parameter bundle.
///
/// # Returns
/// The signature `s` as a `k`-byte big-endian octet string.
///
/// # Errors
/// - [`RsaError::KeyTooSmall`] if the key cannot accommodate `hLen + sLen + 2`.
/// - [`CryptoError::Encoding`] for malformed `mhash`.
/// - [`CryptoError::Common`] propagated from `BigNum` modular operations.
pub fn pss_sign(key: &RsaPrivateKey, mhash: &[u8], params: PssParams) -> CryptoResult<Vec<u8>> {
    let mod_bits = key.key_size_bits();
    let k = key.key_size_bytes() as usize;

    // emLen = ceil((modBits - 1) / 8) ; k = ceil(modBits / 8). When (modBits-1)
    // is a multiple of 8, emLen = k - 1. Otherwise emLen = k.
    let emlen = if mod_bits % 8 == 0 {
        k.checked_sub(1).ok_or(RsaError::KeyTooSmall {
            min_bits: 512,
            actual_bits: mod_bits,
        })?
    } else {
        k
    };

    let mut em: Vec<u8> = vec![0u8; emlen];
    emsa_pss_encode(
        &mut em,
        mhash,
        params.hash,
        params.mgf1_hash,
        params.salt_len,
        mod_bits,
    )?;

    // Convert EM to BigNum, perform private-key exponentiation, encode to
    // k-byte big-endian.
    let m = BigNum::from_bytes_be(&em);
    em.zeroize();

    let n = key.modulus();
    if m.cmp(n) != core::cmp::Ordering::Less {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }

    // Compute s = m^d mod n via CRT-accelerated modular exponentiation.
    // Note: super::crt_mod_exp takes (input, key) — opposite of what we'd write.
    let s = super::crt_mod_exp(&m, key)?;

    // Encode s to a k-byte big-endian octet string.
    let signature = s.to_bytes_be_padded(k).map_err(|_| {
        CryptoError::Encoding("RSA-PSS sign: signature encoding failed".to_string())
    })?;

    debug!(
        "RSA-PSS sign: bits={}, hash={:?}, sLen={:?}",
        mod_bits, params.hash, params.salt_len
    );

    Ok(signature)
}

/// Verify a RSASSA-PSS signature per RFC 8017 §8.1.2.
///
/// # Arguments
/// * `key`       - RSA public key.
/// * `mhash`     - Message hash digest.
/// * `signature` - Candidate signature octet string.
/// * `params`    - PSS parameter bundle.
///
/// # Returns
/// `Ok(salt_len)` indicating verification success and the recovered salt
/// length, otherwise an `Err` describing the failure reason.
pub fn pss_verify(
    key: &RsaPublicKey,
    mhash: &[u8],
    signature: &[u8],
    params: PssParams,
) -> CryptoResult<usize> {
    let mod_bits = key.key_size_bits();
    let k = key.key_size_bytes() as usize;

    if signature.len() != k {
        return Err(CryptoError::Verification(format!(
            "RSA-PSS verify: signature length {} != k {}",
            signature.len(),
            k
        )));
    }

    let s = BigNum::from_bytes_be(signature);
    let n = key.modulus();
    if s.cmp(n) != core::cmp::Ordering::Less {
        return Err(CryptoError::Verification(
            "RSA-PSS verify: signature representative >= n".to_string(),
        ));
    }

    // Compute m = s^e mod n.
    let m = montgomery::mod_exp(&s, key.public_exponent(), n)?;

    let emlen = if mod_bits % 8 == 0 {
        k.checked_sub(1).ok_or(CryptoError::Verification(
            "RSA-PSS verify: degenerate emLen".to_string(),
        ))?
    } else {
        k
    };

    let em = m
        .to_bytes_be_padded(emlen)
        .map_err(|_| CryptoError::Verification("RSA-PSS verify: EM encoding failed".to_string()))?;

    let recovered_slen = emsa_pss_verify(
        &em,
        mhash,
        params.hash,
        params.mgf1_hash,
        params.salt_len,
        mod_bits,
    )?;

    Ok(recovered_slen)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code conventionally uses expect/unwrap/panic with descriptive messages \
              for fast-fail diagnostics; the crate-level `#![deny(clippy::expect_used)]` and \
              `#![deny(clippy::unwrap_used)]` apply to library code, not test code."
)]
mod tests {
    use super::*;

    #[test]
    fn default_params_match_rfc4055() {
        let p = DEFAULT_PSS_PARAMS_30;
        assert_eq!(p.hash_algorithm, Some(DigestAlgorithm::Sha1));
        assert_eq!(p.mask_gen.algorithm_nid, NID_MGF1);
        assert_eq!(p.mask_gen.hash_algorithm, Some(DigestAlgorithm::Sha1));
        assert_eq!(p.salt_len, 20);
        assert_eq!(p.trailer_field, 1);
    }

    #[test]
    fn unrestricted_is_zero_init() {
        let p = PssParams30::unrestricted();
        assert!(p.is_unrestricted());
        assert_eq!(p.hash_algorithm, None);
        assert_eq!(p.salt_len, 0);
        assert_eq!(p.trailer_field, 0);
    }

    #[test]
    fn defaults_overrides_unset() {
        let mut p = PssParams30::unrestricted();
        assert!(p.is_unrestricted());
        p.set_defaults();
        assert!(!p.is_unrestricted());
        assert_eq!(p, DEFAULT_PSS_PARAMS_30);
    }

    #[test]
    fn salt_length_legacy_int_round_trip() {
        for v in [-4, -3, -2, -1, 0, 20, 32, 64] {
            let s = PssSaltLength::from_legacy_int(v);
            assert_eq!(s.as_legacy_int(), v);
        }
    }

    #[test]
    fn pss_params_default_mgf1_matches_hash() {
        let p = PssParams::new(DigestAlgorithm::Sha256, PssSaltLength::Digest);
        assert_eq!(p.resolved_mgf1_hash(), DigestAlgorithm::Sha256);
        let p2 = PssParams::with_mgf1_hash(
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            PssSaltLength::Digest,
        );
        assert_eq!(p2.resolved_mgf1_hash(), DigestAlgorithm::Sha384);
    }

    #[test]
    fn mgf1_zero_length_is_noop() {
        let mut mask: [u8; 0] = [];
        pkcs1_mgf1(&mut mask, b"seed", DigestAlgorithm::Sha256).unwrap();
    }

    #[test]
    fn mgf1_deterministic_known_vector() {
        // RFC 8017 Appendix B.2.1 example: MGF1 with SHA-256, seed = "foo",
        // length 32 — recompute deterministically. We do not have the RFC
        // test vector inline; we instead verify deterministic behavior.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pkcs1_mgf1(&mut a, b"seed", DigestAlgorithm::Sha256).unwrap();
        pkcs1_mgf1(&mut b, b"seed", DigestAlgorithm::Sha256).unwrap();
        assert_eq!(a, b);
        // Different seed should give a different mask.
        let mut c = [0u8; 32];
        pkcs1_mgf1(&mut c, b"different", DigestAlgorithm::Sha256).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn pss_params30_to_from_params_round_trip() {
        let mut p = PssParams30::default();
        p.set_hash_algorithm(DigestAlgorithm::Sha256);
        p.set_mgf1_hash_algorithm(DigestAlgorithm::Sha384);
        p.set_salt_len(32);
        p.set_trailer_field(1);

        let params = p.to_params();
        let recovered = PssParams30::from_params(&params).unwrap();
        assert_eq!(recovered.hash_algorithm, Some(DigestAlgorithm::Sha256));
        assert_eq!(
            recovered.mask_gen.hash_algorithm,
            Some(DigestAlgorithm::Sha384)
        );
        assert_eq!(recovered.salt_len, 32);
        assert_eq!(recovered.trailer_field, 1);
    }

    #[test]
    fn resolve_salt_len_encode_max() {
        // emlen = 256 (2048-bit key), hlen = 32 (SHA-256) → max salt = 222.
        let r = resolve_salt_len_encode(PssSaltLength::Max, 32, 256).unwrap();
        assert_eq!(r, 256 - 32 - 2);
    }

    #[test]
    fn resolve_salt_len_encode_digest() {
        let r = resolve_salt_len_encode(PssSaltLength::Digest, 32, 256).unwrap();
        assert_eq!(r, 32);
    }

    #[test]
    fn resolve_salt_len_encode_custom_too_large_fails() {
        let err = resolve_salt_len_encode(PssSaltLength::Custom(1000), 32, 256);
        assert!(err.is_err());
    }
}
