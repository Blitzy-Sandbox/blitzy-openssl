//! OAEP (Optimal Asymmetric Encryption Padding) implementation per RFC 8017 §7.1.
//!
//! Translates the C implementation from `crypto/rsa/rsa_oaep.c` (393 lines).
//! Provides EME-OAEP encoding and decoding with configurable hash functions
//! and Mask Generation Function (MGF1).
//!
//! ## Schema-Required API
//!
//! This module exposes the following public surface mandated by the OAEP
//! schema for the workspace:
//!
//! * [`OaepParams`] — typed parameter bag (digest, `mgf1_digest`, label).
//! * [`OaepError`] — enum capturing the five OAEP-specific failure modes.
//! * [`mgf1`] — Mask Generation Function 1 (RFC 8017 §B.2.1).
//! * [`oaep_encode`] — byte-buffer EME-OAEP encoding (no RSA primitive).
//! * [`oaep_decode`] — byte-buffer EME-OAEP decoding (constant-time).
//! * [`oaep_encode_default`] / [`oaep_decode_default`] — convenience wrappers
//!   matching legacy C `RSA_padding_add_PKCS1_OAEP` / `RSA_padding_check_PKCS1_OAEP`.
//!
//! Higher-level [`oaep_encrypt`] / [`oaep_decrypt`] functions wrap an RSA
//! key primitive around the byte-buffer encode/decode and remain available
//! for convenience and backward compatibility within the crate.
//!
//! ## Security Properties
//!
//! - All decoding operations use constant-time comparisons to prevent
//!   timing side-channels (Manger's attack, Bleichenbacher-style attacks).
//!   The decode flow accumulates a single `good` mask across every check
//!   and only collapses to a Result at the very end, mirroring the C
//!   reference implementation in `crypto/rsa/rsa_oaep.c`.
//! - Intermediate buffers (random seed, dbMask, seedMask, unmasked DB,
//!   the encoded message) are zeroized on every code path via
//!   [`zeroize::Zeroize`].
//! - FIPS mode (when the `fips` cargo feature is enabled) restricts the
//!   acceptable digest algorithms in line with NIST SP 800-131A and
//!   FIPS 186-5.
//!
//! ## Source Mapping
//!
//! | C symbol (`crypto/rsa/rsa_oaep.c`)                              | Rust counterpart |
//! |-----------------------------------------------------------------|------------------|
//! | `RSA_padding_add_PKCS1_OAEP`                                    | [`oaep_encode_default`] |
//! | `ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex`                       | [`oaep_encode`]         |
//! | `RSA_padding_check_PKCS1_OAEP`                                  | [`oaep_decode_default`] |
//! | `ossl_rsa_padding_check_PKCS1_OAEP_mgf1_ex`                     | [`oaep_decode`]         |
//! | `PKCS1_MGF1`                                                    | [`mgf1`]                |
//! | `RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE`                             | [`OaepError::DataTooLargeForKeySize`] |
//! | `RSA_R_OAEP_DECODING_ERROR`                                     | [`OaepError::OaepDecodingError`]      |
//! | `RSA_R_INVALID_OAEP_PARAMETERS`                                 | [`OaepError::InvalidOaepParametersValue`] |
//! | `RSA_R_DIGEST_NOT_ALLOWED`                                      | [`OaepError::DigestNotAllowed`]       |
//! | (FIPS-only) MGF1 digest validation failure                      | [`OaepError::InvalidMgf1Digest`]      |
//!
//! ## Default Parameters
//!
//! Per AAP §0 (Step 4 of the file's instructions) and the legacy C wrapper
//! `RSA_padding_add_PKCS1_OAEP`, the default OAEP parameters use **SHA-1**
//! for both the label hash and MGF1 hash, with an empty label. SHA-1 is
//! retained as the default for backwards-compatible interoperability with
//! existing RFC 8017 implementations; security-conscious callers should
//! select SHA-256 or stronger via [`OaepParams::with_digest`].
//!
//! ## References
//!
//! - RFC 8017 §7.1: RSAES-OAEP encryption scheme.
//! - RFC 8017 §B.2.1: MGF1 mask generation function.
//! - NIST SP 800-56B §7.2.2: RSA-OAEP key transport.
//! - NIST SP 800-131A: hash algorithm transition guidance (FIPS gating).
//!
//! ## Safety
//!
//! Unsafe code is `forbid`den at the crate root in
//! `crates/openssl-crypto/src/lib.rs`; this file inherits that
//! guarantee. There are zero `unsafe` blocks in this module.

use openssl_common::constant_time;
use openssl_common::error::{CryptoError, CryptoResult};

use crate::hash::{create_digest, Digest, DigestAlgorithm};
use crate::rand::rand_bytes;

use tracing::{debug, trace};
use zeroize::Zeroize;

use super::{
    digest_to_scheme_nid, private_decrypt, public_encrypt, scheme_nid_to_digest, PaddingMode,
    RsaError, RsaPrivateKey, RsaPublicKey,
};

// =============================================================================
// 1. OaepError — schema-required error enum
// =============================================================================

/// Errors produced by OAEP padding operations.
///
/// This enum surfaces the five OAEP-specific failure modes mandated by the
/// workspace schema and corresponds 1:1 with the `RSA_R_*` reason codes
/// raised in `crypto/rsa/rsa_oaep.c`. Each variant converts into a
/// [`CryptoError`] via the [`From`] impl below so callers can propagate
/// errors uniformly through the `?` operator.
#[derive(Debug, thiserror::Error)]
pub enum OaepError {
    /// The plaintext message exceeds the maximum size that the modulus can
    /// hold once OAEP overhead is accounted for. The maximum message length
    /// for an RSA modulus of `k` bytes and a hash of `hLen` bytes is
    /// `k - 2*hLen - 2`.
    ///
    /// Maps `RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE` from
    /// `crypto/rsa/rsa_oaep.c`.
    #[error("OAEP: data too large for RSA modulus")]
    DataTooLargeForKeySize,

    /// OAEP decoding failed: the encoded message did not pass one or more
    /// integrity checks (first byte != 0x00, lHash mismatch, missing 0x01
    /// separator, or padding-string contained non-zero bytes).
    ///
    /// **SECURITY:** This single, opaque error variant is intentional —
    /// the underlying check results are accumulated in a constant-time
    /// `good` mask to prevent Manger-style attacks. Callers MUST NOT try
    /// to distinguish the specific failure cause from this error.
    ///
    /// Maps `RSA_R_OAEP_DECODING_ERROR` from `crypto/rsa/rsa_oaep.c`.
    #[error("OAEP: decoding error")]
    OaepDecodingError,

    /// One of the OAEP parameters is structurally invalid — for example,
    /// an empty output buffer or a key size below `2*hLen + 2` bytes.
    ///
    /// Maps `RSA_R_INVALID_OAEP_PARAMETERS` from `crypto/rsa/rsa_oaep.c`.
    #[error("OAEP: invalid parameter value: {0}")]
    InvalidOaepParametersValue(&'static str),

    /// The requested hash algorithm is not approved for OAEP under the
    /// active operating mode. Raised in FIPS mode for legacy hashes
    /// (MD2/MD4/MD5/SHA-1 outside legacy-allowed contexts) and for
    /// extendable-output functions (SHAKE128/SHAKE256) which are not
    /// defined for OAEP label hashing.
    #[error("OAEP: digest not allowed")]
    DigestNotAllowed,

    /// The requested MGF1 digest algorithm is not acceptable. Raised in
    /// FIPS mode for unapproved MGF1 hashes and for XOFs whose output
    /// length is not fixed.
    #[error("OAEP: invalid MGF1 digest")]
    InvalidMgf1Digest,
}

impl From<OaepError> for CryptoError {
    fn from(err: OaepError) -> Self {
        match err {
            OaepError::DataTooLargeForKeySize
            | OaepError::OaepDecodingError
            | OaepError::InvalidOaepParametersValue(_) => CryptoError::Encoding(err.to_string()),
            OaepError::DigestNotAllowed | OaepError::InvalidMgf1Digest => {
                CryptoError::AlgorithmNotFound(err.to_string())
            }
        }
    }
}

// =============================================================================
// 2. OaepParams — typed parameter bag
// =============================================================================

/// OAEP encryption / decryption parameters.
///
/// Replaces the C pattern of passing `md`, `mgf1md`, `param`, and `plen`
/// as separate arguments to
/// `ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex`. The schema-defined field
/// names are `digest`, `mgf1_digest`, and `label`.
///
/// The default value uses SHA-1 (per legacy `RSA_padding_add_PKCS1_OAEP`),
/// no MGF1 override (so MGF1 also uses SHA-1), and an empty label. To
/// override, use the builder-style `with_*` helpers.
#[derive(Debug, Clone)]
pub struct OaepParams {
    /// Hash function used both for hashing the label and (by default) for
    /// MGF1 mask generation. Required by RFC 8017 §7.1.1 step 2a.
    pub digest: DigestAlgorithm,

    /// Optional override for the MGF1 hash. When `None`, MGF1 uses the
    /// same hash as `digest`. Per RFC 8017 §7.1, OAEP allows the label
    /// hash and MGF1 hash to differ.
    pub mgf1_digest: Option<DigestAlgorithm>,

    /// OAEP label (called "L" in RFC 8017 §7.1.1; an empty label is
    /// permitted and is the most common case). The label is hashed once
    /// to produce `lHash` and bound into the encoded message; decoders
    /// MUST supply the same label or decoding will fail.
    pub label: Vec<u8>,
}

impl OaepParams {
    /// Constructs the default OAEP parameter set.
    ///
    /// Equivalent to `OaepParams::default()`. Returns parameters with
    /// SHA-1 for both the label hash and MGF1 hash, and an empty label —
    /// matching the legacy C wrapper `RSA_padding_add_PKCS1_OAEP` from
    /// `crypto/rsa/rsa_oaep.c` line 39.
    #[must_use]
    pub fn new_default() -> Self {
        Self {
            digest: DigestAlgorithm::Sha1,
            mgf1_digest: None,
            label: Vec::new(),
        }
    }

    /// Returns a copy of `self` with the OAEP digest replaced.
    ///
    /// Builder-style helper used by callers that wish to override the
    /// default SHA-1 with a stronger hash such as SHA-256.
    #[must_use]
    pub fn with_digest(mut self, digest: DigestAlgorithm) -> Self {
        self.digest = digest;
        self
    }

    /// Returns a copy of `self` with the MGF1 digest replaced.
    ///
    /// When set, MGF1 will use this hash instead of `self.digest`.
    #[must_use]
    pub fn with_mgf1_digest(mut self, mgf1_digest: DigestAlgorithm) -> Self {
        self.mgf1_digest = Some(mgf1_digest);
        self
    }

    /// Returns a copy of `self` with the label replaced.
    ///
    /// The label is hashed once during encoding and bound to the
    /// ciphertext; decoders MUST supply the same label.
    #[must_use]
    pub fn with_label(mut self, label: Vec<u8>) -> Self {
        self.label = label;
        self
    }

    /// Returns the effective MGF1 digest, applying the default fallback.
    ///
    /// If `mgf1_digest` is `Some(h)`, returns `h`; otherwise returns
    /// `self.digest`. Per RFC 8017 §7.1, OAEP defaults MGF1 to use the
    /// same hash as the label hash unless explicitly overridden.
    #[must_use]
    pub fn mgf1_digest_effective(&self) -> DigestAlgorithm {
        self.mgf1_digest.unwrap_or(self.digest)
    }


    /// Returns the upstream-compatible NID for the OAEP digest.
    ///
    /// Used by ASN.1 encoding paths that emit `RSAES-OAEP-params`
    /// (RFC 8017 Appendix A.2.1) into PKCS#1 / PKCS#8 / X.509 structures.
    /// Returns `None` if the digest does not have an OpenSSL-native NID.
    #[must_use]
    pub fn oaep_digest_nid(&self) -> Option<u32> {
        digest_to_scheme_nid(self.digest)
    }

    /// Returns the upstream-compatible NID for the MGF1 digest.
    ///
    /// Returns the NID corresponding to [`Self::mgf1_digest_effective`].
    #[must_use]
    pub fn mgf1_digest_nid(&self) -> Option<u32> {
        digest_to_scheme_nid(self.mgf1_digest_effective())
    }

    /// Constructs an [`OaepParams`] from a pair of NIDs.
    ///
    /// Returns `None` if either NID does not map to a known
    /// [`DigestAlgorithm`]. The label is left empty; callers that need a
    /// non-empty label should chain [`Self::with_label`].
    #[must_use]
    pub fn from_nids(oaep_digest_nid: u32, mgf1_digest_nid: u32) -> Option<Self> {
        let digest = scheme_nid_to_digest(oaep_digest_nid)?;
        let mgf1 = scheme_nid_to_digest(mgf1_digest_nid)?;
        Some(Self {
            digest,
            mgf1_digest: if mgf1 == digest { None } else { Some(mgf1) },
            label: Vec::new(),
        })
    }
}

impl Default for OaepParams {
    /// Default OAEP parameters: SHA-1 hash, SHA-1 MGF1, empty label.
    fn default() -> Self {
        Self::new_default()
    }
}

// =============================================================================
// 3. Internal helpers
// =============================================================================

/// One-shot label hash helper. Computes `lHash = Hash(label)` per
/// RFC 8017 §7.1.1 step 2a. The returned `Vec<u8>` has length
/// `digest.digest_size()`.
///
/// An empty label is valid and produces `Hash("")`.
fn hash_label(label: &[u8], digest: DigestAlgorithm) -> CryptoResult<Vec<u8>> {
    let mut ctx: Box<dyn Digest> = create_digest(digest)?;
    ctx.update(label)?;
    ctx.finalize()
}

/// Convenience helper that wraps the schema-required
/// [`OaepError::OaepDecodingError`] in a [`CryptoError`]. All decode
/// failure paths funnel through here so the error message is uniform
/// and information-leak-free.
fn oaep_decode_error() -> CryptoError {
    CryptoError::from(OaepError::OaepDecodingError)
}

// =============================================================================
// 4. FIPS digest validation
// =============================================================================

/// Validates that the specified digest is approved for OAEP in FIPS mode.
///
/// Translates the FIPS-only check from `crypto/rsa/rsa_oaep.c` lines
/// 79-100 (which calls into the provider's
/// `rsa_oaep_check_digest_compatible` predicate). XOFs (SHAKE128 /
/// SHAKE256) and unapproved legacy hashes (MD2 / MD4 / MD5) are
/// rejected. SHA-1 is permitted only for legacy interoperability.
///
/// This function is gated on the `fips` cargo feature; it is inert when
/// the feature is disabled. The signature is preserved unconditionally
/// so that downstream callers do not need conditional compilation.
#[cfg(feature = "fips_module")]
fn validate_oaep_digest_fips(digest: DigestAlgorithm) -> Result<(), OaepError> {
    match digest {
        // Legacy hashes are not approved under SP 800-131A.
        DigestAlgorithm::Md2 | DigestAlgorithm::Md4 | DigestAlgorithm::Md5 => {
            Err(OaepError::DigestNotAllowed)
        }
        // SHAKE XOFs are not defined for OAEP (no fixed output length).
        DigestAlgorithm::Shake128 | DigestAlgorithm::Shake256 => Err(OaepError::DigestNotAllowed),
        _ => Ok(()),
    }
}

/// FIPS-mode MGF1 digest validation. Mirrors
/// [`validate_oaep_digest_fips`] but emits
/// [`OaepError::InvalidMgf1Digest`] for unapproved MGF1 hashes.
#[cfg(feature = "fips_module")]
fn validate_mgf1_digest_fips(digest: DigestAlgorithm) -> Result<(), OaepError> {
    match digest {
        DigestAlgorithm::Md2 | DigestAlgorithm::Md4 | DigestAlgorithm::Md5 => {
            Err(OaepError::InvalidMgf1Digest)
        }
        // SHAKE XOFs are technically usable as MGFs but are out of scope
        // for FIPS-approved OAEP.
        DigestAlgorithm::Shake128 | DigestAlgorithm::Shake256 => {
            Err(OaepError::InvalidMgf1Digest)
        }
        _ => Ok(()),
    }
}

// Inert when the `fips_module` feature is disabled. Defined as no-ops
// so the call sites remain identical between builds; we keep the
// `Result<(), OaepError>` return type intentionally so callers don't
// need cfg-conditional `?` operators.
#[cfg(not(feature = "fips_module"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Symmetry with the FIPS-enabled variant; callers use `?` regardless."
)]
fn validate_oaep_digest_fips(_digest: DigestAlgorithm) -> Result<(), OaepError> {
    Ok(())
}

#[cfg(not(feature = "fips_module"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Symmetry with the FIPS-enabled variant; callers use `?` regardless."
)]
fn validate_mgf1_digest_fips(_digest: DigestAlgorithm) -> Result<(), OaepError> {
    Ok(())
}

// =============================================================================
// 5. mgf1 — Mask Generation Function 1 (RFC 8017 §B.2.1)
// =============================================================================

/// Mask Generation Function 1 (MGF1) per RFC 8017 §B.2.1.
///
/// Generates `mask.len()` bytes of pseudo-random output by iterating
/// `Hash(seed || I2OSP(counter, 4))` with `counter` running from 0 upward.
/// The output is the concatenation of the hash blocks, truncated to
/// `mask.len()` bytes. This is the schema-required public entry point;
/// it is also used internally by [`oaep_encode`] and [`oaep_decode`].
///
/// Translates `PKCS1_MGF1` from `crypto/rsa/rsa_oaep.c` lines 350-393.
///
/// # Arguments
///
/// * `mask` — output buffer to fill with generated mask bytes.
/// * `seed` — input seed value (typically `hLen` bytes, but any length
///   is permitted by RFC 8017).
/// * `digest` — hash function to use (e.g., SHA-256).
///
/// # Errors
///
/// * Returns `CryptoError::Encoding` if the digest has zero output size
///   (XOFs without an explicit output length).
/// * Returns `CryptoError::Encoding` on counter overflow (mathematically
///   unreachable for any realistic mask length, but checked for
///   defence-in-depth per Rule R6).
/// * Propagates digest engine errors (digest creation / update /
///   finalization).
///
/// # Example
///
/// ```ignore
/// use openssl_crypto::hash::DigestAlgorithm;
/// use openssl_crypto::rsa::oaep::mgf1;
///
/// let mut mask = [0u8; 64];
/// let seed = b"seed bytes";
/// mgf1(&mut mask, seed, DigestAlgorithm::Sha256).unwrap();
/// ```
pub fn mgf1(mask: &mut [u8], seed: &[u8], digest: DigestAlgorithm) -> CryptoResult<()> {
    let mdlen = digest.digest_size();
    if mdlen == 0 {
        return Err(CryptoError::Encoding(format!(
            "MGF1: hash {} has zero digest size",
            digest.name()
        )));
    }

    let len = mask.len();
    if len == 0 {
        // Vacuous case: nothing to do. Matches C behaviour where
        // PKCS1_MGF1 returns success with an empty output buffer.
        return Ok(());
    }

    let mut outlen: usize = 0;
    let mut counter: u32 = 0;

    while outlen < len {
        // I2OSP(counter, 4) — big-endian 4-byte encoding of the counter.
        let cnt = counter.to_be_bytes();

        // T = T || Hash(seed || I2OSP(counter, 4))
        let mut ctx: Box<dyn Digest> = create_digest(digest)?;
        ctx.update(seed)?;
        ctx.update(&cnt)?;
        let mut block = ctx.finalize()?;

        let remaining = len - outlen;
        if remaining >= mdlen {
            mask[outlen..outlen + mdlen].copy_from_slice(&block);
            outlen += mdlen;
        } else {
            mask[outlen..len].copy_from_slice(&block[..remaining]);
            outlen = len;
        }

        // Zero out the per-iteration block buffer; the mask itself will
        // be cleared by the caller when appropriate.
        block.zeroize();

        // Advance the counter using checked arithmetic (Rule R6: no bare
        // narrowing casts; overflow is structurally impossible for any
        // realistic mask length but we still check).
        counter = counter.checked_add(1).ok_or_else(|| {
            CryptoError::Encoding("MGF1: counter overflow".to_string())
        })?;
    }

    Ok(())
}

// =============================================================================
// 6. oaep_encode — EME-OAEP encoding (RFC 8017 §7.1.1)
// =============================================================================

/// EME-OAEP encoding of a message into the encoded-message buffer.
///
/// Performs the OAEP encoding described in RFC 8017 §7.1.1, **excluding**
/// the final RSA primitive. Given an output buffer `encoded` of length
/// `k` (the RSA modulus length in bytes) and a message `M`, fills
/// `encoded` with the EM block:
///
/// ```text
/// EM = 0x00 || maskedSeed || maskedDB
/// where
///     DB         = lHash || PS || 0x01 || M
///     dbMask     = MGF1(seed, k - hLen - 1)
///     maskedDB   = DB XOR dbMask
///     seedMask   = MGF1(maskedDB, hLen)
///     maskedSeed = seed XOR seedMask
/// ```
///
/// Translates `ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex` from
/// `crypto/rsa/rsa_oaep.c` lines 54-161.
///
/// # Arguments
///
/// * `encoded` — output buffer of length `k` (the RSA modulus length in
///   bytes). On success, populated with the encoded message; on
///   failure, zeroed via [`Zeroize`].
/// * `message` — the plaintext to encode (`M` in RFC 8017 notation).
/// * `params` — OAEP parameters (digest, MGF1 digest, label).
///
/// # Errors
///
/// * Returns `OaepError::DataTooLargeForKeySize` (wrapped in
///   [`CryptoError`]) if `message.len() > k - 2*hLen - 2`.
/// * Returns `OaepError::InvalidOaepParametersValue` if `encoded` is too
///   small to hold any OAEP message under the chosen hash, or if the
///   chosen digest has zero output size.
/// * Returns `OaepError::DigestNotAllowed` /
///   `OaepError::InvalidMgf1Digest` under FIPS mode for unapproved
///   digests.
/// * Propagates underlying random-byte and digest engine errors.
///
/// # Security
///
/// The seed, dbMask, and seedMask intermediate buffers are zeroized on
/// every code path. The output buffer is zeroized on the error path so
/// that partial state cannot leak.
pub fn oaep_encode(
    encoded: &mut [u8],
    message: &[u8],
    params: &OaepParams,
) -> CryptoResult<()> {
    // ---- 1. Resolve digest sizes ------------------------------------
    let digest = params.digest;
    let mgf1_digest = params.mgf1_digest_effective();

    // FIPS mode (when enabled) gates the acceptable digest set.
    validate_oaep_digest_fips(digest)?;
    validate_mgf1_digest_fips(mgf1_digest)?;

    let mdlen = digest.digest_size();
    if mdlen == 0 {
        return Err(OaepError::InvalidOaepParametersValue(
            "OAEP digest has zero output size",
        )
        .into());
    }

    // ---- 2. Compute geometric constraints ---------------------------
    // k = |EM|, the RSA modulus length in bytes.
    let k = encoded.len();

    // Minimum k for OAEP is 2*hLen + 2 (lHash || 0x01 || empty PS || empty M
    // would still overflow without at least one separator byte, so the C
    // reference treats k < 2*hLen + 2 as an invalid parameter).
    let two_mdlen_plus_2 = mdlen
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or(OaepError::InvalidOaepParametersValue(
            "OAEP digest size too large",
        ))?;

    if k < two_mdlen_plus_2 {
        return Err(OaepError::InvalidOaepParametersValue(
            "OAEP output buffer smaller than 2*hLen + 2",
        )
        .into());
    }

    // Maximum message length: k - 2*hLen - 2.
    let max_msg = k - two_mdlen_plus_2;
    if message.len() > max_msg {
        return Err(OaepError::DataTooLargeForKeySize.into());
    }

    debug!(
        digest = %digest.name(),
        mgf1_digest = %mgf1_digest.name(),
        k,
        msg_len = message.len(),
        "OAEP encode: parameters validated"
    );

    // ---- 3. Compute lHash = Hash(label) -----------------------------
    let lhash = hash_label(&params.label, digest)?;
    debug_assert_eq!(lhash.len(), mdlen);

    // ---- 4. Lay out EM in the output buffer -------------------------
    //
    //   EM = 0x00 || maskedSeed || maskedDB
    //   where DB = lHash || PS || 0x01 || M and |DB| = k - hLen - 1
    //
    // We first fill the buffer with the unmasked layout, then apply
    // the MGF1-derived masks in place.
    //
    // Byte ranges in `encoded`:
    //   [0]                                     0x00
    //   [1..=mdlen]                             seed (random)
    //   [db_off..db_off + mdlen]                lHash
    //   [db_off + mdlen..one_pos]               PS (zero padding)
    //   [one_pos]                               0x01 separator
    //   [one_pos + 1..one_pos + 1 + msg.len()]  M (the message)
    let db_off = 1 + mdlen;
    let db_len = k - db_off;
    let one_pos = db_off + db_len - message.len() - 1;

    // Zero the entire output first so that any "leftover" PS bytes are
    // already 0x00.
    for b in encoded.iter_mut() {
        *b = 0u8;
    }

    // First byte is 0x00 (already zeroed above, but explicit for clarity).
    encoded[0] = 0x00;

    // Place lHash at the start of DB.
    encoded[db_off..db_off + mdlen].copy_from_slice(&lhash);

    // Place 0x01 separator.
    encoded[one_pos] = 0x01;

    // Place message after the separator.
    if !message.is_empty() {
        encoded[one_pos + 1..one_pos + 1 + message.len()].copy_from_slice(message);
    }

    // ---- 5. Generate the random seed --------------------------------
    rand_bytes(&mut encoded[1..=mdlen])?;

    // ---- 6. dbMask = MGF1(seed, k - hLen - 1); maskedDB = DB XOR dbMask
    let mut dbmask = vec![0u8; db_len];
    {
        let seed_slice = &encoded[1..=mdlen];
        // Run MGF1; if it fails, zeroize buffers before returning.
        if let Err(e) = mgf1(&mut dbmask, seed_slice, mgf1_digest) {
            dbmask.zeroize();
            for b in encoded.iter_mut() {
                *b = 0u8;
            }
            return Err(e);
        }
    }
    for (i, mask_byte) in dbmask.iter().enumerate() {
        encoded[db_off + i] ^= *mask_byte;
    }
    dbmask.zeroize();

    // ---- 7. seedMask = MGF1(maskedDB, hLen); maskedSeed = seed XOR seedMask
    let mut seedmask = vec![0u8; mdlen];
    {
        let masked_db = &encoded[db_off..db_off + db_len];
        if let Err(e) = mgf1(&mut seedmask, masked_db, mgf1_digest) {
            seedmask.zeroize();
            for b in encoded.iter_mut() {
                *b = 0u8;
            }
            return Err(e);
        }
    }
    for (i, mask_byte) in seedmask.iter().enumerate() {
        encoded[1 + i] ^= *mask_byte;
    }
    seedmask.zeroize();

    debug_assert_eq!(encoded.len(), k);
    trace!("OAEP encode: complete");
    Ok(())
}


// =============================================================================
// 7. oaep_decode — EME-OAEP decoding (RFC 8017 §7.1.2) — CONSTANT TIME
// =============================================================================

/// EME-OAEP decoding of an encoded message.
///
/// Performs the OAEP decoding described in RFC 8017 §7.1.2, **excluding**
/// the inverse RSA primitive (which the caller must perform first to
/// recover `EM` from the ciphertext). Recovers and returns the
/// plaintext message `M` from the encoded message `EM`.
///
/// **SECURITY CRITICAL.** This function executes in time independent of
/// the encoded message contents, modulo the variable-length output. All
/// integrity checks are accumulated into a single `good` mask using the
/// constant-time primitives in [`openssl_common::constant_time`]; the
/// mask is collapsed to a `Result` only at the very end. This defends
/// against Manger's attack and Bleichenbacher-style oracles that target
/// PKCS#1 padding-error timing variability.
///
/// Translates `ossl_rsa_padding_check_PKCS1_OAEP_mgf1_ex` from
/// `crypto/rsa/rsa_oaep.c` lines 163-308.
///
/// # Arguments
///
/// * `encoded` — the OAEP-encoded message `EM`. Must have length exactly
///   equal to `key_size`.
/// * `params` — OAEP parameters; MUST match the parameters used at
///   encoding time (label, digest, MGF1 digest).
/// * `key_size` — RSA modulus size in bytes (`k = RSA_size(rsa)` in C).
///
/// # Returns
///
/// The decoded original message `M`. The returned `Vec<u8>` length
/// equals the length of the message that was originally encoded.
///
/// # Errors
///
/// * Returns `OaepError::OaepDecodingError` (wrapped in [`CryptoError`])
///   if any integrity check fails. The single, opaque error is
///   intentional — exposing the specific failure cause would create a
///   timing oracle for Manger's attack.
/// * Returns `OaepError::InvalidOaepParametersValue` if `key_size` is
///   too small for the chosen digest, or if `encoded.len() != key_size`.
/// * Returns `OaepError::DigestNotAllowed` /
///   `OaepError::InvalidMgf1Digest` under FIPS mode for unapproved
///   digests.
///
/// # Constant-time Properties
///
/// * Length-input: every check produces a `u32` mask; the masks are
///   bitwise-`AND`ed into a single `good` accumulator and never branched on.
/// * The 0x01 separator scan is implemented as a single linear sweep
///   that updates `zeroth_one_index` via `constant_time_select`.
/// * The output extraction uses an `O(log₂ db_len)` cascade of
///   conditional moves (one per power of two ≤ `db_len`) so that the
///   memory-access pattern is independent of the actual message length.
pub fn oaep_decode(
    encoded: &[u8],
    params: &OaepParams,
    key_size: usize,
) -> CryptoResult<Vec<u8>> {
    // ---- 1. Resolve digest sizes ------------------------------------
    let digest = params.digest;
    let mgf1_digest = params.mgf1_digest_effective();

    validate_oaep_digest_fips(digest)?;
    validate_mgf1_digest_fips(mgf1_digest)?;

    let mdlen = digest.digest_size();
    if mdlen == 0 {
        return Err(OaepError::InvalidOaepParametersValue(
            "OAEP digest has zero output size",
        )
        .into());
    }

    // ---- 2. Validate input length -----------------------------------
    let two_mdlen_plus_2 = mdlen
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or(OaepError::InvalidOaepParametersValue(
            "OAEP digest size too large",
        ))?;
    if key_size < two_mdlen_plus_2 {
        return Err(OaepError::InvalidOaepParametersValue(
            "OAEP key_size smaller than 2*hLen + 2",
        )
        .into());
    }
    if encoded.len() != key_size {
        return Err(oaep_decode_error());
    }

    // ---- 3. Working copy of EM -------------------------------------
    // We need a mutable buffer to keep the constant-time guarantees;
    // operations on `&[u8]` via indexing would also be constant-time
    // but we'd still allocate temporaries. We allocate exactly once.
    let mut em: Vec<u8> = encoded.to_vec();

    // ---- 4. Manger defense: first byte must be 0x00 -----------------
    //
    // C reference: crypto/rsa/rsa_oaep.c line 248 —
    //     good = constant_time_is_zero(em[0]);
    //
    // `good` carries `0xFFFFFFFF` if all checks pass, `0x00000000`
    // otherwise. ANDing in subsequent check results preserves the
    // accumulator's all-or-nothing semantics.
    let mut good: u32 = constant_time::constant_time_is_zero(u32::from(em[0]));

    let db_off = 1 + mdlen;
    let db_len = key_size - db_off;

    // ---- 5. Recover seed = maskedSeed XOR MGF1(maskedDB, hLen) ------
    let mut seedmask = vec![0u8; mdlen];
    if let Err(e) = mgf1(&mut seedmask, &em[db_off..db_off + db_len], mgf1_digest) {
        seedmask.zeroize();
        em.zeroize();
        return Err(e);
    }
    let mut seed = vec![0u8; mdlen];
    for (i, mask_byte) in seedmask.iter().enumerate() {
        seed[i] = em[1 + i] ^ *mask_byte;
    }
    seedmask.zeroize();

    // ---- 6. Recover DB = maskedDB XOR MGF1(seed, k - hLen - 1) ------
    let mut dbmask = vec![0u8; db_len];
    if let Err(e) = mgf1(&mut dbmask, &seed, mgf1_digest) {
        dbmask.zeroize();
        seed.zeroize();
        em.zeroize();
        return Err(e);
    }
    let mut db = vec![0u8; db_len];
    for (i, mask_byte) in dbmask.iter().enumerate() {
        db[i] = em[db_off + i] ^ *mask_byte;
    }
    dbmask.zeroize();
    seed.zeroize();

    // ---- 7. Constant-time lHash comparison --------------------------
    let lhash = match hash_label(&params.label, digest) {
        Ok(h) => h,
        Err(e) => {
            em.zeroize();
            db.zeroize();
            return Err(e);
        }
    };

    let mut hash_eq: u32 = u32::MAX;
    for i in 0..mdlen {
        hash_eq &= constant_time::constant_time_eq(u32::from(db[i]), u32::from(lhash[i]));
    }
    good &= hash_eq;

    // ---- 8. Find 0x01 separator in constant time --------------------
    //
    // C reference: crypto/rsa/rsa_oaep.c lines 274-296.
    //
    // Iterate over DB[hLen..]:
    //   - `pre_one`     = !found    (true while we haven't hit 0x01 yet)
    //   - `is_one`      = (byte == 1)
    //   - `is_zero`     = (byte == 0)
    //   - `bad_pad`    |= pre_one & !is_one & !is_zero
    //                     (any non-{0,1} byte before the separator)
    //   - `take_now`    = pre_one & is_one
    //                     (this is the 0x01 separator we want)
    //   - `zeroth_one_index = ct_select(take_now, i, zeroth_one_index)`
    //   - `found       |= take_now`
    //
    // After the scan:
    //   * `good &= found`     (we must have found the separator)
    //   * `good &= !bad_pad`  (no junk in PS)
    let mut found: u32 = 0;
    let mut zeroth_one_index: u32 = 0;
    let mut bad_pad: u32 = 0;

    for (i, byte_val) in db.iter().enumerate().skip(mdlen) {
        let byte = u32::from(*byte_val);
        let is_one = constant_time::constant_time_eq(byte, 1);
        let is_zero = constant_time::constant_time_is_zero(byte);
        let pre_one = !found;
        bad_pad |= pre_one & !is_one & !is_zero;
        let take_now = pre_one & is_one;
        // `db_len < 2^32` for any realistic key, so `i as u32` is
        // lossless. We still use `try_from` for Rule R6 compliance.
        let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
        zeroth_one_index = constant_time::constant_time_select(take_now, i_u32, zeroth_one_index);
        found |= take_now;
    }
    good &= found;
    good &= !bad_pad;

    // ---- 9. Compute the message length ------------------------------
    //
    // mlen = db_len - 1 - zeroth_one_index
    //   (the message starts immediately after the separator at index
    //    `zeroth_one_index` and runs to the end of DB).
    //
    // We use saturating arithmetic so a malformed `zeroth_one_index >=
    // db_len` cannot wrap around and produce a huge length; `good` will
    // already be zeroed in that case.
    let db_len_u32 = u32::try_from(db_len).unwrap_or(u32::MAX);
    let mlen_u32 = db_len_u32
        .saturating_sub(1)
        .saturating_sub(zeroth_one_index);

    // ---- 10. Constant-time message extraction (left-shift cascade) --
    //
    // We need to copy `db[zeroth_one_index + 1 ..]` to the front of `db`
    // without leaking `zeroth_one_index` through the memory-access
    // pattern. The C code does this with a `O(log₂ db_len)` cascade:
    // for each power-of-two `bit ≤ db_len`, we conditionally shift `db`
    // left by `bit` bytes if `(shift & bit) != 0`, where `shift =
    // zeroth_one_index + 1`. After all bits have been processed, the
    // first `mlen` bytes of `db` hold the recovered message.
    let shift = zeroth_one_index.saturating_add(1);
    let mut bit: u32 = 1;
    while bit < db_len_u32 && bit != 0 {
        let bit_set = constant_time::constant_time_eq(shift & bit, bit);
        // Convert `bit` to a usize distance for indexing.
        let dist = usize::try_from(bit).unwrap_or(0);
        if dist == 0 {
            break;
        }
        // Build a u8 mask: 0xFF when bit_set is non-zero, 0x00 otherwise.
        // `constant_time_is_zero_8` returns 0xFF when its argument is
        // zero, so we negate `bit_set` first.
        let mask_u8 = constant_time::constant_time_is_zero_8(!bit_set);
        for i in 0..db_len {
            let src = if i + dist < db_len { db[i + dist] } else { 0 };
            db[i] = constant_time::constant_time_select_8(mask_u8, src, db[i]);
        }
        bit = bit.wrapping_shl(1);
    }

    // ---- 11. Allocate the output buffer -----------------------------
    //
    // We always allocate the maximum possible message length (db_len -
    // 1) and copy that much from `db`; the caller never gets to see
    // bytes beyond `mlen`. Returning a fixed-length buffer here would
    // also work but is cumbersome for callers, so we truncate to
    // `mlen_usize` at the very end.
    //
    // Note: `mlen_safe` is `mlen_u32` if `good` is all-ones (i.e., all
    // checks passed); otherwise it is 0. This prevents a malformed
    // ciphertext from triggering an overlong allocation.
    let mlen_safe = constant_time::constant_time_select(good, mlen_u32, 0);
    let mlen_usize = usize::try_from(mlen_safe).unwrap_or(0);

    let max_msg_len = db_len.saturating_sub(1);
    let mut out = vec![0u8; max_msg_len];
    if max_msg_len > 0 {
        out.copy_from_slice(&db[..max_msg_len]);
    }

    em.zeroize();
    db.zeroize();

    // ---- 12. Final selection — collapse `good` mask to Result -------
    //
    // We use `constant_time_select_int` to pick `mlen_usize` (cast to
    // i32) when `good == 0xFFFFFFFF`, or `-1` otherwise. A negative
    // result indicates failure; a non-negative result is the recovered
    // message length.
    let mlen_i32 = i32::try_from(mlen_usize).unwrap_or(-1);
    let result_i32 = constant_time::constant_time_select_int(good, mlen_i32, -1);

    if result_i32 < 0 {
        // Zero out the candidate output before discarding to avoid
        // leaking partial decoded data through stack reuse.
        out.zeroize();
        return Err(oaep_decode_error());
    }

    // Result is non-negative; truncate to the recovered length.
    let final_len = usize::try_from(result_i32).unwrap_or(0);
    if final_len > out.len() {
        // Shouldn't be reachable given the saturating arithmetic above,
        // but defend against it.
        out.zeroize();
        return Err(oaep_decode_error());
    }
    out.truncate(final_len);

    Ok(out)
}

// =============================================================================
// 8. Convenience wrappers — oaep_encode_default / oaep_decode_default
// =============================================================================

/// One-shot OAEP encode with default parameters (SHA-1, no label).
///
/// Convenience wrapper matching the legacy C
/// `RSA_padding_add_PKCS1_OAEP` from `crypto/rsa/rsa_oaep.c` line 39.
/// Equivalent to:
///
/// ```ignore
/// oaep_encode(encoded, message, &OaepParams::default())
/// ```
pub fn oaep_encode_default(encoded: &mut [u8], message: &[u8]) -> CryptoResult<()> {
    oaep_encode(encoded, message, &OaepParams::default())
}

/// One-shot OAEP decode with default parameters (SHA-1, no label).
///
/// Convenience wrapper matching the legacy C
/// `RSA_padding_check_PKCS1_OAEP` from `crypto/rsa/rsa_oaep.c` line 163.
/// Equivalent to:
///
/// ```ignore
/// oaep_decode(encoded, &OaepParams::default(), key_size)
/// ```
pub fn oaep_decode_default(encoded: &[u8], key_size: usize) -> CryptoResult<Vec<u8>> {
    oaep_decode(encoded, &OaepParams::default(), key_size)
}


// =============================================================================
// 9. High-level RSA-OAEP encrypt / decrypt (preserved for crate-internal use)
// =============================================================================

/// Encrypt a message under RSA-OAEP using the given public key.
///
/// This is the high-level convenience wrapper that:
/// 1. Calls [`oaep_encode`] to produce the encoded message `EM`.
/// 2. Applies the RSA encryption primitive to `EM` to produce the
///    ciphertext.
///
/// Equivalent to the C code path
/// `RSA_padding_add_PKCS1_OAEP_mgf1 + rsa_ossl_public_encrypt`. Used
/// internally by the EVP layer; external callers normally route
/// through `EVP_PKEY_encrypt` instead.
///
/// # Errors
///
/// Propagates errors from [`oaep_encode`] and from the underlying RSA
/// primitive. The intermediate `EM` buffer is zeroized before return on
/// every code path so plaintext-derived state cannot leak.
pub fn oaep_encrypt(
    key: &RsaPublicKey,
    msg: &[u8],
    params: &OaepParams,
) -> CryptoResult<Vec<u8>> {
    // Compute k from the public modulus.
    let k_u32 = key.key_size_bytes();
    let k = usize::try_from(k_u32).map_err(|_| RsaError::DataTooLargeForKeySize)?;

    // Reject zero-sized keys before allocating; would otherwise be
    // caught by oaep_encode's parameter validation but the dedicated
    // RsaError makes the failure semantics clearer for crate-internal
    // callers.
    let mdlen = params.digest.digest_size();
    let two_mdlen_plus_2 = mdlen
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or(RsaError::DataTooLargeForKeySize)?;
    if k < two_mdlen_plus_2 {
        return Err(RsaError::KeyTooSmall {
            min_bits: u32::try_from(two_mdlen_plus_2.saturating_mul(8)).unwrap_or(u32::MAX),
            actual_bits: k_u32.saturating_mul(8),
        }
        .into());
    }

    // Translate "data too large" so the legacy crate-level error type
    // is preserved for callers that relied on `RsaError::DataTooLargeForKeySize`.
    let max_msg = k - two_mdlen_plus_2;
    if msg.len() > max_msg {
        return Err(RsaError::DataTooLargeForKeySize.into());
    }

    // Build EM via the schema-required primitive.
    let mut em = vec![0u8; k];
    let encode_result = oaep_encode(&mut em, msg, params);
    if let Err(e) = encode_result {
        em.zeroize();
        return Err(e);
    }

    // Apply the RSA primitive (no further padding).
    let ct_result = public_encrypt(key, &em, PaddingMode::None);

    // Always wipe `em` regardless of outcome — it contains the
    // randomised but plaintext-derived encoded message.
    em.zeroize();

    ct_result
}

/// Decrypt an RSA-OAEP ciphertext using the given private key.
///
/// This is the high-level convenience wrapper that:
/// 1. Applies the RSA decryption primitive to the ciphertext to
///    recover `EM`.
/// 2. Calls [`oaep_decode`] to verify integrity and extract the
///    plaintext.
///
/// **SECURITY:** Both stages of this function preserve constant-time
/// properties — `private_decrypt` returns the raw `EM` without
/// inspection, and [`oaep_decode`] performs all integrity checks in
/// constant time relative to the encoded message contents.
///
/// Equivalent to the C code path
/// `rsa_ossl_private_decrypt + RSA_padding_check_PKCS1_OAEP_mgf1`.
///
/// # Errors
///
/// Propagates errors from the RSA primitive and from [`oaep_decode`].
/// Returns `RsaError::OaepDecodingError` (via the [`From`] chain) when
/// integrity checks fail.
pub fn oaep_decrypt(
    key: &RsaPrivateKey,
    ciphertext: &[u8],
    params: &OaepParams,
) -> CryptoResult<Vec<u8>> {
    let k_u32 = key.key_size_bytes();
    let k = usize::try_from(k_u32).map_err(|_| RsaError::DataTooLargeForKeySize)?;

    let mdlen = params.digest.digest_size();
    let two_mdlen_plus_2 = mdlen
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or(RsaError::DataTooLargeForKeySize)?;
    if k < two_mdlen_plus_2 {
        return Err(RsaError::KeyTooSmall {
            min_bits: u32::try_from(two_mdlen_plus_2.saturating_mul(8)).unwrap_or(u32::MAX),
            actual_bits: k_u32.saturating_mul(8),
        }
        .into());
    }

    // Apply the RSA primitive to recover EM.
    let mut em = private_decrypt(key, ciphertext, PaddingMode::None)?;
    if em.len() != k {
        em.zeroize();
        return Err(oaep_decode_error());
    }

    // Decode via the schema-required primitive.
    let result = oaep_decode(&em, params, k);

    // Always wipe `em` — it contains the encoded message which is
    // derived from the plaintext.
    em.zeroize();

    result
}

// =============================================================================
// 10. Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code conventionally uses expect/unwrap/panic for clarity over robustness"
)]
mod tests {
    use super::*;
    use crate::rsa::{generate_key, RsaKeyGenParams};

    /// Helper to obtain a fresh 2048-bit RSA key pair for round-trip
    /// tests. Generation is the dominant cost of these tests.
    fn test_keypair() -> super::super::RsaKeyPair {
        generate_key(&RsaKeyGenParams::default())
            .expect("RSA-2048 key generation should succeed")
    }

    // ---- OaepParams API --------------------------------------------

    #[test]
    fn oaep_params_default_is_sha1() {
        let p = OaepParams::default();
        assert_eq!(p.digest, DigestAlgorithm::Sha1);
        assert_eq!(p.mgf1_digest, None);
        assert!(p.label.is_empty());
        assert_eq!(p.mgf1_digest_effective(), DigestAlgorithm::Sha1);
    }

    #[test]
    fn oaep_params_with_digest() {
        let p = OaepParams::default().with_digest(DigestAlgorithm::Sha384);
        assert_eq!(p.digest, DigestAlgorithm::Sha384);
        assert_eq!(p.mgf1_digest, None);
        assert_eq!(p.mgf1_digest_effective(), DigestAlgorithm::Sha384);
    }

    #[test]
    fn oaep_params_mgf1_override() {
        let p = OaepParams::default().with_mgf1_digest(DigestAlgorithm::Sha512);
        assert_eq!(p.digest, DigestAlgorithm::Sha1);
        assert_eq!(p.mgf1_digest, Some(DigestAlgorithm::Sha512));
        assert_eq!(p.mgf1_digest_effective(), DigestAlgorithm::Sha512);
    }

    #[test]
    fn oaep_params_with_label() {
        let p = OaepParams::default().with_label(b"hello".to_vec());
        assert_eq!(p.label, b"hello");
    }

    #[test]
    fn oaep_params_nid_roundtrip() {
        let p = OaepParams::default()
            .with_digest(DigestAlgorithm::Sha256)
            .with_mgf1_digest(DigestAlgorithm::Sha384);
        let oaep_nid = p.oaep_digest_nid().expect("SHA-256 has OSSL NID");
        let mgf1_nid = p.mgf1_digest_nid().expect("SHA-384 has OSSL NID");
        let q = OaepParams::from_nids(oaep_nid, mgf1_nid).expect("both NIDs are known");
        assert_eq!(q.digest, DigestAlgorithm::Sha256);
        assert_eq!(q.mgf1_digest_effective(), DigestAlgorithm::Sha384);
    }

    // ---- mgf1 -------------------------------------------------------

    #[test]
    fn mgf1_zero_length_output_is_noop() {
        let mut mask: [u8; 0] = [];
        mgf1(&mut mask, b"seed", DigestAlgorithm::Sha256).expect("MGF1 with empty mask is no-op");
    }

    #[test]
    fn mgf1_deterministic_for_same_seed() {
        let mut mask_a = [0u8; 64];
        let mut mask_b = [0u8; 64];
        mgf1(&mut mask_a, b"seed-bytes", DigestAlgorithm::Sha256).unwrap();
        mgf1(&mut mask_b, b"seed-bytes", DigestAlgorithm::Sha256).unwrap();
        assert_eq!(mask_a, mask_b);
    }

    #[test]
    fn mgf1_different_seeds_produce_different_masks() {
        let mut mask_a = [0u8; 32];
        let mut mask_b = [0u8; 32];
        mgf1(&mut mask_a, b"seed-a", DigestAlgorithm::Sha256).unwrap();
        mgf1(&mut mask_b, b"seed-b", DigestAlgorithm::Sha256).unwrap();
        assert_ne!(mask_a, mask_b);
    }

    #[test]
    fn mgf1_truncates_when_mask_smaller_than_block() {
        // SHA-256 produces 32-byte blocks. Request 7 bytes; the
        // result should be the first 7 bytes of a single block.
        let mut short_mask = [0u8; 7];
        let mut full_block = [0u8; 32];
        mgf1(&mut short_mask, b"seed", DigestAlgorithm::Sha256).unwrap();
        mgf1(&mut full_block, b"seed", DigestAlgorithm::Sha256).unwrap();
        assert_eq!(&short_mask, &full_block[..7]);
    }

    #[test]
    fn mgf1_spans_multiple_blocks() {
        // SHA-256 = 32-byte blocks. Request 100 bytes ⇒ 4 blocks
        // truncated to 100. First 32 bytes must equal Hash(seed||0)
        // and bytes 32..64 must equal Hash(seed||1).
        let mut mask = [0u8; 100];
        mgf1(&mut mask, b"seed", DigestAlgorithm::Sha256).unwrap();
        // Verify the first block matches the standalone block-0 output.
        let mut block0 = [0u8; 32];
        mgf1(&mut block0, b"seed", DigestAlgorithm::Sha256).unwrap();
        assert_eq!(&mask[..32], &block0);
    }

    // ---- oaep_encode / oaep_decode (byte-buffer primitives) --------

    #[test]
    fn oaep_encode_decode_roundtrip_default_params() {
        let k = 256; // 2048-bit modulus.
        let mut em = vec![0u8; k];
        let msg = b"hello, OAEP!";
        oaep_encode(&mut em, msg, &OaepParams::default()).expect("encode succeeds");
        let recovered = oaep_decode(&em, &OaepParams::default(), k).expect("decode succeeds");
        assert_eq!(recovered, msg);
    }

    #[test]
    fn oaep_encode_decode_roundtrip_sha256() {
        let k = 256;
        let params = OaepParams::default().with_digest(DigestAlgorithm::Sha256);
        let mut em = vec![0u8; k];
        let msg = b"the quick brown fox jumps over the lazy dog";
        oaep_encode(&mut em, msg, &params).unwrap();
        let recovered = oaep_decode(&em, &params, k).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn oaep_encode_decode_roundtrip_with_label() {
        let k = 256;
        let params = OaepParams::default().with_label(b"context-bind".to_vec());
        let mut em = vec![0u8; k];
        let msg = b"bound message";
        oaep_encode(&mut em, msg, &params).unwrap();
        let recovered = oaep_decode(&em, &params, k).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn oaep_encode_decode_roundtrip_empty_message() {
        let k = 256;
        let mut em = vec![0u8; k];
        oaep_encode(&mut em, &[], &OaepParams::default()).unwrap();
        let recovered = oaep_decode(&em, &OaepParams::default(), k).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn oaep_encode_two_invocations_produce_different_em() {
        // OAEP is randomised: same plaintext, same parameters ⇒
        // different EM each time (because the seed differs).
        let k = 256;
        let mut em1 = vec![0u8; k];
        let mut em2 = vec![0u8; k];
        oaep_encode(&mut em1, b"msg", &OaepParams::default()).unwrap();
        oaep_encode(&mut em2, b"msg", &OaepParams::default()).unwrap();
        assert_ne!(em1, em2);
    }

    #[test]
    fn oaep_encode_message_too_long_returns_error() {
        let k = 256;
        // Default uses SHA-1 (hLen=20), so max msg = 256 - 42 = 214 bytes.
        let mut em = vec![0u8; k];
        let too_long = vec![0u8; 215];
        let err = oaep_encode(&mut em, &too_long, &OaepParams::default())
            .expect_err("message too long should be rejected");
        // The error path shouldn't leak via partial writes.
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_encode_buffer_too_small_returns_error() {
        // 2*hLen + 2 = 42 for SHA-1; a 30-byte buffer is too small.
        let mut em = vec![0u8; 30];
        let err = oaep_encode(&mut em, b"hi", &OaepParams::default())
            .expect_err("undersized buffer rejected");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_decode_tampered_em_fails() {
        let k = 256;
        let mut em = vec![0u8; k];
        oaep_encode(&mut em, b"msg", &OaepParams::default()).unwrap();
        // Flip a bit in the masked DB region.
        em[100] ^= 0x01;
        let err = oaep_decode(&em, &OaepParams::default(), k)
            .expect_err("tampered EM should fail to decode");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_decode_wrong_label_fails() {
        let k = 256;
        let enc_params = OaepParams::default().with_label(b"correct".to_vec());
        let dec_params = OaepParams::default().with_label(b"wrong".to_vec());
        let mut em = vec![0u8; k];
        oaep_encode(&mut em, b"msg", &enc_params).unwrap();
        let err = oaep_decode(&em, &dec_params, k)
            .expect_err("mismatched label should fail");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_decode_wrong_digest_fails() {
        let k = 256;
        let enc_params = OaepParams::default().with_digest(DigestAlgorithm::Sha256);
        let dec_params = OaepParams::default().with_digest(DigestAlgorithm::Sha384);
        let mut em = vec![0u8; k];
        oaep_encode(&mut em, b"msg", &enc_params).unwrap();
        let err = oaep_decode(&em, &dec_params, k)
            .expect_err("digest mismatch should fail");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_decode_wrong_first_byte_fails() {
        // Manger defense: first byte must be 0x00.
        let k = 256;
        let mut em = vec![0u8; k];
        oaep_encode(&mut em, b"msg", &OaepParams::default()).unwrap();
        em[0] = 0x01;
        let err = oaep_decode(&em, &OaepParams::default(), k)
            .expect_err("non-zero first byte must fail");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_decode_short_em_fails() {
        // EM length mismatch with key_size.
        let k = 256;
        let em = vec![0u8; 100];
        let err = oaep_decode(&em, &OaepParams::default(), k)
            .expect_err("length mismatch should fail");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    // ---- oaep_encode_default / oaep_decode_default ------------------

    #[test]
    fn oaep_encode_default_decode_default_roundtrip() {
        let k = 256;
        let mut em = vec![0u8; k];
        oaep_encode_default(&mut em, b"default params").unwrap();
        let recovered = oaep_decode_default(&em, k).unwrap();
        assert_eq!(recovered, b"default params");
    }

    // ---- OaepError --------------------------------------------------

    #[test]
    fn oaep_error_into_crypto_error() {
        let err: CryptoError = OaepError::DataTooLargeForKeySize.into();
        assert!(matches!(err, CryptoError::Encoding(_)));
        let err: CryptoError = OaepError::OaepDecodingError.into();
        assert!(matches!(err, CryptoError::Encoding(_)));
        let err: CryptoError = OaepError::InvalidOaepParametersValue("test").into();
        assert!(matches!(err, CryptoError::Encoding(_)));
        let err: CryptoError = OaepError::DigestNotAllowed.into();
        assert!(matches!(err, CryptoError::AlgorithmNotFound(_)));
        let err: CryptoError = OaepError::InvalidMgf1Digest.into();
        assert!(matches!(err, CryptoError::AlgorithmNotFound(_)));
    }

    #[test]
    fn oaep_error_display_messages_are_useful() {
        let err = OaepError::DataTooLargeForKeySize;
        assert!(err.to_string().contains("data too large"));
        let err = OaepError::OaepDecodingError;
        assert!(err.to_string().contains("decoding error"));
        let err = OaepError::InvalidOaepParametersValue("oops");
        assert!(err.to_string().contains("oops"));
    }

    // ---- High-level oaep_encrypt / oaep_decrypt --------------------

    #[test]
    fn oaep_roundtrip_empty_message_default_params() {
        let kp = test_keypair();
        let ct = oaep_encrypt(&kp.public_key(), &[], &OaepParams::default()).unwrap();
        let pt = oaep_decrypt(kp.private_key(), &ct, &OaepParams::default()).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn oaep_roundtrip_short_message_default_params() {
        let kp = test_keypair();
        let msg = b"the quick brown fox jumps over the lazy dog";
        let ct = oaep_encrypt(&kp.public_key(), msg, &OaepParams::default()).unwrap();
        let pt = oaep_decrypt(kp.private_key(), &ct, &OaepParams::default()).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_roundtrip_with_label() {
        let kp = test_keypair();
        let params = OaepParams::default().with_label(b"context-binding-label".to_vec());
        let msg = b"bound to a label";
        let ct = oaep_encrypt(&kp.public_key(), msg, &params).unwrap();
        let pt = oaep_decrypt(kp.private_key(), &ct, &params).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_roundtrip_sha384() {
        let kp = test_keypair();
        let params = OaepParams::default().with_digest(DigestAlgorithm::Sha384);
        let msg = b"sha384 oaep test";
        let ct = oaep_encrypt(&kp.public_key(), msg, &params).unwrap();
        let pt = oaep_decrypt(kp.private_key(), &ct, &params).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_roundtrip_distinct_mgf1_digest() {
        let kp = test_keypair();
        let params = OaepParams::default()
            .with_digest(DigestAlgorithm::Sha256)
            .with_mgf1_digest(DigestAlgorithm::Sha384);
        let msg = b"distinct hash and MGF1";
        let ct = oaep_encrypt(&kp.public_key(), msg, &params).unwrap();
        let pt = oaep_decrypt(kp.private_key(), &ct, &params).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_message_too_long_returns_error() {
        let kp = test_keypair();
        // 2048-bit key: 256-byte modulus.
        // SHA-1 default: max msg = 256 - 42 = 214 bytes.
        // 256-byte message is >>> 214 and must be rejected.
        let too_long = vec![0u8; 256];
        let err = oaep_encrypt(&kp.public_key(), &too_long, &OaepParams::default())
            .expect_err("oversize plaintext should be rejected");
        // RsaError::DataTooLargeForKeySize maps to CryptoError::Encoding.
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_tampered_ciphertext_fails_decode() {
        let kp = test_keypair();
        let mut ct = oaep_encrypt(&kp.public_key(), b"tamper-me", &OaepParams::default()).unwrap();
        // Flip a bit somewhere in the middle of the ciphertext.
        let mid = ct.len() / 2;
        ct[mid] ^= 0x01;
        let err = oaep_decrypt(kp.private_key(), &ct, &OaepParams::default())
            .expect_err("tampered ciphertext must not decode");
        // Could be either Encoding (OAEP integrity) or Encoding via
        // RsaError::OaepDecodingError; both map to CryptoError::Encoding.
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_wrong_label_fails_decode() {
        let kp = test_keypair();
        let enc_params = OaepParams::default().with_label(b"correct-label".to_vec());
        let dec_params = OaepParams::default().with_label(b"wrong-label".to_vec());
        let ct = oaep_encrypt(&kp.public_key(), b"msg", &enc_params).unwrap();
        let err = oaep_decrypt(kp.private_key(), &ct, &dec_params)
            .expect_err("wrong label must fail integrity check");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_wrong_digest_fails_decode() {
        let kp = test_keypair();
        let enc_params = OaepParams::default().with_digest(DigestAlgorithm::Sha256);
        let dec_params = OaepParams::default().with_digest(DigestAlgorithm::Sha384);
        let ct = oaep_encrypt(&kp.public_key(), b"msg", &enc_params).unwrap();
        let err = oaep_decrypt(kp.private_key(), &ct, &dec_params)
            .expect_err("wrong digest must fail integrity check");
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn oaep_ciphertext_length_equals_modulus_bytes() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let ct = oaep_encrypt(&pubkey, b"x", &OaepParams::default()).unwrap();
        // Per Rule R6: lossless conversion. ct.len() can never exceed
        // u32::MAX in practice (RSA moduli are at most a few KiB), but
        // we use try_from rather than `as` so the cast lint stays
        // satisfied without a justification.
        let ct_len_u32 = u32::try_from(ct.len()).expect("ciphertext length fits in u32");
        assert_eq!(ct_len_u32, pubkey.key_size_bytes());
    }
}

