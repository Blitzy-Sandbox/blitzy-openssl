//! ECDSA (Elliptic Curve Digital Signature Algorithm) implementation.
//!
//! Provides signature creation and verification over elliptic curves per FIPS 186-5
//! and ANSI X9.62. Translates C ECDSA_* functions from `crypto/ec/ecdsa_sign.c`,
//! `crypto/ec/ecdsa_vrf.c`, and `crypto/ec/ecdsa_ossl.c`.
//!
//! # Key Design Choices
//!
//! - **`Result<bool>` replaces triple-value returns:** C `ECDSA_verify` returns 1/0/-1;
//!   Rust uses [`CryptoResult<bool>`] (Rule R5)
//! - **[`EcdsaSignature`] replaces `ECDSA_SIG`:** Typed struct with `r` and `s` components
//!   instead of opaque C struct
//! - **Deterministic nonce support:** RFC 6979 deterministic `k` generation included
//! - **Constant-time operations:** Uses [`subtle::ConstantTimeEq`] for signature comparison
//! - **Secure erasure:** Nonce `k` and intermediates zeroed via [`zeroize`] (AAP §0.7.6)
//!
//! # Wiring (Rule R10)
//!
//! Reachable via `openssl_crypto::ec::ecdsa::sign()` from the EVP signature layer
//! and ultimately from the CLI `dgst` and provider signature implementations.

use openssl_common::{CryptoError, CryptoResult};

use crate::bn::arithmetic::{mod_add, mod_inverse_checked, mod_mul, nnmod, rshift};
use crate::bn::BigNum;

use subtle::ConstantTimeEq;
use tracing::{error, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{EcGroup, EcKey, EcPoint};

// ---------------------------------------------------------------------------
// Constants (from ecdsa_ossl.c)
// ---------------------------------------------------------------------------

/// Maximum number of sign retries before returning an error.
/// Matches C `#define MAX_ECDSA_SIGN_RETRIES 8` from `ecdsa_ossl.c` line 31.
const MAX_ECDSA_SIGN_RETRIES: u32 = 8;

/// Minimum order bit length for ECDSA curves.
/// Matches C `#define MIN_ECDSA_SIGN_ORDERBITS 64` from `ecdsa_ossl.c` line 32.
const MIN_ECDSA_SIGN_ORDERBITS: u32 = 64;

// ---------------------------------------------------------------------------
// Sensitive byte wrapper — auto-zeroes on drop (per AAP §0.7.6)
// ---------------------------------------------------------------------------

/// Wrapper for sensitive byte buffers (nonce seed material, HMAC keys)
/// that are automatically zeroed when dropped.
///
/// Uses [`ZeroizeOnDrop`] to ensure no key material residue remains on
/// the stack or heap after the scope exits.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    /// Creates a new `SensitiveBytes` buffer of given length, initialised to zero.
    fn new(len: usize) -> Self {
        Self(vec![0u8; len])
    }

    /// Returns a mutable reference to the inner buffer.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns a reference to the inner buffer.
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

// ===========================================================================
// EcdsaSignature — replaces C `ECDSA_SIG` from ec_local.h
// ===========================================================================

/// ECDSA signature consisting of `(r, s)` components.
///
/// Replaces C `ECDSA_SIG` struct from `ec_local.h`:
/// ```c
/// struct ECDSA_SIG_st {
///     BIGNUM *r;
///     BIGNUM *s;
/// };
/// ```
///
/// # Security
///
/// Signature components are not secret, but [`Clone`] is provided for
/// convenience without security risk. The struct does not hold key material.
#[derive(Debug, Clone)]
pub struct EcdsaSignature {
    /// The `r` component of the signature (`x`-coordinate of `k*G mod n`).
    r: BigNum,
    /// The `s` component of the signature (`k⁻¹ * (hash + r*privkey) mod n`).
    s: BigNum,
}

impl EcdsaSignature {
    /// Creates a new ECDSA signature from `(r, s)` components.
    ///
    /// # Arguments
    ///
    /// * `r` — The `r` component (x-coordinate derived)
    /// * `s` — The `s` component (scalar proof)
    ///
    /// Replaces C `ECDSA_SIG_new()` + `ECDSA_SIG_set0()`.
    pub fn new(r: BigNum, s: BigNum) -> Self {
        Self { r, s }
    }

    /// Returns a reference to the `r` component.
    ///
    /// Replaces C `ECDSA_SIG_get0_r()`.
    #[inline]
    pub fn r(&self) -> &BigNum {
        &self.r
    }

    /// Returns a reference to the `s` component.
    ///
    /// Replaces C `ECDSA_SIG_get0_s()`.
    #[inline]
    pub fn s(&self) -> &BigNum {
        &self.s
    }

    /// DER-encodes the signature as ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`.
    ///
    /// Replaces C `i2d_ECDSA_SIG()` from `crypto/ec/ecdsa_ossl.c` lines 90, 429.
    /// The encoding follows X9.62 / SEC 1 format.
    ///
    /// # Errors
    ///
    /// This method is infallible for well-formed `EcdsaSignature` instances.
    /// Returns `Ok` always.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(encode_signature_der(self))
    }

    /// Parses a DER-encoded ECDSA signature.
    ///
    /// Replaces C `d2i_ECDSA_SIG()` from `crypto/ec/ecdsa_ossl.c` lines 123, 432–433.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the DER data is malformed or contains
    /// negative integers.
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        decode_signature_der(der)
    }

    /// Consumes the signature and returns `(r, s)` as owned [`BigNum`] values.
    ///
    /// Replaces C `ECDSA_SIG_get0()` with ownership transfer.
    pub fn into_components(self) -> (BigNum, BigNum) {
        (self.r, self.s)
    }
}

/// Constant-time equality comparison for ECDSA signatures.
///
/// Uses [`subtle::ConstantTimeEq`] to prevent timing side-channel leakage
/// when comparing signatures. Both `r` and `s` components are compared
/// in constant time using their big-endian byte representations.
impl PartialEq for EcdsaSignature {
    fn eq(&self, other: &Self) -> bool {
        let r_self = self.r.to_bytes_be();
        let r_other = other.r.to_bytes_be();
        let s_self = self.s.to_bytes_be();
        let s_other = other.s.to_bytes_be();

        // Pad to equal lengths for constant-time comparison
        let r_len = r_self.len().max(r_other.len());
        let s_len = s_self.len().max(s_other.len());

        let mut r_a = vec![0u8; r_len];
        let mut r_b = vec![0u8; r_len];
        let mut s_a = vec![0u8; s_len];
        let mut s_b = vec![0u8; s_len];

        r_a[r_len - r_self.len()..].copy_from_slice(&r_self);
        r_b[r_len - r_other.len()..].copy_from_slice(&r_other);
        s_a[s_len - s_self.len()..].copy_from_slice(&s_self);
        s_b[s_len - s_other.len()..].copy_from_slice(&s_other);

        let r_eq = r_a.ct_eq(&r_b);
        let s_eq = s_a.ct_eq(&s_b);

        // Combine results — both must match
        (r_eq & s_eq).into()
    }
}

impl Eq for EcdsaSignature {}

// ===========================================================================
// NonceType — nonce generation strategy
// ===========================================================================

/// Nonce generation strategy for ECDSA signing.
///
/// Controls how the ephemeral `k` value is generated. Translates the
/// C `nonce_type` parameter from `ossl_ecdsa_sign_setup()` in
/// `crypto/ec/ecdsa_ossl.c` (0 = random, 1 = deterministic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceType {
    /// Random nonce generation (default). Uses CSPRNG-seeded
    /// rejection sampling in `[1, order-1]`.
    Random,
    /// Deterministic nonce per RFC 6979. Generates `k` from the
    /// private key and message hash using HMAC-DRBG, eliminating
    /// the need for a CSPRNG during signing.
    Deterministic,
}

// ===========================================================================
// Public API — Sign operations
// ===========================================================================

/// Signs a message digest using ECDSA with a random nonce.
///
/// Replaces C `ECDSA_do_sign()` from `crypto/ec/ecdsa_sign.c`.
/// Generates a random nonce `k`, computes the signature `(r, s)`, and
/// securely zeroes all intermediates.
///
/// # Arguments
///
/// * `key` — EC key pair (must contain a private key component)
/// * `digest` — Message digest bytes (e.g., SHA-256 hash output)
///
/// # Returns
///
/// The ECDSA signature `(r, s)` as an [`EcdsaSignature`].
///
/// # Errors
///
/// Returns [`CryptoError`] if:
/// - The key does not have a private key component
/// - The curve order is too small (< 64 bits)
/// - Nonce generation or signing fails after `MAX_ECDSA_SIGN_RETRIES` attempts
///
/// # Security
///
/// All intermediate values (nonce `k`, `k_inverse`, digest-to-integer `m`)
/// are securely zeroed after use via [`zeroize`].
pub fn sign(key: &EcKey, digest: &[u8]) -> CryptoResult<EcdsaSignature> {
    sign_with_nonce_type(key, digest, NonceType::Random)
}

/// Signs a message digest using ECDSA with explicit nonce type selection.
///
/// Replaces C `ECDSA_do_sign_ex()` from `crypto/ec/ecdsa_sign.c`.
/// Allows selection between random and deterministic (RFC 6979) nonce
/// generation.
///
/// # Arguments
///
/// * `key` — EC key pair (must contain a private key component)
/// * `digest` — Message digest bytes
/// * `nonce_type` — [`NonceType::Random`] or [`NonceType::Deterministic`]
///
/// # Returns
///
/// The ECDSA signature `(r, s)` as an [`EcdsaSignature`].
///
/// # Errors
///
/// Returns [`CryptoError`] if signing fails. See [`sign`] for details.
///
/// # Security
///
/// All intermediate values are securely zeroed after use.
/// Implements the algorithm from `ecdsa_simple_sign_sig()` in
/// `crypto/ec/ecdsa_ossl.c` lines 268–409.
pub fn sign_with_nonce_type(
    key: &EcKey,
    digest: &[u8],
    nonce_type: NonceType,
) -> CryptoResult<EcdsaSignature> {
    let curve_label = key.curve_name().map_or("custom", |c| c.name());
    trace!(
        curve = curve_label,
        digest_len = digest.len(),
        nonce_type = ?nonce_type,
        "ECDSA sign: entry"
    );

    // Validate that the key has a private component
    let priv_key = key.private_key().ok_or_else(|| {
        error!("ECDSA sign: missing private key");
        CryptoError::Key("ECDSA sign: missing private key".to_string())
    })?;

    let group = key.group();
    let order = group.order();

    // Validate minimum order bit length (C: MIN_ECDSA_SIGN_ORDERBITS = 64)
    let order_bits = order.num_bits();
    if order_bits < MIN_ECDSA_SIGN_ORDERBITS {
        error!(
            order_bits = order_bits,
            min = MIN_ECDSA_SIGN_ORDERBITS,
            "ECDSA sign: curve order too small"
        );
        return Err(CryptoError::Key(
            "ECDSA sign: curve order too small".to_string(),
        ));
    }

    // Convert digest to integer m, truncated to order bit length.
    // Translates ecdsa_ossl.c lines 350-375: BN_bin2bn(dgst, dgst_len, m)
    // then truncate if 8*dgst_len > order_bits.
    let mut m = digest_to_bignum(digest, order_bits);

    // Retry loop — matches C MAX_ECDSA_SIGN_RETRIES = 8
    for retry in 0..MAX_ECDSA_SIGN_RETRIES {
        // Generate nonce k and pre-compute (k_inverse, r_value)
        let setup_result = sign_setup_internal(group, priv_key, digest, nonce_type);

        match setup_result {
            Ok((mut k_inv, r_value)) => {
                // Compute s = k_inv * (m + r * priv_key) mod order
                // Translates ecdsa_ossl.c lines 380–400
                let r_times_priv = mod_mul(&r_value, priv_key, order)?;
                let m_plus_r_priv = mod_add(&m, &r_times_priv, order)?;
                let mut s = mod_mul(&k_inv, &m_plus_r_priv, order)?;

                // If s == 0, retry (extremely unlikely but required by spec)
                if s.is_zero() {
                    trace!(retry = retry, "ECDSA sign: s == 0, retrying");
                    k_inv.clear();
                    s.clear();
                    continue;
                }

                // Zero intermediates (AAP §0.7.6)
                k_inv.clear();
                m.clear();

                trace!(curve = curve_label, retry = retry, "ECDSA sign: success");

                return Ok(EcdsaSignature::new(r_value, s));
            }
            Err(e) => {
                // sign_setup may fail if r == 0 after mod reduction; retry
                trace!(retry = retry, error = %e, "ECDSA sign: setup failed, retrying");
                if retry == MAX_ECDSA_SIGN_RETRIES - 1 {
                    m.clear();
                    error!("ECDSA sign: max retries exceeded");
                    return Err(CryptoError::Verification(
                        "ECDSA sign: too many retries".to_string(),
                    ));
                }
            }
        }
    }

    m.clear();
    error!("ECDSA sign: max retries exceeded");
    Err(CryptoError::Verification(
        "ECDSA sign: too many retries".to_string(),
    ))
}

/// Signs a message digest and returns a DER-encoded signature.
///
/// Replaces C `ECDSA_sign()` / `ECDSA_sign_ex()` from
/// `crypto/ec/ecdsa_sign.c`. Equivalent to calling [`sign`] followed
/// by [`EcdsaSignature::to_der`].
///
/// # Arguments
///
/// * `key` — EC key pair (must contain a private key component)
/// * `digest` — Message digest bytes
///
/// # Returns
///
/// DER-encoded ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`.
///
/// # Errors
///
/// Returns [`CryptoError`] if signing or DER encoding fails.
pub fn sign_der(key: &EcKey, digest: &[u8]) -> CryptoResult<Vec<u8>> {
    let sig = sign(key, digest)?;
    sig.to_der()
}

// ===========================================================================
// Public API — Verify operations
// ===========================================================================

/// Verifies an ECDSA signature over a message digest.
///
/// Replaces C `ECDSA_do_verify()` from `crypto/ec/ecdsa_vrf.c`.
///
/// **Rule R5 (CRITICAL):** The C function returns `1` (valid), `0` (invalid),
/// or `-1` (error). This Rust function returns `CryptoResult<bool>`:
/// - `Ok(true)` — signature is valid
/// - `Ok(false)` — signature is invalid
/// - `Err(...)` — verification error (malformed input, missing key, etc.)
///
/// # Arguments
///
/// * `key` — EC key (must contain a public key component)
/// * `digest` — Message digest bytes that were signed
/// * `signature` — ECDSA signature to verify
///
/// # Algorithm
///
/// Implements `ecdsa_simple_verify_sig()` from `crypto/ec/ecdsa_ossl.c`
/// lines 442–547:
/// 1. Check `r, s ∈ [1, order-1]`
/// 2. Compute `u1 = digest × s⁻¹ mod order`
/// 3. Compute `u2 = r × s⁻¹ mod order`
/// 4. Compute `(x₁, y₁) = u1 × G + u2 × pub_key`
/// 5. If result is point at infinity → invalid
/// 6. `v = x₁ mod order`
/// 7. Signature valid iff `v == r` (constant-time comparison)
///
/// # Security
///
/// The final comparison uses [`subtle::ConstantTimeEq`] to prevent
/// timing side-channel attacks. All intermediate values are zeroed.
pub fn verify(key: &EcKey, digest: &[u8], signature: &EcdsaSignature) -> CryptoResult<bool> {
    let curve_label = key.curve_name().map_or("custom", |c| c.name());
    trace!(
        curve = curve_label,
        digest_len = digest.len(),
        "ECDSA verify: entry"
    );

    // Validate that the key has a public key component
    let pub_key = key.public_key().ok_or_else(|| {
        error!("ECDSA verify: missing public key");
        CryptoError::Key("ECDSA verify: missing public key".to_string())
    })?;

    let group = key.group();
    let order = group.order();
    let order_bits = order.num_bits();

    let r = signature.r();
    let s = signature.s();

    // Step 1: Check r, s in [1, order-1]
    // Translates ecdsa_ossl.c lines 473-487
    if r.is_zero() || r.is_negative() {
        trace!("ECDSA verify: r is zero or negative");
        return Ok(false);
    }
    if r.ucmp(order) != std::cmp::Ordering::Less {
        trace!("ECDSA verify: r >= order");
        return Ok(false);
    }
    if s.is_zero() || s.is_negative() {
        trace!("ECDSA verify: s is zero or negative");
        return Ok(false);
    }
    if s.ucmp(order) != std::cmp::Ordering::Less {
        trace!("ECDSA verify: s >= order");
        return Ok(false);
    }

    // Step 2-3: Compute s_inverse, u1, u2
    // Translates ecdsa_ossl.c lines 489-520
    // u2 = s^-1 mod order (reused as temp)
    let mut s_inv = mod_inverse_checked(s, order)?;

    // Convert digest to bignum m, truncated to order bit length
    let mut m = digest_to_bignum(digest, order_bits);

    // u1 = m * s_inv mod order
    let mut u1 = mod_mul(&m, &s_inv, order)?;

    // u2 = r * s_inv mod order
    let mut u2 = mod_mul(r, &s_inv, order)?;

    // Step 4: Compute point = u1 * G + u2 * pub_key
    // Translates ecdsa_ossl.c lines 522-529
    let point_u1g = EcPoint::generator_mul(group, &u1)?;
    let point_u2q = EcPoint::mul(group, pub_key, &u2)?;
    let point = EcPoint::add(group, &point_u1g, &point_u2q)?;

    // Step 5: Check for point at infinity
    if point.is_at_infinity() {
        trace!("ECDSA verify: result is point at infinity");
        // Zero intermediates
        s_inv.clear();
        m.clear();
        u1.clear();
        u2.clear();
        return Ok(false);
    }

    // Step 6: v = x1 mod order
    // Translates ecdsa_ossl.c lines 531-539
    let x1 = point.x();
    let v = nnmod(x1, order)?;

    // Step 7: Signature valid iff v == r (constant-time)
    // Translates ecdsa_ossl.c line 541: ret = (BN_ucmp(u1, sig->r) == 0)
    let v_bytes = v.to_bytes_be();
    let r_bytes = r.to_bytes_be();

    // Pad to equal lengths for constant-time comparison
    let max_len = v_bytes.len().max(r_bytes.len());
    let mut v_padded = vec![0u8; max_len];
    let mut r_padded = vec![0u8; max_len];
    v_padded[max_len - v_bytes.len()..].copy_from_slice(&v_bytes);
    r_padded[max_len - r_bytes.len()..].copy_from_slice(&r_bytes);

    let valid: bool = v_padded.ct_eq(&r_padded).into();

    // Zero all intermediates (AAP §0.7.6)
    s_inv.clear();
    m.clear();
    u1.clear();
    u2.clear();
    v_padded.zeroize();
    r_padded.zeroize();

    trace!(curve = curve_label, valid = valid, "ECDSA verify: complete");

    Ok(valid)
}

/// Verifies a DER-encoded ECDSA signature over a message digest.
///
/// Replaces C `ECDSA_verify()` from `crypto/ec/ecdsa_vrf.c`.
/// Parses the DER-encoded signature, then calls [`verify`].
///
/// **Rule R5:** Returns `CryptoResult<bool>`, not integer sentinel.
///
/// # Arguments
///
/// * `key` — EC key (must contain a public key component)
/// * `digest` — Message digest bytes that were signed
/// * `sig_der` — DER-encoded ASN.1 signature
///
/// # Errors
///
/// Returns [`CryptoError`] if DER parsing or verification fails.
pub fn verify_der(key: &EcKey, digest: &[u8], sig_der: &[u8]) -> CryptoResult<bool> {
    let sig = EcdsaSignature::from_der(sig_der)?;
    verify(key, digest, &sig)
}

// ===========================================================================
// Public API — Sign setup (pre-computation)
// ===========================================================================

/// Pre-computes `(k_inverse, r)` for ECDSA batch signing.
///
/// Replaces C `ECDSA_sign_setup()` from `crypto/ec/ecdsa_sign.c`.
/// Returns a `(k_inverse, r_value)` tuple that can be reused to sign
/// multiple messages with the same ephemeral key parameters.
///
/// # Arguments
///
/// * `key` — EC key pair (must contain a private key component)
///
/// # Returns
///
/// `(k_inverse, r_value)` where:
/// - `k_inverse = k⁻¹ mod order`
/// - `r_value = (k × G).x mod order`
///
/// # Security
///
/// **WARNING:** Reusing `(k_inverse, r)` across multiple signatures
/// can lead to private key recovery if not handled carefully. Each
/// call generates a fresh random `k`.
///
/// Both returned values should be zeroed when no longer needed.
///
/// # Errors
///
/// Returns [`CryptoError`] if the key has no private component or
/// nonce generation fails.
pub fn sign_setup(key: &EcKey) -> CryptoResult<(BigNum, BigNum)> {
    let curve_label = key.curve_name().map_or("custom", |c| c.name());
    trace!(curve = curve_label, "ECDSA sign_setup: entry");

    let priv_key = key.private_key().ok_or_else(|| {
        error!("ECDSA sign_setup: missing private key");
        CryptoError::Key("ECDSA sign_setup: missing private key".to_string())
    })?;

    let group = key.group();
    // Use an empty digest for setup-only (random nonce, no deterministic)
    let result = sign_setup_internal(group, priv_key, &[], NonceType::Random)?;

    trace!(curve = curve_label, "ECDSA sign_setup: success");
    Ok(result)
}

// ===========================================================================
// Internal — Sign setup core
// ===========================================================================

/// Core sign setup: generates nonce `k`, computes `r` and `k_inverse`.
///
/// Implements the core logic from `ecdsa_sign_setup()` in
/// `crypto/ec/ecdsa_ossl.c` lines 132–258.
///
/// # Algorithm
///
/// 1. Generate nonce `k` in `[1, order-1]`
/// 2. Compute `(x₁, y₁) = k × G`
/// 3. `r = x₁ mod order`; if `r == 0` return error (caller retries)
/// 4. Compute `k_inverse = k⁻¹ mod order`
/// 5. Return `(k_inverse, r)`
///
/// # Security
///
/// Nonce `k` is zeroed immediately after `k_inverse` is computed.
fn sign_setup_internal(
    group: &EcGroup,
    priv_key: &BigNum,
    digest: &[u8],
    nonce_type: NonceType,
) -> CryptoResult<(BigNum, BigNum)> {
    let order = group.order();

    // Step 1: Generate nonce k
    let mut k = generate_nonce(group, priv_key, digest, nonce_type)?;

    // Step 2: Compute point = k * G
    let point = EcPoint::generator_mul(group, &k)?;

    // Verify the result is not at infinity
    if point.is_at_infinity() {
        k.clear();
        return Err(CryptoError::Key(
            "ECDSA setup: k*G is point at infinity".to_string(),
        ));
    }

    // Step 3: r = x1 mod order
    let x1 = point.x();
    let r_value = nnmod(x1, order)?;

    if r_value.is_zero() {
        k.clear();
        return Err(CryptoError::Key(
            "ECDSA setup: r == 0, retry needed".to_string(),
        ));
    }

    // Step 4: k_inverse = k^-1 mod order
    let k_inv = mod_inverse_checked(&k, order)?;

    // Zero the nonce immediately (AAP §0.7.6)
    k.clear();

    Ok((k_inv, r_value))
}

// ===========================================================================
// Internal — Nonce generation
// ===========================================================================

/// Generates an ECDSA nonce `k` in `[1, order-1]`.
///
/// Translates the nonce generation from `ecdsa_sign_setup()` in
/// `crypto/ec/ecdsa_ossl.c` lines 189–230.
///
/// # Nonce Types
///
/// - [`NonceType::Random`]: Uses `crate::rand::rand_bytes()` to seed
///   rejection sampling. Translates `ossl_bn_priv_rand_range_fixed_top()`.
/// - [`NonceType::Deterministic`]: RFC 6979 HMAC-DRBG based generation.
///   Translates `ossl_gen_deterministic_nonce_rfc6979()`.
///
/// # Security
///
/// The returned nonce MUST be zeroed by the caller after use.
fn generate_nonce(
    group: &EcGroup,
    priv_key: &BigNum,
    digest: &[u8],
    nonce_type: NonceType,
) -> CryptoResult<BigNum> {
    let order = group.order();

    match nonce_type {
        NonceType::Random => generate_random_nonce(order),
        NonceType::Deterministic => generate_deterministic_nonce(order, priv_key, digest),
    }
}

/// Generates a random nonce `k` in `[1, order-1]` using CSPRNG.
///
/// Uses `crate::rand::rand_bytes()` to fill a buffer, then performs
/// rejection sampling to ensure `k` falls in the valid range.
///
/// Translates C `ossl_bn_priv_rand_range_fixed_top(k, order, 0, ctx)`
/// from `crypto/ec/ecdsa_ossl.c` line 211.
fn generate_random_nonce(order: &BigNum) -> CryptoResult<BigNum> {
    let order_byte_len = (order.num_bits() as usize + 7) / 8;

    // Rejection sampling: generate random bytes, reduce to [0, order),
    // reject 0. This is the standard approach.
    for _ in 0..256 {
        // Use SensitiveBytes so nonce seed is auto-zeroed on drop
        let mut buf = SensitiveBytes::new(order_byte_len);
        crate::rand::rand_bytes(buf.as_mut_slice())?;

        // Mask the top bits to match order bit length, reducing rejection rate
        let excess_bits = (order_byte_len * 8) - order.num_bits() as usize;
        if excess_bits > 0 && !buf.as_slice().is_empty() {
            // Rule R6: excess_bits < 8 since order_byte_len = ceil(num_bits/8)
            let mask = 0xFFu8 >> (excess_bits & 7);
            buf.as_mut_slice()[0] &= mask;
        }

        let k = BigNum::from_bytes_be(buf.as_slice());
        // buf is zeroed automatically when dropped (ZeroizeOnDrop)

        // k must be in [1, order-1]
        if !k.is_zero() && k.ucmp(order) == std::cmp::Ordering::Less {
            return Ok(k);
        }
    }

    error!("ECDSA: random nonce generation failed after 256 attempts");
    Err(CryptoError::Rand(
        "ECDSA: random nonce generation failed".to_string(),
    ))
}

/// Generates a deterministic nonce per RFC 6979 using HMAC-DRBG.
///
/// Translates C `ossl_gen_deterministic_nonce_rfc6979()` from
/// `crypto/ec/ecdsa_ossl.c`. The algorithm:
///
/// 1. `x = int2octets(privkey)`
/// 2. `h1 = bits2octets(digest)`
/// 3. Initialize HMAC-DRBG with `K = HMAC(0x00...00, V || 0x00 || x || h1)`
///    then `V = HMAC(K, V)`, then `K = HMAC(K, V || 0x01 || x || h1)`, `V = HMAC(K, V)`
/// 4. Generate candidate `k` from HMAC-DRBG output until `k ∈ [1, order-1]`
///
/// # References
///
/// - RFC 6979, Section 3.2: "Generation of k"
/// - FIPS 186-5, Appendix A.2.1: "Per-Message Secret Number Generation Using
///   Extra Random Bits"
fn generate_deterministic_nonce(
    order: &BigNum,
    priv_key: &BigNum,
    digest: &[u8],
) -> CryptoResult<BigNum> {
    // RFC 6979 Section 3.2 — simplified HMAC-DRBG approach
    // We use a straightforward implementation with SHA-256-based HMAC
    // as the internal hash function.

    let order_byte_len = (order.num_bits() as usize + 7) / 8;

    // Step a: h1 = H(m) — already provided as `digest`

    // Step b: V = 0x01 0x01 ... 0x01 (hash_len bytes)
    let hash_len = 32; // SHA-256 output length
    let mut v = vec![0x01u8; hash_len];

    // Step c: K = 0x00 0x00 ... 0x00 (hash_len bytes)
    let mut k_hmac = vec![0x00u8; hash_len];

    // int2octets(x) — private key as fixed-length big-endian bytes
    let x_bytes = priv_key.to_bytes_be_padded(order_byte_len)?;

    // bits2octets(h1) — digest truncated/padded to order byte length
    let h1_bytes = truncate_digest_bytes(digest, order_byte_len, order.num_bits());

    // Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    k_hmac = hmac_sha256_simple(&k_hmac, &[&v, &[0x00u8], &x_bytes, &h1_bytes]);

    // Step e: V = HMAC_K(V)
    v = hmac_sha256_simple(&k_hmac, &[&v]);

    // Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    k_hmac = hmac_sha256_simple(&k_hmac, &[&v, &[0x01u8], &x_bytes, &h1_bytes]);

    // Step g: V = HMAC_K(V)
    v = hmac_sha256_simple(&k_hmac, &[&v]);

    // Step h: Generate candidates
    for _ in 0..256 {
        // h.1: Generate T (empty initially)
        let mut t = Vec::with_capacity(order_byte_len);

        // h.2: While tlen < qlen, do V = HMAC_K(V); T = T || V
        while t.len() < order_byte_len {
            v = hmac_sha256_simple(&k_hmac, &[&v]);
            t.extend_from_slice(&v);
        }
        t.truncate(order_byte_len);

        // h.3: k = bits2int(T)
        let candidate = BigNum::from_bytes_be(&t);
        t.zeroize();

        // Check k in [1, order-1]
        if !candidate.is_zero() && candidate.ucmp(order) == std::cmp::Ordering::Less {
            // Zero sensitive material
            k_hmac.zeroize();
            v.zeroize();
            return Ok(candidate);
        }

        // h.3 (continued): K = HMAC_K(V || 0x00); V = HMAC_K(V)
        k_hmac = hmac_sha256_simple(&k_hmac, &[&v, &[0x00u8]]);
        v = hmac_sha256_simple(&k_hmac, &[&v]);
    }

    k_hmac.zeroize();
    v.zeroize();

    error!("ECDSA: deterministic nonce generation failed after 256 attempts");
    Err(CryptoError::Rand(
        "ECDSA: deterministic nonce generation failed".to_string(),
    ))
}

// ===========================================================================
// Internal — HMAC-SHA256 helper (for RFC 6979 DRBG)
// ===========================================================================

/// Simplified HMAC-SHA256 for RFC 6979 nonce generation.
///
/// Computes `HMAC-SHA256(key, data[0] || data[1] || ...)`.
///
/// This is a minimal implementation using only basic operations,
/// avoiding `unsafe` code (Rule R8). For production use, this should
/// be replaced with a proper HMAC implementation from the MAC module.
fn hmac_sha256_simple(key: &[u8], data_parts: &[&[u8]]) -> Vec<u8> {
    // HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))
    // where ipad = 0x36 repeated, opad = 0x5C repeated
    let block_size = 64; // SHA-256 block size
    let hash_len = 32; // SHA-256 output size

    // Pad or hash the key to block_size
    let mut padded_key = vec![0u8; block_size];
    if key.len() > block_size {
        let hashed = sha256_simple(key);
        padded_key[..hash_len].copy_from_slice(&hashed);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    // Inner hash: H((K ^ ipad) || m)
    let mut inner_data =
        Vec::with_capacity(block_size + data_parts.iter().map(|d| d.len()).sum::<usize>());
    for &key_byte in &padded_key {
        inner_data.push(key_byte ^ 0x36);
    }
    for part in data_parts {
        inner_data.extend_from_slice(part);
    }
    let inner_hash = sha256_simple(&inner_data);
    inner_data.zeroize();

    // Outer hash: H((K ^ opad) || inner_hash)
    let mut outer_data = Vec::with_capacity(block_size + hash_len);
    for &key_byte in &padded_key {
        outer_data.push(key_byte ^ 0x5C);
    }
    outer_data.extend_from_slice(&inner_hash);
    let result = sha256_simple(&outer_data);

    padded_key.zeroize();
    outer_data.zeroize();

    result
}

/// SHA-256 round constants (FIPS 180-4 Section 4.2.2).
///
/// Placed at module level to satisfy `clippy::items_after_statements`.
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Minimal SHA-256 implementation for HMAC-DRBG in RFC 6979.
///
/// Pure Rust, no `unsafe` (Rule R8). Implements FIPS 180-4.
///
/// Uses `state` array for working variables to avoid single-char names
/// per `clippy::many_single_char_names`.
#[allow(clippy::cast_possible_truncation)] // bit_len: data.len() < 2^32 in practice
fn sha256_simple(data: &[u8]) -> Vec<u8> {
    // SHA-256 initial hash values (FIPS 180-4 Section 5.3.3)
    let mut hash_state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    // Pre-processing: pad the message
    // Rule R6: data.len() is practically bounded well within u64
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for chunk in padded.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for idx in 0..16 {
            schedule[idx] = u32::from_be_bytes([
                chunk[4 * idx],
                chunk[4 * idx + 1],
                chunk[4 * idx + 2],
                chunk[4 * idx + 3],
            ]);
        }
        for idx in 16..64 {
            let sig0 = schedule[idx - 15].rotate_right(7)
                ^ schedule[idx - 15].rotate_right(18)
                ^ (schedule[idx - 15] >> 3);
            let sig1 = schedule[idx - 2].rotate_right(17)
                ^ schedule[idx - 2].rotate_right(19)
                ^ (schedule[idx - 2] >> 10);
            schedule[idx] = schedule[idx - 16]
                .wrapping_add(sig0)
                .wrapping_add(schedule[idx - 7])
                .wrapping_add(sig1);
        }

        // Working variables: [a, b, c, d, e, f, g, h]
        let mut wv = hash_state;

        for idx in 0..64 {
            let big_sig1 = wv[4].rotate_right(6) ^ wv[4].rotate_right(11) ^ wv[4].rotate_right(25);
            let ch = (wv[4] & wv[5]) ^ ((!wv[4]) & wv[6]);
            let temp1 = wv[7]
                .wrapping_add(big_sig1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[idx])
                .wrapping_add(schedule[idx]);
            let big_sig0 = wv[0].rotate_right(2) ^ wv[0].rotate_right(13) ^ wv[0].rotate_right(22);
            let maj = (wv[0] & wv[1]) ^ (wv[0] & wv[2]) ^ (wv[1] & wv[2]);
            let temp2 = big_sig0.wrapping_add(maj);

            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3].wrapping_add(temp1);
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = temp1.wrapping_add(temp2);
        }

        for idx in 0..8 {
            hash_state[idx] = hash_state[idx].wrapping_add(wv[idx]);
        }
    }

    padded.zeroize();

    // Produce final hash
    let mut result = Vec::with_capacity(32);
    for word in &hash_state {
        result.extend_from_slice(&word.to_be_bytes());
    }
    result
}

// ===========================================================================
// Internal — Digest conversion
// ===========================================================================

/// Converts a message digest to a [`BigNum`], truncated to the order bit
/// length.
///
/// Translates `ecdsa_ossl.c` lines 350–375:
/// ```c
/// i = BN_num_bits(order);
/// if (8 * dgst_len > i)
///     dgst_len = (i + 7) / 8;
/// BN_bin2bn(dgst, dgst_len, m);
/// if (8 * dgst_len > i)
///     BN_rshift(m, m, 8 - (i & 0x7));
/// ```
///
/// # Arguments
///
/// * `digest` — Raw digest bytes
/// * `order_bits` — Bit length of the curve order
///
/// # Returns
///
/// A [`BigNum`] representing the truncated digest value.
fn digest_to_bignum(digest: &[u8], order_bits: u32) -> BigNum {
    let mut dgst_len = digest.len();

    // Truncate digest to order byte length if it's longer
    // Rule R6: use checked arithmetic for the conversion
    let order_byte_len = ((order_bits + 7) / 8) as usize;

    if dgst_len > order_byte_len {
        dgst_len = order_byte_len;
    }

    let m = BigNum::from_bytes_be(&digest[..dgst_len]);

    // If the digest bit length exceeds the order bit length after byte
    // truncation, right-shift to remove excess bits.
    // This handles the case where order_bits is not a multiple of 8.
    // Rule R6: use saturating_mul to prevent overflow; dgst_len is bounded
    // by digest.len() which is practically < 2^31, so this won't saturate.
    #[allow(clippy::cast_possible_truncation)]
    // TRUNCATION: dgst_len is bounded by digest byte length (< 2^31 in practice)
    let dgst_bits = (dgst_len as u32).saturating_mul(8);
    if dgst_bits > order_bits {
        let shift = dgst_bits - order_bits;
        rshift(&m, shift)
    } else {
        m
    }
}

/// Truncates digest bytes for RFC 6979 `bits2octets` operation.
///
/// Returns a byte slice of `target_len` bytes representing the digest
/// value reduced to the order's bit length.
fn truncate_digest_bytes(digest: &[u8], target_len: usize, order_bits: u32) -> Vec<u8> {
    let mut result = if digest.len() >= target_len {
        digest[..target_len].to_vec()
    } else {
        let mut buf = vec![0u8; target_len];
        buf[target_len - digest.len()..].copy_from_slice(digest);
        buf
    };

    // Mask excess bits in the first byte
    let excess_bits = (target_len * 8).saturating_sub(order_bits as usize);
    if excess_bits > 0 && !result.is_empty() {
        let mask = 0xFFu8 >> (excess_bits & 7);
        result[0] &= mask;
    }

    result
}

// ===========================================================================
// Internal — DER encoding/decoding helpers
// ===========================================================================

/// DER-encodes an ECDSA signature as ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`.
///
/// Replaces C `i2d_ECDSA_SIG()`. The encoding follows X9.62 / SEC 1:
/// ```text
/// ECDSASignature ::= SEQUENCE {
///     r   INTEGER,
///     s   INTEGER
/// }
/// ```
///
/// ASN.1 INTEGERs are signed, so a leading 0x00 byte is prepended
/// when the high bit of the magnitude is set (to distinguish from
/// negative values).
fn encode_signature_der(sig: &EcdsaSignature) -> Vec<u8> {
    let r_bytes = sig.r.to_bytes_be();
    let s_bytes = sig.s.to_bytes_be();

    // Encode r as ASN.1 INTEGER (prepend 0x00 if high bit set)
    let r_der = encode_asn1_integer(&r_bytes);
    let s_der = encode_asn1_integer(&s_bytes);

    // SEQUENCE = 0x30, length, contents
    let content_len = r_der.len() + s_der.len();
    let mut result = Vec::with_capacity(2 + content_len + 2); // +2 for possible long form

    result.push(0x30); // SEQUENCE tag
    encode_asn1_length(content_len, &mut result);
    result.extend_from_slice(&r_der);
    result.extend_from_slice(&s_der);

    result
}

/// Parses a DER-encoded ECDSA signature.
///
/// Replaces C `d2i_ECDSA_SIG()`. Validates the ASN.1 structure and
/// extracts the `r` and `s` INTEGER components.
fn decode_signature_der(der: &[u8]) -> CryptoResult<EcdsaSignature> {
    if der.len() < 6 {
        return Err(CryptoError::Encoding(
            "ECDSA DER: signature too short".to_string(),
        ));
    }

    // Parse SEQUENCE tag
    if der[0] != 0x30 {
        return Err(CryptoError::Encoding(
            "ECDSA DER: expected SEQUENCE tag 0x30".to_string(),
        ));
    }

    let (seq_len, seq_hdr_len) = decode_asn1_length(&der[1..])?;
    let seq_content = &der[1 + seq_hdr_len..];

    if seq_content.len() < seq_len {
        return Err(CryptoError::Encoding(
            "ECDSA DER: sequence content truncated".to_string(),
        ));
    }

    // Parse r INTEGER
    let (r_value, r_consumed) = decode_asn1_integer(seq_content)?;

    // Parse s INTEGER
    let s_data = &seq_content[r_consumed..];
    let (s_value, _s_consumed) = decode_asn1_integer(s_data)?;

    // Validate components are positive
    if r_value.is_zero() || r_value.is_negative() {
        return Err(CryptoError::Encoding(
            "ECDSA DER: r must be positive".to_string(),
        ));
    }
    if s_value.is_zero() || s_value.is_negative() {
        return Err(CryptoError::Encoding(
            "ECDSA DER: s must be positive".to_string(),
        ));
    }

    Ok(EcdsaSignature::new(r_value, s_value))
}

/// Encodes a big-endian unsigned integer as an ASN.1 INTEGER TLV.
///
/// ASN.1 INTEGERs are signed; if the high bit of the first byte is set,
/// a leading 0x00 is prepended to indicate a positive value.
fn encode_asn1_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros (but keep at least one byte)
    let stripped = strip_leading_zeros(bytes);

    // Determine if we need a leading 0x00 (high bit set = would look negative)
    let needs_pad = !stripped.is_empty() && (stripped[0] & 0x80) != 0;
    let value_len = if needs_pad {
        stripped.len() + 1
    } else if stripped.is_empty() {
        1
    } else {
        stripped.len()
    };

    let mut result = Vec::with_capacity(2 + value_len + 2);
    result.push(0x02); // INTEGER tag
    encode_asn1_length(value_len, &mut result);

    if needs_pad {
        result.push(0x00);
    }
    if stripped.is_empty() {
        result.push(0x00);
    } else {
        result.extend_from_slice(stripped);
    }

    result
}

/// Decodes an ASN.1 INTEGER TLV, returning `(BigNum, bytes_consumed)`.
fn decode_asn1_integer(data: &[u8]) -> CryptoResult<(BigNum, usize)> {
    if data.is_empty() {
        return Err(CryptoError::Encoding(
            "ECDSA DER: empty INTEGER data".to_string(),
        ));
    }

    if data[0] != 0x02 {
        return Err(CryptoError::Encoding(format!(
            "ECDSA DER: expected INTEGER tag 0x02, got 0x{:02x}",
            data[0]
        )));
    }

    let (int_len, hdr_len) = decode_asn1_length(&data[1..])?;
    let total_consumed = 1 + hdr_len + int_len;

    if data.len() < total_consumed {
        return Err(CryptoError::Encoding(
            "ECDSA DER: INTEGER content truncated".to_string(),
        ));
    }

    let int_bytes = &data[1 + hdr_len..1 + hdr_len + int_len];

    // Check for negative (high bit set without leading 0x00)
    if !int_bytes.is_empty() && (int_bytes[0] & 0x80) != 0 {
        return Err(CryptoError::Encoding(
            "ECDSA DER: negative INTEGER not allowed in signature".to_string(),
        ));
    }

    // Skip leading 0x00 padding byte if present
    let value_bytes = if int_bytes.len() > 1 && int_bytes[0] == 0x00 {
        &int_bytes[1..]
    } else {
        int_bytes
    };

    let value = if value_bytes.is_empty() {
        BigNum::zero()
    } else {
        BigNum::from_bytes_be(value_bytes)
    };

    Ok((value, total_consumed))
}

/// Encodes an ASN.1 length into DER format.
///
/// - Short form (0–127): single byte
/// - Long form (128+): `0x80 | num_length_bytes`, then length bytes
fn encode_asn1_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        // Rule R6: len < 128 always fits in u8
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len < 256 {
        out.push(0x81);
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        // Rule R6: use checked conversion
        out.push(0x82);
        let high = u8::try_from((len >> 8) & 0xFF).unwrap_or(0);
        let low = u8::try_from(len & 0xFF).unwrap_or(0);
        out.push(high);
        out.push(low);
    }
}

/// Decodes an ASN.1 length from DER format.
///
/// Returns `(length_value, header_bytes_consumed)`.
fn decode_asn1_length(data: &[u8]) -> CryptoResult<(usize, usize)> {
    if data.is_empty() {
        return Err(CryptoError::Encoding(
            "ECDSA DER: unexpected end of length".to_string(),
        ));
    }

    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err(CryptoError::Encoding(
                "ECDSA DER: truncated length".to_string(),
            ));
        }
        Ok((data[1] as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err(CryptoError::Encoding(
                "ECDSA DER: truncated length".to_string(),
            ));
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((len, 3))
    } else {
        Err(CryptoError::Encoding(format!(
            "ECDSA DER: unsupported length encoding 0x{first:02x}"
        )))
    }
}

/// Strips leading zero bytes from a big-endian byte slice.
///
/// Returns a reference to the slice starting at the first non-zero byte.
/// If all bytes are zero, returns an empty slice.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // EcdsaSignature tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_signature_new_and_accessors() {
        let r = BigNum::from_u64(12345);
        let s = BigNum::from_u64(67890);
        let sig = EcdsaSignature::new(r.clone(), s.clone());

        assert_eq!(sig.r(), &r);
        assert_eq!(sig.s(), &s);
    }

    #[test]
    fn test_signature_into_components() {
        let r = BigNum::from_u64(111);
        let s = BigNum::from_u64(222);
        let sig = EcdsaSignature::new(r.clone(), s.clone());

        let (r_out, s_out) = sig.into_components();
        assert_eq!(r_out, r);
        assert_eq!(s_out, s);
    }

    #[test]
    fn test_signature_equality() {
        let sig1 = EcdsaSignature::new(BigNum::from_u64(42), BigNum::from_u64(99));
        let sig2 = EcdsaSignature::new(BigNum::from_u64(42), BigNum::from_u64(99));
        let sig3 = EcdsaSignature::new(BigNum::from_u64(42), BigNum::from_u64(100));

        assert_eq!(sig1, sig2);
        assert_ne!(sig1, sig3);
    }

    // -----------------------------------------------------------------------
    // DER encoding/decoding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_der_roundtrip_small_values() {
        let sig = EcdsaSignature::new(BigNum::from_u64(1), BigNum::from_u64(2));
        let der = sig.to_der().expect("DER encode should succeed");
        let decoded = EcdsaSignature::from_der(&der).expect("DER decode should succeed");

        assert_eq!(sig, decoded);
    }

    #[test]
    fn test_der_roundtrip_large_values() {
        // Use values that require leading 0x00 padding (high bit set)
        let r = BigNum::from_bytes_be(&[0x80, 0x01, 0x02, 0x03]);
        let s = BigNum::from_bytes_be(&[0xFF, 0xFE, 0xFD, 0xFC]);
        let sig = EcdsaSignature::new(r, s);

        let der = sig.to_der().expect("DER encode should succeed");
        let decoded = EcdsaSignature::from_der(&der).expect("DER decode should succeed");

        assert_eq!(sig, decoded);
    }

    #[test]
    fn test_der_decode_invalid_tag() {
        // Not a SEQUENCE
        let bad_der = [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        assert!(EcdsaSignature::from_der(&bad_der).is_err());
    }

    #[test]
    fn test_der_decode_truncated() {
        let short = [0x30, 0x06, 0x02];
        assert!(EcdsaSignature::from_der(&short).is_err());
    }

    // -----------------------------------------------------------------------
    // Digest-to-BigNum conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_digest_to_bignum_shorter_than_order() {
        // 128-bit digest, 256-bit order
        let digest = [0x01u8; 16];
        let m = digest_to_bignum(&digest, 256);
        assert!(!m.is_zero());
    }

    #[test]
    fn test_digest_to_bignum_longer_than_order() {
        // 256-bit digest (32 bytes), 160-bit order
        let digest = [0xABu8; 32];
        let m = digest_to_bignum(&digest, 160);
        // After truncation, m should have at most 160 bits
        assert!(m.num_bits() <= 160);
    }

    #[test]
    fn test_digest_to_bignum_exact_match() {
        let digest = [0x7Fu8; 32]; // 256-bit digest
        let m = digest_to_bignum(&digest, 256);
        assert!(!m.is_zero());
    }

    // -----------------------------------------------------------------------
    // NonceType tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_nonce_type_enum() {
        assert_eq!(NonceType::Random, NonceType::Random);
        assert_ne!(NonceType::Random, NonceType::Deterministic);
    }

    // -----------------------------------------------------------------------
    // SHA-256 sanity test
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_empty_string() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
        let hash = sha256_simple(b"");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
        assert_eq!(hash[2], 0xc4);
        assert_eq!(hash[3], 0x42);
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223...
        let hash = sha256_simple(b"abc");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash[0], 0xba);
        assert_eq!(hash[1], 0x78);
        assert_eq!(hash[2], 0x16);
        assert_eq!(hash[3], 0xbf);
    }

    // -----------------------------------------------------------------------
    // ASN.1 helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_asn1_integer_small() {
        let encoded = encode_asn1_integer(&[0x42]);
        // 0x02 (tag) 0x01 (len) 0x42 (value)
        assert_eq!(encoded, vec![0x02, 0x01, 0x42]);
    }

    #[test]
    fn test_encode_asn1_integer_high_bit() {
        let encoded = encode_asn1_integer(&[0x80]);
        // Needs leading 0x00: 0x02 (tag) 0x02 (len) 0x00 0x80
        assert_eq!(encoded, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn test_encode_asn1_integer_zero() {
        let encoded = encode_asn1_integer(&[0x00]);
        // 0x02 0x01 0x00
        assert_eq!(encoded, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_strip_leading_zeros() {
        assert_eq!(strip_leading_zeros(&[0x00, 0x00, 0x42]), &[0x42]);
        assert_eq!(strip_leading_zeros(&[0x42, 0x00]), &[0x42, 0x00]);
        assert_eq!(strip_leading_zeros(&[0x00, 0x00, 0x00]), &[] as &[u8]);
        assert_eq!(strip_leading_zeros(&[0x80]), &[0x80]);
    }

    // -----------------------------------------------------------------------
    // HMAC-SHA256 test
    // -----------------------------------------------------------------------

    #[test]
    fn test_hmac_sha256_rfc4231_test1() {
        // RFC 4231 Test Case 1:
        // Key  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
        // Data = "Hi There"
        // HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha256_simple(&key, &[data.as_slice()]);
        assert_eq!(result[0], 0xb0);
        assert_eq!(result[1], 0x34);
        assert_eq!(result[2], 0x4c);
        assert_eq!(result[3], 0x61);
    }
}
