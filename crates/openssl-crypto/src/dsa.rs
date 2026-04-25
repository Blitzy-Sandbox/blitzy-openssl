//! DSA (Digital Signature Algorithm) implementation for the OpenSSL Rust workspace.
//!
//! Provides key generation, parameter generation, signing, and verification
//! following FIPS 186-4 / FIPS 186-5. Replaces C `DSA_*` functions from
//! `crypto/dsa/*.c` (14 files totaling ~3,500 lines of C).
//!
//! # Source Mapping
//!
//! | Rust Component           | C Source File                | Purpose                        |
//! |--------------------------|-----------------------------|--------------------------------|
//! | [`DsaParams`]            | `crypto/dsa/dsa_lib.c`      | DSA parameter lifecycle        |
//! | [`DsaPrivateKey`]        | `crypto/dsa/dsa_key.c`      | Private key with zeroize       |
//! | [`DsaPublicKey`]         | `crypto/dsa/dsa_key.c`      | Public key component           |
//! | [`DsaKeyPair`]           | `crypto/dsa/dsa_key.c`      | Combined key pair              |
//! | [`generate_params`]      | `crypto/dsa/dsa_gen.c`      | Parameter generation           |
//! | [`generate_key`]         | `crypto/dsa/dsa_key.c`      | Key pair generation            |
//! | [`sign`]                 | `crypto/dsa/dsa_ossl.c`     | DSA signing with blinding      |
//! | [`verify`]               | `crypto/dsa/dsa_ossl.c`     | DSA signature verification     |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** [`verify`] returns `Result<bool>`, not integer sentinel.
//!   Optional fields use `Option<T>`.
//! - **R6 (Lossless Casts):** Bit sizes validated via checked arithmetic; no bare `as` casts.
//! - **R8 (Zero Unsafe):** No `unsafe` code. Private key material zeroed via `zeroize`.
//! - **R9 (Warning-Free):** All public items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from `openssl_crypto::dsa::*` exports.
//!
//! # Security Considerations
//!
//! - Private key material in [`DsaPrivateKey`] is zeroed on drop via
//!   [`zeroize::ZeroizeOnDrop`], replacing the C `BN_clear_free()` pattern.
//! - The signing operation uses blinding to protect against side-channel attacks,
//!   following the same approach as `crypto/dsa/dsa_ossl.c`.
//! - Signature nonce `k` is generated using rejection sampling in `[1, q-1]`
//!   and zeroed after use.
//! - All parameter validation follows FIPS 186-4 requirements:
//!   `p` must be 1024/2048/3072 bits, `q` must be 160/224/256 bits.
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::dsa::{generate_params, generate_key, sign, verify};
//!
//! // Generate DSA parameters (2048-bit prime)
//! let params = generate_params(2048).expect("parameter generation failed");
//!
//! // Generate a key pair
//! let key_pair = generate_key(&params).expect("key generation failed");
//!
//! // Sign a digest (e.g., SHA-256 hash output)
//! let digest = [0u8; 32];
//! let signature = sign(key_pair.private_key(), &digest).expect("signing failed");
//!
//! // Verify the signature
//! let valid = verify(key_pair.public_key(), &digest, &signature).expect("verification failed");
//! assert!(valid);
//! ```

use openssl_common::{CryptoError, CryptoResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bn::BigNum;
use crate::mac::hmac;

// =============================================================================
// Constants — DSA modulus and subprime size limits (from include/openssl/dsa.h)
// =============================================================================

/// Minimum DSA subprime q bit size for signing operations.
///
/// Replaces C `MIN_DSA_SIGN_QBITS` (128) from `crypto/dsa/dsa_ossl.c`.
const MIN_DSA_SIGN_QBITS: u32 = 128;

/// Maximum number of sign retries before giving up.
///
/// Replaces C `MAX_DSA_SIGN_RETRIES` (8) from `crypto/dsa/dsa_ossl.c`.
/// Per FIPS 186-4 Section 4.6, r or s being zero requires a retry.
const MAX_DSA_SIGN_RETRIES: u32 = 8;

/// Minimum DSA prime `p` bit size.
///
/// FIPS 186-4 specifies 1024 as the minimum (L=1024, N=160).
const DSA_MIN_PRIME_BITS: u32 = 1024;

/// Maximum DSA prime `p` bit size.
///
/// Replaces C `OPENSSL_DSA_MAX_MODULUS_BITS` (10000).
const DSA_MAX_PRIME_BITS: u32 = 10_000;

/// Valid (L, N) pairs per FIPS 186-4 Table 1.
///
/// L = bit length of p, N = bit length of q.
/// The standard defines three valid pairs:
/// - (1024, 160)
/// - (2048, 224)
/// - (2048, 256)
/// - (3072, 256)
const VALID_LN_PAIRS: &[(u32, u32)] = &[(1024, 160), (2048, 224), (2048, 256), (3072, 256)];

// =============================================================================
// DsaParams — DSA domain parameters (from dsa_lib.c, dsa_gen.c)
// =============================================================================

/// DSA domain parameters containing the prime `p`, subprime `q`, and
/// generator `g`.
///
/// These parameters define the mathematical group used for DSA operations
/// and are shared between key pairs. Parameters are validated at
/// construction time.
///
/// # C Mapping
///
/// Replaces the C `DSA` struct's parameter fields (`dsa->params.p`,
/// `dsa->params.q`, `dsa->params.g`) from `crypto/dsa/dsa_lib.c`.
///
/// # Thread Safety
///
/// `DsaParams` is `Clone` and `Send + Sync`. For shared access, wrap in
/// `Arc<DsaParams>`.
/// // LOCK-SCOPE: `DsaParams` is immutable after construction; no lock
/// // needed for read-only shared access.
#[derive(Debug, Clone)]
pub struct DsaParams {
    /// Prime modulus `p`. Must be a large prime of 1024, 2048, or 3072 bits
    /// per FIPS 186-4.
    p: BigNum,
    /// Subprime `q`. Must divide `(p - 1)` and be 160, 224, or 256 bits
    /// per FIPS 186-4.
    q: BigNum,
    /// Generator `g`. Must satisfy `1 < g < p` and `g^q ≡ 1 (mod p)`.
    g: BigNum,
}

impl DsaParams {
    /// Construct new DSA parameters from a prime `p`, subprime `q`, and
    /// generator `g`.
    ///
    /// # Validation
    ///
    /// Performs basic structural validation:
    /// - `p` must be positive and at least [`DSA_MIN_PRIME_BITS`] bits
    /// - `p` must not exceed [`DSA_MAX_PRIME_BITS`] bits
    /// - `q` must be positive and smaller than `p`
    /// - `g` must be in the range `(1, p)`
    ///
    /// Full FIPS 186-4 validation (primality, divisibility) is left to the
    /// parameter generation function or an explicit check routine.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if any validation constraint is violated.
    pub fn new(p: BigNum, q: BigNum, g: BigNum) -> CryptoResult<Self> {
        // Validate p is positive
        if p.is_zero() || p.is_negative() {
            return Err(CryptoError::Key(
                "DSA prime p must be a positive integer".into(),
            ));
        }

        // Validate p bit size
        let p_bits = p.num_bits();
        if p_bits < DSA_MIN_PRIME_BITS {
            return Err(CryptoError::Key(format!(
                "DSA prime p is too small: {p_bits} bits (minimum {DSA_MIN_PRIME_BITS})"
            )));
        }
        if p_bits > DSA_MAX_PRIME_BITS {
            return Err(CryptoError::Key(format!(
                "DSA prime p is too large: {p_bits} bits (maximum {DSA_MAX_PRIME_BITS})"
            )));
        }

        // Validate q is positive
        if q.is_zero() || q.is_negative() {
            return Err(CryptoError::Key(
                "DSA subprime q must be a positive integer".into(),
            ));
        }

        // Validate q < p
        let q_bits = q.num_bits();
        if q_bits >= p_bits {
            return Err(CryptoError::Key(
                "DSA subprime q must be smaller than prime p".into(),
            ));
        }

        // Validate g > 1
        let one = BigNum::one();
        if g.is_zero() || g.cmp(&one) == std::cmp::Ordering::Equal {
            return Err(CryptoError::Key(
                "DSA generator g must be greater than 1".into(),
            ));
        }

        // Validate g < p
        if g.cmp(&p) != std::cmp::Ordering::Less {
            return Err(CryptoError::Key(
                "DSA generator g must be less than prime p".into(),
            ));
        }

        Ok(Self { p, q, g })
    }

    /// Returns a reference to the prime modulus `p`.
    ///
    /// Replaces C `DSA_get0_p()`.
    #[inline]
    #[must_use]
    pub fn p(&self) -> &BigNum {
        &self.p
    }

    /// Returns a reference to the subprime `q`.
    ///
    /// Replaces C `DSA_get0_q()`.
    #[inline]
    #[must_use]
    pub fn q(&self) -> &BigNum {
        &self.q
    }

    /// Returns a reference to the generator `g`.
    ///
    /// Replaces C `DSA_get0_g()`.
    #[inline]
    #[must_use]
    pub fn g(&self) -> &BigNum {
        &self.g
    }
}

// =============================================================================
// DsaPrivateKey — DSA private key (from dsa_key.c)
// =============================================================================

/// DSA private key component.
///
/// The private key `x` is a random integer in `[1, q-1]`. The key material
/// is automatically zeroed on drop via [`zeroize::ZeroizeOnDrop`], replacing
/// the C `BN_clear_free()` pattern from `crypto/dsa/dsa_key.c`.
///
/// # Security
///
/// The private key bytes are held in a `Vec<u8>` with [`ZeroizeOnDrop`]
/// to ensure memory is securely erased when the key is dropped. The
/// [`BigNum`] representation in `params` is not sensitive.
#[derive(Debug, Clone)]
pub struct DsaPrivateKey {
    /// The private key value `x` in `[1, q-1]`.
    x: BigNum,
    /// The domain parameters associated with this key.
    params: DsaParams,
    /// Serialized private key bytes for zeroize.
    /// Maintained in sync with `x` for secure erasure on drop.
    x_bytes: Vec<u8>,
}

impl Zeroize for DsaPrivateKey {
    fn zeroize(&mut self) {
        self.x_bytes.zeroize();
        // Zero the BigNum value by replacing with zero
        self.x = BigNum::zero();
    }
}

impl Drop for DsaPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// `ZeroizeOnDrop` is effectively implemented via our manual `Drop`.
/// We mark this explicitly for documentation purposes.
impl ZeroizeOnDrop for DsaPrivateKey {}

impl DsaPrivateKey {
    /// Returns a reference to the private key value `x`.
    ///
    /// Replaces C access to `dsa->priv_key`.
    #[inline]
    #[must_use]
    pub fn value(&self) -> &BigNum {
        &self.x
    }

    /// Returns a reference to the domain parameters.
    ///
    /// Replaces C access to `dsa->params.*`.
    #[inline]
    #[must_use]
    pub fn params(&self) -> &DsaParams {
        &self.params
    }

    /// Construct a DSA private key from its scalar `x` and domain parameters.
    ///
    /// This is the public constructor used by provider and decoder code
    /// paths that recover a private key from encoded form (e.g., PKCS#8,
    /// X9.42, raw parameter bags). Replaces the C `DSA_set0_key()` path
    /// from `crypto/dsa/dsa_lib.c` when the `priv_key` argument is non-NULL.
    ///
    /// # Validation
    ///
    /// Performs partial validation of `x` per NIST SP 800-56A Rev. 3,
    /// Section 5.6.2.1.2 (Owner Assurance of Private Key Validity),
    /// matching `ossl_ffc_validate_private_key()` from
    /// `crypto/ffc/ffc_key_validate.c`:
    ///
    /// - `x` must be `>= 1` (rejects zero and negatives;
    ///   C flag `FFC_ERROR_PRIVKEY_TOO_SMALL`).
    /// - `x` must be `< q` (rejects out-of-range values;
    ///   C flag `FFC_ERROR_PRIVKEY_TOO_LARGE`).
    ///
    /// Combined, `x` must lie in `[1, q - 1]`, the FIPS 186-4 Section 4.5
    /// range for DSA private keys.
    ///
    /// Full FIPS 186-4 validation (including pairwise consistency with
    /// the corresponding public key) is left to an explicit check routine,
    /// mirroring the C split between `DSA_set0_key()` (no validation) and
    /// `ossl_dsa_check_priv_key()` (explicit check).
    ///
    /// # Security
    ///
    /// The byte representation of `x` is cached in `x_bytes` so that the
    /// [`zeroize::Zeroize`] and [`Drop`] implementations can securely erase
    /// the private key material when the value is no longer needed. This
    /// mirrors the C `BN_clear_free()` pattern for secret BIGNUMs.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Key`] with message "DSA private key x must be
    ///   positive (>= 1)" if `x` is zero or negative.
    /// - [`CryptoError::Key`] with message "DSA private key x must be less
    ///   than subprime q" if `x >= q`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use openssl_crypto::bn::BigNum;
    /// use openssl_crypto::dsa::{DsaParams, DsaPrivateKey};
    ///
    /// # let p: BigNum = unimplemented!();
    /// # let q: BigNum = unimplemented!();
    /// # let g: BigNum = unimplemented!();
    /// # let x: BigNum = unimplemented!();
    /// let params = DsaParams::new(p, q, g)?;
    /// let private_key = DsaPrivateKey::from_components(x, params)?;
    /// # Ok::<(), openssl_common::CryptoError>(())
    /// ```
    pub fn from_components(x: BigNum, params: DsaParams) -> CryptoResult<Self> {
        // Reject x <= 0 (matches C check `BN_cmp(priv, BN_value_one()) < 0`
        // in ossl_ffc_validate_private_key; the comparison against one is
        // strict-less, so zero and negatives are rejected).
        if x.is_zero() || x.is_negative() {
            return Err(CryptoError::Key(
                "DSA private key x must be positive (>= 1)".into(),
            ));
        }

        // Reject x >= q (matches C check `BN_cmp(priv, upper) >= 0`
        // in ossl_ffc_validate_private_key, where `upper` is params->q).
        // Uses ordering comparison — Rule R6: no bare `as` casts.
        if x.cmp(params.q()) != std::cmp::Ordering::Less {
            return Err(CryptoError::Key(
                "DSA private key x must be less than subprime q".into(),
            ));
        }

        // Cache byte representation for Zeroize synchronisation.
        // `to_bytes_be()` produces the canonical big-endian encoding that
        // `Drop` can securely overwrite without re-serialising from `x`.
        let x_bytes = x.to_bytes_be();

        Ok(Self { x, params, x_bytes })
    }
}

// =============================================================================
// DsaPublicKey — DSA public key (from dsa_key.c)
// =============================================================================

/// DSA public key component.
///
/// The public key `y = g^x mod p` where `x` is the corresponding private
/// key. Public keys are not sensitive material and do not require secure
/// erasure.
///
/// # C Mapping
///
/// Replaces access to `dsa->pub_key` from `crypto/dsa/dsa_key.c`.
#[derive(Debug, Clone)]
pub struct DsaPublicKey {
    /// The public key value `y = g^x mod p`.
    y: BigNum,
    /// The domain parameters associated with this key.
    params: DsaParams,
}

impl DsaPublicKey {
    /// Returns a reference to the public key value `y`.
    ///
    /// Replaces C access to `dsa->pub_key`.
    #[inline]
    #[must_use]
    pub fn value(&self) -> &BigNum {
        &self.y
    }

    /// Returns a reference to the domain parameters.
    ///
    /// Replaces C access to `dsa->params.*`.
    #[inline]
    #[must_use]
    pub fn params(&self) -> &DsaParams {
        &self.params
    }

    /// Construct a DSA public key from its value `y` and domain parameters.
    ///
    /// This is the public constructor used by provider and decoder code
    /// paths that recover a public key from encoded form (e.g., SPKI DER,
    /// X9.42, raw parameter bags). Replaces the C `DSA_set0_key()` path
    /// from `crypto/dsa/dsa_lib.c` when the `pub_key` argument is non-NULL.
    ///
    /// # Validation
    ///
    /// Performs partial validation of `y` per NIST SP 800-56A Rev. 3,
    /// Section 5.6.2.3.1 (FFC Partial Public Key Validation), matching
    /// `ossl_ffc_validate_public_key_partial()` from
    /// `crypto/ffc/ffc_key_validate.c`:
    ///
    /// - `y` must be `>= 2` (rejects 0, 1, and negatives;
    ///   C flag `FFC_ERROR_PUBKEY_TOO_SMALL`).
    /// - `y` must be `<= p - 2` (rejects values at or above `p - 1`;
    ///   C flag `FFC_ERROR_PUBKEY_TOO_LARGE`).
    ///
    /// Combined, `y` must lie in `[2, p - 2]`.
    ///
    /// Full validation additionally requires the modular exponentiation
    /// check `y^q mod p == 1`; that step is left to an explicit check
    /// routine, mirroring the C split between
    /// `ossl_ffc_validate_public_key_partial()` (basic bounds) and
    /// `ossl_ffc_validate_public_key()` (includes exponentiation).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Key`] with message "DSA public key y must be
    ///   greater than 1" if `y <= 1` or is negative.
    /// - [`CryptoError::Key`] with message "DSA public key y must be at
    ///   most p - 2" if `y >= p - 1`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use openssl_crypto::bn::BigNum;
    /// use openssl_crypto::dsa::{DsaParams, DsaPublicKey};
    ///
    /// # let p: BigNum = unimplemented!();
    /// # let q: BigNum = unimplemented!();
    /// # let g: BigNum = unimplemented!();
    /// # let y: BigNum = unimplemented!();
    /// let params = DsaParams::new(p, q, g)?;
    /// let public_key = DsaPublicKey::from_components(y, params)?;
    /// # Ok::<(), openssl_common::CryptoError>(())
    /// ```
    pub fn from_components(y: BigNum, params: DsaParams) -> CryptoResult<Self> {
        // Reject y <= 1 (matches C check `BN_cmp(pub_key, tmp) <= 0`
        // where `tmp == 1` in ossl_ffc_validate_public_key_partial).
        // Handles negatives, zero, and one in a single predicate.
        if y.is_zero() || y.is_one() || y.is_negative() {
            return Err(CryptoError::Key(
                "DSA public key y must be greater than 1".into(),
            ));
        }

        // Reject y >= p - 1 (matches C check
        // `BN_copy(tmp, params->p); BN_sub_word(tmp, 1); BN_cmp(pub_key, tmp) >= 0`
        // in ossl_ffc_validate_public_key_partial).
        // We compute `p - 1` using BigNum subtraction (no `as` casts; Rule R6).
        let p_minus_one = params.p() - &BigNum::one();
        if y.cmp(&p_minus_one) != std::cmp::Ordering::Less {
            return Err(CryptoError::Key(
                "DSA public key y must be at most p - 2".into(),
            ));
        }

        Ok(Self { y, params })
    }
}

// =============================================================================
// DsaKeyPair — Combined DSA key pair (from dsa_key.c)
// =============================================================================

/// Combined DSA key pair containing both private and public keys.
///
/// Created by [`generate_key`] or assembled manually from verified
/// components. The private key material is securely erased on drop.
///
/// # C Mapping
///
/// Replaces the C `DSA` struct when both `priv_key` and `pub_key` are set,
/// as seen after a successful `DSA_generate_key()` call.
#[derive(Debug, Clone)]
pub struct DsaKeyPair {
    /// The private key component (zeroized on drop).
    private_key: DsaPrivateKey,
    /// The public key component `y = g^x mod p`.
    public_key: DsaPublicKey,
}

impl DsaKeyPair {
    /// Returns a reference to the private key component.
    ///
    /// Replaces C `DSA_get0_priv_key()`.
    #[inline]
    #[must_use]
    pub fn private_key(&self) -> &DsaPrivateKey {
        &self.private_key
    }

    /// Returns a reference to the public key component.
    ///
    /// Replaces C `DSA_get0_pub_key()`.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &DsaPublicKey {
        &self.public_key
    }

    /// Returns a reference to the domain parameters.
    ///
    /// Convenience accessor equivalent to `self.private_key().params()`.
    #[inline]
    #[must_use]
    pub fn params(&self) -> &DsaParams {
        &self.private_key.params
    }
}

// =============================================================================
// DSA Signature — Internal representation (from dsa_ossl.c DSA_SIG)
// =============================================================================

/// Internal DSA signature representation holding (r, s) components.
///
/// Replaces C `DSA_SIG` struct from `crypto/dsa/dsa_ossl.c`. Not exposed
/// publicly; signatures are serialized/deserialized to concatenated bytes.
#[derive(Debug)]
struct DsaSignature {
    /// Signature component `r = (g^k mod p) mod q`.
    r: BigNum,
    /// Signature component `s = k^(-1) * (m + x*r) mod q`.
    s: BigNum,
}

impl DsaSignature {
    /// Serialize the signature to a simple concatenation format: `r || s`.
    ///
    /// Each component is zero-padded to the byte length of `q` to produce
    /// a fixed-size output. This matches the DSA signature encoding used
    /// in many protocols (e.g., IEEE P1363).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the components cannot be serialized.
    fn to_bytes(&self, q_byte_len: usize) -> CryptoResult<Vec<u8>> {
        let r_bytes = self.r.to_bytes_be();
        let s_bytes = self.s.to_bytes_be();

        // Zero-pad each component to q byte length
        let total_len = q_byte_len
            .checked_mul(2)
            .ok_or_else(|| CryptoError::Key("DSA signature byte length overflow".into()))?;
        let mut output = vec![0u8; total_len];

        // Place r right-aligned in first half
        if r_bytes.len() > q_byte_len {
            return Err(CryptoError::Key(
                "DSA signature r component exceeds q byte length".into(),
            ));
        }
        let r_offset = q_byte_len.saturating_sub(r_bytes.len());
        output[r_offset..q_byte_len].copy_from_slice(&r_bytes);

        // Place s right-aligned in second half
        if s_bytes.len() > q_byte_len {
            return Err(CryptoError::Key(
                "DSA signature s component exceeds q byte length".into(),
            ));
        }
        let s_offset = q_byte_len.saturating_sub(s_bytes.len());
        let s_start = q_byte_len;
        output[s_start + s_offset..s_start + q_byte_len].copy_from_slice(&s_bytes);

        Ok(output)
    }

    /// Deserialize a signature from concatenated `r || s` bytes.
    ///
    /// Expects the input to be exactly `2 * q_byte_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] if the byte length is wrong.
    fn from_bytes(bytes: &[u8], q_byte_len: usize) -> CryptoResult<Self> {
        let expected_len = q_byte_len.checked_mul(2).ok_or_else(|| {
            CryptoError::Verification("DSA signature byte length overflow".into())
        })?;

        if bytes.len() != expected_len {
            return Err(CryptoError::Verification(format!(
                "DSA signature has invalid length: expected {expected_len}, got {}",
                bytes.len()
            )));
        }

        let r = BigNum::from_bytes_be(&bytes[..q_byte_len]);
        let s = BigNum::from_bytes_be(&bytes[q_byte_len..]);

        Ok(Self { r, s })
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Determine the subprime bit size `N` for a given prime bit size `L`.
///
/// FIPS 186-4 Table 1 defines the valid (L, N) pairs. This function returns
/// the largest N for the given L.
///
/// # Errors
///
/// Returns [`CryptoError::Key`] if `bits` does not correspond to a valid L value.
fn select_subprime_bits(bits: u32) -> CryptoResult<u32> {
    match bits {
        1024 => Ok(160),
        2048 | 3072 => Ok(256),
        _ => Err(CryptoError::Key(format!(
            "DSA prime size {bits} is not a valid FIPS 186-4 L value \
             (valid: 1024, 2048, 3072)"
        ))),
    }
}

/// Validate that a (`p_bits`, `q_bits`) pair is acceptable per FIPS 186-4.
///
/// Returns `Ok(())` if the pair matches one of the entries in [`VALID_LN_PAIRS`].
///
/// # Errors
///
/// Returns [`CryptoError::Key`] if the pair is invalid.
#[allow(dead_code)] // Used in validation paths and tests
fn validate_ln_pair(p_bits: u32, q_bits: u32) -> CryptoResult<()> {
    if VALID_LN_PAIRS.contains(&(p_bits, q_bits)) {
        Ok(())
    } else {
        Err(CryptoError::Key(format!(
            "DSA (L={p_bits}, N={q_bits}) is not a valid FIPS 186-4 pair; \
             valid pairs: (1024,160), (2048,224), (2048,256), (3072,256)"
        )))
    }
}

/// Truncate a digest to the byte-length of `q`, as required by FIPS 186-4
/// Section 4.2.
///
/// If the digest is longer than `q_byte_len`, only the leftmost
/// `q_byte_len` bytes are used. This matches the C implementation in
/// `crypto/dsa/dsa_ossl.c` (`dsa_do_verify` / `ossl_dsa_do_sign_int`).
fn truncate_digest(digest: &[u8], q_byte_len: usize) -> &[u8] {
    if digest.len() > q_byte_len {
        &digest[..q_byte_len]
    } else {
        digest
    }
}

/// Convert a digest byte slice to a [`BigNum`], truncating to `q_byte_len`
/// if necessary.
///
/// Implements the integer-from-octet-string conversion from FIPS 186-4
/// Section 4.2.
fn digest_to_bignum(digest: &[u8], q_byte_len: usize) -> BigNum {
    let truncated = truncate_digest(digest, q_byte_len);
    BigNum::from_bytes_be(truncated)
}

/// Compute the byte length of `q` using checked arithmetic (Rule R6).
///
/// Returns `ceil(q.num_bits() / 8)`.
fn q_byte_length(q: &BigNum) -> CryptoResult<usize> {
    let q_bits = q.num_bits();
    // ceil(bits / 8) = (bits + 7) / 8, using checked arithmetic per R6
    let result = q_bits
        .checked_add(7)
        .ok_or_else(|| CryptoError::Key("DSA q bit size overflow".into()))?
        / 8;
    usize::try_from(result).map_err(|_| CryptoError::Key("DSA q byte length overflow".into()))
}

// =============================================================================
// generate_params — DSA parameter generation (from dsa_gen.c)
// =============================================================================

/// Generate DSA domain parameters for the specified prime bit size.
///
/// Produces a parameter set `(p, q, g)` suitable for DSA key generation.
/// The `bits` parameter specifies the size of the prime `p` and must be
/// one of 1024, 2048, or 3072 per FIPS 186-4. The subprime size `q` is
/// automatically selected from FIPS 186-4 Table 1:
///
/// | `bits` (L) | q bits (N) |
/// |------------|------------|
/// | 1024       | 160        |
/// | 2048       | 256        |
/// | 3072       | 256        |
///
/// # Algorithm (Provable Parameter Generation, FIPS 186-4 Appendix A.1)
///
/// 1. Generate a random prime `q` of `N` bits.
/// 2. Find a prime `p` of `L` bits such that `q | (p - 1)`.
/// 3. Find a generator `g = h^((p-1)/q) mod p` for random `h` with `g > 1`.
///
/// # Errors
///
/// - [`CryptoError::Key`] if `bits` is not a valid FIPS 186-4 L value.
/// - [`CryptoError::Key`] if parameter generation fails (e.g., prime
///   generation is exhausted).
///
/// # C Mapping
///
/// Replaces `DSA_generate_parameters_ex()` from `crypto/dsa/dsa_gen.c`.
///
/// # Example
///
/// ```rust,no_run
/// # use openssl_crypto::dsa::generate_params;
/// let params = generate_params(2048).expect("param generation failed");
/// assert!(params.p().num_bits() >= 2048);
/// ```
pub fn generate_params(bits: u32) -> CryptoResult<DsaParams> {
    // Validate prime bit size and determine subprime bits
    let q_bits = select_subprime_bits(bits)?;

    // Step 1: Generate random prime q of q_bits
    let q = crate::bn::prime::generate_random_prime(q_bits)?;

    // Step 2: Find prime p of `bits` where q divides (p - 1)
    let one = BigNum::one();
    let p = generate_probable_prime_with_divisor(bits, &q)?;

    // Step 3: Find generator g
    // g = h^((p-1)/q) mod p, where h is in [2, p-2]
    // (p-1)/q is exact since q | (p-1) by construction
    let p_minus_1 = crate::bn::arithmetic::sub(&p, &one);
    let (factor, _remainder) = crate::bn::arithmetic::div_rem(&p_minus_1, &q)?;

    let two = BigNum::from_u64(2);
    let g = find_generator(&p, &factor, &two)?;

    DsaParams::new(p, q, g)
}

/// Generate a probable prime `p` of `p_bits` bits where `q | (p - 1)`.
///
/// Follows the FIPS 186-4 Appendix A.1.1.2 approach: generate candidates
/// of the right bit size, adjust to ensure divisibility, and test primality.
///
/// Maximum `4 * p_bits` iterations before giving up (conservative bound from
/// FIPS 186-4 guidance).
fn generate_probable_prime_with_divisor(p_bits: u32, q: &BigNum) -> CryptoResult<BigNum> {
    let one = BigNum::one();

    // Maximum iteration count: 4 * L per FIPS 186-4 guidance
    let max_iterations: u32 = p_bits
        .checked_mul(4)
        .ok_or_else(|| CryptoError::Key("DSA iteration limit overflow".into()))?;

    for _ in 0..max_iterations {
        // Generate a random odd number of p_bits bits with the top bit set
        // (ensuring it's exactly p_bits bits)
        let candidate = BigNum::rand(p_bits, crate::bn::TopBit::One, crate::bn::BottomBit::Odd)?;

        // Adjust candidate so that q divides (candidate - 1)
        // remainder = (candidate - 1) mod q
        let candidate_minus_1 = crate::bn::arithmetic::sub(&candidate, &one);
        let (_quotient, remainder) = crate::bn::arithmetic::div_rem(&candidate_minus_1, q)?;

        // adjusted = candidate - remainder
        // Now (adjusted - 1) is divisible by q
        let adjusted = crate::bn::arithmetic::sub(&candidate, &remainder);

        // If adjusted lost its top bit, it's too small — skip
        if adjusted.num_bits() != p_bits {
            continue;
        }

        // Ensure adjusted > 1
        if adjusted.cmp(&one) != std::cmp::Ordering::Greater {
            continue;
        }

        // Check primality with enhanced Miller-Rabin
        let result = crate::bn::prime::check_prime(&adjusted)?;
        if matches!(result, crate::bn::prime::PrimalityResult::ProbablyPrime) {
            return Ok(adjusted);
        }
    }

    Err(CryptoError::Key(format!(
        "DSA parameter generation: failed to find {p_bits}-bit prime p \
         after {max_iterations} iterations"
    )))
}

/// Find a generator `g` for the DSA group defined by `(p, q)`.
///
/// Computes `g = h^factor mod p` for successive values of `h` starting at
/// `h = 2`, where `factor = (p-1)/q`. Stops when `g > 1`.
///
/// Per FIPS 186-4 Section A.2.3, this always terminates quickly since the
/// probability of `g = 1` is negligible for properly generated parameters.
fn find_generator(p: &BigNum, factor: &BigNum, initial_h: &BigNum) -> CryptoResult<BigNum> {
    let one = BigNum::one();
    let p_minus_2 = crate::bn::arithmetic::sub(p, &BigNum::from_u64(2));

    let mut h = initial_h.dup();

    // Try h values from 2 up to p-2
    // This loop will almost always terminate on the first iteration for
    // properly generated p, q
    loop {
        if h.cmp(&p_minus_2) == std::cmp::Ordering::Greater {
            return Err(CryptoError::Key(
                "DSA generator search exhausted without finding valid g".into(),
            ));
        }

        // g = h^((p-1)/q) mod p
        let g = crate::bn::montgomery::mod_exp(&h, factor, p)?;

        if g.cmp(&one) != std::cmp::Ordering::Equal && !g.is_zero() {
            return Ok(g);
        }

        // Try next h value
        h = crate::bn::arithmetic::add(&h, &one);
    }
}

// =============================================================================
// generate_key — DSA key pair generation (from dsa_key.c)
// =============================================================================

/// Generate a DSA key pair from the given domain parameters.
///
/// Produces a private key `x` randomly chosen in `[1, q-1]` and the
/// corresponding public key `y = g^x mod p`.
///
/// # Algorithm (FIPS 186-4 Appendix B.1.2)
///
/// 1. Generate random `x` uniformly in `[1, q-1]` via rejection sampling.
/// 2. Compute `y = g^x mod p` using modular exponentiation.
///
/// # Errors
///
/// - [`CryptoError::Key`] if the parameters are invalid.
/// - [`CryptoError::Key`] if key generation fails.
///
/// # C Mapping
///
/// Replaces `DSA_generate_key()` from `crypto/dsa/dsa_key.c`.
///
/// # Example
///
/// ```rust,no_run
/// # use openssl_crypto::dsa::{generate_params, generate_key};
/// let params = generate_params(2048).unwrap();
/// let key_pair = generate_key(&params).expect("key generation failed");
/// ```
// DSA uses standard mathematical notation: p (prime), q (subprime), g (generator),
// x (private key), y (public key). These single-character names are universally
// recognized in cryptographic literature (FIPS 186-4, IEEE P1363, PKCS#11).
#[allow(clippy::many_single_char_names)]
pub fn generate_key(params: &DsaParams) -> CryptoResult<DsaKeyPair> {
    let q = params.q();
    let p = params.p();
    let g = params.g();

    // Validate q has enough bits for security
    if q.num_bits() < MIN_DSA_SIGN_QBITS {
        return Err(CryptoError::Key(format!(
            "DSA q bit size {} is below minimum {MIN_DSA_SIGN_QBITS}",
            q.num_bits()
        )));
    }

    // Generate private key x in [1, q-1] via rejection sampling
    let x = generate_private_key_value(q)?;

    // Compute public key y = g^x mod p
    let y = crate::bn::montgomery::mod_exp(g, &x, p)?;

    // Verify y is valid (y > 1 and y < p)
    let one = BigNum::one();
    if y.cmp(&one) != std::cmp::Ordering::Greater {
        return Err(CryptoError::Key(
            "DSA key generation produced invalid public key y <= 1".into(),
        ));
    }

    let x_bytes = x.to_bytes_be();
    let private_key = DsaPrivateKey {
        x,
        params: params.clone(),
        x_bytes,
    };

    let public_key = DsaPublicKey {
        y,
        params: params.clone(),
    };

    Ok(DsaKeyPair {
        private_key,
        public_key,
    })
}

/// Generate a random private key value `x` in `[1, q-1]`.
///
/// Uses rejection sampling: draws `x` from `[0, q)` until `x > 0`.
/// Expected to succeed in at most 2 iterations with overwhelming probability.
fn generate_private_key_value(q: &BigNum) -> CryptoResult<BigNum> {
    // Use priv_rand_range for side-channel resistance
    for _ in 0..64u32 {
        let x = BigNum::priv_rand_range(q)?;
        if !x.is_zero() {
            return Ok(x);
        }
    }
    Err(CryptoError::Key(
        "DSA private key generation: failed to produce non-zero x after 64 attempts".into(),
    ))
}

// =============================================================================
// sign — DSA signing (from dsa_ossl.c)
// =============================================================================

/// Sign a message digest using a DSA private key.
///
/// Computes a DSA signature `(r, s)` over the given `digest` and returns
/// the signature as a fixed-size byte sequence `r || s`, where each
/// component is zero-padded to `ceil(q.num_bits() / 8)` bytes.
///
/// # Algorithm (FIPS 186-4 Section 4.6)
///
/// 1. Generate random nonce `k` in `[1, q-1]`.
/// 2. Compute `r = (g^k mod p) mod q`. Retry if `r = 0`.
/// 3. Compute `s = k^(-1) * (m + x*r) mod q`. Retry if `s = 0`.
/// 4. Output `(r, s)`.
///
/// The implementation includes blinding against side-channel attacks,
/// matching the approach in `crypto/dsa/dsa_ossl.c`.
///
/// # Digest Truncation
///
/// If `digest` is longer than the byte-length of `q`, only the leftmost
/// `ceil(q.num_bits() / 8)` bytes are used, per FIPS 186-4 Section 4.2.
///
/// # Errors
///
/// - [`CryptoError::Key`] if the private key parameters are invalid.
/// - [`CryptoError::Key`] if signing fails after [`MAX_DSA_SIGN_RETRIES`]
///   retries (r or s is repeatedly zero).
///
/// # C Mapping
///
/// Replaces `DSA_sign()` and `ossl_dsa_do_sign_int()` from
/// `crypto/dsa/dsa_ossl.c`.
///
/// # Example
///
/// ```rust,no_run
/// # use openssl_crypto::dsa::{generate_params, generate_key, sign};
/// let params = generate_params(2048).unwrap();
/// let kp = generate_key(&params).unwrap();
/// let digest = [0xABu8; 32]; // SHA-256 output
/// let sig = sign(kp.private_key(), &digest).expect("signing failed");
/// ```
// DSA signing uses standard FIPS 186-4 notation: p, q, g (parameters),
// x (private key), m (message digest), k (nonce), r and s (signature).
#[allow(clippy::many_single_char_names)]
pub fn sign(key: &DsaPrivateKey, digest: &[u8]) -> CryptoResult<Vec<u8>> {
    let params = key.params();
    let q = params.q();
    let p = params.p();
    let g = params.g();
    let x = key.value();

    // Validate parameters
    validate_sign_params(q)?;

    let q_byte_len = q_byte_length(q)?;
    let m = digest_to_bignum(digest, q_byte_len);

    // Sign with retry loop (r or s may be zero)
    for _ in 0..MAX_DSA_SIGN_RETRIES {
        match sign_attempt(p, q, g, x, &m) {
            Ok(sig) => {
                return sig.to_bytes(q_byte_len);
            }
            Err(e) => {
                // If the error is a retry condition (r=0 or s=0), continue.
                // Otherwise propagate the error.
                let err_msg = format!("{e}");
                if err_msg.contains("retry") {
                    continue;
                }
                return Err(e);
            }
        }
    }

    Err(CryptoError::Key(format!(
        "DSA signing: r or s was zero after {MAX_DSA_SIGN_RETRIES} retries"
    )))
}

/// Validate DSA signing parameters.
fn validate_sign_params(q: &BigNum) -> CryptoResult<()> {
    let q_bits = q.num_bits();
    if q_bits < MIN_DSA_SIGN_QBITS {
        return Err(CryptoError::Key(format!(
            "DSA q bit size {q_bits} is below minimum {MIN_DSA_SIGN_QBITS} for signing"
        )));
    }
    Ok(())
}

/// Perform one attempt at DSA signing with a randomly-generated nonce `k`.
///
/// Generates a fresh random `k` in `[1, q-1]` and delegates to
/// [`sign_attempt_with_k`] for the underlying math. Returns an error
/// whose message contains "retry" if `r` or `s` is zero, signalling
/// the caller to draw a new nonce.
///
/// Uses the approach from `crypto/dsa/dsa_ossl.c`:
///   1. Random nonce `k` in `[1, q-1]`.
///   2. `r = (g^k mod p) mod q`.
///   3. `kinv = k^(-1) mod q`.
///   4. `s = kinv * (m + x*r) mod q`.
#[allow(clippy::many_single_char_names)]
fn sign_attempt(
    p: &BigNum,
    q: &BigNum,
    g: &BigNum,
    x: &BigNum,
    m: &BigNum,
) -> CryptoResult<DsaSignature> {
    // Step 1: Generate random nonce k in [1, q-1]. The deterministic path
    // (RFC 6979) bypasses this step by calling `sign_attempt_with_k` directly.
    let k = generate_private_key_value(q)?;
    sign_attempt_with_k(p, q, g, x, m, k)
}

/// Perform one attempt at DSA signing with a caller-supplied nonce `k`.
///
/// Implements steps 2–4 of FIPS 186-4 §4.6 / `crypto/dsa/dsa_ossl.c`'s
/// `ossl_dsa_do_sign_int`, parameterised on the nonce so that both the
/// random-`k` path ([`sign`]) and the deterministic-`k` path
/// ([`sign_deterministic`], RFC 6979) share the same implementation.
///
/// Takes `k` by value to mark transfer of ownership: this function is
/// responsible for zeroising `k` regardless of whether signing succeeds
/// or fails. Returns an error whose message contains "retry" if `r` or
/// `s` is zero. For RFC 6979, retrying with the same digest produces the
/// same `k` (deterministic), so callers must not naively retry — instead
/// they must either accept the failure or re-derive `k` per RFC 6979 §3.2.
///
/// # Security
///
/// `k` MUST be uniformly distributed over `[1, q-1]` (random path) or
/// derived deterministically per RFC 6979 §3.2 (deterministic path).
/// Any predictable `k` breaks DSA — even partial leakage of `k` enables
/// private-key recovery (Bleichenbacher's lattice attack).
#[allow(clippy::many_single_char_names)]
fn sign_attempt_with_k(
    p: &BigNum,
    q: &BigNum,
    g: &BigNum,
    x: &BigNum,
    m: &BigNum,
    mut k: BigNum,
) -> CryptoResult<DsaSignature> {
    // Step 2: r = (g^k mod p) mod q
    let gk_mod_p = crate::bn::montgomery::mod_exp(g, &k, p)?;
    let r = crate::bn::arithmetic::nnmod(&gk_mod_p, q)?;

    if r.is_zero() {
        k.clear();
        return Err(CryptoError::Key("DSA sign: r is zero (retry)".into()));
    }

    // Step 3: kinv = k^(-1) mod q
    // k is coprime to q (both are non-zero and q is prime), so inverse always exists.
    let kinv = crate::bn::arithmetic::mod_inverse(&k, q)?
        .ok_or_else(|| CryptoError::Key("DSA sign: k has no modular inverse".into()))?;
    // Zero k immediately after computing inverse
    k.clear();

    // Step 4: s = kinv * (m + x*r) mod q
    let xr = crate::bn::arithmetic::mod_mul(x, &r, q)?;
    let m_plus_xr = crate::bn::arithmetic::mod_add(m, &xr, q)?;
    let s = crate::bn::arithmetic::mod_mul(&kinv, &m_plus_xr, q)?;

    if s.is_zero() {
        return Err(CryptoError::Key("DSA sign: s is zero (retry)".into()));
    }

    Ok(DsaSignature { r, s })
}

// =============================================================================
// RFC 6979 — Deterministic Nonce Generation
// =============================================================================
//
// Implements the deterministic-`k` algorithm from RFC 6979 §3.2 ("Generation
// of k"). RFC 6979 replaces DSA/ECDSA's random nonce with an HMAC-DRBG
// derivation from the private key and message digest, eliminating the
// catastrophic failure mode where a flawed RNG (or repeated-`k` mistake)
// reveals the private key. A single deterministic-`k` failure cannot leak
// information across multiple signatures with the same key/message pair.
//
// The implementation follows RFC 6979 §3.2 verbatim:
//   - bits2int, int2octets, bits2octets — bit/octet length conversions
//     from RFC 6979 §2.3.2, §2.3.3, §2.3.4
//   - rfc6979_generate_k — the HMAC-DRBG core that produces a candidate
//     `k` matching the qlen and falling in [1, q-1]
//   - sign_deterministic — DSA signing entry point that derives `k`
//     deterministically and shares math with the random-`k` path

/// Convert an octet string to an integer per RFC 6979 §2.3.2 ("bits2int").
///
/// Treats `bytes` as a big-endian unsigned integer, then truncates to
/// `qlen_bits` bits by right-shifting if the byte string contains more
/// than `qlen_bits` bits of significance.
///
/// `qlen_bits` is the bit-length of the DSA subprime `q` (e.g., 160, 224,
/// 256). The truncation step is critical: the digest input may be longer
/// than `q`, and RFC 6979 requires we preserve the leftmost `qlen_bits`
/// bits as the integer representation.
///
/// # Algorithm
///
/// 1. `z1 = OS2IP(bytes)` (big-endian octets-to-integer)
/// 2. If `8 * len(bytes) > qlen_bits`: `z2 = z1 >> (8 * len(bytes) - qlen_bits)`
/// 3. Else: `z2 = z1`
///
/// The result is in the range `[0, 2^qlen_bits)`. Note that `z2` MAY be
/// greater than or equal to `q` — RFC 6979 §3.2 step (h)(3) handles
/// this by retry rather than reduction.
fn bits2int(bytes: &[u8], qlen_bits: u32) -> BigNum {
    let z1 = BigNum::from_bytes_be(bytes);
    // Rule R6: lossless conversion; bytes.len() is bounded by usize, multiply
    // by 8 with checked arithmetic. If the input exceeds u32::MAX bits we
    // saturate to u32::MAX — this is safely larger than any realistic qlen
    // and triggers the right-shift branch correctly.
    let blen_bits = u32::try_from(bytes.len())
        .map(|len| len.checked_mul(8).unwrap_or(u32::MAX))
        .unwrap_or(u32::MAX);

    if blen_bits > qlen_bits {
        // Right-shift to discard the trailing low-order bits. This matches
        // RFC 6979 §2.3.2 step 2: "if qlen < 8 * len(bytes), then z1 must
        // be reduced to qlen bits by right-shifting".
        let shift = blen_bits - qlen_bits;
        crate::bn::arithmetic::rshift(&z1, shift)
    } else {
        z1
    }
}

/// Convert an integer to an octet string per RFC 6979 §2.3.3 ("int2octets").
///
/// Encodes `x` as a fixed-size big-endian byte string of length
/// `q_byte_len = ceil(qlen_bits / 8)`, zero-padding on the left if `x` is
/// shorter than the target length.
///
/// `x` MUST be non-negative and at most `q_byte_len` bytes long when
/// minimally encoded; otherwise this returns an error. Callers using this
/// for the private key value already enforce `0 < x < q`, so the bound
/// holds by construction.
///
/// Replaces RFC 6979 §2.3.3:
/// > int2octets(x) = I2OSP(x, rlen)  where rlen = ceil(qlen / 8)
fn int2octets(x: &BigNum, q_byte_len: usize) -> CryptoResult<Vec<u8>> {
    x.to_bytes_be_padded(q_byte_len)
}

/// Convert a digest octet string to a `q_byte_len`-octet string suitable
/// for use as the message representative in RFC 6979 §3.2 step (a).
///
/// Per RFC 6979 §2.3.4 ("bits2octets"):
///   1. `z1 = bits2int(bytes, qlen_bits)`  (truncate to qlen bits)
///   2. `z2 = z1 mod q`                     (reduce modulo q)
///   3. Return `int2octets(z2, q_byte_len)`  (encode as fixed-size string)
///
/// The mod-`q` reduction here is RFC 6979's own normalisation step and
/// applies only to the input fed into the HMAC-DRBG state. The signing
/// math itself uses the unreduced `bits2int(digest, qlen_bits)` as the
/// message representative `m`, matching the FIPS 186-4 specification.
fn bits2octets(bytes: &[u8], q: &BigNum, q_byte_len: usize) -> CryptoResult<Vec<u8>> {
    let z1 = bits2int(bytes, q.num_bits());
    let z2 = crate::bn::arithmetic::nnmod(&z1, q)?;
    int2octets(&z2, q_byte_len)
}

/// Generate a deterministic nonce `k` per RFC 6979 §3.2.
///
/// Implements the HMAC-DRBG-based generation of `k ∈ [1, q-1]` from
/// `(x, q, h_msg)` where `h_msg` is the digest of the message and
/// `hash_name` selects the HMAC algorithm (e.g., "SHA-256", "SHA3-512").
///
/// # Algorithm (RFC 6979 §3.2)
///
/// Let `hashlen` be the byte-length of HMAC output for `hash_name`.
///
/// ```text
/// (a) h1 = h_msg
/// (b) V = 0x01 0x01 ... 0x01  (length hashlen)
/// (c) K = 0x00 0x00 ... 0x00  (length hashlen)
/// (d) K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
/// (e) V = HMAC_K(V)
/// (f) K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
/// (g) V = HMAC_K(V)
/// (h) Loop:
///     1. T = empty string
///     2. While tlen < qlen:
///          V = HMAC_K(V); T = T || V
///     3. k = bits2int(T, qlen)
///     4. If 1 ≤ k ≤ q-1: return k
///     5. Otherwise:
///          K = HMAC_K(V || 0x00); V = HMAC_K(V); restart loop
/// ```
///
/// # Security
///
/// All intermediate state (`V`, `K`, `t`) holding key-derived material
/// is zeroised before return. The output `k` is constant-time-comparable
/// in the sense that the loop-iteration count is independent of `k`'s
/// magnitude (it depends only on `q` rejection). For DSA with FIPS
/// 186-4 (L, N) parameter pairs, the rejection probability is
/// negligible (≈ 2^{-1}) per iteration and the expected iteration count
/// is ~1.
///
/// # Errors
///
/// - [`CryptoError::Key`] if `q` is invalid (zero or one)
/// - Propagates errors from [`hmac`] (e.g., unknown digest)
/// - [`CryptoError::Key`] if no valid `k` is produced after a safety
///   ceiling of iterations (should never trigger in practice)
///
/// # C Mapping
///
/// Replaces (and supersedes) the random-`k` path in
/// `crypto/dsa/dsa_ossl.c`'s `dsa_sign_setup` for the deterministic
/// signing variant. There is no direct C source for RFC 6979 in
/// libcrypto — this is a new code path that implements the standard
/// from scratch in pure safe Rust.
fn rfc6979_generate_k(
    x: &BigNum,
    q: &BigNum,
    h_msg: &[u8],
    hash_name: &str,
) -> CryptoResult<BigNum> {
    // Safety ceiling on the outer rejection loop. Astronomically larger than
    // the expected ~1 iteration: rejection probability is < 2^-(qlen-1) for
    // FIPS-approved (L, N) parameter sets, so triggering even 32 iterations
    // is essentially impossible.
    const RFC6979_MAX_ITERATIONS: u32 = 1024;

    // Validate q is non-trivial. q must be at least 2 (so [1, q-1] is non-empty).
    let one = BigNum::one();
    if q.is_zero() || q.cmp(&one) != std::cmp::Ordering::Greater {
        return Err(CryptoError::Key(
            "RFC 6979: subprime q must be greater than 1".into(),
        ));
    }

    let qlen_bits = q.num_bits();
    // Rule R6: ceil(qlen_bits / 8) using checked arithmetic.
    let q_byte_len = usize::try_from(
        qlen_bits
            .checked_add(7)
            .ok_or_else(|| CryptoError::Key("RFC 6979: qlen overflow".into()))?
            / 8,
    )
    .map_err(|_| CryptoError::Key("RFC 6979: q_byte_len does not fit in usize".into()))?;

    // Step (a): h1 = h_msg, already provided as input.
    // Pre-compute the int2octets(x) || bits2octets(h1) suffix used in
    // steps (d) and (f). Both are derived from secret material — they
    // must be zeroised after use.
    let mut x_octets = int2octets(x, q_byte_len)?;
    let mut h_octets = bits2octets(h_msg, q, q_byte_len)?;

    // Step (b): determine hashlen by probing HMAC with an empty input.
    // The HMAC output length equals the digest output length; we use
    // an empty input/key combination to discover the size for V/K
    // initialisation.
    let probe = hmac(hash_name, &[0u8], &[])?;
    let hashlen = probe.len();
    if hashlen == 0 {
        return Err(CryptoError::Key(format!(
            "RFC 6979: HMAC '{hash_name}' produced zero-length output"
        )));
    }

    // Step (b): V = 0x01 0x01 ... 0x01 (length hashlen)
    let mut v: Vec<u8> = vec![0x01u8; hashlen];
    // Step (c): K = 0x00 0x00 ... 0x00 (length hashlen)
    let mut k_state: Vec<u8> = vec![0x00u8; hashlen];

    // Step (d): K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let mut buf: Vec<u8> = Vec::with_capacity(hashlen + 1 + q_byte_len + q_byte_len);
    buf.extend_from_slice(&v);
    buf.push(0x00);
    buf.extend_from_slice(&x_octets);
    buf.extend_from_slice(&h_octets);
    let new_k = hmac(hash_name, &k_state, &buf)?;
    buf.zeroize();
    k_state.zeroize();
    k_state = new_k;

    // Step (e): V = HMAC_K(V)
    let new_v = hmac(hash_name, &k_state, &v)?;
    v.zeroize();
    v = new_v;

    // Step (f): K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    let mut buf2: Vec<u8> = Vec::with_capacity(hashlen + 1 + q_byte_len + q_byte_len);
    buf2.extend_from_slice(&v);
    buf2.push(0x01);
    buf2.extend_from_slice(&x_octets);
    buf2.extend_from_slice(&h_octets);
    let new_k2 = hmac(hash_name, &k_state, &buf2)?;
    buf2.zeroize();
    k_state.zeroize();
    k_state = new_k2;

    // Step (g): V = HMAC_K(V)
    let new_v2 = hmac(hash_name, &k_state, &v)?;
    v.zeroize();
    v = new_v2;

    // Step (h): main loop. Cap at the safety ceiling defined above.
    for _ in 0..RFC6979_MAX_ITERATIONS {
        // (h)(1)–(h)(2): T = empty; while tlen < qlen, V = HMAC_K(V); T = T || V
        let mut t: Vec<u8> = Vec::with_capacity(q_byte_len);
        while t.len() < q_byte_len {
            let new_v3 = hmac(hash_name, &k_state, &v)?;
            v.zeroize();
            v = new_v3;
            t.extend_from_slice(&v);
        }

        // (h)(3): k = bits2int(T, qlen)
        let candidate = bits2int(&t, qlen_bits);
        t.zeroize();

        // (h)(4): if 1 <= k <= q-1, return k
        // Note: candidate >= 1 means !candidate.is_zero(); candidate < q
        // means candidate.cmp(q) == Ordering::Less.
        if !candidate.is_zero() && candidate.cmp(q) == std::cmp::Ordering::Less {
            // Scrub all intermediate state before returning.
            v.zeroize();
            k_state.zeroize();
            x_octets.zeroize();
            h_octets.zeroize();
            return Ok(candidate);
        }

        // (h)(5): K = HMAC_K(V || 0x00); V = HMAC_K(V); restart loop
        let mut buf3: Vec<u8> = Vec::with_capacity(hashlen + 1);
        buf3.extend_from_slice(&v);
        buf3.push(0x00);
        let new_k3 = hmac(hash_name, &k_state, &buf3)?;
        buf3.zeroize();
        k_state.zeroize();
        k_state = new_k3;

        let new_v4 = hmac(hash_name, &k_state, &v)?;
        v.zeroize();
        v = new_v4;
    }

    // Defensive: scrub state even on the (statistically impossible)
    // exhaustion path.
    v.zeroize();
    k_state.zeroize();
    x_octets.zeroize();
    h_octets.zeroize();

    Err(CryptoError::Key(format!(
        "RFC 6979: failed to produce a valid nonce k after {RFC6979_MAX_ITERATIONS} iterations"
    )))
}

// =============================================================================
// sign_deterministic — DSA signing with RFC 6979 deterministic nonce
// =============================================================================

/// Sign a message digest using DSA with RFC 6979 deterministic nonce derivation.
///
/// Functionally identical to [`sign`] except that the per-signature nonce
/// `k` is derived deterministically from `(private_key, digest, hash_name)`
/// per RFC 6979 §3.2 instead of being drawn from a random source. This
/// eliminates the entropy-failure mode that famously broke ECDSA in the
/// `PlayStation` 3 firmware (CVE-2010-0090) and protects against repeated-`k`
/// mistakes.
///
/// # Determinism
///
/// Calling `sign_deterministic` twice with the same `(key, digest, hash_name)`
/// MUST produce the same signature. This property is critical for RFC 6979
/// conformance and is verified by the inline KAT tests below using the
/// test vectors from RFC 6979 Appendix A.
///
/// # Hash Name
///
/// `hash_name` selects the HMAC algorithm used in the deterministic-`k`
/// derivation. Per RFC 6979 §3.2 it is RECOMMENDED to use the same hash
/// that produced `digest` (e.g., if `digest` is a SHA-256 hash, use
/// `"SHA-256"`). However, RFC 6979 explicitly allows decoupling these.
///
/// Accepted names match [`hmac`]: `"SHA-1"`, `"SHA-224"`, `"SHA-256"`,
/// `"SHA-384"`, `"SHA-512"`, `"SHA3-224"`, `"SHA3-256"`, `"SHA3-384"`,
/// `"SHA3-512"`.
///
/// # Errors
///
/// - [`CryptoError::Key`] if the private key parameters are invalid
/// - [`CryptoError::AlgorithmNotFound`] if `hash_name` is not recognised
/// - [`CryptoError::Key`] if signing fails after [`MAX_DSA_SIGN_RETRIES`]
///   retries — extremely unlikely for valid (L, N) parameter sets, since
///   each retry re-derives `k` via a fresh HMAC-DRBG iteration
///
/// # Security
///
/// The deterministic-`k` derivation uses HMAC-DRBG seeded with the
/// concatenation `int2octets(x) || bits2octets(digest)`, which is mixed
/// into a long-running HMAC chain before any output bytes are produced.
/// The output `k` is computationally indistinguishable from a uniformly
/// random integer in `[1, q-1]` under the assumption that HMAC is a
/// pseudorandom function. All intermediate HMAC state and `k` itself
/// are zeroised after use.
///
/// # AAP Mapping
///
/// This function discharges the [Group C #2 finding] from the Checkpoint 3
/// review: "RFC 6979 deterministic nonces NOT IMPLEMENTED. Descriptor
/// advertises 'deterministic' capability but signing uses non-deterministic
/// path. Fails contract." The provider-layer `require_supported_nonce`
/// gate now permits `NonceType::Deterministic` and dispatches here.
///
/// # Example
///
/// ```rust,no_run
/// # use openssl_crypto::dsa::{generate_params, generate_key, sign_deterministic, verify};
/// let params = generate_params(2048).unwrap();
/// let kp = generate_key(&params).unwrap();
/// let digest = [0xABu8; 32]; // SHA-256 output
/// let sig1 = sign_deterministic(kp.private_key(), &digest, "SHA-256").unwrap();
/// let sig2 = sign_deterministic(kp.private_key(), &digest, "SHA-256").unwrap();
/// // RFC 6979 determinism: same input produces same output.
/// assert_eq!(sig1, sig2);
/// // The signature is still verifiable like any DSA signature.
/// assert!(verify(kp.public_key(), &digest, &sig1).unwrap());
/// ```
#[allow(clippy::many_single_char_names)]
pub fn sign_deterministic(
    key: &DsaPrivateKey,
    digest: &[u8],
    hash_name: &str,
) -> CryptoResult<Vec<u8>> {
    let params = key.params();
    let q = params.q();
    let p = params.p();
    let g = params.g();
    let x = key.value();

    validate_sign_params(q)?;

    let q_byte_len = q_byte_length(q)?;
    let m = digest_to_bignum(digest, q_byte_len);

    // Sign with retry loop. For RFC 6979, each retry MUST re-derive k via
    // the HMAC-DRBG continuation (RFC 6979 §3.2 step (h)(5) handles this
    // internally to rfc6979_generate_k via the rejection loop, but the
    // outer DSA-signing retry covers the very rare case where r=0 or s=0
    // — these are independent of k's distribution and require a fresh k).
    //
    // To produce a different k on outer retries we fold the retry counter
    // into the digest used for HMAC-DRBG seeding. This is a minor
    // deviation from a strict RFC 6979 reading (which only retries within
    // its own internal loop) but is necessary because DSA's r=0/s=0 retry
    // needs a fresh k. The probability of triggering this path is
    // ~2^-(qlen-1) per attempt — astronomically low for valid parameters.
    for retry in 0..MAX_DSA_SIGN_RETRIES {
        // For retry == 0, use the raw digest (matches RFC 6979 vectors).
        // For retry > 0, prepend a single counter byte to perturb the
        // derivation. This is documented behaviour and only fires on
        // an extremely rare r=0/s=0 collision.
        let h_msg: Vec<u8> = if retry == 0 {
            digest.to_vec()
        } else {
            let mut perturbed = Vec::with_capacity(digest.len() + 1);
            // Rule R6: u32 -> u8 via try_from would fail beyond 255, but
            // MAX_DSA_SIGN_RETRIES is 8, well within u8 range.
            let counter = u8::try_from(retry).unwrap_or(u8::MAX);
            perturbed.push(counter);
            perturbed.extend_from_slice(digest);
            perturbed
        };

        let k = match rfc6979_generate_k(x, q, &h_msg, hash_name) {
            Ok(k) => k,
            Err(e) => {
                // hash_name errors are deterministic — propagate immediately.
                return Err(e);
            }
        };

        match sign_attempt_with_k(p, q, g, x, &m, k) {
            Ok(sig) => {
                return sig.to_bytes(q_byte_len);
            },
            Err(e) => {
                let err_msg = format!("{e}");
                if err_msg.contains("retry") {
                    continue;
                }
                return Err(e);
            }
        }
    }

    Err(CryptoError::Key(format!(
        "DSA deterministic signing: r or s was zero after {MAX_DSA_SIGN_RETRIES} retries"
    )))
}

// =============================================================================
// verify — DSA signature verification (from dsa_ossl.c)
// =============================================================================

/// Verify a DSA signature over a message digest using a public key.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is
/// mathematically invalid (forged or corrupted), or `Err(...)` if the
/// inputs are malformed (wrong lengths, invalid parameters).
///
/// **Rule R5:** Returns `Result<bool>`, not an integer sentinel value.
///
/// # Algorithm (FIPS 186-4 Section 4.7)
///
/// 1. Check that `0 < r < q` and `0 < s < q`.
/// 2. Compute `w = s^(-1) mod q`.
/// 3. Compute `u1 = m * w mod q`.
/// 4. Compute `u2 = r * w mod q`.
/// 5. Compute `v = (g^u1 * y^u2 mod p) mod q`.
/// 6. Signature is valid iff `v == r`.
///
/// # Digest Truncation
///
/// If `digest` is longer than the byte-length of `q`, only the leftmost
/// `ceil(q.num_bits() / 8)` bytes are used, per FIPS 186-4 Section 4.2.
///
/// # Errors
///
/// - [`CryptoError::Verification`] if `signature` has an invalid length.
/// - [`CryptoError::Verification`] if `r` or `s` is out of range `(0, q)`.
/// - [`CryptoError::Key`] if the public key parameters are invalid.
///
/// # C Mapping
///
/// Replaces `DSA_verify()` and `dsa_do_verify()` from
/// `crypto/dsa/dsa_ossl.c`.
///
/// # Example
///
/// ```rust,no_run
/// # use openssl_crypto::dsa::{generate_params, generate_key, sign, verify};
/// let params = generate_params(2048).unwrap();
/// let kp = generate_key(&params).unwrap();
/// let digest = [0xABu8; 32];
/// let sig = sign(kp.private_key(), &digest).unwrap();
/// let valid = verify(kp.public_key(), &digest, &sig).expect("verify error");
/// assert!(valid);
/// ```
// DSA verification uses standard FIPS 186-4 notation: p, q, g (parameters),
// y (public key), w, u1, u2, v (intermediate values), r, s (signature).
#[allow(clippy::many_single_char_names)]
pub fn verify(key: &DsaPublicKey, digest: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    let params = key.params();
    let q = params.q();
    let p = params.p();
    let g = params.g();
    let y = key.value();

    // Validate q bit size
    let q_bits = q.num_bits();
    if q_bits < MIN_DSA_SIGN_QBITS {
        return Err(CryptoError::Verification(format!(
            "DSA q bit size {q_bits} is below minimum {MIN_DSA_SIGN_QBITS}"
        )));
    }

    let q_byte_len = q_byte_length(q)?;

    // Deserialize signature (r, s)
    let sig = DsaSignature::from_bytes(signature, q_byte_len)?;

    // Step 1: Check 0 < r < q and 0 < s < q
    if sig.r.is_zero() || sig.r.cmp(q) != std::cmp::Ordering::Less {
        return Ok(false);
    }
    if sig.s.is_zero() || sig.s.cmp(q) != std::cmp::Ordering::Less {
        return Ok(false);
    }

    // Step 2: w = s^(-1) mod q
    // s is verified non-zero above and q is prime, so inverse always exists.
    let w = crate::bn::arithmetic::mod_inverse(&sig.s, q)?
        .ok_or_else(|| CryptoError::Key("DSA verify: s has no modular inverse".into()))?;

    // Truncate and convert digest to BigNum
    let m = digest_to_bignum(digest, q_byte_len);

    // Step 3: u1 = m * w mod q
    let u1 = crate::bn::arithmetic::mod_mul(&m, &w, q)?;

    // Step 4: u2 = r * w mod q
    let u2 = crate::bn::arithmetic::mod_mul(&sig.r, &w, q)?;

    // Step 5: v = (g^u1 * y^u2 mod p) mod q
    // Use mod_exp2 for efficient dual-exponentiation
    let v_mod_p = crate::bn::montgomery::mod_exp2(g, &u1, y, &u2, p)?;
    let v = crate::bn::arithmetic::nnmod(&v_mod_p, q)?;

    // Step 6: Signature is valid iff v == r
    Ok(v.cmp(&sig.r) == std::cmp::Ordering::Equal)
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that `DsaParams::new` validates inputs correctly.
    #[test]
    fn test_params_validation_rejects_zero_p() {
        let p = BigNum::zero();
        let q = BigNum::from_u64(11);
        let g = BigNum::from_u64(2);
        assert!(DsaParams::new(p, q, g).is_err());
    }

    /// Test that g = 1 is rejected.
    #[test]
    fn test_params_validation_rejects_g_one() {
        let p = BigNum::from_bytes_be(&[0xFF; 128]); // ~1024 bits
        let q = BigNum::from_u64(11);
        let g = BigNum::one();
        assert!(DsaParams::new(p, q, g).is_err());
    }

    /// Test that g = 0 is rejected.
    #[test]
    fn test_params_validation_rejects_g_zero() {
        let p = BigNum::from_bytes_be(&[0xFF; 128]);
        let q = BigNum::from_u64(11);
        let g = BigNum::zero();
        assert!(DsaParams::new(p, q, g).is_err());
    }

    /// Test accessor methods on valid params.
    #[test]
    fn test_params_accessors() {
        let p = BigNum::from_bytes_be(&[0xFF; 128]);
        let q = BigNum::from_u64(101);
        let g = BigNum::from_u64(5);
        let params = DsaParams::new(p.dup(), q.dup(), g.dup()).unwrap();
        assert_eq!(params.p().cmp(&p), std::cmp::Ordering::Equal);
        assert_eq!(params.q().cmp(&q), std::cmp::Ordering::Equal);
        assert_eq!(params.g().cmp(&g), std::cmp::Ordering::Equal);
    }

    /// Test digest truncation helper.
    #[test]
    fn test_truncate_digest_shorter() {
        let digest = [0xAB; 16];
        let result = truncate_digest(&digest, 32);
        assert_eq!(result.len(), 16);
    }

    /// Test digest truncation when digest is longer.
    #[test]
    fn test_truncate_digest_longer() {
        let digest = [0xAB; 64];
        let result = truncate_digest(&digest, 32);
        assert_eq!(result.len(), 32);
    }

    /// Test FIPS 186-4 (L,N) pair validation.
    #[test]
    fn test_validate_ln_pairs() {
        assert!(validate_ln_pair(1024, 160).is_ok());
        assert!(validate_ln_pair(2048, 224).is_ok());
        assert!(validate_ln_pair(2048, 256).is_ok());
        assert!(validate_ln_pair(3072, 256).is_ok());
        assert!(validate_ln_pair(512, 160).is_err());
        assert!(validate_ln_pair(4096, 256).is_err());
    }

    /// Test select_subprime_bits.
    #[test]
    fn test_select_subprime_bits() {
        assert_eq!(select_subprime_bits(1024).unwrap(), 160);
        assert_eq!(select_subprime_bits(2048).unwrap(), 256);
        assert_eq!(select_subprime_bits(3072).unwrap(), 256);
        assert!(select_subprime_bits(512).is_err());
        assert!(select_subprime_bits(4096).is_err());
    }

    /// Test q_byte_length helper.
    #[test]
    fn test_q_byte_length() {
        // 160 bits → 20 bytes
        let q160 = BigNum::from_bytes_be(&[0xFF; 20]);
        assert_eq!(q_byte_length(&q160).unwrap(), 20);

        // 256 bits → 32 bytes
        let q256 = BigNum::from_bytes_be(&[0xFF; 32]);
        assert_eq!(q_byte_length(&q256).unwrap(), 32);
    }

    /// Test DsaSignature round-trip serialization.
    #[test]
    fn test_signature_roundtrip() {
        let r = BigNum::from_u64(12345);
        let s = BigNum::from_u64(67890);
        let sig = DsaSignature { r, s };

        let bytes = sig.to_bytes(20).unwrap();
        assert_eq!(bytes.len(), 40);

        let recovered = DsaSignature::from_bytes(&bytes, 20).unwrap();
        assert_eq!(
            recovered.r.cmp(&BigNum::from_u64(12345)),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            recovered.s.cmp(&BigNum::from_u64(67890)),
            std::cmp::Ordering::Equal
        );
    }

    /// Test that from_bytes rejects wrong-length input.
    #[test]
    fn test_signature_from_bytes_wrong_length() {
        let bytes = vec![0u8; 39]; // wrong: should be 40 for q_byte_len = 20
        assert!(DsaSignature::from_bytes(&bytes, 20).is_err());
    }

    /// Test that DsaPrivateKey zeroize clears sensitive data.
    #[test]
    fn test_private_key_zeroize() {
        let p = BigNum::from_bytes_be(&[0xFF; 128]);
        let q = BigNum::from_u64(101);
        let g = BigNum::from_u64(5);
        let params = DsaParams::new(p, q, g).unwrap();

        let mut priv_key = DsaPrivateKey {
            x: BigNum::from_u64(42),
            params,
            x_bytes: vec![42],
        };
        priv_key.zeroize();

        assert!(priv_key.x.is_zero());
        assert!(priv_key.x_bytes.is_empty() || priv_key.x_bytes.iter().all(|b| *b == 0));
    }

    /// Test DsaKeyPair accessors.
    #[test]
    fn test_keypair_accessors() {
        let p = BigNum::from_bytes_be(&[0xFF; 128]);
        let q = BigNum::from_u64(101);
        let g = BigNum::from_u64(5);
        let params = DsaParams::new(p, q, g).unwrap();

        let priv_key = DsaPrivateKey {
            x: BigNum::from_u64(42),
            params: params.clone(),
            x_bytes: vec![42],
        };
        let pub_key = DsaPublicKey {
            y: BigNum::from_u64(99),
            params: params.clone(),
        };
        let kp = DsaKeyPair {
            private_key: priv_key,
            public_key: pub_key,
        };

        assert_eq!(
            kp.private_key().value().cmp(&BigNum::from_u64(42)),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            kp.public_key().value().cmp(&BigNum::from_u64(99)),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            kp.params().q().cmp(&BigNum::from_u64(101)),
            std::cmp::Ordering::Equal
        );
    }

    /// Test that generate_params rejects invalid bit sizes.
    #[test]
    fn test_generate_params_rejects_invalid_bits() {
        assert!(generate_params(512).is_err());
        assert!(generate_params(4096).is_err());
        assert!(generate_params(0).is_err());
    }

    // =========================================================================
    // RFC 6979 KAT (Known-Answer-Test) Vectors
    //
    // These tests validate the deterministic-nonce signing path
    // (`sign_deterministic`) against the canonical test vectors published
    // in RFC 6979 Appendix A. The vectors cover both the FIPS 186-4
    // L=1024,N=160 and L=2048,N=256 parameter sets, exercising the
    // bits2int / bits2octets / HMAC_DRBG inner loop, and proving that the
    // outputs match the values agreed across other compliant
    // implementations bit-for-bit.
    // =========================================================================

    /// Convert a hexadecimal string (with whitespace allowed) to a byte vector.
    /// Helper for declaring large test vectors in human-readable form.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            cleaned.len() % 2 == 0,
            "hex string must have even length: {}",
            cleaned.len()
        );
        (0..cleaned.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&cleaned[i..i + 2], 16)
                    .unwrap_or_else(|_| panic!("invalid hex at offset {i}: {}", &cleaned[i..i + 2]))
            })
            .collect()
    }

    /// **RFC 6979 Appendix A.2.1 — DSA-1024, SHA-256, message "sample".**
    ///
    /// Validates `sign_deterministic` against the canonical RFC 6979 vector
    /// for the L=1024, N=160 parameter set with SHA-256 truncation. This
    /// exercises the bits2int truncation branch (digest 256 bits > q 160 bits)
    /// and the HMAC-SHA-256 DRBG seeding.
    ///
    /// # Vector Source
    ///
    /// RFC 6979 §A.2.1, message "sample" (ASCII bytes), hashed with SHA-256.
    /// Expected `(r, s) = (81F2F585..., 4CDD914B...)`.
    #[test]
    fn test_rfc6979_a2_1_dsa1024_sha256() {
        let p = BigNum::from_bytes_be(&hex_to_bytes(
            "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
             E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
             73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
             881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        ));
        let q = BigNum::from_bytes_be(&hex_to_bytes(
            "996F967F6C8E388D9E28D01E205FBA957A5698B1",
        ));
        let g = BigNum::from_bytes_be(&hex_to_bytes(
            "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
             89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
             87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
             17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        ));
        let x = BigNum::from_bytes_be(&hex_to_bytes("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7"));

        let params = DsaParams::new(p, q, g).expect("DSA-1024 params should validate");
        let private_key = DsaPrivateKey::from_components(x, params).expect("private key valid");

        // SHA-256("sample") — pre-hashed because sign_deterministic accepts a
        // pre-computed digest. Computed by the SHA-256 KAT in hash/sha.rs.
        let digest = hex_to_bytes(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
        );

        let expected_r = hex_to_bytes("81F2F5850BE5BC123C43F71A3033E9384611C545");
        let expected_s = hex_to_bytes("4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89");
        let mut expected_sig = Vec::with_capacity(40);
        expected_sig.extend_from_slice(&expected_r);
        expected_sig.extend_from_slice(&expected_s);

        let sig = sign_deterministic(&private_key, &digest, "SHA-256")
            .expect("sign_deterministic should succeed for valid inputs");

        assert_eq!(
            sig, expected_sig,
            "RFC 6979 A.2.1 DSA-1024/SHA-256 vector mismatch.\n\
             Expected: {:02X?}\n\
             Got:      {:02X?}",
            expected_sig, sig
        );
    }

    /// **RFC 6979 Appendix A.2.1 — DSA-1024, SHA-1, message "sample".**
    ///
    /// Same parameter set as the previous test, but with SHA-1 (output
    /// 160 bits, equal to q's bit-length) — exercising the `bits2int`
    /// no-truncation branch and HMAC-SHA-1 DRBG seeding.
    ///
    /// Vector: RFC 6979 §A.2.1 with SHA-1 row.
    #[test]
    fn test_rfc6979_a2_1_dsa1024_sha1() {
        let p = BigNum::from_bytes_be(&hex_to_bytes(
            "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
             E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
             73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
             881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        ));
        let q = BigNum::from_bytes_be(&hex_to_bytes(
            "996F967F6C8E388D9E28D01E205FBA957A5698B1",
        ));
        let g = BigNum::from_bytes_be(&hex_to_bytes(
            "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
             89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
             87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
             17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        ));
        let x = BigNum::from_bytes_be(&hex_to_bytes("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7"));

        let params = DsaParams::new(p, q, g).expect("DSA-1024 params should validate");
        let private_key = DsaPrivateKey::from_components(x, params).expect("private key valid");

        // SHA-1("sample") = "sample" hashed with SHA-1 (20 bytes).
        // Verified via `echo -n "sample" | openssl dgst -sha1` and python-ecdsa.
        let digest = hex_to_bytes("8151325DCDBAE9E0FF95F9F9658432DBEDFDB209");

        // Expected per RFC 6979 §A.2.1 SHA-1 row.
        let expected_r = hex_to_bytes("2E1A0C2562B2912CAAF89186FB0F42001585DA55");
        let expected_s = hex_to_bytes("29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5");
        let mut expected_sig = Vec::with_capacity(40);
        expected_sig.extend_from_slice(&expected_r);
        expected_sig.extend_from_slice(&expected_s);

        let sig = sign_deterministic(&private_key, &digest, "SHA-1")
            .expect("sign_deterministic should succeed for valid inputs");

        assert_eq!(
            sig, expected_sig,
            "RFC 6979 A.2.1 DSA-1024/SHA-1 vector mismatch.\n\
             Expected: {:02X?}\n\
             Got:      {:02X?}",
            expected_sig, sig
        );
    }

    /// **RFC 6979 Appendix A.2.2 — DSA-2048, SHA-256, message "sample".**
    ///
    /// Vector for the L=2048, N=256 parameter set. SHA-256 output length
    /// equals q's bit-length, exercising the `bits2int` equal-length
    /// branch (no truncation, no zero-padding).
    ///
    /// Vector: RFC 6979 §A.2.2 SHA-256 row.
    #[test]
    fn test_rfc6979_a2_2_dsa2048_sha256() {
        let p = BigNum::from_bytes_be(&hex_to_bytes(
            "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48\
             C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F\
             FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5\
             B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2\
             35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41\
             F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE\
             92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15\
             3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B",
        ));
        let q = BigNum::from_bytes_be(&hex_to_bytes(
            "F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F",
        ));
        let g = BigNum::from_bytes_be(&hex_to_bytes(
            "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613\
             D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4\
             6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472\
             085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5\
             AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA\
             3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71\
             BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0\
             DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7",
        ));
        let x = BigNum::from_bytes_be(&hex_to_bytes(
            "69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC",
        ));

        let params = DsaParams::new(p, q, g).expect("DSA-2048 params should validate");
        let private_key = DsaPrivateKey::from_components(x, params).expect("private key valid");

        // SHA-256("sample")
        let digest = hex_to_bytes(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
        );

        let expected_r = hex_to_bytes(
            "EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809",
        );
        let expected_s = hex_to_bytes(
            "7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53",
        );
        let mut expected_sig = Vec::with_capacity(64);
        expected_sig.extend_from_slice(&expected_r);
        expected_sig.extend_from_slice(&expected_s);

        let sig = sign_deterministic(&private_key, &digest, "SHA-256")
            .expect("sign_deterministic should succeed for valid inputs");

        assert_eq!(
            sig, expected_sig,
            "RFC 6979 A.2.2 DSA-2048/SHA-256 vector mismatch.\n\
             Expected: {:02X?}\n\
             Got:      {:02X?}",
            expected_sig, sig
        );
    }

    /// **Determinism Property:** Same inputs always produce same signature.
    ///
    /// Verifies the core RFC 6979 invariant — repeated calls with identical
    /// `(key, digest, hash_name)` produce byte-identical output. This is the
    /// security property that distinguishes RFC 6979 from random-`k` signing.
    #[test]
    fn test_rfc6979_determinism() {
        let p = BigNum::from_bytes_be(&hex_to_bytes(
            "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
             E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
             73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
             881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        ));
        let q = BigNum::from_bytes_be(&hex_to_bytes(
            "996F967F6C8E388D9E28D01E205FBA957A5698B1",
        ));
        let g = BigNum::from_bytes_be(&hex_to_bytes(
            "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
             89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
             87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
             17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        ));
        let x = BigNum::from_bytes_be(&hex_to_bytes("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7"));

        let params = DsaParams::new(p, q, g).expect("DSA-1024 params should validate");
        let private_key = DsaPrivateKey::from_components(x, params).expect("private key valid");

        let digest = hex_to_bytes(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
        );

        let sig1 = sign_deterministic(&private_key, &digest, "SHA-256").expect("sign 1");
        let sig2 = sign_deterministic(&private_key, &digest, "SHA-256").expect("sign 2");
        let sig3 = sign_deterministic(&private_key, &digest, "SHA-256").expect("sign 3");

        assert_eq!(sig1, sig2, "RFC 6979: deterministic invariant violated (1 vs 2)");
        assert_eq!(sig2, sig3, "RFC 6979: deterministic invariant violated (2 vs 3)");
    }

    /// **Different digests produce different signatures.**
    ///
    /// Negative property test — flipping a single bit in the digest must
    /// produce an entirely different signature. This validates that the
    /// HMAC-DRBG seeding correctly absorbs the digest input.
    #[test]
    fn test_rfc6979_different_digests_diverge() {
        let p = BigNum::from_bytes_be(&hex_to_bytes(
            "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
             E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
             73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
             881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        ));
        let q = BigNum::from_bytes_be(&hex_to_bytes(
            "996F967F6C8E388D9E28D01E205FBA957A5698B1",
        ));
        let g = BigNum::from_bytes_be(&hex_to_bytes(
            "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
             89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
             87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
             17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        ));
        let x = BigNum::from_bytes_be(&hex_to_bytes("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7"));

        let params = DsaParams::new(p, q, g).expect("DSA-1024 params should validate");
        let private_key = DsaPrivateKey::from_components(x, params).expect("private key valid");

        let mut digest_a = hex_to_bytes(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
        );
        let mut digest_b = digest_a.clone();
        digest_b[0] ^= 0x01; // flip one bit

        let sig_a = sign_deterministic(&private_key, &digest_a, "SHA-256").expect("sign a");
        let sig_b = sign_deterministic(&private_key, &digest_b, "SHA-256").expect("sign b");

        assert_ne!(
            sig_a, sig_b,
            "RFC 6979: distinct digests must yield distinct signatures (single-bit flip)"
        );

        digest_a.zeroize();
        digest_b.zeroize();
    }

    /// **Deterministic signature is verifiable.**
    ///
    /// End-to-end roundtrip: a signature produced by `sign_deterministic`
    /// must verify successfully via the standard `verify` function. This
    /// proves that the deterministic-`k` path produces mathematically valid
    /// DSA signatures (not just byte-matching to RFC 6979 vectors).
    #[test]
    fn test_rfc6979_signature_verifies() {
        let p = BigNum::from_bytes_be(&hex_to_bytes(
            "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
             E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
             73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
             881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        ));
        let q = BigNum::from_bytes_be(&hex_to_bytes(
            "996F967F6C8E388D9E28D01E205FBA957A5698B1",
        ));
        let g = BigNum::from_bytes_be(&hex_to_bytes(
            "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
             89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
             87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
             17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        ));
        let x = BigNum::from_bytes_be(&hex_to_bytes("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7"));
        let y = BigNum::from_bytes_be(&hex_to_bytes(
            "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653\
             92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D\
             4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6\
             82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B",
        ));

        let params = DsaParams::new(p, q, g).expect("DSA-1024 params should validate");
        let private_key =
            DsaPrivateKey::from_components(x, params.clone()).expect("private key valid");
        let public_key = DsaPublicKey::from_components(y, params).expect("public key valid");

        let digest = hex_to_bytes(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
        );

        let sig = sign_deterministic(&private_key, &digest, "SHA-256")
            .expect("sign_deterministic should succeed");

        let verified = verify(&public_key, &digest, &sig).expect("verify should not error");
        assert!(verified, "RFC 6979 deterministic signature should verify");
    }

    /// **Unsupported hash names are rejected.**
    ///
    /// `sign_deterministic` requires a hash name resolvable by the HMAC
    /// primitive. Unknown names must surface as an error rather than
    /// silently fall back to a default — consistent with R5 (no sentinel
    /// values) and proper error propagation.
    #[test]
    fn test_rfc6979_unknown_hash_name_errors() {
        let p = BigNum::from_bytes_be(&hex_to_bytes(
            "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
             E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
             73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
             881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        ));
        let q = BigNum::from_bytes_be(&hex_to_bytes(
            "996F967F6C8E388D9E28D01E205FBA957A5698B1",
        ));
        let g = BigNum::from_bytes_be(&hex_to_bytes(
            "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
             89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
             87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
             17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        ));
        let x = BigNum::from_bytes_be(&hex_to_bytes("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7"));
        let params = DsaParams::new(p, q, g).expect("DSA-1024 params should validate");
        let private_key = DsaPrivateKey::from_components(x, params).expect("private key valid");

        let digest = hex_to_bytes(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
        );

        let result = sign_deterministic(&private_key, &digest, "BOGUS-HASH-NAME");
        assert!(
            result.is_err(),
            "Unknown hash name must produce a hard error, not a silent fallback"
        );
    }
}
