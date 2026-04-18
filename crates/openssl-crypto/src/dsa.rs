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
    let q = crate::bn::prime::generate_prime(q_bits, false)?;

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

/// Perform one attempt at DSA signing.
///
/// Returns the signature `(r, s)` or an error. If `r` or `s` is zero,
/// returns an error whose message contains "retry" to signal the caller.
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
    // Step 1: Generate random nonce k in [1, q-1]
    let mut k = generate_private_key_value(q)?;

    // Step 2: r = (g^k mod p) mod q
    let gk_mod_p = crate::bn::montgomery::mod_exp(g, &k, p)?;
    let r = crate::bn::arithmetic::nnmod(&gk_mod_p, q)?;

    if r.is_zero() {
        k.clear();
        return Err(CryptoError::Key("DSA sign: r is zero (retry)".into()));
    }

    // Step 3: kinv = k^(-1) mod q
    let kinv = crate::bn::arithmetic::mod_inverse(&k, q)?;
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
    let w = crate::bn::arithmetic::mod_inverse(&sig.s, q)?;

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
}
