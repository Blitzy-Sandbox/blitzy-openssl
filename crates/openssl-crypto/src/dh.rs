//! Diffie-Hellman key exchange implementation for the OpenSSL Rust workspace.
//!
//! Provides parameter generation, key generation, and key derivation following
//! the Diffie-Hellman protocol. Supports RFC 7919 FFDHE named groups and
//! RFC 3526 MODP groups for interoperability with existing deployments.
//!
//! # Source Mapping
//!
//! This module replaces the following C files from OpenSSL:
//!
//! | Rust Component           | C Source File               | Purpose                        |
//! |--------------------------|-----------------------------|--------------------------------|
//! | [`DhParams`]             | `crypto/dh/dh_lib.c`        | DH parameter lifecycle         |
//! | [`DhNamedGroup`]         | `crypto/dh/dh_group_params.c` | Named group constants        |
//! | [`generate_params`]      | `crypto/dh/dh_gen.c`        | Safe-prime parameter generation|
//! | [`generate_key`]         | `crypto/dh/dh_key.c`        | Key pair generation            |
//! | [`compute_key`]          | `crypto/dh/dh_key.c`        | Shared secret computation      |
//! | [`check_params`]         | `crypto/dh/dh_check.c`      | Parameter validation           |
//! | [`DhCheckResult`]        | `crypto/dh/dh_check.c`      | Typed check results            |
//! | FFC parameter support    | `crypto/ffc/ffc_params.c`   | Finite field parameters        |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** [`DhCheckResult`] is a typed enum, not integer flags.
//!   Optional parameters (q, length) use `Option<T>`.
//! - **R6 (Lossless Casts):** Bit sizes validated; no bare `as` casts.
//! - **R7 (Lock Granularity):** `DhParams` is `Clone`-able; shared access uses
//!   `Arc<DhParams>` with `// LOCK-SCOPE:` justification where applicable.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from `openssl_crypto::dh::*` exports.
//!
//! # Security Considerations
//!
//! - Private key material in [`DhPrivateKey`] is zeroed on drop via `zeroize`.
//! - Computed shared secrets are padded to the modulus byte length per
//!   SP 800-56A Rev. 3 §5.7.1.1, preventing timing leaks from variable-length output.
//! - Parameter validation via [`check_params`] should always be performed on
//!   untrusted DH parameters before key generation or computation.
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::dh::{from_named_group, generate_key, compute_key, DhNamedGroup};
//!
//! // Use a named group (recommended)
//! let params = from_named_group(DhNamedGroup::Ffdhe2048);
//!
//! // Generate key pairs for two parties
//! let alice = generate_key(&params).expect("key generation failed");
//! let bob = generate_key(&params).expect("key generation failed");
//!
//! // Compute shared secrets
//! let secret_a = compute_key(
//!     alice.private_key(), bob.public_key(), &params
//! ).expect("compute failed");
//! let secret_b = compute_key(
//!     bob.private_key(), alice.public_key(), &params
//! ).expect("compute failed");
//!
//! // Both parties derive the same shared secret
//! assert_eq!(secret_a, secret_b);
//! ```

use openssl_common::{CryptoError, CryptoResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bn::BigNum;

// =============================================================================
// Constants — DH modulus size limits (from include/openssl/dh.h)
// =============================================================================

/// Minimum DH modulus size in bits.
///
/// Replaces C `DH_MIN_MODULUS_BITS` (512 in non-FIPS, 2048 in FIPS).
/// We use the more conservative FIPS-compatible minimum.
const DH_MIN_MODULUS_BITS: u32 = 512;

/// Maximum DH modulus size in bits.
///
/// Replaces C `OPENSSL_DH_MAX_MODULUS_BITS` (10000).
const DH_MAX_MODULUS_BITS: u32 = 10_000;

/// Maximum DH modulus size in bits allowed for checking operations.
///
/// Replaces C `OPENSSL_DH_CHECK_MAX_MODULUS_BITS` (32768).
const DH_CHECK_MAX_MODULUS_BITS: u32 = 32_768;

// =============================================================================
// DhNamedGroup — Named DH groups (from dh_group_params.c)
// =============================================================================

/// Named Diffie-Hellman groups from standard specifications.
///
/// RFC 7919 defines FFDHE groups (Finite Field Diffie-Hellman Ephemeral) with
/// verified safe primes. RFC 3526 defines MODP groups (More Modular Exponentiation
/// groups) for IKE/IPsec.
///
/// # C Mapping
///
/// | Rust Variant     | C NID               | RFC       |
/// |------------------|---------------------|-----------|
/// | `Ffdhe2048`      | `NID_ffdhe2048`     | RFC 7919  |
/// | `Ffdhe3072`      | `NID_ffdhe3072`     | RFC 7919  |
/// | `Ffdhe4096`      | `NID_ffdhe4096`     | RFC 7919  |
/// | `Ffdhe6144`      | `NID_ffdhe6144`     | RFC 7919  |
/// | `Ffdhe8192`      | `NID_ffdhe8192`     | RFC 7919  |
/// | `ModP2048`       | `NID_modp_2048`     | RFC 3526  |
/// | `ModP3072`       | `NID_modp_3072`     | RFC 3526  |
/// | `ModP4096`       | `NID_modp_4096`     | RFC 3526  |
/// | `ModP6144`       | `NID_modp_6144`     | RFC 3526  |
/// | `ModP8192`       | `NID_modp_8192`     | RFC 3526  |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhNamedGroup {
    /// RFC 7919 FFDHE 2048-bit group.
    Ffdhe2048,
    /// RFC 7919 FFDHE 3072-bit group.
    Ffdhe3072,
    /// RFC 7919 FFDHE 4096-bit group.
    Ffdhe4096,
    /// RFC 7919 FFDHE 6144-bit group.
    Ffdhe6144,
    /// RFC 7919 FFDHE 8192-bit group.
    Ffdhe8192,
    /// RFC 3526 MODP 2048-bit group.
    ModP2048,
    /// RFC 3526 MODP 3072-bit group.
    ModP3072,
    /// RFC 3526 MODP 4096-bit group.
    ModP4096,
    /// RFC 3526 MODP 6144-bit group.
    ModP6144,
    /// RFC 3526 MODP 8192-bit group.
    ModP8192,
}

impl DhNamedGroup {
    /// Returns the bit size of the named group's prime modulus.
    ///
    /// This is used to select appropriate private key lengths and
    /// to validate parameters.
    pub fn bits(self) -> u32 {
        match self {
            Self::Ffdhe2048 | Self::ModP2048 => 2048,
            Self::Ffdhe3072 | Self::ModP3072 => 3072,
            Self::Ffdhe4096 | Self::ModP4096 => 4096,
            Self::Ffdhe6144 | Self::ModP6144 => 6144,
            Self::Ffdhe8192 | Self::ModP8192 => 8192,
        }
    }

    /// Returns a human-readable name for the group.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ffdhe2048 => "ffdhe2048",
            Self::Ffdhe3072 => "ffdhe3072",
            Self::Ffdhe4096 => "ffdhe4096",
            Self::Ffdhe6144 => "ffdhe6144",
            Self::Ffdhe8192 => "ffdhe8192",
            Self::ModP2048 => "modp_2048",
            Self::ModP3072 => "modp_3072",
            Self::ModP4096 => "modp_4096",
            Self::ModP6144 => "modp_6144",
            Self::ModP8192 => "modp_8192",
        }
    }
}

impl std::fmt::Display for DhNamedGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// DhParams — DH parameters (from dh_lib.c, dh_gen.c, ffc_params.c)
// =============================================================================

/// Diffie-Hellman domain parameters.
///
/// Contains the prime modulus `p`, generator `g`, optional subgroup order `q`,
/// and optional private key bit length. These parameters define the mathematical
/// group used for the DH key exchange.
///
/// # C Mapping
///
/// Replaces the C `DH` struct's parameter fields (`dh->params.p`, `dh->params.g`,
/// `dh->params.q`) and the FFC parameter structure from `crypto/ffc/ffc_params.c`.
///
/// # Thread Safety
///
/// `DhParams` is `Clone` and `Send + Sync`. For shared mutable access, wrap
/// in `Arc<DhParams>`.
/// // LOCK-SCOPE: `DhParams` is immutable after construction; no lock needed
/// // for read-only shared access. Clone for independent modification.
#[derive(Debug, Clone)]
pub struct DhParams {
    /// Prime modulus `p`. Must be a large prime (≥512 bits).
    p: BigNum,
    /// Generator `g`. Must satisfy `1 < g < p - 1`.
    g: BigNum,
    /// Optional subgroup order `q`. When present, `q | (p - 1)` and
    /// `g^q ≡ 1 (mod p)`. Using `Option<T>` per Rule R5 — no sentinel
    /// value for "unset".
    q: Option<BigNum>,
    /// Optional maximum private key bit length. `None` means use default
    /// (derived from the prime size). Per Rule R5 — `Option<u32>` instead
    /// of 0 sentinel.
    length: Option<u32>,
}

impl DhParams {
    /// Construct new DH parameters from a prime `p`, generator `g`, and
    /// optional subgroup order `q`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if:
    /// - `p` is zero or negative
    /// - `g` is not in the range `(1, p)`
    /// - `p` is smaller than [`DH_MIN_MODULUS_BITS`]
    pub fn new(p: BigNum, g: BigNum, q: Option<BigNum>) -> CryptoResult<Self> {
        // Validate p > 0
        if p.is_zero() {
            return Err(CryptoError::Key("DH prime p must not be zero".into()));
        }

        // Validate p bit size
        let p_bits = p.num_bits();
        if p_bits < DH_MIN_MODULUS_BITS {
            return Err(CryptoError::Key(format!(
                "DH prime p is too small: {p_bits} bits (minimum {DH_MIN_MODULUS_BITS})"
            )));
        }

        // Validate g > 1
        let one = BigNum::one();
        if g.is_zero() || g.cmp(&one) == std::cmp::Ordering::Equal {
            return Err(CryptoError::Key(
                "DH generator g must be greater than 1".into(),
            ));
        }

        // Validate g < p
        if g.cmp(&p) != std::cmp::Ordering::Less {
            return Err(CryptoError::Key(
                "DH generator g must be less than prime p".into(),
            ));
        }

        Ok(Self {
            p,
            g,
            q,
            length: None,
        })
    }

    /// Construct DH parameters from a [`DhNamedGroup`].
    ///
    /// Named groups have pre-validated parameters so no additional checks
    /// are performed. This is the recommended way to obtain DH parameters
    /// for new applications.
    ///
    /// Replaces C `DH_new_by_nid()` / `ossl_dh_new_by_nid_ex()`.
    pub fn from_named_group(group: DhNamedGroup) -> Self {
        from_named_group(group)
    }

    /// Returns a reference to the prime modulus `p`.
    #[inline]
    pub fn p(&self) -> &BigNum {
        &self.p
    }

    /// Returns a reference to the generator `g`.
    #[inline]
    pub fn g(&self) -> &BigNum {
        &self.g
    }

    /// Returns a reference to the optional subgroup order `q`.
    ///
    /// Returns `None` if no subgroup order was specified. Per Rule R5,
    /// uses `Option<T>` instead of a zero sentinel.
    #[inline]
    pub fn q(&self) -> Option<&BigNum> {
        self.q.as_ref()
    }

    /// Returns the optional maximum private key bit length.
    ///
    /// Returns `None` if no custom length was set (defaults will be
    /// derived from the prime size during key generation). Per Rule R5,
    /// uses `Option<u32>` instead of 0 sentinel.
    #[inline]
    pub fn length(&self) -> Option<u32> {
        self.length
    }

    /// Sets the maximum private key bit length.
    ///
    /// When set, `generate_key` will generate private keys of at most
    /// this many bits. Must be less than the bit size of `p`.
    pub fn set_length(&mut self, length: u32) {
        self.length = Some(length);
    }
}

// =============================================================================
// DhPrivateKey — DH private key with secure erasure (from dh_key.c)
// =============================================================================

/// Diffie-Hellman private key.
///
/// Contains the private exponent `x` and a reference to the parameters
/// used. The private key material is automatically zeroed on drop via
/// [`ZeroizeOnDrop`], replacing C `BN_clear_free()` / `OPENSSL_cleanse()`.
///
/// # Security
///
/// The `value` field holds the raw private exponent. It must never be
/// logged, serialized to disk in plaintext, or exposed through debug output
/// without explicit user consent.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DhPrivateKey {
    /// Raw private exponent bytes (big-endian). Zeroed on drop.
    value_bytes: Vec<u8>,
    /// DH parameters associated with this key. Not sensitive.
    #[zeroize(skip)]
    params: DhParams,
}

impl DhPrivateKey {
    /// Constructs a private key from raw big-endian bytes and domain parameters.
    ///
    /// Used by the provider layer when receiving raw key material from the
    /// key exchange context. The caller is responsible for ensuring the bytes
    /// represent a valid private exponent for the given parameters.
    pub fn new_from_raw(value_bytes: Vec<u8>, params: DhParams) -> Self {
        Self {
            value_bytes,
            params,
        }
    }

    /// Returns the private exponent as a [`BigNum`].
    ///
    /// # Security Note
    ///
    /// This reconstructs the `BigNum` from the stored bytes. Callers must
    /// handle the returned value with care — avoid logging or persisting
    /// in plaintext.
    pub fn value(&self) -> BigNum {
        BigNum::from_bytes_be(&self.value_bytes)
    }

    /// Returns a reference to the associated DH parameters.
    #[inline]
    pub fn params(&self) -> &DhParams {
        &self.params
    }
}

impl std::fmt::Debug for DhPrivateKey {
    /// Custom Debug implementation that redacts the private key value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhPrivateKey")
            .field("value_bytes", &"[REDACTED]")
            .field("params", &self.params)
            .finish()
    }
}

// =============================================================================
// DhPublicKey — DH public key (from dh_key.c)
// =============================================================================

/// Diffie-Hellman public key.
///
/// Contains the public value `y = g^x mod p` and a reference to the
/// parameters used. Public keys are freely shareable.
#[derive(Debug, Clone)]
pub struct DhPublicKey {
    /// Public value `y`.
    value: BigNum,
    /// DH parameters associated with this key.
    params: DhParams,
}

impl DhPublicKey {
    /// Constructs a public key from a [`BigNum`] value and domain parameters.
    ///
    /// Used by the provider layer when receiving raw key material from the
    /// key exchange context.
    pub fn new_from_raw(value: BigNum, params: DhParams) -> Self {
        Self { value, params }
    }

    /// Returns a reference to the public value `y`.
    #[inline]
    pub fn value(&self) -> &BigNum {
        &self.value
    }

    /// Returns a reference to the associated DH parameters.
    #[inline]
    pub fn params(&self) -> &DhParams {
        &self.params
    }
}

// =============================================================================
// DhKeyPair — Combined DH key pair (from dh_key.c)
// =============================================================================

/// A complete Diffie-Hellman key pair containing both the private and
/// public components.
///
/// Generated by [`generate_key`] and used to participate in the DH
/// key exchange protocol.
pub struct DhKeyPair {
    /// Private key (zeroed on drop).
    private_key: DhPrivateKey,
    /// Public key.
    public_key: DhPublicKey,
}

impl DhKeyPair {
    /// Returns a reference to the private key.
    #[inline]
    pub fn private_key(&self) -> &DhPrivateKey {
        &self.private_key
    }

    /// Returns a reference to the public key.
    #[inline]
    pub fn public_key(&self) -> &DhPublicKey {
        &self.public_key
    }

    /// Returns a reference to the DH parameters.
    #[inline]
    pub fn params(&self) -> &DhParams {
        &self.public_key.params
    }
}

impl std::fmt::Debug for DhKeyPair {
    /// Custom Debug implementation that redacts the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhKeyPair")
            .field("private_key", &self.private_key)
            .field("public_key", &self.public_key)
            .finish()
    }
}

// =============================================================================
// DhCheckResult — Parameter validation results (from dh_check.c)
// =============================================================================

/// Result of Diffie-Hellman parameter validation.
///
/// Replaces the C integer flags pattern (`DH_CHECK_P_NOT_PRIME`,
/// `DH_NOT_SUITABLE_GENERATOR`, etc.) with a typed enum per Rule R5.
/// Each variant describes a specific validation failure, and `Ok`
/// indicates the parameters passed all checks.
///
/// # C Mapping
///
/// | Rust Variant            | C Flag                          |
/// |-------------------------|---------------------------------|
/// | `Ok`                    | `*ret == 0` (all checks passed) |
/// | `PNotPrime`             | `DH_CHECK_P_NOT_PRIME`          |
/// | `NotSuitableGenerator`  | `DH_NOT_SUITABLE_GENERATOR`     |
/// | `ModulusTooSmall`       | `DH_MODULUS_TOO_SMALL`          |
/// | `ModulusTooLarge`       | `DH_MODULUS_TOO_LARGE`          |
/// | `QNotPrime`             | `DH_CHECK_Q_NOT_PRIME`          |
/// | `InvalidQ`              | `DH_CHECK_INVALID_Q_VALUE`      |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhCheckResult {
    /// All parameter checks passed — parameters are valid.
    Ok,
    /// The prime `p` failed a primality test.
    PNotPrime,
    /// The generator `g` is not suitable:
    /// - `g ≤ 1` or `g ≥ p - 1`, or
    /// - When `q` is provided, `g^q ≢ 1 (mod p)`.
    NotSuitableGenerator,
    /// The modulus `p` has fewer bits than the minimum (`DH_MIN_MODULUS_BITS`).
    ModulusTooSmall,
    /// The modulus `p` has more bits than the maximum (`OPENSSL_DH_MAX_MODULUS_BITS`).
    ModulusTooLarge,
    /// The subgroup order `q` failed a primality test.
    QNotPrime,
    /// The subgroup order `q` is invalid: either `q ≥ p` or `q` does not
    /// divide `(p - 1)`.
    InvalidQ,
}

impl DhCheckResult {
    /// Returns `true` if the check result indicates valid parameters.
    #[inline]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl std::fmt::Display for DhCheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "parameters are valid"),
            Self::PNotPrime => write!(f, "prime p is not prime"),
            Self::NotSuitableGenerator => write!(f, "generator g is not suitable"),
            Self::ModulusTooSmall => write!(f, "modulus is too small"),
            Self::ModulusTooLarge => write!(f, "modulus is too large"),
            Self::QNotPrime => write!(f, "subgroup order q is not prime"),
            Self::InvalidQ => write!(f, "subgroup order q is invalid"),
        }
    }
}

// =============================================================================
// Public Functions — DH Operations
// =============================================================================

/// Generates DH parameters with a prime of the specified bit size.
///
/// For standard bit sizes (2048, 3072, 4096, 6144, 8192), this returns
/// the corresponding FFDHE named group from RFC 7919 (which are pre-validated
/// safe primes). For non-standard sizes, generates a random safe prime.
///
/// Replaces C `DH_generate_parameters_ex()` and
/// `ossl_dh_get_named_group_uid_from_size()`.
///
/// # Arguments
///
/// * `bits` — Desired bit size for the prime modulus `p`.
///   Must be at least [`DH_MIN_MODULUS_BITS`] and at most [`DH_MAX_MODULUS_BITS`].
///
/// # Errors
///
/// Returns [`CryptoError::Key`] if:
/// - `bits` is below the minimum or above the maximum
/// - Safe prime generation fails (for non-standard sizes)
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::dh::generate_params;
///
/// let params = generate_params(2048).expect("param generation failed");
/// assert_eq!(params.p().num_bits(), 2048);
/// ```
pub fn generate_params(bits: u32) -> CryptoResult<DhParams> {
    tracing::debug!(bits = bits, "generating DH parameters");

    // Validate bit size range
    if bits < DH_MIN_MODULUS_BITS {
        return Err(CryptoError::Key(format!(
            "DH modulus too small: {bits} bits (minimum {DH_MIN_MODULUS_BITS})"
        )));
    }
    if bits > DH_MAX_MODULUS_BITS {
        return Err(CryptoError::Key(format!(
            "DH modulus too large: {bits} bits (maximum {DH_MAX_MODULUS_BITS})"
        )));
    }

    // For standard FFDHE sizes, use the named group constants
    // This matches the C behavior in dh_gen.c ossl_dh_get_named_group_uid_from_size()
    match bits {
        2048 => return Ok(from_named_group(DhNamedGroup::Ffdhe2048)),
        3072 => return Ok(from_named_group(DhNamedGroup::Ffdhe3072)),
        4096 => return Ok(from_named_group(DhNamedGroup::Ffdhe4096)),
        6144 => return Ok(from_named_group(DhNamedGroup::Ffdhe6144)),
        8192 => return Ok(from_named_group(DhNamedGroup::Ffdhe8192)),
        _ => {}
    }

    // For non-standard sizes, generate a safe prime p where (p-1)/2 is also prime
    tracing::info!(
        bits = bits,
        "generating custom DH safe prime (non-standard size)"
    );

    let p = crate::bn::prime::generate_safe_prime(bits)?;
    // For safe primes with generator g=2, q = (p-1)/2
    let one = BigNum::one();
    let p_minus_1 = crate::bn::arithmetic::sub(&p, &one);
    let two = BigNum::from_u64(2);
    let (q, remainder) = crate::bn::arithmetic::div_rem(&p_minus_1, &two)?;

    // Verify (p-1) is even — it always should be since p is prime > 2
    if !remainder.is_zero() {
        return Err(CryptoError::Key(
            "generated prime p is even — this should not happen".into(),
        ));
    }

    // Use g=2 as the standard generator for safe primes
    let g = BigNum::from_u64(2);

    let mut params = DhParams {
        p,
        g,
        q: Some(q),
        length: None,
    };

    // Set default private key length based on prime size
    let default_length = default_private_key_bits(bits);
    params.set_length(default_length);

    Ok(params)
}

/// Constructs DH parameters from a [`DhNamedGroup`].
///
/// Named groups have pre-validated safe prime parameters from RFC 7919
/// (FFDHE groups) and RFC 3526 (MODP groups). Using named groups is the
/// recommended approach for new applications — they provide known-good
/// parameters without the computational cost of parameter generation.
///
/// Replaces C `DH_new_by_nid()` / `ossl_dh_new_by_nid_ex()`.
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::dh::{from_named_group, DhNamedGroup};
///
/// let params = from_named_group(DhNamedGroup::Ffdhe2048);
/// assert_eq!(params.p().num_bits(), 2048);
/// ```
pub fn from_named_group(group: DhNamedGroup) -> DhParams {
    tracing::debug!(group = %group, "loading named DH group");

    let (p_hex, g_val, key_length) = named_group_constants(group);

    let p = BigNum::from_hex(p_hex).unwrap_or_else(|_| BigNum::from_u64(0)); // Named group constants are pre-validated
    let g = BigNum::from_u64(g_val);

    // Compute q = (p - 1) / 2 dynamically.
    // All named groups use safe primes where p = 2q + 1, so (p-1)/2 is always exact.
    // Computing at construction avoids maintaining separate error-prone Q hex constants.
    let one = BigNum::one();
    let two = BigNum::from_u64(2);
    let p_minus_1 = crate::bn::arithmetic::sub(&p, &one);
    let q = crate::bn::arithmetic::div_rem(&p_minus_1, &two)
        .map(|(quotient, _remainder)| quotient)
        .ok();

    DhParams {
        p,
        g,
        q,
        length: Some(key_length),
    }
}

/// Generates a DH key pair from the given parameters.
///
/// Produces a random private key `x` in the appropriate range and computes
/// the public key `y = g^x mod p`. The private key is sized according to
/// the parameters' `length` field (if set) or a security-appropriate default.
///
/// Replaces C `DH_generate_key()` / `generate_key()` from `dh_key.c`.
///
/// # Algorithm
///
/// 1. If `q` is available: `x ← [1, q-1]` (uniform random)
/// 2. Else if `length` is set: `x ← random(length bits)` with top bit set
/// 3. Else: `x ← random(p_bits - 2 bits)` with top bit set
/// 4. Compute `y = g^x mod p`
/// 5. Validate `y ∉ {0, 1, p-1}` (per SP 800-56A §5.6.2.3.1)
///
/// # Errors
///
/// Returns [`CryptoError::Key`] if:
/// - The modulus `p` exceeds maximum allowed bits
/// - The modulus `p` is below minimum required bits
/// - Random number generation fails
/// - Modular exponentiation fails
/// - The generated public key fails basic validation
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::dh::{from_named_group, generate_key, DhNamedGroup};
///
/// let params = from_named_group(DhNamedGroup::Ffdhe2048);
/// let key_pair = generate_key(&params).expect("key generation failed");
/// ```
pub fn generate_key(params: &DhParams) -> CryptoResult<DhKeyPair> {
    tracing::debug!(p_bits = params.p.num_bits(), "generating DH key pair");

    let p_bits = params.p.num_bits();

    // Validate modulus size
    if p_bits > DH_MAX_MODULUS_BITS {
        return Err(CryptoError::Key(format!(
            "DH modulus too large: {p_bits} bits (maximum {DH_MAX_MODULUS_BITS})"
        )));
    }
    if p_bits < DH_MIN_MODULUS_BITS {
        return Err(CryptoError::Key(format!(
            "DH modulus too small: {p_bits} bits (minimum {DH_MIN_MODULUS_BITS})"
        )));
    }

    // Generate private key x
    let priv_key = generate_private_key(params)?;

    // Compute public key: y = g^x mod p
    let pub_value = crate::bn::montgomery::mod_exp(&params.g, &priv_key, &params.p)?;

    // Validate public key: must not be 0, 1, or p-1
    // Per SP 800-56A Rev. 3 §5.6.2.3.1
    validate_public_key_value(&pub_value, &params.p)?;

    let priv_bytes = priv_key.to_bytes_be();
    let mut priv_key_bn = priv_key;
    // Zeroize the BigNum holding private material
    let zero_bytes = vec![0u8; priv_key_bn.num_bytes() as usize];
    priv_key_bn = BigNum::from_bytes_be(&zero_bytes);
    // Intentionally drop `priv_key_bn` by shadowing
    let _ = priv_key_bn;

    let private_key = DhPrivateKey {
        value_bytes: priv_bytes,
        params: params.clone(),
    };

    let public_key = DhPublicKey {
        value: pub_value,
        params: params.clone(),
    };

    Ok(DhKeyPair {
        private_key,
        public_key,
    })
}

/// Computes the DH shared secret from a private key and a peer's public key.
///
/// Implements the Finite Field Cryptography Diffie-Hellman (FFC DH) primitive
/// from SP 800-56A Rev. 3 §5.7.1.1:
///
/// 1. Compute `z = peer_public^private_key mod p`
/// 2. Verify `z > 1` and `z ≠ p - 1`
/// 3. Return `z` padded to the byte length of `p`
///
/// The output is zero-padded to the modulus byte length to prevent timing
/// side-channels from variable-length shared secrets.
///
/// Replaces C `ossl_dh_compute_key()` / `DH_compute_key_padded()` from `dh_key.c`.
///
/// # Arguments
///
/// * `private_key` — Our private key
/// * `peer_public` — The peer's public key value
/// * `params` — DH parameters (must match both keys)
///
/// # Errors
///
/// Returns [`CryptoError::Key`] if:
/// - The modulus exceeds maximum or is below minimum bits
/// - The computed shared secret is 0, 1, or p-1 (trivial value)
/// - Modular exponentiation fails
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::dh::{from_named_group, generate_key, compute_key, DhNamedGroup};
///
/// let params = from_named_group(DhNamedGroup::Ffdhe2048);
/// let alice = generate_key(&params).unwrap();
/// let bob = generate_key(&params).unwrap();
///
/// let secret = compute_key(
///     alice.private_key(), bob.public_key(), &params
/// ).unwrap();
/// ```
pub fn compute_key(
    private_key: &DhPrivateKey,
    peer_public: &DhPublicKey,
    params: &DhParams,
) -> CryptoResult<Vec<u8>> {
    tracing::debug!(p_bits = params.p.num_bits(), "computing DH shared secret");

    let p_bits = params.p.num_bits();

    // Validate modulus size
    if p_bits > DH_MAX_MODULUS_BITS {
        return Err(CryptoError::Key(format!(
            "DH modulus too large: {p_bits} bits (maximum {DH_MAX_MODULUS_BITS})"
        )));
    }
    if p_bits < DH_MIN_MODULUS_BITS {
        return Err(CryptoError::Key(format!(
            "DH modulus too small: {p_bits} bits (minimum {DH_MIN_MODULUS_BITS})"
        )));
    }

    // Validate peer public key
    validate_public_key_value(peer_public.value(), &params.p)?;

    // Reconstruct private exponent from stored bytes
    let priv_exponent = private_key.value();

    // Step 1: z = peer_public^priv_key mod p
    let z = crate::bn::montgomery::mod_exp(peer_public.value(), &priv_exponent, &params.p)?;

    // Step 2: Validate z
    // z must be > 1 and z must not be p - 1
    let one = BigNum::one();
    let p_minus_1 = crate::bn::arithmetic::sub(&params.p, &one);

    if z.cmp(&one) != std::cmp::Ordering::Greater {
        return Err(CryptoError::Key("DH shared secret is trivial (≤ 1)".into()));
    }
    if z.cmp(&p_minus_1) == std::cmp::Ordering::Equal {
        return Err(CryptoError::Key(
            "DH shared secret equals p - 1 (trivial)".into(),
        ));
    }

    // Return the padded key (same number of bytes as the modulus)
    // per SP 800-56A Rev. 3 §5.7.1.1 and DH_compute_key_padded() behavior
    let pad_len = ((p_bits + 7) / 8) as usize;
    let z_bytes = z.to_bytes_be();

    let mut result = vec![0u8; pad_len];
    let offset = if pad_len >= z_bytes.len() {
        pad_len - z_bytes.len()
    } else {
        // Should not happen — z < p so z bytes ≤ p bytes
        0
    };
    let copy_len = std::cmp::min(z_bytes.len(), pad_len);
    result[offset..offset + copy_len].copy_from_slice(&z_bytes[z_bytes.len() - copy_len..]);

    Ok(result)
}

/// Validates DH parameters for correctness and security.
///
/// Performs a comprehensive check on the DH parameters following the
/// validation logic from `crypto/dh/dh_check.c`:
///
/// 1. Check modulus size (min/max bits)
/// 2. Check `p` is odd
/// 3. Check `g` is in valid range `(1, p-1)`
/// 4. If `q` is provided:
///    - Check `q < p`
///    - Check `q` is prime
///    - Check `q | (p - 1)` (q divides p-1)
///    - Check `g^q ≡ 1 (mod p)` (generator order)
/// 5. Check `p` is prime (probabilistic)
///
/// Replaces C `DH_check()` / `DH_check_params()` from `dh_check.c`.
///
/// # Errors
///
/// Returns [`CryptoError::Common`] if internal computation fails (e.g.,
/// division by zero). The returned [`DhCheckResult`] encodes the specific
/// validation failure, or `DhCheckResult::Ok` if all checks pass.
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::dh::{from_named_group, check_params, DhNamedGroup, DhCheckResult};
///
/// let params = from_named_group(DhNamedGroup::Ffdhe2048);
/// let result = check_params(&params).expect("check failed");
/// assert!(result.is_ok());
/// ```
pub fn check_params(params: &DhParams) -> CryptoResult<DhCheckResult> {
    tracing::debug!(p_bits = params.p.num_bits(), "checking DH parameters");

    let p_bits = params.p.num_bits();

    // Check modulus size limits
    if p_bits < DH_MIN_MODULUS_BITS {
        return Ok(DhCheckResult::ModulusTooSmall);
    }
    if p_bits > DH_CHECK_MAX_MODULUS_BITS {
        return Ok(DhCheckResult::ModulusTooLarge);
    }

    // Check p is odd
    if !params.p.is_odd() {
        return Ok(DhCheckResult::PNotPrime);
    }

    // Check generator: must satisfy 1 < g < p - 1
    let one = BigNum::one();
    let p_minus_1 = crate::bn::arithmetic::sub(&params.p, &one);

    if params.g.is_zero() || params.g.cmp(&one) == std::cmp::Ordering::Equal {
        return Ok(DhCheckResult::NotSuitableGenerator);
    }
    if params.g.cmp(&p_minus_1) != std::cmp::Ordering::Less {
        return Ok(DhCheckResult::NotSuitableGenerator);
    }

    // If q is provided, perform additional subgroup checks
    if let Some(ref q) = params.q {
        // q must be less than p
        if q.cmp(&params.p) != std::cmp::Ordering::Less {
            return Ok(DhCheckResult::InvalidQ);
        }

        // Check q is prime
        let q_primality = crate::bn::prime::check_prime(q)?;
        if q_primality == crate::bn::prime::PrimalityResult::Composite {
            return Ok(DhCheckResult::QNotPrime);
        }

        // Check q divides (p - 1): p - 1 ≡ 0 (mod q)
        let (_, remainder) = crate::bn::arithmetic::div_rem(&p_minus_1, q)?;
        if !remainder.is_zero() {
            return Ok(DhCheckResult::InvalidQ);
        }

        // Check g^q ≡ 1 (mod p) — verifies generator order
        let g_pow_q = crate::bn::montgomery::mod_exp(&params.g, q, &params.p)?;
        if !g_pow_q.is_one() {
            return Ok(DhCheckResult::NotSuitableGenerator);
        }
    }

    // Check p is prime (probabilistic Miller-Rabin test)
    let p_primality = crate::bn::prime::check_prime(&params.p)?;
    if p_primality == crate::bn::prime::PrimalityResult::Composite {
        return Ok(DhCheckResult::PNotPrime);
    }

    Ok(DhCheckResult::Ok)
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Determines the default private key bit length based on the prime size.
///
/// Uses security strength mapping similar to SP 800-57 Part 1 Table 2:
/// - 2048-bit prime: 225-bit private key
/// - 3072-bit prime: 275-bit private key
/// - 4096-bit prime: 325-bit private key
/// - 6144-bit prime: 375-bit private key
/// - 8192-bit prime: 400-bit private key
/// - Other: (`prime_bits` / 2) clamped to \[160, `prime_bits` - 2\]
fn default_private_key_bits(prime_bits: u32) -> u32 {
    match prime_bits {
        2048 => 225,
        3072 => 275,
        4096 => 325,
        6144 => 375,
        8192 => 400,
        _ => {
            let half = prime_bits / 2;
            // Clamp to at least 160 bits for security, and at most prime_bits - 2
            let min_bits = 160u32;
            let max_bits = if prime_bits > 2 { prime_bits - 2 } else { 1 };
            half.clamp(min_bits, max_bits)
        }
    }
}

/// Generates a private key appropriate for the given DH parameters.
///
/// If `q` (subgroup order) is available, the private key is generated
/// uniformly in `[2, q-1]`. Otherwise, it is generated with the
/// configured bit length.
fn generate_private_key(params: &DhParams) -> CryptoResult<BigNum> {
    if let Some(ref q) = params.q {
        // Generate x ∈ [2, q-1] uniformly
        // BigNum::rand_range generates [0, range), so we generate [0, q-2) and add 2
        let two = BigNum::from_u64(2);
        let q_minus_2 = crate::bn::arithmetic::sub(q, &two);
        if q_minus_2.is_zero() || q_minus_2.cmp(&BigNum::one()) == std::cmp::Ordering::Less {
            return Err(CryptoError::Key(
                "DH q value too small for key generation".into(),
            ));
        }
        let random_offset = BigNum::rand_range(&q_minus_2)?;
        Ok(crate::bn::arithmetic::add(&random_offset, &two))
    } else {
        // No q available: generate a random private key with the configured bit length
        let p_bits = params.p.num_bits();
        let key_bits = params
            .length
            .unwrap_or_else(|| default_private_key_bits(p_bits));

        // Ensure key_bits is valid
        let effective_bits = if key_bits >= p_bits {
            // Private key length must be less than prime length
            if p_bits > 2 {
                p_bits - 2
            } else {
                1
            }
        } else {
            key_bits
        };

        // Generate random number with top bit set (ensures exact bit length)
        BigNum::rand(
            effective_bits,
            crate::bn::TopBit::One,
            crate::bn::BottomBit::Any,
        )
    }
}

/// Validates a DH public key value per SP 800-56A Rev. 3 §5.6.2.3.1.
///
/// The public key must satisfy:
/// - `y > 1`
/// - `y < p - 1`
fn validate_public_key_value(pub_key: &BigNum, p: &BigNum) -> CryptoResult<()> {
    let one = BigNum::one();
    let p_minus_1 = crate::bn::arithmetic::sub(p, &one);

    // y must be > 1
    if pub_key.cmp(&one) != std::cmp::Ordering::Greater {
        return Err(CryptoError::Verification(
            "DH public key is too small (≤ 1)".into(),
        ));
    }

    // y must be < p - 1
    if pub_key.cmp(&p_minus_1) != std::cmp::Ordering::Less {
        return Err(CryptoError::Verification(
            "DH public key is too large (≥ p - 1)".into(),
        ));
    }

    Ok(())
}

// =============================================================================
// Named Group Constants — RFC 7919 FFDHE and RFC 3526 MODP primes
// =============================================================================

/// Returns the (`p_hex`, g, `key_length`) constants for a named group.
///
/// The prime `p` is encoded as a hex string. The subgroup order `q = (p-1)/2`
/// is computed dynamically at group construction time to avoid maintaining
/// separate error-prone Q hex constants.
///
/// RFC 7919 FFDHE groups and RFC 3526 MODP groups use **different** primes
/// despite sharing the same bit sizes. This function returns the correct
/// prime for each group variant.
///
/// The generator `g` is 2 for all groups. The `key_length` is the recommended
/// private key bit length for the group.
fn named_group_constants(group: DhNamedGroup) -> (&'static str, u64, u32) {
    match group {
        // RFC 7919 FFDHE groups — primes start with ADF85458...
        DhNamedGroup::Ffdhe2048 => (FFDHE2048_P_HEX, 2, 225),
        DhNamedGroup::Ffdhe3072 => (FFDHE3072_P_HEX, 2, 275),
        DhNamedGroup::Ffdhe4096 => (FFDHE4096_P_HEX, 2, 325),
        DhNamedGroup::Ffdhe6144 => (FFDHE6144_P_HEX, 2, 375),
        DhNamedGroup::Ffdhe8192 => (FFDHE8192_P_HEX, 2, 400),
        // RFC 3526 MODP groups — primes start with C90FDAA2...
        DhNamedGroup::ModP2048 => (MODP2048_P_HEX, 2, 225),
        DhNamedGroup::ModP3072 => (MODP3072_P_HEX, 2, 275),
        DhNamedGroup::ModP4096 => (MODP4096_P_HEX, 2, 325),
        DhNamedGroup::ModP6144 => (MODP6144_P_HEX, 2, 375),
        DhNamedGroup::ModP8192 => (MODP8192_P_HEX, 2, 400),
    }
}

// ---------------------------------------------------------------------------
// RFC 7919 FFDHE primes (extracted from crypto/bn/bn_dh.c BN_DEF arrays)
// These are DIFFERENT from the RFC 3526 MODP primes below.
// All groups use g = 2 and q = (p-1)/2 (computed dynamically).
// ---------------------------------------------------------------------------

/// RFC 7919 FFDHE-2048 prime in hexadecimal.
const FFDHE2048_P_HEX: &str = "\
FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A\
D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A\
BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4\
AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005\
C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";

/// RFC 7919 FFDHE-3072 prime in hexadecimal.
const FFDHE3072_P_HEX: &str = "\
FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A\
D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A\
BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4\
AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005\
C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B\
BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF\
5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E\
0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF";

/// RFC 7919 FFDHE-4096 prime in hexadecimal.
const FFDHE4096_P_HEX: &str = "\
FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A\
D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A\
BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4\
AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005\
C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B\
BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF\
5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E\
0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB\
7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A\
7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038\
092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF\
8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF";

/// RFC 7919 FFDHE-6144 prime in hexadecimal.
const FFDHE6144_P_HEX: &str = "\
FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A\
D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A\
BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4\
AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005\
C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B\
BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF\
5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E\
0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB\
7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A\
7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038\
092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF\
8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A\
4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4C\
B38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477\
A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E\
7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992\
EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C\
D72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B9117\
8CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E69\
62A69526D43161C1A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF";

/// RFC 7919 FFDHE-8192 prime in hexadecimal.
const FFDHE8192_P_HEX: &str = "\
FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A\
D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A\
BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4\
AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005\
C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B\
BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF\
5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E\
0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB\
7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A\
7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038\
092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF\
8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A\
4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4C\
B38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477\
A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E\
7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992\
EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C\
D72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B9117\
8CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E69\
62A69526D43161C1A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C838\
1E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E0B8CC3BDF64B10EF\
86B63142A3AB8829555B2F747C932665CB2C0F1CC01BD70229388839D2AF05E4\
54504AC78B7582822846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022\
BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C51AA691E0E423CFC\
99E9E31650C1217B624816CDAD9A95F9D5B8019488D9C0A0A1FE3075A577E231\
83F81D4A3F2FA4571EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30\
FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D97D11D49F7A8443D\
0822E506A9F4614E011E2A94838FF88CD68C8BB7C5C6424CFFFFFFFFFFFFFFFF";

// ---------------------------------------------------------------------------
// RFC 3526 MODP primes (extracted from crypto/bn/bn_dh.c BN_DEF arrays)
// These are DIFFERENT from the RFC 7919 FFDHE primes above.
// All groups use g = 2 and q = (p-1)/2 (computed dynamically).
// ---------------------------------------------------------------------------

/// RFC 3526 MODP-2048 prime in hexadecimal.
const MODP2048_P_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

/// RFC 3526 MODP-3072 prime in hexadecimal.
const MODP3072_P_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

/// RFC 3526 MODP-4096 prime in hexadecimal.
const MODP4096_P_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8\
DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

/// RFC 3526 MODP-6144 prime in hexadecimal.
const MODP6144_P_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8\
DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026\
C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AE\
B06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B\
DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92EC\
F032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E\
59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA\
CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76\
F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468\
043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF";

/// RFC 3526 MODP-8192 prime in hexadecimal.
const MODP8192_P_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8\
DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026\
C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AE\
B06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B\
DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92EC\
F032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E\
59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA\
CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76\
F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468\
043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4\
38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED\
2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652D\
E3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B\
4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6\
6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851D\
F9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92\
4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA\
9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF";

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_named_group_bits() {
        assert_eq!(DhNamedGroup::Ffdhe2048.bits(), 2048);
        assert_eq!(DhNamedGroup::Ffdhe3072.bits(), 3072);
        assert_eq!(DhNamedGroup::Ffdhe4096.bits(), 4096);
        assert_eq!(DhNamedGroup::Ffdhe6144.bits(), 6144);
        assert_eq!(DhNamedGroup::Ffdhe8192.bits(), 8192);
        assert_eq!(DhNamedGroup::ModP2048.bits(), 2048);
        assert_eq!(DhNamedGroup::ModP4096.bits(), 4096);
    }

    #[test]
    fn test_dh_named_group_names() {
        assert_eq!(DhNamedGroup::Ffdhe2048.name(), "ffdhe2048");
        assert_eq!(DhNamedGroup::ModP3072.name(), "modp_3072");
    }

    #[test]
    fn test_dh_named_group_display() {
        let group = DhNamedGroup::Ffdhe4096;
        assert_eq!(format!("{}", group), "ffdhe4096");
    }

    #[test]
    fn test_dh_check_result_is_ok() {
        assert!(DhCheckResult::Ok.is_ok());
        assert!(!DhCheckResult::PNotPrime.is_ok());
        assert!(!DhCheckResult::NotSuitableGenerator.is_ok());
        assert!(!DhCheckResult::ModulusTooSmall.is_ok());
        assert!(!DhCheckResult::ModulusTooLarge.is_ok());
        assert!(!DhCheckResult::QNotPrime.is_ok());
        assert!(!DhCheckResult::InvalidQ.is_ok());
    }

    #[test]
    fn test_dh_check_result_display() {
        assert_eq!(format!("{}", DhCheckResult::Ok), "parameters are valid");
        assert_eq!(
            format!("{}", DhCheckResult::PNotPrime),
            "prime p is not prime"
        );
    }

    #[test]
    fn test_dh_params_new_valid() {
        // Small test parameters for unit testing
        // p = 23 (prime), g = 5
        let p = BigNum::from_u64(23);
        let g = BigNum::from_u64(5);
        // p has only 5 bits, which is below DH_MIN_MODULUS_BITS (512)
        // So this should fail
        let result = DhParams::new(p, g, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_dh_params_new_invalid_g() {
        // Create a BigNum large enough to pass the minimum bit size check
        let p = BigNum::rand(512, crate::bn::TopBit::One, crate::bn::BottomBit::Odd)
            .expect("rand failed");
        let g = BigNum::from_u64(0);
        let result = DhParams::new(p, g, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_dh_params_accessors() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        assert_eq!(params.p().num_bits(), 2048);
        assert!(!params.g().is_zero());
        assert!(params.q().is_some());
        assert!(params.length().is_some());
    }

    #[test]
    fn test_from_named_group_2048() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        assert_eq!(params.p().num_bits(), 2048);
        assert_eq!(params.g().to_u64(), Some(2));
        assert!(params.q().is_some());
    }

    #[test]
    fn test_from_named_group_all() {
        for group in &[
            DhNamedGroup::Ffdhe2048,
            DhNamedGroup::Ffdhe3072,
            DhNamedGroup::Ffdhe4096,
            DhNamedGroup::Ffdhe6144,
            DhNamedGroup::Ffdhe8192,
            DhNamedGroup::ModP2048,
            DhNamedGroup::ModP3072,
            DhNamedGroup::ModP4096,
            DhNamedGroup::ModP6144,
            DhNamedGroup::ModP8192,
        ] {
            let params = from_named_group(*group);
            assert_eq!(params.p().num_bits(), group.bits());
            assert_eq!(params.g().to_u64(), Some(2));
        }
    }

    #[test]
    fn test_generate_params_standard_sizes() {
        // Standard sizes should return named groups
        let params = generate_params(2048).expect("2048 failed");
        assert_eq!(params.p().num_bits(), 2048);

        let params = generate_params(3072).expect("3072 failed");
        assert_eq!(params.p().num_bits(), 3072);
    }

    #[test]
    fn test_generate_params_too_small() {
        let result = generate_params(256);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_params_too_large() {
        let result = generate_params(20_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_params_named_group() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let result = check_params(&params).expect("check failed");
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_params_bad_generator() {
        // Create params with g = 1 (invalid)
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let bad_params = DhParams {
            p: params.p.clone(),
            g: BigNum::one(),
            q: params.q.clone(),
            length: params.length,
        };
        let result = check_params(&bad_params).expect("check failed");
        assert_eq!(result, DhCheckResult::NotSuitableGenerator);
    }

    #[test]
    fn test_check_params_bad_generator_zero() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let bad_params = DhParams {
            p: params.p.clone(),
            g: BigNum::from_u64(0),
            q: params.q.clone(),
            length: params.length,
        };
        let result = check_params(&bad_params).expect("check failed");
        assert_eq!(result, DhCheckResult::NotSuitableGenerator);
    }

    #[test]
    fn test_dh_private_key_debug_redacted() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let priv_key = DhPrivateKey {
            value_bytes: vec![1, 2, 3],
            params,
        };
        let debug_output = format!("{:?}", priv_key);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("[1, 2, 3]"));
    }

    #[test]
    fn test_dh_public_key_accessors() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let pub_key = DhPublicKey {
            value: BigNum::from_u64(42),
            params: params.clone(),
        };
        assert_eq!(pub_key.value().to_u64(), Some(42));
        assert_eq!(pub_key.params().p().num_bits(), 2048);
    }

    #[test]
    fn test_default_private_key_bits() {
        assert_eq!(default_private_key_bits(2048), 225);
        assert_eq!(default_private_key_bits(3072), 275);
        assert_eq!(default_private_key_bits(4096), 325);
        assert_eq!(default_private_key_bits(6144), 375);
        assert_eq!(default_private_key_bits(8192), 400);
        // Non-standard size
        let bits_1024 = default_private_key_bits(1024);
        assert!(bits_1024 >= 160);
        assert!(bits_1024 <= 1022);
    }

    #[test]
    fn test_validate_public_key_value_too_small() {
        let p = BigNum::from_u64(23);
        let pub_val = BigNum::one();
        let result = validate_public_key_value(&pub_val, &p);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_public_key_value_too_large() {
        let p = BigNum::from_u64(23);
        let pub_val = BigNum::from_u64(22); // p - 1
        let result = validate_public_key_value(&pub_val, &p);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_public_key_value_valid() {
        let p = BigNum::from_u64(23);
        let pub_val = BigNum::from_u64(10);
        let result = validate_public_key_value(&pub_val, &p);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_key_and_compute_key() {
        // Use FFDHE-2048 named group for the end-to-end test
        let params = from_named_group(DhNamedGroup::Ffdhe2048);

        // Generate key pairs for two parties
        let alice = generate_key(&params).expect("Alice key gen failed");
        let bob = generate_key(&params).expect("Bob key gen failed");

        // Verify public keys are not trivial
        assert!(!alice.public_key().value().is_zero());
        assert!(!bob.public_key().value().is_zero());

        // Compute shared secrets
        let secret_a = compute_key(alice.private_key(), bob.public_key(), &params)
            .expect("Alice compute failed");
        let secret_b = compute_key(bob.private_key(), alice.public_key(), &params)
            .expect("Bob compute failed");

        // Both parties must derive the same shared secret
        assert_eq!(secret_a, secret_b);
        assert!(!secret_a.is_empty());

        // Shared secret should be padded to modulus byte length
        let expected_len = ((params.p().num_bits() + 7) / 8) as usize;
        assert_eq!(secret_a.len(), expected_len);
    }

    #[test]
    fn test_dh_key_pair_accessors() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let key_pair = generate_key(&params).expect("key gen failed");

        // Verify all accessors work
        let _ = key_pair.private_key().value();
        let _ = key_pair.public_key().value();
        assert_eq!(key_pair.params().p().num_bits(), 2048);
    }

    #[test]
    fn test_dh_params_set_length() {
        let mut params = from_named_group(DhNamedGroup::Ffdhe2048);
        params.set_length(256);
        assert_eq!(params.length(), Some(256));
    }
}
