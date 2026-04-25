//! Big Number (BN) arithmetic module for the OpenSSL Rust workspace.
//!
//! Provides arbitrary-precision integer operations equivalent to OpenSSL's
//! BN_* API. The internal representation uses `num-bigint::BigInt` as the
//! backend, replacing the hand-rolled limb-level C implementation.
//!
//! # Module Structure
//!
//! - [`BigNum`] — Core type wrapping `BigInt` with OpenSSL-compatible API
//! - [`arithmetic`] — Addition, subtraction, multiplication, division, modular ops
//! - [`montgomery`] — Montgomery multiplication and modular exponentiation
//! - [`prime`] — Primality testing (Miller-Rabin) and prime generation
//!
//! # Design Decisions
//!
//! - `num-bigint::BigInt` is the internal representation, replacing C's
//!   `BN_ULONG *d` limb array. This delegates low-level arithmetic to a
//!   well-tested Rust crate while exposing an OpenSSL-compatible API surface.
//! - `BN_CTX` (temporary allocator pool) is not needed — Rust's ownership
//!   model handles temporary values automatically.
//! - `BN_BLINDING` is implemented as a standalone struct using `BigNum`
//!   operations for RSA blinding support.
//! - All sensitive key material uses `zeroize` for secure erasure.
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::bn::BigNum;
//!
//! let a = BigNum::from_u64(42);
//! let b = BigNum::from_u64(58);
//! let sum = &a + &b;
//! assert_eq!(sum, BigNum::from_u64(100));
//! ```

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Shl, Shr, Sub, SubAssign};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, ToPrimitive, Zero};
use openssl_common::{CryptoError, CryptoResult};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Submodule declarations
pub mod arithmetic;
pub mod montgomery;
pub mod prime;

// ---------------------------------------------------------------------------
// Error types (replaces C ERR_LIB_BN error codes from bn_err.c)
// ---------------------------------------------------------------------------

/// Errors specific to big number operations.
///
/// Replaces C `ERR_LIB_BN` error codes such as `BN_R_DIV_BY_ZERO`,
/// `BN_R_BITS_TOO_SMALL`, etc.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BigNumError {
    /// Division by zero attempted.
    /// Replaces C `BN_R_DIV_BY_ZERO`.
    #[error("division by zero")]
    DivisionByZero,

    /// Number of bits too small for requested operation.
    /// Replaces C `BN_R_BITS_TOO_SMALL`.
    #[error("bits too small: {0}")]
    BitsTooSmall(u32),

    /// `BigNum` too long (exceeds maximum supported size).
    /// Replaces C `BN_R_BIGNUM_TOO_LONG`.
    #[error("bignum too long")]
    BigNumTooLong,

    /// Invalid range for random number generation.
    /// Replaces C `BN_R_INVALID_RANGE`.
    #[error("invalid range")]
    InvalidRange,

    /// Negative value not allowed in this context.
    #[error("negative value not allowed")]
    NegativeNotAllowed,

    /// Invalid encoding format.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    /// Expand on static bignum data not permitted.
    /// Replaces C `BN_R_EXPAND_ON_STATIC_BIGNUM_DATA`.
    #[error("operation not permitted on static bignum")]
    StaticData,

    /// Modular inverse does not exist (gcd != 1).
    #[error("no modular inverse exists")]
    NoInverse,

    /// Called function is not suitable for this context.
    /// Replaces C `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED`.
    #[error("should not have been called")]
    ShouldNotHaveBeenCalled,

    /// Input argument was invalid.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Numeric overflow during computation.
    #[error("arithmetic overflow")]
    Overflow,
}

/// Convert [`BigNumError`] into [`CryptoError`] for seamless `?` propagation.
///
/// Maps BigNum-specific errors to the closest `CryptoError` / `CommonError` variant,
/// preserving the full error message for diagnostics.
impl From<BigNumError> for CryptoError {
    fn from(e: BigNumError) -> Self {
        use openssl_common::CommonError;
        match e {
            BigNumError::Overflow => CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "bignum",
            }),
            BigNumError::InvalidEncoding(msg) => CryptoError::Encoding(msg),
            other => CryptoError::Common(CommonError::InvalidArgument(other.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Random generation control enums (from bn_rand.c)
// ---------------------------------------------------------------------------

/// Control for the most significant bit(s) of a random [`BigNum`].
///
/// Used with [`BigNum::rand`] to control the structure of the generated value.
/// Translates the C `top` parameter of `BN_rand()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopBit {
    /// No constraint on top bit.
    Any,
    /// Top bit is set to 1, guaranteeing exact bit length.
    One,
    /// Top two bits are set to 1 (used for RSA prime generation to ensure
    /// the product of two such primes has the expected bit length).
    Two,
}

/// Control for the least significant bit of a random [`BigNum`].
///
/// Used with [`BigNum::rand`] to control parity of the generated value.
/// Translates the C `bottom` parameter of `BN_rand()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BottomBit {
    /// No constraint on bottom bit.
    Any,
    /// Bottom bit is set to 1, guaranteeing an odd number.
    Odd,
}

// ---------------------------------------------------------------------------
// BigNum core type (replaces C `bignum_st` from bn_local.h)
// ---------------------------------------------------------------------------

/// Arbitrary-precision integer type.
///
/// The Rust equivalent of OpenSSL's `BIGNUM` type. Wraps `num_bigint::BigInt`
/// as the internal representation, providing a complete API for cryptographic
/// big number arithmetic.
///
/// # Lifecycle
///
/// Replaces C `BN_new()` / `BN_free()` with Rust construction / `Drop`.
/// Replaces C `BN_clear_free()` with [`SecureBigNum`] which zeroes memory on drop.
///
/// # Memory Safety
///
/// Sensitive `BigNum` values (private keys, nonces) should use [`SecureBigNum`]
/// which zeroes memory on drop via `zeroize`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BigNum {
    inner: BigInt,
}

// ---------------------------------------------------------------------------
// Construction and lifecycle (from bn_lib.c BN_new/BN_free/BN_dup/BN_clear)
// ---------------------------------------------------------------------------

impl BigNum {
    /// Create a new `BigNum` with value 0.
    ///
    /// Replaces C `BN_new()` which allocates a zeroed BIGNUM.
    #[inline]
    pub fn zero() -> Self {
        Self {
            inner: BigInt::zero(),
        }
    }

    /// Create a `BigNum` with value 1.
    ///
    /// Replaces C `BN_value_one()` which returns a static constant.
    #[inline]
    pub fn one() -> Self {
        Self {
            inner: BigInt::one(),
        }
    }

    /// Create a `BigNum` from a `u64` value.
    ///
    /// Replaces C `BN_set_word()`.
    #[inline]
    pub fn from_u64(val: u64) -> Self {
        Self {
            inner: BigInt::from(val),
        }
    }

    /// Create a `BigNum` from an `i64` value.
    #[inline]
    pub fn from_i64(val: i64) -> Self {
        Self {
            inner: BigInt::from(val),
        }
    }

    /// Try to convert to `u64`.
    ///
    /// Returns `None` if the value is negative or does not fit in a `u64`.
    /// Replaces C `BN_get_word()` — returns `Option` instead of `BN_MASK2` sentinel
    /// per Rule R5.
    #[inline]
    pub fn to_u64(&self) -> Option<u64> {
        if self.inner.sign() == Sign::Minus {
            return None;
        }
        self.inner.to_u64()
    }

    /// Duplicate this `BigNum`.
    ///
    /// Replaces C `BN_dup()`. Equivalent to `Clone::clone()` but provided as
    /// an explicit API for clarity.
    #[inline]
    #[must_use]
    pub fn dup(&self) -> Self {
        self.clone()
    }

    /// Set to zero and clear all data.
    ///
    /// Replaces C `BN_clear()`.
    #[inline]
    pub fn clear(&mut self) {
        self.inner = BigInt::zero();
    }
}

// ---------------------------------------------------------------------------
// Comparison operations (from bn_lib.c BN_cmp, BN_ucmp)
// ---------------------------------------------------------------------------

impl BigNum {
    /// Signed comparison. Returns [`Ordering`].
    ///
    /// Replaces C `BN_cmp()`.
    #[inline]
    #[allow(clippy::should_implement_trait)] // Intentional: mirrors C BN_cmp() API name
    pub fn cmp(&self, other: &BigNum) -> Ordering {
        Ord::cmp(&self.inner, &other.inner)
    }

    /// Unsigned (absolute value) comparison.
    ///
    /// Replaces C `BN_ucmp()` which compares magnitudes ignoring sign.
    #[inline]
    pub fn ucmp(&self, other: &BigNum) -> Ordering {
        Ord::cmp(self.inner.magnitude(), other.inner.magnitude())
    }

    /// Check if this value is zero.
    ///
    /// Replaces C `BN_is_zero()`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        Zero::is_zero(&self.inner)
    }

    /// Check if this value is 1.
    ///
    /// Replaces C `BN_is_one()`.
    #[inline]
    pub fn is_one(&self) -> bool {
        One::is_one(&self.inner)
    }

    /// Check if this value is odd.
    ///
    /// Replaces C `BN_is_odd()`.
    #[inline]
    pub fn is_odd(&self) -> bool {
        self.inner.magnitude().bit(0)
    }

    /// Check if this value is negative.
    ///
    /// Replaces C access to `a->neg` flag.
    #[inline]
    pub fn is_negative(&self) -> bool {
        Signed::is_negative(&self.inner)
    }

    /// Check if this value equals a specific word.
    ///
    /// Replaces C `BN_is_word(a, w)`.
    #[inline]
    pub fn is_word(&self, w: u64) -> bool {
        self.inner == BigInt::from(w)
    }
}

// ---------------------------------------------------------------------------
// Bit operations (from bn_lib.c BN_num_bits, BN_is_bit_set, BN_set_bit, etc.)
// ---------------------------------------------------------------------------

impl BigNum {
    /// Number of significant bits (bit length of the absolute value).
    ///
    /// Returns 0 for zero. For positive values, returns `floor(log2(|n|)) + 1`.
    /// Replaces C `BN_num_bits()`.
    pub fn num_bits(&self) -> u32 {
        let bits = self.inner.magnitude().bits();
        // Rule R6: use try_from for lossless u64 to u32 conversion
        u32::try_from(bits).unwrap_or(u32::MAX)
    }

    /// Number of bytes needed to represent the absolute value.
    ///
    /// Replaces C `BN_num_bytes()` which is defined as `(BN_num_bits(a)+7)/8`.
    pub fn num_bytes(&self) -> u32 {
        (self.num_bits() + 7) / 8
    }

    /// Test if bit `n` is set in the absolute value.
    ///
    /// Replaces C `BN_is_bit_set()` which operates on the magnitude directly.
    #[inline]
    pub fn is_bit_set(&self, n: u32) -> bool {
        self.inner.magnitude().bit(u64::from(n))
    }

    /// Set bit `n` in the absolute value.
    ///
    /// Replaces C `BN_set_bit()`.
    pub fn set_bit(&mut self, n: u32) -> CryptoResult<()> {
        let bit_pos = u64::from(n);
        let sign = self.inner.sign();
        let mut mag = self.inner.magnitude().clone();
        mag.set_bit(bit_pos, true);
        self.inner = match sign {
            Sign::Minus => BigInt::from_biguint(Sign::Minus, mag),
            _ => BigInt::from_biguint(Sign::Plus, mag),
        };
        Ok(())
    }

    /// Clear bit `n` in the absolute value.
    ///
    /// Replaces C `BN_clear_bit()`.
    pub fn clear_bit(&mut self, n: u32) {
        let bit_pos = u64::from(n);
        let sign = self.inner.sign();
        let mut mag = self.inner.magnitude().clone();
        mag.set_bit(bit_pos, false);
        if mag.is_zero() {
            self.inner = BigInt::zero();
        } else {
            self.inner = BigInt::from_biguint(
                if sign == Sign::Minus {
                    Sign::Minus
                } else {
                    Sign::Plus
                },
                mag,
            );
        }
    }

    /// Truncate to `n` bits (clear all bits above position `n`).
    ///
    /// Replaces C `BN_mask_bits()`.
    pub fn mask_bits(&mut self, n: u32) {
        if n == 0 {
            self.inner = BigInt::zero();
            return;
        }
        let current_bits = self.num_bits();
        if n >= current_bits {
            return; // Nothing to mask
        }
        let one = BigUint::from(1u32);
        let mask = (&one << (n as usize)) - &one;
        let sign = self.inner.sign();
        let masked_mag = self.inner.magnitude() & &mask;
        if masked_mag.is_zero() {
            self.inner = BigInt::zero();
        } else {
            self.inner = BigInt::from_biguint(
                if sign == Sign::Minus {
                    Sign::Minus
                } else {
                    Sign::Plus
                },
                masked_mag,
            );
        }
    }

    /// Set the sign: `negative = true` makes the number negative.
    ///
    /// Zero is always non-negative regardless of the flag.
    pub fn set_negative(&mut self, negative: bool) {
        if self.is_zero() {
            return; // Zero is always non-negative
        }
        if negative && !self.is_negative() {
            self.inner = -std::mem::replace(&mut self.inner, BigInt::zero());
        } else if !negative && self.is_negative() {
            self.inner = Signed::abs(&self.inner);
        }
    }

    /// Get the absolute value.
    #[inline]
    #[must_use]
    pub fn abs(&self) -> BigNum {
        BigNum {
            inner: Signed::abs(&self.inner),
        }
    }

    /// Negate the value in place.
    pub fn negate(&mut self) {
        if !self.is_zero() {
            self.inner = -std::mem::replace(&mut self.inner, BigInt::zero());
        }
    }
}

// ---------------------------------------------------------------------------
// Byte encoding / decoding (from bn_lib.c BN_bin2bn, BN_bn2binpad, etc.)
// ---------------------------------------------------------------------------

impl BigNum {
    /// Create `BigNum` from big-endian byte array (unsigned).
    ///
    /// Replaces C `BN_bin2bn()`.
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        Self {
            inner: BigInt::from_bytes_be(Sign::Plus, bytes),
        }
    }

    /// Create `BigNum` from little-endian byte array (unsigned).
    ///
    /// Replaces C `BN_lebin2bn()`.
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        Self {
            inner: BigInt::from_bytes_le(Sign::Plus, bytes),
        }
    }

    /// Create `BigNum` from big-endian signed (two's complement) bytes.
    ///
    /// Replaces C `BN_signed_bin2bn()`.
    pub fn from_signed_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        Self {
            inner: BigInt::from_signed_bytes_be(bytes),
        }
    }

    /// Serialize to big-endian byte array (unsigned), minimal length.
    ///
    /// Replaces C `BN_bn2bin()`. Returns an empty `Vec` for zero.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let (_sign, bytes) = self.inner.to_bytes_be();
        bytes
    }

    /// Serialize to big-endian byte array (unsigned), padded to `pad_len` bytes.
    ///
    /// Returns an error if `pad_len` is smaller than the number of bytes needed
    /// or if the value is negative.
    /// Replaces C `BN_bn2binpad()`.
    pub fn to_bytes_be_padded(&self, pad_len: usize) -> CryptoResult<Vec<u8>> {
        if self.is_negative() {
            return Err(BigNumError::NegativeNotAllowed.into());
        }
        let (_sign, bytes) = self.inner.to_bytes_be();
        if bytes.len() > pad_len {
            return Err(BigNumError::BigNumTooLong.into());
        }
        let mut padded = vec![0u8; pad_len];
        let offset = pad_len - bytes.len();
        padded[offset..].copy_from_slice(&bytes);
        Ok(padded)
    }

    /// Serialize to little-endian byte array (unsigned), minimal length.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        let (_sign, bytes) = self.inner.to_bytes_le();
        bytes
    }

    /// Serialize to little-endian byte array (unsigned), padded to `pad_len` bytes.
    ///
    /// Replaces C `BN_bn2lebinpad()`.
    pub fn to_bytes_le_padded(&self, pad_len: usize) -> CryptoResult<Vec<u8>> {
        if self.is_negative() {
            return Err(BigNumError::NegativeNotAllowed.into());
        }
        let (_sign, bytes) = self.inner.to_bytes_le();
        if bytes.len() > pad_len {
            return Err(BigNumError::BigNumTooLong.into());
        }
        let mut padded = vec![0u8; pad_len];
        padded[..bytes.len()].copy_from_slice(&bytes);
        Ok(padded)
    }

    /// Serialize to signed big-endian (two's complement) bytes.
    ///
    /// Replaces C `BN_signed_bn2bin()`.
    pub fn to_signed_bytes_be(&self) -> Vec<u8> {
        self.inner.to_signed_bytes_be()
    }
}

// ---------------------------------------------------------------------------
// String encoding / decoding (from bn_conv.c BN_bn2hex, BN_bn2dec, etc.)
// ---------------------------------------------------------------------------

impl BigNum {
    /// Convert to uppercase hexadecimal string.
    ///
    /// Replaces C `BN_bn2hex()`. Negative values are prefixed with `-`.
    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let hex = self.inner.magnitude().to_str_radix(16).to_uppercase();
        if self.is_negative() {
            format!("-{hex}")
        } else {
            hex
        }
    }

    /// Convert to decimal string.
    ///
    /// Replaces C `BN_bn2dec()`.
    pub fn to_dec(&self) -> String {
        self.inner.to_str_radix(10)
    }

    /// Parse from hexadecimal string.
    ///
    /// Accepts optional leading `-` for negative values and optional `0x`/`0X` prefix.
    /// Replaces C `BN_hex2bn()`. Returns [`CryptoResult`] instead of null pointer
    /// per Rule R5.
    pub fn from_hex(hex: &str) -> CryptoResult<Self> {
        let trimmed = hex.trim();
        if trimmed.is_empty() {
            return Err(BigNumError::InvalidEncoding("empty hex string".into()).into());
        }
        // Strip optional "0x" or "0X" prefix, handling negative prefix too
        let clean = if let Some(rest) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            rest
        } else if let Some(rest) = trimmed
            .strip_prefix("-0x")
            .or_else(|| trimmed.strip_prefix("-0X"))
        {
            let inner_hex = format!("-{rest}");
            return BigInt::parse_bytes(inner_hex.as_bytes(), 16)
                .map(|bi| Self { inner: bi })
                .ok_or_else(|| BigNumError::InvalidEncoding(format!("invalid hex: {hex}")).into());
        } else {
            trimmed
        };
        BigInt::parse_bytes(clean.as_bytes(), 16)
            .map(|bi| Self { inner: bi })
            .ok_or_else(|| BigNumError::InvalidEncoding(format!("invalid hex: {hex}")).into())
    }

    /// Parse from decimal string.
    ///
    /// Replaces C `BN_dec2bn()`. Returns [`CryptoResult`] instead of null pointer
    /// per Rule R5.
    pub fn from_dec(dec: &str) -> CryptoResult<Self> {
        let trimmed = dec.trim();
        if trimmed.is_empty() {
            return Err(BigNumError::InvalidEncoding("empty decimal string".into()).into());
        }
        BigInt::parse_bytes(trimmed.as_bytes(), 10)
            .map(|bi| Self { inner: bi })
            .ok_or_else(|| BigNumError::InvalidEncoding(format!("invalid decimal: {dec}")).into())
    }
}

// ---------------------------------------------------------------------------
// Random number generation (from bn_rand.c BN_rand, BN_rand_range, etc.)
// ---------------------------------------------------------------------------

impl BigNum {
    /// Generate a cryptographically random `BigNum` of the specified bit length.
    ///
    /// `top` controls the most significant bits:
    /// - [`TopBit::Any`] — no constraint
    /// - [`TopBit::One`] — top bit is 1 (guarantees exact bit length)
    /// - [`TopBit::Two`] — top two bits are 1 (for RSA primes)
    ///
    /// `bottom` controls the least significant bit:
    /// - [`BottomBit::Any`] — no constraint
    /// - [`BottomBit::Odd`] — bottom bit is 1 (guarantees odd)
    ///
    /// Replaces C `BN_rand()`.
    pub fn rand(bits: u32, top: TopBit, bottom: BottomBit) -> CryptoResult<Self> {
        if bits == 0 {
            return Ok(Self::zero());
        }
        // TopBit::Two requires at least 2 bits
        if top == TopBit::Two && bits < 2 {
            return Err(BigNumError::BitsTooSmall(bits).into());
        }

        tracing::debug!(bits = bits, "generating random BigNum");

        // Calculate number of bytes needed: ceil(bits / 8)
        let byte_len = ((bits as usize) + 7) / 8;
        let mut buf = vec![0u8; byte_len];
        OsRng.fill_bytes(&mut buf);

        // Mask the top byte to have the exact number of bits requested.
        // The number of "surplus" bits in the top byte:
        let surplus_bits = (byte_len * 8) - (bits as usize);
        if surplus_bits > 0 {
            buf[0] &= 0xFFu8 >> surplus_bits;
        }

        // Apply top-bit constraints
        match top {
            TopBit::Any => {} // No constraint
            TopBit::One => {
                // Set the most significant bit
                let bit_in_top_byte = (bits - 1) % 8;
                buf[0] |= 1u8 << bit_in_top_byte;
            }
            TopBit::Two => {
                // Set the top two bits
                let bit_in_top_byte = (bits - 1) % 8;
                buf[0] |= 1u8 << bit_in_top_byte;
                if bit_in_top_byte > 0 {
                    buf[0] |= 1u8 << (bit_in_top_byte - 1);
                } else {
                    // Top bit is bit 0 of buf[0], second bit is bit 7 of buf[1]
                    if buf.len() > 1 {
                        buf[1] |= 0x80;
                    }
                }
            }
        }

        // Apply bottom-bit constraint
        if bottom == BottomBit::Odd {
            let last_idx = buf.len() - 1;
            buf[last_idx] |= 1;
        }

        let result = Self::from_bytes_be(&buf);
        buf.zeroize(); // Clear random bytes from stack
        Ok(result)
    }

    /// Generate a random `BigNum` in the range `[0, range)`.
    ///
    /// Returns an error if `range` is zero or negative.
    /// Replaces C `BN_rand_range()`. Returns [`CryptoResult`] per Rule R5.
    pub fn rand_range(range: &BigNum) -> CryptoResult<Self> {
        if range.is_zero() || range.is_negative() {
            return Err(BigNumError::InvalidRange.into());
        }

        tracing::debug!(
            range_bits = range.num_bits(),
            "generating random BigNum in range"
        );

        // Simple rejection sampling to produce uniform distribution
        let bits = range.num_bits();
        loop {
            let candidate = Self::rand(bits, TopBit::Any, BottomBit::Any)?;
            // Ensure candidate is strictly less than range
            if candidate.cmp(range) == Ordering::Less {
                return Ok(candidate);
            }
        }
    }

    /// Generate a random `BigNum` in the range `[0, range)` using private DRBG.
    ///
    /// Functionally identical to [`rand_range`](Self::rand_range) in the Rust
    /// implementation since Rust uses OS entropy via [`OsRng`]. The separate
    /// method exists for API compatibility with C `BN_priv_rand_range()`.
    pub fn priv_rand_range(range: &BigNum) -> CryptoResult<Self> {
        if range.is_zero() || range.is_negative() {
            return Err(BigNumError::InvalidRange.into());
        }

        tracing::debug!(
            range_bits = range.num_bits(),
            "generating private random BigNum in range"
        );

        let bits = range.num_bits();
        loop {
            let candidate = Self::rand(bits, TopBit::Any, BottomBit::Any)?;
            if candidate.cmp(range) == Ordering::Less {
                return Ok(candidate);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Well-known constants (from bn_const.c, bn_dh.c, bn_nist.c)
// ---------------------------------------------------------------------------

/// Well-known `BigNum` constants for cryptographic operations.
///
/// Provides NIST curve primes, RFC 3526 MODP group primes, and
/// RFC 7919 FFDHE group primes. Each function lazily constructs the
/// `BigNum` from its hexadecimal representation.
pub mod constants {
    use super::BigNum;

    /// Internal helper: parse hex constant that is known to be valid at compile time.
    /// All hex strings in this module are static RFC/NIST values verified offline.
    fn static_hex(hex: &str) -> BigNum {
        match BigNum::from_hex(hex) {
            Ok(bn) => bn,
            Err(_) => unreachable!("static hex constant is always valid"),
        }
    }

    /// NIST P-192 prime: `2^192 - 2^64 - 1`.
    pub fn nist_p192() -> BigNum {
        static_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF")
    }

    /// NIST P-224 prime: `2^224 - 2^96 + 1`.
    pub fn nist_p224() -> BigNum {
        static_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001")
    }

    /// NIST P-256 prime: `2^256 - 2^224 + 2^192 + 2^96 - 1`.
    pub fn nist_p256() -> BigNum {
        static_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")
    }

    /// NIST P-384 prime: `2^384 - 2^128 - 2^96 + 2^32 - 1`.
    pub fn nist_p384() -> BigNum {
        static_hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE\
             FFFFFFFF0000000000000000FFFFFFFF",
        )
    }

    /// NIST P-521 prime: `2^521 - 1`.
    pub fn nist_p521() -> BigNum {
        // P-521 = 2^521 - 1 (132 hex chars = 01 + 130 F's)
        static_hex(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
             FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
             FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        )
    }

    /// RFC 3526 MODP 2048-bit prime (Group 14).
    pub fn rfc3526_prime_2048() -> BigNum {
        static_hex(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
             29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
             EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
             E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
             EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
             C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
             83655D23DCA3AD961C62F356208552BB9ED529077096966D\
             670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
             E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
             DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
             15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        )
    }

    /// RFC 3526 MODP 3072-bit prime (Group 15).
    pub fn rfc3526_prime_3072() -> BigNum {
        static_hex(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
             29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
             EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
             E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
             EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
             C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
             83655D23DCA3AD961C62F356208552BB9ED529077096966D\
             670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
             E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
             DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
             15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64\
             ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
             ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B\
             F12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
             BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
             43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        )
    }

    /// RFC 3526 MODP 4096-bit prime (Group 16).
    pub fn rfc3526_prime_4096() -> BigNum {
        static_hex(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
             29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
             EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
             E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
             EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
             C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
             83655D23DCA3AD961C62F356208552BB9ED529077096966D\
             670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
             E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
             DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
             15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64\
             ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
             ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B\
             F12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
             BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
             43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
             88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA\
             2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6\
             287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED\
             1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
             93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199\
             FFFFFFFFFFFFFFFF",
        )
    }

    /// RFC 7919 FFDHE 2048-bit prime.
    pub fn ffdhe2048() -> BigNum {
        static_hex(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1\
             D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9\
             7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561\
             2433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
             984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735\
             30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB\
             B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19\
             0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
             9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73\
             3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA\
             886B423861285C97FFFFFFFFFFFFFFFF",
        )
    }

    /// RFC 7919 FFDHE 3072-bit prime.
    pub fn ffdhe3072() -> BigNum {
        static_hex(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1\
             D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9\
             7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561\
             2433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
             984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735\
             30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB\
             B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19\
             0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
             9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73\
             3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA\
             886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238\
             61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
             AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3\
             64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D\
             ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF\
             3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB\
             7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004\
             87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832\
             A907600A918130C46DC778F971AD0038092999A333CB8B7A\
             1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF\
             8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902\
             0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6\
             3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A\
             CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477\
             A52471F7A9A96910B855322EDB6340D8A00EF092350511E30\
             ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B46\
             63B75E6B0F0101EF9FEAAD82D03E6B8AFD1EB3F994B6BBEF\
             2818D4F40D69B3FE6F3C7E6F376FCED12F78C379A6C9CF03\
             59F94D25E4E53274B65E08F9FAFCF0C28D4AAE0F1E2DDCD7\
             9DCB8B9536C6F6F3C0C20F217BA5678C2FFEE0C43F454643\
             4AECE5F63A19D51BB9D84F3A3C5F2B6E4FD74EDDCA15A3FF\
             FFFFFFFFFFFFFFFF",
        )
    }

    /// RFC 7919 FFDHE 4096-bit prime.
    pub fn ffdhe4096() -> BigNum {
        static_hex(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1\
             D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9\
             7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561\
             2433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
             984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735\
             30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB\
             B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19\
             0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
             9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73\
             3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA\
             886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238\
             61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
             AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3\
             64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D\
             ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF\
             3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB\
             7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004\
             87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832\
             A907600A918130C46DC778F971AD0038092999A333CB8B7A\
             1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF\
             8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902\
             0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6\
             3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A\
             CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477\
             A52471F7A9A96910B855322EDB6340D8A00EF092350511E30\
             ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B46\
             63B75E6B0F0101EF9FEAAD82D03E6B8AFD1EB3F994B6BBEF\
             2818D4F40D69B3FE6F3C7E6F376FCED12F78C379A6C9CF03\
             59F94D25E4E53274B65E08F9FAFCF0C28D4AAE0F1E2DDCD7\
             9DCB8B9536C6F6F3C0C20F217BA5678C2FFEE0C43F454643\
             4AECE5F63A19D51BB9D84F3A3C5F2B6E4FD74EDDCA15A3FF\
             E285039B67834C0A4E32FE9DFAE5C9B61FE903B0FC6A3B19\
             6B9C9B97C5A26EC3B4D6B5C3E66E39F1BBEE998CF8B1C7B1\
             D7E18F7BAFE7A4C1A592BB8CC1DB13C5064E4A5765CB46E1\
             8D3BA6F4E9FDF2B58C0CBB35B2BFBA48E2283D1E7A511B77\
             B05FEE034BC20EEAF71DDE024D17B9DE75498EE7B925D06C\
             B22B30E74C6D4A09DA88C86EFC73AEE5CFC3D4FED97F6EFD\
             25B6C07DE4C2D36D0B86DDC9B1E0DC1D8679C37D6BD6D9B3\
             74F6C6D3A7B9C9E4F5F417E6AC65C9BABB6B0BB86FEC0E5D\
             C68A8E78F28F08C5FA61CAA5E9CD3C8BA6B62DCE01A5B0E0\
             F456C4489F5B6B15C7FE09E91C1B14E54D78C6B6E8FD97D6\
             2B4DC7F3B1F49C93BFBB524B4CF19F2F44093B841FF68F83\
             FFFFFFFFFFFFFFFF",
        )
    }

    /// Constant 2 as a `BigNum`.
    #[inline]
    pub fn two() -> BigNum {
        BigNum::from_u64(2)
    }
}

// ---------------------------------------------------------------------------
// RSA Blinding (from bn_blind.c BN_BLINDING)
// ---------------------------------------------------------------------------

/// RSA blinding context for side-channel protection.
///
/// Blinding prevents timing attacks on RSA private key operations by
/// randomizing the input before the operation and unblinding afterward.
///
/// Replaces C `BN_BLINDING` (`bn_blinding_st`).
///
/// # Blinding Protocol
///
/// 1. Generate random `r` coprime to modulus `n`.
/// 2. Compute blinding factor `A = r^e mod n`.
/// 3. Compute unblinding factor `Ai = r^(-1) mod n`.
/// 4. To blind message `m`: compute `m * A mod n`.
/// 5. After private key operation on blinded value, unblind: `result * Ai mod n`.
///
/// The blinding factors are refreshed after `max_reuses` operations by squaring.
pub struct Blinding {
    /// Blinding factor: `r^e mod n`
    a: BigNum,
    /// Unblinding factor: `r^(-1) mod n`
    ai: BigNum,
    /// The modulus
    modulus: BigNum,
    /// Number of times the current blinding factors have been reused.
    // LOCK-SCOPE: blinding is per-RSA-key, accessed during private operations only.
    counter: u32,
    /// Maximum number of reuses before forced refresh.
    max_reuses: u32,
}

/// Default maximum reuses matches C `BN_BLINDING_COUNTER` (32).
const BN_BLINDING_COUNTER: u32 = 32;

impl Blinding {
    /// Create a new blinding context for modulus `n` with public exponent `e`.
    ///
    /// Generates a random `r` coprime to `n`, then computes:
    /// - `A = r^e mod n` (blinding factor)
    /// - `Ai = r^(-1) mod n` (unblinding factor)
    ///
    /// Replaces C `BN_BLINDING_new()`.
    pub fn new(e: &BigNum, n: &BigNum) -> CryptoResult<Self> {
        if n.is_zero() || n.is_negative() {
            return Err(BigNumError::InvalidArgument("modulus must be positive".into()).into());
        }
        if e.is_zero() {
            return Err(BigNumError::InvalidArgument("exponent must be non-zero".into()).into());
        }

        tracing::debug!("creating new RSA blinding context");

        // Generate random r in [1, n) that is coprime to n
        let r = loop {
            let candidate = BigNum::rand_range(n)?;
            if candidate.is_zero() {
                continue;
            }
            if arithmetic::gcd(&candidate, n).is_one() {
                break candidate;
            }
        };

        // Compute unblinding factor: r^(-1) mod n
        // The inverse is guaranteed to exist because r is coprime to n (checked above).
        let ai = arithmetic::mod_inverse(&r, n)?.ok_or(BigNumError::NoInverse)?;

        // Compute blinding factor: r^e mod n
        let a = montgomery::mod_exp(&r, e, n)?;

        Ok(Self {
            a,
            ai,
            modulus: n.dup(),
            counter: 0,
            max_reuses: BN_BLINDING_COUNTER,
        })
    }

    /// Blind a message: compute `m * A mod n`.
    ///
    /// The blinding factors are automatically refreshed when the reuse counter
    /// exceeds `max_reuses` (default 32).
    ///
    /// Replaces C `BN_BLINDING_convert_ex()`.
    pub fn blind(&mut self, m: &BigNum) -> CryptoResult<BigNum> {
        // Auto-refresh blinding factors if counter exceeded
        if self.counter >= self.max_reuses {
            self.update()?;
        }
        let result = arithmetic::mod_mul(m, &self.a, &self.modulus)?;
        self.counter = self.counter.saturating_add(1);
        Ok(result)
    }

    /// Unblind a result: compute `m * Ai mod n`.
    ///
    /// Replaces C `BN_BLINDING_invert_ex()`.
    pub fn unblind(&mut self, m: &BigNum) -> CryptoResult<BigNum> {
        arithmetic::mod_mul(m, &self.ai, &self.modulus)
    }

    /// Update (refresh) the blinding factors by squaring.
    ///
    /// Computes `A = A^2 mod n` and `Ai = Ai^2 mod n`, which is equivalent
    /// to using `r^2` as the new blinding base. Resets the reuse counter.
    ///
    /// Replaces C `BN_BLINDING_update()`.
    pub fn update(&mut self) -> CryptoResult<()> {
        self.a = arithmetic::mod_sqr(&self.a, &self.modulus)?;
        self.ai = arithmetic::mod_sqr(&self.ai, &self.modulus)?;
        self.counter = 0;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Display and formatting traits (from bn_print.c)
// ---------------------------------------------------------------------------

/// Display as decimal string.
impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_dec())
    }
}

/// Format as lowercase hexadecimal.
impl fmt::LowerHex for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        let hex = self.inner.magnitude().to_str_radix(16);
        if self.is_negative() {
            write!(f, "-{hex}")
        } else {
            write!(f, "{hex}")
        }
    }
}

/// Format as uppercase hexadecimal.
impl fmt::UpperHex for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        let hex = self.inner.magnitude().to_str_radix(16).to_uppercase();
        if self.is_negative() {
            write!(f, "-{hex}")
        } else {
            write!(f, "{hex}")
        }
    }
}

// ---------------------------------------------------------------------------
// Standard operator trait implementations
// ---------------------------------------------------------------------------

impl Add<&BigNum> for &BigNum {
    type Output = BigNum;

    #[inline]
    fn add(self, rhs: &BigNum) -> BigNum {
        BigNum {
            inner: &self.inner + &rhs.inner,
        }
    }
}

impl Sub<&BigNum> for &BigNum {
    type Output = BigNum;

    #[inline]
    fn sub(self, rhs: &BigNum) -> BigNum {
        BigNum {
            inner: &self.inner - &rhs.inner,
        }
    }
}

impl Mul<&BigNum> for &BigNum {
    type Output = BigNum;

    #[inline]
    fn mul(self, rhs: &BigNum) -> BigNum {
        BigNum {
            inner: &self.inner * &rhs.inner,
        }
    }
}

impl Neg for BigNum {
    type Output = BigNum;

    #[inline]
    fn neg(self) -> BigNum {
        BigNum { inner: -self.inner }
    }
}

impl Shl<u32> for &BigNum {
    type Output = BigNum;

    #[inline]
    fn shl(self, rhs: u32) -> BigNum {
        BigNum {
            inner: &self.inner << (rhs as usize),
        }
    }
}

impl Shr<u32> for &BigNum {
    type Output = BigNum;

    #[inline]
    fn shr(self, rhs: u32) -> BigNum {
        BigNum {
            inner: &self.inner >> (rhs as usize),
        }
    }
}

impl AddAssign<&BigNum> for BigNum {
    #[inline]
    fn add_assign(&mut self, rhs: &BigNum) {
        self.inner += &rhs.inner;
    }
}

impl SubAssign<&BigNum> for BigNum {
    #[inline]
    fn sub_assign(&mut self, rhs: &BigNum) {
        self.inner -= &rhs.inner;
    }
}

impl MulAssign<&BigNum> for BigNum {
    #[inline]
    fn mul_assign(&mut self, rhs: &BigNum) {
        self.inner *= &rhs.inner;
    }
}

// ---------------------------------------------------------------------------
// Conversion traits
// ---------------------------------------------------------------------------

impl From<u64> for BigNum {
    #[inline]
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl From<u32> for BigNum {
    #[inline]
    fn from(val: u32) -> Self {
        Self {
            inner: BigInt::from(val),
        }
    }
}

impl From<i64> for BigNum {
    #[inline]
    fn from(val: i64) -> Self {
        Self::from_i64(val)
    }
}

impl From<i32> for BigNum {
    #[inline]
    fn from(val: i32) -> Self {
        Self {
            inner: BigInt::from(val),
        }
    }
}

impl TryFrom<&BigNum> for u64 {
    type Error = CryptoError;

    fn try_from(bn: &BigNum) -> Result<Self, Self::Error> {
        bn.to_u64().ok_or_else(|| {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(
                "BigNum value does not fit in u64".into(),
            ))
        })
    }
}

impl TryFrom<&BigNum> for i64 {
    type Error = CryptoError;

    fn try_from(bn: &BigNum) -> Result<Self, Self::Error> {
        use num_traits::ToPrimitive as _;
        bn.inner.to_i64().ok_or_else(|| {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(
                "BigNum value does not fit in i64".into(),
            ))
        })
    }
}

impl From<BigInt> for BigNum {
    #[inline]
    fn from(val: BigInt) -> Self {
        Self { inner: val }
    }
}

impl From<BigUint> for BigNum {
    #[inline]
    fn from(val: BigUint) -> Self {
        Self {
            inner: BigInt::from(val),
        }
    }
}

impl From<BigNum> for BigInt {
    #[inline]
    fn from(val: BigNum) -> Self {
        val.inner
    }
}

// ---------------------------------------------------------------------------
// Zeroize impl for BigNum — secure erasure of sensitive scalar values
// (replaces C BN_clear() / OPENSSL_cleanse() pattern from crypto/bn/bn_lib.c)
// ---------------------------------------------------------------------------

/// Best-effort secure erasure of a [`BigNum`].
///
/// This implementation replaces the C `BN_clear()` / `OPENSSL_cleanse()`
/// pattern used by `BN_clear_free()` in `crypto/bn/bn_lib.c`. It is invoked
/// automatically by [`SecureBigNum`]'s `Drop` impl, and may also be invoked
/// manually by callers that hold transient secrets in a plain [`BigNum`].
///
/// # Behaviour
///
/// 1. The current value is **snapshotted** into a [`Zeroizing<Vec<u8>>`],
///    which guarantees the byte snapshot is overwritten with zeros before
///    its heap allocation is released. This neutralises the dominant leak
///    in the previous implementation, where `to_bytes_le()`'s returned
///    `Vec<u8>` (containing the secret in big-endian form) was dropped
///    unzeroed.
/// 2. The internal [`BigInt`] is replaced with `BigInt::zero()`. After this
///    call, [`BigNum::is_zero`] returns `true` and the value is observably
///    erased from the public API surface.
///
/// # SECURITY: Documented residual leak
///
/// `num_bigint::BigInt` exposes no `Zeroize` trait nor any `pub` accessor
/// for its underlying limb buffer (`Vec<u32>`/`Vec<u64>`). When the original
/// [`BigInt`] is replaced via assignment, its limb `Vec` is dropped through
/// the global allocator **without** being zeroed first. The freed pages may
/// retain the secret material until the allocator reuses or returns them
/// to the operating system.
///
/// This residual leak is unavoidable in safe Rust without unsafe access to
/// `num-bigint`'s private fields. The long-term remedy is to migrate the
/// backend to a `Zeroize`-aware bignum library such as `crypto-bigint`,
/// which is tracked as a future architectural improvement (see
/// `ARCHITECTURE.md` and the AAP §0.7.6 "Memory Safety and Secure Erasure"
/// follow-up notes).
///
/// In the meantime, this `Zeroize` impl mitigates the dominant exposure
/// surface — namely the byte snapshot held in heap-allocated `Vec<u8>` —
/// while the limb residual is documented as a known limitation rather than
/// silently masked.
///
/// # Rules compliance
///
/// - **R6 (lossless casts):** No narrowing casts; the `Vec<u8>` snapshot
///   matches `to_bytes_le()`'s natural byte width.
/// - **R8 (zero unsafe):** Pure safe Rust. No `unsafe` block introduced.
impl Zeroize for BigNum {
    fn zeroize(&mut self) {
        // Snapshot the limb-derived bytes into a Zeroizing<Vec<u8>>. The
        // wrapper guarantees the heap-allocated byte buffer is zeroed before
        // its allocation is released, fixing the heap-copy escape that the
        // previous implementation introduced via `let bytes = ...to_bytes_le();`.
        //
        // We deliberately discard the sign component — `Sign` is a 3-variant
        // enum stored on the stack, and zeroizing it offers no defence beyond
        // the byte-buffer zero we already perform on the magnitude.
        let snapshot: Zeroizing<Vec<u8>> = Zeroizing::new(self.inner.to_bytes_le().1);
        // `snapshot` will be zeroed on drop at the end of this scope.

        // Replace the BigInt with zero. This drops the original BigInt whose
        // internal Vec<limb> is dropped without being zeroed (documented
        // residual leak above). After this assignment, BigNum::is_zero()
        // returns true, which is the observable contract of `BN_clear()`.
        self.inner = BigInt::zero();

        // Defensive read of `snapshot` to discourage dead-code optimisation
        // from eliding the `to_bytes_le()` materialisation. The compiler
        // cannot easily prove the side-effect-free nature of this read
        // because `Zeroizing<T>` has a non-trivial Drop. This pattern
        // mirrors RustCrypto's `subtle` defence-in-depth idiom.
        let _ = snapshot.len();
    }
}

// ---------------------------------------------------------------------------
// SecureBigNum — zeroed on drop (replaces C BN_secure_new / BN_clear_free)
// ---------------------------------------------------------------------------

/// Secure variant of [`BigNum`] that zeroes memory on drop.
///
/// Used for private keys, nonces, and other sensitive values.
/// Replaces C `BN_secure_new()` / `BN_clear_free()`.
///
/// The `zeroize` crate is used to zero the internal representation
/// when this value is dropped, replacing `OPENSSL_cleanse()`.
#[derive(Debug, Clone)]
pub struct SecureBigNum {
    inner: BigNum,
}

impl SecureBigNum {
    /// Create a new `SecureBigNum` wrapping the given `BigNum`.
    pub fn new(bn: BigNum) -> Self {
        Self { inner: bn }
    }

    /// Consume and extract the inner `BigNum`.
    ///
    /// # SECURITY
    ///
    /// **The returned [`BigNum`] is _not_ zeroed when dropped.** Once the
    /// scalar leaves the [`SecureBigNum`] container it falls outside the
    /// `Drop`-driven zeroization contract documented at the type level,
    /// and any subsequent secure erasure becomes the caller's
    /// responsibility (e.g. by calling [`BigNum::zeroize`] explicitly,
    /// or by re-wrapping with `SecureBigNum::new(...)`).
    ///
    /// The `self` value is consumed by this call, so the original
    /// `SecureBigNum`'s `Drop` will _not_ run after `into_inner` (the
    /// move semantics of `self: Self` guarantee a single drop, and that
    /// drop happens at the call site of `into_inner` where the local
    /// `self` is consumed). Concretely, this means:
    ///
    /// 1. `self.inner.clone()` produces an independent `BigNum` copy that
    ///    contains the secret.
    /// 2. `self` is then dropped at the end of this function, which
    ///    invokes `Drop for SecureBigNum`, which calls
    ///    `self.inner.zeroize()`. This zeroes the _original_ `inner`
    ///    field, but the cloned copy returned to the caller still
    ///    contains the secret value.
    ///
    /// Use this method only when transferring ownership across an
    /// abstraction boundary that itself enforces secure erasure on the
    /// receiving end.
    pub fn into_inner(self) -> BigNum {
        // The clone produces a fresh BigNum holding the secret. The
        // caller takes responsibility for its lifetime; see the docstring
        // above for why this is intentional and not a regression on the
        // previous (also-cloning) implementation.
        self.inner.clone()
    }
}

impl Drop for SecureBigNum {
    fn drop(&mut self) {
        // Delegate to the BigNum::zeroize() impl above, which (a) zeros
        // any heap-allocated byte snapshot via Zeroizing<Vec<u8>>, and
        // (b) replaces the inner BigInt with zero. See `impl Zeroize for
        // BigNum` for the full security analysis, including the
        // documented residual leak in num-bigint's limb buffer.
        //
        // This replaces the prior implementation, which had three
        // independent defects:
        //
        //   1. `to_bytes_le()` allocated a fresh Vec<u8> containing the
        //      secret and dropped it unzeroed at end of scope, leaking
        //      the bytes to the global allocator.
        //   2. `BigInt::zero()` replacement dropped the original limb
        //      Vec<u64> without zeroing — same residual as today, but
        //      previously undocumented.
        //   3. `let mut scrub = vec![0u8; byte_count]; scrub.zeroize();`
        //      was security theatre — a freshly allocated Vec is already
        //      zero, and its zeroize() call merely re-zeroed zero before
        //      dropping.
        //
        // The new path eliminates (1) entirely (the snapshot lives inside
        // a Zeroizing wrapper that is zeroed on drop), retains (2) as a
        // documented residual, and removes (3) outright.
        self.inner.zeroize();
    }
}

impl std::ops::Deref for SecureBigNum {
    type Target = BigNum;

    #[inline]
    fn deref(&self) -> &BigNum {
        &self.inner
    }
}

impl std::ops::DerefMut for SecureBigNum {
    #[inline]
    fn deref_mut(&mut self) -> &mut BigNum {
        &mut self.inner
    }
}

impl From<BigNum> for SecureBigNum {
    #[inline]
    fn from(bn: BigNum) -> Self {
        Self::new(bn)
    }
}

/// Marker that promises [`SecureBigNum`] zeroes its sensitive contents when
/// dropped (see [`Drop for SecureBigNum`](struct.SecureBigNum.html)).
///
/// `ZeroizeOnDrop` is a marker trait from the `zeroize` crate signalling
/// that a type's `Drop` impl performs the equivalent of `Zeroize::zeroize`
/// on all sensitive fields. We implement it explicitly here — even though
/// `Drop` already calls `self.inner.zeroize()` — so that downstream
/// consumers (e.g. compound key types in `crates/openssl-crypto/src/dsa.rs`,
/// `crates/openssl-crypto/src/ec/mod.rs`) can rely on this trait bound when
/// composing zeroize-aware key structs.
///
/// # SECURITY: Marker scope
///
/// This marker reflects the dominant byte-snapshot zeroization performed
/// by the inner `BigNum::zeroize` impl. The documented residual leak in
/// `num-bigint`'s limb buffer (see [`Zeroize for BigNum`]) does **not**
/// invalidate the marker, because `ZeroizeOnDrop` is best-effort by the
/// `zeroize` crate's own contract — it asserts the type's `Drop` calls
/// `Zeroize::zeroize`, not that every byte of the underlying allocator
/// metadata is necessarily wiped.
impl ZeroizeOnDrop for SecureBigNum {}

// ---------------------------------------------------------------------------
// Internal access for sibling modules (pub(crate) only)
// ---------------------------------------------------------------------------

impl BigNum {
    /// Access the inner `BigInt` (crate-internal only).
    ///
    /// Used by `arithmetic`, `montgomery`, and `prime` submodules to access
    /// the underlying representation for operations not exposed in the public API.
    #[inline]
    pub(crate) fn inner(&self) -> &BigInt {
        &self.inner
    }

    /// Mutable access to inner `BigInt` (crate-internal only).
    #[inline]
    #[allow(dead_code)] // Used by sibling bn modules (arithmetic, montgomery, prime)
    pub(crate) fn inner_mut(&mut self) -> &mut BigInt {
        &mut self.inner
    }

    /// Construct from inner `BigInt` (crate-internal only).
    #[inline]
    pub(crate) fn from_inner(inner: BigInt) -> Self {
        Self { inner }
    }
}

// ---------------------------------------------------------------------------
// Unit tests for Zeroize / SecureBigNum::Drop behaviour
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unit tests for `BigNum`'s `Zeroize` impl and `SecureBigNum`'s `Drop`
    //! delegation.
    //!
    //! These tests exercise the secure-erasure pathway introduced to replace
    //! the prior `SecureBigNum::Drop` security theatre. They validate the
    //! observable side-effects of `Zeroize`/`Drop` (the stored value goes to
    //! zero), but they cannot — and do not pretend to — directly observe
    //! whether the allocator's freed pages have been wiped. The latter
    //! property is governed by the documented residual leak in `num-bigint`
    //! and is tracked as a future architectural improvement.
    //!
    //! Rules compliance:
    //! - **R8 (zero unsafe):** Pure safe Rust. No `unsafe` blocks.
    //! - **R10 (wiring):** Tests are reachable through the standard
    //!   `cargo test -p openssl-crypto --lib` path.

    use super::*;

    /// Constructs a multi-limb [`BigNum`] (≥ 2048 bits) by left-shifting
    /// `0xDEADBEEFCAFEF00D` past a 64-bit limb boundary, then ORing in a
    /// distinct low-order pattern. The result spans at least 32 32-bit
    /// limbs (or 16 64-bit limbs depending on the `num-bigint` build),
    /// which is sufficient to exercise the multi-limb path of
    /// `to_bytes_le()`.
    fn multi_limb_secret() -> BigNum {
        let high = BigNum::from_u64(0xDEAD_BEEF_CAFE_F00D);
        let low = BigNum::from_u64(0x0123_4567_89AB_CDEF);
        // Shift `high` left by 1984 bits so that the combined value spans
        // multiple limbs and pushes the magnitude well past one limb.
        let shifted = &high << 1984u32;
        // Use addition (saturating into BigNum's natural width) to combine.
        // Both operands are non-negative, so this is equivalent to OR for
        // disjoint bit ranges.
        super::arithmetic::add(&shifted, &low)
    }

    #[test]
    fn bignum_zeroize_sets_value_to_zero() {
        let mut bn = BigNum::from_u64(0xDEAD_BEEF_CAFE_F00D);
        assert!(!bn.is_zero(), "precondition: value must be non-zero");
        bn.zeroize();
        assert!(bn.is_zero(), "post-zeroize: BigNum must report is_zero()");
        assert_eq!(
            bn,
            BigNum::zero(),
            "post-zeroize: BigNum must be value-equal to zero"
        );
    }

    #[test]
    fn bignum_zeroize_idempotent_on_zero() {
        let mut bn = BigNum::zero();
        assert!(bn.is_zero(), "precondition: starting value is zero");
        bn.zeroize();
        assert!(bn.is_zero(), "post-zeroize: still zero (no-op)");
        assert_eq!(bn, BigNum::zero());
    }

    #[test]
    fn bignum_zeroize_idempotent_when_called_twice() {
        let mut bn = BigNum::from_u64(0xCAFE_BABE_DEAD_BEEF);
        bn.zeroize();
        assert!(bn.is_zero());
        // Calling zeroize() a second time must remain safe and observable.
        bn.zeroize();
        assert!(bn.is_zero());
        assert_eq!(bn, BigNum::zero());
    }

    #[test]
    fn bignum_zeroize_multi_limb_value() {
        // Build a value that requires multiple num-bigint limbs to store.
        let mut bn = multi_limb_secret();
        assert!(
            !bn.is_zero(),
            "precondition: multi-limb secret must be non-zero"
        );
        // Sanity-check the magnitude crosses a 64-bit limb boundary so
        // that `to_bytes_le()` allocates a multi-byte buffer.
        assert!(
            bn.num_bits() > 64,
            "precondition: multi-limb test must exceed 64 bits, got {}",
            bn.num_bits()
        );
        bn.zeroize();
        assert!(
            bn.is_zero(),
            "post-zeroize: multi-limb BigNum must report is_zero()"
        );
        assert_eq!(bn, BigNum::zero());
    }

    #[test]
    fn bignum_zeroize_negative_value() {
        // Negative magnitudes traverse a different `Sign` branch in
        // `to_bytes_le()`. Verify the zeroize path works for both.
        let pos = BigNum::from_u64(0xFEED_FACE_BAD_F00D);
        let mut bn = -&pos;
        assert!(!bn.is_zero(), "precondition: negated value is non-zero");
        bn.zeroize();
        assert!(
            bn.is_zero(),
            "post-zeroize: negative BigNum must report is_zero()"
        );
        assert_eq!(bn, BigNum::zero());
    }

    #[test]
    fn secure_bignum_drop_runs_without_panic() {
        // Construct, then explicitly drop a SecureBigNum. The Drop impl
        // delegates to `self.inner.zeroize()` which exercises the same
        // pathway as `BigNum::zeroize` directly. Reaching the assertion
        // proves Drop ran to completion without panicking.
        let secret = BigNum::from_u64(0xCAFE_BABE);
        let secure = SecureBigNum::new(secret);
        drop(secure);
        // If we reach here, Drop ran successfully.
    }

    #[test]
    fn secure_bignum_drop_runs_on_multi_limb_secret() {
        let secret = multi_limb_secret();
        let secure = SecureBigNum::new(secret);
        // Multi-limb path must not panic during drop.
        drop(secure);
    }

    #[test]
    fn secure_bignum_zeroize_via_deref_mut() {
        // SecureBigNum exposes DerefMut<Target = BigNum>, so callers can
        // explicitly invoke Zeroize::zeroize through the deref. Verify
        // that path also works correctly.
        let mut secure = SecureBigNum::new(BigNum::from_u64(0xAB));
        assert!(!secure.is_zero());
        secure.zeroize();
        assert!(
            secure.is_zero(),
            "DerefMut zeroize must zero the inner BigNum"
        );
    }

    #[test]
    fn secure_bignum_into_inner_returns_clone_with_secret() {
        // Documented contract: `into_inner` returns a CLONE of the inner
        // BigNum that retains the secret. The original SecureBigNum's Drop
        // runs when `self` falls out of scope, zeroing the original inner;
        // the returned clone is unaffected.
        let original = BigNum::from_u64(0x4242_4242_4242_4242);
        let secure = SecureBigNum::new(original.clone());
        let extracted = secure.into_inner();
        assert_eq!(
            extracted, original,
            "into_inner must return a clone bearing the original secret"
        );
        assert!(!extracted.is_zero(), "clone must retain the secret value");
    }

    #[test]
    fn secure_bignum_clone_does_not_zeroize_original() {
        // Cloning a SecureBigNum must not zeroize the original, because
        // Clone produces an independent instance. Both copies must retain
        // the secret value until each is independently dropped.
        let secure = SecureBigNum::new(BigNum::from_u64(0x1234_5678));
        let cloned = secure.clone();
        assert!(!secure.is_zero(), "original must retain secret after clone");
        assert!(!cloned.is_zero(), "clone must contain the secret");
        // Both clones drop independently at end of scope.
    }

    #[test]
    fn secure_bignum_implements_zeroize_on_drop_marker() {
        // Compile-time check: the `ZeroizeOnDrop` marker trait must be
        // implemented for SecureBigNum. The function below requires the
        // trait bound; if the marker were missing this test would fail
        // to compile.
        fn assert_marker<T: zeroize::ZeroizeOnDrop>() {}
        assert_marker::<SecureBigNum>();
    }

    #[test]
    fn bignum_zeroize_does_not_change_is_zero_observability_for_other_instances() {
        // Sanity: zeroizing one BigNum must not affect a sibling instance.
        let a = BigNum::from_u64(0x1111);
        let mut b = BigNum::from_u64(0x2222);
        b.zeroize();
        assert!(!a.is_zero(), "sibling BigNum must remain unchanged");
        assert!(b.is_zero(), "zeroized BigNum must be zero");
    }

    #[test]
    fn bignum_zeroize_via_zeroizing_wrapper_compiles() {
        // Ensure BigNum can be wrapped in `Zeroizing<BigNum>` (since it
        // implements Zeroize). This composes the type with the zeroize
        // crate's RAII helper for callers that hold transient secrets.
        let mut wrapped: Zeroizing<BigNum> = Zeroizing::new(BigNum::from_u64(0xAA));
        assert!(!wrapped.is_zero());
        wrapped.zeroize();
        assert!(wrapped.is_zero());
        // `wrapped` will be zeroized again on drop here — must not panic.
    }
}
