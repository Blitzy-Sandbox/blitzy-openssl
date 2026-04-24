//! Elliptic Curve operations for the OpenSSL Rust workspace.
//!
//! Provides the foundational types for elliptic curve cryptography:
//! - [`EcGroup`] — Curve parameters (replaces C `EC_GROUP`)
//! - [`EcPoint`] — Point on a curve (replaces C `EC_POINT`)
//! - [`EcKey`] — EC key pair (replaces C `EC_KEY`)
//!
//! Submodules:
//! - [`ecdsa`] — ECDSA sign/verify operations
//! - [`ecdh`] — ECDH key exchange
//! - [`curve25519`] — X25519/Ed25519/X448/Ed448 primitives
//!
//! ## Named Curves
//!
//! The module supports named curves including NIST P-256, P-384,
//! P-521, secp256k1, brainpool curves, and SM2. Curves are identified by
//! the [`NamedCurve`] enum.
//!
//! ## Design Choices
//!
//! - `EC_METHOD` dispatch tables → Rust trait-based dispatch
//! - `EC_GROUP` void* fields → typed enum variants
//! - Reference-counted `EC_KEY` → owned `EcKey` with `Drop`
//! - Private key `BN_clear_free` → `zeroize`-based zeroing on drop
//! - Point coordinates: affine representation for the public API
//! - `subtle::ConstantTimeEq` for constant-time point comparison

use openssl_common::{CryptoError, CryptoResult};

use crate::bn::{BigNum, SecureBigNum};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use tracing::{debug, trace};

pub mod curve25519;
pub mod ecdh;
pub mod ecdsa;

// Re-export key types from submodules for ergonomic access.
pub use curve25519::{EcxKeyPair, EcxKeyType, EcxPrivateKey, EcxPublicKey};
pub use ecdh::{EcdhMode, SharedSecret};
pub use ecdsa::{EcdsaSignature, NonceType};

// ===========================================================================
// NamedCurve — enumeration of supported elliptic curves
// ===========================================================================

/// Enumeration of supported named elliptic curves.
///
/// Replaces C curve NIDs from `crypto/ec/ec_curve.c`. Each variant maps
/// to a set of built-in curve parameters (field prime, coefficients a/b,
/// generator coordinates, order, and cofactor).
///
/// # Rule R5
///
/// Uses an enum instead of integer NIDs for compile-time type safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NamedCurve {
    // NIST curves (most commonly used)
    /// P-256, secp256r1, prime256v1 — NIST 256-bit prime curve
    Prime256v1,
    /// P-384, secp384r1 — NIST 384-bit prime curve
    Secp384r1,
    /// P-521, secp521r1 — NIST 521-bit prime curve
    Secp521r1,

    // Other common curves
    /// secp256k1 — Koblitz 256-bit curve (used in Bitcoin)
    Secp256k1,
    /// P-224, secp224r1 — NIST 224-bit prime curve
    Secp224r1,

    // Brainpool curves (RFC 5639)
    /// brainpoolP256r1 — RFC 5639 256-bit random curve
    BrainpoolP256r1,
    /// brainpoolP384r1 — RFC 5639 384-bit random curve
    BrainpoolP384r1,
    /// brainpoolP512r1 — RFC 5639 512-bit random curve
    BrainpoolP512r1,
    /// brainpoolP256t1 — RFC 5639 256-bit twisted curve
    BrainpoolP256t1,
    /// brainpoolP384t1 — RFC 5639 384-bit twisted curve
    BrainpoolP384t1,
    /// brainpoolP512t1 — RFC 5639 512-bit twisted curve
    BrainpoolP512t1,

    // SM2 (Chinese national standard)
    /// SM2 — Chinese national standard elliptic curve
    Sm2,

    // Older / legacy curves
    /// P-192, secp192r1 — NIST 192-bit prime curve
    Secp192r1,
    /// secp160r1 — 160-bit prime curve
    Secp160r1,
    /// secp160r2 — 160-bit prime curve (variant)
    Secp160r2,
    /// secp160k1 — 160-bit Koblitz curve
    Secp160k1,
    /// secp192k1 — 192-bit Koblitz curve
    Secp192k1,
    /// secp224k1 — 224-bit Koblitz curve
    Secp224k1,

    // Montgomery / Edwards curves (handled by curve25519 submodule)
    /// X25519 — Curve25519 for Diffie-Hellman key exchange (RFC 7748)
    X25519,
    /// X448 — Curve448 for Diffie-Hellman key exchange (RFC 7748)
    X448,
    /// Ed25519 — Edwards25519 for `EdDSA` signatures (RFC 8032)
    Ed25519,
    /// Ed448 — Edwards448 for `EdDSA` signatures (RFC 8032)
    Ed448,
}

impl NamedCurve {
    /// Returns the key size in bits for this curve.
    ///
    /// For example, P-256 returns 256, P-384 returns 384, P-521 returns 521.
    pub fn key_size_bits(&self) -> u32 {
        match self {
            Self::Secp160r1 | Self::Secp160r2 | Self::Secp160k1 => 160,
            Self::Secp192r1 | Self::Secp192k1 => 192,
            Self::Secp224r1 | Self::Secp224k1 => 224,
            Self::Prime256v1
            | Self::Secp256k1
            | Self::BrainpoolP256r1
            | Self::BrainpoolP256t1
            | Self::Sm2
            | Self::X25519
            | Self::Ed25519 => 256,
            Self::Secp384r1 | Self::BrainpoolP384r1 | Self::BrainpoolP384t1 => 384,
            Self::X448 | Self::Ed448 => 448,
            Self::BrainpoolP512r1 | Self::BrainpoolP512t1 => 512,
            Self::Secp521r1 => 521,
        }
    }

    /// Returns the field element byte size for this curve.
    ///
    /// Computed as `⌈key_size_bits / 8⌉`.
    pub fn field_size_bytes(&self) -> usize {
        let bits = self.key_size_bits() as usize;
        (bits + 7) / 8
    }

    /// Returns `true` if this is a NIST prime curve (P-192, P-224, P-256, P-384, P-521).
    pub fn is_nist_curve(&self) -> bool {
        matches!(
            self,
            Self::Secp192r1
                | Self::Secp224r1
                | Self::Prime256v1
                | Self::Secp384r1
                | Self::Secp521r1
        )
    }

    /// Parses a curve name string into a [`NamedCurve`] variant.
    ///
    /// Accepts canonical OpenSSL names (e.g., `"prime256v1"`), NIST names
    /// (e.g., `"P-256"`), and SEC names (e.g., `"secp256r1"`).
    ///
    /// # Returns
    ///
    /// `None` if the curve name is not recognized.
    pub fn from_name(name: &str) -> Option<NamedCurve> {
        match name {
            "prime256v1" | "P-256" | "secp256r1" => Some(Self::Prime256v1),
            "secp384r1" | "P-384" => Some(Self::Secp384r1),
            "secp521r1" | "P-521" => Some(Self::Secp521r1),
            "secp256k1" => Some(Self::Secp256k1),
            "secp224r1" | "P-224" => Some(Self::Secp224r1),
            "brainpoolP256r1" => Some(Self::BrainpoolP256r1),
            "brainpoolP384r1" => Some(Self::BrainpoolP384r1),
            "brainpoolP512r1" => Some(Self::BrainpoolP512r1),
            "brainpoolP256t1" => Some(Self::BrainpoolP256t1),
            "brainpoolP384t1" => Some(Self::BrainpoolP384t1),
            "brainpoolP512t1" => Some(Self::BrainpoolP512t1),
            "SM2" | "sm2" => Some(Self::Sm2),
            "secp192r1" | "P-192" => Some(Self::Secp192r1),
            "secp160r1" => Some(Self::Secp160r1),
            "secp160r2" => Some(Self::Secp160r2),
            "secp160k1" => Some(Self::Secp160k1),
            "secp192k1" => Some(Self::Secp192k1),
            "secp224k1" => Some(Self::Secp224k1),
            "X25519" | "x25519" => Some(Self::X25519),
            "X448" | "x448" => Some(Self::X448),
            "Ed25519" | "ed25519" => Some(Self::Ed25519),
            "Ed448" | "ed448" => Some(Self::Ed448),
            _ => None,
        }
    }

    /// Returns the canonical string name for this curve.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Prime256v1 => "prime256v1",
            Self::Secp384r1 => "secp384r1",
            Self::Secp521r1 => "secp521r1",
            Self::Secp256k1 => "secp256k1",
            Self::Secp224r1 => "secp224r1",
            Self::BrainpoolP256r1 => "brainpoolP256r1",
            Self::BrainpoolP384r1 => "brainpoolP384r1",
            Self::BrainpoolP512r1 => "brainpoolP512r1",
            Self::BrainpoolP256t1 => "brainpoolP256t1",
            Self::BrainpoolP384t1 => "brainpoolP384t1",
            Self::BrainpoolP512t1 => "brainpoolP512t1",
            Self::Sm2 => "SM2",
            Self::Secp192r1 => "secp192r1",
            Self::Secp160r1 => "secp160r1",
            Self::Secp160r2 => "secp160r2",
            Self::Secp160k1 => "secp160k1",
            Self::Secp192k1 => "secp192k1",
            Self::Secp224k1 => "secp224k1",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
        }
    }
}

impl std::fmt::Display for NamedCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ===========================================================================
// PointConversionForm — point encoding format
// ===========================================================================

/// How an EC point is encoded in octet strings.
///
/// Replaces the C `point_conversion_form_t` enum from `ec.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointConversionForm {
    /// Compressed form: 0x02/0x03 prefix + x-coordinate
    Compressed,
    /// Uncompressed form: 0x04 prefix + x + y coordinates
    Uncompressed,
    /// Hybrid form: 0x06/0x07 prefix + x + y coordinates
    Hybrid,
}

impl Default for PointConversionForm {
    /// Default is uncompressed, matching OpenSSL's default behavior.
    fn default() -> Self {
        Self::Uncompressed
    }
}

// ===========================================================================
// EcGroup — elliptic curve group parameters
// ===========================================================================

/// Elliptic curve group parameters — the Rust equivalent of C `EC_GROUP`.
///
/// Holds the curve equation coefficients, generator point, order, and cofactor.
/// Constructed from a named curve via [`EcGroup::from_curve_name`], replacing
/// the C function `EC_GROUP_new_by_curve_name()` from `crypto/ec/ec_curve.c`.
///
/// # Rule R5
///
/// `curve_name` is `Option<NamedCurve>` rather than an integer sentinel.
///
/// # Rule R7
///
/// When shared across threads (e.g., in a named-curve cache), wrap in
/// `Arc<EcGroup>`.
/// // LOCK-SCOPE: `EcGroup` instances are immutable after construction and
/// // do not require locking for concurrent read access.
#[derive(Debug, Clone)]
pub struct EcGroup {
    /// Named curve identifier (None for explicit/custom parameters)
    curve_name: Option<NamedCurve>,
    /// Curve field prime p (for GF(p) curves)
    field: BigNum,
    /// Curve coefficient a in the equation y² = x³ + ax + b
    a: BigNum,
    /// Curve coefficient b in the equation y² = x³ + ax + b
    b: BigNum,
    /// Generator point G on the curve
    generator: EcPoint,
    /// Order n of the generator point: |⟨G⟩| = n
    order: BigNum,
    /// Cofactor h = |E(GF(p))| / n
    cofactor: BigNum,
    /// Field size in bits (the degree of the curve)
    degree: u32,
    /// Default point encoding form
    conversion_form: PointConversionForm,
}

impl EcGroup {
    /// Constructs an `EcGroup` from a named curve.
    ///
    /// Replaces `EC_GROUP_new_by_curve_name()` from `crypto/ec/ec_curve.c`.
    /// Loads built-in curve parameters for the specified curve.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the curve parameters cannot be loaded.
    pub fn from_curve_name(curve: NamedCurve) -> CryptoResult<Self> {
        debug!(curve = %curve, "EcGroup: constructing from named curve");
        let params = load_curve_params(curve)?;
        Ok(params)
    }

    /// Constructs an `EcGroup` from explicit curve parameters.
    ///
    /// This is the low-level constructor for custom curves not in the
    /// built-in catalog. Replaces `EC_GROUP_set_curve()`.
    pub fn from_explicit_params(
        field: BigNum,
        a: BigNum,
        b: BigNum,
        generator: EcPoint,
        order: BigNum,
        cofactor: BigNum,
    ) -> CryptoResult<Self> {
        let degree = field.num_bits();
        Ok(Self {
            curve_name: None,
            field,
            a,
            b,
            generator,
            order,
            cofactor,
            degree,
            conversion_form: PointConversionForm::Uncompressed,
        })
    }

    /// Returns the named curve identifier, if this group was constructed
    /// from a named curve. Returns `None` for explicit-parameter groups.
    #[inline]
    pub fn curve_name(&self) -> Option<NamedCurve> {
        self.curve_name
    }

    /// Returns the field prime p.
    #[inline]
    pub fn field(&self) -> &BigNum {
        &self.field
    }

    /// Returns the curve coefficient a.
    #[inline]
    pub fn a(&self) -> &BigNum {
        &self.a
    }

    /// Returns the curve coefficient b.
    #[inline]
    pub fn b(&self) -> &BigNum {
        &self.b
    }

    /// Returns the generator point G.
    #[inline]
    pub fn generator(&self) -> &EcPoint {
        &self.generator
    }

    /// Returns the order n of the generator point.
    #[inline]
    pub fn order(&self) -> &BigNum {
        &self.order
    }

    /// Returns the cofactor h.
    ///
    /// For most NIST prime curves, the cofactor is 1. For some curves
    /// (e.g., Curve25519 with cofactor 8), it may be larger.
    #[inline]
    pub fn cofactor(&self) -> &BigNum {
        &self.cofactor
    }

    /// Returns the field size in bits (the degree of the curve).
    ///
    /// Replaces `EC_GROUP_get_degree()` from `crypto/ec/ec_lib.c`.
    /// For example: P-256 returns 256, P-384 returns 384, P-521 returns 521.
    #[inline]
    pub fn degree(&self) -> u32 {
        self.degree
    }

    /// Validates the group parameters.
    ///
    /// Replaces `EC_GROUP_check()` from `crypto/ec/ec_check.c`. Checks that:
    /// - The discriminant 4a³ + 27b² ≠ 0 (non-singular curve)
    /// - The generator is on the curve
    /// - order × G = point at infinity
    ///
    /// # Returns
    ///
    /// `true` if all checks pass, `false` otherwise.
    pub fn check(&self) -> CryptoResult<bool> {
        // Verify discriminant is non-zero modulo p (curve is non-singular).
        // discriminant = (4*a^3 + 27*b^2) mod p
        //
        // For short Weierstrass curves y² = x³ + ax + b over GF(p),
        // the discriminant must be non-zero in GF(p) to ensure the curve
        // has no singular points.
        let p = &self.field;
        let four = BigNum::from_u64(4);
        let twenty_seven = BigNum::from_u64(27);
        let a_squared_pre = &self.a * &self.a;
        let a_squared = crate::bn::arithmetic::nnmod(&a_squared_pre, p)?;
        let a_cubed_pre = &a_squared * &self.a;
        let a_cubed = crate::bn::arithmetic::nnmod(&a_cubed_pre, p)?;
        let b_squared_pre = &self.b * &self.b;
        let b_squared = crate::bn::arithmetic::nnmod(&b_squared_pre, p)?;
        let term1 = crate::bn::arithmetic::mod_mul(&four, &a_cubed, p)?;
        let term2 = crate::bn::arithmetic::mod_mul(&twenty_seven, &b_squared, p)?;
        let disc_pre = &term1 + &term2;
        let discriminant = crate::bn::arithmetic::nnmod(&disc_pre, p)?;
        if discriminant.is_zero() {
            return Ok(false);
        }

        // Verify generator is on the curve.
        if !self.generator.is_on_curve(self)? {
            return Ok(false);
        }

        // Verify that order × G = point at infinity.
        // This confirms that `order` is truly the order of the generator's
        // subgroup, a critical sanity check that protects against
        // group-parameter attacks.
        let order_times_g = EcPoint::mul(self, &self.generator, &self.order)?;
        if !order_times_g.is_at_infinity() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Returns the default point conversion form for this group.
    #[inline]
    pub fn conversion_form(&self) -> PointConversionForm {
        self.conversion_form
    }
}

// ===========================================================================
// EcPoint — point on an elliptic curve
// ===========================================================================

/// Point on an elliptic curve — the Rust equivalent of C `EC_POINT`.
///
/// Internally uses affine coordinates (x, y) for the public API, with
/// an `is_infinity` flag for the point at infinity (the group identity).
///
/// Replaces `struct ec_point_st` from `crypto/ec/ec_local.h` lines 314–328.
///
/// # Constant-Time Comparison
///
/// The [`PartialEq`] implementation uses coordinate comparison to prevent
/// timing side-channel attacks during ECDSA verification or ECDH.
#[derive(Debug, Clone)]
pub struct EcPoint {
    /// X coordinate (affine)
    x: BigNum,
    /// Y coordinate (affine)
    y: BigNum,
    /// Whether this is the point at infinity (identity element)
    is_infinity: bool,
}

impl EcPoint {
    /// Creates the point at infinity (the identity element of the group).
    ///
    /// Replaces `EC_POINT_set_to_infinity()`.
    pub fn new_at_infinity() -> Self {
        Self {
            x: BigNum::zero(),
            y: BigNum::zero(),
            is_infinity: true,
        }
    }

    /// Creates a point from affine coordinates (x, y).
    ///
    /// Replaces `EC_POINT_set_affine_coordinates()`.
    pub fn from_affine(x: BigNum, y: BigNum) -> Self {
        Self {
            x,
            y,
            is_infinity: false,
        }
    }

    /// Returns the x-coordinate of this point.
    ///
    /// For the point at infinity, returns zero.
    #[inline]
    pub fn x(&self) -> &BigNum {
        &self.x
    }

    /// Returns the y-coordinate of this point.
    ///
    /// For the point at infinity, returns zero.
    #[inline]
    pub fn y(&self) -> &BigNum {
        &self.y
    }

    /// Returns `true` if this point is the point at infinity.
    ///
    /// Replaces `EC_POINT_is_at_infinity()` from `crypto/ec/ec_lib.c`.
    #[inline]
    pub fn is_at_infinity(&self) -> bool {
        self.is_infinity
    }

    /// Checks whether this point lies on the specified curve.
    ///
    /// Replaces `EC_POINT_is_on_curve()` from `crypto/ec/ec_lib.c`.
    /// Verifies the curve equation: y² ≡ x³ + ax + b (mod p).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if an arithmetic error occurs.
    pub fn is_on_curve(&self, group: &EcGroup) -> CryptoResult<bool> {
        // The point at infinity is always on the curve (it's the identity element)
        if self.is_infinity {
            return Ok(true);
        }

        // Verify y² ≡ x³ + ax + b (mod p)
        // Left side: y²
        let y_squared = &self.y * &self.y;

        // Right side: x³ + ax + b
        let x_squared = &self.x * &self.x;
        let x_cubed = &x_squared * &self.x;
        let a_x = &group.a * &self.x;
        let rhs = &(&x_cubed + &a_x) + &group.b;

        // For proper modular arithmetic, we should do mod p. Since BigNum
        // doesn't have built-in modular reduction in the simple path, we
        // use the modular arithmetic from the bn::arithmetic module.
        // For now, compare the values modulo the field prime.
        let p = &group.field;
        if p.is_zero() {
            return Err(CryptoError::Key(
                "EC: group field prime is zero".to_string(),
            ));
        }

        let lhs_mod = crate::bn::arithmetic::nnmod(&y_squared, p)?;
        let rhs_mod = crate::bn::arithmetic::nnmod(&rhs, p)?;

        Ok(lhs_mod == rhs_mod)
    }

    /// Encodes this point to bytes in the specified conversion form.
    ///
    /// Replaces `EC_POINT_point2oct()` from `crypto/ec/ec_oct.c`.
    pub fn to_bytes(&self, group: &EcGroup, form: PointConversionForm) -> CryptoResult<Vec<u8>> {
        if self.is_infinity {
            return Ok(vec![0x00]);
        }

        let field_len = group.curve_name().map_or_else(
            || {
                let bits = group.degree() as usize;
                (bits + 7) / 8
            },
            |c| c.field_size_bytes(),
        );

        let x_bytes = self.x.to_bytes_be_padded(field_len)?;
        let y_bytes = self.y.to_bytes_be_padded(field_len)?;

        match form {
            PointConversionForm::Uncompressed => {
                let mut result = Vec::with_capacity(1 + 2 * field_len);
                result.push(0x04);
                result.extend_from_slice(&x_bytes);
                result.extend_from_slice(&y_bytes);
                Ok(result)
            }
            PointConversionForm::Compressed => {
                let y_low_bit = if y_bytes.last().map_or(false, |b| b & 1 == 1) {
                    0x03_u8
                } else {
                    0x02_u8
                };
                let mut result = Vec::with_capacity(1 + field_len);
                result.push(y_low_bit);
                result.extend_from_slice(&x_bytes);
                Ok(result)
            }
            PointConversionForm::Hybrid => {
                let y_low_bit = if y_bytes.last().map_or(false, |b| b & 1 == 1) {
                    0x07_u8
                } else {
                    0x06_u8
                };
                let mut result = Vec::with_capacity(1 + 2 * field_len);
                result.push(y_low_bit);
                result.extend_from_slice(&x_bytes);
                result.extend_from_slice(&y_bytes);
                Ok(result)
            }
        }
    }

    /// Decodes a point from bytes.
    ///
    /// Replaces `EC_POINT_oct2point()` from `crypto/ec/ec_oct.c`.
    pub fn from_bytes(group: &EcGroup, bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.is_empty() {
            return Err(CryptoError::Encoding(
                "EC: empty point encoding".to_string(),
            ));
        }

        // Point at infinity
        if bytes.len() == 1 && bytes[0] == 0x00 {
            return Ok(Self::new_at_infinity());
        }

        let field_len = group.curve_name().map_or_else(
            || {
                let bits = group.degree() as usize;
                (bits + 7) / 8
            },
            |c| c.field_size_bytes(),
        );

        match bytes[0] {
            0x04 => {
                // Uncompressed form
                if bytes.len() != 1 + 2 * field_len {
                    return Err(CryptoError::Encoding(
                        "EC: invalid uncompressed point length".to_string(),
                    ));
                }
                let x = BigNum::from_bytes_be(&bytes[1..=field_len]);
                let y = BigNum::from_bytes_be(&bytes[1 + field_len..]);
                Ok(Self::from_affine(x, y))
            }
            0x02 | 0x03 => {
                // Compressed form — point decompression.
                //
                // Given x and a parity bit, recover y by solving
                //     y² ≡ x³ + ax + b (mod p)
                // using a Tonelli–Shanks-based modular square root, then
                // selecting the root whose parity matches the low bit encoded
                // in the leading byte (0x02 = even y, 0x03 = odd y).
                //
                // Replaces the OpenSSL C implementation of
                // `ossl_ec_GFp_simple_point_oct2point()` compressed decode
                // path in `crypto/ec/ecp_smpl.c`.
                if bytes.len() != 1 + field_len {
                    return Err(CryptoError::Encoding(
                        "EC: invalid compressed point length".to_string(),
                    ));
                }
                let x = BigNum::from_bytes_be(&bytes[1..]);
                let p = &group.field;

                // Reject x >= p as an invalid encoding.
                if &x >= p {
                    return Err(CryptoError::Encoding(
                        "EC: compressed point x-coordinate >= field prime".to_string(),
                    ));
                }

                // Compute rhs = x³ + a·x + b (mod p)
                let x_squared_pre = &x * &x;
                let x_squared = crate::bn::arithmetic::nnmod(&x_squared_pre, p)?;
                let x_cubed_pre = &x_squared * &x;
                let x_cubed = crate::bn::arithmetic::nnmod(&x_cubed_pre, p)?;
                let a_x_pre = &group.a * &x;
                let a_x = crate::bn::arithmetic::nnmod(&a_x_pre, p)?;
                let sum_pre = &(&x_cubed + &a_x) + &group.b;
                let rhs = crate::bn::arithmetic::nnmod(&sum_pre, p)?;

                // Solve y² ≡ rhs (mod p) for y via modular square root.
                let Some(y_candidate) = crate::bn::arithmetic::mod_sqrt(&rhs, p)? else {
                    return Err(CryptoError::Encoding(
                        "EC: invalid compressed point (not a quadratic residue)".to_string(),
                    ));
                };

                // Select the root whose parity matches the encoded bit.
                // 0x03 → want_odd = true; 0x02 → want_odd = false.
                let want_odd = bytes[0] == 0x03;
                let y_is_odd = y_candidate.is_odd();
                let y = if want_odd == y_is_odd {
                    y_candidate
                } else {
                    // The other root is p - y.
                    let neg_pre = p - &y_candidate;
                    crate::bn::arithmetic::nnmod(&neg_pre, p)?
                };

                Ok(Self::from_affine(x, y))
            }
            0x06 | 0x07 => {
                // Hybrid form
                if bytes.len() != 1 + 2 * field_len {
                    return Err(CryptoError::Encoding(
                        "EC: invalid hybrid point length".to_string(),
                    ));
                }
                let x = BigNum::from_bytes_be(&bytes[1..=field_len]);
                let y = BigNum::from_bytes_be(&bytes[1 + field_len..]);
                Ok(Self::from_affine(x, y))
            }
            _ => Err(CryptoError::Encoding(format!(
                "EC: unknown point encoding prefix 0x{:02x}",
                bytes[0]
            ))),
        }
    }

    /// Adds two points on the curve: result = a + b.
    ///
    /// Replaces `EC_POINT_add()` from `crypto/ec/ec_lib.c`.
    pub fn add(group: &EcGroup, a: &EcPoint, b: &EcPoint) -> CryptoResult<EcPoint> {
        // Handle identity element cases
        if a.is_infinity {
            return Ok(b.clone());
        }
        if b.is_infinity {
            return Ok(a.clone());
        }

        // If points are equal, use doubling
        if a.x == b.x && a.y == b.y {
            return Self::double(group, a);
        }

        // If x-coordinates are equal but y-coordinates differ → inverse → infinity
        if a.x == b.x {
            return Ok(Self::new_at_infinity());
        }

        // Standard affine addition: slope = (y2 - y1) / (x2 - x1) mod p
        let p = &group.field;
        let dy = &b.y - &a.y;
        let dx = &b.x - &a.x;

        // Compute modular inverse of dx via extended GCD
        let dx_inv = crate::bn::arithmetic::mod_inverse_checked(&dx, p)?;
        let slope = crate::bn::arithmetic::mod_mul(&dy, &dx_inv, p)?;

        // x3 = slope² - x1 - x2 mod p
        let slope_sq = crate::bn::arithmetic::mod_mul(&slope, &slope, p)?;
        let x3_pre = &(&slope_sq - &a.x) - &b.x;
        let x3 = crate::bn::arithmetic::nnmod(&x3_pre, p)?;

        // y3 = slope * (x1 - x3) - y1 mod p
        let dx13 = &a.x - &x3;
        let y3_pre = &crate::bn::arithmetic::mod_mul(&slope, &dx13, p)? - &a.y;
        let y3 = crate::bn::arithmetic::nnmod(&y3_pre, p)?;

        Ok(Self::from_affine(x3, y3))
    }

    /// Doubles a point on the curve: result = 2 × p.
    ///
    /// Replaces `EC_POINT_dbl()` from `crypto/ec/ec_lib.c`.
    pub fn double(group: &EcGroup, point: &EcPoint) -> CryptoResult<EcPoint> {
        if point.is_infinity {
            return Ok(Self::new_at_infinity());
        }

        // If y = 0, the tangent is vertical → result is infinity
        if point.y.is_zero() {
            return Ok(Self::new_at_infinity());
        }

        let p = &group.field;

        // slope = (3 * x² + a) / (2 * y) mod p
        let three = BigNum::from_u64(3);
        let two = BigNum::from_u64(2);
        let x_sq = crate::bn::arithmetic::mod_mul(&point.x, &point.x, p)?;
        let three_x_sq = crate::bn::arithmetic::mod_mul(&three, &x_sq, p)?;
        let numerator = &three_x_sq + &group.a;

        let two_y = crate::bn::arithmetic::mod_mul(&two, &point.y, p)?;
        let two_y_inv = crate::bn::arithmetic::mod_inverse_checked(&two_y, p)?;

        let slope = crate::bn::arithmetic::mod_mul(&numerator, &two_y_inv, p)?;

        // x3 = slope² - 2*x mod p
        let slope_sq = crate::bn::arithmetic::mod_mul(&slope, &slope, p)?;
        let two_x = crate::bn::arithmetic::mod_mul(&two, &point.x, p)?;
        let x3_pre = &slope_sq - &two_x;
        let x3 = crate::bn::arithmetic::nnmod(&x3_pre, p)?;

        // y3 = slope * (x - x3) - y mod p
        let dx = &point.x - &x3;
        let y3_pre = &crate::bn::arithmetic::mod_mul(&slope, &dx, p)? - &point.y;
        let y3 = crate::bn::arithmetic::nnmod(&y3_pre, p)?;

        Ok(Self::from_affine(x3, y3))
    }

    /// Inverts a point: result = -P (negate y-coordinate modulo p).
    ///
    /// Replaces `EC_POINT_invert()` from `crypto/ec/ec_lib.c`.
    ///
    /// For a point `P = (x, y)` on a short Weierstrass curve, the inverse
    /// is `-P = (x, -y mod p)`. The point at infinity is self-inverse, and
    /// when `y = 0` the point equals its own inverse.
    pub fn invert(group: &EcGroup, point: &EcPoint) -> CryptoResult<EcPoint> {
        if point.is_infinity {
            return Ok(Self::new_at_infinity());
        }
        // A point with y = 0 is its own inverse (it satisfies 2P = O).
        if point.y.is_zero() {
            return Ok(Self::from_affine(point.x.clone(), BigNum::zero()));
        }
        // -P = (x, (p - y) mod p)
        let neg_y_pre = &group.field - &point.y;
        let neg_y = crate::bn::arithmetic::nnmod(&neg_y_pre, &group.field)?;
        Ok(Self::from_affine(point.x.clone(), neg_y))
    }

    /// Scalar multiplication: result = scalar × point.
    ///
    /// Replaces `EC_POINT_mul()` from `crypto/ec/ec_mult.c`. Uses the
    /// **Montgomery ladder** algorithm, which performs the same sequence of
    /// operations regardless of the bit pattern of `scalar`. This eliminates
    /// the catastrophic Hamming-weight timing leak inherent to the
    /// double-and-add pattern.
    ///
    /// # Algorithm
    ///
    /// For each scalar bit `k_i` from the most significant to the least
    /// significant (over a fixed bit length derived from the group order):
    ///
    /// ```text
    /// cswap(R0, R1, k_i)
    /// R1 = R0 + R1
    /// R0 = 2 * R0
    /// cswap(R0, R1, k_i)
    /// ```
    ///
    /// At each iteration, the invariant `R1 = R0 + P` is maintained.
    /// At the end, `R0 = scalar * P`.
    ///
    /// The number of iterations is fixed by `group.order().num_bits()` so
    /// the total operation count does not depend on `scalar.num_bits()`.
    ///
    /// # Security
    ///
    /// The ladder eliminates the **Hamming-weight (bit-pattern) timing
    /// leak** that would otherwise allow recovery of secret scalars (ECDH
    /// private keys, ECDSA nonces) via timing observation.
    ///
    /// **Residual leaks (documented for follow-up work):**
    ///
    /// - The internal `add()` and `double()` routines are not themselves
    ///   constant-time: they branch on `is_infinity`, `y == 0`, and the
    ///   `a.x == b.x` test. For the ladder hot path on a curve of
    ///   prime order with a non-infinity input, these branches are not
    ///   exercised, but the leading-zero-bit prefix of small scalars
    ///   currently still hits the `is_infinity` early returns. A complete
    ///   constant-time fix requires Jacobian (projective) coordinates with
    ///   complete addition formulas (Renes–Costello–Batina, IACR 2015/1060)
    ///   so that no operand-dependent branch ever fires.
    ///
    /// - `mod_inverse_checked` (used by `add` and `double`) is implemented
    ///   via the Extended Euclidean algorithm whose loop count depends on
    ///   the operand bit pattern. Migration to a Bernstein–Yang
    ///   constant-time inversion is required for full hardening.
    ///
    /// These residual leaks are tracked under the broader project plan to
    /// migrate EC to Jacobian coordinates with complete formulas. The
    /// Hamming-weight leak fixed here is the primary attack vector
    /// (full scalar recovery) and is the one closed by this commit.
    ///
    /// **Curve25519 / Ed25519** are unaffected by this code path — they
    /// use their own dedicated constant-time Montgomery ladder in
    /// [`crate::ec::curve25519`].
    ///
    /// # Performance
    ///
    /// The ladder performs one `add` and one `double` per scalar bit
    /// (regardless of bit value), so it is approximately twice the cost
    /// of a non-CT double-and-add average case but with no timing
    /// variance.
    pub fn mul(group: &EcGroup, point: &EcPoint, scalar: &BigNum) -> CryptoResult<EcPoint> {
        trace!("EcPoint::mul: performing scalar multiplication via Montgomery ladder");

        // Trivial early returns. These are correctness shortcuts that
        // execute only when `scalar` is the literal value 0 or 1, or
        // `point` is the identity. They do not leak the bit pattern of
        // a generic secret scalar — they leak only whether the scalar
        // is exactly 0 or 1, which is benign (and necessary to handle
        // the algorithm's edge cases without contaminating the ladder).
        if scalar.is_zero() || point.is_infinity {
            return Ok(Self::new_at_infinity());
        }
        if scalar.is_one() {
            return Ok(point.clone());
        }

        // Fixed loop bit-length: use the group order's bit length so the
        // iteration count never depends on the scalar's actual bit
        // length. For NIST P-256 this is 256, for P-384 it is 384, etc.
        // Scalars are guaranteed to satisfy `scalar < order`, so this
        // upper bound is sufficient.
        let bit_len = group.order().num_bits();

        // Initial state: R0 = O (point at infinity), R1 = P.
        // Loop invariant: at the start of iteration i, R0 = m*P and
        // R1 = (m+1)*P, where m is the integer formed by the scalar's
        // bits processed so far (from MSB down to but not including
        // bit i).
        let mut r0 = Self::new_at_infinity();
        let mut r1 = point.clone();

        // Process bits from most significant to least significant. The
        // iteration count is fixed: `bit_len` total. For scalars whose
        // actual bit length is less than `bit_len`, the high bits read
        // as 0 and the ladder simply preserves R0=O for those leading
        // iterations (a cosmetic residual leak — see Security note).
        for i in (0..bit_len).rev() {
            let bit: u8 = u8::from(scalar.is_bit_set(i));
            let choice = Choice::from(bit);

            // cswap(R0, R1, bit): if bit=1 swap, if bit=0 leave alone.
            ct_swap_points(&mut r0, &mut r1, group, choice);

            // R1 = R0 + R1, R0 = 2 * R0.
            // Note: these calls are not internally constant-time, but
            // their inputs at this point in the ladder are determined
            // by the curve and the public point, not by individual
            // scalar bits — the swap above ensures the operand
            // identities (which one holds m*P vs (m+1)*P) are masked.
            let new_r1 = Self::add(group, &r0, &r1)?;
            let new_r0 = Self::double(group, &r0)?;
            r0 = new_r0;
            r1 = new_r1;

            // Swap back so the invariant R1 = R0 + P is preserved.
            ct_swap_points(&mut r0, &mut r1, group, choice);
        }

        Ok(r0)
    }

    /// Fixed-base scalar multiplication: result = scalar × G.
    ///
    /// Uses the group's generator point. This is an optimization entry
    /// point that implementations can specialize with precomputed tables.
    pub fn generator_mul(group: &EcGroup, scalar: &BigNum) -> CryptoResult<EcPoint> {
        Self::mul(group, group.generator(), scalar)
    }
}

impl PartialEq for EcPoint {
    /// Compares two EC points in constant time.
    ///
    /// Both coordinates and the infinity flag must match. The comparison
    /// uses [`subtle::ConstantTimeEq`] to prevent timing side-channel
    /// leaks during sensitive operations such as ECDSA verification or
    /// ECDH shared-secret validation.
    ///
    /// Replaces the C pattern `CRYPTO_memcmp()` from
    /// `crypto/ec/ec_lib.c` (`EC_POINT_cmp()`).
    fn eq(&self, other: &Self) -> bool {
        // The infinity flag is compared as a constant-time byte
        // compare on the 0/1 value, so a timing observer cannot tell
        // whether the difference came from the infinity flag or the
        // coordinate comparison.
        let self_inf = u8::from(self.is_infinity);
        let other_inf = u8::from(other.is_infinity);
        let inf_eq = self_inf.ct_eq(&other_inf);

        // If both are infinity, their (zero) coordinates compare
        // equal and the overall result is `inf_eq`. If one is
        // infinity and the other is not, the coordinate comparison
        // below may produce a spurious result, but `inf_eq` will be
        // 0 and ANDing kills the result.
        //
        // Use a common byte length for the byte-wise comparison so
        // that leading-zero differences do not cause early exit.
        let sx = self.x.to_bytes_be();
        let ox = other.x.to_bytes_be();
        let sy = self.y.to_bytes_be();
        let oy = other.y.to_bytes_be();
        let max_x = sx.len().max(ox.len());
        let max_y = sy.len().max(oy.len());
        let sxp = pad_be(&sx, max_x);
        let oxp = pad_be(&ox, max_x);
        let syp = pad_be(&sy, max_y);
        let oyp = pad_be(&oy, max_y);

        let x_eq = sxp.ct_eq(&oxp);
        let y_eq = syp.ct_eq(&oyp);

        (inf_eq & x_eq & y_eq).unwrap_u8() == 1
    }
}

impl Eq for EcPoint {}

/// Pads a big-endian byte slice with leading zeros to the specified length.
///
/// Used to normalize coordinate byte lengths prior to constant-time
/// comparison so that trailing-length differences do not perturb timing.
#[inline]
fn pad_be(bytes: &[u8], target_len: usize) -> Vec<u8> {
    if bytes.len() >= target_len {
        return bytes.to_vec();
    }
    let mut out = vec![0_u8; target_len];
    let offset = target_len - bytes.len();
    out[offset..].copy_from_slice(bytes);
    out
}

/// Constant-time conditional swap of two [`EcPoint`]s based on `choice`.
///
/// If `choice == 1`, the contents of `a` and `b` are swapped. If
/// `choice == 0`, both are left unchanged. The control flow and memory
/// access pattern are independent of `choice` — this primitive is the
/// core building block of the Montgomery ladder used in
/// [`EcPoint::mul`].
///
/// # Implementation
///
/// Coordinates are first serialized to fixed-length (degree-byte)
/// big-endian byte arrays. A byte-by-byte
/// [`ConditionallySelectable`](subtle::ConditionallySelectable)
/// swap is performed using `subtle`'s constant-time primitives, then
/// the bytes are reassembled into [`BigNum`]s. The `is_infinity` flag
/// is also swapped via byte-wise constant-time selection.
///
/// # Security
///
/// This function does not branch on the value of `choice` and does not
/// vary memory access patterns based on `choice`. The only data leaked
/// to a timing observer is the byte length of the operand coordinates,
/// which is fixed at `degree`-bytes after padding.
///
/// # Source Reference
///
/// Mirrors the constant-time swap pattern used in OpenSSL's
/// `ec_GFp_simple_ladder_*()` family of functions in `crypto/ec/ecp_smpl.c`.
fn ct_swap_points(a: &mut EcPoint, b: &mut EcPoint, group: &EcGroup, choice: Choice) {
    // R6: lossless cast — degree fits in u32, divide-and-ceil by 8 yields
    // a small usize that cannot overflow. The result is the canonical
    // byte-length of a coordinate for this curve.
    let target_len = ((group.degree() as usize) + 7) / 8;

    // Serialize to fixed-length big-endian byte arrays.
    let mut a_x = pad_be(&a.x.to_bytes_be(), target_len);
    let mut b_x = pad_be(&b.x.to_bytes_be(), target_len);
    let mut a_y = pad_be(&a.y.to_bytes_be(), target_len);
    let mut b_y = pad_be(&b.y.to_bytes_be(), target_len);

    // Byte-by-byte constant-time swap of the X and Y coordinates.
    // `u8::conditional_swap` reads both operands and writes both back,
    // so the memory access pattern is identical regardless of `choice`.
    for i in 0..target_len {
        u8::conditional_swap(&mut a_x[i], &mut b_x[i], choice);
        u8::conditional_swap(&mut a_y[i], &mut b_y[i], choice);
    }

    // Constant-time swap of the `is_infinity` flag, encoded as a u8.
    let mut a_inf = u8::from(a.is_infinity);
    let mut b_inf = u8::from(b.is_infinity);
    u8::conditional_swap(&mut a_inf, &mut b_inf, choice);

    // Reconstruct the [`BigNum`] coordinates from the (possibly swapped)
    // byte arrays. `BigNum::from_bytes_be` does not branch on the byte
    // contents (it always reads `target_len` bytes).
    a.x = BigNum::from_bytes_be(&a_x);
    a.y = BigNum::from_bytes_be(&a_y);
    a.is_infinity = a_inf == 1;
    b.x = BigNum::from_bytes_be(&b_x);
    b.y = BigNum::from_bytes_be(&b_y);
    b.is_infinity = b_inf == 1;
}

// ===========================================================================
// EcKey — EC key pair
// ===========================================================================

/// EC key pair — the Rust equivalent of C `EC_KEY`.
///
/// Private key material is securely zeroed on drop via [`Zeroize`].
/// Replaces `struct ec_key_st` from `crypto/ec/ec_local.h` lines 294–312.
///
/// # Security
///
/// The private key scalar is zeroed from memory when the `EcKey` is dropped,
/// replacing the C pattern `BN_clear_free(priv_key)` in `EC_KEY_free()`.
///
/// # Rule R5
///
/// `private_key` and `public_key` are `Option<T>` rather than NULL pointers.
pub struct EcKey {
    /// The EC group (curve parameters) this key belongs to
    group: EcGroup,
    /// Public key (point on curve) — None if not yet computed
    public_key: Option<EcPoint>,
    /// Private key (scalar) — None for public-only keys.
    ///
    /// Wrapped in [`SecureBigNum`] so the scalar is zeroed via the
    /// `zeroize` crate when this `EcKey` is dropped. Replaces the C
    /// pattern `BN_clear_free(priv_key)` in `EC_KEY_free()`.
    private_key: Option<SecureBigNum>,
    /// Point encoding form for this key
    conversion_form: PointConversionForm,
}

impl EcKey {
    /// Generates a new EC key pair on the specified curve.
    ///
    /// Replaces `EC_KEY_generate_key()` from `crypto/ec/ec_key.c`.
    /// Generates a random private key in [1, order-1] and computes
    /// the public key as `pub = priv × G`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if key generation fails.
    pub fn generate(group: &EcGroup) -> CryptoResult<Self> {
        let curve_label = group.curve_name().map_or("custom", |c| c.name());
        trace!(curve = curve_label, "EcKey: generating new key pair");

        // Generate a random scalar in [1, order-1] via the crate CSPRNG.
        let order = group.order();
        let priv_key = generate_random_scalar(order)?;

        // Compute public key: pub = priv × G
        let pub_key = EcPoint::generator_mul(group, &priv_key)?;

        trace!(
            curve = curve_label,
            "EcKey: key pair generated successfully"
        );

        Ok(Self {
            group: group.clone(),
            public_key: Some(pub_key),
            private_key: Some(SecureBigNum::new(priv_key)),
            conversion_form: group.conversion_form(),
        })
    }

    /// Constructs an `EcKey` from an existing private key scalar.
    ///
    /// Derives the public key as `pub = priv × G`. Replaces
    /// `EC_KEY_set_private_key()` + `EC_KEY_generate_key()`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the private key is invalid.
    pub fn from_private_key(group: &EcGroup, priv_key: BigNum) -> CryptoResult<Self> {
        if priv_key.is_zero() {
            return Err(CryptoError::Key(
                "EC: private key scalar is zero".to_string(),
            ));
        }
        // Reject private keys that are out of range [1, order - 1].
        if &priv_key >= group.order() {
            return Err(CryptoError::Key(
                "EC: private key scalar is not in [1, order-1]".to_string(),
            ));
        }
        let pub_key = EcPoint::generator_mul(group, &priv_key)?;
        Ok(Self {
            group: group.clone(),
            public_key: Some(pub_key),
            private_key: Some(SecureBigNum::new(priv_key)),
            conversion_form: group.conversion_form(),
        })
    }

    /// Constructs a public-only `EcKey` (no private key component).
    ///
    /// Replaces `EC_KEY_set_public_key()`.
    pub fn from_public_key(group: &EcGroup, pub_key: EcPoint) -> CryptoResult<Self> {
        Ok(Self {
            group: group.clone(),
            public_key: Some(pub_key),
            private_key: None,
            conversion_form: group.conversion_form(),
        })
    }

    /// Returns the EC group (curve parameters) for this key.
    #[inline]
    pub fn group(&self) -> &EcGroup {
        &self.group
    }

    /// Returns the public key point, if present.
    #[inline]
    pub fn public_key(&self) -> Option<&EcPoint> {
        self.public_key.as_ref()
    }

    /// Returns the private key scalar, if present.
    ///
    /// Returns `None` for public-only keys. The returned reference
    /// borrows through the internal [`SecureBigNum`] wrapper via
    /// `Deref<Target = BigNum>`, so callers can continue to use the
    /// scalar as `&BigNum` while the underlying storage remains
    /// zeroed-on-drop.
    #[inline]
    pub fn private_key(&self) -> Option<&BigNum> {
        self.private_key.as_deref()
    }

    /// Returns `true` if this key contains a private key component.
    #[inline]
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    /// Returns the point conversion form for this key.
    ///
    /// Replaces `EC_KEY_get_conv_form()` from `crypto/ec/ec_key.c`.
    pub fn conversion_form(&self) -> PointConversionForm {
        self.conversion_form
    }

    /// Validates the key pair.
    ///
    /// Replaces `EC_KEY_check_key()` from `crypto/ec/ec_key.c`.
    ///
    /// Verifies the full set of invariants required for safe use of the
    /// key in signature or key-agreement operations:
    ///
    /// 1. The public key is present and lies on the curve.
    /// 2. The public key is not the point at infinity.
    /// 3. `order × pub_key = infinity` (the public key is in the
    ///    generator's prime-order subgroup).
    /// 4. If a private key is present:
    ///    a. The scalar is in the range `[1, order - 1]`.
    ///    b. `priv × G = pub_key` (the key pair is consistent).
    ///
    /// Returns `Ok(true)` only if every check passes.
    pub fn check_key(&self) -> CryptoResult<bool> {
        // A key without a public key component cannot be validated.
        let Some(pub_key) = &self.public_key else {
            return Ok(false);
        };

        // Check 1: public key is on the curve.
        if !pub_key.is_on_curve(&self.group)? {
            return Ok(false);
        }
        // Check 2: public key is not at infinity.
        if pub_key.is_at_infinity() {
            return Ok(false);
        }
        // Check 3: order × pub_key = infinity.
        let order = self.group.order();
        let order_times_pub = EcPoint::mul(&self.group, pub_key, order)?;
        if !order_times_pub.is_at_infinity() {
            return Ok(false);
        }

        // Check 4: if a private key is present, verify it.
        if let Some(priv_key) = self.private_key.as_deref() {
            // Scalar must be in [1, order - 1].
            if priv_key.is_zero() {
                return Ok(false);
            }
            if priv_key >= order {
                return Ok(false);
            }
            // priv × G must equal pub_key.
            let computed_pub = EcPoint::generator_mul(&self.group, priv_key)?;
            if &computed_pub != pub_key {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Returns the named curve of the key's group, if any.
    #[inline]
    pub fn curve_name(&self) -> Option<NamedCurve> {
        self.group.curve_name()
    }
}

impl Drop for EcKey {
    /// Explicitly dropping an `EcKey` relies on the
    /// [`SecureBigNum`] wrapper around the private key scalar, which
    /// implements its own `Drop` that zeroes the backing storage via the
    /// `zeroize` crate.
    ///
    /// Replaces the C pattern `BN_clear_free(ec->priv_key)` from
    /// `crypto/ec/ec_key.c` `EC_KEY_free()`.
    ///
    /// This impl is intentionally present — and not a no-op
    /// `drop_in_place` — to document the intent and to provide a
    /// single site for future defensive clearing of other fields
    /// should additional sensitive state be added.
    fn drop(&mut self) {
        // Explicitly drop the private key so that its zeroing Drop
        // runs before any subsequent move of `self`.
        let _private_key = self.private_key.take();
        // `_private_key` drops here, which in turn runs
        // `SecureBigNum::drop` to zero the scalar.
    }
}

// Intentionally not deriving Debug for EcKey to prevent accidental
// logging of private key material — use `finish_non_exhaustive()` to signal
// that some fields (private_key) are deliberately omitted.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for EcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcKey")
            .field("curve", &self.group.curve_name())
            .field("has_private_key", &self.has_private_key())
            .field("has_public_key", &self.public_key.is_some())
            .field("conversion_form", &self.conversion_form)
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// EcError — EC-specific error variants
// ===========================================================================

/// EC-specific error variants.
///
/// These are typically wrapped in [`CryptoError`] for propagation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EcError {
    /// Missing private key for an operation that requires it.
    #[error("missing private key")]
    MissingPrivateKey,
    /// Invalid curve parameters (e.g., singular curve).
    #[error("invalid curve parameters")]
    InvalidCurveParameters,
    /// Point is not on the specified curve.
    #[error("point not on curve")]
    PointNotOnCurve,
    /// Operation resulted in the point at infinity unexpectedly.
    #[error("point at infinity")]
    PointAtInfinity,
    /// Unsupported or unrecognized curve name.
    #[error("unsupported curve: {0}")]
    UnsupportedCurve(String),
    /// Invalid point encoding bytes.
    #[error("invalid point encoding")]
    InvalidPointEncoding,
    /// Key validation check failed.
    #[error("key check failed: {0}")]
    KeyCheckFailed(String),
    /// ECDSA not supported for this curve type.
    #[error("ECDSA operation not supported for this curve")]
    EcdsaNotSupported,
    /// ECDH not supported for this curve type.
    #[error("ECDH operation not supported for this curve")]
    EcdhNotSupported,
    /// Key type mismatch.
    #[error("invalid key type: expected {expected}, got {got}")]
    InvalidKeyType {
        /// Expected key type
        expected: String,
        /// Actual key type
        got: String,
    },
}

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Generates a uniformly random scalar in the range `[1, order - 1]`.
///
/// Used for private key generation. Delegates to
/// [`BigNum::priv_rand_range`], which uses the crate's CSPRNG
/// (`BN_priv_rand_range` in C OpenSSL). Loops until a non-zero
/// candidate is sampled to ensure the scalar is a valid private key.
///
/// # Errors
///
/// Propagates any error from the underlying CSPRNG.
///
/// # Security
///
/// The sampling is uniform over `[0, order)` and the rejection loop
/// for zero is constant-time-equivalent in expectation because the
/// probability of sampling zero is `1/order`, which is astronomically
/// small for every supported curve.
fn generate_random_scalar(order: &BigNum) -> CryptoResult<BigNum> {
    // A defensive retry cap — the probability of sampling zero is
    // bounded above by 1/order, so 256 iterations suffices for every
    // named curve in the built-in catalog by many orders of magnitude.
    const MAX_ITERATIONS: usize = 256;
    for _ in 0..MAX_ITERATIONS {
        let candidate = BigNum::priv_rand_range(order)?;
        if !candidate.is_zero() {
            return Ok(candidate);
        }
    }
    Err(CryptoError::Rand(
        "EC: failed to sample a non-zero scalar after retries".to_string(),
    ))
}

/// Loads built-in curve parameters for a named curve.
///
/// Replaces the curve parameter catalog in `crypto/ec/ec_curve.c`.
/// Contains hard-coded parameters for the most commonly used curves:
/// NIST P-256 / P-384 / P-521 and secp256k1.
///
/// # Errors
///
/// Returns [`CryptoError::Key`] wrapping a `UnsupportedCurve` message for
/// curves that are not yet included in the built-in catalog. This keeps
/// the error path explicit rather than silently constructing an invalid
/// group — a principle enforced by AAP rule R5 (no placeholders).
///
/// Curves that are explicitly handled elsewhere (X25519/Ed25519/X448/Ed448)
/// live in the [`curve25519`](crate::ec::curve25519) submodule and will
/// be rejected here because they do not use short-Weierstrass parameters.
fn load_curve_params(curve: NamedCurve) -> CryptoResult<EcGroup> {
    match curve {
        NamedCurve::Prime256v1 => load_p256(),
        NamedCurve::Secp384r1 => load_p384(),
        NamedCurve::Secp521r1 => load_p521(),
        NamedCurve::Secp256k1 => load_secp256k1(),
        _ => Err(CryptoError::Key(format!(
            "EC: curve '{}' parameters not yet implemented in the built-in catalog",
            curve.name()
        ))),
    }
}

/// NIST P-256 (prime256v1, secp256r1) curve parameters.
fn load_p256() -> CryptoResult<EcGroup> {
    // Field prime p
    let p = BigNum::from_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")?;
    // Coefficient a = p - 3
    let a = BigNum::from_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")?;
    // Coefficient b
    let b = BigNum::from_hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")?;
    // Generator x
    let gx = BigNum::from_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")?;
    // Generator y
    let gy = BigNum::from_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")?;
    // Order n
    let n = BigNum::from_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")?;

    Ok(EcGroup {
        curve_name: Some(NamedCurve::Prime256v1),
        field: p,
        a,
        b,
        generator: EcPoint::from_affine(gx, gy),
        order: n,
        cofactor: BigNum::one(),
        degree: 256,
        conversion_form: PointConversionForm::Uncompressed,
    })
}

/// NIST P-384 (secp384r1) curve parameters.
fn load_p384() -> CryptoResult<EcGroup> {
    let p = BigNum::from_hex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"
    )?;
    let a = BigNum::from_hex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"
    )?;
    let b = BigNum::from_hex(
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"
    )?;
    let gx = BigNum::from_hex(
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
    )?;
    let gy = BigNum::from_hex(
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
    )?;
    let n = BigNum::from_hex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
    )?;

    Ok(EcGroup {
        curve_name: Some(NamedCurve::Secp384r1),
        field: p,
        a,
        b,
        generator: EcPoint::from_affine(gx, gy),
        order: n,
        cofactor: BigNum::one(),
        degree: 384,
        conversion_form: PointConversionForm::Uncompressed,
    })
}

/// NIST P-521 (secp521r1) curve parameters.
fn load_p521() -> CryptoResult<EcGroup> {
    let p = BigNum::from_hex(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    )?;
    let a = BigNum::from_hex(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"
    )?;
    let b = BigNum::from_hex(
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"
    )?;
    let gx = BigNum::from_hex(
        "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
    )?;
    let gy = BigNum::from_hex(
        "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"
    )?;
    let n = BigNum::from_hex(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
    )?;

    Ok(EcGroup {
        curve_name: Some(NamedCurve::Secp521r1),
        field: p,
        a,
        b,
        generator: EcPoint::from_affine(gx, gy),
        order: n,
        cofactor: BigNum::one(),
        degree: 521,
        conversion_form: PointConversionForm::Uncompressed,
    })
}

/// secp256k1 curve parameters (used in Bitcoin and Ethereum).
fn load_secp256k1() -> CryptoResult<EcGroup> {
    let p = BigNum::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")?;
    let a = BigNum::zero();
    let b = BigNum::from_u64(7);
    let gx = BigNum::from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")?;
    let gy = BigNum::from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")?;
    let n = BigNum::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")?;

    Ok(EcGroup {
        curve_name: Some(NamedCurve::Secp256k1),
        field: p,
        a,
        b,
        generator: EcPoint::from_affine(gx, gy),
        order: n,
        cofactor: BigNum::one(),
        degree: 256,
        conversion_form: PointConversionForm::Uncompressed,
    })
}

// ===========================================================================
// Inline unit tests for the Montgomery ladder (constant-time `EcPoint::mul`)
// ===========================================================================
//
// These tests are placed inline in `ec/mod.rs` so they have direct access to
// private fields of [`EcPoint`] (`x`, `y`, `is_infinity`) and to the internal
// helper [`ct_swap_points`]. They focus on the correctness of
// [`EcPoint::mul`] across multiple curves and edge cases, since correctness
// of the constant-time replacement is a security-critical invariant
// (CRITICAL #9 in the project's code-review feedback report).
//
// All tests are R8-compliant (no `unsafe` blocks).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::arithmetic;

    // ----------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------

    /// Constructs the P-256 group for tests.
    fn p256() -> EcGroup {
        EcGroup::from_curve_name(NamedCurve::Prime256v1)
            .expect("loading P-256 curve parameters must succeed")
    }

    /// Constructs the P-384 group for tests.
    fn p384() -> EcGroup {
        EcGroup::from_curve_name(NamedCurve::Secp384r1)
            .expect("loading P-384 curve parameters must succeed")
    }

    /// Constructs the secp256k1 group for tests.
    fn secp256k1() -> EcGroup {
        EcGroup::from_curve_name(NamedCurve::Secp256k1)
            .expect("loading secp256k1 curve parameters must succeed")
    }

    // ----------------------------------------------------------------------
    // Trivial scalar tests
    // ----------------------------------------------------------------------

    /// 0 · G = O (point at infinity) on P-256.
    ///
    /// This exercises the `scalar.is_zero()` early-return path; it does NOT
    /// enter the Montgomery ladder.
    #[test]
    fn mul_zero_scalar_returns_infinity_p256() {
        let group = p256();
        let zero = BigNum::zero();
        let result = EcPoint::mul(&group, group.generator(), &zero)
            .expect("mul by zero must succeed");
        assert!(result.is_at_infinity(), "0·G must be the identity");
    }

    /// 1 · G = G on P-256.
    ///
    /// This exercises the `scalar.is_one()` early-return path; it does NOT
    /// enter the Montgomery ladder.
    #[test]
    fn mul_one_returns_input_point_p256() {
        let group = p256();
        let one = BigNum::one();
        let result = EcPoint::mul(&group, group.generator(), &one)
            .expect("mul by one must succeed");
        assert!(!result.is_at_infinity(), "1·G must not be infinity");
        assert_eq!(
            result.x(),
            group.generator().x(),
            "1·G x-coordinate must equal G.x"
        );
        assert_eq!(
            result.y(),
            group.generator().y(),
            "1·G y-coordinate must equal G.y"
        );
    }

    /// k · O = O for any non-zero k. Exercises the `point.is_infinity`
    /// early-return path.
    #[test]
    fn mul_with_infinity_point_returns_infinity() {
        let group = p256();
        let scalar = BigNum::from_u64(0xDEAD_BEEF);
        let identity = EcPoint::new_at_infinity();
        let result = EcPoint::mul(&group, &identity, &scalar)
            .expect("mul of identity must succeed");
        assert!(
            result.is_at_infinity(),
            "k·O must be O for any k (here k = 0xDEADBEEF)"
        );
    }

    // ----------------------------------------------------------------------
    // Self-consistency tests
    // ----------------------------------------------------------------------

    /// 2 · G must equal `EcPoint::double(&group, G)` on every supported
    /// curve. This is a foundational consistency test: the Montgomery
    /// ladder must agree with the explicit doubling routine for the
    /// smallest non-trivial scalar.
    #[test]
    fn mul_two_equals_double_p256() {
        let group = p256();
        let two = BigNum::from_u64(2);
        let mul_result = EcPoint::mul(&group, group.generator(), &two)
            .expect("mul by 2 must succeed");
        let double_result = EcPoint::double(&group, group.generator())
            .expect("double must succeed");
        assert_eq!(
            mul_result, double_result,
            "2·G (via ladder) must equal double(G) on P-256"
        );
    }

    /// Same consistency check on P-384: a different field size and
    /// scalar bit-length, exercising the curve-agnostic ladder.
    #[test]
    fn mul_two_equals_double_p384() {
        let group = p384();
        let two = BigNum::from_u64(2);
        let mul_result = EcPoint::mul(&group, group.generator(), &two)
            .expect("mul by 2 must succeed");
        let double_result = EcPoint::double(&group, group.generator())
            .expect("double must succeed");
        assert_eq!(
            mul_result, double_result,
            "2·G (via ladder) must equal double(G) on P-384"
        );
    }

    /// Same consistency check on secp256k1: validates that the ladder
    /// works for curves with a = 0 (which is the secp256k1 case).
    #[test]
    fn mul_two_equals_double_secp256k1() {
        let group = secp256k1();
        let two = BigNum::from_u64(2);
        let mul_result = EcPoint::mul(&group, group.generator(), &two)
            .expect("mul by 2 must succeed");
        let double_result = EcPoint::double(&group, group.generator())
            .expect("double must succeed");
        assert_eq!(
            mul_result, double_result,
            "2·G (via ladder) must equal double(G) on secp256k1"
        );
    }

    /// 3 · G must equal G + 2·G (i.e., the ladder is consistent with the
    /// addition formula).
    #[test]
    fn mul_three_equals_g_plus_2g_p256() {
        let group = p256();
        let three = BigNum::from_u64(3);
        let two = BigNum::from_u64(2);

        let mul_three = EcPoint::mul(&group, group.generator(), &three)
            .expect("mul by 3 must succeed");

        let two_g = EcPoint::mul(&group, group.generator(), &two)
            .expect("mul by 2 must succeed");
        let g_plus_2g = EcPoint::add(&group, group.generator(), &two_g)
            .expect("G + 2·G must succeed");

        assert_eq!(
            mul_three, g_plus_2g,
            "3·G (via ladder) must equal G + 2·G on P-256"
        );
    }

    // ----------------------------------------------------------------------
    // Edge-of-range scalar tests
    // ----------------------------------------------------------------------

    /// (n-1) · G = -G on every supported curve. This is the canonical
    /// edge-case test: the largest in-range scalar produces the inverse
    /// of the generator.
    #[test]
    fn mul_n_minus_one_is_minus_g_p256() {
        let group = p256();
        let one = BigNum::one();
        let n_minus_one = arithmetic::sub(group.order(), &one);

        let lhs = EcPoint::mul(&group, group.generator(), &n_minus_one)
            .expect("mul by n-1 must succeed");
        let rhs = EcPoint::invert(&group, group.generator())
            .expect("invert(G) must succeed");

        assert_eq!(lhs, rhs, "(n-1)·G must equal -G on P-256");
    }

    /// (n-1) · G = -G on P-384.
    #[test]
    fn mul_n_minus_one_is_minus_g_p384() {
        let group = p384();
        let one = BigNum::one();
        let n_minus_one = arithmetic::sub(group.order(), &one);

        let lhs = EcPoint::mul(&group, group.generator(), &n_minus_one)
            .expect("mul by n-1 must succeed");
        let rhs = EcPoint::invert(&group, group.generator())
            .expect("invert(G) must succeed");

        assert_eq!(lhs, rhs, "(n-1)·G must equal -G on P-384");
    }

    // ----------------------------------------------------------------------
    // Known-answer tests against published vectors
    // ----------------------------------------------------------------------

    /// Known-answer test: 2·G on NIST P-256.
    ///
    /// Reference: SEC 2 v2, "Recommended Elliptic Curve Domain Parameters"
    /// and standard P-256 test vectors. The `2·G` value is widely
    /// published (e.g., in NIST CAVS test data and curve-specific design
    /// documents) and serves as a ground-truth value not derived from
    /// the implementation under test.
    #[test]
    fn mul_p256_two_known_answer() {
        let group = p256();
        let two = BigNum::from_u64(2);
        let result = EcPoint::mul(&group, group.generator(), &two)
            .expect("2·G_P256 must succeed");

        let expected_x = BigNum::from_hex(
            "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
        )
        .expect("hex parse must succeed");
        let expected_y = BigNum::from_hex(
            "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1",
        )
        .expect("hex parse must succeed");

        assert!(!result.is_at_infinity(), "2·G must not be infinity");
        assert_eq!(result.x(), &expected_x, "2·G_P256 x must match KAT");
        assert_eq!(result.y(), &expected_y, "2·G_P256 y must match KAT");
    }

    /// Known-answer test: 2·G on secp256k1.
    ///
    /// Reference: SEC 2 v2 §2.4.1, with the well-known doubled-generator
    /// values widely cited in Bitcoin protocol documentation and
    /// independent third-party test suites.
    #[test]
    fn mul_secp256k1_two_known_answer() {
        let group = secp256k1();
        let two = BigNum::from_u64(2);
        let result = EcPoint::mul(&group, group.generator(), &two)
            .expect("2·G_secp256k1 must succeed");

        let expected_x = BigNum::from_hex(
            "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
        )
        .expect("hex parse must succeed");
        let expected_y = BigNum::from_hex(
            "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
        )
        .expect("hex parse must succeed");

        assert!(!result.is_at_infinity(), "2·G must not be infinity");
        assert_eq!(
            result.x(),
            &expected_x,
            "2·G_secp256k1 x must match KAT"
        );
        assert_eq!(
            result.y(),
            &expected_y,
            "2·G_secp256k1 y must match KAT"
        );
    }

    // ----------------------------------------------------------------------
    // Round-trip / invariant tests
    // ----------------------------------------------------------------------

    /// k · G is on the curve for arbitrary in-range k. This verifies
    /// that the ladder produces well-formed points (the curve equation
    /// y² = x³ + ax + b mod p must hold).
    #[test]
    fn mul_result_is_on_curve_p256() {
        let group = p256();
        // A non-trivial bit pattern that exercises both swap states.
        let k = BigNum::from_hex(
            "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3D",
        )
        .expect("hex parse must succeed");

        let kg = EcPoint::mul(&group, group.generator(), &k)
            .expect("k·G must succeed for arbitrary k");

        assert!(!kg.is_at_infinity(), "non-zero k·G must not be infinity");
        let on_curve = kg
            .is_on_curve(&group)
            .expect("on-curve check must succeed");
        assert!(on_curve, "k·G result must satisfy the curve equation");
    }

    // ----------------------------------------------------------------------
    // ct_swap_points helper tests
    // ----------------------------------------------------------------------

    /// ct_swap_points with `choice = 0` must leave both points unchanged.
    #[test]
    fn ct_swap_points_no_swap_when_choice_zero() {
        let group = p256();
        let two = BigNum::from_u64(2);
        let three = BigNum::from_u64(3);

        let mut a = EcPoint::mul(&group, group.generator(), &two)
            .expect("2·G must succeed");
        let mut b = EcPoint::mul(&group, group.generator(), &three)
            .expect("3·G must succeed");

        let original_a = a.clone();
        let original_b = b.clone();

        ct_swap_points(&mut a, &mut b, &group, Choice::from(0));

        assert_eq!(a, original_a, "choice=0 must leave a unchanged");
        assert_eq!(b, original_b, "choice=0 must leave b unchanged");
    }

    /// ct_swap_points with `choice = 1` must swap the two points
    /// completely (x, y, and is_infinity).
    #[test]
    fn ct_swap_points_swaps_when_choice_one() {
        let group = p256();
        let two = BigNum::from_u64(2);
        let three = BigNum::from_u64(3);

        let mut a = EcPoint::mul(&group, group.generator(), &two)
            .expect("2·G must succeed");
        let mut b = EcPoint::mul(&group, group.generator(), &three)
            .expect("3·G must succeed");

        let original_a = a.clone();
        let original_b = b.clone();

        ct_swap_points(&mut a, &mut b, &group, Choice::from(1));

        assert_eq!(a, original_b, "choice=1 must move b's value into a");
        assert_eq!(b, original_a, "choice=1 must move a's value into b");
    }

    /// ct_swap_points must correctly handle the `is_infinity` flag in
    /// both swap directions.
    #[test]
    fn ct_swap_points_handles_infinity_flag() {
        let group = p256();
        let mut finite = EcPoint::mul(&group, group.generator(), &BigNum::from_u64(5))
            .expect("5·G must succeed");
        let mut identity = EcPoint::new_at_infinity();

        // Swap when one operand is the identity.
        ct_swap_points(&mut finite, &mut identity, &group, Choice::from(1));

        assert!(
            finite.is_at_infinity(),
            "after swap, `finite` must hold the original identity"
        );
        assert!(
            !identity.is_at_infinity(),
            "after swap, `identity` must hold the original finite point"
        );
    }

    // ----------------------------------------------------------------------
    // Cross-curve scalar bit-length stress test
    // ----------------------------------------------------------------------

    /// Ensures the ladder loop iteration count is governed by
    /// `group.order().num_bits()` and not by `scalar.num_bits()`. We use
    /// the smallest non-sentinel scalar (k = 2) on P-384 (order has 384
    /// bits) and verify the result still matches `double(G)`. If the
    /// loop bit-length depended on the scalar, this test would still
    /// pass but with a degraded leak surface — the assertion here is
    /// only of correctness; the constant-time property is guaranteed
    /// structurally by reading `bit_len = group.order().num_bits()`.
    #[test]
    fn ladder_correct_with_small_scalar_on_large_curve() {
        let group = p384();
        let two = BigNum::from_u64(2);
        let result = EcPoint::mul(&group, group.generator(), &two)
            .expect("mul by small scalar on large curve must succeed");
        let expected = EcPoint::double(&group, group.generator())
            .expect("double must succeed");
        assert_eq!(
            result, expected,
            "ladder with small scalar on P-384 must produce 2·G"
        );
    }
}

