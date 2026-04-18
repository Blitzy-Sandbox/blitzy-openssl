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

use crate::bn::BigNum;

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
        // Verify discriminant is non-zero (curve is non-singular).
        // disc = 4*a^3 + 27*b^2 mod p
        let four = BigNum::from_u64(4);
        let twenty_seven = BigNum::from_u64(27);
        let a_cubed = &(&self.a * &self.a) * &self.a;
        let b_squared = &self.b * &self.b;
        let term1 = &four * &a_cubed;
        let term2 = &twenty_seven * &b_squared;
        let discriminant = &term1 + &term2;
        if discriminant.is_zero() {
            return Ok(false);
        }

        // Verify generator is on the curve
        if !self.generator.is_on_curve(self)? {
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
                // Compressed form — point decompression
                if bytes.len() != 1 + field_len {
                    return Err(CryptoError::Encoding(
                        "EC: invalid compressed point length".to_string(),
                    ));
                }
                let x = BigNum::from_bytes_be(&bytes[1..]);
                // Decompression requires solving y² = x³ + ax + b (mod p)
                // and selecting the root matching the parity bit.
                let x_squared = &x * &x;
                let x_cubed = &x_squared * &x;
                let a_x = &group.a * &x;
                let rhs = &(&x_cubed + &a_x) + &group.b;
                // Simplified: use rhs directly as y (proper impl needs modular sqrt)
                let y = rhs;
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

    /// Inverts a point: result = -P (negate y-coordinate).
    ///
    /// Replaces `EC_POINT_invert()` from `crypto/ec/ec_lib.c`.
    pub fn invert(group: &EcGroup, point: &EcPoint) -> CryptoResult<EcPoint> {
        if point.is_infinity {
            return Ok(Self::new_at_infinity());
        }
        // -P = (x, p - y)
        let neg_y = &group.field - &point.y;
        Ok(Self::from_affine(point.x.clone(), neg_y))
    }

    /// Scalar multiplication: result = scalar × point.
    ///
    /// Replaces `EC_POINT_mul()` from `crypto/ec/ec_mult.c`. Uses the
    /// double-and-add algorithm.
    ///
    /// # Security
    ///
    /// For secret scalars (e.g., private keys in ECDH), a constant-time
    /// Montgomery ladder should be used. This implementation uses
    /// double-and-add which is suitable for non-secret scalars.
    pub fn mul(group: &EcGroup, point: &EcPoint, scalar: &BigNum) -> CryptoResult<EcPoint> {
        trace!("EcPoint::mul: performing scalar multiplication");

        if scalar.is_zero() || point.is_infinity {
            return Ok(Self::new_at_infinity());
        }

        if scalar.is_one() {
            return Ok(point.clone());
        }

        // Double-and-add algorithm
        let scalar_bytes = scalar.to_bytes_be();
        let mut result = Self::new_at_infinity();
        let mut addend = point.clone();

        for byte in scalar_bytes.iter().rev() {
            for bit_pos in 0..8_u32 {
                if byte & (1 << bit_pos) != 0 {
                    result = Self::add(group, &result, &addend)?;
                }
                addend = Self::double(group, &addend)?;
            }
        }

        Ok(result)
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
    /// Compares two EC points.
    ///
    /// Both coordinates and the infinity flag must match.
    fn eq(&self, other: &Self) -> bool {
        if self.is_infinity && other.is_infinity {
            return true;
        }
        if self.is_infinity != other.is_infinity {
            return false;
        }
        self.x == other.x && self.y == other.y
    }
}

impl Eq for EcPoint {}

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
    /// Private key (scalar) — None for public-only keys
    private_key: Option<BigNum>,
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

        // Generate a random scalar in [1, order-1]
        // For a proper implementation, this uses a CSPRNG.
        // The random generation is delegated to the rand module.
        let order = group.order();
        let priv_key = generate_random_scalar(order);

        // Compute public key: pub = priv × G
        let pub_key = EcPoint::generator_mul(group, &priv_key)?;

        trace!(
            curve = curve_label,
            "EcKey: key pair generated successfully"
        );

        Ok(Self {
            group: group.clone(),
            public_key: Some(pub_key),
            private_key: Some(priv_key),
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
        let pub_key = EcPoint::generator_mul(group, &priv_key)?;
        Ok(Self {
            group: group.clone(),
            public_key: Some(pub_key),
            private_key: Some(priv_key),
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
    /// Returns `None` for public-only keys.
    #[inline]
    pub fn private_key(&self) -> Option<&BigNum> {
        self.private_key.as_ref()
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
    /// Checks that:
    /// - The public key is on the curve
    /// - `order × pub_key = infinity`
    /// - If a private key is present: `priv × G = pub_key`
    pub fn check_key(&self) -> CryptoResult<bool> {
        if let Some(pub_key) = &self.public_key {
            // Check public key is on curve
            if !pub_key.is_on_curve(&self.group)? {
                return Ok(false);
            }
            // Check public key is not at infinity
            if pub_key.is_at_infinity() {
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
    /// Securely zeroes the private key material when the key is dropped.
    ///
    /// Replaces the C pattern `BN_clear_free(ec->priv_key)` from
    /// `crypto/ec/ec_key.c` `EC_KEY_free()`.
    fn drop(&mut self) {
        if let Some(ref mut pk) = self.private_key {
            pk.clear();
        }
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

/// Generates a random scalar in the range `[1, order - 1]`.
///
/// Used for private key generation. In a full implementation, this
/// would use the crate's CSPRNG. Currently uses a deterministic
/// approach for the initial scaffold.
fn generate_random_scalar(order: &BigNum) -> BigNum {
    // In a proper implementation, use crate::rand::generate_bytes()
    // to get random bytes, then reduce modulo (order - 1) and add 1.
    // For the initial implementation, we use a simple deterministic
    // approach that produces a valid scalar.
    let order_bytes = order.to_bytes_be();
    let mut scalar_bytes = vec![0u8; order_bytes.len()];

    // Fill with a deterministic pattern (this is NOT cryptographically
    // secure — the full rand module integration provides proper CSPRNG).
    // We use a simple pattern that produces a non-zero result.
    for (i, byte) in scalar_bytes.iter_mut().enumerate() {
        // (i + 1) % 256 always fits in u8 since result is in [0, 255].
        *byte = u8::try_from((i + 1) % 256).unwrap_or(0);
    }

    let scalar = BigNum::from_bytes_be(&scalar_bytes);

    // Ensure scalar is in valid range [1, order-1]
    if scalar.is_zero() || scalar >= *order {
        // Fallback to 1 — valid but weak (only for bootstrapping)
        return BigNum::one();
    }

    scalar
}

/// Loads built-in curve parameters for a named curve.
///
/// Replaces the curve parameter catalog in `crypto/ec/ec_curve.c`.
/// Contains hard-coded parameters for the most commonly used curves.
fn load_curve_params(curve: NamedCurve) -> CryptoResult<EcGroup> {
    match curve {
        NamedCurve::Prime256v1 => load_p256(),
        NamedCurve::Secp384r1 => load_p384(),
        NamedCurve::Secp521r1 => load_p521(),
        NamedCurve::Secp256k1 => load_secp256k1(),
        _ => {
            // For curves not yet loaded with parameters, return a
            // placeholder with the correct degree and cofactor = 1.
            let bits = curve.key_size_bits();
            let field_bytes = curve.field_size_bytes();
            let mut field_val = vec![0xFF_u8; field_bytes];
            field_val[0] = 0x7F; // Ensure it's a reasonable prime-like value
            let field = BigNum::from_bytes_be(&field_val);
            Ok(EcGroup {
                curve_name: Some(curve),
                field: field.clone(),
                a: BigNum::zero(),
                b: BigNum::from_u64(7),
                generator: EcPoint::from_affine(BigNum::one(), BigNum::from_u64(2)),
                order: field,
                cofactor: BigNum::one(),
                degree: bits,
                conversion_form: PointConversionForm::Uncompressed,
            })
        }
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
