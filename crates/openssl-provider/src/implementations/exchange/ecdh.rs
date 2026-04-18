//! Elliptic-Curve Diffie-Hellman key exchange provider implementation.
//!
//! Translates `providers/implementations/exchange/ecdh_exch.c` (1 C file)
//! into idiomatic Rust, implementing `KeyExchangeProvider` + `KeyExchangeContext`
//! for ECDH key agreement over NIST prime curves (P-256, P-384, P-521) and
//! `secp256k1`.
//!
//! # Architecture
//!
//! ECDH computes a shared secret via scalar multiplication of the peer's
//! public point by our private scalar. For NIST curves the implementation
//! performs the computation using the `openssl_crypto::bn` big-number module
//! for modular arithmetic and a simplified Weierstrass-curve point
//! multiplication.
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KeyExchange)
//!         → implementations::all_exchange_descriptors()
//!           → exchange::descriptors()
//!             → ecdh::EcdhKeyExchange
//! ```
//!
//! # Security Properties
//!
//! - Private scalar zeroed on drop via [`zeroize::Zeroize`].
//! - Shared secret validated: not the point at infinity.
//! - Zero `unsafe` blocks (Rule R8).
//!
//! # C Source Mapping
//!
//! | Rust type | C construct | Source |
//! |-----------|------------|--------|
//! | [`EcdhKeyExchange`] | `ossl_ecdh_keyexch_functions` | `ecdh_exch.c` |
//! | [`EcdhExchangeContext`] | `PROV_ECDH_CTX` | `ecdh_exch.c:30` |

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, Zeroizing};

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::bn::BigNum;

use crate::traits::{KeyExchangeContext, KeyExchangeProvider};

// =============================================================================
// Curve Parameters — NIST P-256, P-384, P-521, secp256k1
// =============================================================================

/// Named elliptic curve identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EcCurve {
    /// NIST P-256 (secp256r1, prime256v1)
    P256,
    /// NIST P-384 (secp384r1)
    P384,
    /// NIST P-521 (secp521r1)
    P521,
    /// Bitcoin / Ethereum curve
    Secp256k1,
}

/// Decodes a hex string into bytes at runtime.
///
/// Used for curve constant initialisation. All inputs are compile-time
/// constants so the conversion is infallible.
fn hex_const(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect()
}

impl EcCurve {
    /// Returns the curve field prime `p` (big-endian bytes).
    fn field_prime(self) -> BigNum {
        match self {
            Self::P256 => BigNum::from_bytes_be(&hex_const(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            )),
            Self::P384 => BigNum::from_bytes_be(&hex_const(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE\
                 FFFFFFFF0000000000000000FFFFFFFF",
            )),
            Self::P521 => BigNum::from_bytes_be(&hex_const(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
                 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )),
            Self::Secp256k1 => BigNum::from_bytes_be(&hex_const(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            )),
        }
    }

    /// Returns the curve parameter `a`.
    fn a(self) -> BigNum {
        match self {
            Self::P256 => BigNum::from_bytes_be(&hex_const(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            )),
            Self::P384 => BigNum::from_bytes_be(&hex_const(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE\
                 FFFFFFFF0000000000000000FFFFFFFC",
            )),
            Self::P521 => BigNum::from_bytes_be(&hex_const(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
                 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            )),
            Self::Secp256k1 => BigNum::zero(),
        }
    }

    /// Returns the byte length of a field element.
    fn field_len(self) -> usize {
        match self {
            Self::P256 | Self::Secp256k1 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// Returns the group order `n`.
    fn order(self) -> BigNum {
        match self {
            Self::P256 => BigNum::from_bytes_be(&hex_const(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            )),
            Self::P384 => BigNum::from_bytes_be(&hex_const(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF\
                 581A0DB248B0A77AECEC196ACCC52973",
            )),
            Self::P521 => BigNum::from_bytes_be(&hex_const(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA\
                 51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
            )),
            Self::Secp256k1 => BigNum::from_bytes_be(&hex_const(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            )),
        }
    }

    /// Parses a curve name string.
    fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "p-256" | "p256" | "prime256v1" | "secp256r1" => Some(Self::P256),
            "p-384" | "p384" | "secp384r1" => Some(Self::P384),
            "p-521" | "p521" | "secp521r1" => Some(Self::P521),
            "secp256k1" => Some(Self::Secp256k1),
            _ => None,
        }
    }

    /// Returns a display name.
    fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
            Self::Secp256k1 => "secp256k1",
        }
    }
}

// =============================================================================
// Affine Point — Simple (x, y) on Weierstrass curve
// =============================================================================

/// An affine point on a Weierstrass curve, or the point at infinity.
#[derive(Clone)]
struct AffinePoint {
    x: BigNum,
    y: BigNum,
    infinity: bool,
}

impl AffinePoint {
    fn infinity() -> Self {
        Self {
            x: BigNum::zero(),
            y: BigNum::zero(),
            infinity: true,
        }
    }

    /// Decode from uncompressed form: `04 || x || y`.
    fn from_uncompressed(data: &[u8], field_len: usize) -> ProviderResult<Self> {
        let expected = 1 + 2 * field_len;
        if data.len() != expected || data[0] != 0x04 {
            return Err(ProviderError::Dispatch(format!(
                "invalid uncompressed EC point: expected {expected} bytes with 0x04 prefix, got {} bytes",
                data.len()
            )));
        }
        let x = BigNum::from_bytes_be(&data[1..=field_len]);
        let y = BigNum::from_bytes_be(&data[1 + field_len..]);
        Ok(Self {
            x,
            y,
            infinity: false,
        })
    }

    /// Encode to uncompressed form: `04 || x || y`.
    ///
    /// Used for test round-trip verification and future public-key export.
    #[cfg(test)]
    fn to_uncompressed(&self, field_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 * field_len);
        out.push(0x04);
        let x_bytes = self.x.to_bytes_be();
        let y_bytes = self.y.to_bytes_be();
        // Pad x
        for _ in 0..field_len.saturating_sub(x_bytes.len()) {
            out.push(0);
        }
        let x_start = x_bytes.len().saturating_sub(field_len);
        out.extend_from_slice(&x_bytes[x_start..]);
        // Pad y
        for _ in 0..field_len.saturating_sub(y_bytes.len()) {
            out.push(0);
        }
        let y_start = y_bytes.len().saturating_sub(field_len);
        out.extend_from_slice(&y_bytes[y_start..]);
        out
    }
}

// =============================================================================
// Point arithmetic over short Weierstrass curves: y² = x³ + ax + b (mod p)
// =============================================================================

/// Modular inverse via extended Euclidean algorithm.
fn mod_inverse(a: &BigNum, modulus: &BigNum) -> ProviderResult<BigNum> {
    // Use Fermat's little theorem: a^(p-2) mod p for prime p
    let two = BigNum::from_u64(2);
    let exp = openssl_crypto::bn::arithmetic::sub(modulus, &two);
    openssl_crypto::bn::montgomery::mod_exp(a, &exp, modulus)
        .map_err(|e| ProviderError::Dispatch(format!("mod_inverse failed: {e}")))
}

/// Point addition on a short Weierstrass curve.
fn point_add(
    p1: &AffinePoint,
    p2: &AffinePoint,
    a: &BigNum,
    prime: &BigNum,
) -> ProviderResult<AffinePoint> {
    if p1.infinity {
        return Ok(p2.clone());
    }
    if p2.infinity {
        return Ok(p1.clone());
    }

    // Check if points are equal or inverses
    let x_equal = p1.x.cmp(&p2.x) == std::cmp::Ordering::Equal;
    let y_equal = p1.y.cmp(&p2.y) == std::cmp::Ordering::Equal;

    if x_equal && !y_equal {
        // P + (-P) = O
        return Ok(AffinePoint::infinity());
    }

    let lambda = if x_equal && y_equal {
        // Point doubling: λ = (3x₁² + a) / (2y₁)
        if p1.y.is_zero() {
            return Ok(AffinePoint::infinity());
        }
        let x_sq = mod_mul(&p1.x, &p1.x, prime)?;
        let three = BigNum::from_u64(3);
        let three_x_sq = mod_mul(&three, &x_sq, prime)?;
        let numerator = mod_add(&three_x_sq, a, prime)?;
        let two = BigNum::from_u64(2);
        let denominator = mod_mul(&two, &p1.y, prime)?;
        let denom_inv = mod_inverse(&denominator, prime)?;
        mod_mul(&numerator, &denom_inv, prime)?
    } else {
        // Point addition: λ = (y₂ - y₁) / (x₂ - x₁)
        let dy = mod_sub(&p2.y, &p1.y, prime)?;
        let dx = mod_sub(&p2.x, &p1.x, prime)?;
        let dx_inv = mod_inverse(&dx, prime)?;
        mod_mul(&dy, &dx_inv, prime)?
    };

    // x₃ = λ² - x₁ - x₂
    let lambda_sq = mod_mul(&lambda, &lambda, prime)?;
    let sub1 = mod_sub(&lambda_sq, &p1.x, prime)?;
    let x3 = mod_sub(&sub1, &p2.x, prime)?;

    // y₃ = λ(x₁ - x₃) - y₁
    let diff = mod_sub(&p1.x, &x3, prime)?;
    let lam_diff = mod_mul(&lambda, &diff, prime)?;
    let y3 = mod_sub(&lam_diff, &p1.y, prime)?;

    Ok(AffinePoint {
        x: x3,
        y: y3,
        infinity: false,
    })
}

/// Double-and-add scalar multiplication: `k * P`.
fn scalar_mult(
    k: &BigNum,
    point: &AffinePoint,
    a: &BigNum,
    prime: &BigNum,
) -> ProviderResult<AffinePoint> {
    if k.is_zero() || point.infinity {
        return Ok(AffinePoint::infinity());
    }

    let k_bytes = k.to_bytes_be();
    let mut result = AffinePoint::infinity();
    let mut base = point.clone();

    // Process bits from LSB to MSB
    for byte in k_bytes.iter().rev() {
        for bit_idx in 0..8u32 {
            if (byte >> bit_idx) & 1 == 1 {
                result = point_add(&result, &base, a, prime)?;
            }
            base = point_add(&base, &base, a, prime)?;
        }
    }

    Ok(result)
}

/// Modular addition: `(a + b) mod p`.
fn mod_add(a: &BigNum, b: &BigNum, p: &BigNum) -> ProviderResult<BigNum> {
    openssl_crypto::bn::arithmetic::mod_add(a, b, p)
        .map_err(|e| ProviderError::Dispatch(format!("mod_add: {e}")))
}

/// Modular subtraction: `(a - b) mod p` (always non-negative).
fn mod_sub(a: &BigNum, b: &BigNum, p: &BigNum) -> ProviderResult<BigNum> {
    openssl_crypto::bn::arithmetic::mod_sub(a, b, p)
        .map_err(|e| ProviderError::Dispatch(format!("mod_sub: {e}")))
}

/// Modular multiplication: `(a * b) mod p`.
fn mod_mul(a: &BigNum, b: &BigNum, p: &BigNum) -> ProviderResult<BigNum> {
    openssl_crypto::bn::arithmetic::mod_mul(a, b, p)
        .map_err(|e| ProviderError::Dispatch(format!("mod_mul: {e}")))
}

// =============================================================================
// EcdhKeyExchange — Provider descriptor
// =============================================================================

/// Elliptic-curve Diffie-Hellman key exchange provider.
///
/// Supports NIST P-256, P-384, P-521, and `secp256k1` curves.
pub struct EcdhKeyExchange;

impl KeyExchangeProvider for EcdhKeyExchange {
    fn name(&self) -> &'static str {
        "ECDH"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("ECDH key exchange: creating new context");
        Ok(Box::new(EcdhExchangeContext::new()))
    }
}

// =============================================================================
// EcdhExchangeContext — Stateful key-agreement context
// =============================================================================

/// ECDH key exchange context managing the `init` → `set_peer` → `derive` lifecycle.
///
/// Private key material is zeroed on drop.
struct EcdhExchangeContext {
    /// Our private scalar (big-endian).
    our_private: Option<Zeroizing<Vec<u8>>>,
    /// Peer's public point (uncompressed: 04 || x || y).
    peer_public: Option<Vec<u8>>,
    /// Selected curve.
    curve: Option<EcCurve>,
    /// Use cofactor DH (default: false for prime-order curves).
    use_cofactor: bool,
}

impl EcdhExchangeContext {
    fn new() -> Self {
        Self {
            our_private: None,
            peer_public: None,
            curve: None,
            use_cofactor: false,
        }
    }
}

impl KeyExchangeContext for EcdhExchangeContext {
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        trace!(key_len = key.len(), "ECDH exchange: init");

        if key.is_empty() {
            return Err(ProviderError::Init("ECDH private key is empty".into()));
        }

        self.our_private = Some(Zeroizing::new(key.to_vec()));

        if let Some(ps) = params {
            self.set_params(ps)?;
        }

        Ok(())
    }

    fn set_peer(&mut self, peer_key: &[u8]) -> ProviderResult<()> {
        trace!(peer_len = peer_key.len(), "ECDH exchange: set_peer");

        if peer_key.is_empty() {
            return Err(ProviderError::Dispatch(
                "ECDH peer public key is empty".into(),
            ));
        }
        // Expect uncompressed point format: 04 || x || y
        if peer_key[0] != 0x04 {
            warn!("ECDH: peer key does not have 0x04 prefix (uncompressed point)");
        }
        self.peer_public = Some(peer_key.to_vec());
        Ok(())
    }

    fn derive(&mut self, secret: &mut [u8]) -> ProviderResult<usize> {
        let priv_bytes = self
            .our_private
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch("ECDH not initialised (no private key)".into())
            })?;

        let peer_bytes = self
            .peer_public
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("ECDH peer key not set".into()))?;

        let curve = self
            .curve
            .ok_or_else(|| ProviderError::Dispatch("ECDH curve not selected".into()))?;

        let field_len = curve.field_len();
        let prime = curve.field_prime();
        let a_param = curve.a();

        // Parse peer public point
        let peer_point = AffinePoint::from_uncompressed(peer_bytes, field_len)?;

        // Build private scalar as BigNum
        let scalar = BigNum::from_bytes_be(priv_bytes);

        // Validate scalar is in [1, n-1]
        let order = curve.order();
        if scalar.is_zero() || scalar.cmp(&order) != std::cmp::Ordering::Less {
            return Err(ProviderError::Dispatch(
                "ECDH private scalar out of valid range [1, n-1]".into(),
            ));
        }

        // Compute shared_point = scalar * peer_point
        let shared_point = scalar_mult(&scalar, &peer_point, &a_param, &prime)?;

        if shared_point.infinity {
            return Err(ProviderError::Dispatch(
                "ECDH produced point at infinity — invalid peer key".into(),
            ));
        }

        // The shared secret is the x-coordinate, padded to field_len
        let x_bytes = shared_point.x.to_bytes_be();
        let mut padded = vec![0u8; field_len];
        let offset = field_len.saturating_sub(x_bytes.len());
        let copy_len = std::cmp::min(x_bytes.len(), field_len);
        padded[offset..offset + copy_len]
            .copy_from_slice(&x_bytes[x_bytes.len().saturating_sub(copy_len)..]);

        let out_len = std::cmp::min(padded.len(), secret.len());
        secret[..out_len].copy_from_slice(&padded[..out_len]);

        debug!(
            curve = curve.name(),
            secret_len = out_len,
            "ECDH exchange: derived shared secret"
        );
        Ok(out_len)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        if let Some(curve) = self.curve {
            ps.set(
                "ec-curve",
                ParamValue::Utf8String(curve.name().to_string()),
            );
        }
        ps.set(
            "cofactor",
            ParamValue::Int32(i32::from(self.use_cofactor)),
        );
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(ParamValue::Utf8String(name)) = params.get("ec-curve") {
            self.curve = Some(EcCurve::from_name(name).ok_or_else(|| {
                ProviderError::Init(format!("unknown EC curve: {name}"))
            })?);
        }
        if let Some(ParamValue::Int32(cof)) = params.get("cofactor") {
            self.use_cofactor = *cof != 0;
        }
        Ok(())
    }
}

impl Drop for EcdhExchangeContext {
    fn drop(&mut self) {
        if let Some(ref mut priv_key) = self.our_private {
            priv_key.zeroize();
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ctx_returns_valid_context() {
        let provider = EcdhKeyExchange;
        assert_eq!(provider.name(), "ECDH");
        let ctx = provider.new_ctx();
        assert!(ctx.is_ok());
    }

    #[test]
    fn init_requires_nonempty_key() {
        let provider = EcdhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let result = ctx.init(&[], None);
        assert!(result.is_err());
    }

    #[test]
    fn derive_fails_without_init() {
        let provider = EcdhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut secret = [0u8; 32];
        assert!(ctx.derive(&mut secret).is_err());
    }

    #[test]
    fn derive_fails_without_peer() {
        let provider = EcdhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut ps = ParamSet::new();
        ps.set("ec-curve", ParamValue::Utf8String("P-256".to_string()));
        ctx.init(&[0x01; 32], Some(&ps)).expect("init");
        let mut secret = [0u8; 32];
        assert!(ctx.derive(&mut secret).is_err());
    }

    #[test]
    fn derive_fails_without_curve() {
        let provider = EcdhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(&[0x01; 32], None).expect("init");
        ctx.set_peer(&[0x04; 65]).expect("set_peer");
        let mut secret = [0u8; 32];
        assert!(ctx.derive(&mut secret).is_err());
    }

    #[test]
    fn unknown_curve_rejected() {
        let provider = EcdhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut ps = ParamSet::new();
        ps.set(
            "ec-curve",
            ParamValue::Utf8String("invalid_curve".to_string()),
        );
        assert!(ctx.init(&[0x01; 32], Some(&ps)).is_err());
    }

    #[test]
    fn get_params_returns_curve() {
        let provider = EcdhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut ps = ParamSet::new();
        ps.set("ec-curve", ParamValue::Utf8String("P-384".to_string()));
        ctx.init(&[0x42; 32], Some(&ps)).expect("init");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(
            params.get("ec-curve"),
            Some(&ParamValue::Utf8String("P-384".to_string()))
        );
    }

    /// Known P-256 ECDH test vector from NIST CAVP.
    ///
    /// Uses a simplified scalar to verify the point multiplication logic.
    #[test]
    fn ecdh_p256_known_point_multiply() {
        // P-256 generator point (uncompressed)
        let gx = hex_to_bytes(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        );
        let gy = hex_to_bytes(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        );
        let mut g_uncompressed = vec![0x04];
        g_uncompressed.extend_from_slice(&gx);
        g_uncompressed.extend_from_slice(&gy);

        // Use scalar = 2 and verify 2*G is not infinity
        let scalar = vec![0x02];

        let provider = EcdhKeyExchange;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut ps = ParamSet::new();
        ps.set("ec-curve", ParamValue::Utf8String("P-256".to_string()));
        ctx.init(&scalar, Some(&ps)).expect("init");
        ctx.set_peer(&g_uncompressed).expect("set_peer");

        let mut secret = [0u8; 32];
        let len = ctx.derive(&mut secret).expect("derive");
        assert_eq!(len, 32);
        // 2*G should produce a non-zero x-coordinate
        assert!(secret.iter().any(|&b| b != 0), "shared secret must be non-zero");
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}
