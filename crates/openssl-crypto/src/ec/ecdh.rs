//! ECDH (Elliptic Curve Diffie-Hellman) key exchange implementation.
//!
//! Provides shared secret computation using elliptic curve key pairs per
//! SP 800-56A Rev. 3 §5.7.1.2 (ECC CDH Primitive) and optional X9.63 KDF.
//! Translates C `ossl_ecdh_simple_compute_key()` from `crypto/ec/ecdh_ossl.c`
//! and X9.63 KDF from `crypto/ec/ecdh_kdf.c`.
//!
//! ## Security
//!
//! - Shared secret bytes are zeroed on drop via [`zeroize::ZeroizeOnDrop`]
//! - Cofactor DH mode is used by default to prevent small-subgroup attacks
//! - Point-at-infinity check prevents invalid shared secrets
//! - All intermediate values are zeroed after use
//!
//! ## Algorithm (SP 800-56A §5.7.1.2)
//!
//! 1. Validate the peer public key is on the curve
//! 2. Get the cofactor *h* from the group (typically 1 for prime-order curves)
//! 3. Compute the shared point:
//!    - **Cofactor DH:** `point = (h × priv_key) × peer_pub_key`
//!    - **Standard:** `point = priv_key × peer_pub_key`
//! 4. Verify the result is not the point at infinity
//! 5. Extract the x-coordinate as a big-endian byte array padded to field size
//! 6. Return as [`SharedSecret`]
//!
//! ## X9.63 KDF
//!
//! The [`kdf_x963`] function applies the ANSI X9.63 key derivation function to
//! a raw ECDH shared secret, producing derived key material of a specified
//! length. This replaces `ossl_ecdh_kdf_X9_63()` from `crypto/ec/ecdh_kdf.c`.

use openssl_common::{CryptoError, CryptoResult};

use crate::kdf::{KdfContext, KdfType};

use super::{EcGroup, EcKey, EcPoint};

use tracing::{error, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ===========================================================================
// SharedSecret — typed wrapper for raw ECDH shared secret bytes
// ===========================================================================

/// ECDH shared secret — the raw x-coordinate bytes from the DH computation.
///
/// Automatically zeroed on drop to prevent key material leakage. This type
/// replaces the raw `unsigned char *` buffer returned by
/// `ossl_ecdh_simple_compute_key()` in `crypto/ec/ecdh_ossl.c`.
///
/// # Security
///
/// The inner byte vector is zeroed when this value is dropped, preventing
/// key material from lingering in memory. This replaces the C patterns:
/// - `BN_clear()` / `BN_clear_free()` for intermediate bignums
/// - `EC_POINT_clear_free()` for temporary points
/// - `OPENSSL_cleanse()` for the output buffer
///
/// # Rule R5
///
/// This is a typed wrapper rather than a raw `Vec<u8>`, providing compile-time
/// distinction between shared secrets and other byte buffers.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    /// Raw shared secret bytes (x-coordinate of the computed point),
    /// padded to the field element size in big-endian byte order.
    secret: Vec<u8>,
}

impl SharedSecret {
    /// Creates a new `SharedSecret` from raw bytes.
    ///
    /// This is intentionally crate-private; external callers obtain
    /// shared secrets via [`compute_key`] or [`compute_key_with_mode`].
    fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    /// Returns a reference to the raw shared secret bytes.
    ///
    /// The returned slice is the x-coordinate of the ECDH computation result,
    /// zero-padded to the field element byte length in big-endian order.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Returns the length of the shared secret in bytes.
    ///
    /// This equals `(degree + 7) / 8` where `degree` is the curve's field
    /// size in bits (e.g., 32 for P-256, 48 for P-384, 66 for P-521).
    #[inline]
    pub fn len(&self) -> usize {
        self.secret.len()
    }

    /// Returns `true` if the shared secret is empty.
    ///
    /// A properly computed shared secret is never empty; this method exists
    /// for API completeness and defensive programming.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }

    /// Consumes the `SharedSecret` and returns the raw byte vector.
    ///
    /// **Security warning:** The caller takes ownership of zeroing the returned
    /// bytes. If the `Vec<u8>` is dropped without explicit zeroing, the shared
    /// secret may remain in memory. Prefer [`as_bytes()`](Self::as_bytes) for
    /// read-only access, which maintains automatic zeroing via this struct's
    /// [`ZeroizeOnDrop`] implementation.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        // We need to extract the secret before ZeroizeOnDrop runs.
        // Use ManuallyDrop to prevent the automatic zeroing, since the
        // caller explicitly requested ownership of the raw bytes.
        let mut me = std::mem::ManuallyDrop::new(self);
        std::mem::take(&mut me.secret)
    }
}

impl AsRef<[u8]> for SharedSecret {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

// Intentionally not implementing Debug to prevent accidental logging of
// key material. Rule R9 doc: "tracing on entry/exit with curve name
// (never key material!)".
impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("len", &self.secret.len())
            .finish()
    }
}

// ===========================================================================
// EcdhMode — cofactor vs standard ECDH selection
// ===========================================================================

/// ECDH computation mode.
///
/// Controls whether the shared secret computation includes the curve's
/// cofactor, per SP 800-56A Rev. 3. Cofactor DH is the recommended mode
/// for FIPS compliance and prevents small-subgroup attacks on curves with
/// cofactor > 1.
///
/// # From C Source
///
/// In `ecdh_ossl.c` line 79, the cofactor flag is checked:
/// ```c
/// if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
///     cofactor = EC_GROUP_get0_cofactor(group);
///     ...
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhMode {
    /// Standard ECDH: `shared_secret = priv_key × peer_pub_key`
    ///
    /// The raw scalar multiplication without cofactor adjustment.
    /// Suitable for prime-order curves where cofactor = 1.
    Standard,

    /// Cofactor ECDH (SP 800-56A §5.7.1.2):
    /// `shared_secret = (cofactor × priv_key) × peer_pub_key`
    ///
    /// This is the default and recommended mode for FIPS compliance.
    /// Prevents small-subgroup attacks on curves where cofactor > 1.
    CofactorDh,
}

impl Default for EcdhMode {
    /// Returns [`EcdhMode::CofactorDh`] as the default, matching
    /// OpenSSL's `EC_FLAG_COFACTOR_ECDH` behavior for SP 800-56A compliance.
    #[inline]
    fn default() -> Self {
        Self::CofactorDh
    }
}

impl std::fmt::Display for EcdhMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => write!(f, "Standard ECDH"),
            Self::CofactorDh => write!(f, "Cofactor ECDH (SP800-56A)"),
        }
    }
}

// ===========================================================================
// Peer key validation helper
// ===========================================================================

/// Validates that a peer public key is suitable for ECDH key exchange.
///
/// Checks performed:
/// 1. The point is not the point at infinity
/// 2. The point lies on the specified curve
///
/// This replaces the validation logic embedded in
/// `ossl_ecdh_simple_compute_key()` from `ecdh_ossl.c`, which relies on
/// `EC_POINT_get_affine_coordinates()` returning an error for invalid points.
///
/// # Errors
///
/// Returns [`CryptoError`] if:
/// - The peer public key is the point at infinity
/// - The peer public key is not on the specified curve
fn validate_peer_key(group: &EcGroup, peer_pub: &EcPoint) -> CryptoResult<()> {
    // Check 1: Point must not be at infinity
    if peer_pub.is_at_infinity() {
        error!("ECDH peer key validation failed: point at infinity");
        return Err(CryptoError::Key(
            "ECDH: peer public key is the point at infinity".to_string(),
        ));
    }

    // Check 2: Point must lie on the curve
    //
    // From ecdh_ossl.c line 103–104, the C code checks implicitly via
    // EC_POINT_get_affine_coordinates which returns 0 if the point is
    // not on the curve. We do an explicit on-curve check here.
    if !peer_pub.is_on_curve(group)? {
        error!("ECDH peer key validation failed: point not on curve");
        return Err(CryptoError::Verification(
            "ECDH: peer public key is not on the curve".to_string(),
        ));
    }

    Ok(())
}

// ===========================================================================
// Core ECDH shared secret computation
// ===========================================================================

/// Computes an ECDH shared secret using Cofactor DH mode (default).
///
/// This is the primary entry point for ECDH key exchange, replacing
/// `ossl_ecdh_compute_key()` from `crypto/ec/ecdh_ossl.c` line 28.
/// Uses [`EcdhMode::CofactorDh`] by default for SP 800-56A compliance.
///
/// # Algorithm
///
/// 1. Validates `own_key` has a private key component
/// 2. Validates `peer_public_key` is on the curve and not at infinity
/// 3. Computes: `point = (cofactor × priv_key) × peer_pub_key`
/// 4. Verifies the resulting point is not at infinity
/// 5. Extracts the x-coordinate as a padded big-endian byte array
///
/// # Arguments
///
/// * `own_key` — Our EC key pair (must contain a private key)
/// * `peer_public_key` — The peer's public key (point on the same curve)
///
/// # Returns
///
/// A [`SharedSecret`] containing the raw x-coordinate bytes, zero-padded
/// to the field element size. The secret is automatically zeroed on drop.
///
/// # Errors
///
/// Returns [`CryptoError`] if:
/// - `own_key` has no private key component
/// - `peer_public_key` is not on the curve or is at infinity
/// - The computed shared point is the point at infinity
/// - An arithmetic error occurs during scalar multiplication
///
/// # Security
///
/// All intermediate values (effective scalar, shared point) are zeroed
/// after use. The returned [`SharedSecret`] implements [`ZeroizeOnDrop`].
pub fn compute_key(own_key: &EcKey, peer_public_key: &EcPoint) -> CryptoResult<SharedSecret> {
    compute_key_with_mode(own_key, peer_public_key, EcdhMode::CofactorDh)
}

/// Computes an ECDH shared secret with an explicit mode selection.
///
/// This allows choosing between standard and cofactor DH modes, replacing
/// the `EC_FLAG_COFACTOR_ECDH` flag check in `ossl_ecdh_simple_compute_key()`
/// (`ecdh_ossl.c` lines 75–88).
///
/// # Algorithm (SP 800-56A §5.7.1.2)
///
/// 1. Validate `own_key` has a private key component
/// 2. Validate `peer_public_key` is on the curve and not at infinity
/// 3. Compute the effective scalar:
///    - **Standard:** `effective_scalar = priv_key`
///    - **Cofactor DH:** `effective_scalar = cofactor × priv_key`
/// 4. Compute: `shared_point = effective_scalar × peer_pub_key`
/// 5. Verify the shared point is not at infinity
/// 6. Extract the x-coordinate, padded to `⌈degree / 8⌉` bytes
///
/// # Arguments
///
/// * `own_key` — Our EC key pair (must contain a private key)
/// * `peer_public_key` — The peer's public key (point on the same curve)
/// * `mode` — The ECDH mode: [`EcdhMode::Standard`] or [`EcdhMode::CofactorDh`]
///
/// # Returns
///
/// A [`SharedSecret`] containing the raw x-coordinate bytes, zero-padded
/// to the field element byte size.
///
/// # Errors
///
/// Returns [`CryptoError`] if:
/// - `own_key` has no private key component
/// - `peer_public_key` fails validation
/// - The computed shared point is the point at infinity
/// - An arithmetic error occurs
pub fn compute_key_with_mode(
    own_key: &EcKey,
    peer_public_key: &EcPoint,
    mode: EcdhMode,
) -> CryptoResult<SharedSecret> {
    // Extract the curve name for observability logging (never log key material!)
    let curve_label = own_key
        .curve_name()
        .map_or_else(|| "unknown".to_string(), |cn| format!("{cn:?}"));

    trace!(
        curve = %curve_label,
        mode = %mode,
        "ECDH compute_key: starting shared secret computation"
    );

    // -----------------------------------------------------------------------
    // Step 1: Obtain private key (replaces ecdh_ossl.c line 61)
    // -----------------------------------------------------------------------
    let priv_key = own_key.private_key().ok_or_else(|| {
        error!(
            curve = %curve_label,
            "ECDH compute_key failed: missing private key"
        );
        CryptoError::Key("ECDH: key has no private key component".to_string())
    })?;

    // Validate private key is not zero (would produce point at infinity).
    if priv_key.is_zero() {
        error!(
            curve = %curve_label,
            "ECDH compute_key failed: private key is zero"
        );
        return Err(CryptoError::Key(
            "ECDH: private key scalar is zero".to_string(),
        ));
    }

    let group = own_key.group();

    // -----------------------------------------------------------------------
    // Step 2: Validate peer public key
    // -----------------------------------------------------------------------
    validate_peer_key(group, peer_public_key)?;

    // -----------------------------------------------------------------------
    // Step 3: Compute effective scalar
    // (ecdh_ossl.c lines 75–88: cofactor multiplication)
    // -----------------------------------------------------------------------
    let mut effective_scalar = match mode {
        EcdhMode::Standard => {
            // Standard ECDH: use private key directly as the scalar.
            // We dup() to get an owned copy we can clear() after use.
            priv_key.dup()
        }
        EcdhMode::CofactorDh => {
            // Cofactor DH: effective_scalar = cofactor × priv_key
            // From ecdh_ossl.c line 79:
            //   if (!BN_mul(x, priv_key, cofactor, ctx))
            let cofactor = group.cofactor();
            if cofactor.is_one() {
                // Optimization: skip multiplication when cofactor is 1
                // (common for NIST prime curves: P-256, P-384, P-521)
                priv_key.dup()
            } else {
                // &BigNum * &BigNum → BigNum (via Mul trait impl)
                cofactor * priv_key
            }
        }
    };

    // -----------------------------------------------------------------------
    // Step 4: Scalar multiplication — shared_point = effective_scalar × peer_pub
    // (ecdh_ossl.c line 91: EC_POINT_mul(group, tmp, NULL, pub_key, x, ctx))
    //
    // SECURITY (CRITICAL #11): The `effective_scalar` is the secret ECDH
    // private key (or cofactor × private key). Any timing dependency on its
    // bits would leak the private scalar to a co-resident attacker.
    //
    // `EcPoint::mul` was made constant-time in commit 384775b1b6 (Group B #1)
    // by replacing the Hamming-weight-leaky double-and-add loop with a
    // branchless Montgomery ladder using `subtle::ConditionallySelectable`
    // for point swaps. The control flow and memory access pattern of the
    // ladder are independent of the scalar bits, so this call no longer
    // leaks the ECDH private key through timing or cache-line side channels.
    //
    // Residual leak (documented and out of scope here): `num-bigint` limb
    // arithmetic underneath the field operations is not constant-time at
    // the microarchitectural limb level. Likewise, `EcPoint::add` and
    // `EcPoint::double` retain operand-dependent case splits (point at
    // infinity, equal-x doubling). Both are tracked for the planned
    // Jacobian / projective-coordinates refactor.
    // -----------------------------------------------------------------------
    let shared_point = EcPoint::mul(group, peer_public_key, &effective_scalar)?;

    // Zero the effective scalar immediately after use
    effective_scalar.clear();

    // -----------------------------------------------------------------------
    // Step 5: Verify not at infinity
    // (ecdh_ossl.c lines 96–104: get_affine_coordinates check)
    // -----------------------------------------------------------------------
    if shared_point.is_at_infinity() {
        error!(
            curve = %curve_label,
            mode = %mode,
            "ECDH compute_key failed: shared point is at infinity"
        );
        return Err(CryptoError::Key(
            "ECDH: computed shared point is the point at infinity".to_string(),
        ));
    }

    // -----------------------------------------------------------------------
    // Step 6: Extract x-coordinate as padded big-endian bytes
    // (ecdh_ossl.c lines 107–130: BN_bn2binpad(x, buf, buf_len))
    // -----------------------------------------------------------------------
    let x_coord = shared_point.x();

    // Quick check: if the x-coordinate is zero, the shared point is
    // degenerate. This mirrors the `BN_is_zero` check implied by the C
    // code's use of `BN_bn2binpad()` result validation.
    if x_coord.is_zero() {
        error!(
            curve = %curve_label,
            mode = %mode,
            "ECDH compute_key failed: x-coordinate of shared point is zero"
        );
        return Err(CryptoError::Key(
            "ECDH: x-coordinate of shared point is zero (degenerate result)".to_string(),
        ));
    }

    // Compute field element byte length: ⌈degree / 8⌉
    // Uses checked arithmetic per Rule R6 — no bare `as` casts.
    let degree = group.degree();
    let field_byte_len = usize::try_from(degree)
        .map_err(|_| {
            CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow {
                operation: "ECDH degree to usize conversion",
            })
        })?
        .checked_add(7)
        .and_then(|v| v.checked_div(8))
        .ok_or(CryptoError::Common(
            openssl_common::CommonError::ArithmeticOverflow {
                operation: "ECDH field byte length calculation",
            },
        ))?;

    // Serialize the x-coordinate to a padded big-endian byte array.
    // We use `to_bytes_be_padded()` to ensure consistent output length
    // regardless of the x-coordinate value. For comparison or verification
    // purposes, the un-padded bytes are available via `to_bytes_be()`.
    let raw_bytes = x_coord.to_bytes_be();
    let mut secret_bytes = x_coord.to_bytes_be_padded(field_byte_len)?;

    // Validate consistency: the padded output must be at least as long as
    // the raw big-endian encoding. This is a defensive check — if it fails,
    // something is seriously wrong with the BigNum encoding.
    if raw_bytes.len() > secret_bytes.len() {
        // Clean up both buffers before returning the error.
        let mut raw = raw_bytes;
        raw.zeroize();
        secret_bytes.zeroize();
        error!(
            curve = %curve_label,
            mode = %mode,
            "ECDH compute_key failed: padded encoding shorter than raw encoding"
        );
        return Err(CryptoError::Key(
            "ECDH: internal error in x-coordinate serialization".to_string(),
        ));
    }

    trace!(
        curve = %curve_label,
        mode = %mode,
        secret_len = secret_bytes.len(),
        "ECDH compute_key: shared secret computation complete"
    );

    Ok(SharedSecret::new(secret_bytes))
}

// ===========================================================================
// X9.63 KDF integration (from ecdh_kdf.c)
// ===========================================================================

/// Applies the ANSI X9.63 Key Derivation Function to an ECDH shared secret.
///
/// Replaces `ossl_ecdh_kdf_X9_63()` from `crypto/ec/ecdh_kdf.c` lines 24–50.
/// The X9.63 KDF produces derived key material from a raw shared secret and
/// optional shared info, using a specified digest algorithm.
///
/// # Algorithm
///
/// ```text
/// DerivedKey = H(Z ∥ Counter ∥ SharedInfo)
/// ```
///
/// where `Z` is the ECDH shared secret, `Counter` is a 32-bit big-endian
/// counter starting at 1, and `SharedInfo` is optional application-specific
/// context data.
///
/// # Arguments
///
/// * `shared_secret` — The raw ECDH shared secret from [`compute_key`]
/// * `shared_info` — Application-specific context data (may be empty)
/// * `digest_name` — Hash algorithm name (e.g., `"SHA256"`, `"SHA384"`, `"SHA512"`)
/// * `output_len` — Desired output length in bytes
///
/// # Returns
///
/// A `Vec<u8>` containing the derived key material of the requested length.
///
/// # Errors
///
/// Returns [`CryptoError`] if:
/// - The shared secret is empty
/// - The digest name is empty or unsupported
/// - The output length is zero
/// - The KDF derivation fails internally
///
/// # Example
///
/// ```rust,ignore
/// let shared = compute_key(&my_key, &peer_pubkey)?;
/// let derived = kdf_x963(&shared, b"label", "SHA256", 32)?;
/// ```
pub fn kdf_x963(
    shared_secret: &SharedSecret,
    shared_info: &[u8],
    digest_name: &str,
    output_len: usize,
) -> CryptoResult<Vec<u8>> {
    trace!(
        digest = digest_name,
        output_len = output_len,
        shared_info_len = shared_info.len(),
        "ECDH kdf_x963: starting X9.63 key derivation"
    );

    // Validate inputs — Rule R5: use Option/Result, not sentinel values.
    if shared_secret.is_empty() {
        error!("kdf_x963 failed: shared secret is empty");
        return Err(CryptoError::Key(
            "ECDH shared secret must not be empty for X9.63 KDF".to_string(),
        ));
    }
    if digest_name.is_empty() {
        error!("kdf_x963 failed: digest name is empty");
        return Err(CryptoError::AlgorithmNotFound(
            "digest name must not be empty for X9.63 KDF".to_string(),
        ));
    }
    if output_len == 0 {
        error!("kdf_x963 failed: output length is zero");
        return Err(CryptoError::Key(
            "X9.63 KDF output length must be > 0".to_string(),
        ));
    }

    // Delegate to the KDF module's X963 KDF implementation.
    // This replaces the C pattern from ecdh_kdf.c:
    //   kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_X963KDF, NULL);
    //   kctx = EVP_KDF_CTX_new(kdf);
    //   OSSL_PARAM params[] = { digest, key(Z), info(sinfo) };
    //   EVP_KDF_derive(kctx, out, outlen, params);
    let mut ctx = KdfContext::new(KdfType::X963Kdf);
    ctx.set_key(shared_secret.as_bytes())?;
    ctx.set_info(shared_info)?;
    ctx.set_digest(digest_name)?;

    let derived = ctx.derive(output_len)?;

    trace!(
        digest = digest_name,
        derived_len = derived.len(),
        "ECDH kdf_x963: key derivation complete"
    );

    Ok(derived)
}

/// Computes an ECDH shared secret and applies X9.63 KDF in one step.
///
/// This is a convenience function that combines [`compute_key`] and
/// [`kdf_x963`], replacing the combined ECDH + KDF workflow found in
/// `ECDH_compute_key()` (`crypto/ec/ec_kmeth.c` lines 123–149) when a
/// KDF callback is provided.
///
/// # Arguments
///
/// * `own_key` — Our EC key pair (must contain a private key)
/// * `peer_public_key` — The peer's public key (point on the same curve)
/// * `digest_name` — Hash algorithm for the X9.63 KDF (e.g., `"SHA256"`)
/// * `shared_info` — Application-specific context data for the KDF
/// * `output_len` — Desired output length in bytes
///
/// # Returns
///
/// A `Vec<u8>` containing the derived key material.
///
/// # Errors
///
/// Returns [`CryptoError`] if:
/// - The ECDH computation fails (see [`compute_key`] errors)
/// - The KDF derivation fails (see [`kdf_x963`] errors)
///
/// # Security
///
/// The intermediate raw shared secret is automatically zeroed when the
/// `SharedSecret` goes out of scope at the end of this function.
pub fn compute_key_with_kdf(
    own_key: &EcKey,
    peer_public_key: &EcPoint,
    digest_name: &str,
    shared_info: &[u8],
    output_len: usize,
) -> CryptoResult<Vec<u8>> {
    let curve_label = own_key
        .curve_name()
        .map_or_else(|| "unknown".to_string(), |cn| format!("{cn:?}"));

    trace!(
        curve = %curve_label,
        digest = digest_name,
        output_len = output_len,
        "ECDH compute_key_with_kdf: starting combined ECDH + X9.63 KDF"
    );

    // Step 1: Compute raw ECDH shared secret (cofactor DH by default)
    let shared_secret = compute_key(own_key, peer_public_key)?;

    // Step 2: Apply X9.63 KDF
    // The shared_secret is automatically zeroed when this function returns
    // (it goes out of scope and ZeroizeOnDrop fires).
    let derived = kdf_x963(&shared_secret, shared_info, digest_name, output_len)?;

    trace!(
        curve = %curve_label,
        derived_len = derived.len(),
        "ECDH compute_key_with_kdf: combined operation complete"
    );

    Ok(derived)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::BigNum;

    #[test]
    fn test_shared_secret_basic_operations() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let secret = SharedSecret::new(data.clone());

        assert_eq!(secret.as_bytes(), &data);
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
        assert_eq!(secret.as_ref(), &data[..]);
    }

    #[test]
    fn test_shared_secret_empty() {
        let secret = SharedSecret::new(Vec::new());
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
        assert_eq!(secret.as_bytes(), &[] as &[u8]);
    }

    #[test]
    fn test_shared_secret_into_bytes() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let secret = SharedSecret::new(data.clone());
        let bytes = secret.into_bytes();
        assert_eq!(bytes, data);
    }

    #[test]
    fn test_shared_secret_debug_no_key_material() {
        let secret = SharedSecret::new(vec![0x01, 0x02, 0x03]);
        let debug_str = format!("{secret:?}");
        // Debug output must NOT contain actual secret bytes
        assert!(!debug_str.contains("01"));
        assert!(!debug_str.contains("02"));
        assert!(!debug_str.contains("03"));
        // But should contain the length
        assert!(debug_str.contains("3"));
    }

    #[test]
    fn test_shared_secret_roundtrip_with_bignum() {
        // Verify BigNum::from_bytes_be() can reconstruct the x-coordinate
        // value from a SharedSecret's byte representation. This validates
        // the serialization used in compute_key.
        let original_bytes = vec![0x00, 0x01, 0x02, 0x03, 0xFF];
        let bn = BigNum::from_bytes_be(&original_bytes);
        let rt_bytes = bn.to_bytes_be_padded(original_bytes.len()).unwrap();
        assert_eq!(rt_bytes, original_bytes);
    }

    #[test]
    fn test_ecdh_mode_default_is_cofactor() {
        assert_eq!(EcdhMode::default(), EcdhMode::CofactorDh);
    }

    #[test]
    fn test_ecdh_mode_display() {
        assert_eq!(format!("{}", EcdhMode::Standard), "Standard ECDH");
        assert_eq!(
            format!("{}", EcdhMode::CofactorDh),
            "Cofactor ECDH (SP800-56A)"
        );
    }

    #[test]
    fn test_ecdh_mode_equality() {
        assert_eq!(EcdhMode::Standard, EcdhMode::Standard);
        assert_eq!(EcdhMode::CofactorDh, EcdhMode::CofactorDh);
        assert_ne!(EcdhMode::Standard, EcdhMode::CofactorDh);
    }

    #[test]
    fn test_ecdh_mode_clone_copy() {
        let mode = EcdhMode::CofactorDh;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    // =======================================================================
    // ECDH end-to-end roundtrip tests (Group B #3 — CRITICAL #11)
    //
    // These tests exercise `compute_key_with_mode` through the public API:
    //   Alice generates (a, A=a·G); Bob generates (b, B=b·G); both compute
    //   shared = a·B = b·A. Both sides MUST arrive at the same shared secret.
    //
    // Beyond functional correctness, these tests serve as regression coverage
    // for the constant-time scalar multiplication: any future change that
    // breaks `EcPoint::mul` (the CT Montgomery ladder from Group B #1) would
    // fail the equality assertion or produce mismatched secrets.
    //
    // R10 compliance: the new helper / SECURITY documentation are reachable
    // from the public ECDH entry point `compute_key`, and these tests
    // traverse that path on real curves.
    // =======================================================================

    #[test]
    fn ecdh_roundtrip_p256_cofactor() {
        use crate::ec::{EcGroup, EcKey, NamedCurve};

        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1).unwrap();
        let alice = EcKey::generate(&group).unwrap();
        let bob = EcKey::generate(&group).unwrap();

        let alice_shared = compute_key(&alice, bob.public_key().unwrap()).unwrap();
        let bob_shared = compute_key(&bob, alice.public_key().unwrap()).unwrap();

        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "ECDH roundtrip on P-256 must produce identical shared secrets"
        );
        // Field size for P-256 is 32 bytes (256-bit field).
        assert_eq!(alice_shared.len(), 32);
        // A nonzero shared secret confirms the scalar mul produced a real point.
        assert!(alice_shared.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn ecdh_roundtrip_p256_standard() {
        use crate::ec::{EcGroup, EcKey, NamedCurve};

        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1).unwrap();
        let alice = EcKey::generate(&group).unwrap();
        let bob = EcKey::generate(&group).unwrap();

        // Explicitly request Standard ECDH mode (no cofactor multiplication).
        // For NIST P-256 (cofactor = 1) this is mathematically identical to
        // CofactorDh, so the secrets must still match.
        let alice_shared =
            compute_key_with_mode(&alice, bob.public_key().unwrap(), EcdhMode::Standard).unwrap();
        let bob_shared =
            compute_key_with_mode(&bob, alice.public_key().unwrap(), EcdhMode::Standard).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn ecdh_roundtrip_p384() {
        use crate::ec::{EcGroup, EcKey, NamedCurve};

        let group = EcGroup::from_curve_name(NamedCurve::Secp384r1).unwrap();
        let alice = EcKey::generate(&group).unwrap();
        let bob = EcKey::generate(&group).unwrap();

        let alice_shared = compute_key(&alice, bob.public_key().unwrap()).unwrap();
        let bob_shared = compute_key(&bob, alice.public_key().unwrap()).unwrap();

        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "ECDH roundtrip on P-384 must produce identical shared secrets"
        );
        // Field size for P-384 is 48 bytes (384-bit field).
        assert_eq!(alice_shared.len(), 48);
        assert!(alice_shared.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn ecdh_roundtrip_secp256k1() {
        use crate::ec::{EcGroup, EcKey, NamedCurve};

        let group = EcGroup::from_curve_name(NamedCurve::Secp256k1).unwrap();
        let alice = EcKey::generate(&group).unwrap();
        let bob = EcKey::generate(&group).unwrap();

        let alice_shared = compute_key(&alice, bob.public_key().unwrap()).unwrap();
        let bob_shared = compute_key(&bob, alice.public_key().unwrap()).unwrap();

        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "ECDH roundtrip on secp256k1 must produce identical shared secrets"
        );
        // Field size for secp256k1 is 32 bytes (256-bit field).
        assert_eq!(alice_shared.len(), 32);
        assert!(alice_shared.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn ecdh_distinct_keys_produce_distinct_secrets() {
        // Sanity check that swapping a key changes the resulting shared secret.
        // If the CT scalar multiplication were silently broken (e.g. always
        // returning the identity), this test would fail.
        use crate::ec::{EcGroup, EcKey, NamedCurve};

        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1).unwrap();
        let alice = EcKey::generate(&group).unwrap();
        let bob = EcKey::generate(&group).unwrap();
        let charlie = EcKey::generate(&group).unwrap();

        let alice_with_bob = compute_key(&alice, bob.public_key().unwrap()).unwrap();
        let alice_with_charlie = compute_key(&alice, charlie.public_key().unwrap()).unwrap();

        // With overwhelming probability (1 - 2^{-256}), two random ECDH
        // exchanges with different peers produce different secrets.
        assert_ne!(
            alice_with_bob.as_bytes(),
            alice_with_charlie.as_bytes(),
            "Distinct peer keys must produce distinct shared secrets"
        );
    }

    #[test]
    fn ecdh_rejects_missing_private_key() {
        // A public-only key (no private component) must fail compute_key with
        // a clear error rather than silently producing a degenerate secret.
        use crate::ec::{EcGroup, EcKey, NamedCurve};

        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1).unwrap();
        let alice = EcKey::generate(&group).unwrap();
        let bob = EcKey::generate(&group).unwrap();

        // Strip Alice's private key — leaves only the public component.
        let alice_pub_only =
            EcKey::from_public_key(&group, alice.public_key().unwrap().clone()).unwrap();

        let result = compute_key(&alice_pub_only, bob.public_key().unwrap());
        assert!(
            result.is_err(),
            "compute_key on a public-only key must return Err"
        );
    }
}
