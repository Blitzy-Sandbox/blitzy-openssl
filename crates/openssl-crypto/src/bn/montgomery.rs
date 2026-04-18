//! Montgomery multiplication and modular exponentiation for the OpenSSL Rust workspace.
//!
//! Montgomery multiplication converts modular arithmetic into cheaper operations
//! by replacing division with multiplication. This is critical for RSA, DH, DSA,
//! and other algorithms that perform modular exponentiation with large moduli.
//!
//! Translates C `BN_MONT_CTX`, `BN_mod_mul_montgomery()`, `BN_mod_exp_mont()`,
//! and `BN_mod_exp_mont_consttime()` from `crypto/bn/bn_mont.c` and `crypto/bn/bn_exp.c`.
//!
//! # Montgomery Form
//!
//! Given modulus N and R = 2^ri where ri is the bit-length of N rounded up to a
//! 64-bit word boundary:
//! - To Montgomery form: aR mod N
//! - Montgomery multiply: REDC(aR · bR) = abR mod N
//! - From Montgomery form: REDC(aR) = a mod N
//!
//! # Performance
//!
//! Montgomery multiplication avoids expensive division by precomputing
//! N' = −N⁻¹ mod R. Each Montgomery reduction (REDC) uses only multiplication,
//! addition, and bit-shifting — no division by N. For repeated modular operations
//! (e.g., modular exponentiation), this yields significant speedup.
//!
//! # Constant-Time Operations
//!
//! [`mod_exp_consttime`] provides a fixed-window exponentiation with constant-time
//! table lookups via the `subtle` crate, suitable for private-key operations where
//! timing side-channel resistance is required.

use crate::bn::{BigNum, BigNumError};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Zero};
use openssl_common::{CryptoError, CryptoResult};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use tracing::{debug, trace};

// ---------------------------------------------------------------------------
// Montgomery Multiplication Context
// ---------------------------------------------------------------------------

/// Montgomery multiplication context.
///
/// Precomputes values needed for efficient modular multiplication using
/// Montgomery reduction (REDC). Replaces C `BN_MONT_CTX` from `bn_local.h`
/// lines 246–257 and `bn_mont.c`.
///
/// The context stores:
/// - The modulus N (must be odd and positive)
/// - R² mod N for converting into Montgomery form
/// - −N⁻¹ mod R for the REDC reduction step
/// - The number of bits in R = 2^ri
///
/// # Lock Scope
///
/// // LOCK-SCOPE: `MontgomeryContext` is per-modulus, typically created once
/// // per RSA key and reused across operations within a single thread.
/// // Not shared across threads without external synchronization (e.g., `Arc<Mutex>`).
#[derive(Debug, Clone)]
pub struct MontgomeryContext {
    /// The modulus N — must be odd and positive.
    modulus: BigNum,
    /// R² mod N — precomputed for converting to Montgomery form via
    /// `to_montgomery(a) = montgomery_multiply(a, rr)`.
    rr: BigNum,
    /// −N⁻¹ mod R — used in the REDC reduction step to compute
    /// the correction term m = (t mod R) × (−N⁻¹) mod R.
    n_inverse: BigNum,
    /// Number of bits in R = 2^ri. Word-aligned: ri = ⌈`num_bits(N)`/64⌉ × 64.
    ri: u32,
    /// Cached modulus as [`BigUint`] for efficient unsigned REDC arithmetic.
    n_uint: BigUint,
    /// Cached −N⁻¹ mod R as [`BigUint`] for efficient unsigned REDC arithmetic.
    ni_uint: BigUint,
    /// Cached R − 1 = 2^ri − 1, used as a bitmask for mod-R operations.
    r_mask: BigUint,
}

impl MontgomeryContext {
    /// Create a new Montgomery context for the given modulus.
    ///
    /// Validates that the modulus is positive and odd (Montgomery reduction requires
    /// an odd modulus so that gcd(N, R) = 1 where R is a power of 2).
    ///
    /// Computes:
    /// - `ri` = bit-length of N rounded up to 64-bit word boundary
    /// - `R` = 2^ri
    /// - `RR` = R² mod N (for `to_montgomery` conversion)
    /// - `−N⁻¹ mod R` (for REDC reduction)
    ///
    /// Replaces C `BN_MONT_CTX_new()` + `BN_MONT_CTX_set()`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    /// - Modulus is zero, negative, or even
    /// - Modulus is too large for the bit-width computation
    /// - Modular inverse computation fails (should not happen for odd modulus)
    pub fn new(modulus: &BigNum) -> CryptoResult<Self> {
        // Validate: modulus must be positive
        if modulus.is_zero() || modulus.is_negative() {
            return Err(CryptoError::from(BigNumError::InvalidArgument(
                "Montgomery modulus must be positive".into(),
            )));
        }
        // Validate: modulus must be odd (gcd(N, 2^k) = 1)
        if !modulus.is_odd() {
            return Err(
                BigNumError::InvalidArgument("Montgomery modulus must be odd".into()).into(),
            );
        }

        let n_bits = modulus.num_bits();
        // Compute ri = ⌈n_bits / 64⌉ × 64 using checked arithmetic.
        // TRUNCATION: n_bits is u32, addition of 63 checked for overflow.
        let ri = n_bits
            .checked_add(63)
            .map(|v| (v / 64) * 64)
            .ok_or(BigNumError::Overflow)?;

        debug!(
            modulus_bits = n_bits,
            ri = ri,
            "Creating Montgomery context"
        );

        // Convert modulus to BigUint for unsigned arithmetic
        let n_uint = modulus
            .inner()
            .to_biguint()
            .ok_or(BigNumError::NegativeNotAllowed)?;

        // R = 2^ri
        let ri_usize = usize::try_from(ri).map_err(|_| BigNumError::Overflow)?;
        let r_uint = BigUint::one() << ri_usize;
        // R − 1 bitmask for fast mod-R via bitwise AND
        let r_mask = &r_uint - BigUint::one();

        // RR = R² mod N — precomputed for to_montgomery conversion
        let rr_uint = (&r_uint * &r_uint) % &n_uint;
        let rr = BigNum::from_inner(BigInt::from(rr_uint));

        // Compute −N⁻¹ mod R using extended GCD:
        //   N × x + R × y = gcd(N, R) = 1  (since N is odd, R is power of 2)
        //   N⁻¹ mod R = x mod R
        //   −N⁻¹ mod R = (R − x) mod R
        let n_int = BigInt::from(n_uint.clone());
        let r_int = BigInt::from(r_uint);
        let ext = n_int.extended_gcd(&r_int);
        if !ext.gcd.is_one() {
            return Err(BigNumError::NoInverse.into());
        }
        let n_inv_mod_r = ext.x.mod_floor(&r_int);
        let n_prime_int = (&r_int - &n_inv_mod_r).mod_floor(&r_int);
        let ni_uint = n_prime_int
            .to_biguint()
            .ok_or(BigNumError::InvalidArgument(
                "N inverse computation produced unexpected negative result".into(),
            ))?;
        let n_inverse = BigNum::from_inner(n_prime_int);

        trace!(ri = ri, "Montgomery context created successfully");

        Ok(Self {
            modulus: BigNum::from_inner(modulus.inner().clone()),
            rr,
            n_inverse,
            ri,
            n_uint,
            ni_uint,
            r_mask,
        })
    }

    /// Get a reference to the modulus N.
    pub fn modulus(&self) -> &BigNum {
        &self.modulus
    }

    /// Get the number of bits in R = 2^ri.
    ///
    /// `ri` is the bit-length of the modulus rounded up to a 64-bit word boundary.
    pub fn ri(&self) -> u32 {
        self.ri
    }

    /// Get a reference to the precomputed −N⁻¹ mod R.
    ///
    /// This value is used internally in the REDC reduction step.
    /// Exposed for diagnostic and testing purposes.
    pub fn n_inverse(&self) -> &BigNum {
        &self.n_inverse
    }

    /// Perform Montgomery reduction (REDC) on the unsigned product `t`.
    ///
    /// Computes t × R⁻¹ mod N without explicit division:
    /// 1. m = (t mod R) × (−N⁻¹) mod R
    /// 2. u = (t + m × N) / R
    /// 3. if u ≥ N then u −= N
    ///
    /// Requires: t < N × R for the single conditional subtraction to suffice.
    fn redc(&self, t: &BigUint) -> BigUint {
        // Step 1: m = (t mod R) × n_inverse mod R
        let t_mod_r = t & &self.r_mask;
        let m = (&t_mod_r * &self.ni_uint) & &self.r_mask;

        // Step 2: u = (t + m × N) / R   (exact division since t + m*N ≡ 0 mod R)
        let m_times_n = &m * &self.n_uint;
        let sum = t + &m_times_n;
        let u = sum >> (self.ri as usize);

        // Step 3: conditional subtraction to bring into [0, N)
        if u >= self.n_uint {
            u - &self.n_uint
        } else {
            u
        }
    }

    /// Compute (a × b × R⁻¹) mod N using Montgomery reduction.
    ///
    /// Both `a` and `b` are typically in Montgomery form (i.e., aR mod N),
    /// and the result is also in Montgomery form: REDC(aR · bR) = abR mod N.
    ///
    /// The inputs are reduced modulo N before computation to handle values
    /// outside the range \[0, N).
    ///
    /// Replaces C `BN_mod_mul_montgomery()` from `bn_mont.c` lines 26–85.
    pub fn montgomery_multiply(&self, a: &BigNum, b: &BigNum) -> CryptoResult<BigNum> {
        trace!("Montgomery multiply: computing REDC(a * b)");
        let a_uint = to_biguint_reduced(a, &self.n_uint)?;
        let b_uint = to_biguint_reduced(b, &self.n_uint)?;
        let product = &a_uint * &b_uint;
        let result = self.redc(&product);
        Ok(biguint_to_bignum(result))
    }

    /// Convert a number to Montgomery form: a → aR mod N.
    ///
    /// Uses precomputed RR = R² mod N:
    /// `montgomery_multiply(a, RR) = REDC(a × R²) = a × R² × R⁻¹ = aR mod N`.
    ///
    /// The input is automatically reduced modulo N.
    ///
    /// Replaces C `BN_to_montgomery()` from `bn_mont.c`.
    pub fn to_montgomery(&self, a: &BigNum) -> CryptoResult<BigNum> {
        trace!("Converting to Montgomery form");
        self.montgomery_multiply(a, &self.rr)
    }

    /// Convert a number from Montgomery form: aR → a mod N.
    ///
    /// Equivalent to `montgomery_multiply(aR, 1) = REDC(aR × 1) = aR × R⁻¹ = a mod N`.
    ///
    /// Replaces C `BN_from_montgomery()` from `bn_mont.c` lines 162–220.
    pub fn from_montgomery(&self, a: &BigNum) -> CryptoResult<BigNum> {
        trace!("Converting from Montgomery form");
        let one = BigNum::one();
        self.montgomery_multiply(a, &one)
    }
}

// ---------------------------------------------------------------------------
// Modular Exponentiation — Public API
// ---------------------------------------------------------------------------

/// Compute base^exp mod modulus using Montgomery exponentiation.
///
/// Implements a fixed-window exponentiation algorithm with Montgomery
/// multiplication for efficient modular reduction. For odd moduli,
/// creates a [`MontgomeryContext`] and uses Montgomery arithmetic.
/// For even moduli, falls back to binary square-and-multiply.
///
/// # Algorithm (from `crypto/bn/bn_exp.c`)
///
/// 1. Set up Montgomery context for `modulus`
/// 2. Convert `base` to Montgomery form: baseR = base × R mod N
/// 3. Precompute table of powers: base^0, base^1, ..., base^(2^w−1) in
///    Montgomery form where w is the window size
/// 4. Scan exponent bits from MSB to LSB using fixed windows:
///    - Square the accumulator w times per window
///    - Multiply by the precomputed power for the window value
/// 5. Convert result from Montgomery form
///
/// Replaces C `BN_mod_exp()` from `bn_exp.c` lines 97–167.
///
/// # Errors
///
/// Returns error if modulus is zero, or exponent is negative.
pub fn mod_exp(base: &BigNum, exp: &BigNum, modulus: &BigNum) -> CryptoResult<BigNum> {
    // Validate inputs
    if modulus.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    if modulus.is_one() {
        // Anything mod 1 is 0
        return Ok(BigNum::zero());
    }
    if exp.is_zero() {
        // base^0 = 1
        return Ok(BigNum::one());
    }
    if exp.is_negative() {
        return Err(BigNumError::InvalidArgument(
            "negative exponent requires modular inverse".into(),
        )
        .into());
    }

    let exp_bits = exp.num_bits();
    debug!(exp_bits = exp_bits, "mod_exp: starting exponentiation");

    // For odd positive modulus, use Montgomery exponentiation (matches C routing)
    if modulus.is_odd() && !modulus.is_negative() {
        let ctx = MontgomeryContext::new(modulus)?;
        return mod_exp_with_context(base, exp, &ctx);
    }

    // For even modulus, use binary square-and-multiply without Montgomery
    binary_mod_exp(base, exp, modulus)
}

/// Compute base^exp mod modulus with an existing Montgomery context.
///
/// More efficient when performing multiple exponentiations with the same modulus
/// (e.g., RSA CRT computation where the same p and q are reused).
///
/// Uses a fixed-window method with a precomputed power table and Montgomery
/// multiplication. Window size is selected based on exponent bit-length:
/// - bits ≤ 16: window = 1
/// - bits ≤ 32: window = 2
/// - bits ≤ 128: window = 3
/// - bits ≤ 256: window = 4
/// - bits > 256: window = 5
///
/// Replaces C `BN_mod_exp_mont()` from `bn_exp.c` lines 311–485.
///
/// # Errors
///
/// Returns error if the exponent is negative or if modulus is 1 (result is always 0).
pub fn mod_exp_with_context(
    base: &BigNum,
    exp: &BigNum,
    ctx: &MontgomeryContext,
) -> CryptoResult<BigNum> {
    // Edge cases
    if exp.is_zero() {
        return Ok(BigNum::one());
    }
    if exp.is_negative() {
        return Err(BigNumError::InvalidArgument(
            "negative exponent requires modular inverse".into(),
        )
        .into());
    }
    if ctx.modulus().is_one() {
        return Ok(BigNum::zero());
    }

    let exp_uint = exp
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;
    let total_bits = exp_uint.bits();
    if total_bits == 0 {
        return Ok(BigNum::one());
    }
    let exp_bits_u32 = u32::try_from(total_bits).map_err(|_| BigNumError::Overflow)?;
    let window = window_bits_for_exp_size(exp_bits_u32);

    debug!(
        exp_bits = exp_bits_u32,
        window = window,
        "mod_exp_with_context: fixed-window Montgomery exponentiation"
    );

    // 1 in Montgomery form: R mod N
    let one_mont = ctx.to_montgomery(&BigNum::one())?;
    let one_mont_uint = one_mont
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;

    // base in Montgomery form: base × R mod N
    let base_mont = ctx.to_montgomery(base)?;
    let base_mont_uint = base_mont
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;

    // Build power table: table[i] = base^i × R mod N for i = 0..2^w
    let table_size = 1usize << window;
    let mut table: Vec<BigUint> = Vec::with_capacity(table_size);
    table.push(one_mont_uint.clone()); // table[0] = R mod N  (i.e., 1 in Montgomery form)
    table.push(base_mont_uint.clone()); // table[1] = base*R mod N
    for i in 2..table_size {
        let product = &table[i - 1] * &base_mont_uint;
        table.push(ctx.redc(&product)); // table[i] = base^i * R mod N
    }

    // Fixed-window scan: exponent is split into windows of w bits
    let total_bits_usize = usize::try_from(total_bits).map_err(|_| BigNumError::Overflow)?;
    let w = usize::try_from(window).map_err(|_| BigNumError::Overflow)?;
    let num_windows = (total_bits_usize + w - 1) / w;
    let mut result = one_mont_uint;

    for window_idx in (0..num_windows).rev() {
        // Square w times
        for _ in 0..w {
            let sq = &result * &result;
            result = ctx.redc(&sq);
        }

        // Extract the w-bit window value (LSB at start_bit, MSB at start_bit+w-1)
        let start_bit = window_idx * w;
        let wval = extract_window(&exp_uint, start_bit, w, total_bits_usize);

        // Multiply by table[wval]; skip if zero (variable-time optimisation)
        if wval != 0 {
            let mul_val = &result * &table[wval];
            result = ctx.redc(&mul_val);
        }
    }

    // Convert from Montgomery form: result × R⁻¹ mod N
    let result_bn = biguint_to_bignum(result);
    ctx.from_montgomery(&result_bn)
}

/// Constant-time modular exponentiation for private key operations.
///
/// Uses a fixed-window method with constant-time table lookups via
/// [`subtle::ConditionallySelectable`] to prevent timing side-channel attacks.
/// Critical for RSA private operations, DSA/ECDSA signing, and DH secret
/// computation.
///
/// The table lookup scans every table entry on every window, selecting the
/// correct entry via constant-time conditional moves. No early termination
/// or branching on secret (exponent) bits occurs.
///
/// **Note:** The constant-time guarantee covers the control-flow and table access
/// pattern; the underlying `num-bigint` arithmetic is not itself constant-time.
/// A production deployment requiring full constant-time guarantees should use a
/// dedicated constant-time bignum library.
///
/// Replaces C `BN_mod_exp_mont_consttime()` from `bn_exp.c`.
///
/// # Errors
///
/// Returns error if modulus is not positive and odd, or exponent is negative.
pub fn mod_exp_consttime(base: &BigNum, exp: &BigNum, modulus: &BigNum) -> CryptoResult<BigNum> {
    // Validate
    if modulus.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    if modulus.is_one() {
        return Ok(BigNum::zero());
    }
    if exp.is_zero() {
        return Ok(BigNum::one());
    }
    if exp.is_negative() {
        return Err(BigNumError::InvalidArgument(
            "negative exponent requires modular inverse".into(),
        )
        .into());
    }
    if !modulus.is_odd() || modulus.is_negative() {
        return Err(BigNumError::InvalidArgument(
            "constant-time modular exponentiation requires a positive odd modulus".into(),
        )
        .into());
    }

    let ctx = MontgomeryContext::new(modulus)?;

    let exp_uint = exp
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;
    let total_bits = exp_uint.bits();
    if total_bits == 0 {
        return Ok(BigNum::one());
    }
    let exp_bits_u32 = u32::try_from(total_bits).map_err(|_| BigNumError::Overflow)?;
    let window = window_bits_for_ctime_exp_size(exp_bits_u32);

    debug!(
        exp_bits = exp_bits_u32,
        window = window,
        "mod_exp_consttime: fixed-window constant-time exponentiation"
    );
    trace!("mod_exp_consttime: entry — private key operation");

    // Build power table: table[i] = base^i × R mod N
    let one_mont = ctx.to_montgomery(&BigNum::one())?;
    let one_mont_uint = one_mont
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;
    let base_mont = ctx.to_montgomery(base)?;
    let base_mont_uint = base_mont
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;

    let table_size = 1usize << window;
    let mut table: Vec<BigUint> = Vec::with_capacity(table_size);
    table.push(one_mont_uint.clone());
    table.push(base_mont_uint.clone());
    for i in 2..table_size {
        let product = &table[i - 1] * &base_mont_uint;
        table.push(ctx.redc(&product));
    }

    // Fixed-window scan with constant-time table lookup
    let total_bits_usize = usize::try_from(total_bits).map_err(|_| BigNumError::Overflow)?;
    let w = usize::try_from(window).map_err(|_| BigNumError::Overflow)?;
    let num_windows = (total_bits_usize + w - 1) / w;
    let mut result = one_mont_uint;

    for window_idx in (0..num_windows).rev() {
        // Square w times — always performed (no branching)
        for _ in 0..w {
            let sq = &result * &result;
            result = ctx.redc(&sq);
        }

        // Extract window value
        let start_bit = window_idx * w;
        let wval = extract_window(&exp_uint, start_bit, w, total_bits_usize);

        // Constant-time table lookup: scans ALL entries, selecting by index
        let power = ct_select_biguint(&table, wval);

        // Always multiply — no branching on window value
        let mul_val = &result * &power;
        result = ctx.redc(&mul_val);
    }

    trace!("mod_exp_consttime: exit");

    let result_bn = biguint_to_bignum(result);
    ctx.from_montgomery(&result_bn)
}

/// Compute (base1^exp1 × base2^exp2) mod modulus.
///
/// More efficient than computing each exponentiation separately when
/// both share the same modulus (e.g., DSA verification: `g^u1 × y^u2 mod p`).
/// Uses an interleaved binary method with a single Montgomery context,
/// scanning both exponents simultaneously from MSB to LSB.
///
/// Replaces C `BN_mod_exp2_mont()` from `bn_exp2.c`.
///
/// # Errors
///
/// Returns error if modulus is zero, or either exponent is negative.
pub fn mod_exp2(
    base1: &BigNum,
    exp1: &BigNum,
    base2: &BigNum,
    exp2: &BigNum,
    modulus: &BigNum,
) -> CryptoResult<BigNum> {
    // Validate
    if modulus.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    if modulus.is_one() {
        return Ok(BigNum::zero());
    }
    if exp1.is_negative() || exp2.is_negative() {
        return Err(BigNumError::InvalidArgument(
            "negative exponent not supported in mod_exp2".into(),
        )
        .into());
    }

    // Handle degenerate cases
    if exp1.is_zero() && exp2.is_zero() {
        return Ok(BigNum::one());
    }
    if exp1.is_zero() {
        return mod_exp(base2, exp2, modulus);
    }
    if exp2.is_zero() {
        return mod_exp(base1, exp1, modulus);
    }

    // For odd positive modulus, use Montgomery interleaved binary method
    if modulus.is_odd() && !modulus.is_negative() {
        return mod_exp2_montgomery(base1, exp1, base2, exp2, modulus);
    }

    // Even modulus fallback: compute separately and combine
    let r1 = mod_exp(base1, exp1, modulus)?;
    let r2 = mod_exp(base2, exp2, modulus)?;
    let product = r1.inner() * r2.inner();
    let result = product.mod_floor(modulus.inner());
    Ok(BigNum::from_inner(result))
}

/// Simple (non-Montgomery) exponentiation: base^exp.
///
/// For cases where no modulus is used. Implements left-to-right binary
/// square-and-multiply. Result grows exponentially so the exponent is capped
/// at 65 536 bits (matching C `BN_exp()` limits in `bn_exp.c`).
///
/// Replaces C `BN_exp()` from `bn_exp.c`.
///
/// # Errors
///
/// Returns error if exponent is negative or too large.
pub fn exp(base: &BigNum, power: &BigNum) -> CryptoResult<BigNum> {
    if power.is_negative() {
        return Err(BigNumError::InvalidArgument(
            "negative exponent not supported without modulus".into(),
        )
        .into());
    }
    if power.is_zero() {
        return Ok(BigNum::one());
    }
    if base.is_zero() {
        return Ok(BigNum::zero());
    }

    let power_uint = power
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;
    let power_bits = power_uint.bits();

    // Sanity check: matches C BN_exp() limit — without modular reduction the
    // result size grows exponentially, so cap the exponent.
    let power_bytes = (power_bits + 7) / 8;
    if power_bits > 65536 || power_bytes > 256 {
        return Err(BigNumError::BigNumTooLong.into());
    }

    debug!(
        power_bits = power_bits,
        "exp: left-to-right square-and-multiply"
    );

    // Left-to-right binary method (from bn_exp.c BN_exp)
    let base_int = base.inner().clone();
    let mut result = BigInt::one();

    for bit_pos in (0..power_bits).rev() {
        // Square
        result = &result * &result;
        // Multiply if bit is set
        if power_uint.bit(bit_pos) {
            result = &result * &base_int;
        }
    }

    Ok(BigNum::from_inner(result))
}

// ---------------------------------------------------------------------------
// Reciprocal Division Context (from bn_recp.c)
// ---------------------------------------------------------------------------

/// Reciprocal-based division context for repeated division by the same divisor.
///
/// Precomputes the reciprocal of a divisor to replace division with multiplication.
/// Used as an alternative to Montgomery when the modulus is even, or for specific
/// internal optimisations where repeated division by the same value is needed.
///
/// Replaces C `BN_RECP_CTX` from `bn_recp.c`.
#[derive(Debug, Clone)]
pub struct ReciprocalContext {
    /// The divisor N.
    divisor: BigNum,
    /// Precomputed reciprocal: ⌊2^(2 × `num_bits`) / N⌋.
    reciprocal: BigNum,
    /// Number of significant bits in the divisor.
    num_bits: u32,
    /// Shift amount = `num_bits` (used in the quotient approximation).
    shift: u32,
}

impl ReciprocalContext {
    /// Create a new reciprocal context for the given divisor.
    ///
    /// Precomputes ⌊2^(2k) / divisor⌋ where k = `num_bits(divisor)`.
    ///
    /// Replaces C `BN_RECP_CTX_new()` + `BN_RECP_CTX_set()` from `bn_recp.c`.
    ///
    /// # Errors
    ///
    /// Returns error if divisor is zero or negative.
    pub fn new(divisor: &BigNum) -> CryptoResult<Self> {
        if divisor.is_zero() {
            return Err(BigNumError::DivisionByZero.into());
        }
        if divisor.is_negative() {
            return Err(BigNumError::NegativeNotAllowed.into());
        }

        let d_bits = divisor.num_bits();
        let shift = d_bits;

        debug!(
            divisor_bits = d_bits,
            "ReciprocalContext: computing reciprocal"
        );

        // reciprocal = ⌊2^(2 × d_bits) / divisor⌋
        let shift_usize =
            usize::try_from(u64::from(d_bits) * 2).map_err(|_| BigNumError::Overflow)?;
        let numerator = BigInt::one() << shift_usize;
        let reciprocal_int = &numerator / divisor.inner();
        let reciprocal = BigNum::from_inner(reciprocal_int);

        trace!(shift = shift, "ReciprocalContext created");

        Ok(Self {
            divisor: BigNum::from_inner(divisor.inner().clone()),
            reciprocal,
            num_bits: d_bits,
            shift,
        })
    }

    /// Get the number of significant bits in the divisor.
    ///
    /// Exposed for diagnostic and testing purposes.
    pub fn num_bits(&self) -> u32 {
        self.num_bits
    }

    /// Compute quotient and remainder of `a` divided by the stored divisor.
    ///
    /// Returns `(quotient, remainder)` such that `a = quotient × divisor + remainder`
    /// and `0 ≤ remainder < divisor`.
    ///
    /// Uses the precomputed reciprocal for a fast approximation, then corrects
    /// with at most 2–3 adjustment iterations (matching C `BN_div_recp()` from
    /// `bn_recp.c`).
    ///
    /// # Errors
    ///
    /// Returns error on arithmetic overflow.
    pub fn div_rem(&self, a: &BigNum) -> CryptoResult<(BigNum, BigNum)> {
        trace!("ReciprocalContext: computing quotient and remainder");

        let double_shift = u64::from(self.shift) * 2;
        let shift_usize = usize::try_from(double_shift).map_err(|_| BigNumError::Overflow)?;

        // q_approx = (a × reciprocal) >> (2 × shift)
        let product = a.inner() * self.reciprocal.inner();
        let mut q = &product >> shift_usize;
        let mut r = a.inner() - &q * self.divisor.inner();

        // Correction loop — at most 3 upward and 3 downward iterations
        // (matches the correction behaviour of C BN_div_recp)
        let zero = BigInt::zero();
        let one_int = BigInt::one();
        let mut corrections: u32 = 0;
        while r >= *self.divisor.inner() && corrections < 3 {
            r -= self.divisor.inner();
            q += &one_int;
            corrections += 1;
        }
        while r < zero && corrections < 6 {
            r += self.divisor.inner();
            q -= &one_int;
            corrections += 1;
        }

        Ok((BigNum::from_inner(q), BigNum::from_inner(r)))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Select window size for variable-time modular exponentiation.
///
/// Matches C `BN_window_bits_for_exponent_size()` from `bn_exp.c`.
fn window_bits_for_exp_size(bits: u32) -> u32 {
    if bits <= 16 {
        1
    } else if bits <= 32 {
        2
    } else if bits <= 128 {
        3
    } else if bits <= 256 {
        4
    } else {
        5
    }
}

/// Select window size for constant-time modular exponentiation.
///
/// Uses the same sizing as the variable-time variant (from `bn_exp.c`).
fn window_bits_for_ctime_exp_size(bits: u32) -> u32 {
    // The C constant-time variant uses the same table sizes
    if bits <= 16 {
        1
    } else if bits <= 32 {
        2
    } else if bits <= 128 {
        3
    } else if bits <= 256 {
        4
    } else {
        5
    }
}

/// Extract a window of `w` bits from `val` starting at bit position `start_bit`.
///
/// Bits are numbered from LSB (bit 0) to MSB. The returned value has the bit
/// at `start_bit` as its bit 0, the bit at `start_bit + 1` as its bit 1, etc.
fn extract_window(val: &BigUint, start_bit: usize, w: usize, total_bits: usize) -> usize {
    let mut wval: usize = 0;
    for bit_offset in 0..w {
        let bit_pos = start_bit + bit_offset;
        if bit_pos < total_bits {
            let pos_u64 = u64::try_from(bit_pos).unwrap_or(u64::MAX);
            if val.bit(pos_u64) {
                wval |= 1 << bit_offset;
            }
        }
    }
    wval
}

/// Constant-time table lookup for [`BigUint`] values.
///
/// Scans the entire table, selecting the entry at `index` via byte-level
/// conditional assignment using [`subtle::ConditionallySelectable`]. The access
/// pattern is identical regardless of the index, preventing cache-timing attacks.
fn ct_select_biguint(table: &[BigUint], index: usize) -> BigUint {
    // Determine the maximum byte-length across all table entries to ensure
    // constant-size processing.
    let max_bytes = table
        .iter()
        .map(|x| x.to_bytes_be().len())
        .max()
        .unwrap_or(1)
        .max(1); // At least 1 byte to avoid empty result

    let mut result_bytes = vec![0u8; max_bytes];

    for (i, entry) in table.iter().enumerate() {
        let entry_bytes = entry.to_bytes_be();
        // Constant-time index comparison via subtle::ConstantTimeEq
        let choice: Choice = (i as u64).ct_eq(&(index as u64));
        let offset = max_bytes.saturating_sub(entry_bytes.len());

        for (j, rb) in result_bytes.iter_mut().enumerate() {
            let entry_byte = if j >= offset {
                entry_bytes[j - offset]
            } else {
                0u8
            };
            rb.conditional_assign(&entry_byte, choice);
        }
    }

    BigUint::from_bytes_be(&result_bytes)
}

/// Reduce a [`BigNum`] modulo `modulus` (as [`BigUint`]) and return the non-negative
/// remainder as a [`BigUint`].
///
/// Handles negative inputs by computing the floor-modulus, which always yields
/// a non-negative result for a positive modulus.
fn to_biguint_reduced(bn: &BigNum, modulus: &BigUint) -> CryptoResult<BigUint> {
    // Fast path: non-negative input — convert directly and reduce
    if let Some(bn_uint) = bn.inner().to_biguint() {
        return Ok(&bn_uint % modulus);
    }
    // Negative input: compute non-negative floor remainder via BigInt
    let n_int = BigInt::from(modulus.clone());
    let reduced = bn.inner().mod_floor(&n_int);
    reduced.to_biguint().ok_or_else(|| {
        CryptoError::from(BigNumError::InvalidArgument(
            "unexpected negative value after modular reduction".into(),
        ))
    })
}

/// Convert a [`BigUint`] to a [`BigNum`] (wrapping as a non-negative [`BigInt`]).
fn biguint_to_bignum(val: BigUint) -> BigNum {
    BigNum::from_inner(BigInt::from(val))
}

/// Binary (right-to-left) modular exponentiation without Montgomery form.
///
/// Used as a fallback for even moduli where Montgomery is not applicable.
fn binary_mod_exp(base: &BigNum, exp: &BigNum, modulus: &BigNum) -> CryptoResult<BigNum> {
    let mod_int = modulus.inner();
    if mod_int.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let abs_mod = if modulus.is_negative() {
        BigNum::from_inner(-mod_int).inner().clone()
    } else {
        mod_int.clone()
    };
    if abs_mod.is_one() {
        return Ok(BigNum::zero());
    }

    let exp_uint = exp
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;
    let exp_bits = exp_uint.bits();

    let mut result = BigInt::one();
    let mut b = base.inner().mod_floor(&abs_mod);

    // Right-to-left binary method: scan LSB to MSB
    for bit_pos in 0..exp_bits {
        if exp_uint.bit(bit_pos) {
            result = (&result * &b).mod_floor(&abs_mod);
        }
        b = (&b * &b).mod_floor(&abs_mod);
    }

    Ok(BigNum::from_inner(result))
}

/// Montgomery interleaved dual-base exponentiation.
///
/// Computes (base1^exp1 × base2^exp2) mod modulus with a single Montgomery
/// context, scanning both exponents simultaneously from MSB to LSB.
fn mod_exp2_montgomery(
    base1: &BigNum,
    exp1: &BigNum,
    base2: &BigNum,
    exp2: &BigNum,
    modulus: &BigNum,
) -> CryptoResult<BigNum> {
    let ctx = MontgomeryContext::new(modulus)?;

    let exp1_uint = exp1
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;
    let exp2_uint = exp2
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;

    // Convert both bases to Montgomery form
    let b1_mont = ctx.to_montgomery(base1)?;
    let b2_mont = ctx.to_montgomery(base2)?;
    let b1_uint = b1_mont
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;
    let b2_uint = b2_mont
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;

    // 1 in Montgomery form
    let one_mont = ctx.to_montgomery(&BigNum::one())?;
    let mut result = one_mont
        .inner()
        .to_biguint()
        .ok_or(BigNumError::NegativeNotAllowed)?;

    let max_bits = std::cmp::max(exp1_uint.bits(), exp2_uint.bits());
    debug!(
        max_bits = max_bits,
        "mod_exp2: interleaved binary exponentiation"
    );

    // Interleaved binary method: scan both exponents MSB → LSB
    for bit_pos in (0..max_bits).rev() {
        // Square
        let sq = &result * &result;
        result = ctx.redc(&sq);

        // Multiply by base1^(bit of exp1)
        if exp1_uint.bit(bit_pos) {
            let mul = &result * &b1_uint;
            result = ctx.redc(&mul);
        }

        // Multiply by base2^(bit of exp2)
        if exp2_uint.bit(bit_pos) {
            let mul = &result * &b2_uint;
            result = ctx.redc(&mul);
        }
    }

    // Convert from Montgomery form
    let result_bn = biguint_to_bignum(result);
    ctx.from_montgomery(&result_bn)
}
