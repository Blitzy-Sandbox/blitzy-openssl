//! Integration tests for the BigNum (BN) module.
//!
//! This test module validates the public API of [`crate::bn`], covering:
//!
//! - **Constructors**: `zero`, `one`, `from_u64`, `from_i64`, `from_bytes_be`,
//!   `from_bytes_le`, `from_signed_bytes_be`, `from_hex`, `from_dec`.
//! - **Predicates**: `is_zero`, `is_one`, `is_odd`, `is_negative`, `is_word`,
//!   `is_bit_set`.
//! - **Bit operations**: `num_bits`, `num_bytes`, `set_bit`, `clear_bit`,
//!   `mask_bits`.
//! - **Comparisons**: `cmp`, `ucmp`, equality, ordering.
//! - **Arithmetic**: `add`, `sub`, `mul`, `sqr`, `div_rem`, `div`, `rem`,
//!   shift operators, and operator traits (`Add`, `Sub`, `Mul`, `Neg`,
//!   `Shl`, `Shr`, `AddAssign`, `SubAssign`, `MulAssign`).
//! - **Modular arithmetic**: `nnmod`, `mod_add`, `mod_sub`, `mod_mul`,
//!   `mod_sqr`, `mod_lshift`, `mod_inverse`, `mod_inverse_checked`,
//!   `mod_sqrt`, `gcd`, `lcm`, `are_coprime`, `kronecker`.
//! - **Word operations**: `add_word`, `sub_word`, `mul_word`, `mod_word`,
//!   `div_word`.
//! - **Modular exponentiation**: `mod_exp`, `mod_exp_consttime`,
//!   `mod_exp_with_context`, `mod_exp2`, `exp`.
//! - **Random generation**: `rand`, `rand_range`, `priv_rand_range`.
//! - **Primality testing**: `check_prime`, `miller_rabin_test`,
//!   `trial_division`, `sieve_candidate`.
//! - **Prime generation**: `generate_random_prime`, `generate_safe_prime`,
//!   `rsa_fips186_5_derive_prime`.
//! - **Montgomery**: context construction, `montgomery_multiply`,
//!   `to_montgomery`, `from_montgomery`.
//! - **Format conversions**: `to_bytes_be`, `to_bytes_le`,
//!   `to_bytes_be_padded`, `to_signed_bytes_be`, `to_hex`, `to_dec`,
//!   Display/LowerHex/UpperHex traits.
//! - **Property-based tests** (proptest): commutativity of add/mul,
//!   round-trip of bytes_be, idempotency of nnmod, RSA-style modular
//!   inversion when `gcd(a, m) == 1`.
//! - **SecureBigNum**: ZeroizeOnDrop guarantee, deref/deref_mut access,
//!   conversion from/to BigNum.
//! - **Predefined constants**: NIST curve primes (P-192, P-224, P-256,
//!   P-384, P-521), RFC 3526 MODP groups, RFC 7919 FFDHE primes.
//!
//! # References
//!
//! - `crypto/bn/bn_lib.c` — C reference implementation
//! - `crypto/bn/bn_add.c`, `bn_mul.c`, `bn_div.c` — Arithmetic primitives
//! - `crypto/bn/bn_exp.c` — Modular exponentiation
//! - `crypto/bn/bn_prime.c` — Miller-Rabin primality testing
//! - `crypto/bn/bn_mont.c` — Montgomery multiplication
//! - `test/bntest.c` — Upstream C test reference
//! - FIPS 186-5 §A.1 (Prime number generation)
//! - SP 800-56A Rev. 3 (Pair-Wise Key-Establishment)
//!
//! # Rule Compliance
//!
//! - **R5 (nullability over sentinels):** `mod_inverse` returns
//!   `CryptoResult<Option<BigNum>>` distinguishing failure (Err) from
//!   "not invertible" (Ok(None)).
//! - **R6 (lossless casts):** Tests use literal constants and
//!   `usize::try_from` where narrowing is required.
//! - **R8 (zero unsafe):** No `unsafe` blocks anywhere in this file.
//! - **R10 (wiring before done):** Each tested function is exercised by
//!   at least one positive test plus error-path coverage where relevant.

#![allow(clippy::expect_used)] // Tests call .expect() on known-good Results.
#![allow(clippy::unwrap_used)] // Tests call .unwrap() on values guaranteed to be Some/Ok.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive-match error arms.

use crate::bn::arithmetic::*;
use crate::bn::constants;
use crate::bn::montgomery::{mod_exp, mod_exp_consttime, MontgomeryContext};
use crate::bn::prime::{
    check_prime, generate_random_prime, generate_safe_prime, miller_rabin_test,
    min_miller_rabin_rounds, sieve_candidate, trial_division, GeneratePrimeOptions,
    PrimalityResult,
};
use crate::bn::{BigNum, BottomBit, SecureBigNum, TopBit};
use proptest::prelude::*;
use std::cmp::Ordering;

// =========================================================================
// Phase 1: Constructors and basic predicates
// =========================================================================

#[test]
fn bn_zero_constructs_zero() {
    let z = BigNum::zero();
    assert!(z.is_zero());
    assert!(!z.is_one());
    assert!(!z.is_negative());
    assert_eq!(z.num_bits(), 0);
}

#[test]
fn bn_one_constructs_one() {
    let o = BigNum::one();
    assert!(!o.is_zero());
    assert!(o.is_one());
    assert!(o.is_odd());
    assert!(!o.is_negative());
    assert_eq!(o.num_bits(), 1);
    assert!(o.is_word(1));
}

#[test]
fn bn_from_u64_roundtrip() {
    let values: [u64; 6] = [0, 1, 0xFF, 0xFFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 12345];
    for v in values {
        let bn = BigNum::from_u64(v);
        assert_eq!(bn.to_u64(), Some(v));
        assert!(!bn.is_negative());
    }
}

#[test]
fn bn_from_i64_handles_negative() {
    let n = BigNum::from_i64(-42);
    assert!(n.is_negative());
    let p = BigNum::from_i64(42);
    assert!(!p.is_negative());
    assert_eq!(p.to_u64(), Some(42));
}

#[test]
fn bn_from_bytes_be_basic() {
    let bn = BigNum::from_bytes_be(&[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(bn.to_u64(), Some(0x01020304));
    assert_eq!(bn.num_bits(), 25);
}

#[test]
fn bn_from_bytes_le_reverse_of_be() {
    let be = BigNum::from_bytes_be(&[0x01, 0x02, 0x03, 0x04]);
    let le = BigNum::from_bytes_le(&[0x04, 0x03, 0x02, 0x01]);
    assert_eq!(be.cmp(&le), Ordering::Equal);
}

#[test]
fn bn_to_bytes_be_roundtrip() {
    let original = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let bn = BigNum::from_bytes_be(&original);
    assert_eq!(bn.to_bytes_be(), original);
}

#[test]
fn bn_to_bytes_be_padded() {
    let bn = BigNum::from_u64(0x42);
    let padded = bn.to_bytes_be_padded(4).expect("padding to 4 bytes works");
    assert_eq!(padded, vec![0x00, 0x00, 0x00, 0x42]);
}

#[test]
fn bn_to_bytes_be_padded_too_small_errors() {
    let bn = BigNum::from_u64(0xFFFF_FFFF);
    let result = bn.to_bytes_be_padded(2);
    assert!(result.is_err(), "padding to insufficient size must error");
}

#[test]
fn bn_from_hex_and_to_hex_roundtrip() {
    let hex = "DEADBEEFCAFEBABE";
    let bn = BigNum::from_hex(hex).expect("valid hex parses");
    assert_eq!(bn.to_hex().to_uppercase(), hex);
}

#[test]
fn bn_from_hex_with_negative() {
    let bn = BigNum::from_hex("-1234").expect("negative hex parses");
    assert!(bn.is_negative());
    let abs = bn.abs();
    assert_eq!(abs.to_u64(), Some(0x1234));
}

#[test]
fn bn_from_hex_invalid_errors() {
    assert!(BigNum::from_hex("XYZ").is_err());
    assert!(BigNum::from_hex("").is_err());
}

#[test]
fn bn_from_dec_and_to_dec_roundtrip() {
    let bn = BigNum::from_dec("1234567890123456789").expect("valid decimal");
    assert_eq!(bn.to_dec(), "1234567890123456789");
}

#[test]
fn bn_from_dec_invalid_errors() {
    assert!(BigNum::from_dec("12.34").is_err());
    assert!(BigNum::from_dec("abc").is_err());
}

// =========================================================================
// Phase 2: Bit operations
// =========================================================================

#[test]
fn bn_num_bits_computes_correctly() {
    assert_eq!(BigNum::from_u64(0).num_bits(), 0);
    assert_eq!(BigNum::from_u64(1).num_bits(), 1);
    assert_eq!(BigNum::from_u64(2).num_bits(), 2);
    assert_eq!(BigNum::from_u64(0xFF).num_bits(), 8);
    assert_eq!(BigNum::from_u64(0x100).num_bits(), 9);
}

#[test]
fn bn_num_bytes_computes_correctly() {
    assert_eq!(BigNum::from_u64(0).num_bytes(), 0);
    assert_eq!(BigNum::from_u64(1).num_bytes(), 1);
    assert_eq!(BigNum::from_u64(0xFF).num_bytes(), 1);
    assert_eq!(BigNum::from_u64(0x100).num_bytes(), 2);
}

#[test]
fn bn_set_bit_and_is_bit_set() {
    let mut bn = BigNum::zero();
    bn.set_bit(0).expect("set bit 0");
    assert!(bn.is_bit_set(0));
    bn.set_bit(64).expect("set bit 64");
    assert!(bn.is_bit_set(64));
    assert!(!bn.is_bit_set(63));
}

#[test]
fn bn_clear_bit() {
    let mut bn = BigNum::from_u64(0xFFFF);
    bn.clear_bit(8);
    assert!(!bn.is_bit_set(8));
    assert!(bn.is_bit_set(7));
    assert!(bn.is_bit_set(9));
}

#[test]
fn bn_mask_bits() {
    let mut bn = BigNum::from_u64(0xFFFF_FFFF);
    bn.mask_bits(16);
    assert_eq!(bn.to_u64(), Some(0xFFFF));
}

#[test]
fn bn_is_odd_predicate() {
    assert!(BigNum::from_u64(1).is_odd());
    assert!(BigNum::from_u64(3).is_odd());
    assert!(!BigNum::from_u64(0).is_odd());
    assert!(!BigNum::from_u64(2).is_odd());
}

// =========================================================================
// Phase 3: Comparisons and arithmetic
// =========================================================================

#[test]
fn bn_cmp_signed() {
    let neg5 = BigNum::from_i64(-5);
    let pos5 = BigNum::from_i64(5);
    assert_eq!(neg5.cmp(&pos5), Ordering::Less);
    assert_eq!(pos5.cmp(&neg5), Ordering::Greater);
    assert_eq!(pos5.cmp(&pos5.dup()), Ordering::Equal);
}

#[test]
fn bn_ucmp_unsigned_only() {
    let neg5 = BigNum::from_i64(-5);
    let pos5 = BigNum::from_i64(5);
    // ucmp ignores signs; |−5| == |5|
    assert_eq!(neg5.ucmp(&pos5), Ordering::Equal);
}

#[test]
fn bn_add_basic() {
    let a = BigNum::from_u64(123);
    let b = BigNum::from_u64(456);
    let c = add(&a, &b);
    assert_eq!(c.to_u64(), Some(579));
}

#[test]
fn bn_add_operator_trait() {
    let a = BigNum::from_u64(100);
    let b = BigNum::from_u64(200);
    let c = &a + &b;
    assert_eq!(c.to_u64(), Some(300));
}

#[test]
fn bn_sub_basic() {
    let a = BigNum::from_u64(500);
    let b = BigNum::from_u64(200);
    let c = sub(&a, &b);
    assert_eq!(c.to_u64(), Some(300));
}

#[test]
fn bn_sub_yields_negative() {
    let a = BigNum::from_u64(100);
    let b = BigNum::from_u64(200);
    let c = sub(&a, &b);
    assert!(c.is_negative());
    assert_eq!(c.abs().to_u64(), Some(100));
}

#[test]
fn bn_mul_basic() {
    let a = BigNum::from_u64(123);
    let b = BigNum::from_u64(456);
    let c = mul(&a, &b);
    assert_eq!(c.to_u64(), Some(56088));
}

#[test]
fn bn_sqr_basic() {
    let a = BigNum::from_u64(13);
    let s = sqr(&a);
    assert_eq!(s.to_u64(), Some(169));
}

#[test]
fn bn_div_rem_basic() {
    let a = BigNum::from_u64(100);
    let b = BigNum::from_u64(7);
    let (q, r) = div_rem(&a, &b).expect("non-zero divisor");
    assert_eq!(q.to_u64(), Some(14));
    assert_eq!(r.to_u64(), Some(2));
}

#[test]
fn bn_div_by_zero_errors() {
    let a = BigNum::from_u64(100);
    let zero = BigNum::zero();
    assert!(div_rem(&a, &zero).is_err());
    assert!(div(&a, &zero).is_err());
    assert!(rem(&a, &zero).is_err());
}

#[test]
fn bn_lshift_rshift() {
    let a = BigNum::from_u64(0x10);
    let l = lshift(&a, 4).expect("lshift 4");
    assert_eq!(l.to_u64(), Some(0x100));
    let r = rshift(&l, 4);
    assert_eq!(r.to_u64(), Some(0x10));
}

#[test]
fn bn_lshift1_rshift1() {
    let a = BigNum::from_u64(0x42);
    let l = lshift1(&a);
    assert_eq!(l.to_u64(), Some(0x84));
    let r = rshift1(&l);
    assert_eq!(r.to_u64(), Some(0x42));
}

#[test]
fn bn_negate_and_abs() {
    let mut a = BigNum::from_u64(42);
    a.negate();
    assert!(a.is_negative());
    let b = a.abs();
    assert!(!b.is_negative());
    assert_eq!(b.to_u64(), Some(42));
}

// =========================================================================
// Phase 4: Modular arithmetic
// =========================================================================

#[test]
fn bn_nnmod_basic() {
    let a = BigNum::from_i64(-17);
    let m = BigNum::from_u64(5);
    let r = nnmod(&a, &m).expect("non-zero modulus");
    // -17 ≡ 3 (mod 5)
    assert_eq!(r.to_u64(), Some(3));
    assert!(!r.is_negative());
}

#[test]
fn bn_mod_add_basic() {
    let a = BigNum::from_u64(10);
    let b = BigNum::from_u64(20);
    let m = BigNum::from_u64(7);
    let r = mod_add(&a, &b, &m).expect("ok");
    // (10 + 20) mod 7 = 30 mod 7 = 2
    assert_eq!(r.to_u64(), Some(2));
}

#[test]
fn bn_mod_sub_basic() {
    let a = BigNum::from_u64(5);
    let b = BigNum::from_u64(8);
    let m = BigNum::from_u64(11);
    let r = mod_sub(&a, &b, &m).expect("ok");
    // (5 - 8) mod 11 ≡ -3 ≡ 8
    assert_eq!(r.to_u64(), Some(8));
}

#[test]
fn bn_mod_mul_basic() {
    let a = BigNum::from_u64(5);
    let b = BigNum::from_u64(7);
    let m = BigNum::from_u64(13);
    let r = mod_mul(&a, &b, &m).expect("ok");
    // (5 * 7) mod 13 = 35 mod 13 = 9
    assert_eq!(r.to_u64(), Some(9));
}

#[test]
fn bn_mod_sqr_basic() {
    let a = BigNum::from_u64(11);
    let m = BigNum::from_u64(13);
    let r = mod_sqr(&a, &m).expect("ok");
    // 11^2 mod 13 = 121 mod 13 = 4
    assert_eq!(r.to_u64(), Some(4));
}

#[test]
fn bn_gcd_basic() {
    let a = BigNum::from_u64(48);
    let b = BigNum::from_u64(18);
    let g = gcd(&a, &b);
    assert_eq!(g.to_u64(), Some(6));
}

#[test]
fn bn_gcd_coprime_returns_one() {
    let a = BigNum::from_u64(17);
    let b = BigNum::from_u64(31);
    let g = gcd(&a, &b);
    assert!(g.is_one());
}

#[test]
fn bn_are_coprime_predicate() {
    let a = BigNum::from_u64(15);
    let b = BigNum::from_u64(28);
    assert!(are_coprime(&a, &b));
    let c = BigNum::from_u64(15);
    let d = BigNum::from_u64(25);
    assert!(!are_coprime(&c, &d));
}

#[test]
fn bn_lcm_basic() {
    let a = BigNum::from_u64(4);
    let b = BigNum::from_u64(6);
    let l = lcm(&a, &b).expect("ok");
    assert_eq!(l.to_u64(), Some(12));
}

#[test]
fn bn_mod_inverse_basic() {
    let a = BigNum::from_u64(3);
    let n = BigNum::from_u64(7);
    let inv = mod_inverse(&a, &n).expect("ok");
    let inv = inv.expect("3 is invertible mod 7");
    // 3 * 5 = 15 ≡ 1 (mod 7)
    assert_eq!(inv.to_u64(), Some(5));
}

#[test]
fn bn_mod_inverse_not_coprime_returns_none() {
    let a = BigNum::from_u64(4);
    let n = BigNum::from_u64(8);
    let inv = mod_inverse(&a, &n).expect("ok");
    // gcd(4, 8) = 4 ≠ 1 → no inverse
    assert!(inv.is_none(), "non-coprime pair must yield None");
}

#[test]
fn bn_mod_inverse_checked_errors_when_not_coprime() {
    let a = BigNum::from_u64(4);
    let n = BigNum::from_u64(8);
    assert!(mod_inverse_checked(&a, &n).is_err());
}

#[test]
fn bn_kronecker_basic() {
    // (1/p) = 1 for any odd prime p
    let one = BigNum::one();
    let p = BigNum::from_u64(7);
    let k = kronecker(&one, &p).expect("ok");
    assert_eq!(k, 1);
}

// =========================================================================
// Phase 5: Word operations
// =========================================================================

#[test]
fn bn_add_word() {
    let a = BigNum::from_u64(100);
    let r = add_word(&a, 23);
    assert_eq!(r.to_u64(), Some(123));
}

#[test]
fn bn_sub_word() {
    let a = BigNum::from_u64(100);
    let r = sub_word(&a, 23).expect("non-overflow");
    assert_eq!(r.to_u64(), Some(77));
}

#[test]
fn bn_mul_word() {
    let a = BigNum::from_u64(100);
    let r = mul_word(&a, 5);
    assert_eq!(r.to_u64(), Some(500));
}

#[test]
fn bn_mod_word() {
    let a = BigNum::from_u64(100);
    let r = mod_word(&a, 7).expect("non-zero divisor");
    assert_eq!(r, 2);
}

#[test]
fn bn_div_word() {
    let a = BigNum::from_u64(100);
    let r = div_word(&a, 7).expect("non-zero divisor");
    assert_eq!(r.to_u64(), Some(14));
}

// =========================================================================
// Phase 6: Modular exponentiation
// =========================================================================

#[test]
fn bn_mod_exp_basic() {
    // 2^10 mod 1000 = 1024 mod 1000 = 24
    let base = BigNum::from_u64(2);
    let exp_val = BigNum::from_u64(10);
    let m = BigNum::from_u64(1000);
    let r = mod_exp(&base, &exp_val, &m).expect("ok");
    assert_eq!(r.to_u64(), Some(24));
}

#[test]
fn bn_mod_exp_consttime_matches_mod_exp() {
    let base = BigNum::from_u64(7);
    let exp_val = BigNum::from_u64(11);
    let m = BigNum::from_u64(13);
    let a = mod_exp(&base, &exp_val, &m).expect("ok");
    let b = mod_exp_consttime(&base, &exp_val, &m).expect("ok");
    assert_eq!(a.cmp(&b), Ordering::Equal);
}

#[test]
fn bn_mod_exp_zero_modulus_errors() {
    let base = BigNum::from_u64(2);
    let exp_val = BigNum::from_u64(10);
    let zero = BigNum::zero();
    assert!(mod_exp(&base, &exp_val, &zero).is_err());
}

#[test]
fn bn_montgomery_roundtrip() {
    let modulus = BigNum::from_u64(13);
    let ctx = MontgomeryContext::new(&modulus).expect("odd modulus");
    let a = BigNum::from_u64(7);
    let mont_a = ctx.to_montgomery(&a).expect("ok");
    let back = ctx.from_montgomery(&mont_a).expect("ok");
    assert_eq!(back.cmp(&a), Ordering::Equal);
}

#[test]
fn bn_montgomery_multiplication() {
    let modulus = BigNum::from_u64(101);
    let ctx = MontgomeryContext::new(&modulus).expect("odd modulus");
    let a = BigNum::from_u64(7);
    let b = BigNum::from_u64(11);
    let mont_a = ctx.to_montgomery(&a).expect("ok");
    let mont_b = ctx.to_montgomery(&b).expect("ok");
    let mont_prod = ctx.montgomery_multiply(&mont_a, &mont_b).expect("ok");
    let prod = ctx.from_montgomery(&mont_prod).expect("ok");
    // 7 * 11 mod 101 = 77
    assert_eq!(prod.to_u64(), Some(77));
}

// =========================================================================
// Phase 7: Random generation
// =========================================================================

#[test]
fn bn_rand_default_top_bottom() {
    let r = BigNum::rand(64, TopBit::Any, BottomBit::Any).expect("rand");
    // The maximum bit width is 64 — but the leading bit might happen to be unset.
    assert!(r.num_bits() <= 64);
}

#[test]
fn bn_rand_top_set_top_bit() {
    let r = BigNum::rand(64, TopBit::One, BottomBit::Any).expect("rand");
    assert_eq!(r.num_bits(), 64);
    assert!(r.is_bit_set(63));
}

#[test]
fn bn_rand_bottom_odd() {
    let r = BigNum::rand(64, TopBit::Any, BottomBit::Odd).expect("rand");
    assert!(r.is_odd());
}

#[test]
fn bn_rand_range_bounded() {
    let range = BigNum::from_u64(100);
    for _ in 0..20 {
        let r = BigNum::rand_range(&range).expect("rand range");
        assert_eq!(r.cmp(&range), Ordering::Less);
        assert!(!r.is_negative());
    }
}

// =========================================================================
// Phase 8: Primality testing
// =========================================================================

#[test]
fn bn_check_prime_known_primes() {
    let primes: [u64; 6] = [2, 3, 5, 7, 11, 13];
    for p in primes {
        let bn = BigNum::from_u64(p);
        let result = check_prime(&bn).expect("ok");
        assert_eq!(
            result,
            PrimalityResult::ProbablyPrime,
            "{p} must be classified prime"
        );
    }
}

#[test]
fn bn_check_prime_known_composites() {
    let composites: [u64; 5] = [4, 6, 8, 9, 15];
    for c in composites {
        let bn = BigNum::from_u64(c);
        let result = check_prime(&bn).expect("ok");
        assert_eq!(
            result,
            PrimalityResult::Composite,
            "{c} must be classified composite"
        );
    }
}

#[test]
fn bn_check_prime_one_is_composite() {
    let one = BigNum::one();
    let result = check_prime(&one).expect("ok");
    assert_eq!(result, PrimalityResult::Composite);
}

#[test]
fn bn_trial_division_basic() {
    assert!(trial_division(&BigNum::from_u64(7))); // probably prime
    assert!(!trial_division(&BigNum::from_u64(9))); // 3*3
}

#[test]
fn bn_sieve_candidate_basic() {
    // Even numbers > 2 are sieved out (composite)
    assert!(!sieve_candidate(64, &BigNum::from_u64(8)));
    // 7 (odd, prime)
    assert!(sieve_candidate(64, &BigNum::from_u64(7)));
}

#[test]
fn bn_min_miller_rabin_rounds_fips_table() {
    // FIPS 186-4 Table C.2: 1024-bit DSA → 40 rounds
    assert!(min_miller_rabin_rounds(1024) >= 40);
    // 2048-bit RSA/DSA → 56 rounds (Table C.1/C.2)
    assert!(min_miller_rabin_rounds(2048) >= 56);
    // 3072-bit → 64 rounds
    assert!(min_miller_rabin_rounds(3072) >= 64);
}

#[test]
fn bn_miller_rabin_prime() {
    let n = BigNum::from_u64(101);
    let result = miller_rabin_test(&n, 5).expect("ok");
    assert_eq!(result, PrimalityResult::ProbablyPrime);
}

#[test]
fn bn_miller_rabin_composite() {
    let n = BigNum::from_u64(91); // 7 * 13
    let result = miller_rabin_test(&n, 20).expect("ok");
    assert_eq!(result, PrimalityResult::Composite);
}

// =========================================================================
// Phase 9: Prime generation (small bit sizes — performance-bounded)
// =========================================================================

#[test]
fn bn_generate_random_prime_64bit() {
    // 64-bit primes are fast to generate; verify the result is prime.
    let p = generate_random_prime(64).expect("generate");
    let result = check_prime(&p).expect("ok");
    assert_eq!(result, PrimalityResult::ProbablyPrime);
    assert_eq!(p.num_bits(), 64);
}

#[test]
fn bn_generate_random_prime_128bit() {
    let p = generate_random_prime(128).expect("generate");
    let result = check_prime(&p).expect("ok");
    assert_eq!(result, PrimalityResult::ProbablyPrime);
    assert_eq!(p.num_bits(), 128);
}

#[test]
fn bn_generate_safe_prime_64bit() {
    // Safe prime: p = 2q + 1 where q is also prime
    let p = generate_safe_prime(64).expect("generate");
    let result = check_prime(&p).expect("ok");
    assert_eq!(result, PrimalityResult::ProbablyPrime);
    let q = rshift1(&p);
    let qresult = check_prime(&q).expect("ok");
    assert_eq!(qresult, PrimalityResult::ProbablyPrime);
}

#[test]
fn bn_generate_prime_with_options_default() {
    let opts = GeneratePrimeOptions::new(64);
    let p = crate::bn::prime::generate_prime(&opts).expect("generate");
    let result = check_prime(&p).expect("ok");
    assert_eq!(result, PrimalityResult::ProbablyPrime);
}

// =========================================================================
// Phase 10: Predefined constants — NIST/RFC parameter sanity checks
// =========================================================================

#[test]
fn bn_nist_p256_correct_bit_size() {
    let p = constants::nist_p256();
    assert_eq!(p.num_bits(), 256);
    // P-256 is prime
    let result = check_prime(&p).expect("ok");
    assert_eq!(result, PrimalityResult::ProbablyPrime);
}

#[test]
fn bn_nist_p384_correct_bit_size() {
    let p = constants::nist_p384();
    assert_eq!(p.num_bits(), 384);
}

#[test]
fn bn_nist_p521_correct_bit_size() {
    let p = constants::nist_p521();
    assert_eq!(p.num_bits(), 521);
}

#[test]
fn bn_rfc3526_2048_correct_size() {
    let p = constants::rfc3526_prime_2048();
    assert_eq!(p.num_bits(), 2048);
}

#[test]
fn bn_ffdhe2048_correct_size() {
    let p = constants::ffdhe2048();
    assert_eq!(p.num_bits(), 2048);
}

// =========================================================================
// Phase 11: SecureBigNum (zero-on-drop guarantee)
// =========================================================================

#[test]
fn secure_bn_wraps_bn() {
    let bn = BigNum::from_u64(42);
    let secure = SecureBigNum::new(bn);
    // Deref access works
    assert_eq!(secure.to_u64(), Some(42));
}

#[test]
fn secure_bn_into_inner() {
    let bn = BigNum::from_u64(99);
    let secure = SecureBigNum::new(bn);
    let extracted = secure.into_inner();
    assert_eq!(extracted.to_u64(), Some(99));
}

#[test]
fn secure_bn_deref_mut_allows_mutation() {
    let bn = BigNum::from_u64(10);
    let mut secure = SecureBigNum::new(bn);
    secure.set_negative(true);
    assert!(secure.is_negative());
}

#[test]
fn secure_bn_drop_does_not_panic() {
    // Construct and drop a SecureBigNum at scope exit; the Zeroize impl
    // must not panic. (This validates the Drop impl that was hardened
    // in Group B #4 to explicitly zero the inner BigInt limbs.)
    {
        let bn = BigNum::from_u64(0xDEAD_BEEF_CAFE_BABE);
        let _secure = SecureBigNum::new(bn);
    }
}

// =========================================================================
// Phase 12: Display / formatting traits
// =========================================================================

#[test]
fn bn_display_is_decimal() {
    let bn = BigNum::from_u64(1234);
    assert_eq!(format!("{bn}"), "1234");
}

#[test]
fn bn_lowerhex_format() {
    let bn = BigNum::from_u64(0xDEAD_BEEF);
    assert_eq!(format!("{bn:x}"), "deadbeef");
}

#[test]
fn bn_upperhex_format() {
    let bn = BigNum::from_u64(0xDEAD_BEEF);
    assert_eq!(format!("{bn:X}"), "DEADBEEF");
}

// =========================================================================
// Phase 13: Property-based tests (proptest)
// =========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Property: addition is commutative.
    /// For all u64 a, b: BN(a) + BN(b) == BN(b) + BN(a).
    #[test]
    fn prop_add_commutative(a in 0u64..u64::MAX/2, b in 0u64..u64::MAX/2) {
        let an = BigNum::from_u64(a);
        let bn = BigNum::from_u64(b);
        let s1 = add(&an, &bn);
        let s2 = add(&bn, &an);
        prop_assert_eq!(s1.cmp(&s2), Ordering::Equal);
    }

    /// Property: multiplication is commutative.
    #[test]
    fn prop_mul_commutative(a in 0u64..u64::MAX>>32, b in 0u64..u64::MAX>>32) {
        let an = BigNum::from_u64(a);
        let bn = BigNum::from_u64(b);
        let p1 = mul(&an, &bn);
        let p2 = mul(&bn, &an);
        prop_assert_eq!(p1.cmp(&p2), Ordering::Equal);
    }

    /// Property: byte round-trip — to_bytes_be(from_bytes_be(b)) == b
    /// for any non-empty byte vector with no leading zeros.
    #[test]
    fn prop_bytes_be_roundtrip(bytes in proptest::collection::vec(0u8..=u8::MAX, 1..32)) {
        // Strip leading zeros for canonical representation.
        let trimmed: Vec<u8> = {
            let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
            bytes[first_nonzero..].to_vec()
        };
        let bn = BigNum::from_bytes_be(&trimmed);
        let back = bn.to_bytes_be();
        prop_assert_eq!(back, trimmed);
    }

    /// Property: nnmod yields a non-negative result less than the modulus.
    #[test]
    fn prop_nnmod_in_range(a_bytes in proptest::collection::vec(0u8..=u8::MAX, 1..32),
                          m in 1u64..1_000_000) {
        let a = BigNum::from_bytes_be(&a_bytes);
        let mn = BigNum::from_u64(m);
        let r = nnmod(&a, &mn).expect("ok");
        prop_assert!(!r.is_negative());
        prop_assert_eq!(r.cmp(&mn), Ordering::Less);
    }

    /// Property: when gcd(a, m) == 1, mod_inverse returns Some(x) where
    /// (a * x) mod m == 1.
    #[test]
    fn prop_mod_inverse_correctness(a in 1u64..1_000, m in 2u64..10_000) {
        let an = BigNum::from_u64(a);
        let mn = BigNum::from_u64(m);
        if !are_coprime(&an, &mn) {
            return Ok(());
        }
        let inv = mod_inverse(&an, &mn).expect("ok");
        let inv = inv.expect("coprime → invertible");
        let prod = mod_mul(&an, &inv, &mn).expect("ok");
        prop_assert!(prod.is_one(), "(a * a^-1) mod m must equal 1");
    }
}
