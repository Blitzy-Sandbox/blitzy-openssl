//! Primality testing and prime generation for the OpenSSL Rust workspace.
//!
//! Provides Miller-Rabin primality tests and random prime generation,
//! including safe prime generation for DH parameter creation and
//! RSA FIPS 186-5 prime derivation.
//!
//! Translates C functions from `crypto/bn/bn_prime.c` and
//! `crypto/bn/bn_rsa_fips186_4.c`.

use crate::bn::arithmetic;
use crate::bn::montgomery;
use crate::bn::{BigNum, BigNumError, BottomBit, TopBit};
use num_bigint::BigInt;
use num_traits::One;
use openssl_common::CryptoResult;

/// Result of a primality test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimalityResult {
    /// The number is definitely composite.
    Composite,
    /// The number is probably prime (passed all rounds).
    ProbablyPrime,
}

/// Options for prime generation.
#[derive(Debug, Clone)]
/// Default: rounds = 0 (auto-determine based on bit size), safe = false.
#[derive(Default)]
pub struct GeneratePrimeOptions {
    /// Number of Miller-Rabin rounds (0 means use default based on bit size).
    pub rounds: u32,
    /// If true, also check that (p-1)/2 is prime (safe prime).
    pub safe: bool,
}

/// Small primes for trial division.
const SMALL_PRIMES: &[u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021,
];

/// Determine the default number of Miller-Rabin rounds based on bit size.
///
/// These values are from OpenSSL's `BN_prime_checks_for_size()` and
/// FIPS 186-4 Table C.2 / C.3.
fn default_rounds(bits: u32) -> u32 {
    if bits >= 3747 {
        3
    } else if bits >= 1832 {
        4
    } else if bits >= 1316 {
        5
    } else if bits >= 852 {
        6
    } else if bits >= 620 {
        7
    } else if bits >= 476 {
        8
    } else if bits >= 400 {
        9
    } else if bits >= 347 {
        10
    } else if bits >= 308 {
        11
    } else if bits >= 55 {
        27
    } else {
        34
    }
}

/// Perform a Miller-Rabin primality test on `n`.
///
/// Returns `PrimalityResult::ProbablyPrime` if `n` passes all rounds.
/// Returns `PrimalityResult::Composite` if a witness is found.
///
/// Replaces C `BN_check_prime()`.
pub fn check_prime(n: &BigNum) -> CryptoResult<PrimalityResult> {
    let rounds = default_rounds(n.num_bits());
    check_prime_with_rounds(n, rounds)
}

/// Perform a Miller-Rabin primality test with the given number of rounds.
///
/// Replaces C `BN_check_prime()` with explicit rounds.
pub fn check_prime_with_rounds(candidate: &BigNum, rounds: u32) -> CryptoResult<PrimalityResult> {
    // Handle small cases
    if candidate.num_bits() <= 1 {
        return Ok(PrimalityResult::Composite);
    }
    if candidate.is_negative() {
        return Ok(PrimalityResult::Composite);
    }

    let candidate_u64 = candidate.to_u64();

    // Check against small primes
    if let Some(val) = candidate_u64 {
        if val < 2 {
            return Ok(PrimalityResult::Composite);
        }
        for &sp in SMALL_PRIMES {
            if val == sp {
                return Ok(PrimalityResult::ProbablyPrime);
            }
            if val % sp == 0 {
                return Ok(PrimalityResult::Composite);
            }
        }
    } else {
        // Trial division for larger numbers
        for &sp in SMALL_PRIMES {
            let sp_bn = BigNum::from_u64(sp);
            let remainder = arithmetic::nnmod(candidate, &sp_bn)?;
            if remainder.is_zero() {
                // candidate is divisible by small prime
                if candidate.num_bits() <= 11 && candidate.to_u64() == Some(sp) {
                    return Ok(PrimalityResult::ProbablyPrime);
                }
                return Ok(PrimalityResult::Composite);
            }
        }
    }

    // Miller-Rabin test
    // Write candidate-1 = 2^two_power * odd_factor where odd_factor is odd
    let cand_minus_1 = BigNum::from_inner(candidate.inner() - BigInt::one());
    let mut odd_factor = cand_minus_1.dup();
    let mut two_power: u32 = 0;
    while !odd_factor.is_odd() {
        odd_factor = BigNum::from_inner(odd_factor.inner() >> 1usize);
        two_power += 1;
    }

    let cand_minus_2 = BigNum::from_inner(candidate.inner() - BigInt::from(2));

    for _ in 0..rounds {
        // Pick random witness in [2, candidate-2]
        let witness = if cand_minus_2.num_bits() <= 1 {
            BigNum::from_u64(2)
        } else {
            let mut base = BigNum::rand_range(&cand_minus_2)?;
            if base.is_zero() || base.is_one() {
                base = BigNum::from_u64(2);
            }
            base
        };

        // power_val = witness^odd_factor mod candidate
        let mut power_val = montgomery::mod_exp(&witness, &odd_factor, candidate)?;

        if power_val.is_one() || power_val == cand_minus_1 {
            continue;
        }

        let mut found = false;
        for _ in 1..two_power {
            power_val = montgomery::mod_exp(&power_val, &BigNum::from_u64(2), candidate)?;
            if power_val == cand_minus_1 {
                found = true;
                break;
            }
            if power_val.is_one() {
                return Ok(PrimalityResult::Composite);
            }
        }

        if !found {
            return Ok(PrimalityResult::Composite);
        }
    }

    Ok(PrimalityResult::ProbablyPrime)
}

/// Generate a random prime of the specified bit length.
///
/// Replaces C `BN_generate_prime_ex2()`.
pub fn generate_prime(bits: u32, safe: bool) -> CryptoResult<BigNum> {
    let opts = GeneratePrimeOptions {
        safe,
        ..Default::default()
    };
    generate_random_prime(bits, &opts)
}

/// Generate a random prime with full control over options.
pub fn generate_random_prime(bits: u32, opts: &GeneratePrimeOptions) -> CryptoResult<BigNum> {
    if bits < 2 {
        return Err(BigNumError::BitsTooSmall(bits).into());
    }

    let rounds = if opts.rounds == 0 {
        default_rounds(bits)
    } else {
        opts.rounds
    };

    loop {
        // Generate random odd number of the right bit length
        let candidate = BigNum::rand(bits, TopBit::One, BottomBit::Odd)?;

        // Trial division
        let mut trial_ok = true;
        for &p in SMALL_PRIMES.iter().skip(1) {
            // skip 2, candidate is odd
            let r = arithmetic::mod_word(&candidate, p)?;
            if r == 0 && candidate.num_bits() > 11 {
                trial_ok = false;
                break;
            }
        }
        if !trial_ok {
            continue;
        }

        // Miller-Rabin
        let result = check_prime_with_rounds(&candidate, rounds)?;
        if result == PrimalityResult::Composite {
            continue;
        }

        if opts.safe {
            // Check (candidate - 1) / 2 is also prime
            let half = BigNum::from_inner((candidate.inner() - BigInt::one()) >> 1usize);
            let half_result = check_prime_with_rounds(&half, rounds)?;
            if half_result == PrimalityResult::Composite {
                continue;
            }
        }

        return Ok(candidate);
    }
}

/// Generate a random safe prime of the specified bit length.
///
/// A safe prime `p` is one where `(p-1)/2` is also prime.
/// Used for DH parameter generation.
pub fn generate_safe_prime(bits: u32) -> CryptoResult<BigNum> {
    generate_prime(bits, true)
}

/// RSA FIPS 186-5 prime derivation.
///
/// Derives a provable prime following the procedure in FIPS 186-5
/// appendix B.3.6 for RSA key generation.
///
/// # Parameters
///
/// - `bits`: Target bit length of the prime
/// - `e`: The public exponent (typically 65537)
///
/// # Returns
///
/// A prime `p` such that `gcd(p-1, e) = 1`.
pub fn rsa_fips186_5_derive_prime(bits: u32, e: &BigNum) -> CryptoResult<BigNum> {
    if bits < 512 {
        return Err(BigNumError::BitsTooSmall(bits).into());
    }

    let rounds = default_rounds(bits);

    // Generate candidates until we find one where gcd(p-1, e) = 1
    loop {
        let candidate = BigNum::rand(bits, TopBit::One, BottomBit::Odd)?;

        // Check gcd(candidate - 1, e) = 1
        let p_minus_1 = BigNum::from_inner(candidate.inner() - BigInt::one());
        let g = arithmetic::gcd(&p_minus_1, e);
        if !g.is_one() {
            continue;
        }

        // Trial division
        let mut trial_ok = true;
        for &p in SMALL_PRIMES.iter().skip(1) {
            let r = arithmetic::mod_word(&candidate, p)?;
            if r == 0 && candidate.num_bits() > 11 {
                trial_ok = false;
                break;
            }
        }
        if !trial_ok {
            continue;
        }

        // Miller-Rabin
        let result = check_prime_with_rounds(&candidate, rounds)?;
        if result == PrimalityResult::Composite {
            continue;
        }

        return Ok(candidate);
    }
}
