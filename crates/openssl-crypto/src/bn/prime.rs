//! Primality testing and prime number generation for the OpenSSL Rust workspace.
//!
//! Provides Miller-Rabin probabilistic primality testing, trial division sieve,
//! and prime number generation with configurable security levels. Translates
//! C functions `BN_generate_prime_ex2()`, `BN_check_prime()`,
//! `ossl_bn_miller_rabin_is_prime()`, and the small-prime sieve from
//! `crypto/bn/bn_prime.c`. Also implements RSA prime derivation from
//! `crypto/bn/bn_rsa_fips186_5.c` (FIPS 186-5 Appendix B.9).
//!
//! # Security
//!
//! - Miller-Rabin uses a minimum of 64 rounds (false positive rate ≤ 2^-128)
//!   for primes ≤ 2048 bits, and 128 rounds for larger primes (2^-256)
//!   per `min_miller_rabin_rounds()` (source: `bn_mr_min_checks()`).
//! - Trial division against the first 2048 small primes accelerates rejection
//!   of obvious composites before the expensive Miller-Rabin iterations.
//! - Random candidates generated via `BigNum::rand` (OS entropy via `rand::OsRng`).
//! - Montgomery multiplication is used for the dominant modular exponentiation
//!   step of Miller-Rabin via `MontgomeryContext` reuse across rounds.
//!
//! # References
//!
//! - FIPS 186-4 Appendix C.3.1 (Enhanced Miller-Rabin Probabilistic Primality Test)
//! - FIPS 186-5 Appendix B.9 (RSA probable prime construction)
//! - SP 800-89 Section 5.3.3 (Small prime factors product)
//!
//! # Rule Compliance
//!
//! - **R5 (Nullability):** All APIs use `CryptoResult<T>` or `PrimalityResult` —
//!   never integer sentinels like -1/0/1 to encode status.
//! - **R6 (Lossless casts):** All size/bit arithmetic uses checked conversions.
//! - **R8 (Zero unsafe):** This file contains ZERO `unsafe` blocks.
//! - **R9 (Warning-free):** All public items carry `///` doc comments.
//! - **R10 (Wiring):** Reachable via `openssl_crypto::bn::prime::*` and called
//!   from `dh.rs`, `dsa.rs`, and future RSA key generation.

use crate::bn::montgomery::MontgomeryContext;
use crate::bn::{arithmetic, BigNum, BigNumError, BottomBit, TopBit};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use openssl_common::CryptoResult;
use tracing::{debug, trace};

// ===========================================================================
// Public Types
// ===========================================================================

/// Result of a primality test.
///
/// Replaces the C convention of returning `int` where `0` means composite,
/// `1` means probably prime, and `-1` means error (Rule R5 — Nullability
/// Over Sentinels). Error conditions are expressed via `CryptoResult`'s `Err`
/// variant; this enum only represents the binary primality verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimalityResult {
    /// The number is definitely composite (a Miller-Rabin witness was found,
    /// or it was divisible by a small prime, or it is structurally invalid
    /// such as ≤ 1, negative, or even > 2).
    Composite,
    /// The number is probably prime (passed all Miller-Rabin rounds and the
    /// trial division sieve). The probability of a false positive is bounded
    /// by `2^(-2*rounds)` for randomly-chosen witnesses.
    ProbablyPrime,
}

/// Options controlling prime number generation.
///
/// Translates the parameter set of `BN_generate_prime_ex2()` from
/// `crypto/bn/bn_prime.c`. Construct via `GeneratePrimeOptions::new(bits)` or
/// directly specify fields.
///
/// # Fields
///
/// - `bits`: Required bit length of the generated prime (exact length: the
///   most-significant bit is always set). Must be ≥ 2. For safe primes, must
///   be ≥ 6 or exactly 3.
/// - `safe`: If true, generate a safe prime `p` such that `(p-1)/2` is also
///   prime (per RFC 5114, SP 800-56A for DH parameter generation).
/// - `add`: Optional congruence modulus. If `Some(a)`, the returned prime `p`
///   satisfies `p ≡ rem (mod a)` (or `p ≡ 1 (mod a)` if `rem` is `None` and
///   `safe` is false, or `p ≡ 3 (mod a)` if `safe` is true). Used by DSA
///   parameter generation where `q | (p-1)`.
/// - `rem`: Optional remainder paired with `add`. Only meaningful when `add`
///   is `Some`. If `None`, see `add` description.
#[derive(Debug, Clone)]
pub struct GeneratePrimeOptions {
    /// Exact bit length of the generated prime (MSB always set).
    pub bits: u32,
    /// If true, generate a safe prime (p where (p-1)/2 is also prime).
    pub safe: bool,
    /// Optional modulus for congruence constraint: p ≡ rem (mod add).
    pub add: Option<BigNum>,
    /// Optional remainder for congruence constraint (requires `add`).
    pub rem: Option<BigNum>,
}

impl GeneratePrimeOptions {
    /// Create default options for generating a `bits`-length random prime.
    ///
    /// Equivalent to: `GeneratePrimeOptions { bits, safe: false, add: None, rem: None }`.
    pub fn new(bits: u32) -> Self {
        Self {
            bits,
            safe: false,
            add: None,
            rem: None,
        }
    }
}

impl Default for GeneratePrimeOptions {
    /// Default options with zero bits — callers MUST override `bits` before use.
    fn default() -> Self {
        Self {
            bits: 0,
            safe: false,
            add: None,
            rem: None,
        }
    }
}

// ===========================================================================
// Small Primes Table (from crypto/bn/bn_prime.h)
// ===========================================================================

/// Number of small primes in the trial division sieve.
///
/// The C source (`crypto/bn/bn_prime.h`) is auto-generated by `bn_prime.pl`
/// and contains exactly 2048 primes from 2 through 17863.
pub const NUM_PRIMES: usize = 2048;

/// First 2048 prime numbers for trial division sieve.
///
/// Translated from the `primes[]` table in `crypto/bn/bn_prime.h`. Used by
/// `trial_division()` to quickly reject composite candidates before running
/// the expensive Miller-Rabin test. The first 1031 primes (up to prime 751)
/// are also used to form `small_prime_factors_product()` per SP 800-89.
///
/// # Range
///
/// - First prime: `2`
/// - Last prime: `17863`
/// - Total count: `2048` (`NUM_PRIMES`)
pub const SMALL_PRIMES: &[u32] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613,
    1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741,
    1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873,
    1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999,
    2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113,
    2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251,
    2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371,
    2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477,
    2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647,
    2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731,
    2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857,
    2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001,
    3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163,
    3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299,
    3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407,
    3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539,
    3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659,
    3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793,
    3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919,
    3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051,
    4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201,
    4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327,
    4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463,
    4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603,
    4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733,
    4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903,
    4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009,
    5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153,
    5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303,
    5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441,
    5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569,
    5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701,
    5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843,
    5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987,
    6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131,
    6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269,
    6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373,
    6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553,
    6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691,
    6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829,
    6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967,
    6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109,
    7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247,
    7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451,
    7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559,
    7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687,
    7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841,
    7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993,
    8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147,
    8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287,
    8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431,
    8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599,
    8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719,
    8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849,
    8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007,
    9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157,
    9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293,
    9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431,
    9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551,
    9587, 9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721,
    9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851,
    9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973, 10007,
    10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103, 10111, 10133,
    10139, 10141, 10151, 10159, 10163, 10169, 10177, 10181, 10193, 10211, 10223, 10243, 10247,
    10253, 10259, 10267, 10271, 10273, 10289, 10301, 10303, 10313, 10321, 10331, 10333, 10337,
    10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433, 10453, 10457, 10459, 10463, 10477,
    10487, 10499, 10501, 10513, 10529, 10531, 10559, 10567, 10589, 10597, 10601, 10607, 10613,
    10627, 10631, 10639, 10651, 10657, 10663, 10667, 10687, 10691, 10709, 10711, 10723, 10729,
    10733, 10739, 10753, 10771, 10781, 10789, 10799, 10831, 10837, 10847, 10853, 10859, 10861,
    10867, 10883, 10889, 10891, 10903, 10909, 10937, 10939, 10949, 10957, 10973, 10979, 10987,
    10993, 11003, 11027, 11047, 11057, 11059, 11069, 11071, 11083, 11087, 11093, 11113, 11117,
    11119, 11131, 11149, 11159, 11161, 11171, 11173, 11177, 11197, 11213, 11239, 11243, 11251,
    11257, 11261, 11273, 11279, 11287, 11299, 11311, 11317, 11321, 11329, 11351, 11353, 11369,
    11383, 11393, 11399, 11411, 11423, 11437, 11443, 11447, 11467, 11471, 11483, 11489, 11491,
    11497, 11503, 11519, 11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617, 11621, 11633,
    11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731, 11743, 11777, 11779, 11783,
    11789, 11801, 11807, 11813, 11821, 11827, 11831, 11833, 11839, 11863, 11867, 11887, 11897,
    11903, 11909, 11923, 11927, 11933, 11939, 11941, 11953, 11959, 11969, 11971, 11981, 11987,
    12007, 12011, 12037, 12041, 12043, 12049, 12071, 12073, 12097, 12101, 12107, 12109, 12113,
    12119, 12143, 12149, 12157, 12161, 12163, 12197, 12203, 12211, 12227, 12239, 12241, 12251,
    12253, 12263, 12269, 12277, 12281, 12289, 12301, 12323, 12329, 12343, 12347, 12373, 12377,
    12379, 12391, 12401, 12409, 12413, 12421, 12433, 12437, 12451, 12457, 12473, 12479, 12487,
    12491, 12497, 12503, 12511, 12517, 12527, 12539, 12541, 12547, 12553, 12569, 12577, 12583,
    12589, 12601, 12611, 12613, 12619, 12637, 12641, 12647, 12653, 12659, 12671, 12689, 12697,
    12703, 12713, 12721, 12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821, 12823,
    12829, 12841, 12853, 12889, 12893, 12899, 12907, 12911, 12917, 12919, 12923, 12941, 12953,
    12959, 12967, 12973, 12979, 12983, 13001, 13003, 13007, 13009, 13033, 13037, 13043, 13049,
    13063, 13093, 13099, 13103, 13109, 13121, 13127, 13147, 13151, 13159, 13163, 13171, 13177,
    13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259, 13267, 13291, 13297, 13309, 13313,
    13327, 13331, 13337, 13339, 13367, 13381, 13397, 13399, 13411, 13417, 13421, 13441, 13451,
    13457, 13463, 13469, 13477, 13487, 13499, 13513, 13523, 13537, 13553, 13567, 13577, 13591,
    13597, 13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681, 13687, 13691, 13693, 13697,
    13709, 13711, 13721, 13723, 13729, 13751, 13757, 13759, 13763, 13781, 13789, 13799, 13807,
    13829, 13831, 13841, 13859, 13873, 13877, 13879, 13883, 13901, 13903, 13907, 13913, 13921,
    13931, 13933, 13963, 13967, 13997, 13999, 14009, 14011, 14029, 14033, 14051, 14057, 14071,
    14081, 14083, 14087, 14107, 14143, 14149, 14153, 14159, 14173, 14177, 14197, 14207, 14221,
    14243, 14249, 14251, 14281, 14293, 14303, 14321, 14323, 14327, 14341, 14347, 14369, 14387,
    14389, 14401, 14407, 14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461, 14479, 14489,
    14503, 14519, 14533, 14537, 14543, 14549, 14551, 14557, 14561, 14563, 14591, 14593, 14621,
    14627, 14629, 14633, 14639, 14653, 14657, 14669, 14683, 14699, 14713, 14717, 14723, 14731,
    14737, 14741, 14747, 14753, 14759, 14767, 14771, 14779, 14783, 14797, 14813, 14821, 14827,
    14831, 14843, 14851, 14867, 14869, 14879, 14887, 14891, 14897, 14923, 14929, 14939, 14947,
    14951, 14957, 14969, 14983, 15013, 15017, 15031, 15053, 15061, 15073, 15077, 15083, 15091,
    15101, 15107, 15121, 15131, 15137, 15139, 15149, 15161, 15173, 15187, 15193, 15199, 15217,
    15227, 15233, 15241, 15259, 15263, 15269, 15271, 15277, 15287, 15289, 15299, 15307, 15313,
    15319, 15329, 15331, 15349, 15359, 15361, 15373, 15377, 15383, 15391, 15401, 15413, 15427,
    15439, 15443, 15451, 15461, 15467, 15473, 15493, 15497, 15511, 15527, 15541, 15551, 15559,
    15569, 15581, 15583, 15601, 15607, 15619, 15629, 15641, 15643, 15647, 15649, 15661, 15667,
    15671, 15679, 15683, 15727, 15731, 15733, 15737, 15739, 15749, 15761, 15767, 15773, 15787,
    15791, 15797, 15803, 15809, 15817, 15823, 15859, 15877, 15881, 15887, 15889, 15901, 15907,
    15913, 15919, 15923, 15937, 15959, 15971, 15973, 15991, 16001, 16007, 16033, 16057, 16061,
    16063, 16067, 16069, 16073, 16087, 16091, 16097, 16103, 16111, 16127, 16139, 16141, 16183,
    16187, 16189, 16193, 16217, 16223, 16229, 16231, 16249, 16253, 16267, 16273, 16301, 16319,
    16333, 16339, 16349, 16361, 16363, 16369, 16381, 16411, 16417, 16421, 16427, 16433, 16447,
    16451, 16453, 16477, 16481, 16487, 16493, 16519, 16529, 16547, 16553, 16561, 16567, 16573,
    16603, 16607, 16619, 16631, 16633, 16649, 16651, 16657, 16661, 16673, 16691, 16693, 16699,
    16703, 16729, 16741, 16747, 16759, 16763, 16787, 16811, 16823, 16829, 16831, 16843, 16871,
    16879, 16883, 16889, 16901, 16903, 16921, 16927, 16931, 16937, 16943, 16963, 16979, 16981,
    16987, 16993, 17011, 17021, 17027, 17029, 17033, 17041, 17047, 17053, 17077, 17093, 17099,
    17107, 17117, 17123, 17137, 17159, 17167, 17183, 17189, 17191, 17203, 17207, 17209, 17231,
    17239, 17257, 17291, 17293, 17299, 17317, 17321, 17327, 17333, 17341, 17351, 17359, 17377,
    17383, 17387, 17389, 17393, 17401, 17417, 17419, 17431, 17443, 17449, 17467, 17471, 17477,
    17483, 17489, 17491, 17497, 17509, 17519, 17539, 17551, 17569, 17573, 17579, 17581, 17597,
    17599, 17609, 17623, 17627, 17657, 17659, 17669, 17681, 17683, 17707, 17713, 17729, 17737,
    17747, 17749, 17761, 17783, 17789, 17791, 17807, 17827, 17837, 17839, 17851, 17863,
];

// Compile-time assertion that `SMALL_PRIMES` has exactly `NUM_PRIMES` entries.
// Any divergence would silently change trial-division behavior, so we fail
// fast at build time using a const assertion.
const _: () = assert!(SMALL_PRIMES.len() == NUM_PRIMES);

// ===========================================================================
// Internal Tuning / Round-Count Helpers
// ===========================================================================

/// Determine the optimal number of trial divisions for a candidate of the
/// given bit length.
///
/// Larger primes benefit from more trial division before the expensive
/// Miller-Rabin test. The thresholds are taken verbatim from
/// `calc_trial_divisions()` in `crypto/bn/bn_prime.c`.
fn calc_trial_divisions(bits: u32) -> usize {
    if bits <= 512 {
        64
    } else if bits <= 1024 {
        128
    } else if bits <= 2048 {
        384
    } else if bits <= 4096 {
        1024
    } else {
        NUM_PRIMES
    }
}

/// Minimum Miller-Rabin rounds for primes of the given bit length.
///
/// Implements the 2-tier FIPS schema (from `bn_mr_min_checks()`):
/// - `bits ≤ 2048`: 64 rounds → false-positive probability ≤ 2^-128
/// - `bits >  2048`: 128 rounds → false-positive probability ≤ 2^-256
///
/// For DH/DSA/RSA key generation, callers should use at least this many
/// rounds for security parity with FIPS 186-4.
pub fn min_miller_rabin_rounds(bits: u32) -> u32 {
    if bits > 2048 {
        128
    } else {
        64
    }
}

// ===========================================================================
// Small-Prime Helpers
// ===========================================================================

/// Product of all small odd primes from 3 through 751, returned as a `BigNum`.
///
/// Translates the `small_prime_factors[]` constant from `crypto/bn/bn_prime.c`.
/// The SP 800-89 §5.3.3 optimization uses this constant in RSA prime validation
/// to reject composites quickly via a single GCD:
///
/// ```text
/// gcd(candidate, small_prime_factors_product()) == 1  ⇒  candidate is not
/// divisible by any prime in [3, 751]
/// ```
///
/// This value is approximately a 1040-bit constant (33 64-bit limbs).
/// Computed eagerly each call; callers that need it repeatedly should cache.
pub fn small_prime_factors_product() -> BigNum {
    // Use BigUint for unsigned-only accumulation (no sign-magnitude overhead).
    let mut product = <BigUint as One>::one();
    for &prime in SMALL_PRIMES {
        if prime < 3 {
            continue;
        }
        if prime > 751 {
            break;
        }
        product *= BigUint::from(prime);
    }
    // Safety net — the empty-product case (Zero::zero()) should never occur
    // because SMALL_PRIMES[1..] begins with 3, but guard defensively.
    if <BigUint as Zero>::is_zero(&product) {
        return BigNum::one();
    }
    let bytes = product.to_bytes_be();
    BigNum::from_bytes_be(&bytes)
}

/// Perform trial division of `candidate` by the first `calc_trial_divisions(bits)`
/// small primes.
///
/// Returns `true` iff the candidate is not divisible by any tested small prime
/// (and therefore *may* still be prime — further testing required). Returns
/// `false` as soon as a small-prime divisor is found, short-circuiting the
/// rest of the checks.
///
/// Special cases:
/// - A `candidate` that *is* one of the small primes returns `true` (a prime
///   trivially passes trial division by itself).
/// - Values ≤ 1 return `false` (not prime).
/// - Negative values return `false` (primality is defined on positives).
pub fn trial_division(candidate: &BigNum) -> bool {
    if candidate.is_negative() || candidate.is_zero() || candidate.is_one() {
        return false;
    }
    let bits = candidate.num_bits();
    let num_trials = calc_trial_divisions(bits);

    for &small_prime in SMALL_PRIMES.iter().take(num_trials) {
        // If the candidate equals a small prime, it is trivially prime and
        // passes trial division.
        if candidate.is_word(u64::from(small_prime)) {
            return true;
        }
        // Compute candidate mod small_prime. `mod_word` returns `u64`.
        match arithmetic::mod_word(candidate, u64::from(small_prime)) {
            // Either a clean division (remainder 0 ⇒ composite) or a
            // mod_word error (division-by-zero / overflow — impossible given
            // the >0 table entries but propagated defensively) means we
            // cannot declare primality.
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    true
}

/// Apply the trial-division sieve to a candidate of the given bit length.
///
/// Thin wrapper over `trial_division()` that documents the link to
/// `calc_trial_divisions(bits)`. Mirrors the C `probable_prime()` sieve stage.
pub fn sieve_candidate(bits: u32, candidate: &BigNum) -> bool {
    let _ = bits; // bits is implicit in candidate.num_bits(); kept for API clarity.
    trial_division(candidate)
}

// ===========================================================================
// Miller-Rabin Probabilistic Primality Test
// ===========================================================================

/// Run the Miller-Rabin probabilistic primality test on `w` for the specified
/// number of `rounds`.
///
/// Implements the algorithm from FIPS 186-4 Appendix C.3.1 / SP 800-89 §5.3.3.
/// For each round, a random witness `b ∈ [2, w - 2]` is drawn using the
/// *private* DRBG (via [`BigNum::priv_rand_range`]) so that the witness value
/// does not leak into observable state. The core exponentiation `z = b^m mod w`
/// is performed via [`mod_exp_with_context`](crate::bn::montgomery::mod_exp_with_context)
/// with a [`MontgomeryContext`] constructed **once** and reused across all
/// rounds — this mirrors the optimization in `bn_is_prime_int()`
/// (`crypto/bn/bn_prime.c`) where the `BN_MONT_CTX` is precomputed outside
/// the loop.
///
/// # Algorithmic outline
///
/// 1. Fast-reject tiny / even inputs (≤ 1, 2, 3, or even).
/// 2. Factor `w - 1 = 2^a · m` with `m` odd by counting trailing zero bits.
/// 3. For each round:
///    - Pick witness `b ∈ [2, w - 2]`.
///    - Compute `z = b^m mod w`.
///    - If `z == 1` or `z == w - 1`, the round passes.
///    - Otherwise, square `z` up to `a - 1` times; hitting `w - 1` passes
///      the round; hitting `1` proves compositeness (non-trivial square
///      root of 1).
///    - If no square reaches `w - 1`, the number is composite.
/// 4. After all rounds pass, report [`PrimalityResult::ProbablyPrime`].
///
/// # Complexity
///
/// Each round costs one `bits`-sized modular exponentiation plus at most
/// `a - 1` modular squarings, where `a` is the 2-adic valuation of `w - 1`.
/// For random primes, `a` is typically small (≤ 3), so the cost per round
/// is dominated by the initial `mod_exp`.
///
/// # Security
///
/// For `rounds` ≥ 64, the false-positive probability for a random composite
/// is ≤ `4^-rounds = 2^-128`. Callers generating keys should use at least
/// [`min_miller_rabin_rounds`] rounds.
pub fn miller_rabin_test(w: &BigNum, rounds: u32) -> CryptoResult<PrimalityResult> {
    // Step 1: reject inputs outside the domain of the test.
    if w.is_negative() || w.is_zero() || w.is_one() {
        return Ok(PrimalityResult::Composite);
    }
    // Explicit small primes — the algorithm itself degenerates for these.
    if w.is_word(2) || w.is_word(3) {
        return Ok(PrimalityResult::ProbablyPrime);
    }
    // Even numbers > 2 are composite.
    if !w.is_odd() {
        return Ok(PrimalityResult::Composite);
    }

    // Step 2: compute w_minus_1 = w - 1.
    let w_minus_1 = arithmetic::sub_word(w, 1)?;

    // Count the largest power of 2 dividing w - 1: find `power_of_two_exp`
    // (FIPS 186-4 notation: `a`) such that `2^a | (w - 1)` and
    // `2^(a+1) ∤ (w - 1)`. Equivalently, count trailing zero bits of
    // w_minus_1.
    let mut power_of_two_exp: u32 = 0;
    let w1_bits = w_minus_1.num_bits();
    while power_of_two_exp < w1_bits && !w_minus_1.is_bit_set(power_of_two_exp) {
        power_of_two_exp = power_of_two_exp.saturating_add(1);
    }
    // Defensive: w is odd and > 3, so w - 1 ≥ 4 is even → a ≥ 1 and a < w1_bits.
    // If the invariant fails for any reason, treat as composite rather than
    // risk an out-of-range loop.
    if power_of_two_exp == 0 || power_of_two_exp >= w1_bits {
        return Ok(PrimalityResult::Composite);
    }

    // odd_multiplicand = (w - 1) / 2^a  (FIPS 186-4 notation: `m`).
    let odd_multiplicand = arithmetic::rshift(&w_minus_1, power_of_two_exp);

    // Upper range for the witness: we want b ∈ [2, w - 2], which is
    // (w - 3) distinct values. `priv_rand_range(w - 3)` yields [0, w - 4];
    // adding 2 shifts to [2, w - 2].
    let witness_range = arithmetic::sub_word(w, 3)?;

    // Precompute the Montgomery context once — this is the hot-loop optimization.
    let mont_ctx = MontgomeryContext::new(w)?;

    'outer: for round in 0..rounds {
        // Pick a random witness using the private DRBG (FIPS 186-4: `b`).
        let raw_witness = BigNum::priv_rand_range(&witness_range)?;
        let witness = arithmetic::add_word(&raw_witness, 2);

        // z = witness^odd_multiplicand mod w (FIPS 186-4: z = b^m mod w)
        // using the reusable Montgomery context.
        let mut z =
            crate::bn::montgomery::mod_exp_with_context(&witness, &odd_multiplicand, &mont_ctx)?;

        // If z == 1 or z == w - 1 after the first exponentiation, this round
        // passes immediately.
        if z.is_one() || z == w_minus_1 {
            trace!(round, "miller-rabin: initial z == 1 or w-1, round passes");
            continue 'outer;
        }

        // Square up to (a - 1) times. Hitting w - 1 passes the round; hitting
        // 1 proves a non-trivial square root of unity → composite.
        for _j in 1..power_of_two_exp {
            z = arithmetic::mod_sqr(&z, w)?;
            if z == w_minus_1 {
                trace!(round, "miller-rabin: squaring reached w-1, round passes");
                continue 'outer;
            }
            if z.is_one() {
                trace!(round, "miller-rabin: non-trivial sqrt(1) found, composite");
                return Ok(PrimalityResult::Composite);
            }
        }

        // Finished squaring without finding w - 1 → composite witness.
        trace!(round, "miller-rabin: witness survived, composite");
        return Ok(PrimalityResult::Composite);
    }

    Ok(PrimalityResult::ProbablyPrime)
}

// ===========================================================================
// Composite Primality Check API (replaces C `BN_check_prime`)
// ===========================================================================

/// Test whether `n` is probably prime, combining trial division with
/// Miller-Rabin.
///
/// Replaces the C function `BN_check_prime()` in `crypto/bn/bn_prime.c`.
/// The number of Miller-Rabin rounds is selected automatically based on the
/// bit length of `n` via [`min_miller_rabin_rounds`]:
///
/// - `num_bits ≤ 2048`: 64 rounds (false-positive probability ≤ 2⁻¹²⁸)
/// - `num_bits > 2048`: 128 rounds (false-positive probability ≤ 2⁻²⁵⁶)
///
/// Returns [`PrimalityResult::ProbablyPrime`] if `n` passes both the sieve
/// and every MR round; [`PrimalityResult::Composite`] as soon as any check
/// fails. Small values (`n ≤ 1`, negatives, even numbers > 2) are handled
/// via fast paths.
///
/// # Errors
///
/// Propagates any [`CryptoError`] raised by underlying arithmetic, Montgomery
/// context construction, or random-number generation (e.g. if the system
/// entropy source is unavailable).
pub fn check_prime(n: &BigNum) -> CryptoResult<PrimalityResult> {
    let bits = n.num_bits();
    let rounds = min_miller_rabin_rounds(bits);
    check_prime_with_rounds(n, rounds)
}

/// Test whether `candidate` is probably prime using a caller-specified
/// number of Miller-Rabin `rounds`.
///
/// Identical to [`check_prime`] but lets the caller choose the round count.
/// Useful when the caller has different security targets (e.g. the FIPS
/// 186-4 Table C.2/C.3 schedule for already-sieved candidates) or needs
/// deterministic behavior in tests.
///
/// # Parameters
///
/// - `candidate`: the number under test.
/// - `rounds`: number of Miller-Rabin iterations; `rounds == 0` skips the MR
///   stage entirely and returns [`PrimalityResult::ProbablyPrime`] if trial
///   division passes (suitable only for diagnostic / debugging use).
///
/// # Fast-path handling
///
/// - Negative values, 0, and 1 → `Composite` (by convention, primality is
///   defined on integers ≥ 2).
/// - 2 and 3 → `ProbablyPrime`.
/// - Even values > 2 → `Composite`.
pub fn check_prime_with_rounds(candidate: &BigNum, rounds: u32) -> CryptoResult<PrimalityResult> {
    // Reject out-of-domain values first.
    if candidate.is_negative() || candidate.is_zero() || candidate.is_one() {
        return Ok(PrimalityResult::Composite);
    }
    if candidate.is_word(2) || candidate.is_word(3) {
        return Ok(PrimalityResult::ProbablyPrime);
    }
    if !candidate.is_odd() {
        return Ok(PrimalityResult::Composite);
    }

    // Trial division sieve — catches the vast majority of composites cheaply.
    if !trial_division(candidate) {
        return Ok(PrimalityResult::Composite);
    }

    // Miller-Rabin for the remaining candidates.
    miller_rabin_test(candidate, rounds)
}

// ===========================================================================
// Prime Generation (replaces C `BN_generate_prime_ex2`)
// ===========================================================================

/// Maximum number of candidate draws before [`generate_prime`] gives up.
///
/// For reasonable bit sizes, the density of primes (≥ 1 / (ln 2 · bits))
/// means an average of a few hundred attempts suffices. This bound exists
/// purely as a termination guarantee under pathological constraints (e.g.
/// an `add`/`rem` pair that admits no solutions).
const MAX_GENERATION_ATTEMPTS: u32 = 1_000_000;

/// Generate a random prime according to the provided [`GeneratePrimeOptions`].
///
/// Translates C `BN_generate_prime_ex2()` from `crypto/bn/bn_prime.c`. The
/// algorithm is:
///
/// 1. Draw a random `bits`-bit odd candidate. The top two bits are set
///    (via [`TopBit::Two`]) when no `add` constraint is given — this ensures
///    that the product of two such primes has precisely `2 · bits` bits, a
///    property RSA key generation relies on. When an `add` constraint is
///    present, only the top bit is forced (matching `probable_prime_dh`).
/// 2. For safe primes, additionally set bit 1, forcing the candidate to be
///    congruent to 3 modulo 4 so that `(p - 1) / 2` is odd.
/// 3. Apply any `add`/`rem` congruence constraint: `candidate ≡ rem (mod add)`.
///    The adjustment `candidate ← candidate − (candidate mod add) + rem`
///    may alter the bit length; if so, this attempt is discarded.
/// 4. Reject composites via [`trial_division`].
/// 5. Run [`miller_rabin_test`] with [`min_miller_rabin_rounds`] rounds.
/// 6. For safe primes, also require that `(candidate − 1) / 2` survives
///    trial division and MR.
///
/// # Errors
///
/// - `BigNumError::BitsTooSmall` if `bits < 2`, or if `safe == true` and
///   `bits < 6 && bits != 3` (a safe prime below this size can only be 5
///   or 7 and is not useful for any cryptographic purpose).
/// - `BigNumError::InvalidArgument` if `options.add` is present and zero,
///   or if the generator exceeds [`MAX_GENERATION_ATTEMPTS`] candidates.
/// - Propagates underlying RNG / arithmetic errors.
pub fn generate_prime(options: &GeneratePrimeOptions) -> CryptoResult<BigNum> {
    let bits = options.bits;

    // Bit-count validation mirrors BN_R_BITS_TOO_SMALL in the C source.
    if bits < 2 {
        return Err(BigNumError::BitsTooSmall(bits).into());
    }
    if options.safe && bits < 6 && bits != 3 {
        return Err(BigNumError::BitsTooSmall(bits).into());
    }
    // Catch zero `add` up front — it would cause a divide-by-zero inside
    // the attempt loop.
    if let Some(ref add) = options.add {
        if add.is_zero() {
            return Err(BigNumError::InvalidArgument(
                "GeneratePrimeOptions.add must be non-zero".into(),
            )
            .into());
        }
    }

    debug!(
        bits,
        safe = options.safe,
        has_add = options.add.is_some(),
        has_rem = options.rem.is_some(),
        "generate_prime: starting search"
    );

    // Rounds used for every MR test in this generation; `bits` is fixed
    // across the loop so the round count is too.
    let rounds = min_miller_rabin_rounds(bits);

    'attempt: for attempt in 0..MAX_GENERATION_ATTEMPTS {
        // -----------------------------------------------------------------
        // Phase A: draw a random odd candidate with the right top bits.
        // -----------------------------------------------------------------
        let top = if options.add.is_some() {
            TopBit::One
        } else {
            TopBit::Two
        };
        let mut candidate = BigNum::rand(bits, top, BottomBit::Odd)?;

        // Safe primes need `candidate ≡ 3 (mod 4)` so that (p − 1) / 2 is odd.
        if options.safe {
            candidate.set_bit(1)?;
        }

        // -----------------------------------------------------------------
        // Phase B: apply optional add/rem congruence.
        // -----------------------------------------------------------------
        if let Some(ref add) = options.add {
            // Default rem value is 1 — matches C `probable_prime_dh` when
            // no rem is supplied (the caller is free to override).
            let rem_val: BigNum = match options.rem.as_ref() {
                Some(r) => r.clone(),
                None => BigNum::one(),
            };
            // Use non-negative modular reduction so `current_mod ∈ [0, add)`,
            // matching the C source's `BN_nnmod(current_mod, candidate, add)`.
            let current_mod = arithmetic::nnmod(&candidate, add)?;
            let diff = arithmetic::sub(&rem_val, &current_mod);
            candidate = arithmetic::add(&candidate, &diff);
            // If the subtraction took us below zero, bump back up.
            while candidate.is_negative() {
                candidate = arithmetic::add(&candidate, add);
            }
            // Bit length must still match exactly.
            if candidate.num_bits() != bits {
                continue 'attempt;
            }
            // Safe primes + add/rem: re-assert ≡ 3 (mod 4) if the add step
            // wiped it out. If rem/add don't agree with that constraint,
            // drop the candidate.
            if options.safe && !candidate.is_bit_set(0) {
                continue 'attempt;
            }
            if options.safe && !candidate.is_bit_set(1) {
                continue 'attempt;
            }
        }

        // -----------------------------------------------------------------
        // Phase C: trial division sieve.
        // -----------------------------------------------------------------
        if !sieve_candidate(bits, &candidate) {
            continue 'attempt;
        }

        // -----------------------------------------------------------------
        // Phase D: Miller-Rabin on the candidate itself.
        // -----------------------------------------------------------------
        match miller_rabin_test(&candidate, rounds)? {
            PrimalityResult::Composite => continue 'attempt,
            PrimalityResult::ProbablyPrime => {}
        }

        // -----------------------------------------------------------------
        // Phase E: for safe primes, (p − 1) / 2 must also be prime.
        // -----------------------------------------------------------------
        if options.safe {
            let p_minus_1 = arithmetic::sub_word(&candidate, 1)?;
            let q = arithmetic::rshift1(&p_minus_1);
            if !trial_division(&q) {
                continue 'attempt;
            }
            match miller_rabin_test(&q, rounds)? {
                PrimalityResult::Composite => continue 'attempt,
                PrimalityResult::ProbablyPrime => {}
            }
        }

        debug!(attempt, bits, "generate_prime: candidate accepted");
        return Ok(candidate);
    }

    Err(BigNumError::InvalidArgument(format!(
        "generate_prime: exceeded {MAX_GENERATION_ATTEMPTS} attempts \
         (check `add`/`rem` constraints for solvability)"
    ))
    .into())
}

/// Generate a random prime of the specified bit length.
///
/// Convenience wrapper over [`generate_prime`] with `safe = false` and no
/// `add`/`rem` constraint. This is the most common entry point for
/// applications that just need a random prime (DSA `q` generation, RSA
/// primes, DH group primes, etc.).
///
/// # Errors
///
/// Same as [`generate_prime`]. In particular, `bits < 2` is rejected.
pub fn generate_random_prime(bits: u32) -> CryptoResult<BigNum> {
    generate_prime(&GeneratePrimeOptions {
        bits,
        safe: false,
        add: None,
        rem: None,
    })
}

/// Generate a *safe* prime of the specified bit length.
///
/// A safe prime `p` has the property that `(p − 1) / 2` is also prime — the
/// so-called Sophie Germain prime. Safe primes are required by some
/// Diffie-Hellman parameter sets (MODP groups, RFC 3526) and by certain
/// FIPS-compliant DH key agreement profiles.
///
/// Equivalent to `generate_prime(&GeneratePrimeOptions { bits, safe: true, ..})`.
///
/// # Performance
///
/// Safe prime generation is substantially slower than random prime generation
/// because each candidate must satisfy *two* primality conditions. For a
/// uniform random integer, the density of safe primes is approximately
/// `1 / ln(x)²`, so expected attempt count grows quadratically with bit size.
///
/// # Errors
///
/// Same as [`generate_prime`]. In particular, `bits < 6 && bits != 3`
/// is rejected.
pub fn generate_safe_prime(bits: u32) -> CryptoResult<BigNum> {
    generate_prime(&GeneratePrimeOptions {
        bits,
        safe: true,
        add: None,
        rem: None,
    })
}

// ===========================================================================
// FIPS 186-5 RSA Prime Derivation
// ===========================================================================

/// Derive an RSA prime `p` from a seed `xp` following FIPS 186-5 Appendix B.9.
///
/// Translates `ossl_bn_rsa_fips186_5_derive_prime()` from
/// `crypto/bn/bn_rsa_fips186_5.c`. The algorithm searches upward from the
/// seed `xp` for an odd candidate `Y` satisfying:
///
/// 1. `gcd(Y − 1, e) == 1` (so `e` has an inverse mod `φ(Y)` if `Y` is prime)
/// 2. `Y` passes [`check_prime`] (combined sieve + Miller-Rabin).
///
/// The search increments by 2 each iteration, bounded by `5 · bits` total
/// iterations per FIPS 186-5. If the seed is zero (caller's convention for
/// "no seed supplied"), a random starting point is drawn via
/// [`BigNum::rand`] with [`TopBit::Two`] and [`BottomBit::Odd`].
///
/// # Parameters
///
/// - `bits`: target bit length of the returned prime.
/// - `e`: public RSA exponent (must be positive and odd, commonly 65537).
/// - `xp`: seed value. Use a `BigNum::zero()` to request random seeding.
///
/// # Errors
///
/// - `BigNumError::BitsTooSmall` if `bits < 2`.
/// - `BigNumError::InvalidArgument` if `e` is zero or negative, or if the
///   search exhausts its iteration bound.
/// - Propagates underlying RNG / arithmetic errors.
pub fn rsa_fips186_5_derive_prime(bits: u32, e: &BigNum, xp: &BigNum) -> CryptoResult<BigNum> {
    if bits < 2 {
        return Err(BigNumError::BitsTooSmall(bits).into());
    }
    if e.is_zero() || e.is_negative() {
        return Err(BigNumError::InvalidArgument("RSA exponent must be positive".into()).into());
    }

    debug!(
        bits,
        xp_zero = xp.is_zero(),
        "rsa_fips186_5_derive_prime: starting search"
    );

    // Determine starting candidate: if the seed is zero, draw a random
    // `bits`-bit odd starting point; otherwise force odd and start from there.
    let mut y = if xp.is_zero() {
        BigNum::rand(bits, TopBit::Two, BottomBit::Odd)?
    } else {
        let mut candidate = xp.dup();
        if !candidate.is_odd() {
            candidate = arithmetic::add_word(&candidate, 1);
        }
        candidate
    };

    // FIPS 186-5 caps the inner search at 5 · nlen / 2 = 5 · bits iterations
    // for prime generation.
    let max_iterations: u64 = 5u64.saturating_mul(u64::from(bits));
    let rounds = min_miller_rabin_rounds(bits);

    for i in 0..max_iterations {
        // Candidate must fit in `bits` bits exactly; if we overflow, abort
        // rather than produce a longer prime than requested.
        if y.num_bits() > bits {
            return Err(BigNumError::InvalidArgument(format!(
                "rsa_fips186_5_derive_prime: candidate exceeded {bits} bits after {i} iterations"
            ))
            .into());
        }

        // Only test once bit length has reached target — a seed smaller than
        // `2^(bits-1)` needs to grow first.
        if y.num_bits() == bits {
            let y_minus_1 = arithmetic::sub_word(&y, 1)?;
            if arithmetic::are_coprime(&y_minus_1, e) && trial_division(&y) {
                if let PrimalityResult::ProbablyPrime = miller_rabin_test(&y, rounds)? {
                    trace!(iteration = i, "rsa_fips186_5_derive_prime: accepted");
                    return Ok(y);
                }
            }
        }

        // Y ← Y + 2  (keep parity odd).
        y = arithmetic::add_word(&y, 2);
    }

    Err(BigNumError::InvalidArgument(format!(
        "rsa_fips186_5_derive_prime: no prime found within {max_iterations} iterations"
    ))
    .into())
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_primes_table_is_complete() {
        assert_eq!(SMALL_PRIMES.len(), NUM_PRIMES);
        assert_eq!(SMALL_PRIMES[0], 2);
        assert_eq!(SMALL_PRIMES[1], 3);
        assert_eq!(SMALL_PRIMES[2], 5);
        // The 2048th prime is 17863 per OEIS A000040.
        assert_eq!(SMALL_PRIMES[NUM_PRIMES - 1], 17863);
    }

    #[test]
    fn calc_trial_divisions_thresholds() {
        assert_eq!(calc_trial_divisions(256), 64);
        assert_eq!(calc_trial_divisions(512), 64);
        assert_eq!(calc_trial_divisions(513), 128);
        assert_eq!(calc_trial_divisions(1024), 128);
        assert_eq!(calc_trial_divisions(2048), 384);
        assert_eq!(calc_trial_divisions(4096), 1024);
        assert_eq!(calc_trial_divisions(8192), NUM_PRIMES);
    }

    #[test]
    fn min_miller_rabin_rounds_boundary() {
        assert_eq!(min_miller_rabin_rounds(2048), 64);
        assert_eq!(min_miller_rabin_rounds(2049), 128);
        assert_eq!(min_miller_rabin_rounds(4096), 128);
    }

    #[test]
    fn check_prime_handles_small_values() {
        assert_eq!(
            check_prime(&BigNum::zero()).unwrap(),
            PrimalityResult::Composite
        );
        assert_eq!(
            check_prime(&BigNum::one()).unwrap(),
            PrimalityResult::Composite
        );
        assert_eq!(
            check_prime(&BigNum::from_u64(2)).unwrap(),
            PrimalityResult::ProbablyPrime
        );
        assert_eq!(
            check_prime(&BigNum::from_u64(3)).unwrap(),
            PrimalityResult::ProbablyPrime
        );
        assert_eq!(
            check_prime(&BigNum::from_u64(4)).unwrap(),
            PrimalityResult::Composite
        );
        assert_eq!(
            check_prime(&BigNum::from_u64(5)).unwrap(),
            PrimalityResult::ProbablyPrime
        );
    }

    #[test]
    fn check_prime_recognizes_known_primes() {
        // A handful of primes spanning several magnitudes.
        for &p in &[7u64, 11, 13, 17, 19, 23, 29, 31, 97, 101, 1013, 7919, 65537] {
            let bn = BigNum::from_u64(p);
            assert_eq!(
                check_prime(&bn).unwrap(),
                PrimalityResult::ProbablyPrime,
                "check_prime misidentified {p}"
            );
        }
    }

    #[test]
    fn check_prime_recognizes_known_composites() {
        // Including the Carmichael number 561 = 3 × 11 × 17 which fools
        // simple Fermat tests but must fail MR.
        for &n in &[
            4u64, 6, 8, 9, 15, 21, 25, 49, 91, 341, 561, 1105, 4369, 65535,
        ] {
            let bn = BigNum::from_u64(n);
            assert_eq!(
                check_prime(&bn).unwrap(),
                PrimalityResult::Composite,
                "check_prime misidentified {n}"
            );
        }
    }

    #[test]
    fn miller_rabin_zero_rounds_returns_probably_prime() {
        // With 0 rounds, MR trivially "passes" — only the cheap fast paths
        // run. Used primarily in diagnostic / test code.
        let p = BigNum::from_u64(5);
        assert_eq!(
            miller_rabin_test(&p, 0).unwrap(),
            PrimalityResult::ProbablyPrime
        );
    }

    #[test]
    fn trial_division_small_cases() {
        assert!(!trial_division(&BigNum::zero()));
        assert!(!trial_division(&BigNum::one()));
        assert!(trial_division(&BigNum::from_u64(2))); // 2 is in SMALL_PRIMES
        assert!(trial_division(&BigNum::from_u64(3)));
        assert!(!trial_division(&BigNum::from_u64(4)));
        assert!(trial_division(&BigNum::from_u64(97)));
        assert!(!trial_division(&BigNum::from_u64(9)));
    }

    #[test]
    fn small_prime_factors_product_value_sanity() {
        // The product of odd primes [3..=751] is a well-known ~1040-bit number.
        // We don't hardcode the exact value, but we can assert that it is
        // divisible by every odd prime ≤ 751 and not by any prime > 751.
        let product = small_prime_factors_product();

        assert!(!product.is_zero());
        assert!(!product.is_one());
        assert!(!product.is_negative());

        // Divisible by 3 (the smallest odd prime in the product).
        assert_eq!(arithmetic::mod_word(&product, 3).unwrap(), 0);
        // Divisible by 751 (the largest prime in the product).
        assert_eq!(arithmetic::mod_word(&product, 751).unwrap(), 0);
        // Not divisible by 2 (product is of odd primes only).
        assert_eq!(arithmetic::mod_word(&product, 2).unwrap(), 1);
        // Not divisible by 757 (next prime after 751).
        assert_ne!(arithmetic::mod_word(&product, 757).unwrap(), 0);
    }

    #[test]
    fn generate_prime_rejects_bits_below_two() {
        assert!(generate_random_prime(0).is_err());
        assert!(generate_random_prime(1).is_err());
    }

    #[test]
    fn generate_safe_prime_rejects_small_bits() {
        assert!(generate_safe_prime(2).is_err());
        assert!(generate_safe_prime(4).is_err());
        assert!(generate_safe_prime(5).is_err());
        // bits == 3 is the documented exception — must succeed.
        let p = generate_safe_prime(3).expect("safe-prime generation at bits=3 must work");
        assert_eq!(p.num_bits(), 3);
    }

    #[test]
    fn generate_random_prime_deterministic_at_bits_two() {
        // At 2 bits with top-two + odd, the only possible value is 3.
        let p = generate_random_prime(2).unwrap();
        assert!(p.is_word(3));
    }

    #[test]
    fn generate_random_prime_produces_prime_at_small_bits() {
        // 32-bit primes are cheap enough for a unit test but exercise the
        // full sieve + MR pipeline.
        let p = generate_random_prime(32).unwrap();
        assert_eq!(p.num_bits(), 32);
        assert_eq!(check_prime(&p).unwrap(), PrimalityResult::ProbablyPrime);
    }

    #[test]
    fn generate_safe_prime_yields_sophie_germain() {
        // 16-bit safe primes: small but nontrivial. (p - 1) / 2 must also
        // be prime.
        let p = generate_safe_prime(16).unwrap();
        assert_eq!(p.num_bits(), 16);
        let p_minus_1 = arithmetic::sub_word(&p, 1).unwrap();
        let q = arithmetic::rshift1(&p_minus_1);
        assert_eq!(check_prime(&p).unwrap(), PrimalityResult::ProbablyPrime);
        assert_eq!(check_prime(&q).unwrap(), PrimalityResult::ProbablyPrime);
    }

    #[test]
    fn sieve_candidate_matches_trial_division() {
        let cases = [7u64, 9, 11, 15, 97, 100, 101, 561];
        for &n in &cases {
            let bn = BigNum::from_u64(n);
            assert_eq!(
                sieve_candidate(bn.num_bits(), &bn),
                trial_division(&bn),
                "sieve_candidate disagreed with trial_division on {n}"
            );
        }
    }

    #[test]
    fn rsa_fips186_5_rejects_zero_exponent() {
        let e = BigNum::zero();
        let xp = BigNum::zero();
        assert!(rsa_fips186_5_derive_prime(64, &e, &xp).is_err());
    }

    #[test]
    fn rsa_fips186_5_derives_prime_from_seed() {
        // Use e = 65537 and an in-range 12-bit seed. FIPS 186-5 requires the
        // seed X to be drawn from [√2·2^(nlen/2-1), 2^(nlen/2) - 1]; we
        // satisfy that by picking 2053 ∈ [2048, 4095].
        let e = BigNum::from_u64(65537);
        let xp = BigNum::from_u64(2053);
        let p = rsa_fips186_5_derive_prime(12, &e, &xp).unwrap();
        assert_eq!(p.num_bits(), 12);
        assert_eq!(check_prime(&p).unwrap(), PrimalityResult::ProbablyPrime);
        // gcd(p - 1, e) must be 1.
        let p_minus_1 = arithmetic::sub_word(&p, 1).unwrap();
        assert!(arithmetic::are_coprime(&p_minus_1, &e));
    }

    #[test]
    fn rsa_fips186_5_random_seed() {
        // Zero seed → random starting point is drawn internally.
        let e = BigNum::from_u64(65537);
        let xp = BigNum::zero();
        let p = rsa_fips186_5_derive_prime(32, &e, &xp).unwrap();
        assert_eq!(p.num_bits(), 32);
        assert_eq!(check_prime(&p).unwrap(), PrimalityResult::ProbablyPrime);
    }

    #[test]
    fn generate_prime_with_options_default() {
        // Construct via Default + explicit bits — verifies the struct shape.
        let mut opts = GeneratePrimeOptions::default();
        opts.bits = 16;
        let p = generate_prime(&opts).unwrap();
        assert_eq!(p.num_bits(), 16);
        assert!(p.is_odd());
    }

    #[test]
    fn generate_prime_options_new_constructor() {
        let opts = GeneratePrimeOptions::new(8);
        assert_eq!(opts.bits, 8);
        assert!(!opts.safe);
        assert!(opts.add.is_none());
        assert!(opts.rem.is_none());
    }

    #[test]
    fn primality_result_equality() {
        assert_eq!(PrimalityResult::Composite, PrimalityResult::Composite);
        assert_ne!(PrimalityResult::Composite, PrimalityResult::ProbablyPrime);
    }
}
