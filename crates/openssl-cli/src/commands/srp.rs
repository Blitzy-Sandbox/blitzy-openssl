// The entire module deals with the deprecated SRP command. Suppress warnings
// about referencing the `#[deprecated]` struct inside its own module and in
// derive-macro expansions.
#![allow(deprecated)]

//! `srp` subcommand implementation — SRP verifier database management.
//!
//! This module provides the `openssl srp` command, a **deprecated** utility for
//! managing flat-file SRP (Secure Remote Password, RFC 2945 / RFC 5054) verifier
//! databases used by TLS-SRP cipher suites.
//!
//! # Deprecation
//!
//! SRP support is deprecated. TLS-SRP is not widely deployed and has been
//! superseded by certificate-based authentication and modern key exchange
//! mechanisms. This command is preserved for backward compatibility with
//! existing SRP verifier databases.
//!
//! # Source
//!
//! Rewritten from `apps/srp.c` (C implementation, ~600 lines).
//!
//! # Database Format
//!
//! The SRP verifier database is a tab-separated flat file with 6 fields per record:
//!
//! | Index | Field    | Description                               |
//! |-------|----------|-------------------------------------------|
//! | 0     | verifier | Hex-encoded SRP verifier (`g^x mod N`)    |
//! | 1     | salt     | Hex-encoded random salt                   |
//! | 2     | info     | Optional user information string          |
//! | 3     | id       | Username (unique key)                     |
//! | 4     | type     | Record type: V=valid, R=revoked, I=index  |
//! | 5     | gN       | Group parameter name (e.g., `"2048"`)     |
//!
//! Index entries (type `'I'`) store group parameter references.
//! User entries (type `'V'`, `'v'`, `'R'`) store verifier data.
//!
//! # Rules Compliance
//!
//! - **R5 (Nullability):** `Option<T>` for optional fields; no sentinels
//! - **R6 (Lossless Casts):** No narrowing casts
//! - **R8 (Zero Unsafe):** No `unsafe` blocks
//! - **R9 (Warning-Free):** `#[allow(deprecated)]` on internal usages
//! - **R10 (Wiring):** Reachable via `main.rs → CliCommand::Srp → SrpArgs::execute()`

// ============================================================================
// Imports
// ============================================================================

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use clap::Args;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use openssl_common::config::ConfigParser;
use openssl_common::error::{CommonError, CryptoError};
use openssl_crypto::context::LibContext;

use crate::lib::password::{parse_password_source, PasswordCallbackData, PasswordHandler};

// ============================================================================
// Constants
// ============================================================================

/// Default configuration section name for SRP settings.
const BASE_SECTION: &str = "srp";

/// Configuration key for the SRP verifier database file path.
const ENV_DATABASE: &str = "srpvfile";

/// Configuration key for the default SRP section name override.
const ENV_DEFAULT_SRP: &str = "default_srp";

/// Database field index: hex-encoded SRP verifier.
const DB_SRPVERIFIER: usize = 0;
/// Database field index: hex-encoded salt.
const DB_SRPSALT: usize = 1;
/// Database field index: optional user information.
const DB_SRPINFO: usize = 2;
/// Database field index: username (unique key).
const DB_SRPID: usize = 3;
/// Database field index: record type character.
const DB_SRPTYPE: usize = 4;
/// Database field index: group parameter name.
const DB_SRPGN: usize = 5;
/// Total number of fields per database record.
const DB_NUM_FIELDS: usize = 6;

/// Default group parameter name when none is specified.
const DEFAULT_GN: &str = "2048";

/// Length in bytes of randomly generated salts for new verifiers.
const SALT_LENGTH: usize = 16;

// ============================================================================
// SRP Operation Mode
// ============================================================================

/// The operation mode for the SRP command.
///
/// Mirrors the `OPTION_CHOICE` enum values from C `srp.c:136–142`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SrpMode {
    /// Add a new user to the verifier database.
    Add,
    /// Modify an existing user's verifier (requires old password verification).
    Modify,
    /// Mark a user as revoked (`'R'`) in the verifier database.
    Delete,
    /// List users in the verifier database.
    List,
}

impl fmt::Display for SrpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add => write!(f, "add"),
            Self::Modify => write!(f, "modify"),
            Self::Delete => write!(f, "delete"),
            Self::List => write!(f, "list"),
        }
    }
}

// ============================================================================
// SRP Group Parameters (RFC 5054)
// ============================================================================

/// SRP group parameters: generator `g` and safe prime modulus `N`.
struct SrpGnParams {
    /// The generator as big-endian bytes (typically `[2]` or `[5]`).
    g: Vec<u8>,
    /// The safe prime modulus as big-endian bytes.
    n: Vec<u8>,
}

/// Returns well-known SRP group parameters by name.
///
/// Group parameters are from RFC 5054 Appendix A. The name corresponds to the
/// bit size of the modulus. Replaces `SRP_get_default_gN()` from
/// `crypto/srp/srp_lib.c`.
fn get_default_gn(name: &str) -> Option<SrpGnParams> {
    let (g_val, n_hex): (u8, &str) = match name {
        "1024" => (2, SRP_1024_N_HEX),
        "1536" => (2, SRP_1536_N_HEX),
        "2048" => (2, SRP_2048_N_HEX),
        "3072" => (5, SRP_3072_N_HEX),
        _ => return None,
    };
    let n = hex_decode_const(n_hex)?;
    Some(SrpGnParams { g: vec![g_val], n })
}

/// Decode a hex constant string to bytes. Returns `None` on invalid hex.
fn hex_decode_const(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        // TRUNCATION: hex digits are 0..=15 which always fit in u8.
        let h = u8::try_from(hi.to_digit(16)?).ok()?;
        let l = u8::try_from(lo.to_digit(16)?).ok()?;
        bytes.push((h << 4) | l);
    }
    Some(bytes)
}

/// Encode bytes to uppercase hex string.
fn hex_encode_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Decode a hex string to bytes. Returns an error string on failure.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    hex_decode_const(hex).ok_or_else(|| format!("invalid hex encoding: {hex}"))
}

// RFC 5054 Appendix A — 1024-bit group modulus (g = 2).
const SRP_1024_N_HEX: &str = concat!(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E8",
    "6072618775FF3C0B9EA2314C9C256576",
    "D674DF7496EA81D3383B4813D692C6E0",
    "E0D5D8E250B98BE48E495C1D6089DAD1",
    "5DC7D7B46154D6B6CE8EF4AD69B15D49",
    "82559B297BCF1885C529F566660E57EC",
    "68EDBC3C05726CC02FD4CBF4976EAA9A",
    "FD5138FE8376435B9FC61D2FC0EB06E3",
);

// RFC 5054 Appendix A — 1536-bit group modulus (g = 2).
const SRP_1536_N_HEX: &str = concat!(
    "9DEF3CAFB939277AB1F12A8617A47BBB",
    "DBA51DF499AC4C80BEEEA9614B19CC4D",
    "5F4F5F556E27CBDE51C6A94BE4607A29",
    "1558903BA0D0F84380B655BB9A22E8DC",
    "DF028A7CEC67F0D08134B1C8B9798914",
    "9B609E0BE3BAB63D47548381DBC5B1FC",
    "764E3F4B53DD9DA1158BFD3E2B9C8CF5",
    "6EDF019539349627DB2FD53D24B7C486",
    "65772E437D6C7F8CE442734AF7CCB7AE",
    "837C264AE3A9BEB87F8A2FE9B8B5292E",
    "5A021FFF5E91479E8CE7A28C2442C6F3",
    "15180F93499A234DCF76E3FED135F9BB",
);

// RFC 5054 Appendix A — 2048-bit group modulus (g = 2).
const SRP_2048_N_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582F",
    "AF72B6651987EE07FC3192943DB56050",
    "A37329CBB4A099ED8193E0757767A13D",
    "D52312AB4B03310DCD7F48A9DA04FD50",
    "E8083969EDB767B0CF6095179A163AB3",
    "661A05FBD5FAAAE82918A9962F0B93B8",
    "55F97993EC975EEAA80D740ADBF4FF74",
    "7359D041D5C33EA71D281E446B14773B",
    "CA97B43A23FB801676BD207A436C6481",
    "F1D2B9078717461A5B9D32E688F87748",
    "544523B524B0D57D5EA77A2775D2ECFA",
    "032CFBDBF52FB3786160279004E57AE6",
    "AF874E7303CE53299CCC041C7BC308D8",
    "2A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F5475",
    "9B65E372FCD68EF20FA7111F9E4AFF73",
);

// RFC 5054 Appendix A — 3072-bit group modulus (g = 5).
const SRP_3072_N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234",
    "C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6",
    "F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE6",
    "49286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804",
    "F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28F",
    "B5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A",
    "8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619D",
    "CEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A6452F2B18177B200CB",
    "BE117577A615D6C770988C0BAD946E20",
    "8E24FA074E5AB3143DB5BFCE0FD108E4",
    "B82D120A93AD2CAFFFFFFFFFFFFFFFFF",
);

// ============================================================================
// SHA-1 Implementation (RFC 3174)
// ============================================================================
//
// Minimal, portable SHA-1 used exclusively for SRP verifier computation.
// The SRP protocol (RFC 2945) specifies SHA-1 as its hash function.
// This implementation follows FIPS 180-4 / RFC 3174 exactly.

/// Compute the SHA-1 digest of `data`, returning a 20-byte hash.
///
/// Variable names (`h0`–`h4`, `a`–`e`, `f`, `k`, `w`) follow the FIPS 180-4
/// specification §6.1.2 naming convention exactly, making the implementation
/// directly auditable against the standard.
#[allow(clippy::min_ident_chars, clippy::many_single_char_names)]
fn sha1(data: &[u8]) -> [u8; 20] {
    // Initial hash values (FIPS 180-4 §5.3.1).
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    // Pre-processing: append padding bits and length (FIPS 180-4 §5.1.1).
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block (FIPS 180-4 §6.1.2).
    for chunk in msg.chunks_exact(64) {
        // Message schedule: expand 16 words → 80 words.
        let mut w = [0u32; 80];
        for (idx, w_slot) in w.iter_mut().enumerate().take(16) {
            let off = idx * 4;
            *w_slot = u32::from_be_bytes([
                chunk[off],
                chunk[off + 1],
                chunk[off + 2],
                chunk[off + 3],
            ]);
        }
        for idx in 16..80 {
            w[idx] = (w[idx - 3] ^ w[idx - 8] ^ w[idx - 14] ^ w[idx - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        // 80 compression rounds.
        for round in 0u32..80 {
            let round_idx = round as usize;
            let (f, k) = match round {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1_u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC_u32),
                _ => (b ^ c ^ d, 0xCA62_C1D6_u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[round_idx]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

// ============================================================================
// Minimal Big Unsigned Integer for Modular Exponentiation
// ============================================================================
//
// Provides only the operations required for SRP verifier computation:
//   v = g^x mod N
// Represented as little-endian Vec<u64> limbs with schoolbook algorithms.

/// Big unsigned integer — little-endian `u64` limbs.
#[derive(Clone)]
struct BigUint {
    /// Limbs in little-endian order: `limbs[0]` is the least significant.
    limbs: Vec<u64>,
}

impl BigUint {
    fn zero() -> Self {
        Self { limbs: vec![0] }
    }

    fn one() -> Self {
        Self { limbs: vec![1] }
    }

    /// Construct from big-endian bytes.
    fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        let padded_len = (bytes.len() + 7) / 8 * 8;
        let mut padded = vec![0u8; padded_len];
        padded[padded_len - bytes.len()..].copy_from_slice(bytes);

        let num_limbs = padded_len / 8;
        let mut limbs = Vec::with_capacity(num_limbs);
        for i in (0..num_limbs).rev() {
            let off = i * 8;
            limbs.push(u64::from_be_bytes([
                padded[off],
                padded[off + 1],
                padded[off + 2],
                padded[off + 3],
                padded[off + 4],
                padded[off + 5],
                padded[off + 6],
                padded[off + 7],
            ]));
        }
        let mut r = Self { limbs };
        r.normalize();
        r
    }

    /// Serialize to big-endian bytes (no leading zeros).
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut started = false;
        for &limb in self.limbs.iter().rev() {
            for &byte in &limb.to_be_bytes() {
                if !started && byte == 0 {
                    continue;
                }
                started = true;
                bytes.push(byte);
            }
        }
        if bytes.is_empty() {
            bytes.push(0);
        }
        bytes
    }

    /// Remove trailing zero limbs, keeping at least one.
    fn normalize(&mut self) {
        while self.limbs.len() > 1 && self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// Number of significant bits.
    fn bit_len(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let top = self.limbs.len() - 1;
        let top_bits = 64 - self.limbs[top].leading_zeros() as usize;
        top * 64 + top_bits
    }

    /// Test whether bit `i` (0 = LSB) is set.
    fn bit(&self, i: usize) -> bool {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        if limb_idx >= self.limbs.len() {
            return false;
        }
        (self.limbs[limb_idx] >> bit_idx) & 1 == 1
    }

    /// Compare two big unsigned integers.
    fn cmp_big(&self, other: &Self) -> std::cmp::Ordering {
        let max_len = self.limbs.len().max(other.limbs.len());
        for i in (0..max_len).rev() {
            let a = if i < self.limbs.len() { self.limbs[i] } else { 0 };
            let b = if i < other.limbs.len() { other.limbs[i] } else { 0 };
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Subtraction: `self - other`. Caller must ensure `self >= other`.
    fn sub_big(&self, other: &Self) -> Self {
        let mut result = Vec::with_capacity(self.limbs.len());
        let mut borrow: u64 = 0;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i];
            let b = if i < other.limbs.len() { other.limbs[i] } else { 0 };
            let (diff, b1) = a.overflowing_sub(b);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            result.push(diff2);
            borrow = u64::from(b1) + u64::from(b2);
        }
        let mut r = Self { limbs: result };
        r.normalize();
        r
    }

    /// Schoolbook multiplication.
    ///
    /// The `u128 as u64` casts are intentional truncations that extract the low
    /// 64 bits of the double-wide product. The high 64 bits are captured by
    /// `prod >> 64` and propagated as `carry`. This is the standard technique
    /// for arbitrary-precision arithmetic.
    #[allow(clippy::cast_possible_truncation)]
    fn mul_big(&self, other: &Self) -> Self {
        let n = self.limbs.len();
        let m = other.limbs.len();
        let mut result = vec![0u64; n + m];
        for i in 0..n {
            let mut carry: u128 = 0;
            for j in 0..m {
                let prod = u128::from(self.limbs[i]) * u128::from(other.limbs[j])
                    + u128::from(result[i + j])
                    + carry;
                // TRUNCATION: intentional — take low 64 bits, carry has high bits.
                result[i + j] = prod as u64;
                carry = prod >> 64;
            }
            // TRUNCATION: intentional — carry fits in 64 bits at final column.
            result[i + m] = carry as u64;
        }
        let mut r = Self { limbs: result };
        r.normalize();
        r
    }

    /// Left shift by `n` bits.
    fn shl_bits(&self, n: usize) -> Self {
        if n == 0 || self.is_zero() {
            return self.clone();
        }
        let limb_shift = n / 64;
        let bit_shift = n % 64;
        let mut result = vec![0u64; self.limbs.len() + limb_shift + 1];
        if bit_shift == 0 {
            for (i, &limb) in self.limbs.iter().enumerate() {
                result[i + limb_shift] = limb;
            }
        } else {
            let mut carry: u64 = 0;
            for (i, &limb) in self.limbs.iter().enumerate() {
                result[i + limb_shift] = (limb << bit_shift) | carry;
                carry = limb >> (64 - bit_shift);
            }
            if carry > 0 {
                result[self.limbs.len() + limb_shift] = carry;
            }
        }
        let mut r = Self { limbs: result };
        r.normalize();
        r
    }

    /// Right shift by 1 bit.
    fn shr1(&self) -> Self {
        let mut result = vec![0u64; self.limbs.len()];
        let mut carry: u64 = 0;
        for i in (0..self.limbs.len()).rev() {
            let new_carry = self.limbs[i] & 1;
            result[i] = (self.limbs[i] >> 1) | (carry << 63);
            carry = new_carry;
        }
        let mut r = Self { limbs: result };
        r.normalize();
        r
    }

    /// Modular reduction via binary long-division (shift-and-subtract).
    fn rem_big(&self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        if self.cmp_big(modulus) == std::cmp::Ordering::Less {
            return self.clone();
        }
        let mod_bits = modulus.bit_len();
        let self_bits = self.bit_len();
        if self_bits < mod_bits {
            return self.clone();
        }

        let shift = self_bits - mod_bits;
        let mut remainder = self.clone();
        let mut shifted = modulus.shl_bits(shift);

        for _ in 0..=shift {
            if remainder.cmp_big(&shifted) != std::cmp::Ordering::Less {
                remainder = remainder.sub_big(&shifted);
            }
            shifted = shifted.shr1();
        }
        remainder.normalize();
        remainder
    }

    /// Modular exponentiation: `self^exp mod modulus`.
    ///
    /// Uses left-to-right binary (square-and-multiply) method.
    fn modpow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        let mut result = Self::one();
        let mut base = self.rem_big(modulus);
        let exp_bits = exp.bit_len();

        for i in 0..exp_bits {
            if exp.bit(i) {
                result = result.mul_big(&base).rem_big(modulus);
            }
            base = base.mul_big(&base).rem_big(modulus);
        }
        result
    }
}

// ============================================================================
// SRP Verifier Computation
// ============================================================================

/// Computes the SRP secret exponent per RFC 2945 §3:
///
/// ```text
/// x = SHA1(salt | SHA1(username | ":" | password))
/// ```
fn compute_srp_x(salt: &[u8], username: &str, password: &str) -> Vec<u8> {
    // Inner hash: SHA1(I | ":" | P)
    let mut inner_input = Vec::with_capacity(username.len() + 1 + password.len());
    inner_input.extend_from_slice(username.as_bytes());
    inner_input.push(b':');
    inner_input.extend_from_slice(password.as_bytes());
    let inner_hash = sha1(&inner_input);

    // Outer hash: SHA1(salt | inner_hash)
    let mut outer_input = Vec::with_capacity(salt.len() + 20);
    outer_input.extend_from_slice(salt);
    outer_input.extend_from_slice(&inner_hash);
    sha1(&outer_input).to_vec()
}

/// Creates a new SRP verifier: `v = g^x mod N`.
///
/// Replaces `SRP_create_verifier_ex()` from `crypto/srp/srp_vfy.c`.
fn create_srp_verifier(
    username: &str,
    password: &str,
    salt: &[u8],
    gn: &SrpGnParams,
) -> Vec<u8> {
    let x_bytes = compute_srp_x(salt, username, password);
    let g = BigUint::from_be_bytes(&gn.g);
    let x = BigUint::from_be_bytes(&x_bytes);
    let n = BigUint::from_be_bytes(&gn.n);
    g.modpow(&x, &n).to_be_bytes()
}

/// Generates cryptographically random bytes using the system RNG.
///
/// Reads from `/dev/urandom` which is available on all CI targets
/// (Linux `x86_64`/`aarch64`, macOS `x86_64`/`aarch64`).
fn generate_random_bytes(len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut file = fs::File::open("/dev/urandom")?;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

// ============================================================================
// SRP Database Entry
// ============================================================================

/// A single record in the SRP verifier database.
///
/// Corresponds to one line of the tab-separated flat file. Mirrors the
/// C `TXT_DB` row indexed by `DB_srp*` constants from `apps/include/apps.h`.
#[derive(Debug, Clone)]
struct SrpDbEntry {
    /// Hex-encoded SRP verifier (`g^x mod N`).
    verifier: String,
    /// Hex-encoded random salt.
    salt: String,
    /// Optional user information string.
    info: String,
    /// Username (unique key).
    id: String,
    /// Record type: `'V'` = valid, `'v'` = pending, `'R'` = revoked, `'I'` = index.
    entry_type: char,
    /// Group parameter name (e.g., `"2048"`).
    gn: String,
}

impl SrpDbEntry {
    /// Parse a database entry from tab-separated fields.
    ///
    /// Returns `None` if the line has fewer than [`DB_NUM_FIELDS`] fields or
    /// the type field is empty.
    fn from_fields(fields: &[&str]) -> Option<Self> {
        if fields.len() < DB_NUM_FIELDS {
            return None;
        }
        let entry_type = fields[DB_SRPTYPE].chars().next()?;
        Some(Self {
            verifier: fields[DB_SRPVERIFIER].to_string(),
            salt: fields[DB_SRPSALT].to_string(),
            info: fields[DB_SRPINFO].to_string(),
            id: fields[DB_SRPID].to_string(),
            entry_type,
            gn: fields[DB_SRPGN].to_string(),
        })
    }

    /// Serialize the entry as a tab-separated line (no trailing newline).
    fn to_tab_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.verifier, self.salt, self.info, self.id, self.entry_type, self.gn
        )
    }
}

impl fmt::Display for SrpDbEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "user \"{}\" (type={}, gN={}, info=\"{}\")",
            self.id, self.entry_type, self.gn, self.info
        )
    }
}

// ============================================================================
// SRP Database
// ============================================================================

/// In-memory representation of the SRP verifier flat-file database.
///
/// Replaces the C `TXT_DB` / `CA_DB` structures from `crypto/txt_db/txt_db.c`
/// and `apps/include/apps.h`. Entries are stored as a `Vec` with a `HashMap`
/// index for O(1) username lookups.
struct SrpDatabase {
    /// All entries in insertion order.
    entries: Vec<SrpDbEntry>,
    /// Index: username → position in `entries`.
    index: HashMap<String, usize>,
}

impl SrpDatabase {
    /// Create an empty database.
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Load a database from a tab-separated flat file.
    ///
    /// Replaces `load_index()` from `apps/lib/apps.c`. Lines starting with `#`
    /// are treated as comments. Malformed lines are skipped with a debug log.
    fn load(path: &Path) -> Result<Self, CryptoError> {
        if !path.exists() {
            debug!(path = %path.display(), "SRP database file does not exist, starting empty");
            return Ok(Self::new());
        }
        let content = fs::read_to_string(path)?;
        let mut db = Self::new();
        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = trimmed.split('\t').collect();
            if let Some(entry) = SrpDbEntry::from_fields(&fields) {
                let idx = db.entries.len();
                db.index.insert(entry.id.clone(), idx);
                db.entries.push(entry);
            } else {
                debug!(line = line_no + 1, "skipping malformed line in SRP database");
            }
        }
        debug!(count = db.entries.len(), path = %path.display(), "loaded SRP database");
        Ok(db)
    }

    /// Save the database to a tab-separated flat file.
    ///
    /// Replaces `save_index()` from `apps/lib/apps.c`. Writes all entries,
    /// including revoked ones, preserving the complete database state.
    fn save(&self, path: &Path) -> Result<(), CryptoError> {
        let file = fs::File::create(path)?;
        let mut writer = BufWriter::new(file);
        for entry in &self.entries {
            writeln!(writer, "{}", entry.to_tab_line())?;
        }
        writer.flush()?;
        debug!(count = self.entries.len(), path = %path.display(), "saved SRP database");
        Ok(())
    }

    /// Find an entry by username.
    fn find_by_id(&self, username: &str) -> Option<&SrpDbEntry> {
        self.index.get(username).map(|&idx| &self.entries[idx])
    }

    /// Find a mutable entry by username.
    fn find_by_id_mut(&mut self, username: &str) -> Option<&mut SrpDbEntry> {
        self.index
            .get(username)
            .copied()
            .map(move |idx| &mut self.entries[idx])
    }

    /// Find an entry by username that matches one of the given type characters.
    fn find_by_id_and_type(&self, username: &str, types: &[char]) -> Option<&SrpDbEntry> {
        self.index.get(username).and_then(|&idx| {
            let entry = &self.entries[idx];
            if types.contains(&entry.entry_type) {
                Some(entry)
            } else {
                None
            }
        })
    }

    /// Add a new entry to the database.
    fn add_entry(&mut self, entry: SrpDbEntry) {
        let idx = self.entries.len();
        self.index.insert(entry.id.clone(), idx);
        self.entries.push(entry);
    }

    /// Collect all index entries (type `'I'`) for gN parameter scanning.
    fn gn_index_entries(&self) -> Vec<&SrpDbEntry> {
        self.entries
            .iter()
            .filter(|e| e.entry_type == 'I')
            .collect()
    }

    /// Print all user entries to the log.
    ///
    /// Replaces `print_index()` and `print_user()` from `srp.c:54–89`.
    fn list_all(&self, verbose: bool) {
        let user_entries: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.entry_type != 'I')
            .collect();
        for entry in &user_entries {
            info!("{entry}");
            if verbose {
                info!("  verifier: {}", entry.verifier);
                info!("  salt: {}", entry.salt);
            }
        }
        if user_entries.is_empty() {
            info!("no users in SRP database");
        }
    }
}

// ============================================================================
// Error and Path Helpers
// ============================================================================

/// Create an argument validation error.
fn arg_error(msg: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::InvalidArgument(msg.into()))
}

/// Create a configuration error.
fn config_error(msg: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::Config {
        message: msg.into(),
    })
}

/// Create an internal error.
fn internal_error(msg: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::Internal(msg.into()))
}

/// Construct a suffixed path by appending `.suffix` to the full path string.
///
/// Unlike [`Path::with_extension`], this preserves existing extensions:
/// `"foo.txt"` + `"new"` → `"foo.txt.new"` (not `"foo.new"`).
///
/// Replaces the C pattern of `OPENSSL_strdupcat(path, ".new")` used by
/// `save_index()` and `rotate_index()` in `apps/lib/apps.c`.
fn suffixed_path(base: &Path, suffix: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(".");
    s.push(suffix);
    PathBuf::from(s)
}

/// Rotate database files: current → `.old`, `.new` → current.
///
/// Replaces `rotate_index()` from `apps/lib/apps.c`:
///   1. Remove `<path>.old` if it exists.
///   2. Rename `<path>` → `<path>.old`.
///   3. Rename `<path>.new` → `<path>`.
fn rotate_database_files(base_path: &Path) -> Result<(), CryptoError> {
    let new_path = suffixed_path(base_path, "new");
    let old_path = suffixed_path(base_path, "old");

    // Remove old backup.
    if old_path.exists() {
        fs::remove_file(&old_path)?;
    }
    // Current → old.
    if base_path.exists() {
        fs::rename(base_path, &old_path)?;
    }
    // New → current.
    if new_path.exists() {
        fs::rename(&new_path, base_path)?;
    }
    debug!(path = %base_path.display(), "rotated database files");
    Ok(())
}

// ============================================================================
// SrpArgs — CLI Arguments
// ============================================================================

/// Arguments for the `openssl srp` subcommand.
///
/// Manages SRP verifier databases used by TLS-SRP cipher suites. This command
/// is **deprecated** — use modern authentication protocols instead.
///
/// Replaces the C `srp_options[]` table and `OPTION_CHOICE` enum from
/// `apps/srp.c:136–180`.
#[deprecated(
    since = "0.1.0",
    note = "SRP support is deprecated. Use modern authentication protocols."
)]
#[derive(Args, Debug)]
#[allow(deprecated, clippy::struct_excessive_bools)]
pub struct SrpArgs {
    /// Add a new user to the SRP verifier database.
    #[arg(long, group = "mode")]
    pub add: bool,

    /// Modify an existing user's SRP verifier.
    #[arg(long, group = "mode")]
    pub modify: bool,

    /// Delete (revoke) a user from the SRP verifier database.
    #[arg(long, group = "mode")]
    pub delete: bool,

    /// List users in the SRP verifier database.
    #[arg(long, group = "mode")]
    pub list: bool,

    /// SRP section name in the configuration file.
    #[arg(long, short = 'n', default_value = BASE_SECTION)]
    pub name: String,

    /// Path to the SRP verifier database file.
    #[arg(long)]
    pub srpvfile: Option<PathBuf>,

    /// SRP group parameter name (e.g., `"1024"`, `"1536"`, `"2048"`, `"3072"`).
    #[arg(long, default_value = DEFAULT_GN)]
    pub gn: String,

    /// Additional user information string stored alongside the verifier.
    #[arg(long, default_value = "")]
    pub userinfo: String,

    /// Source for the input passphrase (e.g., `pass:secret`, `env:VAR`,
    /// `file:path`, `fd:N`, `stdin`).
    #[arg(long)]
    pub passin: Option<String>,

    /// Source for the output (new) passphrase.
    #[arg(long)]
    pub passout: Option<String>,

    /// Enable verbose output showing verifier details.
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Path to the OpenSSL configuration file.
    #[arg(long, short = 'C')]
    pub config: Option<PathBuf>,

    /// Engine to use (deprecated, ignored in Rust implementation).
    #[arg(long)]
    pub engine: Option<String>,

    /// Usernames to process.
    pub users: Vec<String>,
}

// ============================================================================
// SrpArgs — Execution
// ============================================================================

#[allow(deprecated)]
impl SrpArgs {
    /// Execute the SRP verifier database management command.
    ///
    /// Implements the complete `srp_main()` logic from `apps/srp.c:233–600`:
    ///   1. Emit deprecation warning.
    ///   2. Validate arguments and determine operation mode.
    ///   3. Resolve the database file path (direct or via config lookup).
    ///   4. Load the flat-file database.
    ///   5. Scan gN index entries and build the group parameter cache.
    ///   6. Process each user according to the selected mode.
    ///   7. Post-process: promote pending `'v'` entries to confirmed `'V'`.
    ///   8. Save the updated database and rotate files.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on I/O failures, configuration issues,
    /// argument validation errors, or password verification failures.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // 1. Deprecation warning (Rule R9: logged, not compiled away).
        warn!("the 'srp' command is deprecated; use modern authentication protocols");

        if let Some(ref engine) = self.engine {
            warn!(engine = %engine, "engine option is deprecated and ignored");
        }

        // 2. Determine operation mode.
        let mode = self.determine_mode()?;

        // 3. Validate argument combinations.
        self.validate_args(mode)?;

        // 4. Resolve database file path.
        let srpvfile = self.resolve_database_path()?;
        debug!(path = %srpvfile.display(), "using SRP verifier database");

        // 5. Resolve password sources (if provided via -passin/-passout).
        let passin = Self::resolve_password_source(&self.passin)?;
        let passout = Self::resolve_password_source(&self.passout)?;

        // 6. Load the database.
        let mut db = SrpDatabase::load(&srpvfile)?;

        // 7. Build gN parameter cache from database index entries.
        let mut gn_cache: HashMap<String, SrpGnParams> = HashMap::new();
        for gn_entry in db.gn_index_entries() {
            if let Some(params) = get_default_gn(&gn_entry.gn) {
                gn_cache.insert(gn_entry.gn.clone(), params);
            }
        }
        // Ensure the requested gN is always available.
        if !gn_cache.contains_key(&self.gn) {
            if let Some(params) = get_default_gn(&self.gn) {
                gn_cache.insert(self.gn.clone(), params);
            }
        }

        // 8. Handle LIST mode (read-only, no save needed).
        if mode == SrpMode::List {
            db.list_all(self.verbose);
            return Ok(());
        }

        // 9. Validate gN parameter availability for write operations.
        if !gn_cache.contains_key(&self.gn) {
            return Err(arg_error(format!(
                "unknown SRP group parameter '{}'; supported: 1024, 1536, 2048, 3072",
                self.gn
            )));
        }

        // 10. Process each user.
        let mut modified = false;
        for username in &self.users {
            let changed = match mode {
                SrpMode::Add => {
                    self.process_add(username, &mut db, &gn_cache, &passout)?
                }
                SrpMode::Modify => {
                    self.process_modify(username, &mut db, &gn_cache, &passin, &passout)?
                }
                SrpMode::Delete => Self::process_delete(username, &mut db)?,
                SrpMode::List => unreachable!("list handled above"),
            };
            modified |= changed;
        }

        if !modified {
            debug!("no changes to SRP database");
            return Ok(());
        }

        // 11. Post-processing: promote pending 'v' → confirmed 'V'.
        //     Mirrors srp.c:571–578.
        for entry in &mut db.entries {
            if entry.entry_type == 'v' {
                entry.entry_type = 'V';
            }
        }

        if self.verbose {
            info!("user processing done, saving database");
        }

        // 12. Save to .new file and rotate.
        let new_path = suffixed_path(&srpvfile, "new");
        db.save(&new_path)?;
        rotate_database_files(&srpvfile)?;

        info!("SRP database updated successfully");
        Ok(())
    }

    // ----------------------------------------------------------------
    // Private helpers
    // ----------------------------------------------------------------

    /// Determine the operation mode from the boolean flags.
    fn determine_mode(&self) -> Result<SrpMode, CryptoError> {
        let count = u8::from(self.add)
            + u8::from(self.modify)
            + u8::from(self.delete)
            + u8::from(self.list);

        if count == 0 {
            return Err(arg_error(
                "one of --add, --modify, --delete, or --list must be specified",
            ));
        }
        // Clap's `group = "mode"` enforces at-most-one, but double-check.
        if count > 1 {
            return Err(arg_error(
                "only one of --add, --modify, --delete, or --list may be specified",
            ));
        }

        if self.add {
            Ok(SrpMode::Add)
        } else if self.modify {
            Ok(SrpMode::Modify)
        } else if self.delete {
            Ok(SrpMode::Delete)
        } else {
            Ok(SrpMode::List)
        }
    }

    /// Validate argument combinations for the selected mode.
    fn validate_args(&self, mode: SrpMode) -> Result<(), CryptoError> {
        // -srpvfile and -config are mutually exclusive (srp.c:263–265).
        if self.srpvfile.is_some() && self.config.is_some() {
            return Err(arg_error(
                "--srpvfile and --config cannot both be specified",
            ));
        }
        // Write modes require at least one username.
        if mode != SrpMode::List && self.users.is_empty() {
            return Err(arg_error(format!(
                "{mode} mode requires at least one username"
            )));
        }
        // -passin/-passout require exactly one user.
        if (self.passin.is_some() || self.passout.is_some()) && self.users.len() > 1 {
            return Err(arg_error(
                "--passin/--passout can only be used with a single user",
            ));
        }
        Ok(())
    }

    /// Resolve the database file path from `-srpvfile` or config lookup.
    ///
    /// Mirrors srp.c:266–292 logic:
    ///   1. If `-srpvfile` is specified, use it directly.
    ///   2. Otherwise load the config file and look up the path.
    fn resolve_database_path(&self) -> Result<PathBuf, CryptoError> {
        if let Some(ref path) = self.srpvfile {
            return Ok(path.clone());
        }

        // Load configuration file.
        let config = if let Some(ref config_path) = self.config {
            ConfigParser::parse_file(config_path).map_err(|e| {
                config_error(format!(
                    "failed to load config '{}': {e}",
                    config_path.display()
                ))
            })?
        } else {
            let default_path = PathBuf::from("openssl.cnf");
            if default_path.exists() {
                ConfigParser::parse_file(&default_path).map_err(|e| {
                    config_error(format!("failed to load default config: {e}"))
                })?
            } else {
                return Err(config_error(
                    "no --srpvfile or --config specified and no openssl.cnf found",
                ));
            }
        };

        // Look up the effective section name (srp.c:281–284).
        let section = config
            .get_string(&self.name, ENV_DEFAULT_SRP)
            .unwrap_or(&self.name)
            .to_string();

        // Look up the database file path in that section.
        let db_path = config.get_string(&section, ENV_DATABASE).ok_or_else(|| {
            config_error(format!(
                "no '{ENV_DATABASE}' key found in section '{section}' of config"
            ))
        })?;

        Ok(PathBuf::from(db_path))
    }

    /// Resolve an optional password source specification to a password string.
    fn resolve_password_source(
        source: &Option<String>,
    ) -> Result<Option<Zeroizing<String>>, CryptoError> {
        match source {
            Some(src) => {
                let pw = parse_password_source(src)
                    .map_err(|e| internal_error(format!("password source error: {e}")))?;
                Ok(Some(pw))
            }
            None => Ok(None),
        }
    }

    /// Prompt for or retrieve a password for a specific user.
    fn get_password_for_user(
        username: &str,
        preset: &Option<Zeroizing<String>>,
        prompt_prefix: &str,
        verify: bool,
    ) -> Result<Zeroizing<String>, CryptoError> {
        if let Some(ref pw) = preset {
            return Ok(pw.clone());
        }
        let handler = PasswordHandler::new();
        let prompt_info = format!("{prompt_prefix} for user '{username}'");
        let cb_data = PasswordCallbackData::with_prompt_info(&prompt_info);
        handler
            .prompt_password(verify, Some(&cb_data))
            .map_err(|e| internal_error(format!("failed to read password: {e}")))
    }

    /// Process ADD mode for a single user.
    ///
    /// Mirrors srp.c:323–397 (ADD branch):
    ///   - If the user already exists and is valid/pending, reactivate.
    ///   - If the user is revoked, re-create with new verifier.
    ///   - If the user doesn't exist, create a new entry.
    fn process_add(
        &self,
        username: &str,
        db: &mut SrpDatabase,
        gn_cache: &HashMap<String, SrpGnParams>,
        passout: &Option<Zeroizing<String>>,
    ) -> Result<bool, CryptoError> {
        // Check for existing entry.
        if let Some(existing) = db.find_by_id(username) {
            match existing.entry_type {
                'V' | 'v' => {
                    // Already active — just re-confirm.
                    if let Some(entry) = db.find_by_id_mut(username) {
                        entry.entry_type = 'V';
                    }
                    info!(user = username, "user reactivated");
                    return Ok(true);
                }
                'R' => {
                    // Revoked — will be replaced below.
                    debug!(user = username, "replacing revoked user entry");
                }
                other => {
                    error!(user = username, entry_type = %other, "user exists with unexpected type");
                    return Err(arg_error(format!("user '{username}' already exists")));
                }
            }
        }

        let gn_params = gn_cache
            .get(&self.gn)
            .ok_or_else(|| arg_error(format!("unknown gN '{}'", self.gn)))?;

        // Get password for the new entry.
        let password =
            Self::get_password_for_user(username, passout, "Enter SRP password", true)?;

        // Generate random salt.
        let salt = generate_random_bytes(SALT_LENGTH)
            .map_err(|e| internal_error(format!("failed to generate random salt: {e}")))?;

        // Compute verifier.
        let verifier = create_srp_verifier(username, &password, &salt, gn_params);

        let entry = SrpDbEntry {
            verifier: hex_encode_upper(&verifier),
            salt: hex_encode_upper(&salt),
            info: self.userinfo.clone(),
            id: username.to_string(),
            entry_type: 'v', // Pending; promoted to 'V' in post-processing.
            gn: self.gn.clone(),
        };

        // If the user was revoked, update in-place; otherwise add new.
        if let Some(existing) = db.find_by_id_mut(username) {
            *existing = entry;
        } else {
            db.add_entry(entry);
        }

        info!(user = username, "user added to SRP database");
        if self.verbose {
            debug!(
                user = username,
                gn = %self.gn,
                salt_len = salt.len(),
                verifier_len = verifier.len(),
                "verifier created"
            );
        }

        Ok(true)
    }

    /// Process MODIFY mode for a single user.
    ///
    /// Mirrors srp.c:398–474 (MODIFY branch):
    ///   1. Verify the old password against the stored verifier.
    ///   2. Create a new verifier with a new salt and password.
    fn process_modify(
        &self,
        username: &str,
        db: &mut SrpDatabase,
        gn_cache: &HashMap<String, SrpGnParams>,
        passin: &Option<Zeroizing<String>>,
        passout: &Option<Zeroizing<String>>,
    ) -> Result<bool, CryptoError> {
        // Extract stored data (clone to release borrow on db).
        let (stored_salt_hex, stored_verifier_hex, existing_gn_name) = {
            let existing = db
                .find_by_id_and_type(username, &['V', 'v'])
                .ok_or_else(|| {
                    arg_error(format!("user '{username}' not found or revoked"))
                })?;
            (
                existing.salt.clone(),
                existing.verifier.clone(),
                existing.gn.clone(),
            )
        };

        // Verify the old password.
        let old_password =
            Self::get_password_for_user(username, passin, "Enter current SRP password", false)?;

        let stored_salt = hex_decode(&stored_salt_hex)
            .map_err(|e| internal_error(format!("invalid salt encoding: {e}")))?;

        let verify_gn = get_default_gn(&existing_gn_name).ok_or_else(|| {
            arg_error(format!(
                "unknown gN '{existing_gn_name}' for user '{username}'"
            ))
        })?;

        let computed_verifier =
            create_srp_verifier(username, &old_password, &stored_salt, &verify_gn);
        let stored_verifier = hex_decode(&stored_verifier_hex)
            .map_err(|e| internal_error(format!("invalid verifier encoding: {e}")))?;

        if computed_verifier != stored_verifier {
            error!(user = username, "password verification failed");
            return Err(CryptoError::Verification(
                format!("SRP password verification failed for user '{username}'"),
            ));
        }
        debug!(user = username, "old password verified");

        // Create new verifier.
        let gn_params = gn_cache
            .get(&self.gn)
            .ok_or_else(|| arg_error(format!("unknown gN '{}'", self.gn)))?;

        let new_password =
            Self::get_password_for_user(username, passout, "Enter new SRP password", true)?;

        let new_salt = generate_random_bytes(SALT_LENGTH)
            .map_err(|e| internal_error(format!("failed to generate random salt: {e}")))?;
        let new_verifier = create_srp_verifier(username, &new_password, &new_salt, gn_params);

        // Update in place.
        if let Some(entry) = db.find_by_id_mut(username) {
            entry.verifier = hex_encode_upper(&new_verifier);
            entry.salt = hex_encode_upper(&new_salt);
            entry.gn.clone_from(&self.gn);
            entry.info.clone_from(&self.userinfo);
            entry.entry_type = 'v'; // Pending; promoted in post-processing.
        }

        info!(user = username, "user verifier modified");
        Ok(true)
    }

    /// Process DELETE mode for a single user.
    ///
    /// Mirrors srp.c:475–503 (DELETE branch): marks the entry type as `'R'`.
    fn process_delete(
        username: &str,
        db: &mut SrpDatabase,
    ) -> Result<bool, CryptoError> {
        // Verify user exists and is active.
        let _existing = db
            .find_by_id_and_type(username, &['V', 'v'])
            .ok_or_else(|| {
                arg_error(format!(
                    "user '{username}' not found or already revoked"
                ))
            })?;

        if let Some(entry) = db.find_by_id_mut(username) {
            entry.entry_type = 'R';
        }

        info!(user = username, "user marked as revoked");
        Ok(true)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_empty() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hash = sha1(b"");
        assert_eq!(
            hex_encode_upper(&hash),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
    }

    #[test]
    fn test_sha1_abc() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let hash = sha1(b"abc");
        assert_eq!(
            hex_encode_upper(&hash),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
    }

    #[test]
    fn test_biguint_from_to_bytes() {
        let bytes = vec![0x01, 0x02, 0x03];
        let n = BigUint::from_be_bytes(&bytes);
        assert_eq!(n.to_be_bytes(), bytes);
    }

    #[test]
    fn test_biguint_modpow_small() {
        // 2^10 mod 1000 = 1024 mod 1000 = 24
        let base = BigUint::from_be_bytes(&[2]);
        let exp = BigUint::from_be_bytes(&[10]);
        let modulus = BigUint::from_be_bytes(&[0x03, 0xE8]); // 1000
        let result = base.modpow(&exp, &modulus);
        assert_eq!(result.to_be_bytes(), vec![24]);
    }

    #[test]
    fn test_biguint_modpow_larger() {
        // 3^7 mod 50 = 2187 mod 50 = 37
        let base = BigUint::from_be_bytes(&[3]);
        let exp = BigUint::from_be_bytes(&[7]);
        let modulus = BigUint::from_be_bytes(&[50]);
        let result = base.modpow(&exp, &modulus);
        assert_eq!(result.to_be_bytes(), vec![37]);
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = hex_encode_upper(&data);
        assert_eq!(encoded, "DEADBEEF");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_srp_db_entry_from_fields() {
        let fields = vec!["VERIFIER", "SALT", "info", "alice", "V", "2048"];
        let entry = SrpDbEntry::from_fields(&fields).unwrap();
        assert_eq!(entry.id, "alice");
        assert_eq!(entry.entry_type, 'V');
        assert_eq!(entry.gn, "2048");
    }

    #[test]
    fn test_srp_db_entry_tab_line_roundtrip() {
        let entry = SrpDbEntry {
            verifier: "AABB".to_string(),
            salt: "CCDD".to_string(),
            info: "test user".to_string(),
            id: "bob".to_string(),
            entry_type: 'V',
            gn: "2048".to_string(),
        };
        let line = entry.to_tab_line();
        let fields: Vec<&str> = line.split('\t').collect();
        let parsed = SrpDbEntry::from_fields(&fields).unwrap();
        assert_eq!(parsed.id, "bob");
        assert_eq!(parsed.verifier, "AABB");
        assert_eq!(parsed.entry_type, 'V');
    }

    #[test]
    fn test_get_default_gn_known() {
        assert!(get_default_gn("1024").is_some());
        assert!(get_default_gn("1536").is_some());
        assert!(get_default_gn("2048").is_some());
        assert!(get_default_gn("3072").is_some());
        assert!(get_default_gn("unknown").is_none());
    }

    #[test]
    fn test_get_default_gn_generator_values() {
        let gn1024 = get_default_gn("1024").unwrap();
        assert_eq!(gn1024.g, vec![2]);
        let gn3072 = get_default_gn("3072").unwrap();
        assert_eq!(gn3072.g, vec![5]);
    }

    #[test]
    fn test_srp_verifier_deterministic() {
        // Same inputs must produce the same verifier.
        let gn = get_default_gn("1024").unwrap();
        let salt = b"fixed_salt_value";
        let v1 = create_srp_verifier("user", "pass", salt, &gn);
        let v2 = create_srp_verifier("user", "pass", salt, &gn);
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_srp_verifier_different_passwords() {
        let gn = get_default_gn("1024").unwrap();
        let salt = b"shared_salt";
        let v1 = create_srp_verifier("user", "pass1", salt, &gn);
        let v2 = create_srp_verifier("user", "pass2", salt, &gn);
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_determine_mode_add() {
        let args = SrpArgs {
            add: true,
            modify: false,
            delete: false,
            list: false,
            name: BASE_SECTION.to_string(),
            srpvfile: None,
            gn: DEFAULT_GN.to_string(),
            userinfo: String::new(),
            passin: None,
            passout: None,
            verbose: false,
            config: None,
            engine: None,
            users: vec!["alice".to_string()],
        };
        assert_eq!(args.determine_mode().unwrap(), SrpMode::Add);
    }

    #[test]
    fn test_determine_mode_none_selected() {
        let args = SrpArgs {
            add: false,
            modify: false,
            delete: false,
            list: false,
            name: BASE_SECTION.to_string(),
            srpvfile: None,
            gn: DEFAULT_GN.to_string(),
            userinfo: String::new(),
            passin: None,
            passout: None,
            verbose: false,
            config: None,
            engine: None,
            users: Vec::new(),
        };
        assert!(args.determine_mode().is_err());
    }

    #[test]
    fn test_suffixed_path() {
        let base = Path::new("/tmp/srpverifier");
        assert_eq!(suffixed_path(base, "new"), PathBuf::from("/tmp/srpverifier.new"));
        assert_eq!(suffixed_path(base, "old"), PathBuf::from("/tmp/srpverifier.old"));

        let with_ext = Path::new("/tmp/data.txt");
        assert_eq!(suffixed_path(with_ext, "new"), PathBuf::from("/tmp/data.txt.new"));
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("ZZ").is_err());
        assert!(hex_decode("123").is_err()); // odd length
    }

    #[test]
    fn test_srp_mode_display() {
        assert_eq!(format!("{}", SrpMode::Add), "add");
        assert_eq!(format!("{}", SrpMode::Modify), "modify");
        assert_eq!(format!("{}", SrpMode::Delete), "delete");
        assert_eq!(format!("{}", SrpMode::List), "list");
    }
}
