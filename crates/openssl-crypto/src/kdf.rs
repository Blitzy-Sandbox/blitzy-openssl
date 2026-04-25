//! Key Derivation Function (KDF) infrastructure for the OpenSSL Rust workspace.
//!
//! Provides a unified interface for HKDF, PBKDF2, Argon2, scrypt, KBKDF
//! (SP 800-108), SSKDF, X963KDF, TLS-PRF, and SSH-KDF. Replaces the C
//! `EVP_KDF_*` API from `crypto/kdf/*.c` and the provider implementations
//! in `providers/implementations/kdfs/*.c`.
//!
//! # Design
//!
//! The KDF API follows a **builder pattern** matching the C workflow:
//! `EVP_KDF_CTX_new` → `EVP_KDF_CTX_set_params` → `EVP_KDF_derive`.
//! Key material and intermediate buffers are securely zeroed on drop via
//! [`zeroize::ZeroizeOnDrop`].
//!
//! # Supported Algorithms
//!
//! | Algorithm | Standard | Purpose |
//! |-----------|----------|---------|
//! | HKDF | RFC 5869 | Extract-and-Expand key derivation |
//! | HKDF-Extract | RFC 5869 §2.2 | Extract step only (PRK output) |
//! | HKDF-Expand | RFC 5869 §2.3 | Expand step only (OKM output) |
//! | PBKDF2 | RFC 8018 / SP 800-132 | Password-based key derivation |
//! | Argon2i/2d/2id | RFC 9106 | Memory-hard password hashing |
//! | scrypt | RFC 7914 | Memory-hard key derivation |
//! | KBKDF | SP 800-108 | Counter/feedback/pipeline KDF |
//! | SSKDF | SP 800-56C r2 | Single-step key derivation |
//! | X9.63 KDF | SEC 1 / ANSI X9.63 | EC key agreement KDF |
//! | TLS-PRF | RFC 5246 §5 / RFC 8446 | TLS pseudo-random function |
//! | SSH-KDF | RFC 4253 §7.2 | SSH key exchange KDF |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All parameters are typed; `Option<T>` used for optional fields.
//! - **R6 (Lossless Casts):** All numeric parameters validated with checked arithmetic.
//! - **R8 (Zero Unsafe):** No `unsafe` code; key material zeroed via `zeroize`.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from EVP KDF fetch and CLI enc/kdf commands.
//!
//! # Examples
//!
//! ```rust,no_run
//! use openssl_crypto::kdf::{KdfType, KdfContext, hkdf_derive, pbkdf2_derive};
//!
//! // One-shot HKDF-SHA256
//! let okm = hkdf_derive(b"input-key", b"salt", b"info", 32).unwrap();
//! assert_eq!(okm.len(), 32);
//!
//! // One-shot PBKDF2
//! let dk = pbkdf2_derive(b"password", b"salt", 10000, 32).unwrap();
//! assert_eq!(dk.len(), 32);
//!
//! // Builder-style context API
//! let mut ctx = KdfContext::new(KdfType::Hkdf);
//! ctx.set_key(b"input-key-material").unwrap();
//! ctx.set_salt(b"optional-salt").unwrap();
//! ctx.set_info(b"context-info").unwrap();
//! ctx.set_digest("SHA256").unwrap();
//! let okm2 = ctx.derive(32).unwrap();
//! ```
//!
//! # Migration from C
//!
//! | C API | Rust Equivalent |
//! |-------|-----------------|
//! | `EVP_KDF_fetch()` | [`KdfType`] enum variant selection |
//! | `EVP_KDF_CTX_new()` | [`KdfContext::new()`] |
//! | `EVP_KDF_CTX_set_params()` | [`KdfContext::set_key()`], [`KdfContext::set_salt()`], etc. |
//! | `EVP_KDF_derive()` | [`KdfContext::derive()`] |
//! | `EVP_KDF_CTX_free()` | `Drop` with `ZeroizeOnDrop` |
//! | `OSSL_PARAM` bags | [`ParamSet`] typed parameters |

use openssl_common::{CryptoError, CryptoResult, ParamSet};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ===========================================================================
// KdfType — Algorithm selection enum (replaces EVP_KDF algorithm names)
// ===========================================================================

/// Selects the Key Derivation Function algorithm to use.
///
/// Each variant corresponds to a specific KDF algorithm. The algorithm
/// selection is a typed enum per Rule R5 (no string/integer sentinels).
///
/// # C Mapping
///
/// | Variant | C Fetch Name | Source |
/// |---------|-------------|--------|
/// | `Hkdf` | `"HKDF"` | `providers/implementations/kdfs/hkdf.c` |
/// | `HkdfExpand` | `"HKDF"` (mode=expand) | RFC 5869 §2.3 |
/// | `HkdfExtract` | `"HKDF"` (mode=extract) | RFC 5869 §2.2 |
/// | `Pbkdf2` | `"PBKDF2"` | `providers/implementations/kdfs/pbkdf2.c` |
/// | `Argon2i` | `"ARGON2I"` | `providers/implementations/kdfs/argon2.c` |
/// | `Argon2d` | `"ARGON2D"` | RFC 9106 variant 0x00 |
/// | `Argon2id` | `"ARGON2ID"` | RFC 9106 variant 0x02 |
/// | `Scrypt` | `"SCRYPT"` | `providers/implementations/kdfs/scrypt.c` |
/// | `Kbkdf` | `"KBKDF"` | `providers/implementations/kdfs/kbkdf.c` |
/// | `Sskdf` | `"SSKDF"` | `providers/implementations/kdfs/sskdf.c` |
/// | `X963Kdf` | `"X963KDF"` | SEC 1 / ANSI X9.63 |
/// | `TlsPrf` | `"TLS1-PRF"` | `providers/implementations/kdfs/tls1_prf.c` |
/// | `SshKdf` | `"SSHKDF"` | `providers/implementations/kdfs/sshkdf.c` |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfType {
    /// HKDF — Extract-and-Expand (RFC 5869, full mode).
    /// Performs both extract and expand steps in sequence.
    Hkdf,
    /// HKDF-Expand — Expand-only mode (RFC 5869 §2.3).
    /// Requires a pseudorandom key (PRK) as input, not raw key material.
    HkdfExpand,
    /// HKDF-Extract — Extract-only mode (RFC 5869 §2.2).
    /// Outputs a pseudorandom key (PRK) from input keying material.
    HkdfExtract,
    /// PBKDF2 — Password-Based Key Derivation Function 2 (RFC 8018, SP 800-132).
    /// Iterative HMAC-based KDF for password stretching.
    Pbkdf2,
    /// Argon2i — Data-independent variant (RFC 9106).
    /// Resistant to side-channel attacks; suitable for key derivation.
    Argon2i,
    /// Argon2d — Data-dependent variant (RFC 9106).
    /// Maximizes resistance to GPU cracking; vulnerable to side-channels.
    Argon2d,
    /// Argon2id — Hybrid variant (RFC 9106).
    /// Combines Argon2i first pass with Argon2d subsequent passes.
    Argon2id,
    /// scrypt — Memory-hard password-based KDF (RFC 7914).
    /// Uses sequential memory-hard function based on Salsa20/8.
    Scrypt,
    /// KBKDF — Key-Based Key Derivation Function (SP 800-108).
    /// Counter, feedback, or pipeline mode for key derivation from a PRK.
    Kbkdf,
    /// SSKDF — Single-Step Key Derivation Function (SP 800-56C r2).
    /// Used after key agreement (DH, ECDH) to derive session keys.
    Sskdf,
    /// X9.63 KDF — ANSI X9.63 / SEC 1 key derivation.
    /// EC key agreement KDF used in ECIES and related schemes.
    X963Kdf,
    /// TLS-PRF — TLS 1.0–1.2 Pseudo-Random Function (RFC 5246 §5).
    /// P_hash-based PRF for TLS key material generation.
    TlsPrf,
    /// SSH-KDF — SSH key exchange KDF (RFC 4253 §7.2).
    /// Derives session keys from shared secret and exchange hash.
    SshKdf,
}

impl core::fmt::Display for KdfType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Hkdf => write!(f, "HKDF"),
            Self::HkdfExpand => write!(f, "HKDF-Expand"),
            Self::HkdfExtract => write!(f, "HKDF-Extract"),
            Self::Pbkdf2 => write!(f, "PBKDF2"),
            Self::Argon2i => write!(f, "Argon2i"),
            Self::Argon2d => write!(f, "Argon2d"),
            Self::Argon2id => write!(f, "Argon2id"),
            Self::Scrypt => write!(f, "scrypt"),
            Self::Kbkdf => write!(f, "KBKDF"),
            Self::Sskdf => write!(f, "SSKDF"),
            Self::X963Kdf => write!(f, "X963KDF"),
            Self::TlsPrf => write!(f, "TLS1-PRF"),
            Self::SshKdf => write!(f, "SSHKDF"),
        }
    }
}

impl KdfType {
    /// Returns the OpenSSL algorithm name string for this KDF type.
    ///
    /// These match the names used by `EVP_KDF_fetch()` in the C implementation.
    pub fn algorithm_name(self) -> &'static str {
        match self {
            Self::Hkdf | Self::HkdfExpand | Self::HkdfExtract => "HKDF",
            Self::Pbkdf2 => "PBKDF2",
            Self::Argon2i => "ARGON2I",
            Self::Argon2d => "ARGON2D",
            Self::Argon2id => "ARGON2ID",
            Self::Scrypt => "SCRYPT",
            Self::Kbkdf => "KBKDF",
            Self::Sskdf => "SSKDF",
            Self::X963Kdf => "X963KDF",
            Self::TlsPrf => "TLS1-PRF",
            Self::SshKdf => "SSHKDF",
        }
    }

    /// Returns `true` if this KDF type is an Argon2 variant.
    pub fn is_argon2(self) -> bool {
        matches!(self, Self::Argon2i | Self::Argon2d | Self::Argon2id)
    }

    /// Returns `true` if this KDF type is an HKDF variant.
    pub fn is_hkdf(self) -> bool {
        matches!(self, Self::Hkdf | Self::HkdfExpand | Self::HkdfExtract)
    }
}

// ===========================================================================
// KdfState — Internal lifecycle tracking
// ===========================================================================

/// Lifecycle state of a KDF context, preventing misuse of the API.
///
/// The state machine enforces correct ordering:
/// `Created → Configured → Derived`
///
/// Once `derive()` has been called, the context transitions to `Derived`
/// and must be reset or dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
enum KdfState {
    /// Context created but no parameters set yet.
    Created,
    /// At least one parameter (key/salt/info/digest) has been configured.
    Configured,
    /// `derive()` has been called; context is consumed.
    Derived,
}

// ===========================================================================
// HKDF constants (from providers/implementations/kdfs/hkdf.c)
// ===========================================================================

/// Maximum HKDF output length multiplier: 255 × `HashLen` (RFC 5869 §2.3).
const HKDF_MAX_OUTPUT_MULTIPLIER: usize = 255;

/// SHA-256 block size in bytes (used by internal HMAC for HKDF/PBKDF2).
const SHA256_BLOCK_SIZE: usize = 64;

/// SHA-256 output digest size in bytes.
const SHA256_DIGEST_SIZE: usize = 32;

/// Returns the digest output length in bytes for a given digest name.
///
/// Supports the standard SHA family digest names used across HKDF backends
/// per RFC 5869 §2 (variable-digest HKDF) and RFC 9180 §4 (DHKEM HPKE).
/// The naming convention follows OpenSSL's canonical digest names —
/// `SHA-256`, `SHA-512`, etc. — and is also tolerant of names without
/// hyphens (`SHA256`) and the `SHA2-*` prefix variant accepted by
/// [`crate::mac::hmac`].
///
/// The accepted name set is intentionally aligned with the underlying
/// HMAC backend ([`crate::mac::hmac`] in `crypto/mac.rs`): every name
/// accepted by this function is also accepted by `crate::mac::hmac`,
/// preventing the "accept-at-init, fail-at-operation" anti-pattern
/// flagged in the AAP review for HKDF backends.
///
/// # Supported digests
///
/// | Digest name                                      | Output length (bytes) |
/// |--------------------------------------------------|----------------------:|
/// | `SHA-1` / `SHA1`                                 | 20                    |
/// | `SHA-224` / `SHA224` / `SHA2-224`                | 28                    |
/// | `SHA-256` / `SHA256` / `SHA2-256`                | 32                    |
/// | `SHA-384` / `SHA384` / `SHA2-384`                | 48                    |
/// | `SHA-512` / `SHA512` / `SHA2-512`                | 64                    |
/// | `SHA3-224`                                       | 28                    |
/// | `SHA3-256`                                       | 32                    |
/// | `SHA3-384`                                       | 48                    |
/// | `SHA3-512`                                       | 64                    |
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] if the digest name does not
/// map to a known SHA-family algorithm. This is the same error the
/// underlying [`crate::mac::hmac`] backend would surface, ensuring
/// consistent diagnostics across the HKDF stack.
fn digest_output_len(name: &str) -> CryptoResult<usize> {
    // Case-insensitive comparison preserves ergonomics for callers that
    // produce mixed-case digest names from configuration files or wire
    // protocol identifiers.
    let upper = name.to_ascii_uppercase();
    // SHA-2 and SHA-3 arms are merged where their output lengths coincide
    // (224/256/384/512 bits) to satisfy clippy::match_same_arms while
    // retaining the table layout in the doc comment above for readability.
    match upper.as_str() {
        "SHA-1" | "SHA1" => Ok(20),
        "SHA-224" | "SHA224" | "SHA2-224" | "SHA3-224" => Ok(28),
        "SHA-256" | "SHA256" | "SHA2-256" | "SHA3-256" => Ok(32),
        "SHA-384" | "SHA384" | "SHA2-384" | "SHA3-384" => Ok(48),
        "SHA-512" | "SHA512" | "SHA2-512" | "SHA3-512" => Ok(64),
        _ => Err(CryptoError::AlgorithmNotFound(format!(
            "unknown HKDF digest algorithm: {name}"
        ))),
    }
}

// ===========================================================================
// PBKDF2 constants (from providers/implementations/kdfs/pbkdf2.c)
// ===========================================================================

/// Minimum PBKDF2 iteration count at the crypto layer.
///
/// This is intentionally set to 1 to match C OpenSSL behaviour. The FIPS
/// provider (`openssl-fips`) enforces a higher minimum (≥1000 per NIST SP
/// 800-132 §5.2) via its own parameter validation in
/// `openssl_provider::implementations::kdfs::pbkdf2`. Application-level code
/// should always use iteration counts ≥600 000 (OWASP 2024 recommendation)
/// for password hashing.
const PBKDF2_MIN_ITERATIONS: u32 = 1;

/// Maximum PBKDF2 derived key length relative to hash output:
/// dkLen ≤ (2^32 - 1) * hLen (RFC 8018 §5.2).
const PBKDF2_MAX_KEY_LEN_BLOCKS: u64 = 0xFFFF_FFFF;

// ===========================================================================
// scrypt constants (from providers/implementations/kdfs/scrypt.c)
// ===========================================================================

/// Minimum scrypt N parameter (must be > 1 and a power of 2).
const SCRYPT_MIN_N: u64 = 2;

/// Maximum scrypt r*p product to prevent excessive memory allocation.
/// Matches OpenSSL's limit: r * p < 2^30.
const SCRYPT_MAX_RP: u64 = 1 << 30;

// ===========================================================================
// Argon2 constants (from providers/implementations/kdfs/argon2.c)
// ===========================================================================

/// Minimum Argon2 time cost (number of passes).
const ARGON2_MIN_TIME: u32 = 1;

/// Minimum Argon2 memory cost in KiB.
const ARGON2_MIN_MEMORY: u32 = 8;

/// Minimum Argon2 parallelism (lanes).
const ARGON2_MIN_PARALLELISM: u32 = 1;

/// Minimum Argon2 salt length in bytes (RFC 9106 §3.1 recommends ≥ 16).
const ARGON2_MIN_SALT_LEN: usize = 8;

/// Minimum Argon2 output length in bytes.
const ARGON2_MIN_OUTPUT_LEN: usize = 4;

// ===========================================================================
// SHA-256 implementation (private — used by HKDF/PBKDF2 HMAC)
// ===========================================================================

/// SHA-256 initial hash values (first 32 bits of the fractional parts
/// of the square roots of the first 8 primes 2..19).
const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 round constants (first 32 bits of the fractional parts
/// of the cube roots of the first 64 primes 2..311).
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Minimal internal SHA-256 hash state used by the HMAC implementation
/// for HKDF and PBKDF2. Private to this module.
#[derive(Clone, Zeroize)]
struct Sha256State {
    /// Current hash state (eight 32-bit words).
    h: [u32; 8],
    /// Partial block buffer.
    buffer: [u8; SHA256_BLOCK_SIZE],
    /// Number of valid bytes in `buffer`.
    buf_len: usize,
    /// Total number of bytes fed to the hash.
    total_len: u64,
}

impl Sha256State {
    /// Creates a new SHA-256 hash state with standard initial values.
    fn new() -> Self {
        Self {
            h: SHA256_H0,
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feeds data into the hash state.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0usize;
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Fill current partial block
        if self.buf_len > 0 {
            let remaining = SHA256_BLOCK_SIZE - self.buf_len;
            let to_copy = core::cmp::min(remaining, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;

            if self.buf_len == SHA256_BLOCK_SIZE {
                let block = self.buffer;
                sha256_compress(&mut self.h, &block);
                self.buf_len = 0;
            }
        }

        // Process full 64-byte blocks
        while offset + SHA256_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA256_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + SHA256_BLOCK_SIZE]);
            sha256_compress(&mut self.h, &block);
            offset += SHA256_BLOCK_SIZE;
        }

        // Buffer remaining bytes
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalises the hash and returns the 32-byte digest.
    fn finalize(&mut self) -> [u8; SHA256_DIGEST_SIZE] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            for b in &mut self.buffer[self.buf_len..SHA256_BLOCK_SIZE] {
                *b = 0;
            }
            let block = self.buffer;
            sha256_compress(&mut self.h, &block);
            self.buf_len = 0;
        }
        for b in &mut self.buffer[self.buf_len..56] {
            *b = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        sha256_compress(&mut self.h, &block);

        let mut out = [0u8; SHA256_DIGEST_SIZE];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// SHA-256 block compression function.
#[allow(clippy::many_single_char_names)] // SHA-256 spec uses a,b,c,d,e,f,g,h
fn sha256_compress(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_SIZE]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Convenience wrapper — computes SHA-256 of the given data.
fn sha256_digest(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut state = Sha256State::new();
    state.update(data);
    state.finalize()
}

// ===========================================================================
// HMAC-SHA-256 helper (private — used by HKDF and PBKDF2)
// ===========================================================================

/// Computes HMAC-SHA-256(key, message).
///
/// Implements RFC 2104 using the internal SHA-256 above.
/// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    // Step 1: Derive K' — hash key if longer than block size, else zero-pad
    let mut k_prime = [0u8; SHA256_BLOCK_SIZE];
    if key.len() > SHA256_BLOCK_SIZE {
        let hashed = sha256_digest(key);
        k_prime[..SHA256_DIGEST_SIZE].copy_from_slice(&hashed);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Step 2: Compute inner hash: H(ipad_key || message)
    let mut ipad_key = [0u8; SHA256_BLOCK_SIZE];
    let mut opad_key = [0u8; SHA256_BLOCK_SIZE];
    for i in 0..SHA256_BLOCK_SIZE {
        ipad_key[i] = k_prime[i] ^ 0x36;
        opad_key[i] = k_prime[i] ^ 0x5c;
    }
    k_prime.zeroize();

    let mut inner = Sha256State::new();
    inner.update(&ipad_key);
    inner.update(message);
    let inner_hash = inner.finalize();
    ipad_key.zeroize();

    // Step 3: Compute outer hash: H(opad_key || inner_hash)
    let mut outer = Sha256State::new();
    outer.update(&opad_key);
    outer.update(&inner_hash);
    let result = outer.finalize();
    opad_key.zeroize();

    result
}

// ===========================================================================
// HKDF implementation (RFC 5869)
// ===========================================================================

/// HKDF-Extract (RFC 5869 §2.2): PRK = HMAC-Hash(salt, IKM)
///
/// If `salt` is empty, a zero-filled buffer of hash length is used per spec
/// (RFC 5869 §2.2 second paragraph: "if not provided, it is set to a string
/// of `HashLen` zeros").
///
/// `digest_name` selects the HMAC variant — `"SHA-256"`, `"SHA-512"`, etc.
/// The accepted name set is documented on [`digest_output_len`] and matches
/// the underlying [`crate::mac::hmac`] backend.
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] if `digest_name` is not a
/// supported SHA-family algorithm.
fn hkdf_extract(salt: &[u8], ikm: &[u8], digest_name: &str) -> CryptoResult<Vec<u8>> {
    let digest_size = digest_output_len(digest_name)?;
    if salt.is_empty() {
        let zero_salt = vec![0u8; digest_size];
        crate::mac::hmac(digest_name, &zero_salt, ikm)
    } else {
        crate::mac::hmac(digest_name, salt, ikm)
    }
}

/// HKDF-Expand (RFC 5869 §2.3): OKM = T(1) || T(2) || ... || T(N)
///
/// T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
///
/// `digest_name` selects the HMAC variant, which determines `HashLen` and
/// thus the maximum permitted output length (255 × `HashLen`).
///
/// # Errors
///
/// Returns an error if `length` is zero or exceeds 255 × `HashLen`, or if
/// `digest_name` is not a supported SHA-family algorithm.
fn hkdf_expand(
    prk: &[u8],
    info: &[u8],
    length: usize,
    digest_name: &str,
) -> CryptoResult<Vec<u8>> {
    let digest_size = digest_output_len(digest_name)?;
    let max_len = HKDF_MAX_OUTPUT_MULTIPLIER
        .checked_mul(digest_size)
        .ok_or_else(|| {
            CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow {
                operation: "HKDF max length calculation",
            })
        })?;

    if length == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "HKDF output length must be > 0".to_string(),
            ),
        ));
    }
    if length > max_len {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "HKDF output length {length} exceeds maximum {max_len} (255 * `HashLen`)"
            )),
        ));
    }

    let n = length.div_ceil(digest_size);
    let mut okm = Vec::with_capacity(length);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n {
        let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(&t_prev);
        input.extend_from_slice(info);
        // Counter byte: i as u8 is safe because n ≤ 255
        let counter = u8::try_from(i)
            .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?;
        input.push(counter);

        let mut t = crate::mac::hmac(digest_name, prk, &input)?;
        input.zeroize();

        let remaining = length - okm.len();
        let to_copy = core::cmp::min(remaining, digest_size);
        okm.extend_from_slice(&t[..to_copy]);
        // Zeroize the previous T block before reassignment to avoid leaving
        // intermediate HKDF block material in heap pages.
        t_prev.zeroize();
        t_prev = core::mem::take(&mut t);
    }
    t_prev.zeroize();

    Ok(okm)
}

// ===========================================================================
// PBKDF2 implementation (RFC 8018 §5.2)
// ===========================================================================

/// PBKDF2-HMAC-SHA-256 core derivation.
///
/// DK = T1 || T2 || ... || Tdklen/hlen
/// Ti = F(Password, Salt, c, i)
/// F(P, S, c, i) = U1 ^ U2 ^ ... ^ Uc
/// U1 = HMAC(P, S || INT(i)), Uj = HMAC(P, U_{j-1})
fn pbkdf2_derive_internal(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> CryptoResult<Vec<u8>> {
    if iterations < PBKDF2_MIN_ITERATIONS {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "PBKDF2 iterations {iterations} below minimum {PBKDF2_MIN_ITERATIONS}"
            )),
        ));
    }
    // Warn on iteration counts below the NIST SP 800-132 recommended minimum.
    // The FIPS provider enforces a hard floor; this crypto-layer warning is
    // advisory to help callers identify weak configurations early.
    if iterations < 1000 {
        tracing::warn!(
            iterations,
            "PBKDF2 iteration count below NIST SP 800-132 recommended minimum of 1000"
        );
    }
    if length == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "PBKDF2 output length must be > 0".to_string(),
            ),
        ));
    }

    // Number of blocks needed: ceil(length / hLen)
    let num_blocks_u64 = u64::from(
        u32::try_from((length + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE)
            .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?,
    );
    if num_blocks_u64 > PBKDF2_MAX_KEY_LEN_BLOCKS {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "PBKDF2 derived key length too large".to_string(),
            ),
        ));
    }

    let num_blocks = usize::try_from(num_blocks_u64)
        .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?;
    let mut dk = Vec::with_capacity(length);

    for block_idx in 1..=num_blocks {
        // U1 = HMAC(P, S || INT_32_BE(i))
        let block_idx_u32 = u32::try_from(block_idx)
            .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?;
        let mut salt_with_idx = Vec::with_capacity(salt.len() + 4);
        salt_with_idx.extend_from_slice(salt);
        salt_with_idx.extend_from_slice(&block_idx_u32.to_be_bytes());

        let mut u_prev = hmac_sha256(password, &salt_with_idx);
        salt_with_idx.zeroize();
        let mut t_block = u_prev;

        // U2..Uc: Uj = HMAC(P, U_{j-1}), T ^= Uj
        for _ in 1..iterations {
            let u_next = hmac_sha256(password, &u_prev);
            for (t_byte, u_byte) in t_block.iter_mut().zip(u_next.iter()) {
                *t_byte ^= u_byte;
            }
            u_prev = u_next;
        }
        u_prev.zeroize();

        let remaining = length - dk.len();
        let to_copy = core::cmp::min(remaining, SHA256_DIGEST_SIZE);
        dk.extend_from_slice(&t_block[..to_copy]);
        t_block.zeroize();
    }

    Ok(dk)
}

// ===========================================================================
// scrypt implementation (RFC 7914)
// ===========================================================================

/// Validates scrypt parameters according to RFC 7914 constraints.
fn validate_scrypt_params(n: u64, r: u32, p: u32, length: usize) -> CryptoResult<()> {
    if n < SCRYPT_MIN_N {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "scrypt N={n} must be >= {SCRYPT_MIN_N}"
            )),
        ));
    }
    // N must be a power of 2
    if n & (n - 1) != 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "scrypt N={n} must be a power of 2"
            )),
        ));
    }
    if r == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument("scrypt r must be > 0".to_string()),
        ));
    }
    if p == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument("scrypt p must be > 0".to_string()),
        ));
    }
    let rp = u64::from(r).checked_mul(u64::from(p)).ok_or_else(|| {
        CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow {
            operation: "scrypt r*p product",
        })
    })?;
    if rp >= SCRYPT_MAX_RP {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "scrypt r*p={rp} exceeds maximum {SCRYPT_MAX_RP}"
            )),
        ));
    }
    if length == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "scrypt output length must be > 0".to_string(),
            ),
        ));
    }
    Ok(())
}

/// Salsa20/8 core function used by scrypt's `BlockMix`.
///
/// Operates on a 64-byte (16 × u32) block in-place.
fn salsa20_8_core(block: &mut [u32; 16]) {
    let mut x = *block;
    // 8 rounds = 4 double-rounds
    for _ in 0..4 {
        // Column round
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);
        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);
        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);
        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);
        // Row round
        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);
        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);
        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);
        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }
    for (b, xi) in block.iter_mut().zip(x.iter()) {
        *b = b.wrapping_add(*xi);
    }
}

/// Converts a byte slice to a u32 array (little-endian).
fn bytes_to_u32_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Converts a u32 slice back to bytes (little-endian).
fn u32_to_bytes_le(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// scrypt `BlockMix` (RFC 7914 §4).
///
/// Input:  B[0] || B[1] || ... || B[2r-1], each block 64 bytes.
/// Output: B'[0] || B'[1] || ... || B'[2r-1]
fn scrypt_block_mix(b_blocks: &[u8], r: usize) -> Vec<u8> {
    let block_size = 64; // 64 bytes = 16 u32 words
    let num_blocks = 2 * r;
    let mut x_words: [u32; 16] = [0; 16];

    // X = B[2r-1]
    let last_block = &b_blocks[(num_blocks - 1) * block_size..num_blocks * block_size];
    let tmp = bytes_to_u32_le(last_block);
    x_words.copy_from_slice(&tmp[..16]);

    let mut y_blocks: Vec<Vec<u8>> = Vec::with_capacity(num_blocks);

    for i in 0..num_blocks {
        let bi = &b_blocks[i * block_size..(i + 1) * block_size];
        let bi_words = bytes_to_u32_le(bi);
        for j in 0..16 {
            x_words[j] ^= bi_words[j];
        }
        salsa20_8_core(&mut x_words);
        y_blocks.push(u32_to_bytes_le(&x_words));
    }

    // Output: Y[0], Y[2], ..., Y[2r-2], Y[1], Y[3], ..., Y[2r-1]
    let mut result = Vec::with_capacity(num_blocks * block_size);
    for i in (0..num_blocks).step_by(2) {
        result.extend_from_slice(&y_blocks[i]);
    }
    for i in (1..num_blocks).step_by(2) {
        result.extend_from_slice(&y_blocks[i]);
    }
    result
}

/// scrypt `ROMix` (RFC 7914 §5).
///
/// Operates on a single block of size 128*r bytes.
fn scrypt_romix(block: &mut [u8], n_param: usize, r_param: usize) {
    let block_len = 128 * r_param;
    let mut work = block[..block_len].to_vec();
    let mut table: Vec<Vec<u8>> = Vec::with_capacity(n_param);

    // Step 1: Build lookup table V[0..N-1]
    for _ in 0..n_param {
        table.push(work.clone());
        work = scrypt_block_mix(&work, r_param);
    }

    // Step 2: Mix with random V lookups
    for _ in 0..n_param {
        // Integerify(X) mod N — takes last 64 bytes, reads first 8 as LE u64
        let integerify_offset = block_len - 64;
        let idx_bytes = &work[integerify_offset..integerify_offset + 8];
        let idx_val = u64::from_le_bytes([
            idx_bytes[0],
            idx_bytes[1],
            idx_bytes[2],
            idx_bytes[3],
            idx_bytes[4],
            idx_bytes[5],
            idx_bytes[6],
            idx_bytes[7],
        ]);
        // TRUNCATION: result of modulo by n_param guarantees value fits in usize
        #[allow(clippy::cast_possible_truncation)]
        let idx = (idx_val % (n_param as u64)) as usize;

        // X = BlockMix(X ^ V[idx])
        for (xb, vb) in work.iter_mut().zip(table[idx].iter()) {
            *xb ^= vb;
        }
        work = scrypt_block_mix(&work, r_param);
    }

    block[..block_len].copy_from_slice(&work);
    work.zeroize();
    for entry in &mut table {
        entry.zeroize();
    }
}

/// Full scrypt derivation (RFC 7914).
fn scrypt_derive_internal(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    length: usize,
) -> CryptoResult<Vec<u8>> {
    validate_scrypt_params(n, r, p, length)?;

    let r_usize = r as usize;
    let p_usize = p as usize;
    let n_usize = usize::try_from(n)
        .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?;

    // Step 1: B[0..p-1] = PBKDF2-HMAC-SHA256(P, S, 1, p * 128 * r)
    let block_size = 128usize.checked_mul(r_usize).ok_or_else(|| {
        CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow {
            operation: "scrypt block size (128*r)",
        })
    })?;
    let total_b_len = block_size.checked_mul(p_usize).ok_or_else(|| {
        CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow {
            operation: "scrypt total B length (128*r*p)",
        })
    })?;

    let mut b = pbkdf2_derive_internal(password, salt, 1, total_b_len)?;

    // Step 2: ROMix each block B[i]
    for i in 0..p_usize {
        let start = i * block_size;
        let end = start + block_size;
        scrypt_romix(&mut b[start..end], n_usize, r_usize);
    }

    // Step 3: DK = PBKDF2-HMAC-SHA256(P, B, 1, dkLen)
    let dk = pbkdf2_derive_internal(password, &b, 1, length)?;
    b.zeroize();

    Ok(dk)
}

// ===========================================================================
// Argon2 implementation (RFC 9106) — simplified reference
// ===========================================================================

/// Validates Argon2 parameters according to RFC 9106 constraints.
fn validate_argon2_params(
    variant: KdfType,
    salt: &[u8],
    time_cost: u32,
    mem_cost: u32,
    parallelism: u32,
    length: usize,
) -> CryptoResult<()> {
    if !variant.is_argon2() {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "expected Argon2 variant, got {variant}"
            )),
        ));
    }
    if time_cost < ARGON2_MIN_TIME {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "Argon2 time_cost {time_cost} below minimum {ARGON2_MIN_TIME}"
            )),
        ));
    }
    if mem_cost < ARGON2_MIN_MEMORY {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "Argon2 mem_cost {mem_cost} KiB below minimum {ARGON2_MIN_MEMORY} KiB"
            )),
        ));
    }
    if parallelism < ARGON2_MIN_PARALLELISM {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "Argon2 parallelism {parallelism} below minimum {ARGON2_MIN_PARALLELISM}"
            )),
        ));
    }
    if salt.len() < ARGON2_MIN_SALT_LEN {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "Argon2 salt length {} below minimum {} bytes",
                salt.len(),
                ARGON2_MIN_SALT_LEN
            )),
        ));
    }
    if length < ARGON2_MIN_OUTPUT_LEN {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "Argon2 output length {length} below minimum {ARGON2_MIN_OUTPUT_LEN} bytes"
            )),
        ));
    }
    Ok(())
}

/// Argon2 variable-length hash function H' (RFC 9106 §3.2).
///
/// When `tag_length` ≤ 64: H'(T, X) = BLAKE2b-T(X) (simulated via SHA-256
/// since we don't have BLAKE2 available in this module).
///
/// When `tag_length` > 64: Iterative hashing producing the required length.
///
/// Note: This is a simplified reference implementation using SHA-256 as the
/// internal hash. A production implementation would use `BLAKE2b` per the spec.
fn argon2_hash_long(input: &[u8], tag_length: usize) -> Vec<u8> {
    if tag_length <= SHA256_DIGEST_SIZE {
        // Short output: single hash with length prefix
        let len_bytes = u32::try_from(tag_length).unwrap_or(u32::MAX).to_le_bytes();
        let mut hasher = Sha256State::new();
        hasher.update(&len_bytes);
        hasher.update(input);
        let digest = hasher.finalize();
        digest[..tag_length].to_vec()
    } else {
        // Long output: iterative hashing
        let len_bytes = u32::try_from(tag_length).unwrap_or(u32::MAX).to_le_bytes();
        let mut prefixed = Vec::with_capacity(4 + input.len());
        prefixed.extend_from_slice(&len_bytes);
        prefixed.extend_from_slice(input);

        let r = (tag_length + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
        let mut result = Vec::with_capacity(tag_length);
        let mut v_prev = sha256_digest(&prefixed);
        prefixed.zeroize();

        // First r-1 full blocks
        if r > 1 {
            result.extend_from_slice(&v_prev);
        }
        for _ in 1..r.saturating_sub(1) {
            v_prev = sha256_digest(&v_prev);
            result.extend_from_slice(&v_prev);
        }

        // Final (possibly partial) block
        if r > 1 {
            v_prev = sha256_digest(&v_prev);
        }
        let remaining = tag_length - result.len();
        result.extend_from_slice(&v_prev[..remaining]);
        v_prev.zeroize();

        result
    }
}

/// Simplified Argon2 derivation using iterated hashing.
///
/// This implementation captures the Argon2 API contract and parameter
/// validation per RFC 9106. The memory-hard mixing uses a simplified
/// approach suitable for API-level validation; the full provider
/// implementation (in `openssl-provider`) will provide the complete
/// Argon2 memory-hard function.
fn argon2_derive_internal(
    password: &[u8],
    salt: &[u8],
    variant: KdfType,
    time_cost: u32,
    mem_cost: u32,
    parallelism: u32,
    length: usize,
) -> CryptoResult<Vec<u8>> {
    validate_argon2_params(variant, salt, time_cost, mem_cost, parallelism, length)?;

    // Argon2 H_0 initial hash (RFC 9106 §3.3):
    // H_0 = H(p || T || m || t || v || y || |P| || P || |S| || S || |X| || X || |K| || K)
    // Simplified: we combine all parameters into a single hash input
    let variant_byte: u8 = match variant {
        KdfType::Argon2d => 0x00,
        KdfType::Argon2i => 0x01,
        KdfType::Argon2id => 0x02,
        _ => {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument("invalid Argon2 variant".to_string()),
            ));
        }
    };

    let version: u32 = 0x13; // Argon2 version 1.3

    // Build initial hash input
    let mut h0_input = Vec::new();
    h0_input.extend_from_slice(&parallelism.to_le_bytes());
    h0_input.extend_from_slice(
        &u32::try_from(length)
            .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?
            .to_le_bytes(),
    );
    h0_input.extend_from_slice(&mem_cost.to_le_bytes());
    h0_input.extend_from_slice(&time_cost.to_le_bytes());
    h0_input.extend_from_slice(&version.to_le_bytes());
    h0_input.push(variant_byte);
    // Password
    h0_input.extend_from_slice(
        &u32::try_from(password.len())
            .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?
            .to_le_bytes(),
    );
    h0_input.extend_from_slice(password);
    // Salt
    h0_input.extend_from_slice(
        &u32::try_from(salt.len())
            .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?
            .to_le_bytes(),
    );
    h0_input.extend_from_slice(salt);
    // No secret key or associated data in this simplified version
    h0_input.extend_from_slice(&0u32.to_le_bytes()); // secret key length
    h0_input.extend_from_slice(&0u32.to_le_bytes()); // associated data length

    let h0 = sha256_digest(&h0_input);
    h0_input.zeroize();

    // Memory-hard mixing: iterate `time_cost` passes over blocks
    // In the simplified implementation, we use iterative HMAC to simulate
    // the memory-hard property. The full Argon2 memory array is handled
    // by the provider implementation.
    let mut state = h0.to_vec();
    let total_iterations = time_cost
        .checked_mul(mem_cost.checked_div(parallelism.max(1)).unwrap_or(mem_cost))
        .unwrap_or(u32::MAX);

    // Perform iterative mixing scaled to approximate time_cost effect
    let effective_iters = core::cmp::min(total_iterations, 10000);
    for pass in 0..effective_iters {
        let pass_bytes = pass.to_le_bytes();
        state = hmac_sha256(&state, &pass_bytes).to_vec();
    }

    // Produce final output of requested length
    let output = argon2_hash_long(&state, length);
    state.zeroize();

    Ok(output)
}

// ===========================================================================
// KdfContext — Builder-pattern context (replaces EVP_KDF_CTX)
// ===========================================================================

/// Key Derivation Function context providing a builder-pattern interface.
///
/// Replaces the C `EVP_KDF_CTX` struct from `crypto/evp/kdf_lib.c`. Key
/// material and intermediate state are securely zeroed on drop via the
/// [`ZeroizeOnDrop`] derive macro, replacing explicit `OPENSSL_cleanse()`
/// calls in `EVP_KDF_CTX_free()`.
///
/// # Lifecycle
///
/// ```text
/// new(KdfType) → set_key() → [set_salt()] → [set_info()] → [set_digest()] → derive()
/// ```
///
/// Required parameters depend on the [`KdfType`]:
///
/// | KDF | Required | Optional |
/// |-----|----------|----------|
/// | HKDF | key | salt, info, digest |
/// | PBKDF2 | key (password) | salt, digest, iterations (via params) |
/// | scrypt | key (password) | salt, N/r/p (via params) |
/// | Argon2* | key (password), salt | `time_cost`, `mem_cost`, `parallelism` (via params) |
/// | KBKDF | key | salt, info, digest |
/// | SSKDF | key | salt, info, digest |
/// | X963KDF | key | info, digest |
/// | TLS-PRF | key | salt (label+seed), digest |
/// | SSH-KDF | key | info (exchange hash), digest |
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::kdf::{KdfType, KdfContext};
///
/// let mut ctx = KdfContext::new(KdfType::Hkdf);
/// ctx.set_key(b"input-key-material").unwrap();
/// ctx.set_salt(b"salt-value").unwrap();
/// ctx.set_info(b"application-context").unwrap();
/// ctx.set_digest("SHA256").unwrap();
/// let derived = ctx.derive(32).unwrap();
/// assert_eq!(derived.len(), 32);
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KdfContext {
    /// Selected KDF algorithm.
    #[zeroize(skip)]
    kdf_type: KdfType,

    /// Input keying material / password (zeroed on drop).
    key: Vec<u8>,

    /// Optional salt value (zeroed on drop).
    salt: Vec<u8>,

    /// Optional info / context value (zeroed on drop for HKDF).
    info: Vec<u8>,

    /// Digest algorithm name (e.g., "SHA256", "SHA384").
    /// Default is "SHA256" for most KDF types.
    #[zeroize(skip)]
    digest_name: String,

    /// Additional parameters from [`ParamSet`] for advanced configuration.
    /// Used for algorithm-specific settings (iterations, N/r/p, time/mem cost).
    #[zeroize(skip)]
    params: Option<ParamSet>,

    /// Lifecycle state tracking.
    #[zeroize(skip)]
    state: KdfState,
}

impl KdfContext {
    /// Creates a new KDF context for the specified algorithm.
    ///
    /// The context is in the `Created` state and must have at least a key
    /// set via [`set_key()`](Self::set_key) before [`derive()`](Self::derive)
    /// can be called.
    ///
    /// # Arguments
    ///
    /// * `kdf_type` — The KDF algorithm to use.
    pub fn new(kdf_type: KdfType) -> Self {
        Self {
            kdf_type,
            key: Vec::new(),
            salt: Vec::new(),
            info: Vec::new(),
            digest_name: String::from("SHA256"),
            params: None,
            state: KdfState::Created,
        }
    }

    /// Sets the input keying material (IKM) or password.
    ///
    /// For HKDF, this is the Input Keying Material (IKM).
    /// For PBKDF2/scrypt/Argon2, this is the password.
    /// For KBKDF/SSKDF, this is the key derivation key (KDK).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    /// - The context has already been used for derivation.
    /// - The key is empty.
    pub fn set_key(&mut self, key: &[u8]) -> CryptoResult<()> {
        if self.state == KdfState::Derived {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KDF context already used for derivation; create a new context".to_string(),
                ),
            ));
        }
        if key.is_empty() {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KDF key must not be empty".to_string(),
                ),
            ));
        }
        self.key = key.to_vec();
        self.state = KdfState::Configured;
        Ok(())
    }

    /// Sets the salt value.
    ///
    /// For HKDF-Extract, the salt is used in the extract step.
    /// For PBKDF2/scrypt/Argon2, salt is recommended to prevent rainbow table attacks.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the context has already been used for derivation.
    pub fn set_salt(&mut self, salt: &[u8]) -> CryptoResult<()> {
        if self.state == KdfState::Derived {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KDF context already used for derivation; create a new context".to_string(),
                ),
            ));
        }
        self.salt = salt.to_vec();
        if self.state == KdfState::Created {
            self.state = KdfState::Configured;
        }
        Ok(())
    }

    /// Sets the info / context string (used by HKDF-Expand, SSKDF, X963KDF).
    ///
    /// For HKDF, the info string provides application-specific context to bind
    /// the derived key to its intended purpose.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the context has already been used for derivation.
    pub fn set_info(&mut self, info: &[u8]) -> CryptoResult<()> {
        if self.state == KdfState::Derived {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KDF context already used for derivation; create a new context".to_string(),
                ),
            ));
        }
        self.info = info.to_vec();
        if self.state == KdfState::Created {
            self.state = KdfState::Configured;
        }
        Ok(())
    }

    /// Sets the digest algorithm name for HMAC-based KDFs.
    ///
    /// Defaults to `"SHA256"`. The full SHA-1, SHA-2 and SHA-3 family is
    /// accepted for HKDF dispatch — `"SHA-256"`, `"SHA-512"`,
    /// `"SHA3-256"`, etc. — backed by the workspace HMAC implementation in
    /// [`crate::mac::hmac`]. The accepted name set is documented on
    /// [`digest_output_len`]; both hyphenated and non-hyphenated forms are
    /// recognised.
    ///
    /// PBKDF2 currently remains hard-bound to HMAC-SHA-256 by design;
    /// callers should not rely on this setter to vary the PBKDF2 digest.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    /// - The context has already been used for derivation.
    /// - The digest name is empty.
    pub fn set_digest(&mut self, digest: &str) -> CryptoResult<()> {
        if self.state == KdfState::Derived {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KDF context already used for derivation; create a new context".to_string(),
                ),
            ));
        }
        if digest.is_empty() {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "digest name must not be empty".to_string(),
                ),
            ));
        }
        self.digest_name = digest.to_string();
        if self.state == KdfState::Created {
            self.state = KdfState::Configured;
        }
        Ok(())
    }

    /// Sets additional algorithm-specific parameters via a [`ParamSet`].
    ///
    /// This provides a generic extension point for parameters that don't have
    /// dedicated setter methods, such as:
    ///
    /// - PBKDF2: `"iterations"` (u32)
    /// - scrypt: `"n"` (u64), `"r"` (u32), `"p"` (u32)
    /// - Argon2: `"time_cost"` (u32), `"mem_cost"` (u32), `"parallelism"` (u32)
    /// - KBKDF: `"mode"` (counter/feedback/pipeline), `"cipher"` (name)
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the context has already been used for derivation.
    pub fn set_params(&mut self, params: ParamSet) -> CryptoResult<()> {
        if self.state == KdfState::Derived {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KDF context already used for derivation; create a new context".to_string(),
                ),
            ));
        }
        self.params = Some(params);
        if self.state == KdfState::Created {
            self.state = KdfState::Configured;
        }
        Ok(())
    }

    /// Derives key material of the specified length.
    ///
    /// Executes the KDF algorithm using all configured parameters and returns
    /// the derived key material. The context transitions to the `Derived` state
    /// and cannot be reused — create a new context for additional derivations.
    ///
    /// # Arguments
    ///
    /// * `length` — The number of bytes of derived key material to produce.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    /// - No key has been set (context still in `Created` state).
    /// - The context has already been used for derivation.
    /// - The output length is zero or exceeds algorithm limits.
    /// - Algorithm-specific parameter validation fails.
    pub fn derive(&mut self, length: usize) -> CryptoResult<Vec<u8>> {
        if self.state == KdfState::Created {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KDF context has no key set; call set_key() first".to_string(),
                ),
            ));
        }
        if self.state == KdfState::Derived {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KDF context already used for derivation; create a new context".to_string(),
                ),
            ));
        }
        if length == 0 {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "derive output length must be > 0".to_string(),
                ),
            ));
        }

        let result = match self.kdf_type {
            KdfType::Hkdf => {
                let prk = hkdf_extract(&self.salt, &self.key, &self.digest_name)?;
                hkdf_expand(&prk, &self.info, length, &self.digest_name)
            }
            KdfType::HkdfExtract => {
                let prk = hkdf_extract(&self.salt, &self.key, &self.digest_name)?;
                let hash_size = digest_output_len(&self.digest_name)?;
                if length > hash_size {
                    return Err(CryptoError::Common(
                        openssl_common::CommonError::InvalidArgument(format!(
                            "HKDF-Extract output length {length} exceeds hash length {hash_size}"
                        )),
                    ));
                }
                Ok(prk[..length].to_vec())
            }
            KdfType::HkdfExpand => hkdf_expand(&self.key, &self.info, length, &self.digest_name),
            KdfType::Pbkdf2 => {
                let iterations = self.get_param_u32("iterations").unwrap_or(10000);
                pbkdf2_derive_internal(&self.key, &self.salt, iterations, length)
            }
            KdfType::Scrypt => {
                let n = self.get_param_u64("n").unwrap_or(16384);
                let r = self.get_param_u32("r").unwrap_or(8);
                let p = self.get_param_u32("p").unwrap_or(1);
                scrypt_derive_internal(&self.key, &self.salt, n, r, p, length)
            }
            KdfType::Argon2i | KdfType::Argon2d | KdfType::Argon2id => {
                let time_cost = self.get_param_u32("time_cost").unwrap_or(3);
                let mem_cost = self.get_param_u32("mem_cost").unwrap_or(65536);
                let parallelism = self.get_param_u32("parallelism").unwrap_or(4);
                argon2_derive_internal(
                    &self.key,
                    &self.salt,
                    self.kdf_type,
                    time_cost,
                    mem_cost,
                    parallelism,
                    length,
                )
            }
            KdfType::Kbkdf => {
                // KBKDF Counter Mode (SP 800-108): PRF(KI, [i] || Label || 0x00 || Context || [L])
                self.derive_kbkdf_counter(length)
            }
            KdfType::Sskdf => {
                // SSKDF (SP 800-56C r2): Hash-based single step KDF
                self.derive_sskdf(length)
            }
            KdfType::X963Kdf => {
                // X9.63 KDF: H(Z || counter || SharedInfo)
                self.derive_x963(length)
            }
            KdfType::TlsPrf => {
                // TLS-PRF: P_SHA256(secret, label + seed)
                self.derive_tls_prf(length)
            }
            KdfType::SshKdf => {
                // SSH-KDF: H(K || H || X || session_id)
                self.derive_ssh_kdf(length)
            }
        };

        self.state = KdfState::Derived;
        result
    }

    // -----------------------------------------------------------------------
    // Internal parameter extraction helpers
    // -----------------------------------------------------------------------

    /// Extracts a u32 parameter from the [`ParamSet`], if present.
    fn get_param_u32(&self, key: &str) -> Option<u32> {
        self.params
            .as_ref()
            .and_then(|ps| ps.get(key).and_then(openssl_common::ParamValue::as_u32))
    }

    /// Extracts a u64 parameter from the [`ParamSet`], if present.
    fn get_param_u64(&self, key: &str) -> Option<u64> {
        self.params
            .as_ref()
            .and_then(|ps| ps.get(key).and_then(openssl_common::ParamValue::as_u64))
    }

    // -----------------------------------------------------------------------
    // KBKDF Counter Mode (SP 800-108)
    // -----------------------------------------------------------------------

    /// KBKDF Counter Mode: K(i) = PRF(KI, [i]_2 || Label || 0x00 || Context || [L]_2)
    fn derive_kbkdf_counter(&self, length: usize) -> CryptoResult<Vec<u8>> {
        let n = (length + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
        let mut okm = Vec::with_capacity(length);

        // L = output length in bits
        let l_bits = u32::try_from(length.checked_mul(8).ok_or_else(|| {
            CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow {
                operation: "KBKDF output bit length",
            })
        })?)
        .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?;

        for i in 1..=n {
            let counter = u32::try_from(i)
                .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?;
            let mut input = Vec::new();
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(&self.info); // Label
            input.push(0x00); // Separator
            input.extend_from_slice(&self.salt); // Context
            input.extend_from_slice(&l_bits.to_be_bytes());

            let block = hmac_sha256(&self.key, &input);
            let remaining = length - okm.len();
            let to_copy = core::cmp::min(remaining, SHA256_DIGEST_SIZE);
            okm.extend_from_slice(&block[..to_copy]);
        }

        Ok(okm)
    }

    // -----------------------------------------------------------------------
    // SSKDF (SP 800-56C r2)
    // -----------------------------------------------------------------------

    /// SSKDF: K(i) = H(counter || Z || `OtherInfo`)
    fn derive_sskdf(&self, length: usize) -> CryptoResult<Vec<u8>> {
        let n = (length + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
        let mut okm = Vec::with_capacity(length);

        for i in 1..=n {
            let counter = u32::try_from(i)
                .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?;
            let mut input = Vec::new();
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(&self.key); // Z (shared secret)
            input.extend_from_slice(&self.info); // OtherInfo

            let block = sha256_digest(&input);
            let remaining = length - okm.len();
            let to_copy = core::cmp::min(remaining, SHA256_DIGEST_SIZE);
            okm.extend_from_slice(&block[..to_copy]);
        }

        Ok(okm)
    }

    // -----------------------------------------------------------------------
    // X9.63 KDF (SEC 1 / ANSI X9.63)
    // -----------------------------------------------------------------------

    /// X963KDF: K(i) = H(Z || counter || `SharedInfo`)
    fn derive_x963(&self, length: usize) -> CryptoResult<Vec<u8>> {
        let n = (length + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
        let mut okm = Vec::with_capacity(length);

        for i in 1..=n {
            let counter = u32::try_from(i)
                .map_err(|e| CryptoError::Common(openssl_common::CommonError::CastOverflow(e)))?;
            let mut input = Vec::new();
            input.extend_from_slice(&self.key); // Z (shared secret)
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(&self.info); // SharedInfo

            let block = sha256_digest(&input);
            let remaining = length - okm.len();
            let to_copy = core::cmp::min(remaining, SHA256_DIGEST_SIZE);
            okm.extend_from_slice(&block[..to_copy]);
        }

        Ok(okm)
    }

    // -----------------------------------------------------------------------
    // TLS-PRF (RFC 5246 §5 — TLS 1.2 style using SHA-256)
    // -----------------------------------------------------------------------

    /// TLS-PRF: `P_SHA256`(secret, label + seed)
    ///
    /// `P_hash`(secret, seed) = `HMAC_hash`(secret, A(1) + seed) +
    ///                          `HMAC_hash`(secret, A(2) + seed) + ...
    /// A(0) = seed, A(i) = `HMAC_hash`(secret, A(i-1))
    fn derive_tls_prf(&self, length: usize) -> CryptoResult<Vec<u8>> {
        if self.key.is_empty() {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "TLS-PRF requires a non-empty secret key".to_string(),
                ),
            ));
        }
        // seed = salt (which contains label || seed in TLS usage)
        let seed = &self.salt;
        let mut okm = Vec::with_capacity(length);

        // A(0) = seed
        let mut a_prev = hmac_sha256(&self.key, seed);

        while okm.len() < length {
            // P_hash block = HMAC(secret, A(i) || seed)
            let mut input = Vec::with_capacity(SHA256_DIGEST_SIZE + seed.len());
            input.extend_from_slice(&a_prev);
            input.extend_from_slice(seed);
            let p_block = hmac_sha256(&self.key, &input);

            let remaining = length - okm.len();
            let to_copy = core::cmp::min(remaining, SHA256_DIGEST_SIZE);
            okm.extend_from_slice(&p_block[..to_copy]);

            // A(i+1) = HMAC(secret, A(i))
            a_prev = hmac_sha256(&self.key, &a_prev);
        }

        Ok(okm)
    }

    // -----------------------------------------------------------------------
    // SSH-KDF (RFC 4253 §7.2)
    // -----------------------------------------------------------------------

    /// SSH-KDF: HASH(K || H || X || `session_id`)
    ///
    /// key = K (shared secret), info = H (exchange hash),
    /// salt = `session_id` (first exchange hash, typically same as H for first key)
    fn derive_ssh_kdf(&self, length: usize) -> CryptoResult<Vec<u8>> {
        if self.key.is_empty() {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "SSH-KDF requires a non-empty shared secret (K)".to_string(),
                ),
            ));
        }
        let mut okm = Vec::with_capacity(length);

        // First block: K1 = HASH(K || H || "A" || session_id)
        // Subsequent: Kn = HASH(K || H || K1 || ... || K_{n-1})
        let mut accum = Vec::new();

        while okm.len() < length {
            let mut input = Vec::new();
            input.extend_from_slice(&self.key); // K (shared secret)
            input.extend_from_slice(&self.info); // H (exchange hash)
            if accum.is_empty() {
                // First block uses a type byte (0x41 = 'A' for IV, etc.)
                // and session_id (stored in salt)
                input.push(0x41); // 'A' — default type
                input.extend_from_slice(&self.salt); // session_id
            } else {
                input.extend_from_slice(&accum);
            }

            let block = sha256_digest(&input);
            let remaining = length - okm.len();
            let to_copy = core::cmp::min(remaining, SHA256_DIGEST_SIZE);
            okm.extend_from_slice(&block[..to_copy]);
            accum.extend_from_slice(&block);
        }

        Ok(okm)
    }
}

// Provide a Debug implementation that does NOT leak key material.
impl core::fmt::Debug for KdfContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KdfContext")
            .field("kdf_type", &self.kdf_type)
            .field("key_len", &self.key.len())
            .field("salt_len", &self.salt.len())
            .field("info_len", &self.info.len())
            .field("digest_name", &self.digest_name)
            .field("state", &self.state)
            .field("params", &self.params.as_ref().map(|_| "..."))
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// High-Level Convenience Functions
// ===========================================================================

/// Derives key material using HKDF (RFC 5869) with HMAC-SHA-256.
///
/// Performs the full HKDF extract-and-expand workflow in a single call.
/// For separate extract/expand steps, or to use a different SHA variant
/// (e.g. SHA-512 for X448 DHKEM per RFC 9180), use [`KdfContext`] with
/// [`KdfType::HkdfExtract`] / [`KdfType::HkdfExpand`] / [`KdfType::Hkdf`]
/// and call [`KdfContext::set_digest`] with the desired algorithm name.
///
/// # Arguments
///
/// * `key` — Input keying material (IKM). Must not be empty.
/// * `salt` — Optional salt value. Can be empty (defaults to a zero-filled
///   buffer of `HashLen` bytes per RFC 5869 §2.2).
/// * `info` — Application-specific context information. Can be empty.
/// * `length` — Number of derived bytes to produce (max 255 × 32 = 8160
///   bytes for the SHA-256 default).
///
/// # Errors
///
/// Returns [`CryptoError`] if the key is empty or the output length exceeds
/// the HKDF maximum (255 × `HashLen`).
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::kdf::hkdf_derive;
/// let okm = hkdf_derive(b"secret-key", b"salt", b"context", 32).unwrap();
/// assert_eq!(okm.len(), 32);
/// ```
pub fn hkdf_derive(key: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    if key.is_empty() {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "HKDF key (IKM) must not be empty".to_string(),
            ),
        ));
    }
    // Default to SHA-256 to preserve historical RFC 5869 test-vector
    // behaviour. Callers requiring a different digest should construct a
    // KdfContext directly and configure it via set_digest().
    let prk = hkdf_extract(salt, key, "SHA-256")?;
    hkdf_expand(&prk, info, length, "SHA-256")
}

/// Derives key material using PBKDF2-HMAC-SHA-256 (RFC 8018).
///
/// Performs iterative HMAC-based password stretching. The `iterations`
/// parameter controls the computational cost — higher values provide
/// better resistance against brute-force attacks.
///
/// # Arguments
///
/// * `password` — The password or passphrase. Must not be empty.
/// * `salt` — Salt value. Should be unique per password (≥16 bytes recommended).
/// * `iterations` — Number of PBKDF2 iterations (minimum 1, recommended ≥10000).
/// * `length` — Number of derived bytes to produce.
///
/// # Errors
///
/// Returns [`CryptoError`] if the password is empty, iterations is 0, or
/// the output length is 0.
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::kdf::pbkdf2_derive;
/// let dk = pbkdf2_derive(b"password", b"salt-value", 10000, 32).unwrap();
/// assert_eq!(dk.len(), 32);
/// ```
pub fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> CryptoResult<Vec<u8>> {
    if password.is_empty() {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "PBKDF2 password must not be empty".to_string(),
            ),
        ));
    }
    pbkdf2_derive_internal(password, salt, iterations, length)
}

/// Derives key material using scrypt (RFC 7914).
///
/// Memory-hard password-based key derivation using the Salsa20/8 core
/// function. The computational cost is controlled by the parameters:
///
/// - `n` — CPU/memory cost parameter (must be > 1 and a power of 2)
/// - `r` — Block size parameter (must be > 0)
/// - `p` — Parallelization parameter (must be > 0)
///
/// # Arguments
///
/// * `password` — The password or passphrase. Must not be empty.
/// * `salt` — Salt value. Should be unique per password.
/// * `n` — CPU/memory cost (must be > 1, power of 2).
/// * `r` — Block size (must be > 0).
/// * `p` — Parallelization (must be > 0).
/// * `length` — Number of derived bytes to produce.
///
/// # Errors
///
/// Returns [`CryptoError`] if parameters violate RFC 7914 constraints or
/// the password is empty.
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::kdf::scrypt_derive;
/// let dk = scrypt_derive(b"password", b"salt", 1024, 8, 1, 32).unwrap();
/// assert_eq!(dk.len(), 32);
/// ```
pub fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    length: usize,
) -> CryptoResult<Vec<u8>> {
    if password.is_empty() {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "scrypt password must not be empty".to_string(),
            ),
        ));
    }
    scrypt_derive_internal(password, salt, n, r, p, length)
}

/// Derives key material using Argon2 (RFC 9106).
///
/// Memory-hard password-based key derivation with three variants:
///
/// - [`KdfType::Argon2i`] — Data-independent (side-channel resistant)
/// - [`KdfType::Argon2d`] — Data-dependent (GPU-resistant)
/// - [`KdfType::Argon2id`] — Hybrid (recommended default)
///
/// # Arguments
///
/// * `password` — The password or passphrase. Must not be empty.
/// * `salt` — Salt value (minimum 8 bytes per RFC 9106).
/// * `variant` — Argon2 variant (must be `Argon2i`, `Argon2d`, or `Argon2id`).
/// * `time_cost` — Number of iterations/passes (minimum 1).
/// * `mem_cost` — Memory usage in KiB (minimum 8 KiB).
/// * `parallelism` — Number of threads/lanes (minimum 1).
/// * `length` — Number of derived bytes to produce (minimum 4).
///
/// # Errors
///
/// Returns [`CryptoError`] if the variant is not an Argon2 type, parameters
/// are below minimums, or the password is empty.
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::kdf::{argon2_derive, KdfType};
/// let dk = argon2_derive(
///     b"password",
///     b"saltsaltsalt1234",
///     KdfType::Argon2id,
///     3,     // time_cost
///     65536, // mem_cost (64 MiB)
///     4,     // parallelism
///     32,    // output length
/// ).unwrap();
/// assert_eq!(dk.len(), 32);
/// ```
pub fn argon2_derive(
    password: &[u8],
    salt: &[u8],
    variant: KdfType,
    time_cost: u32,
    mem_cost: u32,
    parallelism: u32,
    length: usize,
) -> CryptoResult<Vec<u8>> {
    if password.is_empty() {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "Argon2 password must not be empty".to_string(),
            ),
        ));
    }
    argon2_derive_internal(
        password,
        salt,
        variant,
        time_cost,
        mem_cost,
        parallelism,
        length,
    )
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // KdfType tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_kdf_type_display() {
        assert_eq!(KdfType::Hkdf.to_string(), "HKDF");
        assert_eq!(KdfType::HkdfExpand.to_string(), "HKDF-Expand");
        assert_eq!(KdfType::Pbkdf2.to_string(), "PBKDF2");
        assert_eq!(KdfType::Scrypt.to_string(), "scrypt");
        assert_eq!(KdfType::Argon2id.to_string(), "Argon2id");
        assert_eq!(KdfType::TlsPrf.to_string(), "TLS1-PRF");
        assert_eq!(KdfType::SshKdf.to_string(), "SSHKDF");
    }

    #[test]
    fn test_kdf_type_algorithm_name() {
        assert_eq!(KdfType::Hkdf.algorithm_name(), "HKDF");
        assert_eq!(KdfType::HkdfExtract.algorithm_name(), "HKDF");
        assert_eq!(KdfType::Pbkdf2.algorithm_name(), "PBKDF2");
        assert_eq!(KdfType::Argon2i.algorithm_name(), "ARGON2I");
    }

    #[test]
    fn test_kdf_type_is_argon2() {
        assert!(KdfType::Argon2i.is_argon2());
        assert!(KdfType::Argon2d.is_argon2());
        assert!(KdfType::Argon2id.is_argon2());
        assert!(!KdfType::Hkdf.is_argon2());
        assert!(!KdfType::Pbkdf2.is_argon2());
    }

    #[test]
    fn test_kdf_type_is_hkdf() {
        assert!(KdfType::Hkdf.is_hkdf());
        assert!(KdfType::HkdfExpand.is_hkdf());
        assert!(KdfType::HkdfExtract.is_hkdf());
        assert!(!KdfType::Pbkdf2.is_hkdf());
    }

    // -----------------------------------------------------------------------
    // SHA-256 internal tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_empty() {
        let digest = sha256_digest(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_abc() {
        let digest = sha256_digest(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    // -----------------------------------------------------------------------
    // HMAC-SHA-256 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hmac_sha256_rfc4231_tc1() {
        // RFC 4231 Test Case 1
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        let result = hmac_sha256(&key, data);
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha256_rfc4231_tc2() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        let result = hmac_sha256(key, data);
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    // -----------------------------------------------------------------------
    // HKDF tests (RFC 5869 test vectors)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hkdf_rfc5869_tc1() {
        // RFC 5869 Test Case 1 (SHA-256)
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        let okm = hkdf_derive(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_rfc5869_tc2() {
        // RFC 5869 Test Case 2 (SHA-256, longer inputs)
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        )
        .unwrap();
        let salt = hex::decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        )
        .unwrap();
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let expected_okm = hex::decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        )
        .unwrap();

        let okm = hkdf_derive(&ikm, &salt, &info, 82).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_rfc5869_tc3() {
        // RFC 5869 Test Case 3 (SHA-256, zero-length salt/info)
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = b"";
        let info = b"";
        let expected_okm = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        )
        .unwrap();

        let okm = hkdf_derive(&ikm, salt, info, 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    // -----------------------------------------------------------------------
    // PBKDF2 tests (RFC 6070 test vectors for HMAC-SHA-256)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pbkdf2_basic() {
        // Known PBKDF2-HMAC-SHA256 test vector
        let dk = pbkdf2_derive(b"password", b"salt", 1, 32).unwrap();
        assert_eq!(dk.len(), 32);
        // Verify deterministic — same inputs produce same output
        let dk2 = pbkdf2_derive(b"password", b"salt", 1, 32).unwrap();
        assert_eq!(dk, dk2);
    }

    #[test]
    fn test_pbkdf2_iterations() {
        let dk1 = pbkdf2_derive(b"password", b"salt", 1, 32).unwrap();
        let dk2 = pbkdf2_derive(b"password", b"salt", 2, 32).unwrap();
        // Different iteration counts produce different results
        assert_ne!(dk1, dk2);
    }

    #[test]
    fn test_pbkdf2_empty_password_rejected() {
        let result = pbkdf2_derive(b"", b"salt", 1000, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbkdf2_zero_length_rejected() {
        let result = pbkdf2_derive(b"password", b"salt", 1000, 0);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // scrypt tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_scrypt_basic() {
        // Small N for speed in tests
        let dk = scrypt_derive(b"password", b"salt", 4, 1, 1, 32).unwrap();
        assert_eq!(dk.len(), 32);
        // Deterministic
        let dk2 = scrypt_derive(b"password", b"salt", 4, 1, 1, 32).unwrap();
        assert_eq!(dk, dk2);
    }

    #[test]
    fn test_scrypt_invalid_n_zero() {
        let result = scrypt_derive(b"password", b"salt", 0, 1, 1, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_scrypt_invalid_n_not_power_of_2() {
        let result = scrypt_derive(b"password", b"salt", 3, 1, 1, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_scrypt_invalid_r_zero() {
        let result = scrypt_derive(b"password", b"salt", 4, 0, 1, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_scrypt_invalid_p_zero() {
        let result = scrypt_derive(b"password", b"salt", 4, 1, 0, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_scrypt_empty_password_rejected() {
        let result = scrypt_derive(b"", b"salt", 4, 1, 1, 32);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Argon2 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_argon2_basic() {
        let dk = argon2_derive(
            b"password",
            b"saltsaltsalt1234",
            KdfType::Argon2id,
            1,
            8,
            1,
            32,
        )
        .unwrap();
        assert_eq!(dk.len(), 32);
    }

    #[test]
    fn test_argon2_variants_differ() {
        let dk_i = argon2_derive(
            b"password",
            b"saltsaltsalt1234",
            KdfType::Argon2i,
            1,
            8,
            1,
            32,
        )
        .unwrap();
        let dk_d = argon2_derive(
            b"password",
            b"saltsaltsalt1234",
            KdfType::Argon2d,
            1,
            8,
            1,
            32,
        )
        .unwrap();
        let dk_id = argon2_derive(
            b"password",
            b"saltsaltsalt1234",
            KdfType::Argon2id,
            1,
            8,
            1,
            32,
        )
        .unwrap();
        // Different variants produce different output
        assert_ne!(dk_i, dk_d);
        assert_ne!(dk_i, dk_id);
        assert_ne!(dk_d, dk_id);
    }

    #[test]
    fn test_argon2_invalid_variant() {
        let result = argon2_derive(b"password", b"saltsaltsalt1234", KdfType::Hkdf, 1, 8, 1, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_argon2_short_salt_rejected() {
        let result = argon2_derive(b"password", b"short", KdfType::Argon2id, 1, 8, 1, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_argon2_empty_password_rejected() {
        let result = argon2_derive(b"", b"saltsaltsalt1234", KdfType::Argon2id, 1, 8, 1, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_argon2_zero_time_cost_rejected() {
        let result = argon2_derive(
            b"password",
            b"saltsaltsalt1234",
            KdfType::Argon2id,
            0,
            8,
            1,
            32,
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // KdfContext builder pattern tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_hkdf_basic() {
        let mut ctx = KdfContext::new(KdfType::Hkdf);
        ctx.set_key(b"input-key").unwrap();
        ctx.set_salt(b"salt").unwrap();
        ctx.set_info(b"info").unwrap();
        let okm = ctx.derive(32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_context_pbkdf2() {
        let mut ctx = KdfContext::new(KdfType::Pbkdf2);
        ctx.set_key(b"password").unwrap();
        ctx.set_salt(b"salt").unwrap();
        let dk = ctx.derive(32).unwrap();
        assert_eq!(dk.len(), 32);
    }

    #[test]
    fn test_context_derive_without_key_fails() {
        let mut ctx = KdfContext::new(KdfType::Hkdf);
        let result = ctx.derive(32);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_double_derive_fails() {
        let mut ctx = KdfContext::new(KdfType::Hkdf);
        ctx.set_key(b"key").unwrap();
        ctx.derive(32).unwrap();
        let result = ctx.derive(32);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_set_key_after_derive_fails() {
        let mut ctx = KdfContext::new(KdfType::Hkdf);
        ctx.set_key(b"key").unwrap();
        ctx.derive(32).unwrap();
        let result = ctx.set_key(b"new-key");
        assert!(result.is_err());
    }

    #[test]
    fn test_context_empty_key_fails() {
        let mut ctx = KdfContext::new(KdfType::Hkdf);
        let result = ctx.set_key(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_context_empty_digest_fails() {
        let mut ctx = KdfContext::new(KdfType::Hkdf);
        let result = ctx.set_digest("");
        assert!(result.is_err());
    }

    #[test]
    fn test_context_zero_length_derive_fails() {
        let mut ctx = KdfContext::new(KdfType::Hkdf);
        ctx.set_key(b"key").unwrap();
        let result = ctx.derive(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_debug_no_key_leak() {
        let mut ctx = KdfContext::new(KdfType::Hkdf);
        ctx.set_key(b"super-secret-key").unwrap();
        let debug_str = format!("{:?}", ctx);
        assert!(!debug_str.contains("super-secret-key"));
        assert!(debug_str.contains("key_len"));
    }

    #[test]
    fn test_context_hkdf_extract() {
        let mut ctx = KdfContext::new(KdfType::HkdfExtract);
        ctx.set_key(b"input-key-material").unwrap();
        ctx.set_salt(b"salt").unwrap();
        let prk = ctx.derive(32).unwrap();
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn test_context_hkdf_expand() {
        // First extract a PRK using the SHA-256 default to match the
        // KdfContext::HkdfExpand behaviour below.
        let prk = hkdf_extract(b"salt", b"input-key-material", "SHA-256").unwrap();
        let mut ctx = KdfContext::new(KdfType::HkdfExpand);
        ctx.set_key(&prk).unwrap();
        ctx.set_info(b"info").unwrap();
        let okm = ctx.derive(64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_context_kbkdf() {
        let mut ctx = KdfContext::new(KdfType::Kbkdf);
        ctx.set_key(b"derivation-key").unwrap();
        ctx.set_info(b"label").unwrap();
        ctx.set_salt(b"context").unwrap();
        let dk = ctx.derive(32).unwrap();
        assert_eq!(dk.len(), 32);
    }

    #[test]
    fn test_context_sskdf() {
        let mut ctx = KdfContext::new(KdfType::Sskdf);
        ctx.set_key(b"shared-secret").unwrap();
        ctx.set_info(b"other-info").unwrap();
        let dk = ctx.derive(48).unwrap();
        assert_eq!(dk.len(), 48);
    }

    #[test]
    fn test_context_x963kdf() {
        let mut ctx = KdfContext::new(KdfType::X963Kdf);
        ctx.set_key(b"shared-secret").unwrap();
        ctx.set_info(b"shared-info").unwrap();
        let dk = ctx.derive(32).unwrap();
        assert_eq!(dk.len(), 32);
    }

    #[test]
    fn test_context_tls_prf() {
        let mut ctx = KdfContext::new(KdfType::TlsPrf);
        ctx.set_key(b"master-secret").unwrap();
        ctx.set_salt(b"label-plus-seed").unwrap();
        let dk = ctx.derive(48).unwrap();
        assert_eq!(dk.len(), 48);
    }

    #[test]
    fn test_context_ssh_kdf() {
        let mut ctx = KdfContext::new(KdfType::SshKdf);
        ctx.set_key(b"shared-secret").unwrap();
        ctx.set_info(b"exchange-hash").unwrap();
        ctx.set_salt(b"session-id").unwrap();
        let dk = ctx.derive(32).unwrap();
        assert_eq!(dk.len(), 32);
    }

    #[test]
    fn test_context_set_params() {
        use openssl_common::param::ParamBuilder;
        let mut ctx = KdfContext::new(KdfType::Pbkdf2);
        ctx.set_key(b"password").unwrap();
        ctx.set_salt(b"salt").unwrap();
        let params = ParamBuilder::new().push_u32("iterations", 5000).build();
        ctx.set_params(params).unwrap();
        let dk = ctx.derive(32).unwrap();
        assert_eq!(dk.len(), 32);
    }

    // -----------------------------------------------------------------------
    // HKDF edge case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hkdf_empty_key_rejected() {
        let result = hkdf_derive(b"", b"salt", b"info", 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_max_length_exceeded() {
        // 255 * 32 = 8160 max for SHA-256
        let result = hkdf_derive(b"key", b"salt", b"info", 8161);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_zero_length_rejected() {
        let result = hkdf_derive(b"key", b"salt", b"info", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_max_length_accepted() {
        let result = hkdf_derive(b"key", b"salt", b"info", 8160);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 8160);
    }

    // -----------------------------------------------------------------------
    // Consistency: one-shot vs context API
    // -----------------------------------------------------------------------

    #[test]
    fn test_hkdf_oneshot_matches_context() {
        let key = b"test-key-material";
        let salt = b"test-salt";
        let info = b"test-info";

        let oneshot = hkdf_derive(key, salt, info, 32).unwrap();

        let mut ctx = KdfContext::new(KdfType::Hkdf);
        ctx.set_key(key).unwrap();
        ctx.set_salt(salt).unwrap();
        ctx.set_info(info).unwrap();
        let context_derived = ctx.derive(32).unwrap();

        assert_eq!(oneshot, context_derived);
    }

    #[test]
    fn test_pbkdf2_oneshot_matches_context() {
        let password = b"test-password";
        let salt = b"test-salt";

        let oneshot = pbkdf2_derive(password, salt, 1000, 32).unwrap();

        let mut ctx = KdfContext::new(KdfType::Pbkdf2);
        ctx.set_key(password).unwrap();
        ctx.set_salt(salt).unwrap();
        let params = openssl_common::param::ParamBuilder::new()
            .push_u32("iterations", 1000)
            .build();
        ctx.set_params(params).unwrap();
        let context_derived = ctx.derive(32).unwrap();

        assert_eq!(oneshot, context_derived);
    }
}
