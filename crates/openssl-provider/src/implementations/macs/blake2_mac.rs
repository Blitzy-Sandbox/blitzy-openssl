//! `BLAKE2b`-MAC and `BLAKE2s`-MAC provider implementation.
//!
//! Provides keyed BLAKE2 in MAC mode for both the `BLAKE2b` (64-byte key/output)
//! and `BLAKE2s` (32-byte key/output) variants, as specified by RFC 7693.
//!
//! This module replaces the C include-template pattern used in OpenSSL where
//! `blake2_mac_impl.c` was included by `blake2b_mac.c` and `blake2s_mac.c`
//! with preprocessor aliases. In Rust, the [`Blake2Variant`] enum eliminates
//! the preprocessor gymnastics while preserving a single, unified code path.
//!
//! # Algorithms
//!
//! | Algorithm   | Key bytes | Output bytes | Salt bytes | Personal bytes |
//! |-------------|-----------|--------------|------------|----------------|
//! | `BLAKE2b`-MAC | 1–64      | 1–64         | 16         | 16             |
//! | `BLAKE2s`-MAC | 1–32      | 1–32         | 8          | 8              |
//!
//! # Provider descriptors
//!
//! - `BLAKE2BMAC` / `BLAKE2B-MAC` (property `"provider=default"`)
//! - `BLAKE2SMAC` / `BLAKE2S-MAC` (property `"provider=default"`)

use crate::traits::{AlgorithmDescriptor, MacContext, MacProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Parameter name constants (matching OSSL_MAC_PARAM_* from core_names.h)
// ---------------------------------------------------------------------------

/// Parameter name for output / digest length.
const PARAM_SIZE: &str = "size";
/// Parameter name for MAC key.
const PARAM_KEY: &str = "key";
/// Parameter name for salt.
const PARAM_SALT: &str = "salt";
/// Parameter name for personalization / custom value.
const PARAM_CUSTOM: &str = "custom";
/// Parameter name for block size (read-only).
const PARAM_BLOCK_SIZE: &str = "block-size";

// ============================================================================
// Blake2Variant — replaces C preprocessor BLAKE2_* / BLAKE2B_* / BLAKE2S_*
// ============================================================================

/// Selects between the `BLAKE2b` and `BLAKE2s` MAC variants.
///
/// Each variant carries its own constant set (key, output, salt, personal,
/// and block sizes) matching the constants defined in the OpenSSL C headers
/// `blake2_impl.h` / `blake2.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blake2Variant {
    /// `BLAKE2b` — 64-byte key, 64-byte max output, 16-byte salt/personal, 128-byte block.
    Blake2b,
    /// `BLAKE2s` — 32-byte key, 32-byte max output, 8-byte salt/personal, 64-byte block.
    Blake2s,
}

impl Blake2Variant {
    /// Maximum key size in bytes.
    ///
    /// `BLAKE2b`: 64 (`BLAKE2B_KEYBYTES`), `BLAKE2s`: 32 (`BLAKE2S_KEYBYTES`).
    pub fn max_key_bytes(self) -> usize {
        match self {
            Self::Blake2b => 64,
            Self::Blake2s => 32,
        }
    }

    /// Maximum (and default) output size in bytes.
    ///
    /// `BLAKE2b`: 64 (`BLAKE2B_OUTBYTES`), `BLAKE2s`: 32 (`BLAKE2S_OUTBYTES`).
    pub fn max_output_bytes(self) -> usize {
        match self {
            Self::Blake2b => 64,
            Self::Blake2s => 32,
        }
    }

    /// Required salt size in bytes (exact).
    ///
    /// `BLAKE2b`: 16 (`BLAKE2B_SALTBYTES`), `BLAKE2s`: 8 (`BLAKE2S_SALTBYTES`).
    pub fn salt_bytes(self) -> usize {
        match self {
            Self::Blake2b => 16,
            Self::Blake2s => 8,
        }
    }

    /// Required personalization size in bytes (exact).
    ///
    /// `BLAKE2b`: 16 (`BLAKE2B_PERSONALBYTES`), `BLAKE2s`: 8 (`BLAKE2S_PERSONALBYTES`).
    pub fn personal_bytes(self) -> usize {
        match self {
            Self::Blake2b => 16,
            Self::Blake2s => 8,
        }
    }

    /// Default output size — equal to [`max_output_bytes`](Self::max_output_bytes).
    pub fn default_output_bytes(self) -> usize {
        self.max_output_bytes()
    }

    /// Internal block size in bytes.
    ///
    /// `BLAKE2b`: 128, `BLAKE2s`: 64.
    pub fn block_bytes(self) -> usize {
        match self {
            Self::Blake2b => 128,
            Self::Blake2s => 64,
        }
    }
}

// ============================================================================
// Blake2MacParams — typed configuration replacing C OSSL_PARAM bags
// ============================================================================

/// BLAKE2 MAC parameters controlling output length, salt, and personalization.
///
/// Replaces the C `OSSL_PARAM` parameter tables used in
/// `blake2_mac_set_ctx_params` / `blake2_mac_get_ctx_params`.
///
/// All optional fields follow Rule R5 — `Option<T>` instead of sentinel values.
#[derive(Debug, Clone, Default)]
pub struct Blake2MacParams {
    /// Desired output (digest) length in bytes, `1..=max_output_bytes`.
    /// `None` means use [`Blake2Variant::default_output_bytes`].
    pub digest_length: Option<usize>,
    /// Salt value — must be exactly [`Blake2Variant::salt_bytes`] if set.
    pub salt: Option<Vec<u8>>,
    /// Personalization string — must be exactly [`Blake2Variant::personal_bytes`] if set.
    pub personal: Option<Vec<u8>>,
}

// ============================================================================
// BLAKE2 internal constants (RFC 7693)
// ============================================================================

/// `BLAKE2b` initialization vector — fractional part of square roots of first 8 primes.
const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// `BLAKE2s` initialization vector — fractional part of square roots of first 8 primes.
const BLAKE2S_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// Message word permutation schedule, shared by both `BLAKE2b` and `BLAKE2s`.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// ============================================================================
// BLAKE2b internal core
// ============================================================================

/// Internal `BLAKE2b` streaming state (64-bit words, 128-byte blocks).
#[derive(Clone)]
struct Blake2bCore {
    /// Chaining value (8 × u64).
    h: [u64; 8],
    /// Low 64 bits of byte counter.
    t0: u64,
    /// High 64 bits of byte counter.
    t1: u64,
    /// Pending input buffer.
    buf: [u8; 128],
    /// Number of valid bytes in `buf`.
    buf_len: usize,
    /// Configured output length for this instance.
    out_len: usize,
}

impl Blake2bCore {
    /// Initializes the `BLAKE2b` state with the given parameter block.
    ///
    /// `key_len` and `out_len` are encoded into parameter word 0.
    /// `salt` and `personal` are `XOR`-ed into words 4–5 and 6–7 respectively.
    fn new(key_len: usize, out_len: usize, salt: &[u8], personal: &[u8]) -> Self {
        let mut h = BLAKE2B_IV;
        // Parameter word 0: digest_length | key_length | fanout(1) | depth(1)
        h[0] ^= (out_len as u64) | ((key_len as u64) << 8) | (1u64 << 16) | (1u64 << 24);
        // Words 1–3 are zero for sequential mode (no XOR needed)
        // Words 4–5: salt (16 bytes → 2 × u64 LE)
        if !salt.is_empty() {
            h[4] ^= u64::from_le_bytes(salt[..8].try_into().unwrap_or([0u8; 8]));
            h[5] ^= u64::from_le_bytes(salt[8..16].try_into().unwrap_or([0u8; 8]));
        }
        // Words 6–7: personalization (16 bytes → 2 × u64 LE)
        if !personal.is_empty() {
            h[6] ^= u64::from_le_bytes(personal[..8].try_into().unwrap_or([0u8; 8]));
            h[7] ^= u64::from_le_bytes(personal[8..16].try_into().unwrap_or([0u8; 8]));
        }
        Self {
            h,
            t0: 0,
            t1: 0,
            buf: [0u8; 128],
            buf_len: 0,
            out_len,
        }
    }

    /// Compresses one 128-byte block, optionally with the finalization flag.
    fn compress(&mut self, block: &[u8; 128], last: bool) {
        // Parse message words
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let off = i * 8;
            *word = u64::from_le_bytes(block[off..off + 8].try_into().unwrap_or([0u8; 8]));
        }
        // Set up working vector
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&BLAKE2B_IV);
        v[12] ^= self.t0;
        v[13] ^= self.t1;
        if last {
            v[14] ^= u64::MAX;
        }
        // 12 rounds of mixing (`BLAKE2b` uses 12, cycling over 10 SIGMA rows)
        for s in SIGMA.iter().cycle().take(12) {
            // Column step
            blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            // Diagonal step
            blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        // Finalize chaining value
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// `BLAKE2b` G mixing function with rotation constants 32, 24, 16, 63.
/// Parameter names follow RFC 7693 Section 3.1 notation.
#[inline]
#[allow(clippy::many_single_char_names)]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

// ============================================================================
// BLAKE2s internal core
// ============================================================================

/// Internal `BLAKE2s` streaming state (32-bit words, 64-byte blocks).
#[derive(Clone)]
struct Blake2sCore {
    /// Chaining value (8 × u32).
    h: [u32; 8],
    /// Low 32 bits of byte counter.
    t0: u32,
    /// High 32 bits of byte counter.
    t1: u32,
    /// Pending input buffer.
    buf: [u8; 64],
    /// Number of valid bytes in `buf`.
    buf_len: usize,
    /// Configured output length for this instance.
    out_len: usize,
}

impl Blake2sCore {
    /// Initializes the `BLAKE2s` state with the given parameter block.
    fn new(key_len: usize, out_len: usize, salt: &[u8], personal: &[u8]) -> Self {
        let mut h = BLAKE2S_IV;
        // Parameter word 0: digest_length | key_length | fanout(1) | depth(1)
        #[allow(clippy::cast_possible_truncation)]
        // TRUNCATION: out_len and key_len are validated to fit in u8 before reaching here.
        let p0 = (out_len as u32) | ((key_len as u32) << 8) | (1u32 << 16) | (1u32 << 24);
        h[0] ^= p0;
        // Words 4-5: salt (8 bytes -> 2 x u32 LE)
        if !salt.is_empty() {
            h[4] ^= u32::from_le_bytes(salt[..4].try_into().unwrap_or([0u8; 4]));
            h[5] ^= u32::from_le_bytes(salt[4..8].try_into().unwrap_or([0u8; 4]));
        }
        // Words 6-7: personalization (8 bytes -> 2 x u32 LE)
        if !personal.is_empty() {
            h[6] ^= u32::from_le_bytes(personal[..4].try_into().unwrap_or([0u8; 4]));
            h[7] ^= u32::from_le_bytes(personal[4..8].try_into().unwrap_or([0u8; 4]));
        }
        Self {
            h,
            t0: 0,
            t1: 0,
            buf: [0u8; 64],
            buf_len: 0,
            out_len,
        }
    }

    /// Compresses one 64-byte block, optionally with the finalization flag.
    fn compress(&mut self, block: &[u8; 64], last: bool) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let off = i * 4;
            *word = u32::from_le_bytes(block[off..off + 4].try_into().unwrap_or([0u8; 4]));
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&BLAKE2S_IV);
        v[12] ^= self.t0;
        v[13] ^= self.t1;
        if last {
            v[14] ^= u32::MAX;
        }
        // 10 rounds of mixing
        for s in &SIGMA {
            blake2s_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            blake2s_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            blake2s_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            blake2s_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            blake2s_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            blake2s_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            blake2s_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            blake2s_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// `BLAKE2s` G mixing function with rotation constants 16, 12, 8, 7.
/// Parameter names follow RFC 7693 Section 3.1 notation.
#[inline]
#[allow(clippy::many_single_char_names)]
fn blake2s_g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

// ============================================================================
// Shared streaming helpers (update / finalize dispatch)
// ============================================================================

/// Unified BLAKE2 internal state that dispatches to the correct word-size core.
#[derive(Clone)]
enum Blake2Core {
    /// `BLAKE2b` (u64 words, 128-byte blocks).
    B(Blake2bCore),
    /// `BLAKE2s` (u32 words, 64-byte blocks).
    S(Blake2sCore),
}

impl Blake2Core {
    /// Creates and initialises the core for the given variant.
    fn new(
        variant: Blake2Variant,
        key_len: usize,
        out_len: usize,
        salt: &[u8],
        personal: &[u8],
    ) -> Self {
        match variant {
            Blake2Variant::Blake2b => Self::B(Blake2bCore::new(key_len, out_len, salt, personal)),
            Blake2Variant::Blake2s => Self::S(Blake2sCore::new(key_len, out_len, salt, personal)),
        }
    }

    /// Feeds the keyed initial block (key padded to block size) into the state.
    fn ingest_key_block(&mut self, padded_key: &[u8]) {
        match self {
            Self::B(core) => {
                let mut block = [0u8; 128];
                let copy_len = padded_key.len().min(128);
                block[..copy_len].copy_from_slice(&padded_key[..copy_len]);
                core.t0 = 128;
                core.compress(&block, false);
            }
            Self::S(core) => {
                let mut block = [0u8; 64];
                let copy_len = padded_key.len().min(64);
                block[..copy_len].copy_from_slice(&padded_key[..copy_len]);
                core.t0 = 64;
                core.compress(&block, false);
            }
        }
    }

    /// Feeds arbitrary data into the running state.
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::B(core) => blake2b_update(core, data),
            Self::S(core) => blake2s_update(core, data),
        }
    }

    /// Produces the final MAC tag.
    fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::B(core) => blake2b_finalize(core),
            Self::S(core) => blake2s_finalize(core),
        }
    }
}

/// Incrementally feeds data into the `BLAKE2b` core.
fn blake2b_update(core: &mut Blake2bCore, mut data: &[u8]) {
    while !data.is_empty() {
        if core.buf_len == 128 {
            core.t0 = core.t0.wrapping_add(128);
            if core.t0 < 128 {
                core.t1 = core.t1.wrapping_add(1);
            }
            let block: [u8; 128] = core.buf;
            core.compress(&block, false);
            core.buf_len = 0;
        }
        let space = 128 - core.buf_len;
        let take = data.len().min(space);
        core.buf[core.buf_len..core.buf_len + take].copy_from_slice(&data[..take]);
        core.buf_len += take;
        data = &data[take..];
    }
}

/// Finalises the `BLAKE2b` core and returns the hash bytes.
fn blake2b_finalize(core: &mut Blake2bCore) -> Vec<u8> {
    let buf_len_u64 = core.buf_len as u64;
    core.t0 = core.t0.wrapping_add(buf_len_u64);
    if core.t0 < buf_len_u64 {
        core.t1 = core.t1.wrapping_add(1);
    }
    let mut last_block = [0u8; 128];
    last_block[..core.buf_len].copy_from_slice(&core.buf[..core.buf_len]);
    core.compress(&last_block, true);
    let mut out = vec![0u8; 64];
    for (i, word) in core.h.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out.truncate(core.out_len);
    out
}

/// Incrementally feeds data into the `BLAKE2s` core.
fn blake2s_update(core: &mut Blake2sCore, mut data: &[u8]) {
    while !data.is_empty() {
        if core.buf_len == 64 {
            #[allow(clippy::cast_possible_truncation)]
            // TRUNCATION: 64 always fits in u32.
            {
                core.t0 = core.t0.wrapping_add(64);
                if core.t0 < 64 {
                    core.t1 = core.t1.wrapping_add(1);
                }
            }
            let block: [u8; 64] = core.buf;
            core.compress(&block, false);
            core.buf_len = 0;
        }
        let space = 64 - core.buf_len;
        let take = data.len().min(space);
        core.buf[core.buf_len..core.buf_len + take].copy_from_slice(&data[..take]);
        core.buf_len += take;
        data = &data[take..];
    }
}

/// Finalises the `BLAKE2s` core and returns the hash bytes.
fn blake2s_finalize(core: &mut Blake2sCore) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    // TRUNCATION: buf_len is always <= 64, which fits in u32.
    let buf_len_u32 = core.buf_len as u32;
    core.t0 = core.t0.wrapping_add(buf_len_u32);
    if core.t0 < buf_len_u32 {
        core.t1 = core.t1.wrapping_add(1);
    }
    let mut last_block = [0u8; 64];
    last_block[..core.buf_len].copy_from_slice(&core.buf[..core.buf_len]);
    core.compress(&last_block, true);
    let mut out = vec![0u8; 32];
    for (i, word) in core.h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out.truncate(core.out_len);
    out
}

// ============================================================================
// Blake2MacState — computation lifecycle
// ============================================================================

/// Tracks the computation lifecycle of a [`Blake2MacContext`].
#[derive(Clone)]
enum Blake2MacState {
    /// Freshly created — no key or data ingested yet.
    New,
    /// Key applied, BLAKE2 core initialised — ready for `update` calls.
    Initialized(Box<Blake2Core>),
    /// `finalize` has been called — context is exhausted.
    Finalized,
}

// ============================================================================
// Blake2MacContext — streaming MAC context
// ============================================================================

/// Streaming BLAKE2 MAC computation context.
///
/// Replaces the C `blake2_mac_data_st` struct from `blake2_mac_impl.c`.
/// Key material is wrapped in [`Zeroizing`] to ensure automatic secure
/// erasure on drop, replacing the C `OPENSSL_cleanse(macctx->key, ...)`.
pub struct Blake2MacContext {
    /// Selected variant (`BLAKE2b` or `BLAKE2s`).
    variant: Blake2Variant,
    /// MAC key buffer — zeroed on drop via [`Zeroizing`].
    key: Zeroizing<Vec<u8>>,
    /// Whether a key has been set (from `init`, `set_params`, or prior call).
    key_set: bool,
    /// Configured output (digest) length in bytes.
    digest_length: usize,
    /// Optional salt — exactly `variant.salt_bytes()` long if present.
    salt: Option<Vec<u8>>,
    /// Optional personalization — exactly `variant.personal_bytes()` long if present.
    personal: Option<Vec<u8>>,
    /// Current computation lifecycle state.
    state: Blake2MacState,
}

impl Blake2MacContext {
    /// Creates a new context for the given variant with default parameters.
    fn new(variant: Blake2Variant) -> Self {
        Self {
            variant,
            key: Zeroizing::new(Vec::new()),
            key_set: false,
            digest_length: variant.default_output_bytes(),
            salt: None,
            personal: None,
            state: Blake2MacState::New,
        }
    }

    /// Sets the MAC key, validating length constraints.
    ///
    /// The key is zero-padded to `max_key_bytes` as required by the
    /// BLAKE2 keyed-hashing specification (RFC 7693 section 2.5).
    fn set_key(&mut self, key: &[u8]) -> ProviderResult<()> {
        let max = self.variant.max_key_bytes();
        if key.is_empty() || key.len() > max {
            let klen = key.len();
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("BLAKE2 MAC key length {klen} out of range 1..={max}"),
            )));
        }
        // Pad key to max_key_bytes with trailing zeroes.
        let mut padded = vec![0u8; max];
        padded[..key.len()].copy_from_slice(key);
        self.key = Zeroizing::new(padded);
        self.key_set = true;
        Ok(())
    }

    /// Initialises the internal BLAKE2 core with the current key and parameters.
    ///
    /// Equivalent to `BLAKE2_INIT_KEY(ctx, params, key)` in the C implementation.
    fn init_core(&mut self) -> ProviderResult<()> {
        if !self.key_set {
            return Err(ProviderError::Init(
                "BLAKE2 MAC key must be set before initialization".to_string(),
            ));
        }
        let salt_ref = self.salt.as_deref().unwrap_or(&[]);
        let personal_ref = self.personal.as_deref().unwrap_or(&[]);
        // Determine actual key length (before zero-padding).
        let actual_key_len = self
            .key
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |pos| pos + 1);
        let key_len_for_param = actual_key_len.min(self.variant.max_key_bytes());

        let mut core = Blake2Core::new(
            self.variant,
            key_len_for_param,
            self.digest_length,
            salt_ref,
            personal_ref,
        );
        // Ingest the (padded) key as the first block.
        core.ingest_key_block(&self.key);
        self.state = Blake2MacState::Initialized(Box::new(core));
        Ok(())
    }

    /// Applies parameters from a [`ParamSet`] to the context.
    ///
    /// Handles `size`, `key`, `salt`, and `custom` (personalization).
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Digest length / size
        if params.contains(PARAM_SIZE) {
            let size_val = params
                .get_typed::<u64>(PARAM_SIZE)
                .map_err(ProviderError::Common)?;
            let size = usize::try_from(size_val).map_err(|_| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "digest length {size_val} overflows usize"
                )))
            })?;
            let max = self.variant.max_output_bytes();
            if size == 0 || size > max {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!("BLAKE2 digest length {size} out of range 1..={max}"),
                )));
            }
            self.digest_length = size;
        }

        // Key
        if params.contains(PARAM_KEY) {
            let key_bytes = params
                .get_typed::<Vec<u8>>(PARAM_KEY)
                .map_err(ProviderError::Common)?;
            self.set_key(&key_bytes)?;
        }

        // Salt
        if params.contains(PARAM_SALT) {
            let salt_bytes = params
                .get_typed::<Vec<u8>>(PARAM_SALT)
                .map_err(ProviderError::Common)?;
            let expected = self.variant.salt_bytes();
            if salt_bytes.len() != expected {
                return Err(ProviderError::Common(CommonError::InvalidArgument({
                    let got = salt_bytes.len();
                    format!("BLAKE2 salt must be exactly {expected} bytes, got {got}")
                })));
            }
            self.salt = Some(salt_bytes);
        }

        // Personalization / custom
        if params.contains(PARAM_CUSTOM) {
            let personal_bytes = params
                .get_typed::<Vec<u8>>(PARAM_CUSTOM)
                .map_err(ProviderError::Common)?;
            let expected = self.variant.personal_bytes();
            if personal_bytes.len() != expected {
                return Err(ProviderError::Common(CommonError::InvalidArgument({
                    let got = personal_bytes.len();
                    format!("BLAKE2 personalization must be exactly {expected} bytes, got {got}")
                })));
            }
            self.personal = Some(personal_bytes);
        }
        Ok(())
    }
}

// ============================================================================
// MacContext trait implementation
// ============================================================================

impl MacContext for Blake2MacContext {
    /// Initialises or resets the MAC context with the given key and optional
    /// parameters.
    ///
    /// Replaces `blake2_mac_init` from `blake2_mac_impl.c` lines 72-110.
    ///
    /// # Parameters
    ///
    /// - `key`: MAC key bytes. If non-empty, replaces any previously set key.
    ///   If empty, the context reuses the key from a prior `init` or `set_params`.
    /// - `params`: Optional parameter set with `size`, `key`, `salt`, `custom`.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        // Step 1: Apply params (may set digest_length, key, salt, personal).
        if let Some(p) = params {
            self.apply_params(p)?;
        }
        // Step 2: If a key argument was provided, validate and store it.
        if !key.is_empty() {
            self.set_key(key)?;
        }
        // Step 3: Validate that a key is available.
        if !self.key_set {
            return Err(ProviderError::Init(
                "BLAKE2 MAC requires a key -- none set via init() or set_params()".to_string(),
            ));
        }
        // Step 4: Initialise the internal BLAKE2 core with key + params.
        self.init_core()
    }

    /// Feeds data into the running MAC computation.
    ///
    /// Replaces `blake2_mac_update` from `blake2_mac_impl.c` line 112.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        match &mut self.state {
            Blake2MacState::Initialized(core) => {
                core.update(data);
                Ok(())
            }
            Blake2MacState::New => Err(ProviderError::Init(
                "BLAKE2 MAC context not initialized -- call init() first".to_string(),
            )),
            Blake2MacState::Finalized => Err(ProviderError::Init(
                "BLAKE2 MAC context already finalized".to_string(),
            )),
        }
    }

    /// Finalises the MAC computation and returns the authentication tag.
    ///
    /// Replaces `blake2_mac_final` from `blake2_mac_impl.c` lines 114-129.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        match std::mem::replace(&mut self.state, Blake2MacState::Finalized) {
            Blake2MacState::Initialized(mut core) => {
                let tag = core.finalize();
                Ok(tag)
            }
            Blake2MacState::New => Err(ProviderError::Init(
                "BLAKE2 MAC context not initialized -- call init() first".to_string(),
            )),
            Blake2MacState::Finalized => Err(ProviderError::Init(
                "BLAKE2 MAC context already finalized".to_string(),
            )),
        }
    }

    /// Retrieves context parameters.
    ///
    /// Replaces `blake2_get_ctx_params` -- returns `size` (digest length)
    /// and `block-size`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        #[allow(clippy::cast_possible_truncation)]
        // TRUNCATION: digest_length and block_bytes are always small (<= 128).
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, self.digest_length as u64)
            .push_u64(PARAM_BLOCK_SIZE, self.variant.block_bytes() as u64)
            .build();
        Ok(params)
    }

    /// Sets context parameters before or between computations.
    ///
    /// Replaces `blake2_mac_set_ctx_params` from `blake2_mac_impl.c` lines 131-181.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// ============================================================================
// Clone -- deep copy with secure key duplication
// ============================================================================

impl Clone for Blake2MacContext {
    /// Deep-copies the context including key material via [`Zeroizing::clone`].
    ///
    /// Replaces `blake2_mac_dup` from `blake2_mac_impl.c` lines 52-63.
    fn clone(&self) -> Self {
        Self {
            variant: self.variant,
            key: Zeroizing::clone(&self.key),
            key_set: self.key_set,
            digest_length: self.digest_length,
            salt: self.salt.clone(),
            personal: self.personal.clone(),
            state: self.state.clone(),
        }
    }
}

// ============================================================================
// Blake2MacProvider — factory for BLAKE2 MAC contexts
// ============================================================================

/// BLAKE2 MAC provider implementation.
///
/// Implements [`MacProvider`] to produce [`Blake2MacContext`] instances for
/// the selected variant.  Two providers are registered — one for `BLAKE2b`-MAC
/// and one for `BLAKE2s`-MAC — each producing contexts with variant-appropriate
/// defaults.
///
/// Replaces the C `ossl_blake2bmac_functions` / `ossl_blake2smac_functions`
/// dispatch tables.
pub struct Blake2MacProvider {
    /// The variant this provider creates contexts for.
    variant: Blake2Variant,
}

impl Blake2MacProvider {
    /// Creates a new BLAKE2 MAC provider for the given variant.
    pub fn new(variant: Blake2Variant) -> Self {
        Self { variant }
    }

    /// Returns algorithm descriptors for the `BLAKE2b`-MAC variant.
    ///
    /// Registered names: `BLAKE2BMAC`, `BLAKE2B-MAC`.
    pub fn blake2b_descriptors() -> Vec<AlgorithmDescriptor> {
        vec![AlgorithmDescriptor {
            names: vec!["BLAKE2BMAC", "BLAKE2B-MAC"],
            property: "provider=default",
            description: "BLAKE2b keyed MAC (RFC 7693, 64-byte key/output)",
        }]
    }

    /// Returns algorithm descriptors for the `BLAKE2s`-MAC variant.
    ///
    /// Registered names: `BLAKE2SMAC`, `BLAKE2S-MAC`.
    pub fn blake2s_descriptors() -> Vec<AlgorithmDescriptor> {
        vec![AlgorithmDescriptor {
            names: vec!["BLAKE2SMAC", "BLAKE2S-MAC"],
            property: "provider=default",
            description: "BLAKE2s keyed MAC (RFC 7693, 32-byte key/output)",
        }]
    }

    /// Returns all BLAKE2 MAC algorithm descriptors (both variants).
    pub fn all_descriptors() -> Vec<AlgorithmDescriptor> {
        let mut descriptors = Self::blake2b_descriptors();
        descriptors.extend(Self::blake2s_descriptors());
        descriptors
    }
}

// ============================================================================
// MacProvider trait implementation
// ============================================================================

impl MacProvider for Blake2MacProvider {
    /// Returns the canonical algorithm name.
    ///
    /// `"BLAKE2BMAC"` for the `BLAKE2b` variant, `"BLAKE2SMAC"` for `BLAKE2s`.
    fn name(&self) -> &'static str {
        match self.variant {
            Blake2Variant::Blake2b => "BLAKE2BMAC",
            Blake2Variant::Blake2s => "BLAKE2SMAC",
        }
    }

    /// Returns the default MAC output size in bytes.
    fn size(&self) -> usize {
        self.variant.default_output_bytes()
    }

    /// Creates a new [`Blake2MacContext`] for this variant.
    fn new_ctx(&self) -> ProviderResult<Box<dyn MacContext>> {
        Ok(Box::new(Blake2MacContext::new(self.variant)))
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Blake2Variant constant tests
    // -----------------------------------------------------------------

    #[test]
    fn blake2b_variant_constants() {
        let v = Blake2Variant::Blake2b;
        assert_eq!(v.max_key_bytes(), 64);
        assert_eq!(v.max_output_bytes(), 64);
        assert_eq!(v.salt_bytes(), 16);
        assert_eq!(v.personal_bytes(), 16);
        assert_eq!(v.default_output_bytes(), 64);
        assert_eq!(v.block_bytes(), 128);
    }

    #[test]
    fn blake2s_variant_constants() {
        let v = Blake2Variant::Blake2s;
        assert_eq!(v.max_key_bytes(), 32);
        assert_eq!(v.max_output_bytes(), 32);
        assert_eq!(v.salt_bytes(), 8);
        assert_eq!(v.personal_bytes(), 8);
        assert_eq!(v.default_output_bytes(), 32);
        assert_eq!(v.block_bytes(), 64);
    }

    // -----------------------------------------------------------------
    // Provider tests
    // -----------------------------------------------------------------

    #[test]
    fn blake2b_provider_name_and_size() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        assert_eq!(prov.name(), "BLAKE2BMAC");
        assert_eq!(prov.size(), 64);
    }

    #[test]
    fn blake2s_provider_name_and_size() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2s);
        assert_eq!(prov.name(), "BLAKE2SMAC");
        assert_eq!(prov.size(), 32);
    }

    #[test]
    fn blake2b_descriptors_correct() {
        let descs = Blake2MacProvider::blake2b_descriptors();
        assert_eq!(descs.len(), 1);
        assert!(descs[0].names.contains(&"BLAKE2BMAC"));
        assert!(descs[0].names.contains(&"BLAKE2B-MAC"));
        assert_eq!(descs[0].property, "provider=default");
    }

    #[test]
    fn blake2s_descriptors_correct() {
        let descs = Blake2MacProvider::blake2s_descriptors();
        assert_eq!(descs.len(), 1);
        assert!(descs[0].names.contains(&"BLAKE2SMAC"));
        assert!(descs[0].names.contains(&"BLAKE2S-MAC"));
    }

    #[test]
    fn all_descriptors_has_both_variants() {
        let descs = Blake2MacProvider::all_descriptors();
        assert_eq!(descs.len(), 2);
    }

    // -----------------------------------------------------------------
    // Context lifecycle tests
    // -----------------------------------------------------------------

    #[test]
    fn init_without_key_fails() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let result = ctx.init(&[], None);
        assert!(result.is_err());
    }

    #[test]
    fn blake2b_mac_basic_lifecycle() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let key = [0x01u8; 64];
        ctx.init(&key, None).unwrap();
        ctx.update(b"hello world").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 64);
    }

    #[test]
    fn blake2s_mac_basic_lifecycle() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2s);
        let mut ctx = prov.new_ctx().unwrap();
        let key = [0x02u8; 32];
        ctx.init(&key, None).unwrap();
        ctx.update(b"hello world").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn blake2b_key_too_long_rejected() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let key = [0u8; 65];
        let result = ctx.init(&key, None);
        assert!(result.is_err());
    }

    #[test]
    fn blake2s_key_too_long_rejected() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2s);
        let mut ctx = prov.new_ctx().unwrap();
        let key = [0u8; 33];
        let result = ctx.init(&key, None);
        assert!(result.is_err());
    }

    #[test]
    fn update_before_init_fails() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let result = ctx.update(b"data");
        assert!(result.is_err());
    }

    #[test]
    fn finalize_before_init_fails() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let result = ctx.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn double_finalize_fails() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        ctx.init(&[0xAAu8; 32], None).unwrap();
        ctx.finalize().unwrap();
        assert!(ctx.finalize().is_err());
    }

    // -----------------------------------------------------------------
    // Param tests
    // -----------------------------------------------------------------

    #[test]
    fn set_params_digest_length() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let params = ParamBuilder::new().push_u64("size", 32).build();
        ctx.set_params(&params).unwrap();
        let key = [0x01u8; 16];
        ctx.init(&key, None).unwrap();
        ctx.update(b"test data").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn set_params_invalid_digest_length_zero() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let params = ParamBuilder::new().push_u64("size", 0).build();
        assert!(ctx.set_params(&params).is_err());
    }

    #[test]
    fn set_params_invalid_digest_length_too_large() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let params = ParamBuilder::new().push_u64("size", 65).build();
        assert!(ctx.set_params(&params).is_err());
    }

    #[test]
    fn get_params_returns_size_and_block_size() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let ctx = prov.new_ctx().unwrap();
        let p = ctx.get_params().unwrap();
        assert!(p.contains("size"));
        assert!(p.contains("block-size"));
        assert_eq!(p.get("size").and_then(|v| v.as_u64()), Some(64));
        assert_eq!(p.get("block-size").and_then(|v| v.as_u64()), Some(128));
    }

    #[test]
    fn blake2b_salt_wrong_size_rejected() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let mut ctx = prov.new_ctx().unwrap();
        let params = ParamBuilder::new().push_octet("salt", vec![0u8; 8]).build();
        assert!(ctx.set_params(&params).is_err());
    }

    #[test]
    fn blake2s_personal_wrong_size_rejected() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2s);
        let mut ctx = prov.new_ctx().unwrap();
        let params = ParamBuilder::new()
            .push_octet("custom", vec![0u8; 16])
            .build();
        assert!(ctx.set_params(&params).is_err());
    }

    // -----------------------------------------------------------------
    // Determinism and correctness tests
    // -----------------------------------------------------------------

    #[test]
    fn blake2b_mac_deterministic() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let key = b"deterministic test key for blake2";
        let data = b"The quick brown fox jumps over the lazy dog";

        let mut ctx1 = prov.new_ctx().unwrap();
        ctx1.init(key, None).unwrap();
        ctx1.update(data).unwrap();
        let tag1 = ctx1.finalize().unwrap();

        let mut ctx2 = prov.new_ctx().unwrap();
        ctx2.init(key, None).unwrap();
        ctx2.update(data).unwrap();
        let tag2 = ctx2.finalize().unwrap();

        assert_eq!(tag1, tag2, "same key+data must produce identical tags");
        assert_ne!(tag1, vec![0u8; 64], "tag must not be all zeros");
    }

    #[test]
    fn blake2s_mac_deterministic() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2s);
        let key = [0xABu8; 16];
        let data = b"reproducibility check";

        let mut ctx1 = prov.new_ctx().unwrap();
        ctx1.init(&key, None).unwrap();
        ctx1.update(data).unwrap();
        let tag1 = ctx1.finalize().unwrap();

        let mut ctx2 = prov.new_ctx().unwrap();
        ctx2.init(&key, None).unwrap();
        ctx2.update(data).unwrap();
        let tag2 = ctx2.finalize().unwrap();

        assert_eq!(tag1, tag2);
        assert_ne!(tag1, vec![0u8; 32]);
    }

    #[test]
    fn blake2b_different_keys_produce_different_tags() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let data = b"test message";

        let mut ctx1 = prov.new_ctx().unwrap();
        ctx1.init(&[0x01u8; 32], None).unwrap();
        ctx1.update(data).unwrap();
        let tag1 = ctx1.finalize().unwrap();

        let mut ctx2 = prov.new_ctx().unwrap();
        ctx2.init(&[0x02u8; 32], None).unwrap();
        ctx2.update(data).unwrap();
        let tag2 = ctx2.finalize().unwrap();

        assert_ne!(tag1, tag2, "different keys must produce different tags");
    }

    #[test]
    fn blake2b_mac_with_salt_and_personal() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let key = [0x42u8; 64];
        let salt = vec![0x01u8; 16];
        let personal = vec![0x02u8; 16];
        let params = ParamBuilder::new()
            .push_octet("salt", salt)
            .push_octet("custom", personal)
            .build();
        let mut ctx = prov.new_ctx().unwrap();
        ctx.init(&key, Some(&params)).unwrap();
        ctx.update(b"salted personalized data").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 64);
        assert_ne!(tag, vec![0u8; 64]);
    }

    #[test]
    fn blake2b_mac_key_via_params() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let params = ParamBuilder::new()
            .push_octet("key", vec![0xFFu8; 32])
            .build();
        let mut ctx = prov.new_ctx().unwrap();
        ctx.init(&[], Some(&params)).unwrap();
        ctx.update(b"key from params").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 64);
    }

    #[test]
    fn blake2b_mac_incremental_update() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let key = [0x55u8; 16];
        let data = b"split into multiple update calls for testing";

        let mut ctx1 = prov.new_ctx().unwrap();
        ctx1.init(&key, None).unwrap();
        ctx1.update(data).unwrap();
        let tag1 = ctx1.finalize().unwrap();

        let mut ctx2 = prov.new_ctx().unwrap();
        ctx2.init(&key, None).unwrap();
        for chunk in data.chunks(7) {
            ctx2.update(chunk).unwrap();
        }
        let tag2 = ctx2.finalize().unwrap();

        assert_eq!(tag1, tag2, "incremental and single update must match");
    }

    #[test]
    fn blake2b_mac_empty_message() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let key = [0x99u8; 64];
        let mut ctx = prov.new_ctx().unwrap();
        ctx.init(&key, None).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 64);
        assert_ne!(
            tag,
            vec![0u8; 64],
            "MAC of empty message should not be zero"
        );
    }

    #[test]
    fn blake2s_mac_incremental_update() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2s);
        let key = [0x33u8; 16];
        let data = b"incremental blake2s testing with various chunk sizes";

        let mut ctx1 = prov.new_ctx().unwrap();
        ctx1.init(&key, None).unwrap();
        ctx1.update(data).unwrap();
        let tag1 = ctx1.finalize().unwrap();

        let mut ctx2 = prov.new_ctx().unwrap();
        ctx2.init(&key, None).unwrap();
        for chunk in data.chunks(13) {
            ctx2.update(chunk).unwrap();
        }
        let tag2 = ctx2.finalize().unwrap();

        assert_eq!(
            tag1, tag2,
            "incremental and single update must match for blake2s"
        );
    }

    #[test]
    fn blake2s_get_params() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2s);
        let ctx = prov.new_ctx().unwrap();
        let p = ctx.get_params().unwrap();
        assert_eq!(p.get("size").and_then(|v| v.as_u64()), Some(32));
        assert_eq!(p.get("block-size").and_then(|v| v.as_u64()), Some(64));
    }

    #[test]
    fn blake2s_custom_digest_length() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2s);
        let mut ctx = prov.new_ctx().unwrap();
        let params = ParamBuilder::new().push_u64("size", 16).build();
        ctx.init(&[0xCCu8; 16], Some(&params)).unwrap();
        ctx.update(b"short output").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn blake2b_reinit_with_same_key() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let key = [0x77u8; 32];
        let mut ctx = prov.new_ctx().unwrap();

        // First computation
        ctx.init(&key, None).unwrap();
        ctx.update(b"first message").unwrap();
        let tag1 = ctx.finalize().unwrap();

        // Re-init with empty key (reuse previous key)
        ctx.init(&[], None).unwrap();
        ctx.update(b"first message").unwrap();
        let tag2 = ctx.finalize().unwrap();

        assert_eq!(
            tag1, tag2,
            "reinit with same key must produce same tag for same data"
        );
    }

    #[test]
    fn blake2b_large_data() {
        let prov = Blake2MacProvider::new(Blake2Variant::Blake2b);
        let key = [0xBBu8; 64];
        let data = vec![0xCCu8; 4096]; // Multiple blocks
        let mut ctx = prov.new_ctx().unwrap();
        ctx.init(&key, None).unwrap();
        ctx.update(&data).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 64);
        assert_ne!(tag, vec![0u8; 64]);
    }
}
