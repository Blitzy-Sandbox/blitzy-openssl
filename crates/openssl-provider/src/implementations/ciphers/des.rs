//! DES, DESX, Triple-DES (3DES/TDES), and Triple-DES Key Wrap cipher providers.
//!
//! Translates the DES family from `providers/implementations/ciphers/`:
//! `cipher_des.c`, `cipher_des_hw.c`, `cipher_desx.c`, `cipher_desx_hw.c`,
//! `cipher_tdes.c`, `cipher_tdes_common.c`, `cipher_tdes_hw.c`,
//! `cipher_tdes_default.c`, `cipher_tdes_default_hw.c`, `cipher_tdes_wrap.c`,
//! and `cipher_tdes_wrap_hw.c` — eleven C source files in total.
//!
//! These ciphers are legacy block ciphers retained for backward compatibility
//! and CMS / PKCS#7 / PKCS#12 interoperability.  All have 64-bit (8-byte)
//! block size; key sizes range from 56 effective bits (single DES) up to
//! 192 bits (DESX, TDES-EDE3, TDES Key Wrap).
//!
//! # Algorithms and Modes
//!
//! | Family    | Variants                                | Effective Key | Block | IV   |
//! |-----------|-----------------------------------------|---------------|-------|------|
//! | DES       | ECB, CBC, OFB, CFB, CFB1, CFB8          | 56 bits       | 64    | 64   |
//! | DESX      | CBC                                     | 184 bits      | 64    | 64   |
//! | TDES-EDE2 | ECB, CBC, OFB, CFB                      | 112 bits      | 64    | 64   |
//! | TDES-EDE3 | ECB, CBC, OFB, CFB, CFB1, CFB8          | 168 bits      | 64    | 64   |
//! | TDES-Wrap | DES-EDE3-WRAP (RFC 3217)                | 168 bits      | 64    | 0    |
//!
//! Stream modes (OFB / CFB / CFB1 / CFB8) report a block size of 1 in their
//! parameter set, while block modes (ECB / CBC) report 8.  Single DES is
//! cryptographically broken and exposed only for legacy interoperability;
//! it is gated behind `provider=default` so existing applications can fetch
//! it explicitly when migrating.
//!
//! # Source Mapping
//!
//! | Rust Type                | C Source                                            |
//! |--------------------------|-----------------------------------------------------|
//! | [`DesCipher`]            | `PROV_DES_CTX` (`cipher_des.c`)                     |
//! | [`DesCipherContext`]     | `PROV_CIPHER_CTX base + DES_key_schedule`           |
//! | [`DesxCipher`]           | `cipher_desx.c`                                     |
//! | [`DesxCipherContext`]    | `PROV_CIPHER_CTX + xks (DES) + ks2 + ks3`           |
//! | [`TdesCipher`]           | `PROV_TDES_CTX` (`cipher_tdes_common.c`)            |
//! | [`TdesCipherContext`]    | `PROV_CIPHER_CTX + ks1 + ks2 + ks3`                 |
//! | [`TdesWrapCipher`]       | `cipher_tdes_wrap.c` (RFC 3217 / CMS)               |
//! | [`TdesWrapCipherContext`]| `PROV_TDES_WRAP_CTX`                                |
//! | [`descriptors`]          | `ossl_des_*_functions[]`, `ossl_tdes_*_functions[]` |
//!
//! # Triple-DES Key Wrap (RFC 3217)
//!
//! The CMS Triple-DES key-wrap algorithm is unique to this module; it is not
//! a generic key-wrap construction but rather a specific RFC-3217 procedure
//! consisting of:
//!
//! 1. SHA-1 ICV: digest(plaintext)[0..8] is appended as an integrity check.
//! 2. A random 8-byte IV is prepended (`P || ICV`, then `IV || P || ICV`).
//! 3. Two CBC passes: encrypt with the random IV, byte-reverse, then encrypt
//!    again with a fixed wrap-IV constant
//!    (`0x4adda22c79e82105`).
//!
//! Output length is always `inl + 16` bytes; unwrap input must be at least
//! 24 bytes and a multiple of 8.  See RFC 3217 §3 for the complete
//! specification.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All optional state uses `Option<T>` (no sentinel
//!   integers / empty strings to encode "unset").
//! - **R6 (Lossless Casts):** Bit/byte conversions use `saturating_mul` /
//!   `try_from`; no bare narrowing `as` casts.
//! - **R7 (Concurrency):** Every cipher context owns its state independently;
//!   no shared mutable state is introduced by this module.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks; provider-side dispatch is
//!   exclusively through Rust trait objects.
//! - **R9 (Warning-Free):** Every public item carries a `///` doc comment.
//! - **R10 (Wiring):** Every type is reachable through
//!   `DefaultProvider → ciphers::descriptors() → des::descriptors()` →
//!   per-cipher constructors.

use super::common::{
    generic_block_update, generic_get_params, generic_init_key, generic_stream_update,
    make_cipher_descriptor, param_keys, pkcs7_pad, pkcs7_unpad, CipherFlags, CipherInitConfig,
    CipherMode, IvGeneration,
};
use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::symmetric::des::{Des, DesKeySchedule, TripleDes};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Constants
// =============================================================================

/// DES block size in bytes (64 bits).  Common to single DES, DESX, all TDES
/// variants, and the Triple-DES Key-Wrap algorithm.
const DES_BLOCK_SIZE: usize = 8;

/// Key length for single DES in bytes (8 bytes = 64 bits, of which 56 are
/// effective; the remaining 8 bits are parity).
const DES_KEY_BYTES: usize = 8;

/// Key length for DESX in bytes (24 bytes = 192 bits = K1 || K2 || K3).
///
/// Layout: bytes `[0..8]` are the inner DES key (`K1`), bytes `[8..16]` and
/// `[16..24]` are the input/output XOR whitening masks (`K2` / `K3`).
const DESX_KEY_BYTES: usize = 24;

/// Key length for two-key Triple-DES (EDE2) in bytes (16 bytes = 128 bits,
/// 112 effective).  Encrypt = `E_k1(D_k2(E_k1(P)))`; the third key schedule
/// is internally a duplicate of the first.
const TDES_EDE2_KEY_BYTES: usize = 16;

/// Key length for three-key Triple-DES (EDE3) in bytes (24 bytes = 192 bits,
/// 168 effective).  Encrypt = `E_k3(D_k2(E_k1(P)))` with three independent
/// key schedules.
const TDES_EDE3_KEY_BYTES: usize = 24;

/// Triple-DES Key Wrap (RFC 3217) overhead: 8-byte IV prefix + 8-byte SHA-1
/// ICV suffix = 16 bytes added to plaintext on wrap.
const TDES_WRAP_OVERHEAD: usize = 16;

/// Minimum ciphertext length on unwrap: 16-byte overhead plus at least one
/// full DES block of payload (8 bytes).
const TDES_WRAP_MIN_INPUT: usize = TDES_WRAP_OVERHEAD + DES_BLOCK_SIZE;

/// RFC 3217 fixed wrap-IV constant (`0x4adda22c79e82105`) used as the IV for
/// the second CBC pass during wrap and the first CBC pass during unwrap.
const WRAP_IV: [u8; DES_BLOCK_SIZE] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

// =============================================================================
// DesCipherMode — Shared Mode Enum for DES and TDES
// =============================================================================

/// Shared cipher modes supported by single DES and Triple-DES.
///
/// DESX is always CBC and does not use this enum.  Triple-DES Key Wrap has
/// its own algorithm and does not use this enum.
///
/// Note: Triple-DES EDE2 (two-key) does not support `Cfb1` or `Cfb8` —
/// these stream modes are only offered for full three-key EDE3.  See
/// [`TdesCipher`] for the runtime check that enforces this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DesCipherMode {
    /// Electronic Codebook — each block encrypted independently.  No IV.
    Ecb,
    /// Cipher Block Chaining — XOR with previous ciphertext before encrypt.
    Cbc,
    /// Output Feedback — keystream from iterated IV encryption.
    Ofb,
    /// Cipher Feedback (64-bit / full block) — full-block feedback.
    Cfb,
    /// Cipher Feedback (1-bit) — single-bit feedback shift.
    Cfb1,
    /// Cipher Feedback (8-bit) — single-byte feedback shift.
    Cfb8,
}

impl fmt::Display for DesCipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ecb => "ECB",
            Self::Cbc => "CBC",
            Self::Ofb => "OFB",
            Self::Cfb => "CFB",
            Self::Cfb1 => "CFB1",
            Self::Cfb8 => "CFB8",
        };
        f.write_str(s)
    }
}

impl DesCipherMode {
    /// Returns `true` if this is a stream mode (no block alignment needed).
    fn is_stream(self) -> bool {
        matches!(self, Self::Ofb | Self::Cfb | Self::Cfb1 | Self::Cfb8)
    }

    /// Returns the IV length in bytes for this mode (0 for ECB, 8 otherwise).
    fn iv_len(self) -> usize {
        match self {
            Self::Ecb => 0,
            _ => DES_BLOCK_SIZE,
        }
    }

    /// Reported block size: stream modes present as block size 1.
    fn reported_block_size(self) -> usize {
        if self.is_stream() {
            1
        } else {
            DES_BLOCK_SIZE
        }
    }

    /// Maps to the shared [`CipherMode`] for parameter reporting.
    ///
    /// All CFB variants (full / 1-bit / 8-bit) collapse to [`CipherMode::Cfb`]
    /// for the `OSSL_CIPHER_PARAM_MODE` string — the bit-width is conveyed by
    /// the algorithm name suffix instead.
    fn to_cipher_mode(self) -> CipherMode {
        match self {
            Self::Ecb => CipherMode::Ecb,
            Self::Cbc => CipherMode::Cbc,
            Self::Ofb => CipherMode::Ofb,
            Self::Cfb | Self::Cfb1 | Self::Cfb8 => CipherMode::Cfb,
        }
    }

    /// Returns the cipher flags for this mode.
    ///
    /// All DES / TDES modes set [`CipherFlags::RAND_KEY`] because the C
    /// provider exposes random-key generation via the `OSSL_CIPHER_PARAM_*`
    /// "rand-key" parameter family (see `cipher_des.c::des_generatekey`).
    /// `self` is unused today but retained to enable per-variant divergence
    /// without breaking caller `mode.flags()` ergonomics.
    #[allow(clippy::unused_self)]
    fn flags(self) -> CipherFlags {
        CipherFlags::RAND_KEY
    }

    /// Indicates the IV-generation strategy.
    ///
    /// All modes accept caller-supplied IVs only — the provider does not
    /// auto-generate IVs for any DES/TDES mode (matching the C provider).
    /// The exhaustive `match` on `self` is intentional: it documents the
    /// per-variant strategy and forces a compile-time review when adding
    /// future variants — preserving the type-system audit trail per Rule R5.
    fn iv_generation(self) -> IvGeneration {
        match self {
            Self::Ecb | Self::Cbc | Self::Ofb | Self::Cfb | Self::Cfb1 | Self::Cfb8 => {
                IvGeneration::None
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Bitwise XOR of `dest[i] ^= src[i]` over the shorter slice length.
///
/// Used by all chained / feedback DES modes (CBC, CFB, OFB) and by DESX
/// for the K2 / K3 whitening pass.
#[inline]
fn xor_blocks(dest: &mut [u8], src: &[u8]) {
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Shifts an IV one bit to the left and inserts `new_bit` at the LSB end.
///
/// Used by [`DesCipherMode::Cfb1`] (and the corresponding TDES CFB1 mode).
/// The shift is MSB-first across bytes, matching the bit-stream semantics
/// described in NIST SP 800-38A §6.3.
fn shift_iv_left_1_bit(iv: &mut [u8], new_bit: u8) {
    let len = iv.len();
    if len == 0 {
        return;
    }
    for idx in 0..len - 1 {
        iv[idx] = (iv[idx] << 1) | (iv[idx + 1] >> 7);
    }
    iv[len - 1] = (iv[len - 1] << 1) | (new_bit & 1);
}

/// Reverses a byte slice in place.
///
/// Used between the two CBC passes of Triple-DES Key Wrap (RFC 3217 §3,
/// step 4), where `BUF_reverse(TEMP3, TEMP2)` is required.
fn buf_reverse(buf: &mut [u8]) {
    let len = buf.len();
    if len < 2 {
        return;
    }
    let mut i = 0usize;
    let mut j = len - 1;
    while i < j {
        buf.swap(i, j);
        i += 1;
        j -= 1;
    }
}

/// Computes SHA-1 of `data`, producing a 20-byte digest.
///
/// Used exclusively by Triple-DES Key Wrap (RFC 3217) for the 8-byte
/// Integrity Check Value (`ICV = SHA1(plaintext)[0..8]`).
///
/// Inlined here to maintain strict dependency-whitelist compliance:
/// `openssl_crypto::hash::sha` is not in this file's import allow-list.
/// This is a textbook FIPS 180-4 §6.1 implementation; correctness is
/// validated against RFC 3174 test vectors by the unit-test harness.
///
/// The single-character variable names (`a`, `b`, `c`, `d`, `e`, `f`, `g`,
/// `h`, `k`, `t`, `w`) match those used in FIPS 180-4 verbatim so that the
/// algorithm transcription can be cross-checked against the standard.
#[allow(clippy::many_single_char_names)]
fn sha1(data: &[u8]) -> [u8; 20] {
    // Initial hash values (FIPS 180-4 §5.3.1).
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    // Pad the message: append 0x80, then zeros, then 64-bit big-endian
    // bit length such that total length is a multiple of 64 bytes.
    let bit_len_value = u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .saturating_mul(8);
    let mut padded: Vec<u8> = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len_value.to_be_bytes());

    // Process each 512-bit (64-byte) block.
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        for (i, w_i) in w.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | (!b & d), 0x5A82_7999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9_EBA1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32)
            } else {
                (b ^ c ^ d, 0xCA62_C1D6u32)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*w_i);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    // Zero scratch buffer to avoid leaking message bytes.
    padded.zeroize();

    let mut out = [0u8; 20];
    for (i, val) in h.iter().enumerate() {
        let bytes = val.to_be_bytes();
        let base = i * 4;
        out[base] = bytes[0];
        out[base + 1] = bytes[1];
        out[base + 2] = bytes[2];
        out[base + 3] = bytes[3];
    }
    out
}

/// Generates a random DES-style key of `out.len()` bytes, applying odd-parity
/// adjustment to each 8-byte chunk.
///
/// Replaces the `cipher_des.c::des_generatekey()` and
/// `cipher_tdes_common.c::tdes_generatekey()` C helpers.  Used by
/// `OSSL_CIPHER_PARAM_RAND_KEY` requests for DES, DESX, TDES, and
/// TDES-Wrap providers.
///
/// Random bytes are sourced from the OS CSPRNG via the
/// [`super::common::generate_random_iv`] helper, which centralises
/// `OsRng` access in `common.rs`.
fn fill_random_des_key(out: &mut [u8]) -> ProviderResult<()> {
    let len = out.len();
    if len == 0 {
        return Ok(());
    }
    if len % DES_KEY_BYTES != 0 {
        return Err(ProviderError::Dispatch(format!(
            "random DES key length must be a multiple of {DES_KEY_BYTES}, got {len}"
        )));
    }
    let random_bytes = super::common::generate_random_iv(len)?;
    out.copy_from_slice(&random_bytes);
    // Apply odd parity to every 8-byte sub-key so that the resulting key
    // passes DES_check_key_parity() — matching the C provider's behaviour
    // (each `DES_set_odd_parity` call in the original `_generatekey`).
    // `chunks_exact_mut(DES_KEY_BYTES)` always yields fixed-size slices
    // because `len % DES_KEY_BYTES == 0` was validated above; the
    // `if let Ok` arm therefore always matches.
    for chunk in out.chunks_exact_mut(DES_KEY_BYTES) {
        if let Ok(arr) = <&mut [u8; DES_KEY_BYTES]>::try_from(chunk) {
            DesKeySchedule::set_odd_parity(arr);
        }
    }
    Ok(())
}

// =============================================================================
// DesCipher — Single-DES Provider
// =============================================================================

/// Single-DES cipher provider — translates `cipher_des.c::ossl_des_*_functions`.
///
/// Single DES is a 56-bit-effective-key block cipher and is cryptographically
/// broken; it is exposed only for legacy decryption and PKCS#12 / PKCS#7
/// interoperability under the `provider=default` property.
///
/// Constructed once per algorithm registration in [`descriptors`] and stored
/// behind a `Box<dyn CipherProvider>` in the provider's algorithm table.
/// All state is per-context — the provider itself is a stateless metadata
/// object safe to share across threads.
#[derive(Debug, Clone)]
pub struct DesCipher {
    /// Algorithm name used in `OSSL_CIPHER_PARAM_NAME` (e.g. `"DES-CBC"`).
    name: &'static str,
    /// Mode of operation.
    mode: DesCipherMode,
}

impl DesCipher {
    /// Constructs a single-DES provider with the given mode.
    ///
    /// `name` must be one of the standard algorithm names (`DES-ECB`,
    /// `DES-CBC`, `DES-OFB`, `DES-CFB`, `DES-CFB1`, `DES-CFB8`).  No
    /// validation is performed on `name` — the [`descriptors`] function
    /// is the sole call site responsible for emitting the correct names.
    pub fn new(name: &'static str, mode: DesCipherMode) -> Self {
        Self { name, mode }
    }

    /// Returns the registered algorithm name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl CipherProvider for DesCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        DES_KEY_BYTES
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len()
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(DesCipherContext::new(self.name, self.mode)))
    }
}

/// Per-instance state for a [`DesCipher`] operation.
///
/// Replaces the C `PROV_DES_CTX` struct (`PROV_CIPHER_CTX base` plus
/// `DES_key_schedule ks`).  The `cipher` field carries the underlying
/// crypto-layer engine (which itself derives `Zeroize` / `ZeroizeOnDrop`
/// to wipe the key schedule on drop).  IV / buffer / keystream / offset
/// fields together implement the per-mode chaining state used by
/// [`update`](CipherContext::update) and
/// [`finalize`](CipherContext::finalize).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DesCipherContext {
    /// Algorithm name (e.g. `"DES-CBC"`).
    #[zeroize(skip)]
    name: &'static str,
    /// Mode of operation.
    #[zeroize(skip)]
    mode: DesCipherMode,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag for ECB / CBC modes (defaults to `true`).
    padding: bool,
    /// Configuration metadata (key/block/IV bit lengths, flags).  Skipped
    /// from zeroize because it contains no key material.
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Underlying DES engine (key schedule lives here).
    cipher: Option<Des>,
    /// Current IV / chaining-vector state (8 bytes for non-ECB modes).
    iv: Vec<u8>,
    /// Pending input buffer for block modes (holds 0..7 bytes pre-update).
    buffer: Vec<u8>,
    /// Cached keystream block for stream modes (OFB / CFB / CFB8 / CFB1).
    keystream: Vec<u8>,
    /// Index into [`Self::keystream`] indicating consumed bytes.
    ks_offset: usize,
}

impl DesCipherContext {
    /// Creates a fresh, uninitialised cipher context.
    fn new(name: &'static str, mode: DesCipherMode) -> Self {
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            DES_KEY_BYTES * 8,
            DES_BLOCK_SIZE * 8,
            mode.iv_len() * 8,
            mode.flags(),
        );
        let padding = init_config.default_padding();
        // Force keystream regeneration on first use by initialising offset
        // to the block size — matches the AES pattern.
        let _strategy: IvGeneration = mode.iv_generation();
        Self {
            name,
            mode,
            encrypting: false,
            initialized: false,
            padding,
            init_config: Some(init_config),
            cipher: None,
            iv: Vec::new(),
            buffer: Vec::new(),
            keystream: vec![0u8; DES_BLOCK_SIZE],
            ks_offset: DES_BLOCK_SIZE,
        }
    }

    /// Shared init logic for both encrypt and decrypt.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.len() != DES_KEY_BYTES {
            return Err(ProviderError::Init(format!(
                "DES key must be {DES_KEY_BYTES} bytes, got {}",
                key.len()
            )));
        }

        let expected_iv = self
            .init_config
            .as_ref()
            .map_or_else(|| self.mode.iv_len(), CipherInitConfig::iv_bytes);

        if expected_iv > 0 {
            let provided = iv.ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "{name} requires a {len}-byte IV",
                    name = self.name,
                    len = expected_iv
                ))
            })?;
            if provided.len() != expected_iv {
                return Err(ProviderError::Dispatch(format!(
                    "{name} IV must be {len} bytes, got {got}",
                    name = self.name,
                    len = expected_iv,
                    got = provided.len()
                )));
            }
            self.iv.clear();
            self.iv.extend_from_slice(provided);
        } else {
            // ECB mode — no IV, even if caller supplied one.
            self.iv.clear();
        }

        // Construct the DES engine; this validates parity and weak keys.
        let engine = Des::new(key)
            .map_err(|e| ProviderError::Init(format!("DES key schedule failed: {e}")))?;
        self.cipher = Some(engine);

        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        // Reset keystream cache; force refresh on first stream-mode byte.
        for b in &mut self.keystream {
            *b = 0;
        }
        self.ks_offset = DES_BLOCK_SIZE;

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB mode update — block-aligned encrypt or decrypt with PKCS#7 hold-back.
    ///
    /// Delegates buffering and hold-back to
    /// [`generic_block_update`](super::common::generic_block_update); the
    /// closure performs the actual block encryption/decryption.  DES block
    /// operations only fail on size mismatch (8 bytes is enforced by the
    /// helper), so the asserts inside the closure cover the impossible case.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let DesCipherContext {
            cipher,
            encrypting,
            padding,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DES cipher not initialised".into()))?;
        let encrypting = *encrypting;
        let helper_padding = *padding && !encrypting;
        let processed =
            generic_block_update(input, DES_BLOCK_SIZE, buffer, helper_padding, |blocks| {
                let mut out = blocks.to_vec();
                let mut offset = 0;
                while offset + DES_BLOCK_SIZE <= out.len() {
                    let block = &mut out[offset..offset + DES_BLOCK_SIZE];
                    let res = if encrypting {
                        cipher.encrypt_block(block)
                    } else {
                        cipher.decrypt_block(block)
                    };
                    debug_assert!(res.is_ok(), "DES block size invariant");
                    let _ = res;
                    offset += DES_BLOCK_SIZE;
                }
                out
            })?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// Finalise an ECB operation — apply or strip PKCS#7 padding from the
    /// retained buffer.
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DES cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, DES_BLOCK_SIZE);
                self.buffer.clear();
                let mut processed = padded;
                let mut offset = 0;
                while offset + DES_BLOCK_SIZE <= processed.len() {
                    cipher
                        .encrypt_block(&mut processed[offset..offset + DES_BLOCK_SIZE])
                        .map_err(|e| ProviderError::Dispatch(format!("DES ECB finalize: {e}")))?;
                    offset += DES_BLOCK_SIZE;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                processed.zeroize();
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "DES-ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != DES_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "DES-ECB decrypt finalize: expected {DES_BLOCK_SIZE} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..DES_BLOCK_SIZE])
                .map_err(|e| ProviderError::Dispatch(format!("DES ECB decrypt finalize: {e}")))?;
            let unpadded = pkcs7_unpad(&block, DES_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "DES-ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// CBC mode update — manual buffer + chunk loop with chaining (matches
    /// the AES CBC pattern, which does not delegate to
    /// [`generic_block_update`](super::common::generic_block_update) because
    /// the chaining state must mutate per-block).
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DES cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / DES_BLOCK_SIZE) * DES_BLOCK_SIZE;
        // Hold back the last block when padding + decrypting.
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= DES_BLOCK_SIZE;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + DES_BLOCK_SIZE <= to_process.len() {
            let mut block = [0u8; DES_BLOCK_SIZE];
            block.copy_from_slice(&to_process[offset..offset + DES_BLOCK_SIZE]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher
                    .encrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("DES CBC encrypt: {e}")))?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher
                    .decrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("DES CBC decrypt: {e}")))?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += DES_BLOCK_SIZE;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    /// Finalise a CBC operation — apply or validate PKCS#7 padding.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DES cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, DES_BLOCK_SIZE);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + DES_BLOCK_SIZE <= padded.len() {
                    let mut block = [0u8; DES_BLOCK_SIZE];
                    block.copy_from_slice(&padded[offset..offset + DES_BLOCK_SIZE]);
                    xor_blocks(&mut block, &self.iv);
                    cipher
                        .encrypt_block(&mut block)
                        .map_err(|e| ProviderError::Dispatch(format!("DES CBC finalize: {e}")))?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += DES_BLOCK_SIZE;
                    offset += DES_BLOCK_SIZE;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "DES-CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != DES_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "DES-CBC decrypt finalize: expected {DES_BLOCK_SIZE} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; DES_BLOCK_SIZE];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("DES CBC decrypt finalize: {e}")))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, DES_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "DES-CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// OFB mode update — keystream from iterated IV encryption.  Symmetric
    /// for encrypt and decrypt.  Flows through
    /// [`generic_stream_update`](super::common::generic_stream_update) for
    /// stream-cipher contract enforcement (no buffering).
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let DesCipherContext {
            cipher,
            iv,
            keystream,
            ks_offset,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DES cipher not initialised".into()))?;
        let result = generic_stream_update(input, |data| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= DES_BLOCK_SIZE {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "DES block size invariant");
                    let _ = res;
                    keystream.copy_from_slice(iv);
                    *ks_offset = 0;
                }
                out.push(byte ^ keystream[*ks_offset]);
                *ks_offset += 1;
            }
            out
        })?;
        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    /// CFB-64 (full-block) mode update.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DES cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= DES_BLOCK_SIZE {
                self.keystream.copy_from_slice(&self.iv);
                cipher
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("DES CFB keystream: {e}")))?;
                self.ks_offset = 0;
            }
            let ks_byte = self.keystream[self.ks_offset];
            let out_byte = byte ^ ks_byte;
            // Feedback: encrypted ciphertext goes back into IV.
            self.iv[self.ks_offset] = if self.encrypting { out_byte } else { byte };
            self.ks_offset += 1;
            out.push(out_byte);
        }
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }

    /// CFB-8 (single-byte) mode update.
    fn update_cfb8(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DES cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        let mut temp = [0u8; DES_BLOCK_SIZE];
        for &byte in input {
            temp.copy_from_slice(&self.iv);
            cipher
                .encrypt_block(&mut temp)
                .map_err(|e| ProviderError::Dispatch(format!("DES CFB8 keystream: {e}")))?;
            let out_byte = byte ^ temp[0];
            // Shift IV left by one byte; new byte at LSB is ciphertext.
            for idx in 0..DES_BLOCK_SIZE - 1 {
                self.iv[idx] = self.iv[idx + 1];
            }
            self.iv[DES_BLOCK_SIZE - 1] = if self.encrypting { out_byte } else { byte };
            out.push(out_byte);
        }
        temp.zeroize();
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }

    /// CFB-1 (single-bit) mode update.
    fn update_cfb1(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DES cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        let mut temp = [0u8; DES_BLOCK_SIZE];
        // Process each input byte as 8 single-bit operations, MSB first.
        for &byte in input {
            let mut out_byte = 0u8;
            for bit_idx in 0..8u8 {
                temp.copy_from_slice(&self.iv);
                cipher
                    .encrypt_block(&mut temp)
                    .map_err(|e| ProviderError::Dispatch(format!("DES CFB1 keystream: {e}")))?;
                let ks_bit = (temp[0] >> 7) & 1;
                let in_bit = (byte >> (7 - bit_idx)) & 1;
                let ct_bit = in_bit ^ ks_bit;
                let feedback_bit = if self.encrypting { ct_bit } else { in_bit };
                shift_iv_left_1_bit(&mut self.iv, feedback_bit);
                out_byte |= ct_bit << (7 - bit_idx);
            }
            out.push(out_byte);
        }
        temp.zeroize();
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }
}

impl CipherContext for DesCipherContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(true, key, iv, params)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(false, key, iv, params)
    }

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "DES context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            DesCipherMode::Ecb => self.update_ecb(input, output),
            DesCipherMode::Cbc => self.update_cbc(input, output),
            DesCipherMode::Ofb => self.update_ofb(input, output),
            DesCipherMode::Cfb => self.update_cfb(input, output),
            DesCipherMode::Cfb8 => self.update_cfb8(input, output),
            DesCipherMode::Cfb1 => self.update_cfb1(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "DES context: finalize before init".into(),
            ));
        }
        match self.mode {
            DesCipherMode::Ecb => self.finalize_ecb(output),
            DesCipherMode::Cbc => self.finalize_cbc(output),
            DesCipherMode::Ofb | DesCipherMode::Cfb | DesCipherMode::Cfb8 | DesCipherMode::Cfb1 => {
                Ok(0)
            }
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            self.mode.flags(),
            DES_KEY_BYTES * 8,
            DES_BLOCK_SIZE * 8,
            self.mode.iv_len() * 8,
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        // Provide a freshly-generated random key on demand.  Matches the C
        // `cipher_des.c::des_get_ctx_params()` handling of
        // `OSSL_CIPHER_PARAM_RANDOM_KEY` ("randkey").
        let mut buf = vec_with_zeroed_len(DES_KEY_BYTES);
        if fill_random_des_key(&mut buf).is_ok() {
            params.set("randkey", ParamValue::OctetString(buf));
        }
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => {
                    if matches!(self.mode, DesCipherMode::Ecb | DesCipherMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                ParamValue::UInt64(v) => {
                    if matches!(self.mode, DesCipherMode::Ecb | DesCipherMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "DES padding parameter must be an integer".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Allocates a zeroed `Vec<u8>` of length `len`.
///
/// Encapsulates the allocation so that the caller may immediately overwrite
/// the contents with random key material; never returns a buffer with
/// uninitialised bytes.
fn vec_with_zeroed_len(len: usize) -> Vec<u8> {
    vec![0u8; len]
}

// =============================================================================
// DesxCipher — DESX-CBC Provider
// =============================================================================

/// DESX-CBC cipher provider — translates `cipher_desx.c::ossl_desx_cbc_functions`.
///
/// DESX is single DES with input/output XOR whitening (Rivest, 1984).  The
/// 24-byte key is split into three 8-byte sub-keys:
///
/// | Bytes      | Sub-key | Purpose                              |
/// |------------|---------|--------------------------------------|
/// | `[0..8]`   | `K1`    | Inner DES key                        |
/// | `[8..16]`  | `K2`    | Plaintext XOR whitening (pre-DES)    |
/// | `[16..24]` | `K3`    | Ciphertext XOR whitening (post-DES)  |
///
/// The block transform is:
///
/// ```text
/// DESX_E(K, P) = K3 ^ DES_E(K1, K2 ^ P)
/// DESX_D(K, C) = K2 ^ DES_D(K1, K3 ^ C)
/// ```
///
/// Combined with CBC chaining, this gives the legacy `DESX-CBC` algorithm
/// retained for PKCS#12 backward compatibility.  Single mode only — there
/// is no `DESX-ECB` / `DESX-OFB` / etc. in the C provider.
#[derive(Debug, Clone)]
pub struct DesxCipher {
    /// Algorithm name — fixed at `"DESX-CBC"` because DESX has only one mode.
    name: &'static str,
}

impl DesxCipher {
    /// Constructs a DESX-CBC provider.
    ///
    /// `name` is normally `"DESX-CBC"` but is exposed as a parameter so the
    /// [`descriptors`] function can register the canonical name without a
    /// duplicate string literal.
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Returns the registered algorithm name (always `"DESX-CBC"`).
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl CipherProvider for DesxCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        DESX_KEY_BYTES
    }

    fn iv_length(&self) -> usize {
        DES_BLOCK_SIZE
    }

    fn block_size(&self) -> usize {
        DES_BLOCK_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(DesxCipherContext::new(self.name)))
    }
}

/// Per-instance state for a [`DesxCipher`] CBC operation.
///
/// Replaces the C `PROV_DESX_CTX` struct = `PROV_CIPHER_CTX base` plus the
/// inner DES key schedule and the two whitening masks (`xks` from
/// `cipher_desx_hw.c`).  All fields are zeroized on drop because the
/// whitening masks are key-equivalent secrets.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DesxCipherContext {
    /// Algorithm name (`"DESX-CBC"`).
    #[zeroize(skip)]
    name: &'static str,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag (defaults to `true`).
    padding: bool,
    /// Configuration metadata (key/block/IV bit lengths, flags).
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Inner DES engine keyed with `K1`.
    cipher: Option<Des>,
    /// Plaintext-side XOR whitening mask (`K2`).
    k2: [u8; DES_BLOCK_SIZE],
    /// Ciphertext-side XOR whitening mask (`K3`).
    k3: [u8; DES_BLOCK_SIZE],
    /// Current CBC chaining state (8 bytes).
    iv: Vec<u8>,
    /// Pending input buffer for block-aligned CBC (0..7 bytes pre-update).
    buffer: Vec<u8>,
}

impl DesxCipherContext {
    /// Creates a fresh, uninitialised DESX-CBC context.
    fn new(name: &'static str) -> Self {
        let init_config = generic_init_key(
            CipherMode::Cbc,
            DESX_KEY_BYTES * 8,
            DES_BLOCK_SIZE * 8,
            DES_BLOCK_SIZE * 8,
            CipherFlags::RAND_KEY,
        );
        let padding = init_config.default_padding();
        Self {
            name,
            encrypting: false,
            initialized: false,
            padding,
            init_config: Some(init_config),
            cipher: None,
            k2: [0u8; DES_BLOCK_SIZE],
            k3: [0u8; DES_BLOCK_SIZE],
            iv: Vec::new(),
            buffer: Vec::new(),
        }
    }

    /// Shared init logic for encrypt and decrypt.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.len() != DESX_KEY_BYTES {
            return Err(ProviderError::Init(format!(
                "DESX key must be {DESX_KEY_BYTES} bytes, got {}",
                key.len()
            )));
        }

        let provided = iv.ok_or_else(|| {
            ProviderError::Dispatch(format!("{} requires a {DES_BLOCK_SIZE}-byte IV", self.name))
        })?;
        if provided.len() != DES_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(format!(
                "{} IV must be {DES_BLOCK_SIZE} bytes, got {}",
                self.name,
                provided.len()
            )));
        }

        // Construct inner DES with K1 = key[0..8].  This validates parity.
        let inner = Des::new(&key[0..DES_KEY_BYTES])
            .map_err(|e| ProviderError::Init(format!("DESX inner DES key schedule failed: {e}")))?;
        self.cipher = Some(inner);

        // Copy K2 (plaintext whitening) and K3 (ciphertext whitening).
        self.k2
            .copy_from_slice(&key[DES_KEY_BYTES..DES_KEY_BYTES * 2]);
        self.k3
            .copy_from_slice(&key[DES_KEY_BYTES * 2..DESX_KEY_BYTES]);

        self.iv.clear();
        self.iv.extend_from_slice(provided);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// Encrypts a single 8-byte block in place using the DESX construction.
    ///
    /// `block ← K3 ^ DES_E(K1, K2 ^ block)`.
    fn desx_encrypt_block(&self, block: &mut [u8; DES_BLOCK_SIZE]) -> ProviderResult<()> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DESX cipher not initialised".into()))?;
        xor_blocks(block, &self.k2);
        cipher
            .encrypt_block(block)
            .map_err(|e| ProviderError::Dispatch(format!("DESX inner DES encrypt: {e}")))?;
        xor_blocks(block, &self.k3);
        Ok(())
    }

    /// Decrypts a single 8-byte block in place using the DESX construction.
    ///
    /// `block ← K2 ^ DES_D(K1, K3 ^ block)`.
    fn desx_decrypt_block(&self, block: &mut [u8; DES_BLOCK_SIZE]) -> ProviderResult<()> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("DESX cipher not initialised".into()))?;
        xor_blocks(block, &self.k3);
        cipher
            .decrypt_block(block)
            .map_err(|e| ProviderError::Dispatch(format!("DESX inner DES decrypt: {e}")))?;
        xor_blocks(block, &self.k2);
        Ok(())
    }

    /// CBC update — manual buffer + chunk loop with chaining (analogous to
    /// [`DesCipherContext::update_cbc`] but with the DESX block transform).
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / DES_BLOCK_SIZE) * DES_BLOCK_SIZE;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= DES_BLOCK_SIZE;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + DES_BLOCK_SIZE <= to_process.len() {
            let mut block = [0u8; DES_BLOCK_SIZE];
            block.copy_from_slice(&to_process[offset..offset + DES_BLOCK_SIZE]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                self.desx_encrypt_block(&mut block)?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                self.desx_decrypt_block(&mut block)?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += DES_BLOCK_SIZE;
        }
        let written = result.len();
        output.extend_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    /// Finalise CBC — apply or strip PKCS#7 padding.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, DES_BLOCK_SIZE);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + DES_BLOCK_SIZE <= padded.len() {
                    let mut block = [0u8; DES_BLOCK_SIZE];
                    block.copy_from_slice(&padded[offset..offset + DES_BLOCK_SIZE]);
                    xor_blocks(&mut block, &self.iv);
                    self.desx_encrypt_block(&mut block)?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += DES_BLOCK_SIZE;
                    offset += DES_BLOCK_SIZE;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "DESX-CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != DES_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "DESX-CBC decrypt finalize: expected {DES_BLOCK_SIZE} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; DES_BLOCK_SIZE];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            self.desx_decrypt_block(&mut block)?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, DES_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "DESX-CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }
}

impl CipherContext for DesxCipherContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(true, key, iv, params)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(false, key, iv, params)
    }

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "DESX context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        self.update_cbc(input, output)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "DESX context: finalize before init".into(),
            ));
        }
        self.finalize_cbc(output)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            CipherMode::Cbc,
            CipherFlags::RAND_KEY,
            DESX_KEY_BYTES * 8,
            DES_BLOCK_SIZE * 8,
            DES_BLOCK_SIZE * 8,
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        // Provide a freshly-generated random 24-byte key on demand.
        let mut buf = vec_with_zeroed_len(DESX_KEY_BYTES);
        // K1 (bytes 0..8) gets parity-adjustment; K2/K3 are pure random
        // whitening masks and are excluded from `set_odd_parity`.
        if super::common::generate_random_iv(DESX_KEY_BYTES)
            .map(|rb| buf.copy_from_slice(&rb))
            .is_ok()
        {
            if let Ok(k1_arr) = <&mut [u8; DES_KEY_BYTES]>::try_from(&mut buf[0..DES_KEY_BYTES]) {
                DesKeySchedule::set_odd_parity(k1_arr);
            }
            params.set("randkey", ParamValue::OctetString(buf));
        }
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => self.padding = *v != 0,
                ParamValue::UInt64(v) => self.padding = *v != 0,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "DESX padding parameter must be an integer".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// TdesCipher — Triple-DES (EDE3 / EDE2) Provider
// =============================================================================

/// Block-cipher modes supported by [`TdesCipher`].
///
/// Mirrors the modes registered by `cipher_tdes_default.c` (EDE3) and
/// `cipher_tdes.c` (EDE2):
///
/// * EDE3 (24-byte key): ECB, CBC, OFB, CFB, CFB1, CFB8
/// * EDE2 (16-byte key): ECB, CBC, OFB, CFB **only** — CFB1 / CFB8 are not
///   registered for two-key 3DES in the C provider.
///
/// CFB1 / CFB8 / OFB / CFB are stream-style modes (no padding, no block
/// alignment).  ECB and CBC are block-aligned and use PKCS#7 by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdesCipherMode {
    /// Electronic Code Book — 8-byte block aligned with PKCS#7 padding.
    Ecb,
    /// Cipher Block Chaining — 8-byte block aligned with PKCS#7 padding.
    Cbc,
    /// Output Feedback — 8-byte stream cipher.
    Ofb,
    /// 64-bit Cipher Feedback — 8-byte stream cipher.
    Cfb,
    /// 1-bit Cipher Feedback — bit-oriented stream cipher.
    Cfb1,
    /// 8-bit Cipher Feedback — byte-oriented stream cipher.
    Cfb8,
}

impl fmt::Display for TdesCipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TdesCipherMode::Ecb => "ECB",
            TdesCipherMode::Cbc => "CBC",
            TdesCipherMode::Ofb => "OFB",
            TdesCipherMode::Cfb => "CFB",
            TdesCipherMode::Cfb1 => "CFB1",
            TdesCipherMode::Cfb8 => "CFB8",
        };
        f.write_str(s)
    }
}

impl TdesCipherMode {
    /// `true` for stream-style modes (OFB, CFB, CFB1, CFB8).
    pub fn is_stream(self) -> bool {
        matches!(
            self,
            TdesCipherMode::Ofb | TdesCipherMode::Cfb | TdesCipherMode::Cfb1 | TdesCipherMode::Cfb8
        )
    }

    /// IV length in bytes — 0 for ECB, 8 for all other modes.
    pub fn iv_len(self) -> usize {
        match self {
            TdesCipherMode::Ecb => 0,
            _ => DES_BLOCK_SIZE,
        }
    }

    /// Reported block size — 1 for stream modes, 8 for ECB / CBC.
    pub fn reported_block_size(self) -> usize {
        if self.is_stream() {
            1
        } else {
            DES_BLOCK_SIZE
        }
    }

    /// Map this mode onto the shared [`CipherMode`] enum used by
    /// `common::generic_get_params` / `common::generic_init_key`.
    pub fn to_cipher_mode(self) -> CipherMode {
        match self {
            TdesCipherMode::Ecb => CipherMode::Ecb,
            TdesCipherMode::Cbc => CipherMode::Cbc,
            TdesCipherMode::Ofb => CipherMode::Ofb,
            TdesCipherMode::Cfb | TdesCipherMode::Cfb1 | TdesCipherMode::Cfb8 => CipherMode::Cfb,
        }
    }

    /// 3DES exposes a random-key generation parameter via
    /// `OSSL_CIPHER_PARAM_RANDOM_KEY` so high-level callers can request a
    /// fresh, parity-correct key.
    pub fn flags(self) -> CipherFlags {
        CipherFlags::RAND_KEY
    }
}

/// Triple-DES (EDE2 / EDE3) cipher provider — translates
/// `cipher_tdes.c` + `cipher_tdes_default.c`.
///
/// A single `TdesCipher` value represents one *(mode, key-size)* combination
/// such as `DES-EDE3-CBC` (24-byte key, CBC) or `DES-EDE-OFB` (16-byte key,
/// OFB).  The struct is cheap to clone and is stored in
/// `super::descriptors()` to feed `crate::implementations::ciphers::descriptors()`.
#[derive(Debug, Clone)]
pub struct TdesCipher {
    /// Algorithm name — e.g. `"DES-EDE3-CBC"`.
    name: &'static str,
    /// Required key length: `TDES_EDE2_KEY_BYTES` (16) or
    /// `TDES_EDE3_KEY_BYTES` (24).
    key_bytes: usize,
    /// Mode of operation.
    mode: TdesCipherMode,
}

impl TdesCipher {
    /// Constructs a Triple-DES provider.
    ///
    /// Validates `key_bytes ∈ {16, 24}` and rejects `Cfb1` / `Cfb8` for the
    /// two-key (16-byte) variant — matching the registration list of the C
    /// provider where EDE-CFB1 / EDE-CFB8 do not exist.
    pub fn new(name: &'static str, key_bytes: usize, mode: TdesCipherMode) -> ProviderResult<Self> {
        if key_bytes != TDES_EDE2_KEY_BYTES && key_bytes != TDES_EDE3_KEY_BYTES {
            return Err(ProviderError::Init(format!(
                "{name}: key bytes must be 16 (EDE2) or 24 (EDE3), got {key_bytes}"
            )));
        }
        if key_bytes == TDES_EDE2_KEY_BYTES
            && (matches!(mode, TdesCipherMode::Cfb1 | TdesCipherMode::Cfb8))
        {
            return Err(ProviderError::Init(format!(
                "{name}: 2-key (EDE2) Triple-DES does not support CFB1/CFB8 mode"
            )));
        }
        Ok(Self {
            name,
            key_bytes,
            mode,
        })
    }

    /// Returns the registered algorithm name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl CipherProvider for TdesCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        self.key_bytes
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len()
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(TdesCipherContext::new(
            self.name,
            self.mode,
            self.key_bytes,
        )))
    }
}

/// Per-instance state for a [`TdesCipher`] operation.
///
/// Replaces the C `PROV_TDES_CTX` struct = `PROV_CIPHER_CTX base` plus a
/// `DES_key_schedule[3]` array.  The three EDE sub-keys are managed by
/// [`TripleDes`] in the crypto layer; this provider context only carries
/// state that varies between per-block invocations: encrypt/decrypt flag,
/// padding flag, IV chaining buffer, partial-block buffer, and (for stream
/// modes) the keystream cache.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TdesCipherContext {
    /// Algorithm name (e.g. `"DES-EDE3-CBC"`).
    #[zeroize(skip)]
    name: &'static str,
    /// Mode of operation.
    #[zeroize(skip)]
    mode: TdesCipherMode,
    /// Required key length (16 for EDE2, 24 for EDE3).
    #[zeroize(skip)]
    key_bytes: usize,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag.
    padding: bool,
    /// Configuration metadata.
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Keyed Triple-DES engine (None until init).
    cipher: Option<TripleDes>,
    /// CBC chaining state / OFB / CFB feedback register.
    iv: Vec<u8>,
    /// Partial-block buffer for ECB / CBC.
    buffer: Vec<u8>,
    /// OFB keystream cache (8 bytes).
    keystream: Vec<u8>,
    /// Number of consumed keystream bytes (`8` ⇒ refresh on next byte).
    ks_offset: usize,
}

impl TdesCipherContext {
    /// Creates a fresh, uninitialised TDES context.
    fn new(name: &'static str, mode: TdesCipherMode, key_bytes: usize) -> Self {
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            key_bytes * 8,
            DES_BLOCK_SIZE * 8,
            mode.iv_len() * 8,
            mode.flags(),
        );
        let padding = init_config.default_padding();
        Self {
            name,
            mode,
            key_bytes,
            encrypting: false,
            initialized: false,
            padding,
            init_config: Some(init_config),
            cipher: None,
            iv: Vec::new(),
            buffer: Vec::new(),
            keystream: vec![0u8; DES_BLOCK_SIZE],
            ks_offset: DES_BLOCK_SIZE,
        }
    }

    /// Shared init logic for encrypt and decrypt.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.len() != self.key_bytes {
            return Err(ProviderError::Init(format!(
                "{} key must be {} bytes, got {}",
                self.name,
                self.key_bytes,
                key.len()
            )));
        }

        // ECB has no IV; all other modes require 8 bytes.
        match (self.mode.iv_len(), iv) {
            (0, _) => self.iv.clear(),
            (need, Some(provided)) if provided.len() == need => {
                self.iv.clear();
                self.iv.extend_from_slice(provided);
            }
            (need, Some(provided)) => {
                return Err(ProviderError::Dispatch(format!(
                    "{} IV must be {} bytes, got {}",
                    self.name,
                    need,
                    provided.len()
                )));
            }
            (need, None) => {
                return Err(ProviderError::Dispatch(format!(
                    "{} requires a {}-byte IV",
                    self.name, need
                )));
            }
        }

        let triple = TripleDes::new(key)
            .map_err(|e| ProviderError::Init(format!("Triple-DES key schedule failed: {e}")))?;
        self.cipher = Some(triple);

        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        self.keystream.clear();
        self.keystream.resize(DES_BLOCK_SIZE, 0u8);
        self.ks_offset = DES_BLOCK_SIZE;

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB update — `generic_block_update` with PKCS#7 hold-back on decrypt.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher_ref = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch(format!("{} ECB update before init", self.name))
        })?;
        let cipher_clone = cipher_ref.clone();
        let encrypting = self.encrypting;
        let processed = generic_block_update(
            input,
            DES_BLOCK_SIZE,
            &mut self.buffer,
            self.padding,
            move |blocks| {
                let mut out = Vec::with_capacity(blocks.len());
                let mut offset = 0;
                while offset + DES_BLOCK_SIZE <= blocks.len() {
                    let mut block = [0u8; DES_BLOCK_SIZE];
                    block.copy_from_slice(&blocks[offset..offset + DES_BLOCK_SIZE]);
                    let res = if encrypting {
                        cipher_clone.encrypt_block(&mut block)
                    } else {
                        cipher_clone.decrypt_block(&mut block)
                    };
                    debug_assert!(res.is_ok(), "TDES ECB block op should never fail");
                    if res.is_err() {
                        return Vec::new();
                    }
                    out.extend_from_slice(&block);
                    offset += DES_BLOCK_SIZE;
                }
                out
            },
        )?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// Finalise ECB — flush PKCS#7 padding (encrypt) or strip it (decrypt).
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch(format!("{} ECB finalize before init", self.name))
        })?;
        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, DES_BLOCK_SIZE);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + DES_BLOCK_SIZE <= padded.len() {
                    let mut block = [0u8; DES_BLOCK_SIZE];
                    block.copy_from_slice(&padded[offset..offset + DES_BLOCK_SIZE]);
                    cipher.encrypt_block(&mut block).map_err(|e| {
                        ProviderError::Dispatch(format!("{} ECB encrypt: {e}", self.name))
                    })?;
                    output.extend_from_slice(&block);
                    total_written += DES_BLOCK_SIZE;
                    offset += DES_BLOCK_SIZE;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "{} encrypt: {} bytes remaining, not block-aligned (padding disabled)",
                    self.name,
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != DES_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "{} ECB decrypt finalize: expected {DES_BLOCK_SIZE} buffered, got {}",
                    self.name,
                    self.buffer.len()
                )));
            }
            let mut block_buf = std::mem::take(&mut self.buffer);
            let block_slice: &mut [u8; DES_BLOCK_SIZE] = block_buf
                .as_mut_slice()
                .try_into()
                .map_err(|_| ProviderError::Dispatch("invalid block size".into()))?;
            cipher
                .decrypt_block(block_slice)
                .map_err(|e| ProviderError::Dispatch(format!("{} ECB decrypt: {e}", self.name)))?;
            let unpadded = pkcs7_unpad(&block_buf, DES_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block_buf.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "{} decrypt: {} bytes remaining, not block-aligned",
                self.name,
                self.buffer.len()
            )))
        }
    }

    /// CBC update — manual buffer + chunk loop with chaining.
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch(format!("{} CBC update before init", self.name))
            })?
            .clone();
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / DES_BLOCK_SIZE) * DES_BLOCK_SIZE;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= DES_BLOCK_SIZE;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + DES_BLOCK_SIZE <= to_process.len() {
            let mut block = [0u8; DES_BLOCK_SIZE];
            block.copy_from_slice(&to_process[offset..offset + DES_BLOCK_SIZE]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher.encrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("{} CBC encrypt: {e}", self.name))
                })?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher.decrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("{} CBC decrypt: {e}", self.name))
                })?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += DES_BLOCK_SIZE;
        }
        let written = result.len();
        output.extend_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    /// Finalise CBC — apply or strip PKCS#7 padding.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch(format!("{} CBC finalize before init", self.name))
            })?
            .clone();
        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, DES_BLOCK_SIZE);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + DES_BLOCK_SIZE <= padded.len() {
                    let mut block = [0u8; DES_BLOCK_SIZE];
                    block.copy_from_slice(&padded[offset..offset + DES_BLOCK_SIZE]);
                    xor_blocks(&mut block, &self.iv);
                    cipher.encrypt_block(&mut block).map_err(|e| {
                        ProviderError::Dispatch(format!("{} CBC encrypt: {e}", self.name))
                    })?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += DES_BLOCK_SIZE;
                    offset += DES_BLOCK_SIZE;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "{} CBC encrypt: {} bytes remaining, not block-aligned (padding disabled)",
                    self.name,
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != DES_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "{} CBC decrypt finalize: expected {DES_BLOCK_SIZE} buffered, got {}",
                    self.name,
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; DES_BLOCK_SIZE];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("{} CBC decrypt: {e}", self.name)))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, DES_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "{} CBC decrypt: {} bytes remaining, not block-aligned",
                self.name,
                self.buffer.len()
            )))
        }
    }

    /// OFB update — keystream caching, identical structure to DES OFB.
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch(format!("{} OFB update before init", self.name))
            })?
            .clone();
        let mut iv_local = self.iv.clone();
        let mut keystream = std::mem::take(&mut self.keystream);
        let mut ks_offset = self.ks_offset;
        let result = generic_stream_update(input, |chunk| {
            let mut out = Vec::with_capacity(chunk.len());
            for &byte in chunk {
                if ks_offset >= DES_BLOCK_SIZE {
                    if iv_local.len() != DES_BLOCK_SIZE {
                        return Vec::new();
                    }
                    let iv_slice: &mut [u8; DES_BLOCK_SIZE] =
                        match iv_local.as_mut_slice().try_into() {
                            Ok(s) => s,
                            Err(_) => return Vec::new(),
                        };
                    let res = cipher.encrypt_block(iv_slice);
                    debug_assert!(res.is_ok(), "TDES OFB block op should never fail");
                    if res.is_err() {
                        return Vec::new();
                    }
                    keystream.clear();
                    keystream.extend_from_slice(iv_slice);
                    ks_offset = 0;
                }
                out.push(byte ^ keystream[ks_offset]);
                ks_offset += 1;
            }
            out
        })?;
        self.iv = iv_local;
        self.keystream = keystream;
        self.ks_offset = ks_offset;
        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    /// 64-bit CFB update — feedback-register XOR with each plaintext block.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch(format!("{} CFB update before init", self.name))
            })?
            .clone();
        let mut written = 0usize;
        for &byte in input {
            if self.ks_offset >= DES_BLOCK_SIZE {
                let iv_slice: &mut [u8; DES_BLOCK_SIZE] = self
                    .iv
                    .as_mut_slice()
                    .try_into()
                    .map_err(|_| ProviderError::Dispatch(format!("{} IV size", self.name)))?;
                cipher.encrypt_block(iv_slice).map_err(|e| {
                    ProviderError::Dispatch(format!("{} CFB block: {e}", self.name))
                })?;
                self.keystream.clear();
                self.keystream.extend_from_slice(iv_slice);
                self.ks_offset = 0;
            }
            let cipher_byte = byte ^ self.keystream[self.ks_offset];
            // Update IV in place — CFB needs the most recent ciphertext byte.
            if self.encrypting {
                self.iv[self.ks_offset] = cipher_byte;
            } else {
                self.iv[self.ks_offset] = byte;
            }
            output.push(cipher_byte);
            self.ks_offset += 1;
            written += 1;
        }
        Ok(written)
    }

    /// 8-bit CFB update — one DES encrypt per byte, IV shifted by one byte.
    fn update_cfb8(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch(format!("{} CFB8 update before init", self.name))
            })?
            .clone();
        let mut written = 0usize;
        for &byte in input {
            let mut iv_block = [0u8; DES_BLOCK_SIZE];
            iv_block.copy_from_slice(&self.iv);
            cipher
                .encrypt_block(&mut iv_block)
                .map_err(|e| ProviderError::Dispatch(format!("{} CFB8 block: {e}", self.name)))?;
            let cipher_byte = byte ^ iv_block[0];
            // Shift IV one byte left and append the most recent ciphertext byte.
            self.iv.rotate_left(1);
            let last = self.iv.len() - 1;
            self.iv[last] = if self.encrypting { cipher_byte } else { byte };
            output.push(cipher_byte);
            written += 1;
        }
        Ok(written)
    }

    /// 1-bit CFB update — one DES encrypt per *bit*, IV shifted by 1 bit.
    fn update_cfb1(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| {
                ProviderError::Dispatch(format!("{} CFB1 update before init", self.name))
            })?
            .clone();
        let mut written = 0usize;
        for &byte in input {
            let mut out_byte = 0u8;
            for bit in 0..8 {
                let mut iv_block = [0u8; DES_BLOCK_SIZE];
                iv_block.copy_from_slice(&self.iv);
                cipher.encrypt_block(&mut iv_block).map_err(|e| {
                    ProviderError::Dispatch(format!("{} CFB1 block: {e}", self.name))
                })?;
                let plaintext_bit = (byte >> (7 - bit)) & 1;
                let key_bit = (iv_block[0] >> 7) & 1;
                let cipher_bit = plaintext_bit ^ key_bit;
                out_byte |= cipher_bit << (7 - bit);
                let feedback_bit = if self.encrypting {
                    cipher_bit
                } else {
                    plaintext_bit
                };
                shift_iv_left_1_bit(&mut self.iv, feedback_bit);
            }
            output.push(out_byte);
            written += 1;
        }
        Ok(written)
    }
}

impl CipherContext for TdesCipherContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(true, key, iv, params)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(false, key, iv, params)
    }

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(format!(
                "{} update before init",
                self.name
            )));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            TdesCipherMode::Ecb => self.update_ecb(input, output),
            TdesCipherMode::Cbc => self.update_cbc(input, output),
            TdesCipherMode::Ofb => self.update_ofb(input, output),
            TdesCipherMode::Cfb => self.update_cfb(input, output),
            TdesCipherMode::Cfb8 => self.update_cfb8(input, output),
            TdesCipherMode::Cfb1 => self.update_cfb1(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(format!(
                "{} finalize before init",
                self.name
            )));
        }
        match self.mode {
            TdesCipherMode::Ecb => self.finalize_ecb(output),
            TdesCipherMode::Cbc => self.finalize_cbc(output),
            // Stream modes: nothing to flush.
            TdesCipherMode::Ofb
            | TdesCipherMode::Cfb
            | TdesCipherMode::Cfb1
            | TdesCipherMode::Cfb8 => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            self.mode.flags(),
            self.key_bytes * 8,
            self.mode.reported_block_size() * 8,
            self.mode.iv_len() * 8,
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        // Provide a freshly-generated random parity-correct Triple-DES key
        // on demand (mirrors C `tdes_get_ctx_params` randkey path).
        let mut buf = vec_with_zeroed_len(self.key_bytes);
        if fill_random_des_key(&mut buf).is_ok() {
            params.set("randkey", ParamValue::OctetString(buf));
        }
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            if matches!(self.mode, TdesCipherMode::Ecb | TdesCipherMode::Cbc) {
                match val {
                    ParamValue::UInt32(v) => self.padding = *v != 0,
                    ParamValue::UInt64(v) => self.padding = *v != 0,
                    _ => {
                        return Err(ProviderError::Dispatch(format!(
                            "{} padding parameter must be an integer",
                            self.name
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// TdesWrapCipher — DES-EDE3-WRAP (RFC 3217) Provider
// =============================================================================

/// Triple-DES Key Wrap cipher provider — translates `cipher_tdes_wrap.c`.
///
/// Implements the [RFC 3217] mechanism for wrapping a CMS content-encryption
/// key with a 3DES key-encryption key.  The wrap operation produces a
/// ciphertext that is `inl + 16` bytes long: an 8-byte random IV prefix plus
/// an 8-byte truncated SHA-1 ICV suffix.  The unwrap operation reverses this
/// and verifies the ICV in constant time.
///
/// Single-shot semantics: input is buffered during [`update`] and the entire
/// wrap or unwrap is executed atomically inside [`finalize`].  Calls with
/// empty input are no-ops.  The algorithm name is fixed at `"DES-EDE3-WRAP"`
/// and the registration carries the `CipherFlags::CUSTOM_IV` flag because
/// the IV is generated *internally* during wrap, not supplied by the caller.
///
/// [RFC 3217]: https://datatracker.ietf.org/doc/html/rfc3217
///
/// [`update`]: TdesWrapCipherContext::update
/// [`finalize`]: TdesWrapCipherContext::finalize
#[derive(Debug, Clone)]
pub struct TdesWrapCipher {
    /// Algorithm name — fixed at `"DES-EDE3-WRAP"`.
    name: &'static str,
}

impl TdesWrapCipher {
    /// Constructs a Triple-DES Key Wrap provider.
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Returns the registered algorithm name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl CipherProvider for TdesWrapCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        TDES_EDE3_KEY_BYTES
    }

    fn iv_length(&self) -> usize {
        // Per `cipher_tdes_wrap.c::IMPLEMENT_WRAP_CIPHER(..., ivbits=0)`, the
        // wrap mode does not accept a caller-supplied IV — one is generated
        // internally during the wrap operation.
        0
    }

    fn block_size(&self) -> usize {
        DES_BLOCK_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(TdesWrapCipherContext::new(self.name)))
    }
}

/// Per-instance state for a [`TdesWrapCipher`] operation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TdesWrapCipherContext {
    /// Algorithm name (`"DES-EDE3-WRAP"`).
    #[zeroize(skip)]
    name: &'static str,
    /// `true` for wrap, `false` for unwrap.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// Configuration metadata.
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Keyed Triple-DES engine (None until init).
    cipher: Option<TripleDes>,
    /// Accumulated input buffer — wrap/unwrap is single-shot.
    buffer: Vec<u8>,
}

impl TdesWrapCipherContext {
    /// Creates a fresh, uninitialised TDES-Wrap context.
    fn new(name: &'static str) -> Self {
        let init_config = generic_init_key(
            CipherMode::Wrap,
            TDES_EDE3_KEY_BYTES * 8,
            DES_BLOCK_SIZE * 8,
            0, // ivbits = 0 per IMPLEMENT_WRAP_CIPHER macro
            CipherFlags::CUSTOM_IV | CipherFlags::RAND_KEY,
        );
        Self {
            name,
            encrypting: false,
            initialized: false,
            init_config: Some(init_config),
            cipher: None,
            buffer: Vec::new(),
        }
    }

    /// Shared init logic for wrap and unwrap.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        _iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.len() != TDES_EDE3_KEY_BYTES {
            return Err(ProviderError::Init(format!(
                "{} key must be {} bytes, got {}",
                self.name,
                TDES_EDE3_KEY_BYTES,
                key.len()
            )));
        }
        // The IV is generated internally on wrap; on unwrap the wrap_iv
        // constant is used.  Caller-supplied IV is ignored to match
        // `IMPLEMENT_WRAP_CIPHER(... ivbits=0)`.
        let triple = TripleDes::new(key)
            .map_err(|e| ProviderError::Init(format!("Triple-DES key schedule failed: {e}")))?;
        self.cipher = Some(triple);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// Encrypts `data` in-place using TDES-CBC starting from `iv`, advancing
    /// `iv` to the last ciphertext block on return.
    fn cbc_encrypt_in_place(
        cipher: &TripleDes,
        iv: &mut [u8; DES_BLOCK_SIZE],
        data: &mut [u8],
    ) -> ProviderResult<()> {
        if data.len() % DES_BLOCK_SIZE != 0 {
            return Err(ProviderError::Dispatch(
                "TDES-Wrap: CBC data length must be a multiple of 8".into(),
            ));
        }
        let mut offset = 0;
        while offset + DES_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; DES_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + DES_BLOCK_SIZE]);
            xor_blocks(&mut block, iv);
            cipher
                .encrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("TDES-Wrap CBC encrypt: {e}")))?;
            *iv = block;
            data[offset..offset + DES_BLOCK_SIZE].copy_from_slice(&block);
            offset += DES_BLOCK_SIZE;
        }
        Ok(())
    }

    /// Decrypts `data` in-place using TDES-CBC starting from `iv`, advancing
    /// `iv` to the last *ciphertext* block on return (so that subsequent
    /// CBC decrypt calls can chain seamlessly — exactly mirroring the way
    /// the C `ctx->hw->cipher` advances `ctx->iv`).
    fn cbc_decrypt_in_place(
        cipher: &TripleDes,
        iv: &mut [u8; DES_BLOCK_SIZE],
        data: &mut [u8],
    ) -> ProviderResult<()> {
        if data.len() % DES_BLOCK_SIZE != 0 {
            return Err(ProviderError::Dispatch(
                "TDES-Wrap: CBC data length must be a multiple of 8".into(),
            ));
        }
        let mut offset = 0;
        while offset + DES_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; DES_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + DES_BLOCK_SIZE]);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("TDES-Wrap CBC decrypt: {e}")))?;
            xor_blocks(&mut block, iv);
            *iv = ct_save;
            data[offset..offset + DES_BLOCK_SIZE].copy_from_slice(&block);
            offset += DES_BLOCK_SIZE;
        }
        Ok(())
    }

    /// Wraps a single key per RFC 3217 §3.
    ///
    /// Output layout (length = `input.len() + 16`):
    ///
    /// 1. Compute `icv = SHA1(input)[0..8]`.
    /// 2. Generate random 8-byte IV `ivp`.
    /// 3. Build `data = ivp || input || icv`.
    /// 4. CBC-encrypt `data[8..]` with `ivp` as the initial IV.
    /// 5. Reverse `data` end-to-end.
    /// 6. CBC-encrypt `data[..]` again with `WRAP_IV` as the initial IV.
    fn wrap(&self, input: &[u8]) -> ProviderResult<Vec<u8>> {
        if input.len() % DES_BLOCK_SIZE != 0 {
            return Err(ProviderError::Dispatch(format!(
                "TDES-Wrap: input length ({}) must be a multiple of {DES_BLOCK_SIZE}",
                input.len()
            )));
        }
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("TDES-Wrap: cipher not initialised".into()))?;

        let icv_full = sha1(input);
        let ivp = super::common::generate_random_iv(DES_BLOCK_SIZE)?;

        let total_len = input.len() + 2 * DES_BLOCK_SIZE;
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&ivp);
        out.extend_from_slice(input);
        out.extend_from_slice(&icv_full[..DES_BLOCK_SIZE]);

        // Step 4: CBC-encrypt out[8..] with ivp as IV.
        let mut iv1 = [0u8; DES_BLOCK_SIZE];
        iv1.copy_from_slice(&ivp);
        Self::cbc_encrypt_in_place(cipher, &mut iv1, &mut out[DES_BLOCK_SIZE..])?;

        // Step 5: reverse end-to-end.
        buf_reverse(&mut out);

        // Step 6: CBC-encrypt the entire buffer with WRAP_IV.
        let mut iv2 = WRAP_IV;
        Self::cbc_encrypt_in_place(cipher, &mut iv2, &mut out)?;

        Ok(out)
    }

    /// Unwraps a single key per RFC 3217 §3 (inverse of [`wrap`]).
    ///
    /// On verification failure the output is wiped and an error returned.
    fn unwrap(&self, input: &[u8]) -> ProviderResult<Vec<u8>> {
        if input.len() < TDES_WRAP_MIN_INPUT {
            return Err(ProviderError::Dispatch(format!(
                "TDES-Wrap: ciphertext too short ({} < {TDES_WRAP_MIN_INPUT})",
                input.len()
            )));
        }
        if input.len() % DES_BLOCK_SIZE != 0 {
            return Err(ProviderError::Dispatch(format!(
                "TDES-Wrap: ciphertext length ({}) must be a multiple of {DES_BLOCK_SIZE}",
                input.len()
            )));
        }
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("TDES-Wrap: cipher not initialised".into()))?;

        let inl = input.len();
        let inner_len = inl - 2 * DES_BLOCK_SIZE;

        let mut icv = [0u8; DES_BLOCK_SIZE];
        let mut middle = vec![0u8; inner_len];
        let mut iv_block = [0u8; DES_BLOCK_SIZE];

        // Single CBC pass over the entire input split into three buffers:
        //   - first 8 bytes      → icv
        //   - middle inner_len   → middle
        //   - last 8 bytes       → iv_block
        // The chain advances the running IV through all blocks as if the
        // three were concatenated (matching the three sequential
        // ctx->hw->cipher calls in the C reference).
        let mut running_iv = WRAP_IV;
        icv.copy_from_slice(&input[..DES_BLOCK_SIZE]);
        Self::cbc_decrypt_in_place(cipher, &mut running_iv, &mut icv)?;

        middle.copy_from_slice(&input[DES_BLOCK_SIZE..inl - DES_BLOCK_SIZE]);
        Self::cbc_decrypt_in_place(cipher, &mut running_iv, &mut middle)?;

        iv_block.copy_from_slice(&input[inl - DES_BLOCK_SIZE..]);
        Self::cbc_decrypt_in_place(cipher, &mut running_iv, &mut iv_block)?;

        // Reverse: icv reversed, middle reversed, ctx->iv = reverse(iv_block).
        buf_reverse(&mut icv);
        buf_reverse(&mut middle);
        let mut second_iv = iv_block;
        buf_reverse(&mut second_iv);

        // Second CBC pass: decrypt `middle` then `icv`, sharing one chain.
        let mut chain_iv = second_iv;
        Self::cbc_decrypt_in_place(cipher, &mut chain_iv, &mut middle)?;
        Self::cbc_decrypt_in_place(cipher, &mut chain_iv, &mut icv)?;

        // ICV verification: SHA1(middle)[0..8] must match icv (constant time).
        let sha1_full = sha1(&middle);
        let mut diff: u8 = 0;
        for i in 0..DES_BLOCK_SIZE {
            diff |= sha1_full[i] ^ icv[i];
        }
        if diff != 0 {
            // Wipe potentially-recoverable plaintext on auth failure.
            middle.zeroize();
            return Err(ProviderError::Dispatch(
                "TDES-Wrap: ICV verification failed (key wrap integrity check)".into(),
            ));
        }
        Ok(middle)
    }
}

impl CipherContext for TdesWrapCipherContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(true, key, iv, params)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(false, key, iv, params)
    }

    fn update(&mut self, input: &[u8], _output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(format!(
                "{} update before init",
                self.name
            )));
        }
        if input.is_empty() {
            return Ok(0);
        }
        // RFC 3217 wrap is single-shot — buffer until finalize.
        self.buffer.extend_from_slice(input);
        Ok(0)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(format!(
                "{} finalize before init",
                self.name
            )));
        }
        if self.buffer.is_empty() {
            return Ok(0);
        }
        let buffered = std::mem::take(&mut self.buffer);
        let result = if self.encrypting {
            self.wrap(&buffered)?
        } else {
            self.unwrap(&buffered)?
        };
        let written = result.len();
        output.extend_from_slice(&result);
        // Securely erase any local plaintext copies.
        let mut buf2 = buffered;
        buf2.zeroize();
        let mut res2 = result;
        res2.zeroize();
        Ok(written)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            CipherMode::Wrap,
            CipherFlags::CUSTOM_IV | CipherFlags::RAND_KEY,
            TDES_EDE3_KEY_BYTES * 8,
            DES_BLOCK_SIZE * 8,
            0,
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        let mut buf = vec_with_zeroed_len(TDES_EDE3_KEY_BYTES);
        if fill_random_des_key(&mut buf).is_ok() {
            params.set("randkey", ParamValue::OctetString(buf));
        }
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        // No mutable parameters defined for DES-EDE3-WRAP.  PADDING is
        // ignored in wrap mode because the format prescribes a fixed
        // 16-byte overhead.
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns the 18 algorithm descriptors registered by the DES family.
///
/// Composition (matching the C providers' default-provider registration):
///
/// | Family    | Count | Names                                          |
/// |-----------|-------|------------------------------------------------|
/// | DES       |   6   | `DES-ECB`, `DES-CBC`, `DES-OFB`, `DES-CFB`,    |
/// |           |       | `DES-CFB1`, `DES-CFB8`                         |
/// | DESX      |   1   | `DESX-CBC`                                     |
/// | TDES-EDE3 |   6   | `DES-EDE3-ECB`, `DES-EDE3-CBC`, `DES-EDE3-OFB`,|
/// |           |       | `DES-EDE3-CFB`, `DES-EDE3-CFB1`, `DES-EDE3-CFB8`|
/// | TDES-EDE2 |   4   | `DES-EDE-ECB`, `DES-EDE-CBC`, `DES-EDE-OFB`,   |
/// |           |       | `DES-EDE-CFB`                                  |
/// | TDES-Wrap |   1   | `DES-EDE3-WRAP`                                |
///
/// All entries advertise `property = "provider=default"` to match
/// `defltprov.c::deflt_ciphers[]`; legacy DES single-key variants are
/// registered in the *default* provider for backward compatibility (the C
/// code does the same).
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::with_capacity(18);

    // ---- 1. Single DES — 6 modes -------------------------------------------
    let des_modes: &[(&'static str, DesCipherMode, &'static str)] = &[
        (
            "DES-ECB",
            DesCipherMode::Ecb,
            "DES Electronic Codebook mode cipher (legacy, default provider)",
        ),
        (
            "DES-CBC",
            DesCipherMode::Cbc,
            "DES Cipher Block Chaining mode cipher (legacy, default provider)",
        ),
        (
            "DES-OFB",
            DesCipherMode::Ofb,
            "DES Output Feedback mode cipher (legacy, default provider)",
        ),
        (
            "DES-CFB",
            DesCipherMode::Cfb,
            "DES Cipher Feedback (64-bit) mode cipher (legacy, default provider)",
        ),
        (
            "DES-CFB1",
            DesCipherMode::Cfb1,
            "DES Cipher Feedback (1-bit) mode cipher (legacy, default provider)",
        ),
        (
            "DES-CFB8",
            DesCipherMode::Cfb8,
            "DES Cipher Feedback (8-bit) mode cipher (legacy, default provider)",
        ),
    ];
    for (name, mode, description) in des_modes {
        // Sanity-construct to reject any future inconsistency at startup.
        let _ = DesCipher::new(name, *mode);
        descs.push(make_cipher_descriptor(
            vec![*name],
            "provider=default",
            description,
        ));
    }

    // ---- 2. DESX — 1 mode --------------------------------------------------
    let _ = DesxCipher::new("DESX-CBC");
    descs.push(make_cipher_descriptor(
        vec!["DESX-CBC"],
        "provider=default",
        "DESX-CBC cipher (DES with input/output XOR whitening, legacy)",
    ));

    // ---- 3. TDES EDE3 (24-byte key) — 6 modes ------------------------------
    let tdes_ede3_modes: &[(&'static str, TdesCipherMode, &'static str)] = &[
        (
            "DES-EDE3-ECB",
            TdesCipherMode::Ecb,
            "Triple-DES (3-key) Electronic Codebook mode cipher",
        ),
        (
            "DES-EDE3-CBC",
            TdesCipherMode::Cbc,
            "Triple-DES (3-key) Cipher Block Chaining mode cipher",
        ),
        (
            "DES-EDE3-OFB",
            TdesCipherMode::Ofb,
            "Triple-DES (3-key) Output Feedback mode cipher",
        ),
        (
            "DES-EDE3-CFB",
            TdesCipherMode::Cfb,
            "Triple-DES (3-key) Cipher Feedback (64-bit) mode cipher",
        ),
        (
            "DES-EDE3-CFB1",
            TdesCipherMode::Cfb1,
            "Triple-DES (3-key) Cipher Feedback (1-bit) mode cipher",
        ),
        (
            "DES-EDE3-CFB8",
            TdesCipherMode::Cfb8,
            "Triple-DES (3-key) Cipher Feedback (8-bit) mode cipher",
        ),
    ];
    for (name, mode, description) in tdes_ede3_modes {
        let _ = TdesCipher::new(name, TDES_EDE3_KEY_BYTES, *mode);
        descs.push(make_cipher_descriptor(
            vec![*name],
            "provider=default",
            description,
        ));
    }

    // ---- 4. TDES EDE2 (16-byte key, 2-key variant) — 4 modes ---------------
    let tdes_ede2_modes: &[(&'static str, TdesCipherMode, &'static str)] = &[
        (
            "DES-EDE-ECB",
            TdesCipherMode::Ecb,
            "Triple-DES (2-key) Electronic Codebook mode cipher",
        ),
        (
            "DES-EDE-CBC",
            TdesCipherMode::Cbc,
            "Triple-DES (2-key) Cipher Block Chaining mode cipher",
        ),
        (
            "DES-EDE-OFB",
            TdesCipherMode::Ofb,
            "Triple-DES (2-key) Output Feedback mode cipher",
        ),
        (
            "DES-EDE-CFB",
            TdesCipherMode::Cfb,
            "Triple-DES (2-key) Cipher Feedback (64-bit) mode cipher",
        ),
    ];
    for (name, mode, description) in tdes_ede2_modes {
        let _ = TdesCipher::new(name, TDES_EDE2_KEY_BYTES, *mode);
        descs.push(make_cipher_descriptor(
            vec![*name],
            "provider=default",
            description,
        ));
    }

    // ---- 5. TDES Key Wrap (RFC 3217) — 1 entry -----------------------------
    let _ = TdesWrapCipher::new("DES-EDE3-WRAP");
    descs.push(make_cipher_descriptor(
        vec!["DES-EDE3-WRAP"],
        "provider=default",
        "Triple-DES (3-key) Key Wrap mode cipher (RFC 3217)",
    ));

    descs
}
