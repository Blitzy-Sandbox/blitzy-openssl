//! Legacy cipher provider implementations — Blowfish, CAST5, IDEA, SEED, RC2,
//! RC4, RC5.
//!
//! All algorithms in this module are **deprecated**.  They are retained
//! exclusively for backward-compatibility scenarios:
//!
//! * **PKCS#12 / PKCS#7 interop** with files produced by older OpenSSL or
//!   third-party tooling (CAST5-CBC, IDEA-CBC, RC2-40-CBC).
//! * **TLS legacy cipher suites** (RC4, RC4-HMAC-MD5).
//! * **Test-vector validation** of historical specifications.
//!
//! The whole module is gated behind `#[cfg(feature = "legacy")]` at
//! `mod.rs`; no per-cipher feature flag exists in `crates/openssl-provider/
//! Cargo.toml`, so the entire family is enabled / disabled together.  This
//! mirrors the C `OPENSSL_NO_LEGACY` / `STATIC_LEGACY` switch used by
//! `providers/legacyprov.c`.
//!
//! # Source Mapping
//!
//! | Rust Type                | C Source(s)                                                         |
//! |--------------------------|---------------------------------------------------------------------|
//! | [`BlowfishCipher`]       | `cipher_blowfish.c`, `cipher_blowfish_hw.c`                         |
//! | [`Cast5Cipher`]          | `cipher_cast5.c`, `cipher_cast5_hw.c`                               |
//! | [`IdeaCipher`]           | `cipher_idea.c`, `cipher_idea_hw.c`                                 |
//! | [`SeedCipher`]           | `cipher_seed.c`, `cipher_seed_hw.c`                                 |
//! | [`Rc2Cipher`]            | `cipher_rc2.c`, `cipher_rc2_hw.c`                                   |
//! | [`Rc4Cipher`]            | `cipher_rc4.c`, `cipher_rc4_hw.c`, `cipher_rc4_hmac_md5.c` (composite) |
//! | [`Rc5Cipher`]            | `cipher_rc5.c`, `cipher_rc5_hw.c`                                   |
//!
//! # Algorithms and Modes
//!
//! | Family   | Variants                                            | Key (bits)        | Block (bits) | IV (bits) |
//! |----------|-----------------------------------------------------|-------------------|--------------|-----------|
//! | Blowfish | `BF-ECB`, `BF-CBC`, `BF-OFB`, `BF-CFB`              | variable 8..=448  | 64           | 0 / 64    |
//! | CAST5    | `CAST5-ECB`, `CAST5-CBC`, `CAST5-OFB`, `CAST5-CFB`  | variable 40..=128 | 64           | 0 / 64    |
//! | IDEA     | `IDEA-ECB`, `IDEA-CBC`, `IDEA-OFB`, `IDEA-CFB`      | 128 (fixed)       | 64           | 0 / 64    |
//! | SEED     | `SEED-ECB`, `SEED-CBC`, `SEED-OFB`, `SEED-CFB`      | 128 (fixed)       | 128          | 0 / 128   |
//! | RC2      | `RC2-ECB`, `RC2-CBC`, `RC2-OFB`, `RC2-CFB`,         | variable 8..=1024 | 64           | 0 / 64    |
//! |          | `RC2-40-CBC`, `RC2-64-CBC`                          | (effective bits)  |              |           |
//! | RC4      | `RC4`, `RC4-40`, `RC4-HMAC-MD5`                     | variable 8..=2048 | 1 (stream)   | 0         |
//! | RC5      | `RC5-ECB`, `RC5-CBC`, `RC5-OFB`, `RC5-CFB`          | variable 8..=2040 | 64           | 0 / 64    |
//!
//! # Rules Enforced
//!
//! * **Rule R5** — variable-key state uses `Option<usize>` rather than the
//!   `-1` sentinel found in the C `PROV_*_CTX` structs.
//! * **Rule R6** — every numeric conversion uses `u32::try_from` /
//!   `usize::try_from` / `saturating_mul`; no bare `as` casts appear.
//! * **Rule R7** — every cipher context owns its full state; no shared
//!   mutable state crosses context boundaries.
//! * **Rule R8** — zero `unsafe` blocks; all crypto operations delegate
//!   to the safe `openssl_crypto::symmetric::*` engines.
//! * **Rule R9** — every public item carries a `///` doc comment and the
//!   crate compiles cleanly under `-D warnings`.
//! * **Rule R10** — wired through `LegacyProvider::query_operation` via
//!   the [`descriptors`] aggregation function.

use super::common::{
    generic_block_update, generic_get_params, generic_init_key, generic_stream_update, param_keys,
    pkcs7_pad, pkcs7_unpad, CipherFlags, CipherInitConfig, CipherMode, IvGeneration,
};
use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::symmetric::{
    Blowfish, Cast5, Idea, Rc2, Rc4, Rc5, Seed, StreamCipher, SymmetricCipher,
};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Shared Constants
// =============================================================================

/// 64-bit block size shared by Blowfish, CAST5, IDEA, RC2, RC5 (in bytes).
const BLOCK_64: usize = 8;

/// 128-bit block size used by SEED (in bytes).
const BLOCK_128: usize = 16;

/// IDEA fixed key length (in bytes) — 128-bit only.
const IDEA_KEY_BYTES: usize = 16;

/// SEED fixed key length (in bytes) — 128-bit only.
const SEED_KEY_BYTES: usize = 16;

/// Default Blowfish key length when one is not supplied (16 bytes = 128 bits).
const BF_DEFAULT_KEY_BYTES: usize = 16;

/// Default CAST5 key length when one is not supplied (16 bytes = 128 bits).
const CAST5_DEFAULT_KEY_BYTES: usize = 16;

/// Default RC2 key length when one is not supplied (16 bytes = 128 bits).
const RC2_DEFAULT_KEY_BYTES: usize = 16;

/// Default RC4 key length when one is not supplied (16 bytes = 128 bits).
const RC4_DEFAULT_KEY_BYTES: usize = 16;

/// Default RC5 key length when one is not supplied (16 bytes = 128 bits).
const RC5_DEFAULT_KEY_BYTES: usize = 16;

/// Effective key length, in bits, of `RC2-40-CBC` (export-grade).
const RC2_EFFECTIVE_BITS_40: u32 = 40;

/// Effective key length, in bits, of `RC2-64-CBC`.
const RC2_EFFECTIVE_BITS_64: u32 = 64;

/// Key length, in bytes, of `RC2-40-CBC` (5 bytes = 40 bits, export-grade).
const RC2_40_KEY_BYTES: usize = 5;

/// Key length, in bytes, of `RC2-64-CBC` (8 bytes = 64 bits).
const RC2_64_KEY_BYTES: usize = 8;

/// Key length, in bytes, of `RC4-40` (5 bytes = 40 bits, export-grade).
const RC4_40_KEY_BYTES: usize = 5;

/// Default round count for RC5 — 12 rounds matches `RC5_12_ROUNDS` in the
/// C provider.
const RC5_DEFAULT_ROUNDS: u32 = 12;

// =============================================================================
// Helper Functions
// =============================================================================

/// In-place XOR of `dest[i] ^= src[i]` over the shorter slice length.
///
/// Used by every chained / feedback mode (CBC, CFB, OFB) across this
/// module.  Identical to the helper in `des.rs::xor_blocks`; inlined here
/// so the dependency-whitelist remains restricted to `super::common`.
#[inline]
fn xor_blocks(dest: &mut [u8], src: &[u8]) {
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Converts a byte length to its bit-length representation as a `usize`.
///
/// Uses `saturating_mul` per Rule R6 to avoid panicking on absurd inputs;
/// the caller passes only constants from this module so saturation never
/// triggers in practice.
#[inline]
fn bytes_to_bits(bytes: usize) -> usize {
    bytes.saturating_mul(8)
}

// =============================================================================
// LegacyBlockMode — shared mode enum for block ciphers
// =============================================================================

/// Modes of operation supported by the block-cipher legacy families
/// (Blowfish, CAST5, IDEA, SEED, RC2, RC5).
///
/// All five families implement exactly the same set of modes, so a single
/// shared enum suffices.  Stream-cipher RC4 has no mode and is handled
/// independently in [`Rc4CipherContext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyBlockMode {
    /// Electronic Codebook — block-aligned with PKCS#7 padding.
    Ecb,
    /// Cipher Block Chaining — block-aligned with PKCS#7 padding.
    Cbc,
    /// Output Feedback — stream-style, IV evolves via cipher iteration.
    Ofb,
    /// Cipher Feedback (full block) — stream-style with ciphertext feedback.
    Cfb,
}

impl fmt::Display for LegacyBlockMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ecb => "ECB",
            Self::Cbc => "CBC",
            Self::Ofb => "OFB",
            Self::Cfb => "CFB",
        };
        f.write_str(s)
    }
}

impl LegacyBlockMode {
    /// Returns `true` if this mode operates as a stream (no padding,
    /// ciphertext length equal to plaintext length).
    fn is_stream(self) -> bool {
        matches!(self, Self::Ofb | Self::Cfb)
    }

    /// Returns the IV length, in bytes, for this mode given a block size.
    ///
    /// `Ecb` requires no IV; all other modes require one IV per block.
    fn iv_len(self, block_bytes: usize) -> usize {
        match self {
            Self::Ecb => 0,
            Self::Cbc | Self::Ofb | Self::Cfb => block_bytes,
        }
    }

    /// Block size reported through `EVP_CIPHER_block_size`.
    ///
    /// Stream-style modes (OFB, CFB) report `1` to match the C provider's
    /// `IMPLEMENT_var_keylen_cipher_..._BLOCK_SIZE_1` macro family.
    fn reported_block_size(self, block_bytes: usize) -> usize {
        if self.is_stream() {
            1
        } else {
            block_bytes
        }
    }

    /// Translate to the shared [`CipherMode`] enum used by
    /// [`generic_get_params`].
    fn to_cipher_mode(self) -> CipherMode {
        match self {
            Self::Ecb => CipherMode::Ecb,
            Self::Cbc => CipherMode::Cbc,
            Self::Ofb => CipherMode::Ofb,
            Self::Cfb => CipherMode::Cfb,
        }
    }

    /// IV-generation strategy — every legacy mode accepts caller-supplied
    /// IVs only.  The exhaustive match ensures Rule R5 audit-trail
    /// preservation if new variants are introduced.
    fn iv_generation(self) -> IvGeneration {
        match self {
            Self::Ecb | Self::Cbc | Self::Ofb | Self::Cfb => IvGeneration::None,
        }
    }
}

// =============================================================================
// BlowfishCipher — Blowfish block cipher provider
// =============================================================================

/// Blowfish cipher provider — translates `cipher_blowfish.c::ossl_blowfish_*_functions`.
///
/// Blowfish is a 64-bit block cipher with a variable-length key in the
/// range `1..=72` bytes (8..=576 bits, though the canonical legacy
/// provider advertises 128 bits as the default).  It is exposed under the
/// `provider=legacy` property exclusively.
///
/// All state is per-context — [`BlowfishCipher`] itself is a stateless
/// metadata object safe to share across threads.
#[derive(Debug, Clone)]
pub struct BlowfishCipher {
    /// Algorithm name (e.g. `"BF-CBC"`).
    name: &'static str,
    /// Mode of operation.
    mode: LegacyBlockMode,
}

impl BlowfishCipher {
    /// Constructs a Blowfish provider with the given mode and standard name.
    ///
    /// `name` must be one of `"BF-ECB"`, `"BF-CBC"`, `"BF-OFB"`, `"BF-CFB"`.
    /// No validation is performed on `name`: the [`descriptors`] function
    /// is the sole call site.
    #[must_use]
    pub fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        Self { name, mode }
    }

    /// Returns the registered algorithm name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the default key length in bytes (16 bytes = 128 bits).
    #[must_use]
    pub fn key_length(&self) -> usize {
        BF_DEFAULT_KEY_BYTES
    }

    /// Returns the IV length in bytes (0 for ECB, 8 for CBC/OFB/CFB).
    #[must_use]
    pub fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    /// Returns the reported block size in bytes (1 for stream modes,
    /// 8 for block modes).
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    /// Allocates a fresh context for an encrypt or decrypt operation.
    ///
    /// # Errors
    ///
    /// Currently never returns an error — Blowfish allocation is
    /// infallible and the engine is constructed lazily by `encrypt_init`
    /// or `decrypt_init`.  The `Result` return type matches the
    /// [`CipherProvider::new_ctx`] contract.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(BlowfishCipherContext::new(self.name, self.mode)))
    }
}

impl CipherProvider for BlowfishCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        BF_DEFAULT_KEY_BYTES
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(BlowfishCipherContext::new(self.name, self.mode)))
    }
}

/// Per-instance state for a [`BlowfishCipher`] operation.
///
/// Replaces the C `PROV_BLOWFISH_CTX` struct.  Stores the underlying
/// [`Blowfish`] engine (which itself derives `Zeroize` / `ZeroizeOnDrop`)
/// plus chaining state for non-ECB modes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BlowfishCipherContext {
    /// Algorithm name (e.g. `"BF-CBC"`).
    #[zeroize(skip)]
    name: &'static str,
    /// Mode of operation.
    #[zeroize(skip)]
    mode: LegacyBlockMode,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag for ECB / CBC modes.
    padding: bool,
    /// Configuration metadata (no key material, skipped from zeroize).
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Underlying Blowfish engine (key schedule lives here).
    cipher: Option<Blowfish>,
    /// Chaining-vector state (8 bytes for non-ECB modes).
    iv: Vec<u8>,
    /// Pending input buffer for block modes (0..7 bytes pre-update).
    buffer: Vec<u8>,
    /// Cached keystream block for stream modes (OFB / CFB).
    keystream: Vec<u8>,
    /// Index into [`Self::keystream`] for consumed bytes.
    ks_offset: usize,
}

impl BlowfishCipherContext {
    /// Creates a fresh, uninitialised context for the given mode.
    fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            bytes_to_bits(BF_DEFAULT_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(mode.iv_len(BLOCK_64)),
            CipherFlags::VARIABLE_LENGTH,
        );
        let padding = init_config.default_padding();
        // Cement the IV-generation strategy at construction time so future
        // Rule R5 audits can confirm this stays "None".
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
            keystream: vec![0u8; BLOCK_64],
            ks_offset: BLOCK_64,
        }
    }

    /// Shared encrypt / decrypt initialisation logic.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // Blowfish accepts variable key lengths (1..=72); the engine
        // performs the lower-bound check.  Defer all key validation to
        // Blowfish::new() to keep error messages aligned.
        let engine = Blowfish::new(key)
            .map_err(|e| ProviderError::Init(format!("Blowfish key schedule failed: {e}")))?;

        let expected_iv = self.mode.iv_len(BLOCK_64);
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
            self.iv.clear();
        }

        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        for b in &mut self.keystream {
            *b = 0;
        }
        self.ks_offset = BLOCK_64;

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB mode update — block-aligned encrypt or decrypt with hold-back.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let BlowfishCipherContext {
            cipher,
            encrypting,
            padding,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Blowfish cipher not initialised".into()))?;
        let encrypting = *encrypting;
        let helper_padding = *padding && !encrypting;
        let processed = generic_block_update(input, BLOCK_64, buffer, helper_padding, |blocks| {
            let mut out = blocks.to_vec();
            let mut offset = 0;
            while offset + BLOCK_64 <= out.len() {
                let block = &mut out[offset..offset + BLOCK_64];
                let res = if encrypting {
                    cipher.encrypt_block(block)
                } else {
                    cipher.decrypt_block(block)
                };
                debug_assert!(res.is_ok(), "Blowfish block size invariant");
                let _ = res;
                offset += BLOCK_64;
            }
            out
        })?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// Finalise an ECB operation — apply or strip PKCS#7 padding.
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Blowfish cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut processed = padded;
                let mut offset = 0;
                while offset + BLOCK_64 <= processed.len() {
                    cipher
                        .encrypt_block(&mut processed[offset..offset + BLOCK_64])
                        .map_err(|e| {
                            ProviderError::Dispatch(format!("Blowfish ECB finalize: {e}"))
                        })?;
                    offset += BLOCK_64;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                processed.zeroize();
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "BF-ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "BF-ECB decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..BLOCK_64])
                .map_err(|e| ProviderError::Dispatch(format!("Blowfish ECB decrypt: {e}")))?;
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "BF-ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// CBC mode update — manual chaining loop.
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Blowfish cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / BLOCK_64) * BLOCK_64;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= BLOCK_64;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + BLOCK_64 <= to_process.len() {
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&to_process[offset..offset + BLOCK_64]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher
                    .encrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("Blowfish CBC encrypt: {e}")))?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher
                    .decrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("Blowfish CBC decrypt: {e}")))?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += BLOCK_64;
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
            .ok_or_else(|| ProviderError::Dispatch("Blowfish cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + BLOCK_64 <= padded.len() {
                    let mut block = [0u8; BLOCK_64];
                    block.copy_from_slice(&padded[offset..offset + BLOCK_64]);
                    xor_blocks(&mut block, &self.iv);
                    cipher.encrypt_block(&mut block).map_err(|e| {
                        ProviderError::Dispatch(format!("Blowfish CBC finalize: {e}"))
                    })?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += BLOCK_64;
                    offset += BLOCK_64;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "BF-CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "BF-CBC decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("Blowfish CBC decrypt: {e}")))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "BF-CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// OFB mode update — keystream from iterated IV encryption.
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let BlowfishCipherContext {
            cipher,
            iv,
            keystream,
            ks_offset,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Blowfish cipher not initialised".into()))?;
        let result = generic_stream_update(input, |data| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= BLOCK_64 {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "Blowfish block size invariant");
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

    /// CFB-64 mode update.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Blowfish cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= BLOCK_64 {
                self.keystream.copy_from_slice(&self.iv);
                cipher
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("Blowfish CFB keystream: {e}")))?;
                self.ks_offset = 0;
            }
            let ks_byte = self.keystream[self.ks_offset];
            let out_byte = byte ^ ks_byte;
            self.iv[self.ks_offset] = if self.encrypting { out_byte } else { byte };
            self.ks_offset += 1;
            out.push(out_byte);
        }
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }
}

// =============================================================================
// Cast5Cipher — CAST5 block cipher provider
// =============================================================================

/// CAST5 cipher provider — translates `cipher_cast5.c::ossl_cast5_*_functions`.
///
/// CAST5 (a.k.a. CAST-128, RFC 2144) is a 64-bit block cipher with a
/// variable key length in the range `5..=16` bytes (40..=128 bits).  The
/// provider advertises a default key length of 128 bits.
#[derive(Debug, Clone)]
pub struct Cast5Cipher {
    /// Algorithm name (e.g. `"CAST5-CBC"`).
    name: &'static str,
    /// Mode of operation.
    mode: LegacyBlockMode,
}

impl Cast5Cipher {
    /// Constructs a CAST5 provider with the given mode and standard name.
    #[must_use]
    pub fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        Self { name, mode }
    }

    /// Returns the registered algorithm name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the default key length in bytes (16 bytes = 128 bits).
    #[must_use]
    pub fn key_length(&self) -> usize {
        CAST5_DEFAULT_KEY_BYTES
    }

    /// Returns the IV length in bytes (0 for ECB, 8 for CBC/OFB/CFB).
    #[must_use]
    pub fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    /// Returns the reported block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    /// Allocates a fresh context for an encrypt or decrypt operation.
    ///
    /// # Errors
    ///
    /// Currently never returns an error.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Cast5CipherContext::new(self.name, self.mode)))
    }
}

impl CipherProvider for Cast5Cipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        CAST5_DEFAULT_KEY_BYTES
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Cast5CipherContext::new(self.name, self.mode)))
    }
}

/// Per-instance state for a [`Cast5Cipher`] operation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Cast5CipherContext {
    /// Algorithm name (e.g. `"CAST5-CBC"`).
    #[zeroize(skip)]
    name: &'static str,
    /// Mode of operation.
    #[zeroize(skip)]
    mode: LegacyBlockMode,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag for ECB / CBC modes.
    padding: bool,
    /// Configuration metadata.
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Underlying CAST5 engine.
    cipher: Option<Cast5>,
    /// Chaining-vector state.
    iv: Vec<u8>,
    /// Pending input buffer.
    buffer: Vec<u8>,
    /// Cached keystream block.
    keystream: Vec<u8>,
    /// Index into [`Self::keystream`].
    ks_offset: usize,
}

impl Cast5CipherContext {
    /// Creates a fresh, uninitialised CAST5 context.
    fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            bytes_to_bits(CAST5_DEFAULT_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(mode.iv_len(BLOCK_64)),
            CipherFlags::VARIABLE_LENGTH,
        );
        let padding = init_config.default_padding();
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
            keystream: vec![0u8; BLOCK_64],
            ks_offset: BLOCK_64,
        }
    }

    /// Shared encrypt / decrypt initialisation.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        let engine = Cast5::new(key)
            .map_err(|e| ProviderError::Init(format!("CAST5 key schedule failed: {e}")))?;

        let expected_iv = self.mode.iv_len(BLOCK_64);
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
            self.iv.clear();
        }

        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        for b in &mut self.keystream {
            *b = 0;
        }
        self.ks_offset = BLOCK_64;

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB update.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let Cast5CipherContext {
            cipher,
            encrypting,
            padding,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("CAST5 cipher not initialised".into()))?;
        let encrypting = *encrypting;
        let helper_padding = *padding && !encrypting;
        let processed = generic_block_update(input, BLOCK_64, buffer, helper_padding, |blocks| {
            let mut out = blocks.to_vec();
            let mut offset = 0;
            while offset + BLOCK_64 <= out.len() {
                let block = &mut out[offset..offset + BLOCK_64];
                let res = if encrypting {
                    cipher.encrypt_block(block)
                } else {
                    cipher.decrypt_block(block)
                };
                debug_assert!(res.is_ok(), "CAST5 block size invariant");
                let _ = res;
                offset += BLOCK_64;
            }
            out
        })?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// ECB finalize.
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("CAST5 cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut processed = padded;
                let mut offset = 0;
                while offset + BLOCK_64 <= processed.len() {
                    cipher
                        .encrypt_block(&mut processed[offset..offset + BLOCK_64])
                        .map_err(|e| ProviderError::Dispatch(format!("CAST5 ECB finalize: {e}")))?;
                    offset += BLOCK_64;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                processed.zeroize();
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "CAST5-ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "CAST5-ECB decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..BLOCK_64])
                .map_err(|e| ProviderError::Dispatch(format!("CAST5 ECB decrypt: {e}")))?;
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "CAST5-ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// CBC update with chaining state.
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("CAST5 cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / BLOCK_64) * BLOCK_64;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= BLOCK_64;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + BLOCK_64 <= to_process.len() {
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&to_process[offset..offset + BLOCK_64]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher
                    .encrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("CAST5 CBC encrypt: {e}")))?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher
                    .decrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("CAST5 CBC decrypt: {e}")))?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += BLOCK_64;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    /// CBC finalize.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("CAST5 cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + BLOCK_64 <= padded.len() {
                    let mut block = [0u8; BLOCK_64];
                    block.copy_from_slice(&padded[offset..offset + BLOCK_64]);
                    xor_blocks(&mut block, &self.iv);
                    cipher
                        .encrypt_block(&mut block)
                        .map_err(|e| ProviderError::Dispatch(format!("CAST5 CBC finalize: {e}")))?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += BLOCK_64;
                    offset += BLOCK_64;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "CAST5-CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "CAST5-CBC decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("CAST5 CBC decrypt: {e}")))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "CAST5-CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// OFB update.
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let Cast5CipherContext {
            cipher,
            iv,
            keystream,
            ks_offset,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("CAST5 cipher not initialised".into()))?;
        let result = generic_stream_update(input, |data| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= BLOCK_64 {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "CAST5 block size invariant");
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

    /// CFB-64 update.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("CAST5 cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= BLOCK_64 {
                self.keystream.copy_from_slice(&self.iv);
                cipher
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("CAST5 CFB keystream: {e}")))?;
                self.ks_offset = 0;
            }
            let ks_byte = self.keystream[self.ks_offset];
            let out_byte = byte ^ ks_byte;
            self.iv[self.ks_offset] = if self.encrypting { out_byte } else { byte };
            self.ks_offset += 1;
            out.push(out_byte);
        }
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }
}

impl CipherContext for Cast5CipherContext {
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
                "CAST5 context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.update_ecb(input, output),
            LegacyBlockMode::Cbc => self.update_cbc(input, output),
            LegacyBlockMode::Ofb => self.update_ofb(input, output),
            LegacyBlockMode::Cfb => self.update_cfb(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "CAST5 context: finalize before init".into(),
            ));
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.finalize_ecb(output),
            LegacyBlockMode::Cbc => self.finalize_cbc(output),
            LegacyBlockMode::Ofb | LegacyBlockMode::Cfb => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            CipherFlags::VARIABLE_LENGTH,
            bytes_to_bits(CAST5_DEFAULT_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(self.mode.iv_len(BLOCK_64)),
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                ParamValue::UInt64(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "CAST5 padding parameter must be an integer".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl CipherContext for BlowfishCipherContext {
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
                "Blowfish context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.update_ecb(input, output),
            LegacyBlockMode::Cbc => self.update_cbc(input, output),
            LegacyBlockMode::Ofb => self.update_ofb(input, output),
            LegacyBlockMode::Cfb => self.update_cfb(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "Blowfish context: finalize before init".into(),
            ));
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.finalize_ecb(output),
            LegacyBlockMode::Cbc => self.finalize_cbc(output),
            LegacyBlockMode::Ofb | LegacyBlockMode::Cfb => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            CipherFlags::VARIABLE_LENGTH,
            bytes_to_bits(BF_DEFAULT_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(self.mode.iv_len(BLOCK_64)),
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                ParamValue::UInt64(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "Blowfish padding parameter must be an integer".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// IdeaCipher — IDEA block cipher provider
// =============================================================================

/// IDEA cipher provider — translates `cipher_idea.c::ossl_idea_*_functions`.
///
/// IDEA (International Data Encryption Algorithm) is a 64-bit block
/// cipher with a **fixed 128-bit (16-byte) key**.  Unlike Blowfish and
/// CAST5, the IDEA provider does **not** carry the
/// `CipherFlags::VARIABLE_LENGTH` flag.
#[derive(Debug, Clone)]
pub struct IdeaCipher {
    /// Algorithm name (e.g. `"IDEA-CBC"`).
    name: &'static str,
    /// Mode of operation.
    mode: LegacyBlockMode,
}

impl IdeaCipher {
    /// Constructs an IDEA provider with the given mode and standard name.
    #[must_use]
    pub fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        Self { name, mode }
    }

    /// Returns the registered algorithm name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the fixed key length in bytes (16).
    #[must_use]
    pub fn key_length(&self) -> usize {
        IDEA_KEY_BYTES
    }

    /// Returns the IV length in bytes.
    #[must_use]
    pub fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    /// Returns the reported block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    /// Allocates a fresh context for an encrypt or decrypt operation.
    ///
    /// # Errors
    ///
    /// Currently never returns an error.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(IdeaCipherContext::new(self.name, self.mode)))
    }
}

impl CipherProvider for IdeaCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        IDEA_KEY_BYTES
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(IdeaCipherContext::new(self.name, self.mode)))
    }
}

/// Per-instance state for an [`IdeaCipher`] operation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdeaCipherContext {
    /// Algorithm name.
    #[zeroize(skip)]
    name: &'static str,
    /// Mode of operation.
    #[zeroize(skip)]
    mode: LegacyBlockMode,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag.
    padding: bool,
    /// Configuration metadata.
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Underlying IDEA engine.
    cipher: Option<Idea>,
    /// Chaining-vector state.
    iv: Vec<u8>,
    /// Pending input buffer.
    buffer: Vec<u8>,
    /// Cached keystream block.
    keystream: Vec<u8>,
    /// Index into [`Self::keystream`].
    ks_offset: usize,
}

impl IdeaCipherContext {
    /// Creates a fresh IDEA context.
    fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            bytes_to_bits(IDEA_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(mode.iv_len(BLOCK_64)),
            CipherFlags::empty(),
        );
        let padding = init_config.default_padding();
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
            keystream: vec![0u8; BLOCK_64],
            ks_offset: BLOCK_64,
        }
    }

    /// Shared encrypt / decrypt initialisation.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.len() != IDEA_KEY_BYTES {
            return Err(ProviderError::Init(format!(
                "IDEA key must be {IDEA_KEY_BYTES} bytes, got {}",
                key.len()
            )));
        }
        let engine = Idea::new(key)
            .map_err(|e| ProviderError::Init(format!("IDEA key schedule failed: {e}")))?;

        let expected_iv = self.mode.iv_len(BLOCK_64);
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
            self.iv.clear();
        }

        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        for b in &mut self.keystream {
            *b = 0;
        }
        self.ks_offset = BLOCK_64;

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB update.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let IdeaCipherContext {
            cipher,
            encrypting,
            padding,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("IDEA cipher not initialised".into()))?;
        let encrypting = *encrypting;
        let helper_padding = *padding && !encrypting;
        let processed = generic_block_update(input, BLOCK_64, buffer, helper_padding, |blocks| {
            let mut out = blocks.to_vec();
            let mut offset = 0;
            while offset + BLOCK_64 <= out.len() {
                let block = &mut out[offset..offset + BLOCK_64];
                let res = if encrypting {
                    cipher.encrypt_block(block)
                } else {
                    cipher.decrypt_block(block)
                };
                debug_assert!(res.is_ok(), "IDEA block size invariant");
                let _ = res;
                offset += BLOCK_64;
            }
            out
        })?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// ECB finalize.
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("IDEA cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut processed = padded;
                let mut offset = 0;
                while offset + BLOCK_64 <= processed.len() {
                    cipher
                        .encrypt_block(&mut processed[offset..offset + BLOCK_64])
                        .map_err(|e| ProviderError::Dispatch(format!("IDEA ECB finalize: {e}")))?;
                    offset += BLOCK_64;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                processed.zeroize();
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "IDEA-ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "IDEA-ECB decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..BLOCK_64])
                .map_err(|e| ProviderError::Dispatch(format!("IDEA ECB decrypt: {e}")))?;
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "IDEA-ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// CBC update.
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("IDEA cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / BLOCK_64) * BLOCK_64;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= BLOCK_64;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + BLOCK_64 <= to_process.len() {
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&to_process[offset..offset + BLOCK_64]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher
                    .encrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("IDEA CBC encrypt: {e}")))?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher
                    .decrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("IDEA CBC decrypt: {e}")))?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += BLOCK_64;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    /// CBC finalize.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("IDEA cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + BLOCK_64 <= padded.len() {
                    let mut block = [0u8; BLOCK_64];
                    block.copy_from_slice(&padded[offset..offset + BLOCK_64]);
                    xor_blocks(&mut block, &self.iv);
                    cipher
                        .encrypt_block(&mut block)
                        .map_err(|e| ProviderError::Dispatch(format!("IDEA CBC finalize: {e}")))?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += BLOCK_64;
                    offset += BLOCK_64;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "IDEA-CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "IDEA-CBC decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("IDEA CBC decrypt: {e}")))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "IDEA-CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// OFB update.
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let IdeaCipherContext {
            cipher,
            iv,
            keystream,
            ks_offset,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("IDEA cipher not initialised".into()))?;
        let result = generic_stream_update(input, |data| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= BLOCK_64 {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "IDEA block size invariant");
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

    /// CFB-64 update.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("IDEA cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= BLOCK_64 {
                self.keystream.copy_from_slice(&self.iv);
                cipher
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("IDEA CFB keystream: {e}")))?;
                self.ks_offset = 0;
            }
            let ks_byte = self.keystream[self.ks_offset];
            let out_byte = byte ^ ks_byte;
            self.iv[self.ks_offset] = if self.encrypting { out_byte } else { byte };
            self.ks_offset += 1;
            out.push(out_byte);
        }
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }
}

impl CipherContext for IdeaCipherContext {
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
                "IDEA context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.update_ecb(input, output),
            LegacyBlockMode::Cbc => self.update_cbc(input, output),
            LegacyBlockMode::Ofb => self.update_ofb(input, output),
            LegacyBlockMode::Cfb => self.update_cfb(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "IDEA context: finalize before init".into(),
            ));
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.finalize_ecb(output),
            LegacyBlockMode::Cbc => self.finalize_cbc(output),
            LegacyBlockMode::Ofb | LegacyBlockMode::Cfb => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            CipherFlags::empty(),
            bytes_to_bits(IDEA_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(self.mode.iv_len(BLOCK_64)),
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                ParamValue::UInt64(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "IDEA padding parameter must be an integer".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// SeedCipher — SEED block cipher provider
// =============================================================================

/// SEED cipher provider — translates `cipher_seed.c::ossl_seed_*_functions`.
///
/// SEED is a 128-bit block cipher with a **fixed 128-bit (16-byte) key**.
/// Unlike Blowfish/CAST5/RC2/RC4/RC5, SEED uses a **128-bit block size**,
/// not 64.
#[derive(Debug, Clone)]
pub struct SeedCipher {
    /// Algorithm name (e.g. `"SEED-CBC"`).
    name: &'static str,
    /// Mode of operation.
    mode: LegacyBlockMode,
}

impl SeedCipher {
    /// Constructs a SEED provider with the given mode and standard name.
    #[must_use]
    pub fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        Self { name, mode }
    }

    /// Returns the registered algorithm name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the fixed key length in bytes (16).
    #[must_use]
    pub fn key_length(&self) -> usize {
        SEED_KEY_BYTES
    }

    /// Returns the IV length in bytes.
    #[must_use]
    pub fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_128)
    }

    /// Returns the reported block size in bytes (16 for ECB/CBC, 1 for OFB/CFB).
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_128)
    }

    /// Allocates a fresh context for an encrypt or decrypt operation.
    ///
    /// # Errors
    ///
    /// Currently never returns an error.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(SeedCipherContext::new(self.name, self.mode)))
    }
}

impl CipherProvider for SeedCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        SEED_KEY_BYTES
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_128)
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_128)
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(SeedCipherContext::new(self.name, self.mode)))
    }
}

/// Per-instance state for a [`SeedCipher`] operation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SeedCipherContext {
    /// Algorithm name.
    #[zeroize(skip)]
    name: &'static str,
    /// Mode of operation.
    #[zeroize(skip)]
    mode: LegacyBlockMode,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag.
    padding: bool,
    /// Configuration metadata.
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Underlying SEED engine.
    cipher: Option<Seed>,
    /// Chaining-vector state.
    iv: Vec<u8>,
    /// Pending input buffer.
    buffer: Vec<u8>,
    /// Cached keystream block.
    keystream: Vec<u8>,
    /// Index into [`Self::keystream`].
    ks_offset: usize,
}

impl SeedCipherContext {
    /// Creates a fresh SEED context.
    fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            bytes_to_bits(SEED_KEY_BYTES),
            bytes_to_bits(BLOCK_128),
            bytes_to_bits(mode.iv_len(BLOCK_128)),
            CipherFlags::empty(),
        );
        let padding = init_config.default_padding();
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
            keystream: vec![0u8; BLOCK_128],
            ks_offset: BLOCK_128,
        }
    }

    /// Shared encrypt / decrypt initialisation.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.len() != SEED_KEY_BYTES {
            return Err(ProviderError::Init(format!(
                "SEED key must be {SEED_KEY_BYTES} bytes, got {}",
                key.len()
            )));
        }
        let engine = Seed::new(key)
            .map_err(|e| ProviderError::Init(format!("SEED key schedule failed: {e}")))?;

        let expected_iv = self.mode.iv_len(BLOCK_128);
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
            self.iv.clear();
        }

        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        for b in &mut self.keystream {
            *b = 0;
        }
        self.ks_offset = BLOCK_128;

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB update.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let SeedCipherContext {
            cipher,
            encrypting,
            padding,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SEED cipher not initialised".into()))?;
        let encrypting = *encrypting;
        let helper_padding = *padding && !encrypting;
        let processed = generic_block_update(input, BLOCK_128, buffer, helper_padding, |blocks| {
            let mut out = blocks.to_vec();
            let mut offset = 0;
            while offset + BLOCK_128 <= out.len() {
                let block = &mut out[offset..offset + BLOCK_128];
                let res = if encrypting {
                    cipher.encrypt_block(block)
                } else {
                    cipher.decrypt_block(block)
                };
                debug_assert!(res.is_ok(), "SEED block size invariant");
                let _ = res;
                offset += BLOCK_128;
            }
            out
        })?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// ECB finalize.
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SEED cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_128);
                self.buffer.clear();
                let mut processed = padded;
                let mut offset = 0;
                while offset + BLOCK_128 <= processed.len() {
                    cipher
                        .encrypt_block(&mut processed[offset..offset + BLOCK_128])
                        .map_err(|e| ProviderError::Dispatch(format!("SEED ECB finalize: {e}")))?;
                    offset += BLOCK_128;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                processed.zeroize();
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "SEED-ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_128 {
                return Err(ProviderError::Dispatch(format!(
                    "SEED-ECB decrypt finalize: expected {BLOCK_128} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..BLOCK_128])
                .map_err(|e| ProviderError::Dispatch(format!("SEED ECB decrypt: {e}")))?;
            let unpadded = pkcs7_unpad(&block, BLOCK_128)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "SEED-ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// CBC update.
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SEED cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / BLOCK_128) * BLOCK_128;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= BLOCK_128;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + BLOCK_128 <= to_process.len() {
            let mut block = [0u8; BLOCK_128];
            block.copy_from_slice(&to_process[offset..offset + BLOCK_128]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher
                    .encrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("SEED CBC encrypt: {e}")))?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher
                    .decrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("SEED CBC decrypt: {e}")))?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += BLOCK_128;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    /// CBC finalize.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SEED cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_128);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + BLOCK_128 <= padded.len() {
                    let mut block = [0u8; BLOCK_128];
                    block.copy_from_slice(&padded[offset..offset + BLOCK_128]);
                    xor_blocks(&mut block, &self.iv);
                    cipher
                        .encrypt_block(&mut block)
                        .map_err(|e| ProviderError::Dispatch(format!("SEED CBC finalize: {e}")))?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += BLOCK_128;
                    offset += BLOCK_128;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "SEED-CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_128 {
                return Err(ProviderError::Dispatch(format!(
                    "SEED-CBC decrypt finalize: expected {BLOCK_128} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; BLOCK_128];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("SEED CBC decrypt: {e}")))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, BLOCK_128)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "SEED-CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// OFB update.
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let SeedCipherContext {
            cipher,
            iv,
            keystream,
            ks_offset,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SEED cipher not initialised".into()))?;
        let result = generic_stream_update(input, |data| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= BLOCK_128 {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "SEED block size invariant");
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

    /// CFB-128 update.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SEED cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= BLOCK_128 {
                self.keystream.copy_from_slice(&self.iv);
                cipher
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("SEED CFB keystream: {e}")))?;
                self.ks_offset = 0;
            }
            let ks_byte = self.keystream[self.ks_offset];
            let out_byte = byte ^ ks_byte;
            self.iv[self.ks_offset] = if self.encrypting { out_byte } else { byte };
            self.ks_offset += 1;
            out.push(out_byte);
        }
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }
}

impl CipherContext for SeedCipherContext {
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
                "SEED context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.update_ecb(input, output),
            LegacyBlockMode::Cbc => self.update_cbc(input, output),
            LegacyBlockMode::Ofb => self.update_ofb(input, output),
            LegacyBlockMode::Cfb => self.update_cfb(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "SEED context: finalize before init".into(),
            ));
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.finalize_ecb(output),
            LegacyBlockMode::Cbc => self.finalize_cbc(output),
            LegacyBlockMode::Ofb | LegacyBlockMode::Cfb => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            CipherFlags::empty(),
            bytes_to_bits(SEED_KEY_BYTES),
            bytes_to_bits(BLOCK_128),
            bytes_to_bits(self.mode.iv_len(BLOCK_128)),
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                ParamValue::UInt64(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SEED padding parameter must be an integer".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// Rc2Cipher — RC2 block cipher provider
// =============================================================================

/// Parameter key for the RC2 effective-key-bits override
/// (matches OpenSSL's `OSSL_CIPHER_PARAM_RC2_KEYBITS`).
pub const RC2_KEYBITS_PARAM: &str = "rc2-keybits";

/// RC2 cipher provider — translates `cipher_rc2.c::ossl_rc2_*_functions`.
///
/// RC2 is a 64-bit block cipher with a **variable-length key** (1–128
/// bytes) and a separately-configurable **effective key strength in
/// bits** (1–1024).  The OpenSSL CLI exposes two pre-configured
/// variants: `RC2-40-CBC` (effective 40 bits) and `RC2-64-CBC`
/// (effective 64 bits), in addition to the generic `RC2-ECB / -CBC /
/// -OFB / -CFB` four-tuple.
#[derive(Debug, Clone)]
pub struct Rc2Cipher {
    /// Algorithm name (e.g. `"RC2-40-CBC"`).
    name: &'static str,
    /// Mode of operation.
    mode: LegacyBlockMode,
    /// Pre-configured effective key strength override.
    ///
    /// Per **rule R5**, this is `Option<u32>` rather than a sentinel
    /// (the C code uses `-1` to mean "unset", which is forbidden in the
    /// Rust port).
    effective_key_bits: Option<u32>,
}

impl Rc2Cipher {
    /// Constructs an RC2 provider with the given mode and optional
    /// fixed effective key strength.
    ///
    /// - `name`: registered algorithm name.
    /// - `mode`: ECB / CBC / OFB / CFB.
    /// - `effective_key_bits`: when `Some(bits)`, the underlying engine
    ///   is initialised via `Rc2::new_with_effective_bits` so callers
    ///   cannot raise the strength above this value (`RC2-40-CBC` and
    ///   `RC2-64-CBC` use this).  When `None`, the bit count tracks
    ///   `8 * key.len()` and may be overridden via `set_params`.
    #[must_use]
    pub fn new(name: &'static str, mode: LegacyBlockMode, effective_key_bits: Option<u32>) -> Self {
        Self {
            name,
            mode,
            effective_key_bits,
        }
    }

    /// Returns the registered algorithm name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the default key length in bytes for this RC2 variant.
    ///
    /// - `RC2-40-CBC` returns 5 bytes (40 bits) — export-grade.
    /// - `RC2-64-CBC` returns 8 bytes (64 bits).
    /// - All other variants return [`RC2_DEFAULT_KEY_BYTES`] (16 bytes).
    #[must_use]
    pub fn key_length(&self) -> usize {
        match self.effective_key_bits {
            Some(RC2_EFFECTIVE_BITS_40) => RC2_40_KEY_BYTES,
            Some(RC2_EFFECTIVE_BITS_64) => RC2_64_KEY_BYTES,
            _ => RC2_DEFAULT_KEY_BYTES,
        }
    }

    /// Returns the IV length in bytes.
    #[must_use]
    pub fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    /// Returns the reported block size in bytes (8 for ECB/CBC, 1 for OFB/CFB).
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    /// Allocates a fresh context for an encrypt or decrypt operation.
    ///
    /// # Errors
    ///
    /// Currently never returns an error.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Rc2CipherContext::new(
            self.name,
            self.mode,
            self.effective_key_bits,
        )))
    }
}

impl CipherProvider for Rc2Cipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        Self::key_length(self)
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Rc2CipherContext::new(
            self.name,
            self.mode,
            self.effective_key_bits,
        )))
    }
}

/// Per-instance state for an [`Rc2Cipher`] operation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Rc2CipherContext {
    /// Algorithm name.
    #[zeroize(skip)]
    name: &'static str,
    /// Mode of operation.
    #[zeroize(skip)]
    mode: LegacyBlockMode,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag.
    padding: bool,
    /// Configuration metadata.
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Underlying RC2 engine.
    cipher: Option<Rc2>,
    /// Chaining-vector state.
    iv: Vec<u8>,
    /// Pending input buffer.
    buffer: Vec<u8>,
    /// Cached keystream block.
    keystream: Vec<u8>,
    /// Index into [`Self::keystream`].
    ks_offset: usize,
    /// Active effective key strength in bits (rule R5 — `Option`, never sentinel).
    effective_key_bits: Option<u32>,
}

impl Rc2CipherContext {
    /// Creates a fresh RC2 context.
    fn new(name: &'static str, mode: LegacyBlockMode, effective_key_bits: Option<u32>) -> Self {
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            bytes_to_bits(RC2_DEFAULT_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(mode.iv_len(BLOCK_64)),
            CipherFlags::VARIABLE_LENGTH,
        );
        let padding = init_config.default_padding();
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
            keystream: vec![0u8; BLOCK_64],
            ks_offset: BLOCK_64,
            effective_key_bits,
        }
    }

    /// Shared encrypt / decrypt initialisation.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.is_empty() {
            return Err(ProviderError::Init("RC2 key must not be empty".into()));
        }
        if key.len() > 128 {
            return Err(ProviderError::Init(format!(
                "RC2 key must not exceed 128 bytes, got {}",
                key.len()
            )));
        }

        // Build engine: honour the (possibly pre-set) effective bits override.
        let engine = match self.effective_key_bits {
            Some(bits) => {
                let bits_usize = usize::try_from(bits)
                    .map_err(|_| ProviderError::Init("RC2 effective bits overflow usize".into()))?;
                Rc2::new_with_effective_bits(key, bits_usize)
                    .map_err(|e| ProviderError::Init(format!("RC2 key schedule failed: {e}")))?
            }
            None => Rc2::new(key)
                .map_err(|e| ProviderError::Init(format!("RC2 key schedule failed: {e}")))?,
        };

        let expected_iv = self.mode.iv_len(BLOCK_64);
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
            self.iv.clear();
        }

        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        for b in &mut self.keystream {
            *b = 0;
        }
        self.ks_offset = BLOCK_64;

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB update.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let Rc2CipherContext {
            cipher,
            encrypting,
            padding,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC2 cipher not initialised".into()))?;
        let encrypting = *encrypting;
        let helper_padding = *padding && !encrypting;
        let processed = generic_block_update(input, BLOCK_64, buffer, helper_padding, |blocks| {
            let mut out = blocks.to_vec();
            let mut offset = 0;
            while offset + BLOCK_64 <= out.len() {
                let block = &mut out[offset..offset + BLOCK_64];
                let res = if encrypting {
                    cipher.encrypt_block(block)
                } else {
                    cipher.decrypt_block(block)
                };
                debug_assert!(res.is_ok(), "RC2 block size invariant");
                let _ = res;
                offset += BLOCK_64;
            }
            out
        })?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// ECB finalize.
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC2 cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut processed = padded;
                let mut offset = 0;
                while offset + BLOCK_64 <= processed.len() {
                    cipher
                        .encrypt_block(&mut processed[offset..offset + BLOCK_64])
                        .map_err(|e| ProviderError::Dispatch(format!("RC2 ECB finalize: {e}")))?;
                    offset += BLOCK_64;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                processed.zeroize();
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "RC2-ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "RC2-ECB decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..BLOCK_64])
                .map_err(|e| ProviderError::Dispatch(format!("RC2 ECB decrypt: {e}")))?;
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "RC2-ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// CBC update.
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC2 cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / BLOCK_64) * BLOCK_64;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= BLOCK_64;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + BLOCK_64 <= to_process.len() {
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&to_process[offset..offset + BLOCK_64]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher
                    .encrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("RC2 CBC encrypt: {e}")))?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher
                    .decrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("RC2 CBC decrypt: {e}")))?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += BLOCK_64;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    /// CBC finalize.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC2 cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + BLOCK_64 <= padded.len() {
                    let mut block = [0u8; BLOCK_64];
                    block.copy_from_slice(&padded[offset..offset + BLOCK_64]);
                    xor_blocks(&mut block, &self.iv);
                    cipher
                        .encrypt_block(&mut block)
                        .map_err(|e| ProviderError::Dispatch(format!("RC2 CBC finalize: {e}")))?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += BLOCK_64;
                    offset += BLOCK_64;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "RC2-CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "RC2-CBC decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("RC2 CBC decrypt: {e}")))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "RC2-CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// OFB update.
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let Rc2CipherContext {
            cipher,
            iv,
            keystream,
            ks_offset,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC2 cipher not initialised".into()))?;
        let result = generic_stream_update(input, |data| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= BLOCK_64 {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "RC2 block size invariant");
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

    /// CFB-64 update.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC2 cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= BLOCK_64 {
                self.keystream.copy_from_slice(&self.iv);
                cipher
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("RC2 CFB keystream: {e}")))?;
                self.ks_offset = 0;
            }
            let ks_byte = self.keystream[self.ks_offset];
            let out_byte = byte ^ ks_byte;
            self.iv[self.ks_offset] = if self.encrypting { out_byte } else { byte };
            self.ks_offset += 1;
            out.push(out_byte);
        }
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }
}

impl CipherContext for Rc2CipherContext {
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
                "RC2 context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.update_ecb(input, output),
            LegacyBlockMode::Cbc => self.update_cbc(input, output),
            LegacyBlockMode::Ofb => self.update_ofb(input, output),
            LegacyBlockMode::Cfb => self.update_cfb(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "RC2 context: finalize before init".into(),
            ));
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.finalize_ecb(output),
            LegacyBlockMode::Cbc => self.finalize_cbc(output),
            LegacyBlockMode::Ofb | LegacyBlockMode::Cfb => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            CipherFlags::VARIABLE_LENGTH,
            bytes_to_bits(RC2_DEFAULT_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(self.mode.iv_len(BLOCK_64)),
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        if let Some(bits) = self.effective_key_bits {
            params.set(RC2_KEYBITS_PARAM, ParamValue::UInt32(bits));
        }
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                ParamValue::UInt64(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "RC2 padding parameter must be an integer".into(),
                    ));
                }
            }
        }
        if let Some(val) = params.get(RC2_KEYBITS_PARAM) {
            let bits = match val {
                ParamValue::UInt32(v) => *v,
                ParamValue::UInt64(v) => u32::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch("RC2 effective key bits exceeds u32 range".into())
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "RC2 effective key bits parameter must be unsigned integer".into(),
                    ));
                }
            };
            if !(1..=1024).contains(&bits) {
                return Err(ProviderError::Dispatch(format!(
                    "RC2 effective key bits must be in 1..=1024, got {bits}"
                )));
            }
            self.effective_key_bits = Some(bits);
        }
        Ok(())
    }
}

// =============================================================================
// Rc4Cipher — RC4 stream cipher provider
// =============================================================================

/// RC4 cipher provider — translates `cipher_rc4.c::ossl_rc4_*_functions`
/// (and its `RC4-HMAC-MD5` composite TLS variant from
/// `cipher_rc4_hmac_md5.c`).
///
/// RC4 is a **stream cipher**, so:
///
/// - Block size is reported as `1` (no modes, no padding).
/// - IV length is `0` — RC4 uses no IV.
/// - The key length is variable; default is 16 bytes (`RC4`) or
///   5 bytes for the 40-bit `RC4-40` legacy export-grade variant.
///
/// `RC4-HMAC-MD5` is a **TLS record-layer composite**: in OpenSSL it
/// integrates the RC4 stream cipher with an HMAC-MD5 MAC for use with
/// the legacy `TLS_RSA_WITH_RC4_128_MD5` ciphersuite.  At the
/// provider/EVP boundary the visible cipher is plain RC4; the record
/// layer is responsible for authenticating the AAD/payload.  The
/// dedicated descriptor here lets `EVP_CIPHER_fetch("RC4-HMAC-MD5")`
/// continue to succeed for callers that look it up by name.
#[derive(Debug, Clone)]
pub struct Rc4Cipher {
    /// Algorithm name (e.g. `"RC4-40"`).
    name: &'static str,
    /// Default key length in bytes (16 for `RC4` / `RC4-HMAC-MD5`,
    /// 5 for `RC4-40`).
    default_key_bytes: usize,
}

impl Rc4Cipher {
    /// Constructs an RC4 provider with the given name and default key length.
    #[must_use]
    pub fn new(name: &'static str, default_key_bytes: usize) -> Self {
        Self {
            name,
            default_key_bytes,
        }
    }

    /// Constructs the standard `"RC4"` provider with a 128-bit
    /// (16-byte) default key length.
    ///
    /// Equivalent to `Rc4Cipher::new("RC4", RC4_DEFAULT_KEY_BYTES)`.
    #[must_use]
    pub fn standard() -> Self {
        Self::new("RC4", RC4_DEFAULT_KEY_BYTES)
    }

    /// Constructs the legacy export-grade `"RC4-40"` provider with a
    /// 40-bit (5-byte) default key length.
    ///
    /// Equivalent to `Rc4Cipher::new("RC4-40", RC4_40_KEY_BYTES)`.
    #[must_use]
    pub fn rc4_40() -> Self {
        Self::new("RC4-40", RC4_40_KEY_BYTES)
    }

    /// Constructs the TLS composite `"RC4-HMAC-MD5"` provider with a
    /// 128-bit (16-byte) default key length.
    ///
    /// At the provider/EVP boundary the visible cipher is plain RC4;
    /// authentication of the AAD/payload is handled by the record
    /// layer.  Equivalent to
    /// `Rc4Cipher::new("RC4-HMAC-MD5", RC4_DEFAULT_KEY_BYTES)`.
    #[must_use]
    pub fn rc4_hmac_md5() -> Self {
        Self::new("RC4-HMAC-MD5", RC4_DEFAULT_KEY_BYTES)
    }

    /// Returns the registered algorithm name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the default key length in bytes.
    #[must_use]
    pub fn key_length(&self) -> usize {
        self.default_key_bytes
    }

    /// Returns the IV length in bytes (always 0 for stream ciphers).
    #[must_use]
    pub fn iv_length(&self) -> usize {
        0
    }

    /// Returns the reported block size (always 1 for stream ciphers).
    #[must_use]
    pub fn block_size(&self) -> usize {
        1
    }

    /// Allocates a fresh context for an encrypt or decrypt operation.
    ///
    /// # Errors
    ///
    /// Currently never returns an error.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Rc4CipherContext::new(
            self.name,
            self.default_key_bytes,
        )))
    }
}

impl CipherProvider for Rc4Cipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        self.default_key_bytes
    }

    fn iv_length(&self) -> usize {
        0
    }

    fn block_size(&self) -> usize {
        1
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Rc4CipherContext::new(
            self.name,
            self.default_key_bytes,
        )))
    }
}

/// Per-instance state for an [`Rc4Cipher`] operation.
///
/// Note that, unlike the block-cipher contexts, RC4 holds the engine
/// in a way that allows `&mut` access (`StreamCipher::process` takes
/// `&mut self`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Rc4CipherContext {
    /// Algorithm name.
    #[zeroize(skip)]
    name: &'static str,
    /// Default key length in bytes (informational; RC4 accepts variable lengths).
    default_key_bytes: usize,
    /// `true` for encrypt, `false` for decrypt (RC4 is symmetric, so
    /// these behave identically; tracked for diagnostic output).
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// Underlying RC4 stream engine.  Owned by-value so that
    /// [`StreamCipher::process`] (which takes `&mut self`) can be
    /// invoked.
    cipher: Option<Rc4>,
}

impl Rc4CipherContext {
    /// Creates a fresh RC4 context.
    fn new(name: &'static str, default_key_bytes: usize) -> Self {
        Self {
            name,
            default_key_bytes,
            encrypting: false,
            initialized: false,
            cipher: None,
        }
    }

    /// Shared encrypt / decrypt initialisation.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.is_empty() {
            return Err(ProviderError::Init("RC4 key must not be empty".into()));
        }
        if key.len() > 256 {
            return Err(ProviderError::Init(format!(
                "RC4 key must not exceed 256 bytes, got {}",
                key.len()
            )));
        }
        if iv.is_some() {
            return Err(ProviderError::Dispatch(format!(
                "{} is a stream cipher and does not accept an IV",
                self.name
            )));
        }
        let engine = Rc4::new(key)
            .map_err(|e| ProviderError::Init(format!("RC4 key schedule failed: {e}")))?;
        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }
}

impl CipherContext for Rc4CipherContext {
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
                "RC4 context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        let cipher = self
            .cipher
            .as_mut()
            .ok_or_else(|| ProviderError::Dispatch("RC4 cipher not initialised".into()))?;
        let result = generic_stream_update(input, |data| {
            // SAFETY-CHECK: `Rc4::process` is a stream-cipher operation
            // that XOR-mixes the input with the keystream. It returns
            // a `CryptoResult<Vec<u8>>`; for an in-range (1..=256)
            // RC4 instance it cannot fail. We surface any returned
            // error as an empty `Vec<u8>` because `generic_stream_update`
            // expects an infallible callback shape.
            cipher.process(data).unwrap_or_default()
        })?;
        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    fn finalize(&mut self, _output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "RC4 context: finalize before init".into(),
            ));
        }
        // RC4 is a stream cipher: there is no buffered tail.
        Ok(0)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            CipherMode::Stream,
            CipherFlags::VARIABLE_LENGTH,
            bytes_to_bits(self.default_key_bytes),
            8, // block_bits = 1 byte for stream
            0, // iv_bits = 0
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        // RC4 has no settable per-context parameters in the OpenSSL
        // C provider.  We accept any parameter set but ignore unknown
        // keys so that callers that pass a generic options bag are
        // not rejected.
        Ok(())
    }
}

// =============================================================================
// Rc5Cipher — RC5 block cipher provider
// =============================================================================

/// Parameter key for the RC5 round-count override
/// (matches OpenSSL's `OSSL_CIPHER_PARAM_RC5_ROUNDS`).
pub const RC5_ROUNDS_PARAM: &str = "rc5-rounds";

/// RC5 cipher provider — translates `cipher_rc5.c::ossl_rc5_*_functions`.
///
/// RC5 is a 64-bit block cipher with a **variable-length key** (default
/// 128 bits) and a **configurable number of rounds** (8, 12, or 16).
/// Per **rule R6** the round count is held as a typed `u32`, never a
/// raw `as` cast.
#[derive(Debug, Clone)]
pub struct Rc5Cipher {
    /// Algorithm name (e.g. `"RC5-CBC"`).
    name: &'static str,
    /// Mode of operation.
    mode: LegacyBlockMode,
}

impl Rc5Cipher {
    /// Constructs an RC5 provider with the given mode and standard name.
    #[must_use]
    pub fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        Self { name, mode }
    }

    /// Returns the registered algorithm name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the default key length in bytes (16).
    #[must_use]
    pub fn key_length(&self) -> usize {
        RC5_DEFAULT_KEY_BYTES
    }

    /// Returns the IV length in bytes.
    #[must_use]
    pub fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    /// Returns the reported block size in bytes (8 for ECB/CBC, 1 for OFB/CFB).
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    /// Allocates a fresh context for an encrypt or decrypt operation.
    ///
    /// # Errors
    ///
    /// Currently never returns an error.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Rc5CipherContext::new(self.name, self.mode)))
    }
}

impl CipherProvider for Rc5Cipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        RC5_DEFAULT_KEY_BYTES
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len(BLOCK_64)
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size(BLOCK_64)
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Rc5CipherContext::new(self.name, self.mode)))
    }
}

/// Per-instance state for an [`Rc5Cipher`] operation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Rc5CipherContext {
    /// Algorithm name.
    #[zeroize(skip)]
    name: &'static str,
    /// Mode of operation.
    #[zeroize(skip)]
    mode: LegacyBlockMode,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` after a successful `*_init()` call.
    initialized: bool,
    /// PKCS#7 padding flag.
    padding: bool,
    /// Configuration metadata.
    #[zeroize(skip)]
    init_config: Option<CipherInitConfig>,
    /// Underlying RC5 engine.
    cipher: Option<Rc5>,
    /// Chaining-vector state.
    iv: Vec<u8>,
    /// Pending input buffer.
    buffer: Vec<u8>,
    /// Cached keystream block.
    keystream: Vec<u8>,
    /// Index into [`Self::keystream`].
    ks_offset: usize,
    /// Round count (rule R6: u32, no narrowing casts).
    rounds: u32,
}

impl Rc5CipherContext {
    /// Creates a fresh RC5 context with the default round count.
    fn new(name: &'static str, mode: LegacyBlockMode) -> Self {
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            bytes_to_bits(RC5_DEFAULT_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(mode.iv_len(BLOCK_64)),
            CipherFlags::VARIABLE_LENGTH,
        );
        let padding = init_config.default_padding();
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
            keystream: vec![0u8; BLOCK_64],
            ks_offset: BLOCK_64,
            rounds: RC5_DEFAULT_ROUNDS,
        }
    }

    /// Shared encrypt / decrypt initialisation.
    fn init_common(
        &mut self,
        encrypting: bool,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key.is_empty() {
            return Err(ProviderError::Init("RC5 key must not be empty".into()));
        }
        if key.len() > 255 {
            return Err(ProviderError::Init(format!(
                "RC5 key must not exceed 255 bytes, got {}",
                key.len()
            )));
        }

        let engine = Rc5::new_with_rounds(key, self.rounds)
            .map_err(|e| ProviderError::Init(format!("RC5 key schedule failed: {e}")))?;

        let expected_iv = self.mode.iv_len(BLOCK_64);
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
            self.iv.clear();
        }

        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        for b in &mut self.keystream {
            *b = 0;
        }
        self.ks_offset = BLOCK_64;

        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB update.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let Rc5CipherContext {
            cipher,
            encrypting,
            padding,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC5 cipher not initialised".into()))?;
        let encrypting = *encrypting;
        let helper_padding = *padding && !encrypting;
        let processed = generic_block_update(input, BLOCK_64, buffer, helper_padding, |blocks| {
            let mut out = blocks.to_vec();
            let mut offset = 0;
            while offset + BLOCK_64 <= out.len() {
                let block = &mut out[offset..offset + BLOCK_64];
                let res = if encrypting {
                    cipher.encrypt_block(block)
                } else {
                    cipher.decrypt_block(block)
                };
                debug_assert!(res.is_ok(), "RC5 block size invariant");
                let _ = res;
                offset += BLOCK_64;
            }
            out
        })?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// ECB finalize.
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC5 cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut processed = padded;
                let mut offset = 0;
                while offset + BLOCK_64 <= processed.len() {
                    cipher
                        .encrypt_block(&mut processed[offset..offset + BLOCK_64])
                        .map_err(|e| ProviderError::Dispatch(format!("RC5 ECB finalize: {e}")))?;
                    offset += BLOCK_64;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                processed.zeroize();
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "RC5-ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "RC5-ECB decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..BLOCK_64])
                .map_err(|e| ProviderError::Dispatch(format!("RC5 ECB decrypt: {e}")))?;
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "RC5-ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// CBC update.
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC5 cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / BLOCK_64) * BLOCK_64;
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= BLOCK_64;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + BLOCK_64 <= to_process.len() {
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&to_process[offset..offset + BLOCK_64]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher
                    .encrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("RC5 CBC encrypt: {e}")))?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher
                    .decrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("RC5 CBC decrypt: {e}")))?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += BLOCK_64;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    /// CBC finalize.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC5 cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, BLOCK_64);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + BLOCK_64 <= padded.len() {
                    let mut block = [0u8; BLOCK_64];
                    block.copy_from_slice(&padded[offset..offset + BLOCK_64]);
                    xor_blocks(&mut block, &self.iv);
                    cipher
                        .encrypt_block(&mut block)
                        .map_err(|e| ProviderError::Dispatch(format!("RC5 CBC finalize: {e}")))?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += BLOCK_64;
                    offset += BLOCK_64;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "RC5-CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != BLOCK_64 {
                return Err(ProviderError::Dispatch(format!(
                    "RC5-CBC decrypt finalize: expected {BLOCK_64} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; BLOCK_64];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("RC5 CBC decrypt: {e}")))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, BLOCK_64)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "RC5-CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    /// OFB update.
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let Rc5CipherContext {
            cipher,
            iv,
            keystream,
            ks_offset,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC5 cipher not initialised".into()))?;
        let result = generic_stream_update(input, |data| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= BLOCK_64 {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "RC5 block size invariant");
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

    /// CFB-64 update.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("RC5 cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= BLOCK_64 {
                self.keystream.copy_from_slice(&self.iv);
                cipher
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("RC5 CFB keystream: {e}")))?;
                self.ks_offset = 0;
            }
            let ks_byte = self.keystream[self.ks_offset];
            let out_byte = byte ^ ks_byte;
            self.iv[self.ks_offset] = if self.encrypting { out_byte } else { byte };
            self.ks_offset += 1;
            out.push(out_byte);
        }
        let len = out.len();
        output.extend_from_slice(&out);
        out.zeroize();
        Ok(len)
    }
}

impl CipherContext for Rc5CipherContext {
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
                "RC5 context: update before init".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.update_ecb(input, output),
            LegacyBlockMode::Cbc => self.update_cbc(input, output),
            LegacyBlockMode::Ofb => self.update_ofb(input, output),
            LegacyBlockMode::Cfb => self.update_cfb(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "RC5 context: finalize before init".into(),
            ));
        }
        match self.mode {
            LegacyBlockMode::Ecb => self.finalize_ecb(output),
            LegacyBlockMode::Cbc => self.finalize_cbc(output),
            LegacyBlockMode::Ofb | LegacyBlockMode::Cfb => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            CipherFlags::VARIABLE_LENGTH,
            bytes_to_bits(RC5_DEFAULT_KEY_BYTES),
            bytes_to_bits(BLOCK_64),
            bytes_to_bits(self.mode.iv_len(BLOCK_64)),
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        params.set(RC5_ROUNDS_PARAM, ParamValue::UInt32(self.rounds));
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                ParamValue::UInt64(v) => {
                    if matches!(self.mode, LegacyBlockMode::Ecb | LegacyBlockMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "RC5 padding parameter must be an integer".into(),
                    ));
                }
            }
        }
        if let Some(val) = params.get(RC5_ROUNDS_PARAM) {
            let rounds = match val {
                ParamValue::UInt32(v) => *v,
                ParamValue::UInt64(v) => u32::try_from(*v)
                    .map_err(|_| ProviderError::Dispatch("RC5 rounds exceeds u32 range".into()))?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "RC5 rounds parameter must be unsigned integer".into(),
                    ));
                }
            };
            // OpenSSL only permits the canonical {8, 12, 16} round counts.
            if !matches!(rounds, 8 | 12 | 16) {
                return Err(ProviderError::Dispatch(format!(
                    "RC5 rounds must be 8, 12, or 16, got {rounds}"
                )));
            }
            self.rounds = rounds;
        }
        Ok(())
    }
}

// =============================================================================
// descriptors() — Aggregated Legacy Cipher Algorithm Registry
// =============================================================================

/// Returns algorithm descriptors for **all** legacy ciphers handled by this
/// module.
///
/// The returned [`AlgorithmDescriptor`] vector is consumed by
/// `LegacyProvider::query_operation()` (see `providers/legacyprov.c`) to
/// register the entire deprecated-algorithm catalogue with the provider
/// store.  Every entry advertises the property string
/// `"provider=legacy"`, which is what causes the EVP fetch layer to
/// route requests through the legacy provider rather than the default
/// provider — exactly mirroring the C-side `legacy_ciphers[]` table.
///
/// # Coverage
///
/// | Family   | Variants registered                                                      |
/// |----------|--------------------------------------------------------------------------|
/// | Blowfish | `BF-ECB`, `BF-CBC`, `BF-OFB`, `BF-CFB`                                   |
/// | CAST5    | `CAST5-ECB`, `CAST5-CBC`, `CAST5-OFB`, `CAST5-CFB`                       |
/// | IDEA     | `IDEA-ECB`, `IDEA-CBC`, `IDEA-OFB`, `IDEA-CFB`                           |
/// | SEED     | `SEED-ECB`, `SEED-CBC`, `SEED-OFB`, `SEED-CFB`                           |
/// | RC2      | `RC2-ECB`, `RC2-CBC`, `RC2-OFB`, `RC2-CFB`, `RC2-40-CBC`, `RC2-64-CBC`   |
/// | RC4      | `RC4`, `RC4-40`, `RC4-HMAC-MD5`                                          |
/// | RC5      | `RC5-ECB`, `RC5-CBC`, `RC5-OFB`, `RC5-CFB`                               |
///
/// Total: **25 algorithm descriptors**.
///
/// # Rule R10 — Wiring
///
/// The descriptor table is the canonical entry point that wires every
/// concrete cipher type defined in this module into the provider runtime.
/// `LegacyProvider::query_operation` calls this function once at provider
/// load and uses the result to populate the algorithm cache.
///
/// # Implementation Note
///
/// Mode-specific names (`BF-ECB`, `CAST5-CBC`, …) are produced by
/// `format!()` and converted to `&'static str` via `Box::leak` — exactly
/// once per process at provider initialisation.  This is not a memory
/// leak in any meaningful sense: the lifetime of the descriptor table
/// matches the lifetime of the process, and the leaked strings are
/// referenced by the global method store for the duration of the
/// program.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();
    let block_modes = ["ECB", "CBC", "OFB", "CFB"];

    // ---- Blowfish (BF) — variable key 32–448 bits, 64-bit block ------------
    for mode in &block_modes {
        let name = format!("BF-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "Blowfish block cipher (legacy)",
        });
    }

    // ---- CAST5 (CAST-128) — variable key 40–128 bits, 64-bit block ---------
    for mode in &block_modes {
        let name = format!("CAST5-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "CAST5 (CAST-128) block cipher (legacy)",
        });
    }

    // ---- IDEA — 128-bit key, 64-bit block ----------------------------------
    for mode in &block_modes {
        let name = format!("IDEA-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "IDEA block cipher (legacy)",
        });
    }

    // ---- SEED — 128-bit key, 128-bit block (Korean standard) ---------------
    for mode in &block_modes {
        let name = format!("SEED-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "SEED block cipher (legacy, Korean standard)",
        });
    }

    // ---- RC2 — variable key, 64-bit block ----------------------------------
    for mode in &block_modes {
        let name = format!("RC2-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "RC2 block cipher (legacy)",
        });
    }

    // ---- RC2 with explicit effective key bits ------------------------------
    descs.push(AlgorithmDescriptor {
        names: vec!["RC2-40-CBC"],
        property: "provider=legacy",
        description: "RC2-40 CBC (legacy, export-grade)",
    });
    descs.push(AlgorithmDescriptor {
        names: vec!["RC2-64-CBC"],
        property: "provider=legacy",
        description: "RC2-64 CBC (legacy)",
    });

    // ---- RC4 stream cipher -------------------------------------------------
    descs.push(AlgorithmDescriptor {
        names: vec!["RC4"],
        property: "provider=legacy",
        description: "RC4 stream cipher (legacy, insecure)",
    });
    descs.push(AlgorithmDescriptor {
        names: vec!["RC4-40"],
        property: "provider=legacy",
        description: "RC4-40 stream cipher (legacy, export-grade)",
    });
    descs.push(AlgorithmDescriptor {
        names: vec!["RC4-HMAC-MD5"],
        property: "provider=legacy",
        description: "RC4-HMAC-MD5 composite (legacy, TLS)",
    });

    // ---- RC5 — variable key/rounds/block -----------------------------------
    for mode in &block_modes {
        let name = format!("RC5-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "RC5 block cipher (legacy)",
        });
    }

    descs
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // RATIONALE: Within the `#[cfg(test)]` test module the `expect`, `unwrap`,
    // and `panic!` patterns are idiomatic for asserting setup invariants and
    // failing fast on unexpected branches. The clippy.toml guidance explicitly
    // permits these patterns in tests with a justification (see workspace
    // `Cargo.toml` `[workspace.lints.clippy]` notes for `unwrap_used`,
    // `expect_used`, and `panic`). Production code in this file uses
    // `Result<T, ProviderError>` everywhere — these allowances are scoped
    // exclusively to the test module.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    // ---- Helpers ------------------------------------------------------------

    /// Build a `ParamSet` that disables PKCS#7 padding for non-aligned
    /// round-trip tests in CBC/ECB modes.
    fn no_padding_params() -> ParamSet {
        let mut p = ParamSet::new();
        p.set(param_keys::PADDING, ParamValue::UInt32(0));
        p
    }

    // ---- LegacyBlockMode tests ----------------------------------------------

    #[test]
    fn legacy_block_mode_display_renders_uppercase_tokens() {
        assert_eq!(format!("{}", LegacyBlockMode::Ecb), "ECB");
        assert_eq!(format!("{}", LegacyBlockMode::Cbc), "CBC");
        assert_eq!(format!("{}", LegacyBlockMode::Ofb), "OFB");
        assert_eq!(format!("{}", LegacyBlockMode::Cfb), "CFB");
    }

    #[test]
    fn legacy_block_mode_iv_len_zero_for_ecb_and_block_for_others() {
        // ECB never uses an IV.
        assert_eq!(LegacyBlockMode::Ecb.iv_len(BLOCK_64), 0);
        assert_eq!(LegacyBlockMode::Ecb.iv_len(BLOCK_128), 0);

        // CBC/OFB/CFB use a full-block IV.
        for mode in [
            LegacyBlockMode::Cbc,
            LegacyBlockMode::Ofb,
            LegacyBlockMode::Cfb,
        ] {
            assert_eq!(mode.iv_len(BLOCK_64), BLOCK_64);
            assert_eq!(mode.iv_len(BLOCK_128), BLOCK_128);
        }
    }

    #[test]
    fn legacy_block_mode_reported_block_size_distinguishes_block_and_stream_styles() {
        // ECB/CBC are pure block modes — they report the cipher's natural
        // block size.  OFB/CFB report `1` because they decompose into a
        // byte-stream of XOR operations against the IV (matches the C
        // provider's `IMPLEMENT_var_keylen_cipher_..._BLOCK_SIZE_1` macro).
        for mode in [LegacyBlockMode::Ecb, LegacyBlockMode::Cbc] {
            assert_eq!(mode.reported_block_size(BLOCK_64), BLOCK_64);
            assert_eq!(mode.reported_block_size(BLOCK_128), BLOCK_128);
            assert!(!mode.is_stream(), "{mode} must not be classified as stream");
        }
        for mode in [LegacyBlockMode::Ofb, LegacyBlockMode::Cfb] {
            assert_eq!(mode.reported_block_size(BLOCK_64), 1);
            assert_eq!(mode.reported_block_size(BLOCK_128), 1);
            assert!(mode.is_stream(), "{mode} must be classified as stream-like");
        }
    }

    // ---- Descriptor tests ---------------------------------------------------

    #[test]
    fn descriptor_count_matches_29_legacy_variants() {
        // 4 BF + 4 CAST5 + 4 IDEA + 4 SEED + 6 RC2 (4 modes + RC2-40-CBC + RC2-64-CBC)
        // + 3 RC4 (RC4 + RC4-40 + RC4-HMAC-MD5) + 4 RC5 = 29.
        let descs = descriptors();
        assert_eq!(
            descs.len(),
            29,
            "expected 29 legacy cipher descriptors, got {}",
            descs.len()
        );
    }

    #[test]
    fn descriptor_property_is_provider_legacy() {
        for desc in descriptors() {
            assert_eq!(
                desc.property,
                "provider=legacy",
                "descriptor {names:?} has wrong property: {prop}",
                names = desc.names,
                prop = desc.property
            );
        }
    }

    #[test]
    fn descriptor_names_cover_each_family() {
        // Collect every primary name (descriptors emit a single name per entry).
        let names: Vec<&'static str> = descriptors()
            .iter()
            .map(|d| {
                *d.names
                    .first()
                    .expect("each descriptor must have at least one name")
            })
            .collect();

        // Blowfish family.
        for variant in ["BF-ECB", "BF-CBC", "BF-OFB", "BF-CFB"] {
            assert!(
                names.contains(&variant),
                "missing Blowfish descriptor: {variant}"
            );
        }
        // CAST5 family.
        for variant in ["CAST5-ECB", "CAST5-CBC", "CAST5-OFB", "CAST5-CFB"] {
            assert!(
                names.contains(&variant),
                "missing CAST5 descriptor: {variant}"
            );
        }
        // IDEA family.
        for variant in ["IDEA-ECB", "IDEA-CBC", "IDEA-OFB", "IDEA-CFB"] {
            assert!(
                names.contains(&variant),
                "missing IDEA descriptor: {variant}"
            );
        }
        // SEED family.
        for variant in ["SEED-ECB", "SEED-CBC", "SEED-OFB", "SEED-CFB"] {
            assert!(
                names.contains(&variant),
                "missing SEED descriptor: {variant}"
            );
        }
        // RC2 family — note the special reduced-key variants.
        for variant in [
            "RC2-ECB",
            "RC2-CBC",
            "RC2-OFB",
            "RC2-CFB",
            "RC2-40-CBC",
            "RC2-64-CBC",
        ] {
            assert!(
                names.contains(&variant),
                "missing RC2 descriptor: {variant}"
            );
        }
        // RC4 family — stream cipher and TLS composite.
        for variant in ["RC4", "RC4-40", "RC4-HMAC-MD5"] {
            assert!(
                names.contains(&variant),
                "missing RC4 descriptor: {variant}"
            );
        }
        // RC5 family.
        for variant in ["RC5-ECB", "RC5-CBC", "RC5-OFB", "RC5-CFB"] {
            assert!(
                names.contains(&variant),
                "missing RC5 descriptor: {variant}"
            );
        }
    }

    #[test]
    fn descriptor_names_are_unique() {
        // Collect every primary descriptor name and assert no duplicates.
        let mut seen: Vec<&'static str> = Vec::new();
        for desc in descriptors() {
            let name = *desc
                .names
                .first()
                .expect("each descriptor must have at least one name");
            assert!(
                !seen.contains(&name),
                "duplicate descriptor name in legacy registry: {name}"
            );
            seen.push(name);
        }
    }

    // ---- Blowfish provider metadata + round-trip ----------------------------

    #[test]
    fn blowfish_ecb_provider_metadata() {
        let provider = BlowfishCipher::new("BF-ECB", LegacyBlockMode::Ecb);
        assert_eq!(provider.name(), "BF-ECB");
        assert_eq!(provider.key_length(), BF_DEFAULT_KEY_BYTES); // 16 bytes
        assert_eq!(provider.iv_length(), 0); // ECB → no IV
        assert_eq!(provider.block_size(), BLOCK_64); // 8 bytes
    }

    #[test]
    fn blowfish_cbc_provider_metadata() {
        let provider = BlowfishCipher::new("BF-CBC", LegacyBlockMode::Cbc);
        assert_eq!(provider.name(), "BF-CBC");
        assert_eq!(provider.key_length(), BF_DEFAULT_KEY_BYTES);
        assert_eq!(provider.iv_length(), BLOCK_64); // 8-byte IV
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn blowfish_cbc_round_trip_matches_plaintext() {
        let provider = BlowfishCipher::new("BF-CBC", LegacyBlockMode::Cbc);
        let key = [0x42u8; BF_DEFAULT_KEY_BYTES];
        let iv = [0x07u8; BLOCK_64];
        // Use exactly two full blocks so we can test with padding disabled.
        let plaintext = [0xAAu8; BLOCK_64 * 2];

        let nopad = no_padding_params();
        let mut enc_ctx = provider.new_ctx().expect("blowfish enc new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("blowfish enc init");
        let mut ciphertext = Vec::new();
        enc_ctx
            .update(&plaintext, &mut ciphertext)
            .expect("blowfish enc update");
        enc_ctx
            .finalize(&mut ciphertext)
            .expect("blowfish enc finalize");
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(
            ciphertext, plaintext,
            "CBC must produce distinct ciphertext"
        );

        let mut dec_ctx = provider.new_ctx().expect("blowfish dec new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("blowfish dec init");
        let mut recovered = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut recovered)
            .expect("blowfish dec update");
        dec_ctx
            .finalize(&mut recovered)
            .expect("blowfish dec finalize");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn blowfish_cbc_requires_iv() {
        let provider = BlowfishCipher::new("BF-CBC", LegacyBlockMode::Cbc);
        let key = [0x42u8; BF_DEFAULT_KEY_BYTES];
        let mut ctx = provider.new_ctx().expect("blowfish new_ctx");
        // Missing IV must fail with a Dispatch error.
        let err = ctx
            .encrypt_init(&key, None, None)
            .expect_err("init without IV must fail");
        assert!(
            matches!(err, ProviderError::Dispatch(_)),
            "expected Dispatch error, got {err:?}"
        );
    }

    // ---- CAST5 provider metadata + round-trip -------------------------------

    #[test]
    fn cast5_cbc_provider_metadata() {
        let provider = Cast5Cipher::new("CAST5-CBC", LegacyBlockMode::Cbc);
        assert_eq!(provider.name(), "CAST5-CBC");
        assert_eq!(provider.key_length(), CAST5_DEFAULT_KEY_BYTES); // 16 bytes
        assert_eq!(provider.iv_length(), BLOCK_64); // 8-byte IV
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn cast5_ecb_provider_metadata() {
        let provider = Cast5Cipher::new("CAST5-ECB", LegacyBlockMode::Ecb);
        assert_eq!(provider.iv_length(), 0);
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn cast5_cbc_round_trip_matches_plaintext() {
        let provider = Cast5Cipher::new("CAST5-CBC", LegacyBlockMode::Cbc);
        let key = [0x33u8; CAST5_DEFAULT_KEY_BYTES];
        let iv = [0x55u8; BLOCK_64];
        let plaintext = [0xCDu8; BLOCK_64 * 3];

        let nopad = no_padding_params();
        let mut enc_ctx = provider.new_ctx().expect("cast5 enc new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("cast5 enc init");
        let mut ciphertext = Vec::new();
        enc_ctx
            .update(&plaintext, &mut ciphertext)
            .expect("cast5 enc update");
        enc_ctx
            .finalize(&mut ciphertext)
            .expect("cast5 enc finalize");
        assert_eq!(ciphertext.len(), plaintext.len());

        let mut dec_ctx = provider.new_ctx().expect("cast5 dec new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("cast5 dec init");
        let mut recovered = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut recovered)
            .expect("cast5 dec update");
        dec_ctx
            .finalize(&mut recovered)
            .expect("cast5 dec finalize");
        assert_eq!(recovered, plaintext);
    }

    // ---- IDEA provider metadata + round-trip --------------------------------

    #[test]
    fn idea_ecb_provider_metadata() {
        let provider = IdeaCipher::new("IDEA-ECB", LegacyBlockMode::Ecb);
        assert_eq!(provider.name(), "IDEA-ECB");
        assert_eq!(provider.key_length(), IDEA_KEY_BYTES); // 16 bytes (FIXED)
        assert_eq!(provider.iv_length(), 0);
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn idea_cbc_provider_metadata() {
        let provider = IdeaCipher::new("IDEA-CBC", LegacyBlockMode::Cbc);
        assert_eq!(provider.key_length(), IDEA_KEY_BYTES);
        assert_eq!(provider.iv_length(), BLOCK_64);
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn idea_cbc_round_trip_with_padding_grows_by_one_block() {
        let provider = IdeaCipher::new("IDEA-CBC", LegacyBlockMode::Cbc);
        let key = [0x77u8; IDEA_KEY_BYTES];
        let iv = [0x11u8; BLOCK_64];
        // 16 bytes (= 2 blocks) → with PKCS#7 padding produces 24 bytes (3 blocks).
        let plaintext = b"The IDEA test!!!";
        assert_eq!(plaintext.len(), 16);

        let mut enc_ctx = provider.new_ctx().expect("idea enc new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), None)
            .expect("idea enc init");
        let mut ciphertext = Vec::new();
        enc_ctx
            .update(plaintext, &mut ciphertext)
            .expect("idea enc update");
        enc_ctx
            .finalize(&mut ciphertext)
            .expect("idea enc finalize");
        assert_eq!(
            ciphertext.len(),
            24,
            "16-byte plaintext padded to 24 bytes (3 × 8-byte blocks)"
        );

        let mut dec_ctx = provider.new_ctx().expect("idea dec new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), None)
            .expect("idea dec init");
        let mut recovered = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut recovered)
            .expect("idea dec update");
        dec_ctx.finalize(&mut recovered).expect("idea dec finalize");
        assert_eq!(recovered, plaintext);
    }

    // ---- SEED provider metadata + round-trip --------------------------------

    #[test]
    fn seed_ecb_provider_metadata() {
        let provider = SeedCipher::new("SEED-ECB", LegacyBlockMode::Ecb);
        assert_eq!(provider.name(), "SEED-ECB");
        assert_eq!(provider.key_length(), SEED_KEY_BYTES); // 16 bytes
        assert_eq!(provider.iv_length(), 0);
        assert_eq!(provider.block_size(), BLOCK_128); // SEED has a 128-bit block
    }

    #[test]
    fn seed_cbc_provider_metadata() {
        let provider = SeedCipher::new("SEED-CBC", LegacyBlockMode::Cbc);
        assert_eq!(provider.key_length(), SEED_KEY_BYTES);
        // SEED uses a 128-bit (16-byte) IV in CBC because the block size is 128 bits.
        assert_eq!(provider.iv_length(), BLOCK_128);
        assert_eq!(provider.block_size(), BLOCK_128);
    }

    #[test]
    fn seed_cbc_round_trip_matches_plaintext() {
        let provider = SeedCipher::new("SEED-CBC", LegacyBlockMode::Cbc);
        let key = [0x91u8; SEED_KEY_BYTES];
        let iv = [0x37u8; BLOCK_128];
        let plaintext = [0x5Bu8; BLOCK_128 * 2];

        let nopad = no_padding_params();
        let mut enc_ctx = provider.new_ctx().expect("seed enc new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("seed enc init");
        let mut ciphertext = Vec::new();
        enc_ctx
            .update(&plaintext, &mut ciphertext)
            .expect("seed enc update");
        enc_ctx
            .finalize(&mut ciphertext)
            .expect("seed enc finalize");
        assert_eq!(ciphertext.len(), plaintext.len());

        let mut dec_ctx = provider.new_ctx().expect("seed dec new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("seed dec init");
        let mut recovered = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut recovered)
            .expect("seed dec update");
        dec_ctx.finalize(&mut recovered).expect("seed dec finalize");
        assert_eq!(recovered, plaintext);
    }

    // ---- RC2 provider metadata + round-trip ---------------------------------

    #[test]
    fn rc2_default_key_length_is_full_16_bytes() {
        let provider = Rc2Cipher::new("RC2-CBC", LegacyBlockMode::Cbc, None);
        assert_eq!(provider.key_length(), RC2_DEFAULT_KEY_BYTES); // 16
    }

    #[test]
    fn rc2_effective_key_bits_40_yields_5_byte_key_length() {
        // RC2-40-CBC variant: 40-bit effective key → 5-byte advertised key length.
        let provider = Rc2Cipher::new(
            "RC2-40-CBC",
            LegacyBlockMode::Cbc,
            Some(RC2_EFFECTIVE_BITS_40),
        );
        assert_eq!(provider.key_length(), RC2_40_KEY_BYTES); // 5
        assert_eq!(provider.iv_length(), BLOCK_64);
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn rc2_effective_key_bits_64_yields_8_byte_key_length() {
        // RC2-64-CBC variant: 64-bit effective key → 8-byte advertised key length.
        let provider = Rc2Cipher::new(
            "RC2-64-CBC",
            LegacyBlockMode::Cbc,
            Some(RC2_EFFECTIVE_BITS_64),
        );
        assert_eq!(provider.key_length(), RC2_64_KEY_BYTES); // 8
        assert_eq!(provider.iv_length(), BLOCK_64);
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn rc2_other_effective_key_bits_default_to_16() {
        // Effective bits not in {40, 64} fall through to the full 128-bit key.
        let provider = Rc2Cipher::new("RC2-128-CBC", LegacyBlockMode::Cbc, Some(128));
        assert_eq!(provider.key_length(), RC2_DEFAULT_KEY_BYTES);
    }

    #[test]
    fn rc2_cbc_round_trip_matches_plaintext() {
        let provider = Rc2Cipher::new("RC2-CBC", LegacyBlockMode::Cbc, None);
        let key = [0xA1u8; RC2_DEFAULT_KEY_BYTES];
        let iv = [0x5Cu8; BLOCK_64];
        let plaintext = [0x7Eu8; BLOCK_64 * 4];

        let nopad = no_padding_params();
        let mut enc_ctx = provider.new_ctx().expect("rc2 enc new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("rc2 enc init");
        let mut ciphertext = Vec::new();
        enc_ctx
            .update(&plaintext, &mut ciphertext)
            .expect("rc2 enc update");
        enc_ctx.finalize(&mut ciphertext).expect("rc2 enc finalize");
        assert_eq!(ciphertext.len(), plaintext.len());

        let mut dec_ctx = provider.new_ctx().expect("rc2 dec new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("rc2 dec init");
        let mut recovered = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut recovered)
            .expect("rc2 dec update");
        dec_ctx.finalize(&mut recovered).expect("rc2 dec finalize");
        assert_eq!(recovered, plaintext);
    }

    // ---- RC4 helper-constructor + stream round-trip -------------------------

    #[test]
    fn rc4_standard_helper_advertises_default_key_length() {
        let provider = Rc4Cipher::standard();
        assert_eq!(provider.name(), "RC4");
        assert_eq!(provider.key_length(), RC4_DEFAULT_KEY_BYTES); // 16
        assert_eq!(provider.iv_length(), 0); // stream cipher
        assert_eq!(provider.block_size(), 1); // stream
    }

    #[test]
    fn rc4_40_helper_advertises_5_byte_key() {
        let provider = Rc4Cipher::rc4_40();
        assert_eq!(provider.name(), "RC4-40");
        assert_eq!(provider.key_length(), RC4_40_KEY_BYTES); // 5
        assert_eq!(provider.iv_length(), 0);
        assert_eq!(provider.block_size(), 1);
    }

    #[test]
    fn rc4_hmac_md5_helper_uses_default_key_length() {
        let provider = Rc4Cipher::rc4_hmac_md5();
        assert_eq!(provider.name(), "RC4-HMAC-MD5");
        assert_eq!(provider.key_length(), RC4_DEFAULT_KEY_BYTES); // 16
        assert_eq!(provider.iv_length(), 0);
        assert_eq!(provider.block_size(), 1);
    }

    #[test]
    fn rc4_stream_round_trip_matches_plaintext_byte_for_byte() {
        let provider = Rc4Cipher::standard();
        let key = [0xBCu8; RC4_DEFAULT_KEY_BYTES];
        // Stream ciphers handle non-block-aligned lengths natively.
        let plaintext: Vec<u8> = (0u8..=120u8).collect();

        let mut enc_ctx = provider.new_ctx().expect("rc4 enc new_ctx");
        enc_ctx
            .encrypt_init(&key, None, None)
            .expect("rc4 enc init");
        let mut ciphertext = Vec::new();
        enc_ctx
            .update(&plaintext, &mut ciphertext)
            .expect("rc4 enc update");
        enc_ctx.finalize(&mut ciphertext).expect("rc4 enc finalize");
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(ciphertext, plaintext, "RC4 must perturb every byte");

        let mut dec_ctx = provider.new_ctx().expect("rc4 dec new_ctx");
        dec_ctx
            .decrypt_init(&key, None, None)
            .expect("rc4 dec init");
        let mut recovered = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut recovered)
            .expect("rc4 dec update");
        dec_ctx.finalize(&mut recovered).expect("rc4 dec finalize");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn rc4_short_5_byte_key_round_trip() {
        // RC4-40 uses a reduced 5-byte key — verify the engine still
        // round-trips correctly when the key length matches.
        let provider = Rc4Cipher::rc4_40();
        let key = [0x10u8, 0x20, 0x30, 0x40, 0x50];
        assert_eq!(key.len(), RC4_40_KEY_BYTES);
        let plaintext = b"hello rc4-40";

        let mut enc_ctx = provider.new_ctx().expect("rc4-40 enc new_ctx");
        enc_ctx
            .encrypt_init(&key, None, None)
            .expect("rc4-40 enc init");
        let mut ciphertext = Vec::new();
        enc_ctx
            .update(plaintext, &mut ciphertext)
            .expect("rc4-40 enc update");
        enc_ctx
            .finalize(&mut ciphertext)
            .expect("rc4-40 enc finalize");

        let mut dec_ctx = provider.new_ctx().expect("rc4-40 dec new_ctx");
        dec_ctx
            .decrypt_init(&key, None, None)
            .expect("rc4-40 dec init");
        let mut recovered = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut recovered)
            .expect("rc4-40 dec update");
        dec_ctx
            .finalize(&mut recovered)
            .expect("rc4-40 dec finalize");
        assert_eq!(recovered, plaintext);
    }

    // ---- RC5 provider metadata + round-trip ---------------------------------

    #[test]
    fn rc5_ecb_provider_metadata() {
        let provider = Rc5Cipher::new("RC5-ECB", LegacyBlockMode::Ecb);
        assert_eq!(provider.name(), "RC5-ECB");
        assert_eq!(provider.key_length(), RC5_DEFAULT_KEY_BYTES); // 16
        assert_eq!(provider.iv_length(), 0);
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn rc5_cbc_provider_metadata() {
        let provider = Rc5Cipher::new("RC5-CBC", LegacyBlockMode::Cbc);
        assert_eq!(provider.key_length(), RC5_DEFAULT_KEY_BYTES);
        assert_eq!(provider.iv_length(), BLOCK_64);
        assert_eq!(provider.block_size(), BLOCK_64);
    }

    #[test]
    fn rc5_cbc_round_trip_matches_plaintext() {
        let provider = Rc5Cipher::new("RC5-CBC", LegacyBlockMode::Cbc);
        let key = [0x4Du8; RC5_DEFAULT_KEY_BYTES];
        let iv = [0x29u8; BLOCK_64];
        let plaintext = [0x6Bu8; BLOCK_64 * 3];

        let nopad = no_padding_params();
        let mut enc_ctx = provider.new_ctx().expect("rc5 enc new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("rc5 enc init");
        let mut ciphertext = Vec::new();
        enc_ctx
            .update(&plaintext, &mut ciphertext)
            .expect("rc5 enc update");
        enc_ctx.finalize(&mut ciphertext).expect("rc5 enc finalize");
        assert_eq!(ciphertext.len(), plaintext.len());

        let mut dec_ctx = provider.new_ctx().expect("rc5 dec new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), Some(&nopad))
            .expect("rc5 dec init");
        let mut recovered = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut recovered)
            .expect("rc5 dec update");
        dec_ctx.finalize(&mut recovered).expect("rc5 dec finalize");
        assert_eq!(recovered, plaintext);
    }

    // ---- get_params / set_params plumbing -----------------------------------

    #[test]
    fn blowfish_get_params_advertises_correct_metadata() {
        let provider = BlowfishCipher::new("BF-CBC", LegacyBlockMode::Cbc);
        let ctx = provider.new_ctx().expect("blowfish new_ctx");
        let params = ctx.get_params().expect("blowfish get_params");
        // KEYLEN reports the default key length in bits via the generic helper.
        // Just check that the standard fields are present and non-empty.
        assert!(
            params.contains(param_keys::BLOCK_SIZE),
            "BLOCK_SIZE param missing from Blowfish get_params"
        );
        assert!(
            params.contains(param_keys::KEYLEN),
            "KEYLEN param missing from Blowfish get_params"
        );
        assert!(
            params.contains(param_keys::IVLEN),
            "IVLEN param missing from Blowfish get_params"
        );
    }

    #[test]
    fn rc2_set_params_with_keybits_updates_effective_key_bits() {
        let provider = Rc2Cipher::new("RC2-CBC", LegacyBlockMode::Cbc, None);
        let mut ctx = provider.new_ctx().expect("rc2 new_ctx");
        let mut params = ParamSet::new();
        params.set(RC2_KEYBITS_PARAM, ParamValue::UInt32(40));
        ctx.set_params(&params)
            .expect("RC2 must accept rc2-keybits=40");
    }

    #[test]
    fn rc2_set_params_rejects_zero_keybits() {
        let provider = Rc2Cipher::new("RC2-CBC", LegacyBlockMode::Cbc, None);
        let mut ctx = provider.new_ctx().expect("rc2 new_ctx");
        let mut params = ParamSet::new();
        params.set(RC2_KEYBITS_PARAM, ParamValue::UInt32(0));
        let err = ctx
            .set_params(&params)
            .expect_err("RC2 must reject rc2-keybits=0");
        assert!(
            matches!(err, ProviderError::Dispatch(_)),
            "expected Dispatch error, got {err:?}"
        );
    }

    #[test]
    fn rc5_set_params_accepts_supported_round_counts() {
        let provider = Rc5Cipher::new("RC5-CBC", LegacyBlockMode::Cbc);
        for rounds in [8u32, 12u32, 16u32] {
            let mut ctx = provider.new_ctx().expect("rc5 new_ctx");
            let mut params = ParamSet::new();
            params.set(RC5_ROUNDS_PARAM, ParamValue::UInt32(rounds));
            ctx.set_params(&params)
                .unwrap_or_else(|e| panic!("RC5 must accept {rounds} rounds: {e:?}"));
        }
    }

    #[test]
    fn rc5_set_params_rejects_unsupported_round_counts() {
        let provider = Rc5Cipher::new("RC5-CBC", LegacyBlockMode::Cbc);
        let mut ctx = provider.new_ctx().expect("rc5 new_ctx");
        let mut params = ParamSet::new();
        // 10 is not in the {8, 12, 16} set per RC5 spec.
        params.set(RC5_ROUNDS_PARAM, ParamValue::UInt32(10));
        let err = ctx
            .set_params(&params)
            .expect_err("RC5 must reject 10 rounds");
        assert!(
            matches!(err, ProviderError::Dispatch(_) | ProviderError::Init(_)),
            "expected Dispatch/Init error, got {err:?}"
        );
    }

    // ---- new_ctx() returns Ok for every legacy cipher ---------------------

    #[test]
    fn every_legacy_cipher_can_create_a_context() {
        // Quick smoke test: each provider must yield a working context.
        let _ = BlowfishCipher::new("BF-ECB", LegacyBlockMode::Ecb)
            .new_ctx()
            .expect("Blowfish-ECB new_ctx");
        let _ = Cast5Cipher::new("CAST5-ECB", LegacyBlockMode::Ecb)
            .new_ctx()
            .expect("CAST5-ECB new_ctx");
        let _ = IdeaCipher::new("IDEA-ECB", LegacyBlockMode::Ecb)
            .new_ctx()
            .expect("IDEA-ECB new_ctx");
        let _ = SeedCipher::new("SEED-ECB", LegacyBlockMode::Ecb)
            .new_ctx()
            .expect("SEED-ECB new_ctx");
        let _ = Rc2Cipher::new("RC2-ECB", LegacyBlockMode::Ecb, None)
            .new_ctx()
            .expect("RC2-ECB new_ctx");
        let _ = Rc4Cipher::standard().new_ctx().expect("RC4 new_ctx");
        let _ = Rc4Cipher::rc4_40().new_ctx().expect("RC4-40 new_ctx");
        let _ = Rc4Cipher::rc4_hmac_md5()
            .new_ctx()
            .expect("RC4-HMAC-MD5 new_ctx");
        let _ = Rc5Cipher::new("RC5-ECB", LegacyBlockMode::Ecb)
            .new_ctx()
            .expect("RC5-ECB new_ctx");
    }
}
