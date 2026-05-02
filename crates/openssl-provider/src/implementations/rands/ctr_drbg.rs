//! CTR-DRBG (SP 800-90A §10.2) — Counter-mode Deterministic Random Bit Generator.
//!
//! Uses AES (128/192/256) in counter mode for output generation.
//! Supports optional Derivation Function (DF) via Block Cipher Chaining (BCC).
//!
//! ## Key Sizes
//! - AES-128-CTR-DRBG: keylen=16, seedlen=32
//! - AES-192-CTR-DRBG: keylen=24, seedlen=40
//! - AES-256-CTR-DRBG: keylen=32, seedlen=48
//!
//! ## Derivation Function
//! When enabled (`use_df=true`), seed material is processed through a
//! BCC-based derivation function (SP 800-90A §10.3.2) before seeding.
//!
//! Source: `providers/implementations/rands/drbg_ctr.c`

use super::drbg::{Drbg, DrbgConfig, DrbgMechanism, RandState};
use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use tracing::{debug, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES block size in bytes (128 bits).
const AES_BLOCK_LEN: usize = 16;

/// Maximum AES key length in bytes (AES-256).
const MAX_KEYLEN: usize = 32;

/// Maximum KX buffer length: 3 blocks × 16 bytes = 48.
/// Holds BCC output (2 blocks for AES-128, 3 for AES-192/256)
/// and DF chain output for seed material generation.
const MAX_KX_LEN: usize = 48;

/// Fixed derivation function key (SP 800-90A §10.3.2, step 8).
/// K = leftmost keylen bits of 0x00 0x01 0x02 ... 0x1f.
const DF_KEY: [u8; MAX_KEYLEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

/// Parse a cipher name (e.g. `"AES-256-CTR"`) and return the AES key length
/// in bytes (16, 24, or 32).
fn parse_cipher_keylen(name: &str) -> ProviderResult<usize> {
    let upper = name.to_uppercase();
    if upper.contains("256") {
        Ok(32)
    } else if upper.contains("192") {
        Ok(24)
    } else if upper.contains("128") {
        Ok(16)
    } else {
        Err(ProviderError::Init(format!(
            "unsupported CTR-DRBG cipher: '{name}'; expected AES-128, AES-192, or AES-256 variant",
        )))
    }
}

/// Increment a 128-bit big-endian counter in place (SP 800-90A §10.2).
///
/// Carries propagate from the least-significant byte (index 15) upward.
/// Overflow wraps around to zero.  Replaces C `inc_128()` from `drbg_ctr.c`.
fn inc_128(counter: &mut [u8]) {
    debug_assert!(counter.len() >= AES_BLOCK_LEN);
    let mut carry: u16 = 1;
    for byte in counter[..AES_BLOCK_LEN].iter_mut().rev() {
        carry += u16::from(*byte);
        // TRUNCATION: carry & 0xFF is always ≤ 255 — lossless u16→u8.
        *byte = (carry & 0xFF) as u8;
        carry >>= 8;
    }
}

/// Encrypt a single AES block using AES-ECB (single-block encryption).
///
/// Dispatches to `Aes128`, `Aes192`, or `Aes256` based on `keylen`.
/// This is a free function so that callers do not require a mutable
/// borrow on `CtrDrbg` while encrypting with keys stored in the struct.
fn aes_ecb_encrypt_block(
    keylen: usize,
    key: &[u8],
    input: &[u8; AES_BLOCK_LEN],
) -> ProviderResult<[u8; AES_BLOCK_LEN]> {
    let mut block = GenericArray::clone_from_slice(input);
    match keylen {
        16 => {
            let cipher = Aes128::new(GenericArray::from_slice(&key[..16]));
            cipher.encrypt_block(&mut block);
        }
        24 => {
            let cipher = Aes192::new(GenericArray::from_slice(&key[..24]));
            cipher.encrypt_block(&mut block);
        }
        32 => {
            let cipher = Aes256::new(GenericArray::from_slice(&key[..32]));
            cipher.encrypt_block(&mut block);
        }
        _ => {
            return Err(ProviderError::Init(format!(
                "unsupported AES key length: {keylen} bytes",
            )));
        }
    }
    let mut output = [0u8; AES_BLOCK_LEN];
    output.copy_from_slice(block.as_slice());
    Ok(output)
}

/// Block Cipher Chaining — BCC (SP 800-90A §10.3.3).
///
/// Processes `IV || data` through iterative AES-ECB encryption with `df_key`.
/// Returns one 16-byte chaining output block.
///
/// 1. `chaining = AES-ECB(df_key, 0 ⊕ IV) = AES-ECB(df_key, IV)`
/// 2. For each complete 16-byte block `B` of `data`:
///    `chaining = AES-ECB(df_key, chaining ⊕ B)`
///
/// Replaces C `ctr_BCC_init` + `ctr_BCC_block` + `ctr_BCC_blocks`.
fn bcc(
    keylen: usize,
    df_key: &[u8],
    iv: &[u8; AES_BLOCK_LEN],
    data: &[u8],
) -> ProviderResult<[u8; AES_BLOCK_LEN]> {
    // Step 1: encrypt IV (first BCC data block is IV, chaining starts at 0)
    let mut chaining = aes_ecb_encrypt_block(keylen, df_key, iv)?;

    // Pad data to block boundary (zero-pad)
    let padded_len = if data.is_empty() {
        0
    } else {
        ((data.len() + AES_BLOCK_LEN - 1) / AES_BLOCK_LEN) * AES_BLOCK_LEN
    };

    // Step 2: process each complete block
    let mut pos = 0;
    while pos < padded_len {
        let end = (pos + AES_BLOCK_LEN).min(data.len());
        // XOR data bytes into chaining; bytes beyond data.len() are zero
        for i in 0..AES_BLOCK_LEN {
            if pos + i < end {
                chaining[i] ^= data[pos + i];
            }
            // else: XOR with 0 (implicit zero-pad) — no-op
        }
        chaining = aes_ecb_encrypt_block(keylen, df_key, &chaining)?;
        pos += AES_BLOCK_LEN;
    }

    trace!("BCC complete, output {} bytes", AES_BLOCK_LEN);
    Ok(chaining)
}

// ---------------------------------------------------------------------------
// CtrDrbg — CTR-DRBG mechanism state
// ---------------------------------------------------------------------------

/// CTR-DRBG mechanism state (SP 800-90A §10.2).
///
/// Uses AES in counter mode.  The DRBG state consists of Key (`K`) and
/// Value (`V`, a 128-bit counter).  Output is generated by encrypting
/// incrementing counter values with the current key.
///
/// All key material fields derive `Zeroize` and `ZeroizeOnDrop` so that
/// `K`, `V`, `kx`, and `bltmp` are securely wiped from memory on drop and
/// on [`DrbgMechanism::uninstantiate`].
///
/// Replaces C `PROV_DRBG_CTR` (aka `rand_drbg_ctr_st`) from `drbg_ctr.c`.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct CtrDrbg {
    /// AES key length in bytes (16, 24, or 32).
    keylen: usize,
    /// Whether the Derivation Function is enabled.
    use_df: bool,
    /// Current AES key — up to 32 bytes for AES-256.
    k: Vec<u8>,
    /// Current 128-bit counter value (V).
    v: Vec<u8>,
    /// Block-sized scratch buffer used by the DF (16 bytes).
    bltmp: Vec<u8>,
    /// Current write position in `bltmp` for partial block handling.
    bltmp_pos: usize,
    /// Working buffer for BCC / DF output (up to 48 bytes).
    /// Retained between `ctr_update` calls so that the generate
    /// post-update can *reuse* the DF result without re-computing
    /// (matches C `ctr->KX` reuse semantics in `drbg_ctr_generate`).
    kx: Vec<u8>,
    /// Cipher name string (e.g. `"AES-256-CTR"`).
    cipher_name: String,
    /// Tracks whether the mechanism has been instantiated (mirrors [`RandState`]
    /// at the mechanism level for parameter query support).
    instantiated: bool,
}

// ---------------------------------------------------------------------------
// CtrDrbg — construction and accessors
// ---------------------------------------------------------------------------

impl CtrDrbg {
    /// Create a new CTR-DRBG mechanism for the given cipher and DF mode.
    ///
    /// # Arguments
    /// * `cipher_name` — AES cipher variant, e.g. `"AES-256-CTR"`.
    /// * `use_df` — enable the Block Cipher Derivation Function.
    ///
    /// # Errors
    /// Returns [`ProviderError::Init`] if the cipher name does not contain
    /// a recognised AES key size (128, 192, or 256).
    pub fn new(cipher_name: &str, use_df: bool) -> ProviderResult<Self> {
        let keylen = parse_cipher_keylen(cipher_name)?;
        debug!(
            cipher = cipher_name,
            keylen,
            use_df,
            seedlen = keylen + AES_BLOCK_LEN,
            "CTR-DRBG: creating new mechanism"
        );
        Ok(Self {
            keylen,
            use_df,
            k: vec![0u8; keylen],
            v: vec![0u8; AES_BLOCK_LEN],
            bltmp: vec![0u8; AES_BLOCK_LEN],
            bltmp_pos: 0,
            kx: vec![0u8; MAX_KX_LEN],
            cipher_name: cipher_name.to_string(),
            instantiated: false,
        })
    }

    /// AES key length in bytes (16, 24, or 32).
    #[inline]
    pub fn keylen(&self) -> usize {
        self.keylen
    }

    /// Whether the derivation function is enabled.
    #[inline]
    pub fn use_df(&self) -> bool {
        self.use_df
    }

    /// Seed length in bytes: `keylen + AES_BLOCK_LEN`.
    #[inline]
    pub fn seedlen(&self) -> usize {
        self.keylen + AES_BLOCK_LEN
    }

    // -----------------------------------------------------------------
    // Parameter query — replaces C drbg_ctr_get_ctx_params / set_ctx_params
    // -----------------------------------------------------------------

    /// Return a `ParamSet` describing the current CTR-DRBG configuration.
    ///
    /// Reports: cipher name, key length, seed length, `use_df` flag, strength,
    /// and the mechanism state (via [`RandState`]).
    ///
    /// Replaces C `drbg_ctr_get_ctx_params()`.
    pub fn get_ctx_params(&self) -> ParamSet {
        let mut params = ParamSet::new();
        params.set("cipher", ParamValue::Utf8String(self.cipher_name.clone()));
        // Rule R6: use saturating conversions instead of bare `as` casts.
        let keylen_u32 = u32::try_from(self.keylen).unwrap_or(u32::MAX);
        let seedlen_u32 = u32::try_from(self.seedlen()).unwrap_or(u32::MAX);
        let strength_u32 = u32::try_from(self.keylen.saturating_mul(8)).unwrap_or(u32::MAX);
        params.set("keylen", ParamValue::UInt32(keylen_u32));
        params.set("seedlen", ParamValue::UInt32(seedlen_u32));
        params.set("use_df", ParamValue::Int32(i32::from(self.use_df)));
        params.set("strength", ParamValue::UInt32(strength_u32));
        let state = if self.instantiated {
            RandState::Ready
        } else {
            RandState::Uninitialised
        };
        params.set("state", ParamValue::Utf8String(format!("{state:?}")));
        params
    }

    /// Apply configuration parameters from a `ParamSet`.
    ///
    /// Supports setting the cipher name (which derives keylen, seedlen,
    /// strength) and the `use_df` flag.  Must be called *before* instantiate.
    ///
    /// Uses [`ParamSet::get_typed`] for type-safe parameter extraction
    /// (returns [`ProviderError::Common`] on type mismatch).
    ///
    /// Replaces C `drbg_ctr_set_ctx_params_locked()`.
    pub fn set_ctx_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Cipher name — use get_typed for type-safe String extraction.
        if params.contains("cipher") {
            let name: String = params.get_typed("cipher").map_err(ProviderError::Common)?;
            let new_keylen = parse_cipher_keylen(&name)?;
            self.keylen = new_keylen;
            self.cipher_name.clone_from(&name);
            // Resize K buffer to new keylen.
            self.k.resize(new_keylen, 0);
            self.k.fill(0);
            trace!(cipher = %name, keylen = new_keylen, "CTR-DRBG: cipher updated");
        }
        // use_df flag — use get_typed for type-safe bool extraction.
        if params.contains("use_df") {
            // Accept as i32 via get() (C convention: 0/1 integer flag).
            if let Some(val) = params.get("use_df") {
                if let Some(flag) = val.as_i32() {
                    self.use_df = flag != 0;
                    trace!(use_df = self.use_df, "CTR-DRBG: use_df updated");
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// XOR `data` into `K` (first `keylen` bytes) then `V` (remaining).
    ///
    /// Replaces C `ctr_XOR()`.  Any zero-padding of `data` beyond its
    /// length has no effect since XOR with zero is identity.
    fn xor_into_kv(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let n = data.len().min(self.keylen);
        for (k_byte, d_byte) in self.k[..n].iter_mut().zip(data[..n].iter()) {
            *k_byte ^= d_byte;
        }
        if data.len() > self.keylen {
            let remaining = &data[self.keylen..];
            let m = remaining.len().min(AES_BLOCK_LEN);
            for (v_byte, r_byte) in self.v[..m].iter_mut().zip(remaining[..m].iter()) {
                *v_byte ^= r_byte;
            }
        }
    }

    /// CTR Derivation Function (SP 800-90A §10.3.2).
    ///
    /// Processes one or more input slices through parallel BCC chains,
    /// then generates `seedlen` bytes of derived seed material.
    ///
    /// # Algorithm
    /// 1. S = L(4 bytes) || N(4 bytes) || `input_data` || 0x80 || zero-pad
    /// 2. For each BCC chain *i*: `kx_block[i] = BCC(df_key, IV_i, S)`
    /// 3. K' = kx[0..keylen],  X = kx[keylen..keylen+16]
    /// 4. Iteratively encrypt X with K' to produce `seedlen` output bytes
    ///
    /// Replaces C `ctr_df()` from `drbg_ctr.c`.
    fn ctr_df(&self, inputs: &[&[u8]]) -> ProviderResult<Vec<u8>> {
        let seedlen = self.seedlen();
        let num_chains = (seedlen + AES_BLOCK_LEN - 1) / AES_BLOCK_LEN;
        let df_key = &DF_KEY[..self.keylen];

        // Total input length (across all slices).
        let total_input_len: usize = inputs.iter().map(|s| s.len()).sum();

        // Build S = L(4) || N(4) || input_data || 0x80 || zero-pad-to-block
        let header_plus_data_len = 8 + total_input_len + 1; // +1 for 0x80
        let padded_s_len =
            ((header_plus_data_len + AES_BLOCK_LEN - 1) / AES_BLOCK_LEN) * AES_BLOCK_LEN;

        let mut s_buf = vec![0u8; padded_s_len];

        // L = total_input_len as big-endian u32 (Rule R6: use to_be_bytes).
        let l_bytes = u32::try_from(total_input_len)
            .unwrap_or(u32::MAX)
            .to_be_bytes();
        s_buf[0..4].copy_from_slice(&l_bytes);

        // N = seedlen as big-endian u32 (Rule R6: use to_be_bytes).
        let n_bytes = u32::try_from(seedlen).unwrap_or(u32::MAX).to_be_bytes();
        s_buf[4..8].copy_from_slice(&n_bytes);

        // Concatenate input slices
        let mut pos = 8usize;
        for input in inputs {
            if !input.is_empty() {
                s_buf[pos..pos + input.len()].copy_from_slice(input);
                pos += input.len();
            }
        }
        // 0x80 separator byte
        s_buf[pos] = 0x80;
        // Remaining bytes are already zero from vec initialization

        trace!(
            total_input_len,
            seedlen,
            num_chains,
            padded_s_len,
            "CTR-DRBG DF: processing input"
        );

        // Run one BCC chain per output block.
        // Chain i uses IV = big-endian 32-bit counter i, zero-padded to 16 bytes.
        let mut kx_buf = vec![0u8; num_chains * AES_BLOCK_LEN];
        for i in 0..num_chains {
            let mut iv = [0u8; AES_BLOCK_LEN];
            // Big-endian 32-bit counter at bytes 0..3 of IV block.
            // Rule R6: chain index always 0..3, use try_from.
            let i_bytes = u32::try_from(i).unwrap_or(0).to_be_bytes();
            iv[0..4].copy_from_slice(&i_bytes);
            let chain_out = bcc(self.keylen, df_key, &iv, &s_buf)?;
            kx_buf[i * AES_BLOCK_LEN..(i + 1) * AES_BLOCK_LEN].copy_from_slice(&chain_out);
        }

        // Split BCC output: K' = kx[0..keylen], X = kx[keylen..keylen+16]
        let k_prime = &kx_buf[..self.keylen];
        let mut x = [0u8; AES_BLOCK_LEN];
        x.copy_from_slice(&kx_buf[self.keylen..self.keylen + AES_BLOCK_LEN]);

        // Generate seedlen output bytes by iteratively encrypting X with K'.
        let mut output = vec![0u8; num_chains * AES_BLOCK_LEN];
        for i in 0..num_chains {
            x = aes_ecb_encrypt_block(self.keylen, k_prime, &x)?;
            output[i * AES_BLOCK_LEN..(i + 1) * AES_BLOCK_LEN].copy_from_slice(&x);
        }
        output.truncate(seedlen);

        trace!(output_len = output.len(), "CTR-DRBG DF: complete");
        Ok(output)
    }

    // -----------------------------------------------------------------
    // CTR_DRBG_Update variants (SP 800-90A §10.2.1.2)
    // -----------------------------------------------------------------

    /// Core update step: generate `seedlen` bytes via AES-ECB encryption
    /// of the current and incrementing V values, then set new K and V.
    ///
    /// Matches C `ctr_update()` lines 278-298 (ECB encrypt phase only).
    fn update_core(&mut self) -> ProviderResult<()> {
        let seedlen = self.seedlen();
        let num_blocks = (seedlen + AES_BLOCK_LEN - 1) / AES_BLOCK_LEN;

        // Snapshot the current key for encryption (avoids borrow conflict).
        let key = self.k[..self.keylen].to_vec();
        let mut temp = vec![0u8; num_blocks * AES_BLOCK_LEN];

        // First block: encrypt current V (caller already incremented V).
        let mut v_arr = [0u8; AES_BLOCK_LEN];
        v_arr.copy_from_slice(&self.v);
        let block = aes_ecb_encrypt_block(self.keylen, &key, &v_arr)?;
        temp[..AES_BLOCK_LEN].copy_from_slice(&block);

        // Subsequent blocks: increment V, then encrypt.
        for i in 1..num_blocks {
            inc_128(&mut self.v);
            v_arr.copy_from_slice(&self.v);
            let blk = aes_ecb_encrypt_block(self.keylen, &key, &v_arr)?;
            let start = i * AES_BLOCK_LEN;
            temp[start..start + AES_BLOCK_LEN].copy_from_slice(&blk);
        }

        // Set new K and V from the encrypted output.
        self.k[..self.keylen].copy_from_slice(&temp[..self.keylen]);
        self.v.copy_from_slice(&temp[self.keylen..seedlen]);
        Ok(())
    }

    /// Full update with Derivation Function: compute DF, store result in
    /// `kx`, and XOR into K||V.
    fn update_with_df(&mut self, inputs: &[&[u8]]) -> ProviderResult<()> {
        self.update_core()?;
        let kx = self.ctr_df(inputs)?;
        let seedlen = self.seedlen();
        self.kx[..seedlen].copy_from_slice(&kx[..seedlen]);
        let kx_clone = kx;
        self.xor_into_kv(&kx_clone);
        Ok(())
    }

    /// Full update reusing the previously computed DF result stored in `kx`.
    /// This matches the C generate post-update "reuse" path where
    /// `adin=NULL, adinlen=1` causes `ctr_XOR(ctr->KX, seedlen)` without
    /// re-running `ctr_df`.
    fn update_reuse_kx(&mut self) -> ProviderResult<()> {
        self.update_core()?;
        let seedlen = self.seedlen();
        let kx = self.kx[..seedlen].to_vec();
        self.xor_into_kv(&kx);
        Ok(())
    }

    /// Full update without Derivation Function: XOR each input directly
    /// into K||V.
    fn update_no_df(&mut self, inputs: &[&[u8]]) -> ProviderResult<()> {
        self.update_core()?;
        for input in inputs {
            self.xor_into_kv(input);
        }
        Ok(())
    }

    /// Full update with no input material: only the ECB-based K/V
    /// generation (no XOR).
    fn update_no_input(&mut self) -> ProviderResult<()> {
        self.update_core()
    }
}

// ---------------------------------------------------------------------------
// DrbgMechanism trait implementation
// ---------------------------------------------------------------------------

impl DrbgMechanism for CtrDrbg {
    /// CTR-DRBG Instantiate (SP 800-90A §10.2.1.3).
    ///
    /// 1. K = 0,  V = 0
    /// 2. V = V + 1
    /// 3. If DF: seed = `ctr_df`(entropy || nonce || personalization),
    ///    `ctr_update`(seed)
    /// 4. If no-DF: `ctr_update` then XOR entropy and personalization directly.
    fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> ProviderResult<()> {
        debug!(
            keylen = self.keylen,
            use_df = self.use_df,
            entropy_len = entropy.len(),
            nonce_len = nonce.len(),
            pers_len = personalization.len(),
            "CTR-DRBG: instantiate"
        );

        // Zero K and V.
        self.k.iter_mut().for_each(|b| *b = 0);
        self.v.iter_mut().for_each(|b| *b = 0);

        // Increment V (C: inc_128 before ctr_update).
        inc_128(&mut self.v);

        if self.use_df {
            // DF mode: entropy || nonce || personalization through DF, then update.
            self.update_with_df(&[entropy, nonce, personalization])?;
        } else {
            // No-DF mode: XOR entropy and personalization directly.
            self.update_no_df(&[entropy, personalization])?;
        }

        self.instantiated = true;
        Ok(())
    }

    /// CTR-DRBG Reseed (SP 800-90A §10.2.1.4).
    ///
    /// 1. V = V + 1
    /// 2. If DF: seed = `ctr_df`(entropy || additional), `ctr_update`(seed)
    /// 3. If no-DF: `ctr_update` then XOR entropy and additional directly.
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> ProviderResult<()> {
        debug!(
            entropy_len = entropy.len(),
            adin_len = additional.len(),
            "CTR-DRBG: reseed"
        );

        inc_128(&mut self.v);

        if self.use_df {
            self.update_with_df(&[entropy, additional])?;
        } else {
            self.update_no_df(&[entropy, additional])?;
        }

        Ok(())
    }

    /// CTR-DRBG Generate (SP 800-90A §10.2.1.5.2).
    ///
    /// 1. If additional input: pre-generate `ctr_update` with additional
    /// 2. Increment V
    /// 3. For each output block: encrypt V, output block, increment V
    /// 4. Post-generate `ctr_update` (reusing DF result if applicable)
    fn generate(&mut self, output: &mut [u8], additional: &[u8]) -> ProviderResult<()> {
        let has_adin = !additional.is_empty();

        trace!(
            output_len = output.len(),
            adin_len = additional.len(),
            "CTR-DRBG: generate"
        );

        // --- Pre-generate: process additional input ---
        if has_adin {
            inc_128(&mut self.v);
            if self.use_df {
                self.update_with_df(&[additional])?;
            } else {
                self.update_no_df(&[additional])?;
            }
        }

        // Main increment before output generation.
        inc_128(&mut self.v);

        // Handle empty output (special case from C: extra inc + update).
        if output.is_empty() {
            inc_128(&mut self.v);
            return self.post_generate_update(has_adin, additional);
        }

        // --- Output generation loop ---
        // Snapshot the key so the borrow checker is satisfied.
        let key_snapshot = self.k[..self.keylen].to_vec();

        for chunk in output.chunks_mut(AES_BLOCK_LEN) {
            let mut v_arr = [0u8; AES_BLOCK_LEN];
            v_arr.copy_from_slice(&self.v);
            let block = aes_ecb_encrypt_block(self.keylen, &key_snapshot, &v_arr)?;
            chunk.copy_from_slice(&block[..chunk.len()]);
            inc_128(&mut self.v);
        }

        // --- Post-generate update ---
        self.post_generate_update(has_adin, additional)
    }

    /// Zero all internal state (K, V, bltmp, KX, `bltmp_pos`).
    ///
    /// Replaces C `drbg_ctr_uninstantiate()` which calls `OPENSSL_cleanse`.
    fn uninstantiate(&mut self) {
        debug!("CTR-DRBG: uninstantiate — zeroing state");
        self.k.zeroize();
        self.v.zeroize();
        self.bltmp.zeroize();
        self.kx.zeroize();
        self.bltmp_pos = 0;
        self.instantiated = false;
    }

    /// Verify all key material fields are zero (FIPS zeroization check).
    ///
    /// Replaces C `drbg_ctr_verify_zeroization()`.  Returns `true` only
    /// when K, V, bltmp, KX are all-zero and `bltmp_pos` is 0.
    fn verify_zeroization(&self) -> bool {
        let k_zero = self.k.iter().all(|&b| b == 0);
        let v_zero = self.v.iter().all(|&b| b == 0);
        let bltmp_zero = self.bltmp.iter().all(|&b| b == 0);
        let kx_zero = self.kx.iter().all(|&b| b == 0);
        let pos_zero = self.bltmp_pos == 0;
        k_zero && v_zero && bltmp_zero && kx_zero && pos_zero
    }
}

/// Private helper factored out of `generate` to keep the borrow-checker
/// happy (the `additional` slice is re-borrowed after the output loop).
impl CtrDrbg {
    fn post_generate_update(&mut self, has_adin: bool, additional: &[u8]) -> ProviderResult<()> {
        if has_adin && self.use_df {
            // Reuse the DF result stored in kx (C: adin=NULL, adinlen=1 path).
            self.update_reuse_kx()
        } else if has_adin {
            // No-DF: XOR additional directly in post-update.
            self.update_no_df(&[additional])
        } else {
            // No additional input: plain core update (no XOR).
            self.update_no_input()
        }
    }
}

// ---------------------------------------------------------------------------
// CtrDrbgProvider — RandProvider factory
// ---------------------------------------------------------------------------

/// Provider factory for CTR-DRBG instances.
///
/// Implements `RandProvider` to register CTR-DRBG as a RAND algorithm
/// in the provider dispatch table.  The default configuration creates an
/// AES-256-CTR-DRBG with the Derivation Function enabled.
///
/// Replaces C `drbg_ctr_new_wrapper()` / `ossl_drbg_ctr_functions[]`.
pub struct CtrDrbgProvider;

impl RandProvider for CtrDrbgProvider {
    /// Algorithm name reported to the provider system.
    fn name(&self) -> &'static str {
        "CTR-DRBG"
    }

    /// Create a new CTR-DRBG context wrapped in a [`Drbg`] state machine.
    ///
    /// Default: AES-256 with DF enabled, matching C `drbg_ctr_new()`
    /// which sets `use_df = 1` and relies on `drbg_ctr_init()` to
    /// derive strength/seedlen from the cipher.
    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        let mechanism = CtrDrbg::new("AES-256-CTR", true)?;
        // Align config with AES-256: strength=256, seedlen=48.
        // The Drbg wrapper uses config for entropy/nonce bounds.
        let config = DrbgConfig {
            strength: 256,
            min_entropylen: 32, // keylen for AES-256
            min_noncelen: 16,   // keylen / 2
            ..DrbgConfig::default()
        };
        let drbg = Drbg::new(Box::new(mechanism), config);
        Ok(Box::new(drbg))
    }
}

// ---------------------------------------------------------------------------
// Unit-level helpers exposed for testing (cfg(test) only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cipher_keylen() {
        assert_eq!(parse_cipher_keylen("AES-128-CTR").unwrap(), 16);
        assert_eq!(parse_cipher_keylen("AES-192-CTR").unwrap(), 24);
        assert_eq!(parse_cipher_keylen("AES-256-CTR").unwrap(), 32);
        assert_eq!(parse_cipher_keylen("aes-256-ctr").unwrap(), 32);
        assert!(parse_cipher_keylen("CHACHA20").is_err());
    }

    #[test]
    fn test_inc_128_basic() {
        let mut counter = [0u8; 16];
        inc_128(&mut counter);
        assert_eq!(counter[15], 1);
        inc_128(&mut counter);
        assert_eq!(counter[15], 2);
    }

    #[test]
    fn test_inc_128_carry() {
        let mut counter = [0u8; 16];
        counter[15] = 0xff;
        inc_128(&mut counter);
        assert_eq!(counter[14], 1);
        assert_eq!(counter[15], 0);
    }

    #[test]
    fn test_inc_128_overflow() {
        let mut counter = [0xffu8; 16];
        inc_128(&mut counter);
        // Full overflow wraps to zero
        assert!(counter.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_aes_ecb_encrypt_deterministic() {
        // AES-128 encrypt all-zero block with all-zero key — known result.
        let key = [0u8; 16];
        let input = [0u8; 16];
        let result = aes_ecb_encrypt_block(16, &key, &input).unwrap();
        // AES-128(key=0, pt=0) is a well-known constant
        assert_ne!(result, [0u8; 16], "AES should not map zeros to zeros");

        // Same inputs must produce same output (deterministic).
        let result2 = aes_ecb_encrypt_block(16, &key, &input).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_ctr_drbg_new() {
        let drbg = CtrDrbg::new("AES-256-CTR", true).unwrap();
        assert_eq!(drbg.keylen(), 32);
        assert_eq!(drbg.seedlen(), 48);
        assert!(drbg.use_df());
    }

    #[test]
    fn test_ctr_drbg_instantiate_zeroize() {
        let mut drbg = CtrDrbg::new("AES-128-CTR", true).unwrap();
        let entropy = [0x42u8; 16];
        let nonce = [0x13u8; 8];
        let pers = [];

        drbg.instantiate(&entropy, &nonce, &pers).unwrap();

        // After instantiate, K and V should NOT be all-zero.
        assert!(
            !drbg.k.iter().all(|&b| b == 0) || !drbg.v.iter().all(|&b| b == 0),
            "K or V should be non-zero after instantiate"
        );

        // Uninstantiate should zero everything.
        drbg.uninstantiate();
        assert!(drbg.verify_zeroization(), "state should be zeroed");
    }

    #[test]
    fn test_ctr_drbg_generate_output() {
        let mut drbg = CtrDrbg::new("AES-256-CTR", true).unwrap();
        let entropy = [0xab; 32];
        let nonce = [0xcd; 16];
        drbg.instantiate(&entropy, &nonce, &[]).unwrap();

        let mut out = [0u8; 64];
        drbg.generate(&mut out, &[]).unwrap();

        // Output should not be all-zeros after generation.
        assert!(
            !out.iter().all(|&b| b == 0),
            "generated output should be non-zero"
        );
    }

    #[test]
    fn test_ctr_drbg_generate_deterministic() {
        // Same seed → same output.
        let entropy = [0x01u8; 32];
        let nonce = [0x02u8; 16];

        let mut drbg1 = CtrDrbg::new("AES-256-CTR", true).unwrap();
        drbg1.instantiate(&entropy, &nonce, &[]).unwrap();
        let mut out1 = [0u8; 32];
        drbg1.generate(&mut out1, &[]).unwrap();

        let mut drbg2 = CtrDrbg::new("AES-256-CTR", true).unwrap();
        drbg2.instantiate(&entropy, &nonce, &[]).unwrap();
        let mut out2 = [0u8; 32];
        drbg2.generate(&mut out2, &[]).unwrap();

        assert_eq!(out1, out2, "same seed must produce same output");
    }

    #[test]
    fn test_ctr_drbg_reseed_changes_output() {
        let entropy = [0x11u8; 32];
        let nonce = [0x22u8; 16];

        let mut drbg = CtrDrbg::new("AES-256-CTR", true).unwrap();
        drbg.instantiate(&entropy, &nonce, &[]).unwrap();

        let mut out_before = [0u8; 32];
        drbg.generate(&mut out_before, &[]).unwrap();

        drbg.reseed(&[0xffu8; 32], &[]).unwrap();

        let mut out_after = [0u8; 32];
        drbg.generate(&mut out_after, &[]).unwrap();

        assert_ne!(
            out_before, out_after,
            "reseed should change subsequent output"
        );
    }

    #[test]
    fn test_ctr_drbg_additional_input() {
        let entropy = [0x33u8; 32];
        let nonce = [0x44u8; 16];

        let mut drbg1 = CtrDrbg::new("AES-256-CTR", true).unwrap();
        drbg1.instantiate(&entropy, &nonce, &[]).unwrap();
        let mut out1 = [0u8; 32];
        drbg1.generate(&mut out1, &[0xaa; 16]).unwrap();

        let mut drbg2 = CtrDrbg::new("AES-256-CTR", true).unwrap();
        drbg2.instantiate(&entropy, &nonce, &[]).unwrap();
        let mut out2 = [0u8; 32];
        drbg2.generate(&mut out2, &[]).unwrap();

        assert_ne!(out1, out2, "additional input should change output");
    }

    #[test]
    fn test_ctr_drbg_no_df_mode() {
        let mut drbg = CtrDrbg::new("AES-256-CTR", false).unwrap();
        // No-DF: entropy must be exactly seedlen (48) bytes.
        let entropy = [0x55u8; 48];
        let nonce = [];
        drbg.instantiate(&entropy, &nonce, &[]).unwrap();

        let mut out = [0u8; 32];
        drbg.generate(&mut out, &[]).unwrap();

        assert!(
            !out.iter().all(|&b| b == 0),
            "no-DF mode should produce non-zero output"
        );
    }

    #[test]
    fn test_ctr_drbg_aes128() {
        let mut drbg = CtrDrbg::new("AES-128-CTR", true).unwrap();
        assert_eq!(drbg.keylen(), 16);
        assert_eq!(drbg.seedlen(), 32);

        let entropy = [0x77u8; 16];
        let nonce = [0x88u8; 8];
        drbg.instantiate(&entropy, &nonce, &[]).unwrap();

        let mut out = [0u8; 16];
        drbg.generate(&mut out, &[]).unwrap();
        assert!(!out.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ctr_drbg_provider() {
        let provider = CtrDrbgProvider;
        assert_eq!(provider.name(), "CTR-DRBG");
        let _ctx = provider.new_ctx().expect("new_ctx should succeed");
    }

    #[test]
    fn test_bcc_deterministic() {
        let key = &DF_KEY[..16]; // AES-128 DF key
        let iv = [0u8; 16];
        let data = [0x42u8; 32]; // Two blocks of data

        let r1 = bcc(16, key, &iv, &data).unwrap();
        let r2 = bcc(16, key, &iv, &data).unwrap();
        assert_eq!(r1, r2, "BCC must be deterministic");
        assert_ne!(r1, [0u8; 16], "BCC output should not be all-zero");
    }

    #[test]
    fn test_verify_zeroization_initially_true() {
        let drbg = CtrDrbg::new("AES-256-CTR", true).unwrap();
        // All fields start as zero.
        assert!(drbg.verify_zeroization());
    }

    #[test]
    fn test_get_ctx_params() {
        let drbg = CtrDrbg::new("AES-256-CTR", true).unwrap();
        let params = drbg.get_ctx_params();
        // Verify cipher name
        let cipher: String = params.get_typed("cipher").unwrap();
        assert_eq!(cipher, "AES-256-CTR");
        // Verify keylen
        let keylen: u32 = params.get_typed("keylen").unwrap();
        assert_eq!(keylen, 32);
        // Verify seedlen
        let seedlen: u32 = params.get_typed("seedlen").unwrap();
        assert_eq!(seedlen, 48);
        // Verify strength
        let strength: u32 = params.get_typed("strength").unwrap();
        assert_eq!(strength, 256);
        // Verify state (uninitialised before instantiate)
        let state: String = params.get_typed("state").unwrap();
        assert!(state.contains("Uninitialised"));
    }

    #[test]
    fn test_get_ctx_params_after_instantiate() {
        let mut drbg = CtrDrbg::new("AES-128-CTR", true).unwrap();
        drbg.instantiate(&[0x42u8; 16], &[0x13u8; 8], &[]).unwrap();
        let params = drbg.get_ctx_params();
        let state: String = params.get_typed("state").unwrap();
        assert!(state.contains("Ready"));
    }

    #[test]
    fn test_set_ctx_params_cipher() {
        let mut drbg = CtrDrbg::new("AES-128-CTR", true).unwrap();
        assert_eq!(drbg.keylen(), 16);

        let mut params = ParamSet::new();
        params.set("cipher", ParamValue::Utf8String("AES-256-CTR".to_string()));
        drbg.set_ctx_params(&params).unwrap();

        assert_eq!(drbg.keylen(), 32);
        assert_eq!(drbg.seedlen(), 48);
    }

    #[test]
    fn test_set_ctx_params_use_df() {
        let mut drbg = CtrDrbg::new("AES-256-CTR", true).unwrap();
        assert!(drbg.use_df());

        let mut params = ParamSet::new();
        params.set("use_df", ParamValue::Int32(0));
        drbg.set_ctx_params(&params).unwrap();
        assert!(!drbg.use_df());
    }

    #[test]
    fn test_set_ctx_params_invalid_cipher() {
        let mut drbg = CtrDrbg::new("AES-256-CTR", true).unwrap();
        let mut params = ParamSet::new();
        params.set("cipher", ParamValue::Utf8String("CHACHA20".to_string()));
        assert!(drbg.set_ctx_params(&params).is_err());
    }

    #[test]
    fn test_instantiated_flag_lifecycle() {
        let mut drbg = CtrDrbg::new("AES-256-CTR", true).unwrap();
        assert!(!drbg.instantiated);

        drbg.instantiate(&[0xab; 32], &[0xcd; 16], &[]).unwrap();
        assert!(drbg.instantiated);

        drbg.uninstantiate();
        assert!(!drbg.instantiated);
    }
}
