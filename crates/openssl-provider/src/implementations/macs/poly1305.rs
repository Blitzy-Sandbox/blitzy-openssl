//! Poly1305 one-time MAC provider implementation.
//!
//! Pure Rust implementation of the Poly1305 message authentication code
//! (Bernstein, 2005), typically used as the MAC component in the
//! ChaCha20-Poly1305 AEAD construction (RFC 8439). The implementation
//! translates C `providers/implementations/macs/poly1305_prov.c` (provider
//! dispatch layer) and `crypto/poly1305/poly1305.c` (core algorithm) to
//! idiomatic Rust with zero `unsafe` code.
//!
//! # Algorithm overview
//!
//! Poly1305 evaluates a polynomial over GF(2¹³⁰ − 5) keyed by a secret
//! value. The 32-byte key is split into:
//!
//! - **r** (bytes 0..16): the polynomial evaluation point, with certain
//!   bits cleared ("clamped") for efficient reduction.
//! - **s** (bytes 16..32): a one-time nonce added after the polynomial
//!   evaluation to produce the final 16-byte (128-bit) tag.
//!
//! Input is processed in 16-byte blocks; each block is interpreted as a
//! little-endian 128-bit integer with a high bit appended (bit 128 set to 1
//! for full blocks, 0 for the final padded partial block). The accumulator
//! `h` is updated as `h = (h + block) * r  mod  (2¹³⁰ − 5)` for each block,
//! and the final tag is `(h + s) mod 2¹²⁸`.
//!
//! # Security note
//!
//! **Poly1305 is a one-time MAC.** Using the same (r, s) key pair with
//! different messages is catastrophically insecure — an attacker can recover
//! the secret `r` value and forge tags. In practice, the key is derived
//! per-message from `ChaCha20`'s keystream (first 32 bytes of block 0).
//!
//! # Configuration parameters
//!
//! | Parameter | Type  | Default | Valid values       |
//! |-----------|-------|---------|--------------------|
//! | `size`    | u64   | 16      | always 16          |
//! | `key`     | bytes | —       | exactly 32 bytes   |
//!
//! # Dispatch table replacement
//!
//! This module replaces the C `ossl_poly1305_functions[]` dispatch table
//! from `poly1305_prov.c` with Rust trait-based dispatch via [`MacProvider`]
//! and [`MacContext`].

use crate::traits::{AlgorithmDescriptor, MacContext, MacProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Poly1305 key size: exactly 32 bytes (256 bits).
///
/// The key is split into r (16 bytes, clamped) and s (16 bytes, nonce).
/// Replaces C `POLY1305_KEY_SIZE` from `include/crypto/poly1305.h`.
pub const POLY1305_KEY_SIZE: usize = 32;

/// Poly1305 output tag size: exactly 16 bytes (128 bits).
///
/// Replaces C `POLY1305_DIGEST_SIZE` / `POLY1305_BLOCK_SIZE` from
/// `include/crypto/poly1305.h`.
pub const POLY1305_TAG_SIZE: usize = 16;

/// Internal block size for Poly1305 processing.
const BLOCK_SIZE: usize = 16;

/// `OSSL_MAC_PARAM_SIZE` — output size parameter name.
const PARAM_SIZE: &str = "size";

/// `OSSL_MAC_PARAM_KEY` — key parameter name.
const PARAM_KEY: &str = "key";

// ---------------------------------------------------------------------------
// Poly1305State — core algorithm state (pure Rust, zero unsafe)
// ---------------------------------------------------------------------------

/// Internal Poly1305 computation state using radix-2²⁶ representation.
///
/// Implements the Poly1305 polynomial evaluation in GF(2¹³⁰ − 5) using five
/// 26-bit limbs for both the accumulator `h` and the clamped key `r`. This
/// representation allows multiplication using `u64` intermediates without
/// overflow, following the well-known "donna" reference implementation
/// strategy.
///
/// Translates the C `POLY1305` / `POLY1305_INTERNAL` structs from
/// `crypto/poly1305/poly1305.c`.
#[derive(Clone)]
struct Poly1305State {
    /// Clamped polynomial evaluation point r in radix-2²⁶ (5 limbs).
    r: [u32; 5],
    /// Accumulator h in radix-2²⁶ (5 limbs).
    h: [u32; 5],
    /// Pad / nonce (second 16 bytes of key) as four little-endian u32 words.
    pad: [u32; 4],
    /// Partial-block buffer for data that doesn't fill a complete 16-byte block.
    buffer: [u8; BLOCK_SIZE],
    /// Number of valid bytes currently in `buffer`.
    buffer_len: usize,
}

impl Zeroize for Poly1305State {
    fn zeroize(&mut self) {
        self.r.zeroize();
        self.h.zeroize();
        self.pad.zeroize();
        self.buffer.zeroize();
        self.buffer_len = 0;
    }
}

impl Drop for Poly1305State {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Poly1305State {
    /// Initialize a new Poly1305 state from a 32-byte key.
    ///
    /// The first 16 bytes are clamped to produce `r`; the last 16 bytes
    /// become the one-time pad `s`. The accumulator `h` is set to zero.
    ///
    /// # Clamping
    ///
    /// Per the Poly1305 specification, certain bits of `r` must be cleared:
    /// - Bits 4,5,6,7 of bytes 3,7,11,15 (top 4 bits of each 32-bit LE word)
    /// - Bits 0,1 of bytes 4,8,12 (bottom 2 bits of words 1,2,3)
    ///
    /// The clamping is applied during conversion to radix-2²⁶ representation,
    /// matching the C `poly1305_init()` function from `crypto/poly1305/poly1305.c`.
    fn new(key: &[u8; 32]) -> Self {
        // Read first 16 bytes as four little-endian u32 words.
        let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);

        // Convert to radix-2²⁶ with clamping applied.
        // Masks match C poly1305_init: r &= 0x0ffffffc_0ffffffc_0ffffffc_0fffffff
        let r0 = t0 & 0x03FF_FFFF;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03FF_FF03;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03FF_C0FF;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03F0_3FFF;
        let r4 = (t3 >> 8) & 0x000F_FFFF;

        // Read last 16 bytes as pad (one-time nonce s).
        let pad0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        let pad1 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        let pad2 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        let pad3 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Poly1305State {
            r: [r0, r1, r2, r3, r4],
            h: [0; 5],
            pad: [pad0, pad1, pad2, pad3],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    /// Process a single 16-byte block through the Poly1305 polynomial.
    ///
    /// Computes `h = (h + block) * r  mod  (2¹³⁰ − 5)` where `block` is
    /// interpreted as a little-endian integer with `hibit` appended at
    /// bit position 128 (in radix-2²⁶, added to limb h\[4\]).
    ///
    /// For full blocks, `hibit` = `1 << 24` (i.e., 2¹²⁸ in radix-2²⁶ terms).
    /// For the final padded partial block, `hibit` = 0.
    ///
    /// Translates `poly1305_blocks()` from `crypto/poly1305/poly1305.c` (32-bit path).
    // TRUNCATION: All `as u32` casts in this function occur after accumulator
    // carry propagation and masking with `& 0x03FF_FFFF` (26 bits), guaranteeing
    // the result is at most 2²⁶ − 1 = 67,108,863 which always fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    fn process_block(&mut self, block: &[u8], hibit: u32) {
        // Read block as four little-endian u32 words and convert to radix-2²⁶.
        let t0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let t1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let t2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let t3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

        // Add block to accumulator h (radix-2²⁶).
        let h0 = self.h[0].wrapping_add(t0 & 0x03FF_FFFF);
        let h1 = self.h[1].wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x03FF_FFFF);
        let h2 = self.h[2].wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x03FF_FFFF);
        let h3 = self.h[3].wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x03FF_FFFF);
        let h4 = self.h[4].wrapping_add((t3 >> 8) | hibit);

        // Pre-compute r[i] * 5 for reduction (2¹³⁰ ≡ 5 mod p).
        let s1 = self.r[1].wrapping_mul(5);
        let s2 = self.r[2].wrapping_mul(5);
        let s3 = self.r[3].wrapping_mul(5);
        let s4 = self.r[4].wrapping_mul(5);

        // Full multiplication: h * r using schoolbook method with u64 intermediates.
        // Each h[i] is ≤ 27 bits, each r[j] is ≤ 26 bits, so products fit in u64.
        // The "wrap-around" terms use s_i = r_i * 5 because 2¹³⁰ ≡ 5 (mod p).
        let d0 = u64::from(h0) * u64::from(self.r[0])
            + u64::from(h1) * u64::from(s4)
            + u64::from(h2) * u64::from(s3)
            + u64::from(h3) * u64::from(s2)
            + u64::from(h4) * u64::from(s1);

        let mut d1 = u64::from(h0) * u64::from(self.r[1])
            + u64::from(h1) * u64::from(self.r[0])
            + u64::from(h2) * u64::from(s4)
            + u64::from(h3) * u64::from(s3)
            + u64::from(h4) * u64::from(s2);

        let mut d2 = u64::from(h0) * u64::from(self.r[2])
            + u64::from(h1) * u64::from(self.r[1])
            + u64::from(h2) * u64::from(self.r[0])
            + u64::from(h3) * u64::from(s4)
            + u64::from(h4) * u64::from(s3);

        let mut d3 = u64::from(h0) * u64::from(self.r[3])
            + u64::from(h1) * u64::from(self.r[2])
            + u64::from(h2) * u64::from(self.r[1])
            + u64::from(h3) * u64::from(self.r[0])
            + u64::from(h4) * u64::from(s4);

        let mut d4 = u64::from(h0) * u64::from(self.r[4])
            + u64::from(h1) * u64::from(self.r[3])
            + u64::from(h2) * u64::from(self.r[2])
            + u64::from(h3) * u64::from(self.r[1])
            + u64::from(h4) * u64::from(self.r[0]);

        // Carry propagation (partial reduction mod 2¹³⁰ − 5).
        let c = d0 >> 26;
        d1 += c;
        let c = d1 >> 26;
        d2 += c;
        let c = d2 >> 26;
        d3 += c;
        let c = d3 >> 26;
        d4 += c;
        let c = d4 >> 26;

        // Final wrap-around: bits above 130 multiplied by 5.
        let mut h0_out = (d0 as u32) & 0x03FF_FFFF;
        h0_out = h0_out.wrapping_add((c as u32).wrapping_mul(5));
        let carry = h0_out >> 26;
        h0_out &= 0x03FF_FFFF;

        self.h[0] = h0_out;
        self.h[1] = ((d1 as u32) & 0x03FF_FFFF).wrapping_add(carry);
        self.h[2] = (d2 as u32) & 0x03FF_FFFF;
        self.h[3] = (d3 as u32) & 0x03FF_FFFF;
        self.h[4] = (d4 as u32) & 0x03FF_FFFF;
    }

    /// Feed additional data into the Poly1305 computation.
    ///
    /// Buffers partial blocks internally and processes complete 16-byte blocks
    /// immediately. Translates `Poly1305_Update()` from `crypto/poly1305/poly1305.c`.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Step 1: Complete any partial block already in the buffer.
        if self.buffer_len > 0 {
            let need = BLOCK_SIZE - self.buffer_len;
            let can_take = data.len().min(need);
            self.buffer[self.buffer_len..self.buffer_len + can_take]
                .copy_from_slice(&data[..can_take]);
            self.buffer_len += can_take;
            offset = can_take;

            if self.buffer_len == BLOCK_SIZE {
                // Buffer is full — process it as a complete block.
                let block = self.buffer;
                self.process_block(&block, 1 << 24);
                self.buffer_len = 0;
            }
        }

        // Step 2: Process all remaining full 16-byte blocks directly.
        let remaining = &data[offset..];
        let full_blocks = remaining.len() / BLOCK_SIZE;
        for i in 0..full_blocks {
            let start = i * BLOCK_SIZE;
            self.process_block(&remaining[start..start + BLOCK_SIZE], 1 << 24);
        }

        // Step 3: Buffer any trailing partial block.
        let leftover_start = full_blocks * BLOCK_SIZE;
        let leftover = &remaining[leftover_start..];
        if !leftover.is_empty() {
            self.buffer[..leftover.len()].copy_from_slice(leftover);
            self.buffer_len = leftover.len();
        }
    }

    /// Finalize the Poly1305 computation and return the 16-byte tag.
    ///
    /// Processes any buffered partial block with appropriate padding (0x01
    /// byte appended, then zero-padded to 16 bytes, with hibit = 0).
    /// Performs final reduction of `h` modulo 2¹³⁰ − 5, then adds the
    /// pad `s` to produce the 128-bit tag.
    ///
    /// Consumes `self` because the internal state is modified during
    /// finalization (matching C `Poly1305_Final` followed by `OPENSSL_cleanse`).
    /// The [`Zeroize`] derive on [`Poly1305State`] ensures all key material
    /// is securely erased when the state is dropped.
    ///
    /// Translates `Poly1305_Final()` and `poly1305_emit()` from
    /// `crypto/poly1305/poly1305.c`.
    // TRUNCATION: All `as u32` casts in finalize extract the lower 32 bits
    // of a u64 sum of two u32 values (pad addition mod 2¹²⁸). The high bits
    // carry to the next word via `>> 32`, so only the low 32 bits are kept —
    // this is standard big-number addition arithmetic.
    #[allow(clippy::cast_possible_truncation)]
    fn finalize(mut self) -> Vec<u8> {
        // Process any remaining buffered data as a padded partial block.
        if self.buffer_len > 0 {
            let mut block = [0u8; BLOCK_SIZE];
            block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            block[self.buffer_len] = 1; // Poly1305 padding: append 0x01
            // hibit = 0 for the final partial block (no 2¹²⁸ appended).
            self.process_block(&block, 0);
        }

        // --- Full carry propagation ---
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26;
        h1 &= 0x03FF_FFFF;
        h2 = h2.wrapping_add(c);
        c = h2 >> 26;
        h2 &= 0x03FF_FFFF;
        h3 = h3.wrapping_add(c);
        c = h3 >> 26;
        h3 &= 0x03FF_FFFF;
        h4 = h4.wrapping_add(c);
        c = h4 >> 26;
        h4 &= 0x03FF_FFFF;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        h0 &= 0x03FF_FFFF;
        h1 = h1.wrapping_add(c);

        // --- Conditional subtraction of p = 2¹³⁰ − 5 ---
        // Compute g = h + 5 − 2¹³⁰. If g ≥ 0 (i.e., h ≥ p), use g; else use h.
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x03FF_FFFF;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x03FF_FFFF;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x03FF_FFFF;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x03FF_FFFF;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Constant-time conditional select:
        // If h ≥ p then g4 is small (0..3), bit 31 = 0, mask = 0xFFFF_FFFF → use g.
        // If h < p then g4 underflows (wraps to large value), bit 31 = 1, mask = 0 → use h.
        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4_masked = g4 & mask;
        let not_mask = !mask;
        h0 = (h0 & not_mask) | g0;
        h1 = (h1 & not_mask) | g1;
        h2 = (h2 & not_mask) | g2;
        h3 = (h3 & not_mask) | g3;
        h4 = (h4 & not_mask) | g4_masked;

        // --- Convert radix-2²⁶ back to four u32 words ---
        let w0 = (h0) | (h1 << 26);
        let w1 = (h1 >> 6) | (h2 << 20);
        let w2 = (h2 >> 12) | (h3 << 14);
        let w3 = (h3 >> 18) | (h4 << 8);

        // --- Add pad (nonce s) mod 2¹²⁸ ---
        let mut f: u64;
        f = u64::from(w0) + u64::from(self.pad[0]);
        let out0 = f as u32;
        f = u64::from(w1) + u64::from(self.pad[1]) + (f >> 32);
        let out1 = f as u32;
        f = u64::from(w2) + u64::from(self.pad[2]) + (f >> 32);
        let out2 = f as u32;
        f = u64::from(w3) + u64::from(self.pad[3]) + (f >> 32);
        let out3 = f as u32;

        // Serialize tag as 16 bytes, little-endian.
        let mut result = vec![0u8; POLY1305_TAG_SIZE];
        result[0..4].copy_from_slice(&out0.to_le_bytes());
        result[4..8].copy_from_slice(&out1.to_le_bytes());
        result[8..12].copy_from_slice(&out2.to_le_bytes());
        result[12..16].copy_from_slice(&out3.to_le_bytes());
        result
    }
}

// ---------------------------------------------------------------------------
// ContextState — state machine for the MAC context lifecycle
// ---------------------------------------------------------------------------

/// State machine tracking the lifecycle of a [`Poly1305Context`].
///
/// Transitions: `New` → `Active` (after key init) → `Finalized` (after
/// finalize). Re-initialization transitions from any state back to `Active`.
#[derive(Clone)]
enum ContextState {
    /// Created but not yet initialized with a key.
    New,
    /// Initialized with a key and accepting data via `update()`.
    Active(Poly1305State),
    /// Finalized; no further updates allowed without re-init.
    Finalized,
}

// ---------------------------------------------------------------------------
// Poly1305Provider — factory implementing MacProvider
// ---------------------------------------------------------------------------

/// Poly1305 MAC provider (factory).
///
/// Creates [`Poly1305Context`] instances for streaming Poly1305 MAC computation.
/// Replaces the C `ossl_poly1305_functions[]` dispatch table from
/// `providers/implementations/macs/poly1305_prov.c`.
///
/// **Security note:** Poly1305 is a one-time MAC. The same 32-byte key must
/// never be used with different messages. In ChaCha20-Poly1305, the key is
/// derived per-message from the `ChaCha20` keystream (first 32 bytes of block 0).
pub struct Poly1305Provider;

impl Default for Poly1305Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl Poly1305Provider {
    /// Create a new Poly1305 provider instance.
    pub fn new() -> Self {
        Poly1305Provider
    }

    /// Return algorithm descriptors for provider registration.
    ///
    /// Produces a single descriptor with name `"Poly1305"` and the default
    /// provider property string, enabling algorithm lookup via the
    /// provider dispatch framework.
    pub fn descriptors() -> Vec<AlgorithmDescriptor> {
        vec![AlgorithmDescriptor {
            names: vec!["Poly1305"],
            property: "provider=default",
            description: "Poly1305 Message Authentication Code",
        }]
    }
}

impl MacProvider for Poly1305Provider {
    /// Returns the algorithm name: `"Poly1305"`.
    fn name(&self) -> &'static str {
        "Poly1305"
    }

    /// Returns the output tag size: 16 bytes (128 bits).
    fn size(&self) -> usize {
        POLY1305_TAG_SIZE
    }

    /// Create a new Poly1305 MAC computation context.
    fn new_ctx(&self) -> ProviderResult<Box<dyn MacContext>> {
        Ok(Box::new(Poly1305Context::new()))
    }
}

// ---------------------------------------------------------------------------
// Poly1305Context — streaming MAC context implementing MacContext
// ---------------------------------------------------------------------------

/// Poly1305 MAC computation context.
///
/// Maintains the live computation state, a snapshot copy for keyless
/// re-initialization (replacing the C `poly1305_data_st` struct), and
/// an `updated` flag tracking whether `update()` has been called
/// (constraining reinit semantics per the C implementation).
///
/// All key material is securely zeroed on drop via the [`Zeroize`]
/// implementation on [`Poly1305State`], replacing the C pattern of
/// `OPENSSL_cleanse(ctx, sizeof(*ctx))` in `Poly1305_Final()`.
///
/// Replaces `struct poly1305_data_st` from `poly1305_prov.c`.
pub struct Poly1305Context {
    /// Current computation state (lifecycle stage + algorithm state).
    state: ContextState,
    /// Snapshot of initial state after key setup, used for keyless reinit.
    /// Corresponds to the ability to call `poly1305_init(vmacctx, NULL, 0, params)`
    /// in the C implementation to reset to the initial state.
    snapshot: Option<Poly1305State>,
    /// Whether `update()` has been called since last init.
    /// Mirrors the `updated` field in C `poly1305_data_st`.
    /// If true and no key is provided on reinit, the reinit fails
    /// because the one-time key has been "consumed".
    updated: bool,
}

impl Poly1305Context {
    /// Create a new Poly1305 context in the uninitialized state.
    fn new() -> Self {
        Poly1305Context {
            state: ContextState::New,
            snapshot: None,
            updated: false,
        }
    }

    /// Apply parameters from a [`ParamSet`] to this context.
    ///
    /// Handles the `key` parameter (the only configurable parameter for
    /// Poly1305). If a key is provided via params, initializes the internal
    /// state with it.
    ///
    /// Translates `poly1305_set_ctx_params()` from `poly1305_prov.c`.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if params.contains(PARAM_KEY) {
            let key_bytes = params
                .get_typed::<Vec<u8>>(PARAM_KEY)
                .map_err(ProviderError::Common)?;
            if key_bytes.len() != POLY1305_KEY_SIZE {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "Poly1305 key must be exactly {} bytes, got {}",
                        POLY1305_KEY_SIZE,
                        key_bytes.len(),
                    ),
                )));
            }
            self.init_with_key(&key_bytes)?;
        }

        Ok(())
    }

    /// Initialize the internal Poly1305 state with the given 32-byte key.
    ///
    /// Creates a new [`Poly1305State`], saves a snapshot for subsequent
    /// keyless re-initialization, and resets the `updated` flag.
    fn init_with_key(&mut self, key: &[u8]) -> ProviderResult<()> {
        let key_array: &[u8; POLY1305_KEY_SIZE] = key.try_into().map_err(|_| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "Poly1305 key must be exactly {} bytes, got {}",
                POLY1305_KEY_SIZE,
                key.len(),
            )))
        })?;
        let poly_state = Poly1305State::new(key_array);
        self.snapshot = Some(poly_state.clone());
        self.state = ContextState::Active(poly_state);
        self.updated = false;
        Ok(())
    }
}

impl Clone for Poly1305Context {
    /// Create a deep copy of this context, including the live computation
    /// state and snapshot. Replaces `poly1305_dup()` from `poly1305_prov.c`
    /// which performs a simple `memcpy` of the entire struct.
    fn clone(&self) -> Self {
        Poly1305Context {
            state: self.state.clone(),
            snapshot: self.snapshot.clone(),
            updated: self.updated,
        }
    }
}

impl MacContext for Poly1305Context {
    /// Initialize (or re-initialize) the Poly1305 context.
    ///
    /// Follows the C `poly1305_init()` semantics from `poly1305_prov.c`:
    ///
    /// 1. Apply `params` first (may set a key via the `key` parameter).
    /// 2. If an explicit `key` argument is provided (non-empty), validate
    ///    it is exactly 32 bytes and initialize the state with it.
    /// 3. If no explicit key and `apply_params` didn't set one either:
    ///    - If `updated` is false and a snapshot exists, restore from snapshot
    ///      (keyless reinit before any data was processed).
    ///    - If `updated` is true, return an error (one-time key was consumed).
    ///    - If no snapshot exists, return an error (never initialized).
    ///
    /// The `updated` flag guards against reusing a one-time key after data
    /// has been processed, matching the C behavior where reinit without a
    /// new key is only permitted if `update()` was never called.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        // Step 1: Apply parameters (may set key).
        if let Some(p) = params {
            self.apply_params(p)?;
        }

        // Step 2: Explicit key argument takes precedence.
        if !key.is_empty() {
            if key.len() != POLY1305_KEY_SIZE {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "Poly1305 key must be exactly {} bytes, got {}",
                        POLY1305_KEY_SIZE,
                        key.len(),
                    ),
                )));
            }
            self.init_with_key(key)?;
        } else if !matches!(self.state, ContextState::Active(_)) {
            // No explicit key and apply_params did not set a key.
            // Attempt keyless reinit from snapshot.
            if self.updated {
                return Err(ProviderError::Init(
                    "Poly1305 reinit requires a new key after update() was called \
                     (one-time MAC key consumed)"
                        .to_string(),
                ));
            }
            match &self.snapshot {
                Some(snap) => {
                    self.state = ContextState::Active(snap.clone());
                    self.updated = false;
                }
                None => {
                    return Err(ProviderError::Init(
                        "Poly1305 requires a key for initialization".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Feed data into the Poly1305 computation.
    ///
    /// Sets the `updated` flag to `true` on first successful call,
    /// preventing keyless reinit (since the one-time key has been consumed).
    ///
    /// Returns an error if the context is not initialized (state is `New`)
    /// or has already been finalized.
    ///
    /// Translates `poly1305_update()` from `poly1305_prov.c`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        match self.state {
            ContextState::Active(ref mut poly_state) => {
                poly_state.update(data);
                self.updated = true;
                Ok(())
            }
            ContextState::New => Err(ProviderError::Init(
                "Poly1305 not initialized: call init() with a key first".to_string(),
            )),
            ContextState::Finalized => Err(ProviderError::Init(
                "Poly1305 already finalized: call init() to reinitialize".to_string(),
            )),
        }
    }

    /// Finalize the Poly1305 computation and return the 16-byte MAC tag.
    ///
    /// Transitions the context to the `Finalized` state; further `update()`
    /// calls will fail until `init()` is called again with a new key.
    ///
    /// Translates `poly1305_final()` from `poly1305_prov.c`.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        let old_state = std::mem::replace(&mut self.state, ContextState::Finalized);
        match old_state {
            ContextState::Active(poly_state) => Ok(poly_state.finalize()),
            ContextState::New => Err(ProviderError::Init(
                "Poly1305 not initialized: call init() with a key first".to_string(),
            )),
            ContextState::Finalized => Err(ProviderError::Init(
                "Poly1305 already finalized: call init() to reinitialize".to_string(),
            )),
        }
    }

    /// Retrieve current context parameters.
    ///
    /// Returns the output `size` (always 16 for Poly1305) as a [`ParamSet`].
    ///
    /// Translates `poly1305_get_params()` / `poly1305_get_ctx_params()` from
    /// `poly1305_prov.c`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, POLY1305_TAG_SIZE as u64)
            .build();
        Ok(params)
    }

    /// Apply parameter changes to this context.
    ///
    /// Delegates to [`apply_params`](Poly1305Context::apply_params).
    /// Only the `key` parameter is supported for Poly1305.
    ///
    /// Translates standalone `poly1305_set_ctx_params()` invocation from
    /// `poly1305_prov.c`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // RFC 8439 §2.5.2 — Poly1305 reference test vector
    // -----------------------------------------------------------------------
    //
    // Key (32 bytes):
    //   85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8
    //   01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
    //
    // Message: "Cryptographic Forum Research Group"
    //
    // Tag (16 bytes):
    //   a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
    //

    /// RFC 8439 §2.5.2 test vector key.
    const RFC8439_KEY: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
        0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
        0x41, 0x49, 0xf5, 0x1b,
    ];

    /// RFC 8439 §2.5.2 test vector message.
    const RFC8439_MSG: &[u8] = b"Cryptographic Forum Research Group";

    /// RFC 8439 §2.5.2 expected tag.
    const RFC8439_TAG: [u8; 16] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
        0x27, 0xa9,
    ];

    // -----------------------------------------------------------------------
    // Low-level state tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_poly1305_state_rfc8439() {
        let mut state = Poly1305State::new(&RFC8439_KEY);
        state.update(RFC8439_MSG);
        let tag = state.finalize();
        assert_eq!(tag.as_slice(), &RFC8439_TAG);
    }

    #[test]
    fn test_poly1305_state_incremental() {
        // Feed the RFC 8439 message one byte at a time.
        let mut state = Poly1305State::new(&RFC8439_KEY);
        for &byte in RFC8439_MSG {
            state.update(&[byte]);
        }
        let tag = state.finalize();
        assert_eq!(tag.as_slice(), &RFC8439_TAG);
    }

    #[test]
    fn test_poly1305_state_empty_message() {
        // Empty message: tag = (0 + s) mod 2^128 = s (pad portion of key).
        let key = [0u8; 32];
        let state = Poly1305State::new(&key);
        let tag = state.finalize();
        // With an all-zero key, r=0 and s=0, so tag should be all zeros.
        assert_eq!(tag, vec![0u8; 16]);
    }

    #[test]
    fn test_poly1305_state_zero_r() {
        // When r = 0, the polynomial evaluation is always 0.
        // Tag = (0 + s) mod 2^128 = s.
        let mut key = [0u8; 32];
        // Set pad (bytes 16..32) to a known value.
        key[16] = 0x01;
        key[17] = 0x02;
        key[18] = 0x03;
        key[19] = 0x04;

        let mut state = Poly1305State::new(&key);
        state.update(b"any data");
        let tag = state.finalize();
        // Since r=0, h stays 0 regardless of input. tag = h + pad = pad.
        assert_eq!(tag[0], 0x01);
        assert_eq!(tag[1], 0x02);
        assert_eq!(tag[2], 0x03);
        assert_eq!(tag[3], 0x04);
        // Remaining pad bytes are 0.
        assert_eq!(&tag[4..], &[0u8; 12]);
    }

    // -----------------------------------------------------------------------
    // Nacl test vector (from RFC 8439 Appendix A.3)
    // -----------------------------------------------------------------------

    #[test]
    fn test_poly1305_long_message() {
        // Long-message test: 375-byte IETF submission text with zero pad (s=0).
        // Key r-portion: 0x36e5f6b5c5e06070f0efca96227a863e, pad s=0.
        // Independently verified against Python reference implementation.
        let key: [u8; 32] = [
            0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22,
            0x7a, 0x86, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let msg: &[u8] = b"Any submission to the IETF intended by the \
Contributor for publication as all or part of an IETF Internet-Draft or \
RFC and any statement made within the context of an IETF activity is \
considered an \"IETF Contribution\". Such statements include oral \
statements in IETF sessions, as well as written and electronic \
communications made at any time or place, which are addressed to";
        // Expected tag verified by Python poly1305 reference implementation.
        let expected_tag: [u8; 16] = [
            0xf3, 0x47, 0x7e, 0x7c, 0xd9, 0x54, 0x17, 0xaf, 0x89, 0xa6, 0xb8, 0x79, 0x4c,
            0x31, 0x0c, 0xf0,
        ];

        let mut state = Poly1305State::new(&key);
        state.update(msg);
        let tag = state.finalize();
        assert_eq!(tag.as_slice(), &expected_tag);
    }

    // -----------------------------------------------------------------------
    // Provider tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_metadata() {
        let provider = Poly1305Provider::new();
        assert_eq!(provider.name(), "Poly1305");
        assert_eq!(provider.size(), POLY1305_TAG_SIZE);
        assert_eq!(provider.size(), 16);
    }

    #[test]
    fn test_provider_descriptors() {
        let descriptors = Poly1305Provider::descriptors();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].names, vec!["Poly1305"]);
        assert_eq!(descriptors[0].property, "provider=default");
        assert!(!descriptors[0].description.is_empty());
    }

    #[test]
    fn test_provider_new_ctx() {
        let provider = Poly1305Provider::new();
        let ctx = provider.new_ctx();
        assert!(ctx.is_ok());
    }

    #[test]
    fn test_provider_default() {
        let _provider: Poly1305Provider = Default::default();
    }

    // -----------------------------------------------------------------------
    // Context lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_init_update_finalize() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(&RFC8439_KEY, None).unwrap();
        ctx.update(RFC8439_MSG).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.as_slice(), &RFC8439_TAG);
    }

    #[test]
    fn test_context_incremental_update() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(&RFC8439_KEY, None).unwrap();
        // Feed one byte at a time.
        for &byte in RFC8439_MSG {
            ctx.update(&[byte]).unwrap();
        }
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.as_slice(), &RFC8439_TAG);
    }

    #[test]
    fn test_context_key_in_params() {
        let mut params = ParamSet::new();
        params.set(PARAM_KEY, openssl_common::ParamValue::OctetString(RFC8439_KEY.to_vec()));

        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(&[], Some(&params)).unwrap();
        ctx.update(RFC8439_MSG).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.as_slice(), &RFC8439_TAG);
    }

    #[test]
    fn test_context_invalid_key_length() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        // Key too short.
        let result = ctx.init(&[0u8; 16], None);
        assert!(result.is_err());
        // Key too long.
        let result = ctx.init(&[0u8; 64], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_no_key_error() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        // Init without key and no prior initialization.
        let result = ctx.init(&[], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_update_before_init() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        let result = ctx.update(b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_context_finalize_before_init() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        let result = ctx.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_context_double_finalize() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(&RFC8439_KEY, None).unwrap();
        ctx.update(b"test").unwrap();
        let _tag = ctx.finalize().unwrap();
        // Second finalize should fail.
        let result = ctx.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_context_update_after_finalize() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(&RFC8439_KEY, None).unwrap();
        ctx.update(b"test").unwrap();
        let _tag = ctx.finalize().unwrap();
        // Update after finalize should fail.
        let result = ctx.update(b"more data");
        assert!(result.is_err());
    }

    #[test]
    fn test_context_reinit_after_update_requires_key() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(&RFC8439_KEY, None).unwrap();
        ctx.update(b"data").unwrap();
        let _tag = ctx.finalize().unwrap();
        // Reinit without key after update should fail (one-time key consumed).
        let result = ctx.init(&[], None);
        assert!(result.is_err());
        // Reinit with a new key should succeed.
        let result = ctx.init(&RFC8439_KEY, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_context_reinit_with_new_key() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();

        // First computation.
        ctx.init(&RFC8439_KEY, None).unwrap();
        ctx.update(RFC8439_MSG).unwrap();
        let tag1 = ctx.finalize().unwrap();
        assert_eq!(tag1.as_slice(), &RFC8439_TAG);

        // Second computation with the same key.
        ctx.init(&RFC8439_KEY, None).unwrap();
        ctx.update(RFC8439_MSG).unwrap();
        let tag2 = ctx.finalize().unwrap();
        assert_eq!(tag2.as_slice(), &RFC8439_TAG);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_context_keyless_reinit_before_update() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();

        // Initialize with a key but don't call update().
        ctx.init(&RFC8439_KEY, None).unwrap();
        // Keyless reinit should succeed since updated is false.
        ctx.init(&[], None).unwrap();
        ctx.update(RFC8439_MSG).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.as_slice(), &RFC8439_TAG);
    }

    // -----------------------------------------------------------------------
    // Clone tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_clone() {
        // Use concrete type for clone (Box<dyn MacContext> is not Clone).
        let mut ctx = Poly1305Context::new();
        ctx.init(&RFC8439_KEY, None).unwrap();
        ctx.update(b"Cryptographic Forum").unwrap();

        // Clone mid-computation.
        let mut ctx2 = ctx.clone();

        // Finish both with the remaining data.
        ctx.update(b" Research Group").unwrap();
        ctx2.update(b" Research Group").unwrap();

        let tag1 = ctx.finalize().unwrap();
        let tag2 = ctx2.finalize().unwrap();
        assert_eq!(tag1, tag2);
        assert_eq!(tag1.as_slice(), &RFC8439_TAG);
    }

    // -----------------------------------------------------------------------
    // get_params / set_params tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_params() {
        let provider = Poly1305Provider::new();
        let ctx = provider.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        let size = params.get_typed::<u64>("size").unwrap();
        assert_eq!(size, 16);
    }

    #[test]
    fn test_set_params_key() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut params = ParamSet::new();
        params.set(PARAM_KEY, openssl_common::ParamValue::OctetString(RFC8439_KEY.to_vec()));
        ctx.set_params(&params).unwrap();

        // Context should now be active.
        ctx.update(RFC8439_MSG).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.as_slice(), &RFC8439_TAG);
    }

    #[test]
    fn test_set_params_invalid_key_length() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut params = ParamSet::new();
        params.set(
            PARAM_KEY,
            openssl_common::ParamValue::OctetString(vec![0u8; 16]),
        );
        let result = ctx.set_params(&params);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Edge case: exactly block-aligned messages
    // -----------------------------------------------------------------------

    #[test]
    fn test_exact_block_boundary() {
        let provider = Poly1305Provider::new();
        let mut ctx1 = provider.new_ctx().unwrap();
        let mut ctx2 = provider.new_ctx().unwrap();

        // 32 bytes = exactly 2 full blocks.
        let msg = [0x42u8; 32];

        ctx1.init(&RFC8439_KEY, None).unwrap();
        ctx1.update(&msg).unwrap();
        let tag1 = ctx1.finalize().unwrap();

        // Incremental: 1 byte at a time.
        ctx2.init(&RFC8439_KEY, None).unwrap();
        for &b in &msg {
            ctx2.update(&[b]).unwrap();
        }
        let tag2 = ctx2.finalize().unwrap();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_single_byte_message() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(&RFC8439_KEY, None).unwrap();
        ctx.update(&[0x01]).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), POLY1305_TAG_SIZE);
    }

    #[test]
    fn test_empty_message_via_context() {
        let provider = Poly1305Provider::new();
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(&RFC8439_KEY, None).unwrap();
        // No update — empty message.
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), POLY1305_TAG_SIZE);
    }
}
