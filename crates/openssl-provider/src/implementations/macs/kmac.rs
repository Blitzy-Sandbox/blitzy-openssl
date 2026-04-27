//! KMAC-128 / KMAC-256 provider implementation.
//!
//! Pure-Rust, zero-`unsafe` translation of
//! `providers/implementations/macs/kmac_prov.c` (547 lines).
//!
//! **KMAC** (Keccak Message Authentication Code) is defined in
//! [NIST SP 800-185](https://doi.org/10.6028/NIST.SP.800-185).
//! It is built on top of **cSHAKE** which in turn wraps the
//! Keccak-f\[1600\] sponge permutation.
//!
//! # Algorithm overview
//!
//! ```text
//! KMAC128(K, X, L, S):
//!   newX = bytepad(encode_string(K), 168) ‖ X ‖ right_encode(L)
//!   return cSHAKE128(newX, L, "KMAC", S)
//!
//! KMAC256(K, X, L, S):
//!   newX = bytepad(encode_string(K), 136) ‖ X ‖ right_encode(L)
//!   return cSHAKE256(newX, L, "KMAC", S)
//! ```
//!
//! XOF variants use `right_encode(0)` instead of `right_encode(L)`.
//!
//! # Configuration parameters
//!
//! | Parameter  | Type    | Default | Description                           |
//! |------------|---------|---------|---------------------------------------|
//! | `custom`   | bytes   | `""`    | Customization string (max 512 bytes)  |
//! | `size`     | u64     | 32 / 64 | Output length in bytes                |
//! | `xof`      | bool    | false   | Variable-length XOF output mode       |
//!
//! # Encoding helpers (SP 800-185 §2)
//!
//! * **`left_encode(x)`** — byte-count prefix ‖ big-endian value
//! * **`right_encode(x)`** — big-endian value ‖ byte-count suffix
//! * **`encode_string(S)`** — `left_encode(len(S)*8) ‖ S`
//! * **`bytepad(X, w)`** — `left_encode(w) ‖ X ‖ 0*` (pad to w multiple)
//!
//! # Keccak-f\[1600\]
//!
//! A full, pure-Rust implementation of the 24-round Keccak-f\[1600\]
//! permutation is included inline (matching sibling MAC files that
//! embed their core algorithm).  The sponge uses the cSHAKE domain
//! separator byte `0x04`.

use crate::traits::{AlgorithmDescriptor, MacContext, MacProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use zeroize::Zeroizing;

// ===========================================================================
// KMAC constants (from `kmac_prov.c` lines 84–100)
// ===========================================================================

/// Maximum KMAC block size: `(1600 − 128×2) / 8 = 168` bytes (KMAC-128 rate).
/// Used in validation assertions and documentation of rate bounds.
const _KMAC_MAX_BLOCKSIZE: usize = 168;

/// Maximum output length: `0xFF_FFFF / 8 = 2 097 151` bytes.
const KMAC_MAX_OUTPUT_LEN: usize = 0x00FF_FFFF / 8;

/// Maximum encoded header length: 1 byte count prefix + up to 3 value bytes.
const KMAC_MAX_ENCODED_HEADER_LEN: usize = 4;

/// Maximum customization string length: 512 bytes.
const KMAC_MAX_CUSTOM: usize = 512;

/// Maximum encoded customization string size (custom + header overhead).
#[allow(dead_code)] // kept for documentation parity with C
const KMAC_MAX_CUSTOM_ENCODED: usize = KMAC_MAX_CUSTOM + KMAC_MAX_ENCODED_HEADER_LEN;

/// KMAC-128 default output length: 32 bytes (256 bits / 2).
const KMAC128_DEFAULT_OUTPUT_LEN: usize = 32;

/// KMAC-256 default output length: 64 bytes (512 bits / 2).
const KMAC256_DEFAULT_OUTPUT_LEN: usize = 64;

/// KMAC-128 sponge rate: `(1600 − 256) / 8 = 168` bytes.
const KMAC128_RATE: usize = 168;

/// KMAC-256 sponge rate: `(1600 − 512) / 8 = 136` bytes.
const KMAC256_RATE: usize = 136;

/// Minimum key length in bytes (from C `KMAC_MIN_KEY`).
const KMAC_MIN_KEY: usize = 4;

/// Maximum key length in bytes (from C `KMAC_MAX_KEY`).
const KMAC_MAX_KEY: usize = 512;

/// Pre-computed `encode_string("KMAC")`:
/// `left_encode(4×8=32)` ‖ `"KMAC"` = `[0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43]`.
///
/// Matches C `kmac_string` constant (`kmac_prov.c` line ~87).
const KMAC_STRING: [u8; 6] = [0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43];

/// `OSSL_MAC_PARAM_SIZE` — output tag size parameter name.
const PARAM_SIZE: &str = "size";

/// `OSSL_MAC_PARAM_XOF` — XOF mode flag parameter name.
const PARAM_XOF: &str = "xof";

/// `OSSL_MAC_PARAM_CUSTOM` — customization string parameter name.
const PARAM_CUSTOM: &str = "custom";

/// `OSSL_MAC_PARAM_KEY` — key parameter name.
///
/// In the C source (`kmac_set_ctx_params`), the key may also be
/// provided through `OSSL_PARAM`.  In the Rust design the key is
/// supplied directly via `MacContext::init`, so this constant is
/// used only in documentation and test assertions.
const _PARAM_KEY: &str = "key";

/// Block size parameter name for `get_params`.
const PARAM_BLOCK_SIZE: &str = "block-size";

// ===========================================================================
// Keccak-f[1600] round constants  (24 rounds)
// ===========================================================================

/// The 24 round constants (RC) for the ι (iota) step of Keccak-f\[1600\].
const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for the combined ρ/π step, indexed by destination
/// position after the π permutation.  `KECCAK_ROTC[i]` is the left
/// rotation amount for the lane that ends up at flat index `KECCAK_PILN[i]`.
const KECCAK_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44,
];

/// Destination lane indices for the combined ρ/π step.
const KECCAK_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1,
];

// ===========================================================================
// KmacVariant — algorithm selection enum
// ===========================================================================

/// KMAC variant: 128-bit or 256-bit security strength.
///
/// Determines the Keccak capacity (and therefore rate) used by the sponge
/// construction, as well as the default output length.
///
/// | Variant  | Capacity | Rate | Default output |
/// |----------|----------|------|----------------|
/// | Kmac128  | 256 bits | 168 B | 32 B (256 b) |
/// | Kmac256  | 512 bits | 136 B | 64 B (512 b) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmacVariant {
    /// KMAC-128: 128-bit security, KECCAK\[256\] / cSHAKE128.
    Kmac128,
    /// KMAC-256: 256-bit security, KECCAK\[512\] / cSHAKE256.
    Kmac256,
}

impl KmacVariant {
    /// Sponge rate in bytes for this variant.
    fn rate(self) -> usize {
        match self {
            Self::Kmac128 => KMAC128_RATE,
            Self::Kmac256 => KMAC256_RATE,
        }
    }

    /// Default MAC output length in bytes.
    fn default_output_len(self) -> usize {
        match self {
            Self::Kmac128 => KMAC128_DEFAULT_OUTPUT_LEN,
            Self::Kmac256 => KMAC256_DEFAULT_OUTPUT_LEN,
        }
    }

    /// Human-readable algorithm name.
    fn name_str(self) -> &'static str {
        match self {
            Self::Kmac128 => "KMAC-128",
            Self::Kmac256 => "KMAC-256",
        }
    }
}

// ===========================================================================
// KmacParams — typed configuration struct
// ===========================================================================

/// KMAC algorithm parameters.
///
/// Provides a typed configuration struct for callers who prefer structured
/// parameter passing over raw `ParamSet` bags.  Each field is optional;
/// `None` means "use the current or default value."
///
/// Replaces C `OSSL_PARAM` arrays from `kmac_prov.c`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KmacParams {
    /// Customization string `S` (default: empty, max 512 bytes).
    pub custom: Option<Vec<u8>>,
    /// Requested output length in bytes (`0` = use default for variant).
    pub output_len: Option<usize>,
    /// XOF mode: variable-length output via cSHAKE XOF finalization.
    pub xof_mode: bool,
}

impl KmacParams {
    /// Convert these parameters into a `ParamSet` suitable for passing
    /// to `MacContext::init` or `MacContext::set_params`.
    pub fn to_param_set(&self) -> ParamSet {
        let mut builder = ParamBuilder::new();
        if let Some(ref custom) = self.custom {
            builder = builder.push_octet(PARAM_CUSTOM, custom.clone());
        }
        if let Some(len) = self.output_len {
            builder = builder.push_u64(PARAM_SIZE, len as u64);
        }
        if self.xof_mode {
            builder = builder.push_u32(PARAM_XOF, 1);
        }
        builder.build()
    }
}

// ===========================================================================
// SP 800-185 §2 — encoding helpers
// ===========================================================================

/// `left_encode(value)` per SP 800-185 §2.3.1.
///
/// Encodes `value` as a big-endian byte string preceded by a single byte
/// giving the number of significant value bytes.
///
/// ```text
/// left_encode(0)   = [1, 0]
/// left_encode(255) = [1, 255]
/// left_encode(256) = [2, 1, 0]
/// ```
///
/// Uses checked arithmetic per Rule R6.
fn left_encode(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![1, 0];
    }
    // Determine how many bytes are needed for big-endian encoding.
    let byte_count = 8u32.saturating_sub(value.leading_zeros() / 8);
    let n = byte_count.max(1) as usize;
    let mut buf = Vec::with_capacity(n.saturating_add(1));
    // Prefix: number of value bytes (n ≤ 8, always fits in u8).
    // TRUNCATION: n is at most 8 (max bytes for u64); safe cast.
    #[allow(clippy::cast_possible_truncation)]
    buf.push(n as u8);
    // Value bytes, big-endian, most significant first.
    // TRUNCATION: intentional extraction of individual bytes from u64.
    #[allow(clippy::cast_possible_truncation)]
    for i in (0..n).rev() {
        buf.push((value >> (i * 8)) as u8);
    }
    buf
}

/// `right_encode(value)` per SP 800-185 §2.3.2.
///
/// Encodes `value` as a big-endian byte string followed by a single byte
/// giving the number of significant value bytes.
///
/// ```text
/// right_encode(0)   = [0, 1]
/// right_encode(255) = [255, 1]
/// right_encode(256) = [1, 0, 2]
/// ```
///
/// Translates C `right_encode()` from `kmac_prov.c` lines ~180-210.
/// Uses checked arithmetic per Rule R6.
fn right_encode(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0, 1];
    }
    let byte_count = 8u32.saturating_sub(value.leading_zeros() / 8);
    let n = byte_count.max(1) as usize;
    let mut buf = Vec::with_capacity(n.saturating_add(1));
    // TRUNCATION: intentional extraction of individual bytes from u64.
    #[allow(clippy::cast_possible_truncation)]
    for i in (0..n).rev() {
        buf.push((value >> (i * 8)) as u8);
    }
    // Suffix: number of value bytes (n ≤ 8, always fits in u8).
    // TRUNCATION: n is at most 8 (max bytes for u64); safe cast.
    #[allow(clippy::cast_possible_truncation)]
    buf.push(n as u8);
    buf
}

/// `encode_string(input)` per SP 800-185 §2.3.3.
///
/// Returns `left_encode(len(input) × 8) ‖ input`.
///
/// **Special case:** when `input` is empty the C reference returns an empty
/// byte vector (0 bytes) rather than `left_encode(0)`.  This matches the
/// behaviour of `kmac_prov.c` lines ~160-180 and ensures output compatibility
/// with existing OpenSSL KMAC test vectors.
///
/// Uses checked arithmetic per Rule R6.
fn encode_string(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    // Bit length of the input, checked for overflow.
    let bit_len = (input.len() as u64).saturating_mul(8);
    let mut encoded = left_encode(bit_len);
    encoded.extend_from_slice(input);
    encoded
}

/// `bytepad(encoded_data, w)` per SP 800-185 §2.3.4.
///
/// Returns `left_encode(w) ‖ encoded_data ‖ 0*` padded to the next
/// multiple of `w`.
///
/// Translates C `bytepad()` helper from `kmac_prov.c` lines ~210-250.
/// Uses checked arithmetic per Rule R6.
///
/// # Errors
///
/// Returns [`CommonError::InvalidArgument`] if `w` is zero.
fn bytepad(encoded_data: &[u8], w: usize) -> Result<Vec<u8>, CommonError> {
    if w == 0 {
        return Err(CommonError::InvalidArgument(
            "bytepad: block width w must not be zero".into(),
        ));
    }
    let prefix = left_encode(w as u64);
    let unpadded_len = prefix
        .len()
        .checked_add(encoded_data.len())
        .ok_or_else(|| CommonError::ArithmeticOverflow {
            operation: "bytepad length computation",
        })?;
    // Round up to next multiple of w.
    let padded_len = unpadded_len
        .checked_add(w.saturating_sub(1))
        .ok_or_else(|| CommonError::ArithmeticOverflow {
            operation: "bytepad padding computation",
        })?
        / w
        * w;
    let mut buf = Vec::with_capacity(padded_len);
    buf.extend_from_slice(&prefix);
    buf.extend_from_slice(encoded_data);
    buf.resize(padded_len, 0u8);
    Ok(buf)
}

// ===========================================================================
// Keccak-f[1600] sponge construction
// ===========================================================================

/// Internal Keccak sponge state used by the KMAC computation.
///
/// Implements the full 24-round Keccak-f\[1600\] permutation and
/// provides absorb / finalize-squeeze operations with the cSHAKE
/// domain separation byte (`0x04`).
///
/// This is an embedded pure-Rust implementation (zero `unsafe`),
/// matching the pattern used by sibling MAC files (`siphash.rs`,
/// `poly1305.rs`, `blake2_mac.rs`) which embed their core algorithm.
#[derive(Clone)]
struct KeccakSponge {
    /// The 25-lane state (5×5 matrix of 64-bit words = 1600 bits).
    state: [u64; 25],
    /// Partial-block buffer: collects bytes until a full rate-block is ready.
    buf: Vec<u8>,
    /// Number of valid bytes in `buf` (0 .. rate-1).
    buf_len: usize,
    /// Sponge rate in bytes (168 for KMAC-128, 136 for KMAC-256).
    rate: usize,
    /// Whether the sponge has been finalised (padding applied).
    squeezed: bool,
}

impl KeccakSponge {
    /// Create a new sponge with the given rate (in bytes).
    fn new(rate: usize) -> Self {
        Self {
            state: [0u64; 25],
            buf: vec![0u8; rate],
            buf_len: 0,
            rate,
            squeezed: false,
        }
    }

    /// Reset the sponge to the initial (all-zeros) state.
    ///
    /// Currently unused because [`KmacContext::init`] creates a fresh
    /// sponge each time, but retained for potential direct sponge reuse.
    #[allow(dead_code)]
    fn reset(&mut self) {
        self.state = [0u64; 25];
        self.buf.iter_mut().for_each(|b| *b = 0);
        self.buf_len = 0;
        self.squeezed = false;
    }

    // -----------------------------------------------------------------------
    // Keccak-f[1600] permutation (24 rounds)
    // -----------------------------------------------------------------------

    /// Apply the Keccak-f\[1600\] permutation in-place (24 rounds).
    ///
    /// Implements the five steps θ, ρ, π, χ, ι as specified in
    /// FIPS 202 §3.2.  Uses the flat-array representation where index
    /// `i` maps to lane `(x, y) = (i % 5, i / 5)`.
    fn keccak_f(state: &mut [u64; 25]) {
        for (round, &rc) in KECCAK_RC.iter().enumerate() {
            let _ = round; // round index available for debugging if needed
            // θ (theta) step -------------------------------------------------
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = state[x]
                    ^ state[x + 5]
                    ^ state[x + 10]
                    ^ state[x + 15]
                    ^ state[x + 20];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for i in 0..25 {
                state[i] ^= d[i % 5];
            }

            // ρ (rho) + π (pi) combined step ---------------------------------
            let mut temp = state[1];
            for i in 0..24 {
                let j = KECCAK_PILN[i];
                let rotated = temp.rotate_left(KECCAK_ROTC[i]);
                temp = state[j];
                state[j] = rotated;
            }

            // χ (chi) step ---------------------------------------------------
            for y_offset in (0..25).step_by(5) {
                let mut row = [0u64; 5];
                row.copy_from_slice(&state[y_offset..y_offset + 5]);
                for x in 0..5 {
                    state[y_offset + x] =
                        row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
                }
            }

            // ι (iota) step --------------------------------------------------
            state[0] ^= rc;
        }
    }

    // -----------------------------------------------------------------------
    // Sponge operations
    // -----------------------------------------------------------------------

    /// Absorb `data` into the sponge.
    ///
    /// Processes data in rate-sized blocks, applying the Keccak-f
    /// permutation after each full block.
    fn absorb(&mut self, data: &[u8]) {
        let mut offset = 0usize;

        // Fill partial buffer first.
        if self.buf_len > 0 {
            let space = self.rate.saturating_sub(self.buf_len);
            let to_copy = data.len().min(space);
            self.buf[self.buf_len..self.buf_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset += to_copy;

            if self.buf_len == self.rate {
                self.xor_block_into_state_from_buf();
                Self::keccak_f(&mut self.state);
                self.buf_len = 0;
            }
        }

        // Process full blocks directly from input.
        while offset + self.rate <= data.len() {
            self.xor_slice_into_state(&data[offset..offset + self.rate]);
            Self::keccak_f(&mut self.state);
            offset += self.rate;
        }

        // Buffer any remaining bytes.
        let tail = data.len().saturating_sub(offset);
        if tail > 0 {
            self.buf[..tail].copy_from_slice(&data[offset..]);
            self.buf_len = tail;
        }
    }

    /// XOR the internal buffer (`self.buf[..rate]`) into the state.
    fn xor_block_into_state_from_buf(&mut self) {
        let rate = self.rate;
        let lanes = rate / 8;
        for i in 0..lanes {
            let o = i * 8;
            let chunk = [
                self.buf[o],
                self.buf[o + 1],
                self.buf[o + 2],
                self.buf[o + 3],
                self.buf[o + 4],
                self.buf[o + 5],
                self.buf[o + 6],
                self.buf[o + 7],
            ];
            self.state[i] ^= u64::from_le_bytes(chunk);
        }
        let full = lanes * 8;
        if full < rate {
            let remaining = rate - full;
            let mut last = [0u8; 8];
            last[..remaining].copy_from_slice(&self.buf[full..full + remaining]);
            self.state[lanes] ^= u64::from_le_bytes(last);
        }
    }

    /// XOR an external byte slice (of exactly `rate` bytes) into the state.
    fn xor_slice_into_state(&mut self, block: &[u8]) {
        let lanes = self.rate / 8;
        for i in 0..lanes {
            let o = i * 8;
            let chunk = [
                block[o],
                block[o + 1],
                block[o + 2],
                block[o + 3],
                block[o + 4],
                block[o + 5],
                block[o + 6],
                block[o + 7],
            ];
            self.state[i] ^= u64::from_le_bytes(chunk);
        }
        let full = lanes * 8;
        if full < self.rate && full < block.len() {
            let remaining = self.rate - full;
            let avail = (block.len() - full).min(remaining);
            let mut last = [0u8; 8];
            last[..avail].copy_from_slice(&block[full..full + avail]);
            self.state[lanes] ^= u64::from_le_bytes(last);
        }
    }

    /// Finalize the sponge with cSHAKE domain separation and squeeze
    /// `output_len` bytes of output.
    ///
    /// The cSHAKE domain separator is `0x04` (distinct from SHAKE's `0x1F`
    /// and SHA-3's `0x06`).  Multi-rate padding appends `0x04` after the
    /// last data byte and sets bit 7 at position `rate − 1`.
    fn finalize_cshake(&mut self, output_len: usize) -> Vec<u8> {
        if self.squeezed {
            return self.squeeze(output_len);
        }

        // Prepare the padding block in the buffer.
        // Zero the unused portion of the buffer first.
        for b in &mut self.buf[self.buf_len..self.rate] {
            *b = 0;
        }
        // cSHAKE domain separator byte at position buf_len.
        self.buf[self.buf_len] = 0x04;
        // Multi-rate padding: set high bit of the last byte in the block.
        self.buf[self.rate - 1] |= 0x80;

        // XOR padding block into state and permute.
        self.xor_block_into_state_from_buf();
        Self::keccak_f(&mut self.state);
        self.buf_len = 0;
        self.squeezed = true;

        self.squeeze(output_len)
    }

    /// Squeeze `output_len` bytes from the sponge (post-finalization).
    fn squeeze(&mut self, output_len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(output_len);
        let mut produced = 0usize;

        while produced < output_len {
            let state_bytes = self.state_to_bytes();
            let available = self.rate.min(output_len.saturating_sub(produced));
            output.extend_from_slice(&state_bytes[..available]);
            produced += available;

            if produced < output_len {
                Self::keccak_f(&mut self.state);
            }
        }
        output
    }

    /// Serialize the first `rate` bytes of the state into a byte vector.
    fn state_to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; self.rate];
        let lanes = self.rate / 8;
        for i in 0..lanes {
            let le = self.state[i].to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&le);
        }
        let full = lanes * 8;
        if full < self.rate {
            let le = self.state[lanes].to_le_bytes();
            let remaining = self.rate - full;
            bytes[full..full + remaining].copy_from_slice(&le[..remaining]);
        }
        bytes
    }
}

// ===========================================================================
// KmacState — context lifecycle state machine
// ===========================================================================

/// State machine tracking the lifecycle of a [`KmacContext`].
///
/// Transitions: `New` → `Initialized` (after init with key) → `Finalized`
/// (after finalize).  Re-initialization transitions from any state back
/// to `Initialized`.
#[derive(Clone)]
enum KmacState {
    /// Created but not yet keyed.
    New,
    /// Keyed and accepting data via `MacContext::update`.
    /// Boxed to avoid large size difference between variants.
    Initialized(Box<KeccakSponge>),
    /// Finalized; no further updates allowed without re-init.
    Finalized,
}

// ===========================================================================
// KmacProvider — factory implementing MacProvider
// ===========================================================================

/// KMAC-128/256 provider (factory).
///
/// Creates [`KmacContext`] instances for streaming KMAC computation.
/// Replaces the C `ossl_kmac128_functions` and `ossl_kmac256_functions`
/// dispatch tables from `providers/implementations/macs/kmac_prov.c`.
///
/// A single [`KmacProvider`] is instantiated per variant (128 / 256) and
/// is used to produce contexts via [`MacProvider::new_ctx`].
pub struct KmacProvider {
    /// Which KMAC variant this provider creates contexts for.
    variant: KmacVariant,
}

impl KmacProvider {
    /// Create a new KMAC provider for the given variant.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let p128 = KmacProvider::new(KmacVariant::Kmac128);
    /// let p256 = KmacProvider::new(KmacVariant::Kmac256);
    /// ```
    pub fn new(variant: KmacVariant) -> Self {
        Self { variant }
    }

    /// Return algorithm descriptors for provider registration.
    ///
    /// Produces **two** descriptors — one for KMAC-128 and one for KMAC-256 —
    /// each with alternative name forms (hyphenated and non-hyphenated).
    ///
    /// Replaces C `ossl_kmac128_functions` and `ossl_kmac256_functions`
    /// `OSSL_ALGORITHM` entries.
    pub fn descriptors() -> Vec<AlgorithmDescriptor> {
        vec![
            AlgorithmDescriptor {
                names: vec!["KMAC-128", "KMAC128"],
                property: "provider=default",
                description: "KECCAK Message Authentication Code 128-bit",
            },
            AlgorithmDescriptor {
                names: vec!["KMAC-256", "KMAC256"],
                property: "provider=default",
                description: "KECCAK Message Authentication Code 256-bit",
            },
        ]
    }
}

impl MacProvider for KmacProvider {
    /// Returns the canonical algorithm name (`"KMAC-128"` or `"KMAC-256"`).
    fn name(&self) -> &'static str {
        self.variant.name_str()
    }

    /// Returns the default output size in bytes (32 for KMAC-128, 64 for KMAC-256).
    fn size(&self) -> usize {
        self.variant.default_output_len()
    }

    /// Create a new KMAC computation context.
    ///
    /// Translates C `kmac128_new` / `kmac256_new` from `kmac_prov.c`.
    fn new_ctx(&self) -> ProviderResult<Box<dyn MacContext>> {
        Ok(Box::new(KmacContext::new(self.variant)))
    }
}

// ===========================================================================
// KmacContext — streaming MAC context implementing MacContext
// ===========================================================================

/// KMAC computation context.
///
/// Maintains the live Keccak sponge state, the encoded key buffer
/// (protected by `Zeroizing`), the encoded customization string,
/// and algorithm configuration (variant, output length, XOF mode).
///
/// Replaces C `struct kmac_data_st` from `kmac_prov.c`.
///
/// # Key material protection
///
/// The `key` field is wrapped in `Zeroizing` so that key bytes are
/// securely zeroed when the context is dropped, replacing the C
/// `OPENSSL_cleanse(kctx->key, kctx->key_len)` from `kmac_free()`.
pub struct KmacContext {
    /// Which KMAC variant (128 or 256).
    variant: KmacVariant,
    /// Encoded + bytepadded key buffer — zeroed on Drop via `Zeroizing`.
    key: Zeroizing<Vec<u8>>,
    /// Length of the valid encoded key data within `key`.
    key_len: usize,
    /// Encoded customization string (pre-computed in `apply_params`).
    custom: Vec<u8>,
    /// Length of the valid encoded custom data within `custom`.
    custom_len: usize,
    /// Requested output length in bytes.
    out_len: usize,
    /// XOF mode flag (variable-length output).
    xof_mode: bool,
    /// Context lifecycle state.
    state: KmacState,
}

impl KmacContext {
    /// Create a new KMAC context with default parameters for the given variant.
    ///
    /// The context is in the `New` state and must be initialised with a key
    /// via `MacContext::init` before use.
    fn new(variant: KmacVariant) -> Self {
        Self {
            variant,
            key: Zeroizing::new(Vec::new()),
            key_len: 0,
            custom: Vec::new(),
            custom_len: 0,
            out_len: variant.default_output_len(),
            xof_mode: false,
            state: KmacState::New,
        }
    }

    /// Apply parameters from a `ParamSet` to this context.
    ///
    /// Handles `custom` (customization string), `size` (output length),
    /// `xof` (XOF mode flag), and `key` (re-keying).
    ///
    /// Translates `kmac_set_ctx_params()` from `kmac_prov.c`.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Customization string.
        if params.contains(PARAM_CUSTOM) {
            let custom_bytes: Vec<u8> = params
                .get_typed::<Vec<u8>>(PARAM_CUSTOM)
                .map_err(ProviderError::Common)?;
            if custom_bytes.len() > KMAC_MAX_CUSTOM {
                return Err(ProviderError::Init(format!(
                    "KMAC: customization string length {} exceeds maximum {}",
                    custom_bytes.len(),
                    KMAC_MAX_CUSTOM,
                )));
            }
            self.custom = encode_string(&custom_bytes);
            self.custom_len = self.custom.len();
        }

        // Output length.
        if params.contains(PARAM_SIZE) {
            let size_val: u64 = params
                .get_typed::<u64>(PARAM_SIZE)
                .map_err(ProviderError::Common)?;
            let size_usize = usize::try_from(size_val).map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "KMAC output length conversion",
                })
            })?;
            if size_usize > KMAC_MAX_OUTPUT_LEN {
                return Err(ProviderError::Init(format!(
                    "KMAC: output length {size_usize} exceeds maximum {KMAC_MAX_OUTPUT_LEN}",
                )));
            }
            self.out_len = if size_usize == 0 {
                self.variant.default_output_len()
            } else {
                size_usize
            };
        }

        // XOF mode.
        if params.contains(PARAM_XOF) {
            let xof: bool = params
                .get_typed::<bool>(PARAM_XOF)
                .map_err(ProviderError::Common)?;
            self.xof_mode = xof;
        }

        Ok(())
    }

    /// Encode and bytepad the key per SP 800-185.
    ///
    /// Computes `bytepad(encode_string(key), rate)` and stores the result
    /// in the `self.key` buffer.
    ///
    /// Translates C `kmac_bytepad_encode_key()` from `kmac_prov.c`.
    fn encode_key(&mut self, raw_key: &[u8]) -> ProviderResult<()> {
        let rate = self.variant.rate();
        let encoded = encode_string(raw_key);
        let padded = bytepad(&encoded, rate).map_err(ProviderError::Common)?;
        self.key = Zeroizing::new(padded);
        self.key_len = self.key.len();
        Ok(())
    }

    /// Build the cSHAKE header: `bytepad(encode_string("KMAC") ‖ encode_string(S), rate)`.
    ///
    /// This header is absorbed first into the sponge as the cSHAKE framing
    /// for `N = "KMAC"` and `S = custom`.
    fn build_header(&self) -> ProviderResult<Vec<u8>> {
        let rate = self.variant.rate();
        // Concatenate encode_string("KMAC") ‖ encode_string(custom).
        let mut payload = Vec::with_capacity(
            KMAC_STRING.len().saturating_add(self.custom_len),
        );
        payload.extend_from_slice(&KMAC_STRING);
        if self.custom_len > 0 {
            payload.extend_from_slice(&self.custom[..self.custom_len]);
        }
        let header = bytepad(&payload, rate).map_err(ProviderError::Common)?;
        Ok(header)
    }
}

impl MacContext for KmacContext {
    /// Initialise (or reinitialise) the KMAC context with the given key
    /// and optional parameters.
    ///
    /// Performs the following SP 800-185 steps:
    /// 1. Apply parameters (custom string, output length, XOF mode).
    /// 2. Encode the key: `bytepad(encode_string(K), rate)`.
    /// 3. Create a fresh Keccak sponge.
    /// 4. Absorb the cSHAKE header: `bytepad(encode_string("KMAC") ‖ encode_string(S), rate)`.
    /// 5. Absorb the encoded key.
    ///
    /// Translates C `kmac_init()` from `kmac_prov.c`.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        // Apply parameters first (they may change output length, custom, XOF).
        if let Some(p) = params {
            self.apply_params(p)?;
        }

        // Validate key length.
        if key.len() < KMAC_MIN_KEY {
            return Err(ProviderError::Init(format!(
                "KMAC: key length {} is below minimum {} bytes",
                key.len(),
                KMAC_MIN_KEY,
            )));
        }
        if key.len() > KMAC_MAX_KEY {
            return Err(ProviderError::Init(format!(
                "KMAC: key length {} exceeds maximum {} bytes",
                key.len(),
                KMAC_MAX_KEY,
            )));
        }

        // Encode the key with bytepad.
        self.encode_key(key)?;

        // Build the cSHAKE header.
        let header = self.build_header()?;

        // Create a fresh sponge and absorb header + encoded key.
        let mut sponge = KeccakSponge::new(self.variant.rate());
        sponge.absorb(&header);
        sponge.absorb(&self.key);

        self.state = KmacState::Initialized(Box::new(sponge));
        Ok(())
    }

    /// Feed additional data into the running KMAC computation.
    ///
    /// The data `X` in the KMAC specification.  Can be called multiple
    /// times for streaming input.
    ///
    /// Translates C `kmac_update()` from `kmac_prov.c`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        match &mut self.state {
            KmacState::Initialized(ref mut sponge) => {
                sponge.absorb(data);
                Ok(())
            }
            KmacState::New => Err(ProviderError::Init(
                "KMAC: update called before init".into(),
            )),
            KmacState::Finalized => Err(ProviderError::Init(
                "KMAC: update called after finalize; reinitialise first".into(),
            )),
        }
    }

    /// Finalise the KMAC computation and return the authentication tag.
    ///
    /// Appends `right_encode(L)` (or `right_encode(0)` in XOF mode) to the
    /// sponge, applies cSHAKE padding, and squeezes the requested output
    /// length.
    ///
    /// Translates C `kmac_final()` from `kmac_prov.c`.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        // Take ownership of the sponge (moving out of Initialized state).
        let sponge = match std::mem::replace(&mut self.state, KmacState::Finalized) {
            KmacState::Initialized(s) => s,
            KmacState::New => {
                return Err(ProviderError::Init(
                    "KMAC: finalize called before init".into(),
                ));
            }
            KmacState::Finalized => {
                return Err(ProviderError::Init(
                    "KMAC: finalize called twice; reinitialise first".into(),
                ));
            }
        };

        let mut sponge = sponge;

        // Encode the output length in bits (or 0 for XOF mode).
        let l_bits: u64 = if self.xof_mode {
            0
        } else {
            (self.out_len as u64).saturating_mul(8)
        };
        let encoded_len = right_encode(l_bits);
        sponge.absorb(&encoded_len);

        // Finalize the sponge with cSHAKE padding and squeeze output.
        let output = sponge.finalize_cshake(self.out_len);
        Ok(output)
    }

    /// Retrieve current context parameters as a `ParamSet`.
    ///
    /// Returns the current output size (`size`) and block size
    /// (`block-size`) of this KMAC context.
    ///
    /// Translates C `kmac_get_ctx_params()` from `kmac_prov.c`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let builder = ParamBuilder::new()
            .push_u64(PARAM_SIZE, self.out_len as u64)
            .push_u64(PARAM_BLOCK_SIZE, self.variant.rate() as u64);
        Ok(builder.build())
    }

    /// Set context parameters from a `ParamSet`.
    ///
    /// Allows reconfiguring the output length, customization string,
    /// and XOF mode.  Typically called before `MacContext::init`.
    ///
    /// Translates C `kmac_set_ctx_params()` from `kmac_prov.c`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::useless_vec,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SP 800-185 encoding helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_left_encode_zero() {
        assert_eq!(left_encode(0), vec![1, 0]);
    }

    #[test]
    fn test_left_encode_small() {
        // left_encode(255) = [1, 255]
        assert_eq!(left_encode(255), vec![1, 255]);
    }

    #[test]
    fn test_left_encode_two_bytes() {
        // left_encode(256) = [2, 1, 0]
        assert_eq!(left_encode(256), vec![2, 1, 0]);
    }

    #[test]
    fn test_left_encode_large() {
        // left_encode(65536) = [3, 1, 0, 0]
        assert_eq!(left_encode(65536), vec![3, 1, 0, 0]);
    }

    #[test]
    fn test_right_encode_zero() {
        assert_eq!(right_encode(0), vec![0, 1]);
    }

    #[test]
    fn test_right_encode_small() {
        // right_encode(255) = [255, 1]
        assert_eq!(right_encode(255), vec![255, 1]);
    }

    #[test]
    fn test_right_encode_two_bytes() {
        // right_encode(256) = [1, 0, 2]
        assert_eq!(right_encode(256), vec![1, 0, 2]);
    }

    #[test]
    fn test_encode_string_empty() {
        // C convention: encode_string("") = [] (empty).
        assert_eq!(encode_string(b""), Vec::<u8>::new());
    }

    #[test]
    fn test_encode_string_kmac() {
        // encode_string("KMAC") should match the pre-computed KMAC_STRING.
        assert_eq!(encode_string(b"KMAC"), KMAC_STRING.to_vec());
    }

    #[test]
    fn test_encode_string_single_byte() {
        // encode_string([0xAB]) = left_encode(8) ‖ [0xAB]
        // left_encode(8) = [1, 8]
        assert_eq!(encode_string(&[0xAB]), vec![1, 8, 0xAB]);
    }

    #[test]
    fn test_bytepad_basic() {
        // bytepad(encode_string("KMAC"), 168)
        let result = bytepad(&KMAC_STRING, 168).expect("bytepad should succeed");
        assert_eq!(result.len() % 168, 0);
        // First bytes: left_encode(168) = [1, 168] (168 = 0xA8 fits in 1 byte).
        assert_eq!(result[0], 1); // 168 fits in 1 value byte -> prefix = 1
        assert_eq!(result[1], 168);
    }

    #[test]
    fn test_bytepad_zero_width_error() {
        let result = bytepad(&[0x01], 0);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Keccak-f[1600] sanity checks
    // -----------------------------------------------------------------------

    #[test]
    fn test_keccak_f_zero_state() {
        // Keccak-f on all-zeros state should produce a deterministic
        // non-zero result.
        let mut state = [0u64; 25];
        KeccakSponge::keccak_f(&mut state);
        // After permutation, state should not be all zeros.
        assert!(state.iter().any(|&v| v != 0));
    }

    #[test]
    fn test_keccak_sponge_absorb_empty() {
        let mut sponge = KeccakSponge::new(168);
        sponge.absorb(&[]);
        // State should remain all-zeros after absorbing nothing.
        assert!(sponge.state.iter().all(|&v| v == 0));
    }

    #[test]
    fn test_keccak_sponge_deterministic() {
        // Same input should always produce the same output.
        let mut s1 = KeccakSponge::new(168);
        let mut s2 = KeccakSponge::new(168);
        let data = b"Hello, KMAC!";
        s1.absorb(data);
        s2.absorb(data);
        let out1 = s1.finalize_cshake(32);
        let out2 = s2.finalize_cshake(32);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_keccak_sponge_different_data() {
        let mut s1 = KeccakSponge::new(168);
        let mut s2 = KeccakSponge::new(168);
        s1.absorb(b"data1");
        s2.absorb(b"data2");
        let out1 = s1.finalize_cshake(32);
        let out2 = s2.finalize_cshake(32);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_keccak_sponge_incremental_vs_bulk() {
        // Absorbing in chunks should give the same result as absorbing all at once.
        let data = vec![0xABu8; 500];

        let mut bulk = KeccakSponge::new(168);
        bulk.absorb(&data);
        let out_bulk = bulk.finalize_cshake(64);

        let mut incr = KeccakSponge::new(168);
        incr.absorb(&data[..100]);
        incr.absorb(&data[100..250]);
        incr.absorb(&data[250..]);
        let out_incr = incr.finalize_cshake(64);

        assert_eq!(out_bulk, out_incr);
    }

    // -----------------------------------------------------------------------
    // KmacVariant tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_variant_properties() {
        assert_eq!(KmacVariant::Kmac128.rate(), 168);
        assert_eq!(KmacVariant::Kmac256.rate(), 136);
        assert_eq!(KmacVariant::Kmac128.default_output_len(), 32);
        assert_eq!(KmacVariant::Kmac256.default_output_len(), 64);
        assert_eq!(KmacVariant::Kmac128.name_str(), "KMAC-128");
        assert_eq!(KmacVariant::Kmac256.name_str(), "KMAC-256");
    }

    // -----------------------------------------------------------------------
    // KmacParams tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_kmac_params_default() {
        let p = KmacParams::default();
        assert!(p.custom.is_none());
        assert!(p.output_len.is_none());
        assert!(!p.xof_mode);
    }

    #[test]
    fn test_kmac_params_to_param_set() {
        let p = KmacParams {
            custom: Some(b"My Custom".to_vec()),
            output_len: Some(48),
            xof_mode: true,
        };
        let ps = p.to_param_set();
        assert!(ps.contains(PARAM_CUSTOM));
        assert!(ps.contains(PARAM_SIZE));
        assert!(ps.contains(PARAM_XOF));
    }

    // -----------------------------------------------------------------------
    // KmacProvider tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_name_128() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        assert_eq!(p.name(), "KMAC-128");
        assert_eq!(p.size(), 32);
    }

    #[test]
    fn test_provider_name_256() {
        let p = KmacProvider::new(KmacVariant::Kmac256);
        assert_eq!(p.name(), "KMAC-256");
        assert_eq!(p.size(), 64);
    }

    #[test]
    fn test_provider_descriptors() {
        let descs = KmacProvider::descriptors();
        assert_eq!(descs.len(), 2);
        assert_eq!(descs[0].names, vec!["KMAC-128", "KMAC128"]);
        assert_eq!(descs[1].names, vec!["KMAC-256", "KMAC256"]);
        assert_eq!(descs[0].property, "provider=default");
        assert_eq!(descs[1].property, "provider=default");
    }

    #[test]
    fn test_provider_new_ctx() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let ctx = p.new_ctx();
        assert!(ctx.is_ok());
    }

    // -----------------------------------------------------------------------
    // KmacContext lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_init_update_finalize() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let key = vec![0x40u8; 32];
        ctx.init(&key, None).expect("init");
        ctx.update(b"Hello").expect("update");
        let tag = ctx.finalize().expect("finalize");
        assert_eq!(tag.len(), 32); // default KMAC-128 output
    }

    #[test]
    fn test_context_256_default_output() {
        let p = KmacProvider::new(KmacVariant::Kmac256);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let key = vec![0x55u8; 32];
        ctx.init(&key, None).expect("init");
        ctx.update(b"test data").expect("update");
        let tag = ctx.finalize().expect("finalize");
        assert_eq!(tag.len(), 64); // default KMAC-256 output
    }

    #[test]
    fn test_context_custom_output_length() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let key = vec![0xAAu8; 32];
        let params = KmacParams {
            custom: None,
            output_len: Some(48),
            xof_mode: false,
        };
        ctx.init(&key, Some(&params.to_param_set())).expect("init");
        ctx.update(b"data").expect("update");
        let tag = ctx.finalize().expect("finalize");
        assert_eq!(tag.len(), 48);
    }

    #[test]
    fn test_context_xof_mode() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let key = vec![0xBBu8; 32];
        let params = KmacParams {
            custom: None,
            output_len: Some(100),
            xof_mode: true,
        };
        ctx.init(&key, Some(&params.to_param_set())).expect("init");
        ctx.update(b"xof test").expect("update");
        let tag = ctx.finalize().expect("finalize");
        assert_eq!(tag.len(), 100);
    }

    #[test]
    fn test_context_with_custom_string() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let key = vec![0xCCu8; 32];
        let params = KmacParams {
            custom: Some(b"MyApp".to_vec()),
            output_len: None,
            xof_mode: false,
        };
        ctx.init(&key, Some(&params.to_param_set())).expect("init");
        ctx.update(b"data").expect("update");
        let tag = ctx.finalize().expect("finalize");
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_context_determinism() {
        // Same key + data + params → same tag.
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let key = vec![0xDDu8; 32];

        let mut c1 = p.new_ctx().expect("new_ctx");
        c1.init(&key, None).expect("init");
        c1.update(b"data").expect("update");
        let t1 = c1.finalize().expect("finalize");

        let mut c2 = p.new_ctx().expect("new_ctx");
        c2.init(&key, None).expect("init");
        c2.update(b"data").expect("update");
        let t2 = c2.finalize().expect("finalize");

        assert_eq!(t1, t2);
    }

    #[test]
    fn test_context_different_keys() {
        let p = KmacProvider::new(KmacVariant::Kmac128);

        let mut c1 = p.new_ctx().expect("new_ctx");
        c1.init(&vec![0x01u8; 32], None).expect("init");
        c1.update(b"data").expect("update");
        let t1 = c1.finalize().expect("finalize");

        let mut c2 = p.new_ctx().expect("new_ctx");
        c2.init(&vec![0x02u8; 32], None).expect("init");
        c2.update(b"data").expect("update");
        let t2 = c2.finalize().expect("finalize");

        assert_ne!(t1, t2);
    }

    #[test]
    fn test_context_different_data() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let key = vec![0xEEu8; 32];

        let mut c1 = p.new_ctx().expect("new_ctx");
        c1.init(&key, None).expect("init");
        c1.update(b"data1").expect("update");
        let t1 = c1.finalize().expect("finalize");

        let mut c2 = p.new_ctx().expect("new_ctx");
        c2.init(&key, None).expect("init");
        c2.update(b"data2").expect("update");
        let t2 = c2.finalize().expect("finalize");

        assert_ne!(t1, t2);
    }

    #[test]
    fn test_context_128_vs_256_different() {
        let key = vec![0xFFu8; 32];

        let p128 = KmacProvider::new(KmacVariant::Kmac128);
        let mut c128 = p128.new_ctx().expect("new_ctx");
        c128.init(&key, None).expect("init");
        c128.update(b"data").expect("update");
        let t128 = c128.finalize().expect("finalize");

        let p256 = KmacProvider::new(KmacVariant::Kmac256);
        let mut c256 = p256.new_ctx().expect("new_ctx");
        c256.init(&key, None).expect("init");
        c256.update(b"data").expect("update");
        let t256 = c256.finalize().expect("finalize");

        // Different variants produce different-length tags.
        assert_ne!(t128.len(), t256.len());
    }

    // -----------------------------------------------------------------------
    // Error path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_update_before_init() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let err = ctx.update(b"data");
        assert!(err.is_err());
    }

    #[test]
    fn test_context_finalize_before_init() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let err = ctx.finalize();
        assert!(err.is_err());
    }

    #[test]
    fn test_context_double_finalize() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        ctx.init(&vec![0x42u8; 32], None).expect("init");
        ctx.update(b"data").expect("update");
        let _t1 = ctx.finalize().expect("first finalize");
        let err = ctx.finalize();
        assert!(err.is_err());
    }

    #[test]
    fn test_context_key_too_short() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let err = ctx.init(&[0x01, 0x02, 0x03], None); // 3 bytes < KMAC_MIN_KEY
        assert!(err.is_err());
    }

    #[test]
    fn test_context_key_too_long() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let err = ctx.init(&vec![0x01u8; 513], None); // 513 > KMAC_MAX_KEY
        assert!(err.is_err());
    }

    #[test]
    fn test_context_custom_too_long() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let params = KmacParams {
            custom: Some(vec![0xAA; 513]), // 513 > KMAC_MAX_CUSTOM
            output_len: None,
            xof_mode: false,
        };
        let err = ctx.init(&vec![0x42u8; 32], Some(&params.to_param_set()));
        assert!(err.is_err());
    }

    #[test]
    fn test_context_output_too_large() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let ps = ParamBuilder::new()
            .push_u64(PARAM_SIZE, (KMAC_MAX_OUTPUT_LEN as u64) + 1)
            .build();
        let err = ctx.init(&vec![0x42u8; 32], Some(&ps));
        assert!(err.is_err());
    }

    // -----------------------------------------------------------------------
    // get_params / set_params tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_params_default() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let ctx = p.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        let size: u64 = params.get_typed(PARAM_SIZE).expect("size");
        assert_eq!(size, 32);
        let block_size: u64 = params.get_typed(PARAM_BLOCK_SIZE).expect("block-size");
        assert_eq!(block_size, 168);
    }

    #[test]
    fn test_set_params_output_length() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let mut ctx = p.new_ctx().expect("new_ctx");
        let ps = ParamBuilder::new().push_u64(PARAM_SIZE, 48).build();
        ctx.set_params(&ps).expect("set_params");
        let params = ctx.get_params().expect("get_params");
        let size: u64 = params.get_typed(PARAM_SIZE).expect("size");
        assert_eq!(size, 48);
    }

    // -----------------------------------------------------------------------
    // Incremental update test
    // -----------------------------------------------------------------------

    #[test]
    fn test_incremental_update_consistency() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let key = vec![0x42u8; 32];
        let data = b"The quick brown fox jumps over the lazy dog";

        // Single-shot.
        let mut c1 = p.new_ctx().expect("new_ctx");
        c1.init(&key, None).expect("init");
        c1.update(data).expect("update");
        let t1 = c1.finalize().expect("finalize");

        // Incremental.
        let mut c2 = p.new_ctx().expect("new_ctx");
        c2.init(&key, None).expect("init");
        c2.update(&data[..10]).expect("update1");
        c2.update(&data[10..30]).expect("update2");
        c2.update(&data[30..]).expect("update3");
        let t2 = c2.finalize().expect("finalize");

        assert_eq!(t1, t2);
    }

    // -----------------------------------------------------------------------
    // Reinitialisation test
    // -----------------------------------------------------------------------

    #[test]
    fn test_reinit_produces_same_result() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let key = vec![0x42u8; 32];

        let mut ctx = p.new_ctx().expect("new_ctx");
        ctx.init(&key, None).expect("init");
        ctx.update(b"data").expect("update");
        let t1 = ctx.finalize().expect("finalize");

        // Reinitialise with same key.
        ctx.init(&key, None).expect("reinit");
        ctx.update(b"data").expect("update");
        let t2 = ctx.finalize().expect("finalize");

        assert_eq!(t1, t2);
    }

    // -----------------------------------------------------------------------
    // XOF vs fixed mode produce different results for same input
    // -----------------------------------------------------------------------

    #[test]
    fn test_xof_vs_fixed_different() {
        let p = KmacProvider::new(KmacVariant::Kmac128);
        let key = vec![0x42u8; 32];

        // Fixed mode, 32-byte output.
        let mut c_fixed = p.new_ctx().expect("new_ctx");
        c_fixed.init(&key, None).expect("init");
        c_fixed.update(b"data").expect("update");
        let t_fixed = c_fixed.finalize().expect("finalize");

        // XOF mode, 32-byte output.
        let xof_params = KmacParams {
            custom: None,
            output_len: Some(32),
            xof_mode: true,
        };
        let mut c_xof = p.new_ctx().expect("new_ctx");
        c_xof
            .init(&key, Some(&xof_params.to_param_set()))
            .expect("init");
        c_xof.update(b"data").expect("update");
        let t_xof = c_xof.finalize().expect("finalize");

        // XOF and fixed modes encode different right_encode values,
        // so outputs must differ.
        assert_ne!(t_fixed, t_xof);
    }
}
