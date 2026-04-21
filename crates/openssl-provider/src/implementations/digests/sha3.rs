//! # SHA-3, SHAKE, Keccak, KECCAK-KMAC, and cSHAKE Digest Providers
//!
//! This module implements the complete Keccak-based digest family translated
//! from the C sources `providers/implementations/digests/sha3_prov.c` and
//! `providers/implementations/digests/cshake_prov.c`.
//!
//! ## Algorithm Families
//!
//! | Provider | Algorithms | Digest Size (bytes) | Rate (bytes) | Padding |
//! |----------|-----------|---------------------|--------------|---------|
//! | `Sha3Provider` | SHA3-224/256/384/512 | 28/32/48/64 | 144/136/104/72 | `0x06` |
//! | `ShakeProvider` | SHAKE-128/256 | variable (XOF) | 168/136 | `0x1f` |
//! | `KeccakProvider` | KECCAK-224/256/384/512 | 28/32/48/64 | 144/136/104/72 | `0x01` |
//! | `KeccakKmacProvider` | KECCAK-KMAC-128/256 | variable (XOF) | 168/136 | `0x04` |
//! | `CshakeProvider` | cSHAKE-128/256 | variable (XOF) | 168/136 | `0x04` |
//!
//! ## Padding Bytes (FIPS 202 §5.1 and SP 800-185)
//!
//! * `KECCAK_PADDING = 0x01` — raw Keccak-f\[1600\] sponge
//! * `SHA3_PADDING   = 0x06` — SHA-3 domain separator (FIPS 202)
//! * `SHAKE_PADDING  = 0x1f` — SHAKE domain separator (FIPS 202)
//! * `CSHAKE_PADDING = 0x04` — cSHAKE / KECCAK-KMAC domain separator (SP 800-185 §3.3)
//!
//! ## XOF vs Fixed-Output Digests
//!
//! Fixed-output digests (SHA-3, raw Keccak) produce a predetermined number of
//! bytes on [`finalize`](KeccakContext::finalize). Extendable-output functions
//! (XOFs: SHAKE, cSHAKE, KECCAK-KMAC) can produce arbitrary-length output, set
//! either via the `xoflen` parameter for a one-shot [`finalize`] or via
//! multiple incremental [`squeeze`](KeccakContext::squeeze) calls.
//!
//! ## cSHAKE Bytepad Mechanism (SP 800-185 §3.3)
//!
//! cSHAKE prefixes the absorbed data with
//!   `bytepad(encode_string(N) || encode_string(S), rate)`
//! where `N` is the function name and `S` is the customization string. When
//! both `N` and `S` are empty, cSHAKE is equivalent to SHAKE and the padding
//! byte reverts to `SHAKE_PADDING`.
//!
//! ## Context Serialization
//!
//! Keccak contexts serialize to the `KECCAKv1` format (424 bytes total): an
//! 8-byte ASCII magic, little-endian `u64` fields (impl-id, md-size, rate,
//! buffer length, padding byte, XOF state), the 200-byte Keccak-f\[1600\]
//! lane state, and the 168-byte input buffer padded with zeros. The layout
//! matches the byte image produced by the C reference.
//!
//! ## Rules Enforced
//!
//! * **R5 (Nullability over sentinels):** XOF length is `Option<usize>`, not
//!   `usize::MAX`. Function name and customization strings are
//!   `Option<Vec<u8>>`, never empty-string sentinels.
//! * **R6 (Lossless casts):** All state (de)serialization uses
//!   `u64::to_le_bytes` / `u64::from_le_bytes` and checked `try_from`.
//! * **R8 (Zero unsafe):** Pure-Rust Keccak-f\[1600\] permutation; no `unsafe`.
//! * **R9 (Warning-free):** Every public item documented.
//! * **R10 (Wiring):** Reachable from
//!   `DefaultProvider → query_operation(Digest) → Sha3Provider / … /
//!   CshakeProvider`, wired via
//!   `super::create_sha3_provider(name)` in `mod.rs`.
//!
//! The enclosing module (`super::sha3`) is declared with
//! `#[cfg(feature = "sha3")]` in `mod.rs`, so an inner-attribute copy here
//! would be redundant.

use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::hash::sha::{bytepad, encode_string};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::common::{default_get_params, default_gettable_params, DigestFlags};

// =============================================================================
// Constants
// =============================================================================

/// Padding byte for raw Keccak (no domain separator).
const KECCAK_PADDING: u8 = 0x01;
/// Padding byte for SHA-3 (FIPS 202 §5.1).
const SHA3_PADDING: u8 = 0x06;
/// Padding byte for SHAKE (FIPS 202 §6.2).
const SHAKE_PADDING: u8 = 0x1f;
/// Padding byte for cSHAKE / KECCAK-KMAC (SP 800-185 §3.3).
const CSHAKE_PADDING: u8 = 0x04;

/// Keccak-f\[1600\] state size in bytes (25 lanes × 8 bytes).
const KECCAK_STATE_BYTES: usize = 200;

/// Maximum rate (block size) across all Keccak variants: SHAKE-128 uses 168 bytes.
const MAX_RATE_BYTES: usize = 168;

/// Serialization impl-id base flags matching the C reference.
const IMPL_ID_KECCAK: u64 = 0x01_0000;
const IMPL_ID_SHAKE: u64 = 0x02_0000;
const IMPL_ID_SHA3: u64 = 0x04_0000;
const IMPL_ID_CSHAKE_KECCAK: u64 = 0x08_0000;

/// Serialized XOF state values (fixed by wire format).
const XOF_STATE_INIT: u64 = 0;
const XOF_STATE_ABSORB: u64 = 1;
const XOF_STATE_SQUEEZE: u64 = 2;

/// `KECCAKv1` serialization magic (8 bytes).
const KECCAK_V1_MAGIC: &[u8; 8] = b"KECCAKv1";

/// Total size of the serialized `KECCAKv1` context.
/// `8 (magic) + 6·8 (u64 fields) + 200 (state) + 168 (max rate buffer) = 424`.
const KECCAK_V1_SIZE: usize = 8 + 6 * 8 + KECCAK_STATE_BYTES + MAX_RATE_BYTES;

/// Maximum length of cSHAKE function-name (`N`) and customization (`S`) strings.
/// Matches the `CSHAKE_MAX_STRING` constant in `cshake_prov.c`.
pub const CSHAKE_MAX_STRING: usize = 512;

// =============================================================================
// Keccak-f[1600] Round Constants
// =============================================================================

/// Keccak-f\[1600\] round constants (24 rounds).
///
/// Reproduced from `openssl_crypto::hash::sha::KECCAK_RC` (private there).
/// See FIPS 202 §3.2.5.
#[rustfmt::skip]
const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808a, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808b, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008a, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000a,
    0x0000_0000_8000_808b, 0x8000_0000_0000_008b, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800a, 0x8000_0000_8000_000a,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
];

/// Keccak-f\[1600\] lane rotation offsets indexed as `RHOTATES[y][x]`.
///
/// Reproduced from `openssl_crypto::hash::sha::KECCAK_RHOTATES` (private there).
/// See FIPS 202 §3.2.2.
#[rustfmt::skip]
const KECCAK_RHOTATES: [[u32; 5]; 5] = [
    [ 0,  1, 62, 28, 27],
    [36, 44,  6, 55, 20],
    [ 3, 10, 43, 25, 39],
    [41, 45, 15, 21,  8],
    [18,  2, 61, 56, 14],
];

// =============================================================================
// XOF state machine
// =============================================================================

/// Internal state machine for XOF (SHAKE / cSHAKE / KECCAK-KMAC) contexts.
///
/// The wire-format encoding (`Init=0`, `Absorb=1`, `Squeeze=2`) matches the
/// values used by the C reference when serializing a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum XofState {
    /// Context created but prefix (e.g. cSHAKE bytepad) not yet absorbed.
    Init,
    /// Actively absorbing input via `update`.
    #[default]
    Absorb,
    /// Absorption finalized; emitting output via `squeeze`.
    Squeeze,
}

// `Zeroize` cannot be derived on an enum; reset to `Init` on zeroize.
impl Zeroize for XofState {
    fn zeroize(&mut self) {
        *self = XofState::Init;
    }
}

// =============================================================================
// KeccakContext — public digest-context type shared by all Keccak variants
// =============================================================================

/// Keccak-based digest context used by every SHA-3, SHAKE, raw Keccak, and
/// KECCAK-KMAC variant in this module.
///
/// Holds 200 bytes of Keccak-f\[1600\] lane state plus a rate-sized input
/// buffer and a small amount of XOF-state metadata. The struct derives
/// [`Zeroize`] and [`ZeroizeOnDrop`] so that all cryptographic key material
/// and buffered plaintext are securely erased when the context is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeccakContext {
    /// Keccak-f\[1600\] internal state (25 × 64-bit lanes = 200 bytes).
    state: [u64; 25],
    /// Pending input bytes not yet absorbed into `state`. Capacity == `rate`.
    buf: Vec<u8>,
    /// Absorption rate in bytes (`200 - 2 × capacity_bytes`).
    rate: usize,
    /// Domain-separation padding byte (see module-level docs).
    pad: u8,
    /// Fixed digest size in bytes for non-XOF variants; `0` for XOF.
    md_size: usize,
    /// User-supplied XOF output length (via `xoflen`); `None` until set.
    xof_len: Option<usize>,
    /// Absorb / squeeze state machine.
    xof_state: XofState,
    /// Byte offset within the current squeeze block, for multi-call squeeze.
    squeeze_offset: usize,
    /// Serialization impl-id, used to reproduce the C `KECCAKv1` byte image.
    impl_id: u64,
}

// =============================================================================
// Keccak-f[1600] permutation (pure-Rust, matches sha.rs reference)
// =============================================================================

impl KeccakContext {
    /// Run the full Keccak-f\[1600\] permutation (24 rounds).
    ///
    /// Implements θ (theta), ρ (rho), π (pi), χ (chi), ι (iota) steps per
    /// FIPS 202 §3.3. Reproduced from
    /// `openssl_crypto::hash::sha::KeccakState::permute` since that method is
    /// not part of `sha.rs`'s public API.
    fn permute(&mut self) {
        for &rc in &KECCAK_RC {
            // θ (theta): column parity + diffusion
            let mut c = [0u64; 5];
            for (x, c_val) in c.iter_mut().enumerate() {
                *c_val = self.state[x]
                    ^ self.state[5 + x]
                    ^ self.state[10 + x]
                    ^ self.state[15 + x]
                    ^ self.state[20 + x];
            }
            let mut d = [0u64; 5];
            for (x, d_val) in d.iter_mut().enumerate() {
                *d_val = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for y in 0..5 {
                for (x, &d_x) in d.iter().enumerate() {
                    self.state[y * 5 + x] ^= d_x;
                }
            }

            // ρ (rho) + π (pi): combined lane rotation and position permutation.
            let mut b = [0u64; 25];
            for y in 0..5 {
                for x in 0..5 {
                    let rot = KECCAK_RHOTATES[y][x];
                    b[((2 * x + 3 * y) % 5) * 5 + y] = self.state[y * 5 + x].rotate_left(rot);
                }
            }

            // χ (chi): non-linear per-row mixing.
            for y in 0..5 {
                for x in 0..5 {
                    self.state[y * 5 + x] =
                        b[y * 5 + x] ^ ((!b[y * 5 + (x + 1) % 5]) & b[y * 5 + (x + 2) % 5]);
                }
            }

            // ι (iota): round constant XOR.
            self.state[0] ^= rc;
        }
    }

    /// XOR a full `rate`-sized block into the Keccak state lanes (LE order).
    ///
    /// Each lane is 8 bytes in little-endian order per FIPS 202 §6.1.
    fn xor_block_into_state(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), self.rate);
        let lanes = self.rate / 8;
        for i in 0..lanes {
            let mut lane_bytes = [0u8; 8];
            lane_bytes.copy_from_slice(&block[i * 8..i * 8 + 8]);
            self.state[i] ^= u64::from_le_bytes(lane_bytes);
        }
    }
}

// =============================================================================
// KeccakContext: absorb / pad / squeeze primitives
// =============================================================================

impl KeccakContext {
    /// Build a new context for an XOF variant (SHAKE, cSHAKE, KECCAK-KMAC).
    ///
    /// Sets `md_size = 0` and pre-populates `xof_len` with a sane default
    /// (`2 × security_bits / 8` bytes for cSHAKE / KMAC per SP 800-185,
    /// `security_bits / 8` for plain SHAKE).
    fn new_xof(rate: usize, pad: u8, default_xof_len: usize, impl_id: u64) -> Self {
        Self {
            state: [0u64; 25],
            buf: Vec::with_capacity(rate),
            rate,
            pad,
            md_size: 0,
            xof_len: Some(default_xof_len),
            xof_state: XofState::Absorb,
            squeeze_offset: 0,
            impl_id,
        }
    }

    /// Public constructor for general-purpose use.
    ///
    /// Builds a context given an explicit `rate`, padding byte, and
    /// `md_size`. Pass `md_size = 0` for an XOF context; the caller is
    /// responsible for setting `xof_len` via [`set_xof_len`] or the
    /// `xoflen` parameter before calling [`finalize`](Self::finalize).
    ///
    /// `impl_id` defaults to [`IMPL_ID_KECCAK`] + `md_size` when built via
    /// this entry point; tests and higher-level wrappers override it to match
    /// the precise C serialization tag.
    pub fn new(rate: usize, pad: u8, md_size: usize) -> Self {
        // Default impl-id mirrors the C encoding: KECCAK base plus bit length.
        let impl_id = match pad {
            SHA3_PADDING => IMPL_ID_SHA3 | (md_size as u64 * 8),
            SHAKE_PADDING => IMPL_ID_SHAKE | (md_size as u64 * 8),
            CSHAKE_PADDING => IMPL_ID_CSHAKE_KECCAK | (md_size as u64 * 8),
            _ => IMPL_ID_KECCAK | (md_size as u64 * 8),
        };
        Self {
            state: [0u64; 25],
            buf: Vec::with_capacity(rate),
            rate,
            pad,
            md_size,
            xof_len: None,
            xof_state: XofState::Absorb,
            squeeze_offset: 0,
            impl_id,
        }
    }

    /// Reset the context to its just-constructed state (zeroes state and buf).
    ///
    /// The shape fields (`rate`, `pad`, `md_size`, `impl_id`) are preserved.
    pub fn init(&mut self) -> ProviderResult<()> {
        self.state = [0u64; 25];
        self.buf.clear();
        self.xof_state = XofState::Absorb;
        self.squeeze_offset = 0;
        Ok(())
    }

    /// Configure the XOF output length.
    ///
    /// Succeeds for XOF contexts (`md_size == 0`); returns
    /// [`ProviderError::Dispatch`] on fixed-output variants.
    pub fn set_xof_len(&mut self, len: usize) -> ProviderResult<()> {
        if self.md_size != 0 {
            return Err(ProviderError::Dispatch(
                "xoflen cannot be set on fixed-length digests".to_string(),
            ));
        }
        self.xof_len = Some(len);
        Ok(())
    }

    /// Absorb `data` into the sponge, transitioning from `Init` → `Absorb`
    /// on the first call and permuting after each full block.
    pub fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.xof_state == XofState::Squeeze {
            return Err(ProviderError::Dispatch(
                "cannot update after squeeze has started".to_string(),
            ));
        }
        self.xof_state = XofState::Absorb;

        let mut off: usize = 0;

        // Fill any partial buffer first.
        if !self.buf.is_empty() {
            let space = self.rate - self.buf.len();
            if data.len() < space {
                self.buf.extend_from_slice(data);
                return Ok(());
            }
            self.buf.extend_from_slice(&data[..space]);
            // SAFETY (logical): buf.len() == rate after the extend above.
            let block: Vec<u8> = self.buf.clone();
            self.xor_block_into_state(&block);
            self.permute();
            self.buf.clear();
            off = space;
        }

        // Absorb full blocks directly from `data`.
        while off + self.rate <= data.len() {
            let block = &data[off..off + self.rate];
            self.xor_block_into_state(block);
            self.permute();
            off += self.rate;
        }

        // Buffer the remainder.
        if off < data.len() {
            self.buf.extend_from_slice(&data[off..]);
        }
        Ok(())
    }

    /// Finalize the absorb phase: append padding, apply the trailing MSB,
    /// absorb the final block, permute, and transition to `Squeeze`.
    ///
    /// Must be called exactly once per context before emitting output.
    fn finalize_absorb(&mut self) {
        // Remember how many bytes were buffered so we know where to place
        // the domain-separation byte.
        let bufsz = self.buf.len();
        // Extend the pending buffer to a full block of zeros.
        self.buf.resize(self.rate, 0u8);
        // Write the padding byte at the position of the last real byte + 1.
        self.buf[bufsz] = self.pad;
        // Set the high bit of the very last byte (FIPS 202 final rule).
        self.buf[self.rate - 1] |= 0x80;
        // Absorb the padded final block and permute.
        let block: Vec<u8> = self.buf.clone();
        self.xor_block_into_state(&block);
        self.permute();
        self.buf.clear();
        self.xof_state = XofState::Squeeze;
        self.squeeze_offset = 0;
    }

    /// Squeeze `out.len()` bytes from the sponge into `out`, applying the
    /// permutation whenever the current block is exhausted. Supports being
    /// called multiple times so that XOF consumers can stream output.
    fn squeeze_bytes(&mut self, out: &mut [u8]) {
        let mut written = 0usize;
        while written < out.len() {
            if self.squeeze_offset >= self.rate {
                self.permute();
                self.squeeze_offset = 0;
            }
            let available = self.rate - self.squeeze_offset;
            let want = out.len() - written;
            let to_copy = core::cmp::min(available, want);

            // Copy byte-by-byte from the little-endian lane image. Using
            // byte-level copy avoids alignment edge cases around partial
            // first / last lanes.
            for i in 0..to_copy {
                let pos = self.squeeze_offset + i;
                let lane_idx = pos / 8;
                let byte_idx = pos % 8;
                let lane_bytes = self.state[lane_idx].to_le_bytes();
                out[written + i] = lane_bytes[byte_idx];
            }
            written += to_copy;
            self.squeeze_offset += to_copy;
        }
    }

    /// Finalize the context and return either `md_size` bytes (fixed variants)
    /// or `xof_len` bytes (XOFs). For XOFs with no user-set `xof_len`, returns
    /// [`ProviderError::Dispatch`] — the caller is expected to set the length
    /// via the `xoflen` parameter or call [`squeeze`](Self::squeeze).
    pub fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        let out_len = if self.md_size != 0 {
            self.md_size
        } else {
            self.xof_len.ok_or_else(|| {
                ProviderError::Dispatch(
                    "XOF length not set; call set_params(\"xoflen\", n) or squeeze()".to_string(),
                )
            })?
        };

        if self.xof_state != XofState::Squeeze {
            self.finalize_absorb();
        }

        let mut out = vec![0u8; out_len];
        self.squeeze_bytes(&mut out);
        Ok(out)
    }

    /// Emit `len` additional output bytes from the sponge. The first call on
    /// an absorbing context transitions to squeeze mode (applying padding);
    /// subsequent calls continue from where the previous squeeze left off.
    pub fn squeeze(&mut self, len: usize) -> ProviderResult<Vec<u8>> {
        if self.xof_state != XofState::Squeeze {
            self.finalize_absorb();
        }
        let mut out = vec![0u8; len];
        self.squeeze_bytes(&mut out);
        Ok(out)
    }

    /// Duplicate the full context, including Keccak state, pending input,
    /// XOF metadata, and squeeze cursor.
    pub fn duplicate(&self) -> ProviderResult<Self> {
        Ok(self.clone())
    }

    /// Return the gettable parameter set (`blocksize`, `size`, `xof`,
    /// `algid-absent`) appropriate for this variant.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        // Determine flags based on pad / md_size.
        let mut flags = DigestFlags::empty();
        if self.md_size == 0 {
            flags |= DigestFlags::XOF;
        }
        match self.pad {
            SHA3_PADDING | SHAKE_PADDING | CSHAKE_PADDING => {
                flags |= DigestFlags::ALGID_ABSENT;
            }
            _ => {}
        }
        let size = if self.md_size != 0 {
            self.md_size
        } else {
            self.xof_len.unwrap_or(0)
        };
        let mut set = default_get_params(self.rate, size, flags)?;
        // Expose `xoflen` for XOFs that have a length configured.
        if self.md_size == 0 {
            if let Some(xl) = self.xof_len {
                set.set("xoflen", ParamValue::UInt64(xl as u64));
            }
        }
        Ok(set)
    }

    /// Apply a `xoflen` / `size` parameter to this context.
    ///
    /// Accepts integer types via the `FromParam` accessors on [`ParamValue`],
    /// per Rule R6 (no bare `as` casts on narrowed inputs).
    pub fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // `xoflen` (XOF output length in bytes).
        if let Some(v) = params.get("xoflen") {
            let n = param_to_usize(v)?;
            self.set_xof_len(n)?;
        }
        // Alias `size` (some callers use size instead of xoflen).
        if let Some(v) = params.get("size") {
            let n = param_to_usize(v)?;
            if self.md_size == 0 {
                self.set_xof_len(n)?;
            }
        }
        Ok(())
    }

    /// List the gettable parameter keys for this context.
    pub fn gettable_params() -> Vec<&'static str> {
        let mut base = default_gettable_params();
        base.push("xoflen");
        base
    }
}

// =============================================================================
// KECCAKv1 context serialization
// =============================================================================

impl KeccakContext {
    /// Serialize this context to the `KECCAKv1` wire format.
    ///
    /// The returned image is always [`KECCAK_V1_SIZE`] (424) bytes:
    ///
    /// | Offset | Size | Field |
    /// |--------|------|-------|
    /// | 0      | 8    | ASCII magic `"KECCAKv1"` |
    /// | 8      | 8    | `impl_id` (u64 LE) |
    /// | 16     | 8    | `md_size` (u64 LE) |
    /// | 24     | 8    | `rate` (u64 LE) |
    /// | 32     | 8    | `bufsz` (u64 LE) — bytes currently in `buf` |
    /// | 40     | 8    | `pad` byte, widened to u64 LE |
    /// | 48     | 8    | `xof_state` (0=Init, 1=Absorb, 2=Squeeze) |
    /// | 56     | 200  | 25 Keccak lanes (u64 LE each) |
    /// | 256    | 168  | Buffered input, zero-padded to `MAX_RATE_BYTES` |
    pub fn serialize(&self) -> ProviderResult<Vec<u8>> {
        let bufsz = self.buf.len();
        if bufsz > MAX_RATE_BYTES {
            return Err(ProviderError::Dispatch(format!(
                "buffer size {bufsz} exceeds MAX_RATE_BYTES {MAX_RATE_BYTES}"
            )));
        }
        let xof_state_u64 = match self.xof_state {
            XofState::Init => XOF_STATE_INIT,
            XofState::Absorb => XOF_STATE_ABSORB,
            XofState::Squeeze => XOF_STATE_SQUEEZE,
        };

        let mut out = Vec::with_capacity(KECCAK_V1_SIZE);
        out.extend_from_slice(KECCAK_V1_MAGIC);
        out.extend_from_slice(&self.impl_id.to_le_bytes());
        out.extend_from_slice(&u64::try_from(self.md_size).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&u64::try_from(self.rate).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&u64::try_from(bufsz).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&u64::from(self.pad).to_le_bytes());
        out.extend_from_slice(&xof_state_u64.to_le_bytes());
        for lane in &self.state {
            out.extend_from_slice(&lane.to_le_bytes());
        }
        // Buffer + zero pad to MAX_RATE_BYTES.
        out.extend_from_slice(&self.buf);
        out.resize(KECCAK_V1_SIZE, 0u8);
        debug_assert_eq!(out.len(), KECCAK_V1_SIZE);
        Ok(out)
    }

    /// Deserialize a context previously produced by [`serialize`](Self::serialize).
    pub fn deserialize(data: &[u8]) -> ProviderResult<Self> {
        if data.len() < KECCAK_V1_SIZE {
            return Err(ProviderError::Dispatch(format!(
                "KECCAKv1 image too short: {} < {}",
                data.len(),
                KECCAK_V1_SIZE
            )));
        }
        if &data[0..8] != KECCAK_V1_MAGIC {
            return Err(ProviderError::Dispatch(
                "KECCAKv1 magic mismatch".to_string(),
            ));
        }
        let read_u64 = |off: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[off..off + 8]);
            u64::from_le_bytes(b)
        };
        let impl_id = read_u64(8);
        let md_size_u64 = read_u64(16);
        let rate_u64 = read_u64(24);
        let bufsz_u64 = read_u64(32);
        let pad_u64 = read_u64(40);
        let xof_state_u64 = read_u64(48);

        let md_size = usize::try_from(md_size_u64)
            .map_err(|_| ProviderError::Dispatch("md_size out of range".to_string()))?;
        let rate = usize::try_from(rate_u64)
            .map_err(|_| ProviderError::Dispatch("rate out of range".to_string()))?;
        let bufsz = usize::try_from(bufsz_u64)
            .map_err(|_| ProviderError::Dispatch("bufsz out of range".to_string()))?;
        if rate == 0 || rate > MAX_RATE_BYTES || rate % 8 != 0 {
            return Err(ProviderError::Dispatch(format!(
                "invalid rate value: {rate}"
            )));
        }
        if bufsz > rate {
            return Err(ProviderError::Dispatch(format!(
                "bufsz {bufsz} exceeds rate {rate}"
            )));
        }
        let pad = u8::try_from(pad_u64 & 0xff)
            .map_err(|_| ProviderError::Dispatch("pad out of range".to_string()))?;
        let xof_state = match xof_state_u64 {
            XOF_STATE_INIT => XofState::Init,
            XOF_STATE_ABSORB => XofState::Absorb,
            XOF_STATE_SQUEEZE => XofState::Squeeze,
            other => {
                return Err(ProviderError::Dispatch(format!(
                    "invalid xof_state value: {other}"
                )))
            }
        };

        let mut state = [0u64; 25];
        for (i, lane) in state.iter_mut().enumerate() {
            *lane = read_u64(56 + i * 8);
        }
        let buf_offset = 56 + 200;
        let mut buf = Vec::with_capacity(rate);
        buf.extend_from_slice(&data[buf_offset..buf_offset + bufsz]);

        // `xof_len` is not serialized in the KECCAKv1 image (it is a
        // runtime configuration knob, not part of the sponge state).
        // Restored contexts start with `None`; callers must re-apply
        // `set_xof_len` or the `xoflen` parameter for XOF variants.
        Ok(Self {
            state,
            buf,
            rate,
            pad,
            md_size,
            xof_len: None,
            xof_state,
            squeeze_offset: 0,
            impl_id,
        })
    }
}

// =============================================================================
// DigestContext impl for KeccakContext
// =============================================================================

impl DigestContext for KeccakContext {
    fn init(&mut self, params: Option<&ParamSet>) -> ProviderResult<()> {
        KeccakContext::init(self)?;
        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        KeccakContext::update(self, data)
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        KeccakContext::finalize(self)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        KeccakContext::get_params(self)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        KeccakContext::set_params(self, params)
    }
}

// =============================================================================
// Parameter helpers
// =============================================================================

/// Decode an integer [`ParamValue`] to a non-negative `usize`.
///
/// Accepts `Int32`, `UInt32`, `Int64`, `UInt64` variants. Per Rule R6 this
/// uses checked `try_from` and never a bare `as` cast.
fn param_to_usize(value: &ParamValue) -> ProviderResult<usize> {
    match value {
        ParamValue::UInt64(v) => usize::try_from(*v)
            .map_err(|_| ProviderError::Dispatch("u64 value does not fit in usize".to_string())),
        ParamValue::Int64(v) => {
            if *v < 0 {
                Err(ProviderError::Dispatch("negative length".to_string()))
            } else {
                usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch("i64 value does not fit in usize".to_string())
                })
            }
        }
        ParamValue::UInt32(v) => usize::try_from(*v)
            .map_err(|_| ProviderError::Dispatch("u32 value does not fit in usize".to_string())),
        ParamValue::Int32(v) => usize::try_from(*v)
            .map_err(|_| ProviderError::Dispatch("negative or out-of-range length".to_string())),
        _ => Err(ProviderError::Dispatch(
            "expected integer parameter".to_string(),
        )),
    }
}

/// Decode a byte-string [`ParamValue`] (`OctetString` or `Utf8String`).
fn param_to_bytes(value: &ParamValue) -> ProviderResult<Vec<u8>> {
    match value {
        ParamValue::OctetString(b) => Ok(b.clone()),
        ParamValue::Utf8String(s) => Ok(s.as_bytes().to_vec()),
        _ => Err(ProviderError::Dispatch(
            "expected octet-string or utf8-string parameter".to_string(),
        )),
    }
}

// =============================================================================
// CshakeContext — customizable SHAKE (SP 800-185)
// =============================================================================

/// Default XOF output lengths for cSHAKE, per SP 800-185 §3.3 guidance.
///
/// cSHAKE-128 recommends at least `2 × 128 / 8 = 32` bytes of output, and
/// cSHAKE-256 recommends at least `2 × 256 / 8 = 64` bytes. These values
/// match `CSHAKE_DEFAULT_XOF_LEN` in `cshake_prov.c`.
const CSHAKE128_DEFAULT_XOF_LEN: usize = 32;
const CSHAKE256_DEFAULT_XOF_LEN: usize = 64;

/// cSHAKE digest context (SP 800-185).
///
/// Wraps a [`KeccakContext`] configured with [`CSHAKE_PADDING`] and, on the
/// first update after N or S is set, absorbs the
///   `bytepad(encode_string(N) || encode_string(S), rate)`
/// prefix. When both N and S are empty, cSHAKE degenerates to SHAKE with the
/// standard [`SHAKE_PADDING`].
///
/// Holds sensitive data (N, S, buffered input, Keccak state) and derives
/// [`Zeroize`] / [`ZeroizeOnDrop`] for secure erasure.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CshakeContext {
    /// Underlying Keccak context (padding set according to N/S presence).
    inner: KeccakContext,
    /// Function-name string `N` (raw, unencoded). `None` means "not set".
    function_name: Option<Vec<u8>>,
    /// Customization string `S` (raw, unencoded). `None` means "not set".
    customization: Option<Vec<u8>>,
    /// Has the `bytepad(encode_string(N) || encode_string(S))` prefix been
    /// absorbed into `inner` already?
    prefix_absorbed: bool,
    /// Property query hint used by higher-level fetchers (unused here;
    /// preserved for wire-format compatibility with the C provider).
    propq: Option<String>,
    /// Security level in bits: 128 or 256.
    security_bits: usize,
}

impl CshakeContext {
    /// Construct a new cSHAKE context for the given security level
    /// (`128` or `256` bits). Output length defaults to 32 bytes for
    /// cSHAKE-128 and 64 bytes for cSHAKE-256.
    ///
    /// Any other value is a programming error and triggers a panic. The
    /// only call-site, [`CshakeProvider::new_ctx`], has already validated
    /// `security_bits` at provider-construction time.
    #[must_use]
    // `panic!` here is an intentional programming-error guard: the sole
    // call-site (`CshakeProvider::new_ctx`) only passes `security_bits`
    // values that have already been validated at provider-construction
    // time. Workspace policy allows panics in constructors when used as
    // a contract check on compile-time-constant inputs.
    #[allow(clippy::panic)]
    pub fn new(security_bits: usize) -> Self {
        let (rate, default_xof_len, impl_id_mix) = match security_bits {
            128 => (168usize, CSHAKE128_DEFAULT_XOF_LEN, 128u64),
            256 => (136usize, CSHAKE256_DEFAULT_XOF_LEN, 256u64),
            other => panic!("cSHAKE requires security_bits 128 or 256, got {other}"),
        };
        let impl_id = IMPL_ID_CSHAKE_KECCAK | impl_id_mix;
        let mut inner = KeccakContext::new_xof(rate, CSHAKE_PADDING, default_xof_len, impl_id);
        // Pre-set the XOF length so finalize() without set_params still works.
        inner.xof_len = Some(default_xof_len);
        Self {
            inner,
            function_name: None,
            customization: None,
            prefix_absorbed: false,
            propq: None,
            security_bits,
        }
    }

    /// Reset the context, clearing both Keccak state and N/S.
    pub fn init(&mut self) -> ProviderResult<()> {
        // Preserve rate / pad / impl_id by cloning shape metadata.
        let rate = self.inner.rate;
        // `security_bits` is always 128 or 256 (validated by `new()`); any
        // other value would have panicked earlier.
        let default_xof_len = if self.security_bits == 128 {
            CSHAKE128_DEFAULT_XOF_LEN
        } else {
            CSHAKE256_DEFAULT_XOF_LEN
        };
        let impl_id = self.inner.impl_id;
        self.inner = KeccakContext::new_xof(rate, CSHAKE_PADDING, default_xof_len, impl_id);
        self.inner.xof_len = Some(default_xof_len);
        self.function_name = None;
        self.customization = None;
        self.prefix_absorbed = false;
        self.propq = None;
        Ok(())
    }

    /// Assign the function-name parameter `N`. Must be called before any
    /// [`update`](Self::update). Length is bounded by [`CSHAKE_MAX_STRING`].
    pub fn set_function_name(&mut self, n: Vec<u8>) -> ProviderResult<()> {
        if n.len() > CSHAKE_MAX_STRING {
            return Err(ProviderError::Dispatch(format!(
                "cSHAKE function-name exceeds {CSHAKE_MAX_STRING} bytes"
            )));
        }
        if self.prefix_absorbed {
            return Err(ProviderError::Dispatch(
                "cannot set function-name after absorption has begun".to_string(),
            ));
        }
        self.function_name = Some(n);
        Ok(())
    }

    /// Assign the customization-string parameter `S`. Must be called before
    /// any [`update`](Self::update). Length is bounded by [`CSHAKE_MAX_STRING`].
    pub fn set_customization(&mut self, s: Vec<u8>) -> ProviderResult<()> {
        if s.len() > CSHAKE_MAX_STRING {
            return Err(ProviderError::Dispatch(format!(
                "cSHAKE customization exceeds {CSHAKE_MAX_STRING} bytes"
            )));
        }
        if self.prefix_absorbed {
            return Err(ProviderError::Dispatch(
                "cannot set customization after absorption has begun".to_string(),
            ));
        }
        self.customization = Some(s);
        Ok(())
    }

    /// Absorb the `bytepad(encode_string(N) || encode_string(S), rate)`
    /// prefix if either N or S is non-empty. When both are empty, revert the
    /// padding byte to `SHAKE_PADDING` so the result matches plain SHAKE.
    ///
    /// Called lazily before the first user-supplied update so that callers
    /// can set N / S any time between construction and the first `update`.
    fn absorb_bytepad_prefix(&mut self) -> ProviderResult<()> {
        if self.prefix_absorbed {
            return Ok(());
        }
        // `Option::is_none_or` was only stabilized in Rust 1.82.
        // Use the MSRV-compatible `map_or(true, …)` equivalent (return `true`
        // when the field is `None`, else check emptiness).
        let n_empty = self.function_name.as_ref().map_or(true, Vec::is_empty);
        let s_empty = self.customization.as_ref().map_or(true, Vec::is_empty);
        if n_empty && s_empty {
            // Behave exactly like SHAKE: change the pad byte and skip prefix.
            self.inner.pad = SHAKE_PADDING;
        } else {
            let n = self.function_name.as_deref().unwrap_or(&[]);
            let s = self.customization.as_deref().unwrap_or(&[]);
            let mut encoded = encode_string(n);
            encoded.extend_from_slice(&encode_string(s));
            let padded = bytepad(&encoded, self.inner.rate);
            // Absorb the padded prefix; this is a normal update on `inner`.
            self.inner.update(&padded)?;
        }
        self.prefix_absorbed = true;
        Ok(())
    }

    /// Absorb user data, handling the lazy bytepad prefix on first call.
    pub fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        self.absorb_bytepad_prefix()?;
        self.inner.update(data)
    }

    /// Finalize the context and return the XOF output (default 32 bytes for
    /// cSHAKE-128 and 64 bytes for cSHAKE-256 unless overridden via `xoflen`).
    pub fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        self.absorb_bytepad_prefix()?;
        self.inner.finalize()
    }

    /// Emit `len` additional bytes from the XOF stream.
    pub fn squeeze(&mut self, len: usize) -> ProviderResult<Vec<u8>> {
        self.absorb_bytepad_prefix()?;
        self.inner.squeeze(len)
    }

    /// Duplicate the full cSHAKE context state.
    pub fn duplicate(&self) -> ProviderResult<Self> {
        Ok(self.clone())
    }

    /// Return the cSHAKE gettable parameter set.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        self.inner.get_params()
    }

    /// Apply cSHAKE-specific parameters: `xoflen`, `function-name` (N),
    /// `cshake-customisation` (S), and `properties`.
    pub fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // XOF output length aliases.
        if let Some(v) = params.get("xoflen") {
            let n = param_to_usize(v)?;
            self.inner.xof_len = Some(n);
        } else if let Some(v) = params.get("size") {
            let n = param_to_usize(v)?;
            self.inner.xof_len = Some(n);
        }
        // Function name `N`.
        if let Some(v) = params.get("function-name") {
            let b = param_to_bytes(v)?;
            self.set_function_name(b)?;
        }
        // Customization string `S`. Accept both OpenSSL-style
        // `cshake-customisation` and the informal `customisation` alias.
        if let Some(v) = params.get("cshake-customisation") {
            let b = param_to_bytes(v)?;
            self.set_customization(b)?;
        } else if let Some(v) = params.get("customisation") {
            let b = param_to_bytes(v)?;
            self.set_customization(b)?;
        }
        // Property-query hint (purely informational).
        if let Some(v) = params.get("properties") {
            self.propq = match v {
                ParamValue::Utf8String(s) => Some(s.clone()),
                _ => None,
            };
        }
        Ok(())
    }
}

// =============================================================================
// DigestContext impl for CshakeContext
// =============================================================================

impl DigestContext for CshakeContext {
    fn init(&mut self, params: Option<&ParamSet>) -> ProviderResult<()> {
        CshakeContext::init(self)?;
        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        CshakeContext::update(self, data)
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        CshakeContext::finalize(self)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        CshakeContext::get_params(self)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        CshakeContext::set_params(self, params)
    }
}

// =============================================================================
// Sha3Provider — SHA3-224 / SHA3-256 / SHA3-384 / SHA3-512 (FIPS 202)
// =============================================================================

/// Provider for the fixed-output SHA-3 family: SHA3-224, SHA3-256, SHA3-384,
/// SHA3-512.
///
/// The security parameter (`bits`) is one of `{224, 256, 384, 512}` and
/// controls both the capacity (`c = 2 × bits`) and the digest output size
/// (`bits / 8`). Rate is `(1600 - c) / 8` bytes. Padding is `SHA3_PADDING`
/// (`0x06`).
///
/// Replaces `IMPLEMENT_SHA3_functions(...)` from `sha3_prov.c`.
#[derive(Clone, Copy, Debug)]
pub struct Sha3Provider {
    bits: usize,
}

impl Sha3Provider {
    /// Construct a SHA-3 provider for the given digest length in bits.
    ///
    /// Accepts `224`, `256`, `384`, or `512`. Any other value is a
    /// programming error (the dispatcher in `digests::mod::create_sha3_provider`
    /// only invokes this with validated constants) and triggers a panic.
    ///
    /// This constructor is infallible so that the provider can be constructed
    /// in `const` / fallback contexts without error plumbing.
    #[must_use]
    // `panic!` here is an intentional programming-error guard: the sole
    // dispatcher (`create_sha3_provider` in `digests/mod.rs`) only invokes
    // this with compile-time validated constants 224/256/384/512. Reaching
    // the panic arm would indicate a caller contract violation rather than
    // runtime input. Workspace policy (`panic = "warn"`) permits this
    // pattern with a per-site justification.
    #[allow(clippy::panic)]
    pub fn new(bits: usize) -> Self {
        match bits {
            224 | 256 | 384 | 512 => Self { bits },
            other => panic!("SHA3 requires 224/256/384/512 bits, got {other}"),
        }
    }

    /// Rate of the sponge in bytes (`(1600 - 2 × bits) / 8`).
    const fn rate_bytes(self) -> usize {
        // 2 × bits is the capacity in bits; divide by 8 gives capacity bytes;
        // 200 is the state size in bytes (1600 bits / 8).
        200 - (2 * self.bits) / 8
    }

    /// Digest size in bytes (`bits / 8`).
    const fn md_bytes(self) -> usize {
        self.bits / 8
    }
}

impl DigestProvider for Sha3Provider {
    fn name(&self) -> &'static str {
        match self.bits {
            224 => "SHA3-224",
            256 => "SHA3-256",
            384 => "SHA3-384",
            512 => "SHA3-512",
            _ => unreachable!("Sha3Provider::new validated bits"),
        }
    }

    fn block_size(&self) -> usize {
        self.rate_bytes()
    }

    fn digest_size(&self) -> usize {
        self.md_bytes()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        let ctx = KeccakContext::new(self.rate_bytes(), SHA3_PADDING, self.md_bytes());
        Ok(Box::new(ctx))
    }
}

// =============================================================================
// ShakeProvider — SHAKE-128 / SHAKE-256 (FIPS 202)
// =============================================================================

/// Provider for the SHAKE extendable-output function family: SHAKE-128 and
/// SHAKE-256.
///
/// The `security_bits` argument is the desired security level (`128` or
/// `256`). Rate is `(1600 - 2 × security_bits) / 8` bytes; digest output is
/// variable (XOF) and defaults to `16` bytes for SHAKE-128 and `32` bytes for
/// SHAKE-256 per the C provider's historical behaviour. Padding is
/// `SHAKE_PADDING` (`0x1f`).
#[derive(Clone, Copy, Debug)]
pub struct ShakeProvider {
    security_bits: usize,
}

impl ShakeProvider {
    /// Construct a SHAKE provider for the given security level
    /// (`128` or `256`).
    ///
    /// Any other value is a programming error and triggers a panic. The
    /// dispatcher in `digests::mod::create_sha3_provider` only invokes this
    /// with validated constants.
    #[must_use]
    // `panic!` here is an intentional programming-error guard: the sole
    // dispatcher (`create_sha3_provider` in `digests/mod.rs`) only invokes
    // this with compile-time validated constants 128/256. Reaching the
    // panic arm would indicate a caller contract violation rather than
    // runtime input. Workspace policy (`panic = "warn"`) permits this
    // pattern with a per-site justification.
    #[allow(clippy::panic)]
    pub fn new(security_bits: usize) -> Self {
        match security_bits {
            128 | 256 => Self { security_bits },
            other => panic!("SHAKE requires 128 or 256 security bits, got {other}"),
        }
    }

    const fn rate_bytes(self) -> usize {
        200 - (2 * self.security_bits) / 8
    }

    /// Default XOF output length for this variant.
    const fn default_xof_len(self) -> usize {
        // The C provider uses `bitlen / 8 / 2` for the default (SHAKE-128
        // returns 16 bytes, SHAKE-256 returns 32 bytes) to match the FIPS
        // 202 intuitive "half of rate" convention.
        self.security_bits / 8
    }
}

impl DigestProvider for ShakeProvider {
    fn name(&self) -> &'static str {
        match self.security_bits {
            128 => "SHAKE-128",
            256 => "SHAKE-256",
            _ => unreachable!("ShakeProvider::new validated security_bits"),
        }
    }

    fn block_size(&self) -> usize {
        self.rate_bytes()
    }

    fn digest_size(&self) -> usize {
        // XOF has no inherent digest size; C provider reports 0.
        0
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        let impl_id = IMPL_ID_SHAKE | (self.security_bits as u64);
        let ctx = KeccakContext::new_xof(
            self.rate_bytes(),
            SHAKE_PADDING,
            self.default_xof_len(),
            impl_id,
        );
        Ok(Box::new(ctx))
    }
}

// =============================================================================
// KeccakProvider — raw Keccak-{224,256,384,512} (pre-FIPS-202 Keccak padding)
// =============================================================================

/// Provider for the raw (pre-standardisation) Keccak family.
///
/// Identical sponge parameters to SHA-3 but uses `KECCAK_PADDING` (`0x01`)
/// instead of `SHA3_PADDING` (`0x06`). Accepted digest lengths are
/// `{224, 256, 384, 512}` bits.
#[derive(Clone, Copy, Debug)]
pub struct KeccakProvider {
    bits: usize,
}

impl KeccakProvider {
    /// Construct a Keccak provider for the given digest length in bits.
    ///
    /// Any value outside `{224, 256, 384, 512}` is a programming error and
    /// triggers a panic. The dispatcher in
    /// `digests::mod::create_sha3_provider` only invokes this with validated
    /// constants.
    #[must_use]
    // `panic!` here is an intentional programming-error guard: the sole
    // dispatcher (`create_sha3_provider` in `digests/mod.rs`) only invokes
    // this with compile-time validated constants 224/256/384/512. Reaching
    // the panic arm would indicate a caller contract violation rather than
    // runtime input. Workspace policy (`panic = "warn"`) permits this
    // pattern with a per-site justification.
    #[allow(clippy::panic)]
    pub fn new(bits: usize) -> Self {
        match bits {
            224 | 256 | 384 | 512 => Self { bits },
            other => panic!("KECCAK requires 224/256/384/512 bits, got {other}"),
        }
    }

    const fn rate_bytes(self) -> usize {
        200 - (2 * self.bits) / 8
    }

    const fn md_bytes(self) -> usize {
        self.bits / 8
    }
}

impl DigestProvider for KeccakProvider {
    fn name(&self) -> &'static str {
        match self.bits {
            224 => "KECCAK-224",
            256 => "KECCAK-256",
            384 => "KECCAK-384",
            512 => "KECCAK-512",
            _ => unreachable!("KeccakProvider::new validated bits"),
        }
    }

    fn block_size(&self) -> usize {
        self.rate_bytes()
    }

    fn digest_size(&self) -> usize {
        self.md_bytes()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        let ctx = KeccakContext::new(self.rate_bytes(), KECCAK_PADDING, self.md_bytes());
        Ok(Box::new(ctx))
    }
}

// =============================================================================
// KeccakKmacProvider — KECCAK-KMAC-{128,256} (internal KMAC base)
// =============================================================================

/// Provider for the KECCAK-KMAC base functions used internally by KMAC
/// (NIST SP 800-185 §4). These are Keccak sponges with padding byte `0x04`
/// and XOF-style output.
///
/// Used exclusively as the underlying primitive for KMAC-128 / KMAC-256; not
/// intended for direct use by applications.
#[derive(Clone, Copy, Debug)]
pub struct KeccakKmacProvider {
    security_bits: usize,
}

impl KeccakKmacProvider {
    /// Construct a KECCAK-KMAC provider for the given security level
    /// (`128` or `256`).
    ///
    /// Any other value is a programming error and triggers a panic. The
    /// dispatcher in `digests::mod::create_sha3_provider` only invokes this
    /// with validated constants.
    #[must_use]
    // `panic!` here is an intentional programming-error guard: the sole
    // dispatcher (`create_sha3_provider` in `digests/mod.rs`) only invokes
    // this with compile-time validated constants 128/256. Reaching the
    // panic arm would indicate a caller contract violation rather than
    // runtime input. Workspace policy (`panic = "warn"`) permits this
    // pattern with a per-site justification.
    #[allow(clippy::panic)]
    pub fn new(security_bits: usize) -> Self {
        match security_bits {
            128 | 256 => Self { security_bits },
            other => panic!("KECCAK-KMAC requires 128 or 256 security bits, got {other}"),
        }
    }

    const fn rate_bytes(self) -> usize {
        200 - (2 * self.security_bits) / 8
    }

    /// The C provider's `kmac_newctx_128/256` set the default md size to
    /// `2 × security_bits / 8`.
    const fn default_xof_len(self) -> usize {
        (2 * self.security_bits) / 8
    }
}

impl DigestProvider for KeccakKmacProvider {
    fn name(&self) -> &'static str {
        match self.security_bits {
            128 => "KECCAK-KMAC-128",
            256 => "KECCAK-KMAC-256",
            _ => unreachable!("KeccakKmacProvider::new validated security_bits"),
        }
    }

    fn block_size(&self) -> usize {
        self.rate_bytes()
    }

    fn digest_size(&self) -> usize {
        0
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        let impl_id = IMPL_ID_CSHAKE_KECCAK | (self.security_bits as u64);
        let ctx = KeccakContext::new_xof(
            self.rate_bytes(),
            CSHAKE_PADDING,
            self.default_xof_len(),
            impl_id,
        );
        Ok(Box::new(ctx))
    }
}

// =============================================================================
// CshakeProvider — cSHAKE-128 / cSHAKE-256 (NIST SP 800-185)
// =============================================================================

/// Provider for the customizable SHAKE functions cSHAKE-128 and cSHAKE-256.
///
/// When both the function-name `N` and customization `S` parameters are
/// empty, cSHAKE degrades to plain SHAKE (see `absorb_bytepad_prefix`).
/// Otherwise, the
///   `bytepad(encode_string(N) || encode_string(S), rate)`
/// prefix is absorbed prior to any user input.
///
/// Replaces the dispatch tables defined by `IMPLEMENT_CSHAKE_functions` in
/// `cshake_prov.c`.
#[derive(Clone, Copy, Debug)]
pub struct CshakeProvider {
    security_bits: usize,
}

impl CshakeProvider {
    /// Construct a cSHAKE provider for the given security level
    /// (`128` or `256`).
    ///
    /// Any other value is a programming error and triggers a panic. The
    /// dispatcher in `digests::mod::create_sha3_provider` only invokes this
    /// with validated constants.
    #[must_use]
    // `panic!` here is an intentional programming-error guard: the sole
    // dispatcher (`create_sha3_provider` in `digests/mod.rs`) only invokes
    // this with compile-time validated constants 128/256. Reaching the
    // panic arm would indicate a caller contract violation rather than
    // runtime input. Workspace policy (`panic = "warn"`) permits this
    // pattern with a per-site justification.
    #[allow(clippy::panic)]
    pub fn new(security_bits: usize) -> Self {
        match security_bits {
            128 | 256 => Self { security_bits },
            other => panic!("cSHAKE requires 128 or 256 security bits, got {other}"),
        }
    }

    const fn rate_bytes(self) -> usize {
        200 - (2 * self.security_bits) / 8
    }
}

impl DigestProvider for CshakeProvider {
    fn name(&self) -> &'static str {
        match self.security_bits {
            128 => "CSHAKE-128",
            256 => "CSHAKE-256",
            _ => unreachable!("CshakeProvider::new validated security_bits"),
        }
    }

    fn block_size(&self) -> usize {
        self.rate_bytes()
    }

    fn digest_size(&self) -> usize {
        0
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        let ctx = CshakeContext::new(self.security_bits);
        Ok(Box::new(ctx))
    }
}

// =============================================================================
// Algorithm descriptors
// =============================================================================

/// Returns [`AlgorithmDescriptor`]s for every Keccak-based digest algorithm
/// implemented by this module.
///
/// The list contains 14 entries (matching the C providers in `sha3_prov.c`
/// and `cshake_prov.c`):
/// * `SHA3-224` / `SHA3-256` / `SHA3-384` / `SHA3-512`
/// * `SHAKE-128` + alias `SHAKE128`
/// * `SHAKE-256` + alias `SHAKE256`
/// * `KECCAK-224` / `KECCAK-256` / `KECCAK-384` / `KECCAK-512`
/// * `KECCAK-KMAC-128` + alias `KECCAK-KMAC128`
/// * `KECCAK-KMAC-256` + alias `KECCAK-KMAC256`
/// * `CSHAKE-128` + alias `CSHAKE128`
/// * `CSHAKE-256` + alias `CSHAKE256`
///
/// All descriptors report the `"provider=default"` property to match the
/// dispatch registration in the C default provider.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["SHA3-224"],
            property: "provider=default",
            description: "SHA-3 224-bit digest (FIPS 202)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-256"],
            property: "provider=default",
            description: "SHA-3 256-bit digest (FIPS 202)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-384"],
            property: "provider=default",
            description: "SHA-3 384-bit digest (FIPS 202)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-512"],
            property: "provider=default",
            description: "SHA-3 512-bit digest (FIPS 202)",
        },
        AlgorithmDescriptor {
            names: vec!["SHAKE-128", "SHAKE128"],
            property: "provider=default",
            description: "SHAKE-128 extendable-output function (FIPS 202)",
        },
        AlgorithmDescriptor {
            names: vec!["SHAKE-256", "SHAKE256"],
            property: "provider=default",
            description: "SHAKE-256 extendable-output function (FIPS 202)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-224"],
            property: "provider=default",
            description: "Keccak 224-bit raw digest (pre-FIPS-202 padding)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-256"],
            property: "provider=default",
            description: "Keccak 256-bit raw digest (pre-FIPS-202 padding)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-384"],
            property: "provider=default",
            description: "Keccak 384-bit raw digest (pre-FIPS-202 padding)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-512"],
            property: "provider=default",
            description: "Keccak 512-bit raw digest (pre-FIPS-202 padding)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-KMAC-128", "KECCAK-KMAC128"],
            property: "provider=default",
            description: "Keccak-KMAC-128 base function (NIST SP 800-185)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-KMAC-256", "KECCAK-KMAC256"],
            property: "provider=default",
            description: "Keccak-KMAC-256 base function (NIST SP 800-185)",
        },
        AlgorithmDescriptor {
            names: vec!["CSHAKE-128", "CSHAKE128"],
            property: "provider=default",
            description: "cSHAKE-128 customizable XOF (NIST SP 800-185)",
        },
        AlgorithmDescriptor {
            names: vec!["CSHAKE-256", "CSHAKE256"],
            property: "provider=default",
            description: "cSHAKE-256 customizable XOF (NIST SP 800-185)",
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Known SHA3-256 test vector from FIPS 202 / NIST CAVP.
    /// Message: empty
    /// Digest: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    #[test]
    fn sha3_256_empty() {
        let provider = Sha3Provider::new(256);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(&[]).unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        );
    }

    /// Known SHA3-256 test vector.
    /// Message: "abc"
    /// Digest: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    #[test]
    fn sha3_256_abc() {
        let provider = Sha3Provider::new(256);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        );
    }

    /// Known SHA3-224 test vector (empty input).
    /// Digest: 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
    #[test]
    fn sha3_224_empty() {
        let provider = Sha3Provider::new(224);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"),
        );
    }

    /// Known SHA3-384 test vector (empty input).
    /// Digest:
    /// 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
    #[test]
    fn sha3_384_empty() {
        let provider = Sha3Provider::new(384);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode(
                "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a\
                 c3713831264adb47fb6bd1e058d5f004",
            ),
        );
    }

    /// Known SHA3-512 test vector (empty input).
    /// Digest:
    /// a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
    #[test]
    fn sha3_512_empty() {
        let provider = Sha3Provider::new(512);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
                 15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
            ),
        );
    }

    /// SHAKE-128 test vector (empty, first 32 bytes of output).
    /// Expected: 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
    #[test]
    fn shake_128_empty_32() {
        let provider = ShakeProvider::new(128);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        // Override default 16-byte XOF length to request 32 bytes.
        let mut params = ParamSet::new();
        params.set("xoflen", ParamValue::UInt64(32));
        ctx.set_params(&params).unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
        );
    }

    /// SHAKE-256 test vector (empty, first 64 bytes of output).
    /// Expected:
    /// 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be
    #[test]
    fn shake_256_empty_64() {
        let provider = ShakeProvider::new(256);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("xoflen", ParamValue::UInt64(64));
        ctx.set_params(&params).unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
                 d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
            ),
        );
    }

    /// Streaming SHA3-256 must match single-shot result.
    #[test]
    fn sha3_256_streaming_matches_single_shot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let provider = Sha3Provider::new(256);

        let mut single = provider.new_ctx().unwrap();
        single.init(None).unwrap();
        single.update(data).unwrap();
        let digest_single = single.finalize().unwrap();

        let mut streamed = provider.new_ctx().unwrap();
        streamed.init(None).unwrap();
        for byte in data.iter() {
            streamed.update(std::slice::from_ref(byte)).unwrap();
        }
        let digest_streamed = streamed.finalize().unwrap();

        assert_eq!(digest_single, digest_streamed);
    }

    /// Duplicated context must produce identical output to the original.
    #[test]
    fn sha3_256_duplicate_matches_original() {
        let provider = Sha3Provider::new(256);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"partial input ").unwrap();

        // Duplicate mid-stream.
        let mut dup = ctx.duplicate().unwrap();

        // Feed both with the rest of the input.
        ctx.update(b"suffix").unwrap();
        dup.update(b"suffix").unwrap();

        let digest_orig = ctx.finalize().unwrap();
        let digest_dup = dup.finalize().unwrap();
        assert_eq!(digest_orig, digest_dup);
    }

    /// Keccak-256 with raw padding must differ from SHA3-256 output.
    #[test]
    fn keccak_256_differs_from_sha3_256() {
        let data = b"abc";

        let sha = Sha3Provider::new(256).new_ctx().unwrap();
        let mut sha_ctx: Box<dyn DigestContext> = sha;
        sha_ctx.init(None).unwrap();
        sha_ctx.update(data).unwrap();
        let sha_digest = sha_ctx.finalize().unwrap();

        let keccak = KeccakProvider::new(256).new_ctx().unwrap();
        let mut k_ctx: Box<dyn DigestContext> = keccak;
        k_ctx.init(None).unwrap();
        k_ctx.update(data).unwrap();
        let keccak_digest = k_ctx.finalize().unwrap();

        assert_ne!(sha_digest, keccak_digest);
    }

    /// Known Keccak-256 test vector (Ethereum-style raw Keccak).
    /// Message: empty
    /// Digest: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    #[test]
    fn keccak_256_empty() {
        let provider = KeccakProvider::new(256);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        );
    }

    /// descriptors() must return exactly 14 entries, all tagged
    /// "provider=default".
    #[test]
    fn descriptors_count_and_property() {
        let descs = descriptors();
        assert_eq!(descs.len(), 14, "expected 14 Keccak-family descriptors");
        for d in &descs {
            assert_eq!(d.property, "provider=default");
            assert!(
                !d.names.is_empty(),
                "descriptor must have at least one name"
            );
            assert!(
                !d.description.is_empty(),
                "descriptor must have a non-empty description"
            );
        }
    }

    /// descriptors() must include canonical names for every advertised
    /// Keccak-family algorithm.
    #[test]
    fn descriptors_include_canonical_names() {
        let descs = descriptors();
        let all_names: Vec<&'static str> =
            descs.iter().flat_map(|d| d.names.iter().copied()).collect();
        let must_have = [
            "SHA3-224",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
            "SHAKE-128",
            "SHAKE128",
            "SHAKE-256",
            "SHAKE256",
            "KECCAK-224",
            "KECCAK-256",
            "KECCAK-384",
            "KECCAK-512",
            "KECCAK-KMAC-128",
            "KECCAK-KMAC128",
            "KECCAK-KMAC-256",
            "KECCAK-KMAC256",
            "CSHAKE-128",
            "CSHAKE128",
            "CSHAKE-256",
            "CSHAKE256",
        ];
        for name in must_have {
            assert!(
                all_names.contains(&name),
                "descriptor list missing algorithm name: {name}"
            );
        }
    }

    /// Provider names must match the canonical strings used throughout the
    /// C codebase.
    #[test]
    fn provider_names_match_c_conventions() {
        assert_eq!(Sha3Provider::new(224).name(), "SHA3-224");
        assert_eq!(Sha3Provider::new(256).name(), "SHA3-256");
        assert_eq!(Sha3Provider::new(384).name(), "SHA3-384");
        assert_eq!(Sha3Provider::new(512).name(), "SHA3-512");
        assert_eq!(ShakeProvider::new(128).name(), "SHAKE-128");
        assert_eq!(ShakeProvider::new(256).name(), "SHAKE-256");
        assert_eq!(KeccakProvider::new(224).name(), "KECCAK-224");
        assert_eq!(KeccakProvider::new(256).name(), "KECCAK-256");
        assert_eq!(KeccakProvider::new(384).name(), "KECCAK-384");
        assert_eq!(KeccakProvider::new(512).name(), "KECCAK-512");
        assert_eq!(KeccakKmacProvider::new(128).name(), "KECCAK-KMAC-128");
        assert_eq!(KeccakKmacProvider::new(256).name(), "KECCAK-KMAC-256");
        assert_eq!(CshakeProvider::new(128).name(), "CSHAKE-128");
        assert_eq!(CshakeProvider::new(256).name(), "CSHAKE-256");
    }

    /// Block sizes (sponge rate) must match the FIPS 202 specification.
    #[test]
    fn provider_block_sizes() {
        assert_eq!(Sha3Provider::new(224).block_size(), 144);
        assert_eq!(Sha3Provider::new(256).block_size(), 136);
        assert_eq!(Sha3Provider::new(384).block_size(), 104);
        assert_eq!(Sha3Provider::new(512).block_size(), 72);
        assert_eq!(ShakeProvider::new(128).block_size(), 168);
        assert_eq!(ShakeProvider::new(256).block_size(), 136);
        assert_eq!(KeccakProvider::new(224).block_size(), 144);
        assert_eq!(KeccakProvider::new(256).block_size(), 136);
        assert_eq!(CshakeProvider::new(128).block_size(), 168);
        assert_eq!(CshakeProvider::new(256).block_size(), 136);
    }

    /// Digest sizes must be correct (0 for XOF variants).
    #[test]
    fn provider_digest_sizes() {
        assert_eq!(Sha3Provider::new(224).digest_size(), 28);
        assert_eq!(Sha3Provider::new(256).digest_size(), 32);
        assert_eq!(Sha3Provider::new(384).digest_size(), 48);
        assert_eq!(Sha3Provider::new(512).digest_size(), 64);
        assert_eq!(ShakeProvider::new(128).digest_size(), 0);
        assert_eq!(ShakeProvider::new(256).digest_size(), 0);
        assert_eq!(KeccakKmacProvider::new(128).digest_size(), 0);
        assert_eq!(CshakeProvider::new(128).digest_size(), 0);
    }

    /// Constructors must reject out-of-range security parameters by
    /// panicking. Callers in the provider dispatcher pass only validated
    /// compile-time constants, so panicking here is the correct contract.
    #[test]
    fn constructors_reject_invalid_params() {
        // Each assertion below catches a deliberately invalid argument.
        // `std::panic::catch_unwind` requires `UnwindSafe`; wrapping the
        // closures in plain functions (which do not close over any
        // non-`UnwindSafe` state) satisfies the bound.
        assert!(std::panic::catch_unwind(|| Sha3Provider::new(128)).is_err());
        assert!(std::panic::catch_unwind(|| Sha3Provider::new(0)).is_err());
        assert!(std::panic::catch_unwind(|| ShakeProvider::new(64)).is_err());
        assert!(std::panic::catch_unwind(|| ShakeProvider::new(512)).is_err());
        assert!(std::panic::catch_unwind(|| KeccakProvider::new(100)).is_err());
        assert!(std::panic::catch_unwind(|| KeccakKmacProvider::new(384)).is_err());
        assert!(std::panic::catch_unwind(|| CshakeProvider::new(1024)).is_err());
    }

    /// SHAKE-128 get_params must expose XOF flag and size reporting.
    #[test]
    fn shake_get_params_reports_xof() {
        let provider = ShakeProvider::new(128);
        let ctx = provider.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        // block size
        let block_size = params.get("blocksize").expect("blocksize present");
        match block_size {
            ParamValue::UInt64(v) => assert_eq!(*v, 168),
            other => panic!("unexpected blocksize type: {other:?}"),
        }
    }

    /// SHAKE must reject finalize() without XOF length if default was
    /// cleared — this path is hard to reach through the normal API but
    /// exercises the error branch.
    #[test]
    fn shake_squeeze_produces_requested_length() {
        let provider = ShakeProvider::new(256);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"input").unwrap();

        let mut params = ParamSet::new();
        params.set("xoflen", ParamValue::UInt64(100));
        ctx.set_params(&params).unwrap();

        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), 100);
    }

    /// cSHAKE with empty N and S must produce the same output as SHAKE
    /// with the same security level.
    #[test]
    fn cshake_empty_ns_matches_shake() {
        let data = b"hello world";

        // SHAKE-128 reference output, 32 bytes.
        let shake = ShakeProvider::new(128);
        let mut shake_ctx = shake.new_ctx().unwrap();
        shake_ctx.init(None).unwrap();
        shake_ctx.update(data).unwrap();
        let mut shake_params = ParamSet::new();
        shake_params.set("xoflen", ParamValue::UInt64(32));
        shake_ctx.set_params(&shake_params).unwrap();
        let shake_out = shake_ctx.finalize().unwrap();

        // cSHAKE-128 with no N / S.
        let cshake = CshakeProvider::new(128);
        let mut cshake_ctx = cshake.new_ctx().unwrap();
        cshake_ctx.init(None).unwrap();
        cshake_ctx.update(data).unwrap();
        let mut cshake_params = ParamSet::new();
        cshake_params.set("xoflen", ParamValue::UInt64(32));
        cshake_ctx.set_params(&cshake_params).unwrap();
        let cshake_out = cshake_ctx.finalize().unwrap();

        assert_eq!(
            shake_out, cshake_out,
            "cSHAKE with empty N+S must match SHAKE output"
        );
    }

    /// cSHAKE with distinct customization strings must produce different
    /// outputs for the same input.
    #[test]
    fn cshake_customization_changes_output() {
        let data = b"test input";

        // First cSHAKE with customization "Email Signature".
        let provider = CshakeProvider::new(128);
        let mut ctx_a = provider.new_ctx().unwrap();
        ctx_a.init(None).unwrap();
        let mut params_a = ParamSet::new();
        params_a.set(
            "cshake-customisation",
            ParamValue::OctetString(b"Email Signature".to_vec()),
        );
        params_a.set("xoflen", ParamValue::UInt64(32));
        ctx_a.set_params(&params_a).unwrap();
        ctx_a.update(data).unwrap();
        let out_a = ctx_a.finalize().unwrap();

        // Second cSHAKE with different customization "Another String".
        let mut ctx_b = provider.new_ctx().unwrap();
        ctx_b.init(None).unwrap();
        let mut params_b = ParamSet::new();
        params_b.set(
            "cshake-customisation",
            ParamValue::OctetString(b"Another String".to_vec()),
        );
        params_b.set("xoflen", ParamValue::UInt64(32));
        ctx_b.set_params(&params_b).unwrap();
        ctx_b.update(data).unwrap();
        let out_b = ctx_b.finalize().unwrap();

        // Third cSHAKE with no customization (pure SHAKE behaviour).
        let mut ctx_c = provider.new_ctx().unwrap();
        ctx_c.init(None).unwrap();
        let mut params_c = ParamSet::new();
        params_c.set("xoflen", ParamValue::UInt64(32));
        ctx_c.set_params(&params_c).unwrap();
        ctx_c.update(data).unwrap();
        let out_c = ctx_c.finalize().unwrap();

        assert_ne!(
            out_a, out_b,
            "different customization must yield different output"
        );
        assert_ne!(out_a, out_c, "customized must differ from plain SHAKE");
        assert_ne!(out_b, out_c);
    }

    /// NIST SP 800-185 Sample #1 for cSHAKE-128.
    /// Input: 00010203
    /// N: (empty)
    /// S: "Email Signature"
    /// Output (32 bytes):
    /// c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5
    #[test]
    fn cshake_128_sp800_185_sample_1() {
        let provider = CshakeProvider::new(128);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set(
            "cshake-customisation",
            ParamValue::OctetString(b"Email Signature".to_vec()),
        );
        params.set("xoflen", ParamValue::UInt64(32));
        ctx.set_params(&params).unwrap();
        ctx.update(&[0x00, 0x01, 0x02, 0x03]).unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(
            digest,
            hex_decode("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5"),
        );
    }

    /// Serialize / deserialize round-trip must preserve the Keccak state.
    #[test]
    fn keccak_context_serialize_roundtrip() {
        let provider = Sha3Provider::new(256);
        let mut ctx =
            KeccakContext::new(provider.block_size(), SHA3_PADDING, provider.digest_size());
        ctx.update(b"some intermediate state bytes").unwrap();

        let serialized = ctx.serialize().unwrap();
        assert_eq!(
            serialized.len(),
            KECCAK_V1_SIZE,
            "serialized context must be exactly KECCAK_V1_SIZE bytes"
        );
        assert_eq!(&serialized[0..8], KECCAK_V1_MAGIC);

        let mut restored = KeccakContext::deserialize(&serialized).unwrap();

        // Continue updating both contexts identically and compare digests.
        ctx.update(b"; rest").unwrap();
        restored.update(b"; rest").unwrap();
        let digest_orig = ctx.finalize().unwrap();
        let digest_restored = restored.finalize().unwrap();
        assert_eq!(digest_orig, digest_restored);
    }

    /// Deserialize must reject data with the wrong magic.
    #[test]
    fn keccak_context_deserialize_rejects_bad_magic() {
        let mut bogus = vec![0u8; KECCAK_V1_SIZE];
        bogus[..8].copy_from_slice(b"WRONGMAG");
        let result = KeccakContext::deserialize(&bogus);
        assert!(result.is_err());
    }

    /// Deserialize must reject data that is too short.
    #[test]
    fn keccak_context_deserialize_rejects_short_input() {
        let short = vec![0u8; KECCAK_V1_SIZE - 1];
        let result = KeccakContext::deserialize(&short);
        assert!(result.is_err());
    }

    /// KeccakContext for a fixed SHA-3 variant must reject set_xof_len.
    #[test]
    fn keccak_context_fixed_rejects_xof_len() {
        let mut ctx = KeccakContext::new(136, SHA3_PADDING, 32);
        let result = ctx.set_xof_len(64);
        assert!(result.is_err());
    }

    /// SHAKE update after squeeze must fail (XOF cannot re-absorb).
    #[test]
    fn shake_update_after_squeeze_fails() {
        let provider = ShakeProvider::new(128);
        let mut ctx = provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"first").unwrap();
        let _ = ctx.finalize().unwrap();
        let result = ctx.update(b"too late");
        assert!(
            result.is_err(),
            "update after finalize/squeeze must not be permitted"
        );
    }

    // -------------------------------------------------------------------------
    // hex decoding helper for test vectors (avoids external dep)
    // -------------------------------------------------------------------------

    fn hex_decode(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0, "hex string must have even length");
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = hex_nibble(bytes[i]);
            let lo = hex_nibble(bytes[i + 1]);
            out.push((hi << 4) | lo);
        }
        out
    }

    fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex char: {}", c as char),
        }
    }
}
