//! `SipHash` MAC provider implementation.
//!
//! Pure Rust implementation of `SipHash`-c-d (RFC 7693 informational, originally
//! by Aumasson & Bernstein) with configurable output size (8 or 16 bytes) and
//! configurable compression/finalization round parameters.
//!
//! Default configuration: **`SipHash`-2-4** with 16-byte (128-bit) output.
//!
//! This module translates C `providers/implementations/macs/siphash_prov.c`
//! (provider dispatch layer) and `crypto/siphash/siphash.c` (core algorithm)
//! to idiomatic Rust with zero `unsafe` code. The implementation replaces the
//! C `OSSL_DISPATCH ossl_siphash_functions[]` table with Rust trait-based
//! dispatch via `MacProvider` and `MacContext`.
//!
//! # Algorithm overview
//!
//! `SipHash` processes input in 8-byte blocks through a compression function
//! consisting of `c` rounds of the `SipRound` permutation per block, followed
//! by `d` finalization rounds. The key is exactly 16 bytes (128 bits),
//! split into two 64-bit little-endian halves (k0, k1) that XOR into the
//! initial state constants.
//!
//! # Configuration parameters
//!
//! | Parameter   | Type | Default | Valid values   |
//! |-------------|------|---------|----------------|
//! | `size`      | u64  | 16      | 8 or 16        |
//! | `c-rounds`  | u64  | 2       | any u32        |
//! | `d-rounds`  | u64  | 4       | any u32        |
//! | `key`       | bytes| —       | exactly 16 bytes|

use crate::traits::{AlgorithmDescriptor, MacContext, MacProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `SipHash` key size: exactly 16 bytes (128 bits).
pub const SIPHASH_KEY_SIZE: usize = 16;

/// `SipHash` default output size: 16 bytes (128 bits).
pub const SIPHASH_DEFAULT_OUTPUT_SIZE: usize = 16;

/// `SipHash` short output size: 8 bytes (64 bits).
pub const SIPHASH_SHORT_OUTPUT_SIZE: usize = 8;

/// Default number of compression rounds (the "c" in `SipHash`-c-d).
pub const SIPHASH_DEFAULT_C_ROUNDS: u32 = 2;

/// Default number of finalization rounds (the "d" in `SipHash`-c-d).
pub const SIPHASH_DEFAULT_D_ROUNDS: u32 = 4;

/// `OSSL_MAC_PARAM_SIZE` — output hash size parameter name.
const PARAM_SIZE: &str = "size";

/// `OSSL_MAC_PARAM_KEY` — key parameter name.
const PARAM_KEY: &str = "key";

/// `OSSL_MAC_PARAM_C_ROUNDS` — compression rounds parameter name.
const PARAM_C_ROUNDS: &str = "c-rounds";

/// `OSSL_MAC_PARAM_D_ROUNDS` — finalization rounds parameter name.
const PARAM_D_ROUNDS: &str = "d-rounds";

/// `SipHash` initialization magic constant v0 = "somepseu" in LE.
const MAGIC_V0: u64 = 0x736f_6d65_7073_6575;

/// `SipHash` initialization magic constant v1 = "dorandom" in LE.
const MAGIC_V1: u64 = 0x646f_7261_6e64_6f6d;

/// `SipHash` initialization magic constant v2 = "lygenera" in LE.
const MAGIC_V2: u64 = 0x6c79_6765_6e65_7261;

/// `SipHash` initialization magic constant v3 = "tedbytes" in LE.
const MAGIC_V3: u64 = 0x7465_6462_7974_6573;

// ---------------------------------------------------------------------------
// SipHashParams — public configuration struct
// ---------------------------------------------------------------------------

/// `SipHash` algorithm parameters.
///
/// Provides a typed configuration struct for callers who prefer structured
/// parameter passing over raw `ParamSet` bags. Each field is optional;
/// `None` means "use the current or default value."
///
/// Replaces C `OSSL_PARAM` arrays from `siphash_prov.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipHashParams {
    /// Desired output hash size in bytes: 8 or 16.
    pub hash_size: Option<usize>,
    /// Number of compression rounds (the "c" in `SipHash`-c-d).
    pub c_rounds: Option<u32>,
    /// Number of finalization rounds (the "d" in `SipHash`-c-d).
    pub d_rounds: Option<u32>,
}

impl Default for SipHashParams {
    fn default() -> Self {
        Self {
            hash_size: Some(SIPHASH_DEFAULT_OUTPUT_SIZE),
            c_rounds: Some(SIPHASH_DEFAULT_C_ROUNDS),
            d_rounds: Some(SIPHASH_DEFAULT_D_ROUNDS),
        }
    }
}

impl SipHashParams {
    /// Convert these parameters into a `ParamSet` suitable for passing
    /// to `MacContext::init` or `MacContext::set_params`.
    pub fn to_param_set(&self) -> ParamSet {
        let mut builder = ParamBuilder::new();
        if let Some(size) = self.hash_size {
            builder = builder.push_u64(PARAM_SIZE, size as u64);
        }
        if let Some(c) = self.c_rounds {
            builder = builder.push_u64(PARAM_C_ROUNDS, u64::from(c));
        }
        if let Some(d) = self.d_rounds {
            builder = builder.push_u64(PARAM_D_ROUNDS, u64::from(d));
        }
        builder.build()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read 8 bytes from `bytes` as a little-endian u64.
/// Returns an error if the slice is not exactly 8 bytes.
fn le_u64(bytes: &[u8]) -> ProviderResult<u64> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| {
        ProviderError::Common(CommonError::InvalidArgument(format!(
            "SipHash: expected 8 bytes for u64 LE conversion, got {}",
            bytes.len(),
        )))
    })?;
    Ok(u64::from_le_bytes(arr))
}

// ---------------------------------------------------------------------------
// SipHashState — internal computation state
// ---------------------------------------------------------------------------

/// Core `SipHash` computation state.
///
/// Replaces the C `SIPHASH` struct from `crypto/siphash/siphash.c`.
/// Holds the four 64-bit state words (v0–v3), a partial-block "leavings"
/// buffer, and the algorithm configuration (output size, round counts).
///
/// Derives `Zeroize` and `ZeroizeOnDrop` to ensure key-derived state words
/// (v0–v3) are securely erased when the state is dropped, matching the
/// secure erasure behaviour of all other MAC implementations in this module.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SipHashState {
    /// Internal state word 0.
    v0: u64,
    /// Internal state word 1.
    v1: u64,
    /// Internal state word 2.
    v2: u64,
    /// Internal state word 3.
    v3: u64,
    /// Buffer for bytes not yet forming a complete 8-byte block.
    leavings: [u8; 8],
    /// Number of valid bytes in `leavings` (0–7).
    leavings_len: usize,
    /// Total bytes fed via [`update`] since last key init.
    total_inlen: u64,
    /// Configured output hash size (8 or 16 bytes).
    hash_size: usize,
    /// Compression rounds per 8-byte block.
    c_rounds: u32,
    /// Finalization rounds.
    d_rounds: u32,
}

impl SipHashState {
    /// Create a new `SipHash` state initialized with the given key and parameters.
    ///
    /// `key` must be exactly [`SIPHASH_KEY_SIZE`] bytes; the caller is
    /// responsible for validating length before calling this constructor.
    ///
    /// Translates `SipHash_Init()` from `crypto/siphash/siphash.c`.
    fn new(
        key: &[u8],
        hash_size: usize,
        c_rounds: u32,
        d_rounds: u32,
    ) -> ProviderResult<Self> {
        let k0 = le_u64(&key[0..8])?;
        let k1 = le_u64(&key[8..16])?;

        let v0 = MAGIC_V0 ^ k0;
        let mut v1 = MAGIC_V1 ^ k1;
        let v2 = MAGIC_V2 ^ k0;
        let v3 = MAGIC_V3 ^ k1;

        // For 128-bit output mode, toggle v1 marker per SipHash specification.
        if hash_size == SIPHASH_DEFAULT_OUTPUT_SIZE {
            v1 ^= 0xee;
        }

        Ok(SipHashState {
            v0,
            v1,
            v2,
            v3,
            leavings: [0u8; 8],
            leavings_len: 0,
            total_inlen: 0,
            hash_size,
            c_rounds,
            d_rounds,
        })
    }

    /// Execute one `SipRound` permutation on the state.
    ///
    /// Translates the C `SIPROUND` macro:
    /// ```text
    /// v0 += v1; v1 = ROTL(v1,13); v1 ^= v0; v0 = ROTL(v0,32);
    /// v2 += v3; v3 = ROTL(v3,16); v3 ^= v2;
    /// v0 += v3; v3 = ROTL(v3,21); v3 ^= v0;
    /// v2 += v1; v1 = ROTL(v1,17); v1 ^= v2; v2 = ROTL(v2,32);
    /// ```
    #[inline]
    fn sipround(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);

        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;

        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;

        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    /// Feed data into the `SipHash` computation.
    ///
    /// Processes input in 8-byte blocks through the compression function.
    /// Any trailing bytes fewer than 8 are buffered in `leavings` for
    /// subsequent calls or finalization.
    ///
    /// Translates `SipHash_Update()` from `crypto/siphash/siphash.c`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        let mut offset = 0usize;

        // Step 1: Fill any partially-filled leavings buffer.
        if self.leavings_len > 0 {
            let need = 8 - self.leavings_len;
            let can_copy = data.len().min(need);
            self.leavings[self.leavings_len..self.leavings_len + can_copy]
                .copy_from_slice(&data[..can_copy]);
            self.leavings_len += can_copy;
            offset = can_copy;

            if self.leavings_len == 8 {
                // Complete block from leavings — process it.
                let m = u64::from_le_bytes(self.leavings);
                self.v3 ^= m;
                for _ in 0..self.c_rounds {
                    self.sipround();
                }
                self.v0 ^= m;
                self.leavings_len = 0;
            }
        }

        // Step 2: Process full 8-byte blocks from the remaining input.
        let remaining = &data[offset..];
        let full_blocks = remaining.len() / 8;
        for i in 0..full_blocks {
            let start = i * 8;
            let m = le_u64(&remaining[start..start + 8])?;
            self.v3 ^= m;
            for _ in 0..self.c_rounds {
                self.sipround();
            }
            self.v0 ^= m;
        }

        // Step 3: Buffer any leftover bytes (< 8).
        let leftover_start = full_blocks * 8;
        let leftover = &remaining[leftover_start..];
        if !leftover.is_empty() {
            self.leavings[..leftover.len()].copy_from_slice(leftover);
            self.leavings_len = leftover.len();
        }

        self.total_inlen = self.total_inlen.wrapping_add(data.len() as u64);
        Ok(())
    }

    /// Toggle the output hash size between 8 and 16 bytes.
    ///
    /// Returns `false` if `size` is neither 8 nor 16. When the size
    /// actually changes, the v1 marker bit is toggled (XOR with 0xee
    /// is self-inverse).
    ///
    /// Translates `SipHash_set_hash_size()` from `crypto/siphash/siphash.c`.
    fn set_hash_size(&mut self, size: usize) -> bool {
        if size != SIPHASH_SHORT_OUTPUT_SIZE && size != SIPHASH_DEFAULT_OUTPUT_SIZE {
            return false;
        }
        if self.hash_size != size {
            self.v1 ^= 0xee;
        }
        self.hash_size = size;
        true
    }

    /// Finalize the `SipHash` computation and return the MAC tag.
    ///
    /// Processes any remaining bytes in the `leavings` buffer, applies the
    /// finalization rounds, and returns either an 8-byte or 16-byte tag
    /// depending on the configured `hash_size`.
    ///
    /// Consumes `self` because the internal state is modified during
    /// finalization and must not be reused for further updates.
    ///
    /// Translates `SipHash_Final()` from `crypto/siphash/siphash.c`.
    fn finalize(mut self) -> Vec<u8> {
        // Construct the final block: (total_inlen mod 256) in the high byte,
        // plus any remaining leavings in the low bytes.
        let mut b: u64 = (self.total_inlen & 0xff) << 56;
        for (i, &byte) in self.leavings[..self.leavings_len].iter().enumerate() {
            b |= u64::from(byte) << (i * 8);
        }

        // Process the final block through the compression function.
        self.v3 ^= b;
        for _ in 0..self.c_rounds {
            self.sipround();
        }
        self.v0 ^= b;

        // Finalization: marker XOR on v2 depends on output size.
        if self.hash_size == SIPHASH_DEFAULT_OUTPUT_SIZE {
            self.v2 ^= 0xee;
        } else {
            self.v2 ^= 0xff;
        }

        // Finalization rounds (first half).
        for _ in 0..self.d_rounds {
            self.sipround();
        }

        let first_word = self.v0 ^ self.v1 ^ self.v2 ^ self.v3;

        if self.hash_size == SIPHASH_SHORT_OUTPUT_SIZE {
            // 64-bit output: single 8-byte word.
            first_word.to_le_bytes().to_vec()
        } else {
            // 128-bit output: second half requires additional rounds.
            self.v1 ^= 0xdd;
            for _ in 0..self.d_rounds {
                self.sipround();
            }
            let second_word = self.v0 ^ self.v1 ^ self.v2 ^ self.v3;

            let mut result = Vec::with_capacity(16);
            result.extend_from_slice(&first_word.to_le_bytes());
            result.extend_from_slice(&second_word.to_le_bytes());
            result
        }
    }
}

// ---------------------------------------------------------------------------
// ContextState — state machine for the MAC context lifecycle
// ---------------------------------------------------------------------------

/// State machine tracking the lifecycle of a [`SipHashContext`].
///
/// Transitions: `New` → `Active` (after key init) → `Finalized` (after
/// finalize). Re-initialization transitions from any state back to `Active`.
#[derive(Clone)]
enum ContextState {
    /// Created but not yet initialized with a key.
    New,
    /// Initialized and accepting data via `update()`.
    Active(SipHashState),
    /// Finalized; no further updates allowed without re-init.
    Finalized,
}

// ---------------------------------------------------------------------------
// SipHashProvider — factory implementing MacProvider
// ---------------------------------------------------------------------------

/// `SipHash` MAC provider (factory).
///
/// Creates [`SipHashContext`] instances for streaming `SipHash` MAC computation.
/// Replaces the C `ossl_siphash_functions` dispatch table from
/// `providers/implementations/macs/siphash_prov.c`.
pub struct SipHashProvider;

impl Default for SipHashProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SipHashProvider {
    /// Create a new `SipHash` provider instance.
    pub fn new() -> Self {
        SipHashProvider
    }

    /// Return algorithm descriptors for provider registration.
    ///
    /// Produces a single descriptor with name `"SipHash"` and the default
    /// provider property string, enabling algorithm lookup via the
    /// provider dispatch framework.
    pub fn descriptors() -> Vec<AlgorithmDescriptor> {
        vec![AlgorithmDescriptor {
            names: vec!["SipHash"],
            property: "provider=default",
            description: "SipHash Message Authentication Code",
        }]
    }
}

impl MacProvider for SipHashProvider {
    /// Returns the algorithm name: `"SipHash"`.
    fn name(&self) -> &'static str {
        "SipHash"
    }

    /// Returns the default output size: 16 bytes (128 bits).
    fn size(&self) -> usize {
        SIPHASH_DEFAULT_OUTPUT_SIZE
    }

    /// Create a new `SipHash` MAC computation context.
    fn new_ctx(&self) -> ProviderResult<Box<dyn MacContext>> {
        Ok(Box::new(SipHashContext::new()))
    }
}

// ---------------------------------------------------------------------------
// SipHashContext — streaming MAC context implementing MacContext
// ---------------------------------------------------------------------------

/// `SipHash` MAC computation context.
///
/// Maintains the live computation state, a snapshot copy for keyless
/// re-initialization (replacing the C `sipcopy` field), and the
/// algorithm configuration (output size, round counts).
///
/// Replaces `struct siphash_data_st` from `siphash_prov.c`.
pub struct SipHashContext {
    /// Current computation state (lifecycle stage + algorithm state).
    state: ContextState,
    /// Snapshot of initial state after key setup, used for keyless reinit.
    /// Replaces C `sipcopy` field.
    snapshot: Option<SipHashState>,
    /// Configured compression rounds.
    c_rounds: u32,
    /// Configured finalization rounds.
    d_rounds: u32,
    /// Configured output hash size in bytes.
    hash_size: usize,
}

impl SipHashContext {
    /// Create a new `SipHash` context with default parameters (`SipHash`-2-4, 16-byte output).
    fn new() -> Self {
        SipHashContext {
            state: ContextState::New,
            snapshot: None,
            c_rounds: SIPHASH_DEFAULT_C_ROUNDS,
            d_rounds: SIPHASH_DEFAULT_D_ROUNDS,
            hash_size: SIPHASH_DEFAULT_OUTPUT_SIZE,
        }
    }

    /// Apply parameters from a `ParamSet` to this context.
    ///
    /// Handles `size` (output hash size), `c-rounds`, `d-rounds`, and `key`.
    /// If the context is already active, hash size changes are propagated to
    /// the live state and snapshot via [`SipHashState::set_hash_size`].
    ///
    /// Translates `siphash_set_ctx_params()` from `siphash_prov.c`.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Output hash size (8 or 16 bytes).
        if params.contains(PARAM_SIZE) {
            let size_val = params
                .get_typed::<u64>(PARAM_SIZE)
                .map_err(ProviderError::Common)?;
            let size = usize::try_from(size_val).map_err(|_| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "SipHash output size {size_val} overflows platform usize",
                )))
            })?;
            if size != SIPHASH_SHORT_OUTPUT_SIZE && size != SIPHASH_DEFAULT_OUTPUT_SIZE {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SipHash output size must be {SIPHASH_SHORT_OUTPUT_SIZE} or {SIPHASH_DEFAULT_OUTPUT_SIZE} bytes, got {size}",
                    ),
                )));
            }
            // Propagate hash size change to active state if present.
            if let ContextState::Active(ref mut st) = self.state {
                if !st.set_hash_size(size) {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!("Failed to set hash size {size} on active SipHash state"),
                    )));
                }
            }
            // Propagate hash size change to snapshot if present.
            if let Some(ref mut snap) = self.snapshot {
                if !snap.set_hash_size(size) {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!("Failed to set hash size {size} on SipHash snapshot"),
                    )));
                }
            }
            self.hash_size = size;
        }

        // Compression rounds.
        if params.contains(PARAM_C_ROUNDS) {
            let rounds_val = params
                .get_typed::<u64>(PARAM_C_ROUNDS)
                .map_err(ProviderError::Common)?;
            let rounds = u32::try_from(rounds_val).map_err(|_| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "SipHash c-rounds value {rounds_val} overflows u32",
                )))
            })?;
            self.c_rounds = rounds;
        }

        // Finalization rounds.
        if params.contains(PARAM_D_ROUNDS) {
            let rounds_val = params
                .get_typed::<u64>(PARAM_D_ROUNDS)
                .map_err(ProviderError::Common)?;
            let rounds = u32::try_from(rounds_val).map_err(|_| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "SipHash d-rounds value {rounds_val} overflows u32",
                )))
            })?;
            self.d_rounds = rounds;
        }

        // Key parameter (alternative to explicit key argument in init).
        if params.contains(PARAM_KEY) {
            let key_bytes = params
                .get_typed::<Vec<u8>>(PARAM_KEY)
                .map_err(ProviderError::Common)?;
            if key_bytes.len() != SIPHASH_KEY_SIZE {
                return Err(ProviderError::Init(format!(
                    "SipHash key must be exactly {} bytes, got {}",
                    SIPHASH_KEY_SIZE,
                    key_bytes.len(),
                )));
            }
            self.init_with_key(&key_bytes)?;
        }

        Ok(())
    }

    /// Initialize the internal `SipHash` state with the given key.
    ///
    /// Creates a new [`SipHashState`] using the current `hash_size`,
    /// `c_rounds`, and `d_rounds` configuration, and saves a snapshot
    /// copy for subsequent keyless re-initialization.
    fn init_with_key(&mut self, key: &[u8]) -> ProviderResult<()> {
        let sip_state =
            SipHashState::new(key, self.hash_size, self.c_rounds, self.d_rounds)?;
        self.snapshot = Some(sip_state.clone());
        self.state = ContextState::Active(sip_state);
        Ok(())
    }
}

impl Clone for SipHashContext {
    /// Create a deep copy of this context, including the live computation
    /// state and snapshot. Replaces `siphash_dup()` from `siphash_prov.c`.
    fn clone(&self) -> Self {
        SipHashContext {
            state: self.state.clone(),
            snapshot: self.snapshot.clone(),
            c_rounds: self.c_rounds,
            d_rounds: self.d_rounds,
            hash_size: self.hash_size,
        }
    }
}

impl Drop for SipHashContext {
    /// Securely zeroes all key-derived state when the context is dropped.
    ///
    /// Ensures v0–v3 state words, leavings buffers, and snapshot copies are
    /// cleared, matching the secure erasure behaviour of all other MAC
    /// implementations in this module (HMAC, CMAC, GMAC, KMAC, Poly1305).
    fn drop(&mut self) {
        // Zeroize the active computation state if present.
        if let ContextState::Active(ref mut state) = self.state {
            state.zeroize();
        }
        // Zeroize the snapshot copy of initial state used for keyless reinit.
        if let Some(ref mut snap) = self.snapshot {
            snap.zeroize();
        }
        // Zero configuration fields as defense-in-depth.
        self.c_rounds = 0;
        self.d_rounds = 0;
        self.hash_size = 0;
    }
}

impl MacContext for SipHashContext {
    /// Initialize (or re-initialize) the `SipHash` context.
    ///
    /// - If `key` is non-empty, validates it is exactly 16 bytes, initializes
    ///   the internal state, and saves a snapshot for future keyless reinit.
    /// - If `key` is empty and a snapshot exists (from a previous key init),
    ///   restores the context from the snapshot.
    /// - If `key` is empty and no snapshot exists, returns an error.
    /// - If `params` is provided, applies parameter overrides (`hash_size`,
    ///   round counts, and optionally a key) before processing the explicit
    ///   key argument.
    ///
    /// Translates `siphash_init()` from `siphash_prov.c`. Note that in the
    /// C implementation, `siphash_set_ctx_params` is called first, then
    /// `siphash_setkey`; this method mirrors that order.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        // Step 1: Apply parameters (may set hash_size, rounds, and/or key).
        if let Some(p) = params {
            self.apply_params(p)?;
        }

        // Step 2: Explicit key argument takes precedence over key-in-params.
        if !key.is_empty() {
            if key.len() != SIPHASH_KEY_SIZE {
                return Err(ProviderError::Init(format!(
                    "SipHash key must be exactly {} bytes, got {}",
                    SIPHASH_KEY_SIZE,
                    key.len(),
                )));
            }
            self.init_with_key(key)?;
        } else if !matches!(self.state, ContextState::Active(_)) {
            // No explicit key and apply_params did not set a key either.
            // Attempt to restore from snapshot (keyless reinit).
            match &self.snapshot {
                Some(snap) => {
                    self.state = ContextState::Active(snap.clone());
                }
                None => {
                    return Err(ProviderError::Init(
                        "SipHash reinit requires a prior key initialization".to_string(),
                    ));
                }
            }
        }
        // If apply_params already set a key (via PARAM_KEY), self.state is
        // Active and no further action is needed.

        Ok(())
    }

    /// Feed data into the `SipHash` computation.
    ///
    /// Returns an error if the context is not initialized (state is `New`)
    /// or has already been finalized.
    ///
    /// Translates `siphash_update()` from `siphash_prov.c`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        match self.state {
            ContextState::Active(ref mut sip_state) => sip_state.update(data),
            ContextState::New => Err(ProviderError::Init(
                "SipHash not initialized: call init() with a key first".to_string(),
            )),
            ContextState::Finalized => Err(ProviderError::Init(
                "SipHash already finalized: call init() to reinitialize".to_string(),
            )),
        }
    }

    /// Finalize the `SipHash` computation and return the MAC tag.
    ///
    /// Produces an 8-byte or 16-byte tag depending on the configured
    /// `hash_size`. Transitions the context to the `Finalized` state;
    /// further `update()` calls will fail until `init()` is called again.
    ///
    /// Translates `siphash_final()` from `siphash_prov.c`.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        let old_state = std::mem::replace(&mut self.state, ContextState::Finalized);
        match old_state {
            ContextState::Active(sip_state) => Ok(sip_state.finalize()),
            ContextState::New => Err(ProviderError::Init(
                "SipHash not initialized: call init() with a key first".to_string(),
            )),
            ContextState::Finalized => Err(ProviderError::Init(
                "SipHash already finalized: call init() to reinitialize".to_string(),
            )),
        }
    }

    /// Retrieve current context parameters.
    ///
    /// Returns output `size`, `c-rounds`, and `d-rounds` as a `ParamSet`.
    ///
    /// Translates `siphash_get_ctx_params()` from `siphash_prov.c`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, self.hash_size as u64)
            .push_u64(PARAM_C_ROUNDS, u64::from(self.c_rounds))
            .push_u64(PARAM_D_ROUNDS, u64::from(self.d_rounds))
            .build();
        Ok(params)
    }

    /// Apply parameter changes to this context.
    ///
    /// Delegates to `apply_params`.
    ///
    /// Translates standalone `siphash_set_ctx_params()` invocation from
    /// `siphash_prov.c`.
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

    /// Standard reference key: bytes 0x00..0x0f.
    fn test_key() -> Vec<u8> {
        (0u8..16).collect()
    }

    // SipHash-2-4 64-bit reference test vectors.
    //
    // Key = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    // Message[i] = 00 01 02 ... (i-1) for length i.
    //
    // From the reference implementation by Aumasson & Bernstein:
    // https://github.com/veorq/SipHash
    const SIPHASH_2_4_64_VECTORS: [u64; 16] = [
        0x726f_db47_dd0e_0e31, // len  0
        0x74f8_39c5_93dc_67fd, // len  1 (data: 00)
        0x0d6c_8009_d9a9_4f5a, // len  2 (data: 00 01)
        0x8567_6696_d7fb_7e2d, // len  3
        0xcf27_94e0_2771_87b7, // len  4
        0x1876_5564_cd99_a68d, // len  5
        0xcbc9_466e_58fe_e3ce, // len  6
        0xab02_00f5_8b01_d137, // len  7
        0x93f5_f579_9a93_2462, // len  8
        0x9e00_82df_0ba9_e4b0, // len  9
        0x7a5d_bbc5_94dd_b9f3, // len 10
        0xf4b3_2f46_226b_ada7, // len 11
        0x751e_8fbc_860e_e5fb, // len 12
        0x14ea_5627_c084_3d90, // len 13
        0xf723_ca90_8e7a_f2ee, // len 14
        0xa129_ca61_49be_45e5, // len 15
    ];

    // SipHash-2-4 128-bit reference test vectors.
    //
    // From vectors128.h in the reference implementation.
    // Reference vectors from OpenSSL `test/siphash_internal_test.c`, which are
    // in turn derived from the canonical SipHash reference (veorq/SipHash).
    // Key = 00 01 02 … 0f, message = 00 … (len-1).
    const SIPHASH_2_4_128_VECTORS: [[u8; 16]; 4] = [
        // len 0
        [
            0xa3, 0x81, 0x7f, 0x04, 0xba, 0x25, 0xa8, 0xe6, 0x6d, 0xf6, 0x72, 0x14, 0xc7, 0x55,
            0x02, 0x93,
        ],
        // len 1 (data: 00)
        [
            0xda, 0x87, 0xc1, 0xd8, 0x6b, 0x99, 0xaf, 0x44, 0x34, 0x76, 0x59, 0x11, 0x9b, 0x22,
            0xfc, 0x45,
        ],
        // len 2 (data: 00 01)
        [
            0x81, 0x77, 0x22, 0x8d, 0xa4, 0xa4, 0x5d, 0xc7, 0xfc, 0xa3, 0x8b, 0xde, 0xf6, 0x0a,
            0xff, 0xe4,
        ],
        // len 3 (data: 00 01 02)
        [
            0x9c, 0x70, 0xb6, 0x0c, 0x52, 0x67, 0xa9, 0x4e, 0x5f, 0x33, 0xb6, 0xb0, 0x29, 0x85,
            0xed, 0x51,
        ],
    ];

    // ------------------------------------------------------------------
    // Provider tests
    // ------------------------------------------------------------------

    #[test]
    fn test_provider_name_and_size() {
        let provider = SipHashProvider::new();
        assert_eq!(provider.name(), "SipHash");
        assert_eq!(provider.size(), SIPHASH_DEFAULT_OUTPUT_SIZE);
    }

    #[test]
    fn test_provider_new_ctx() {
        let provider = SipHashProvider::new();
        let ctx = provider.new_ctx();
        assert!(ctx.is_ok(), "new_ctx() should succeed");
    }

    #[test]
    fn test_provider_descriptors() {
        let descs = SipHashProvider::descriptors();
        assert_eq!(descs.len(), 1);
        assert!(descs[0].names.contains(&"SipHash"));
        assert_eq!(descs[0].property, "provider=default");
        assert!(!descs[0].description.is_empty());
    }

    // ------------------------------------------------------------------
    // SipHash-2-4 64-bit vector tests
    // ------------------------------------------------------------------

    #[test]
    fn test_siphash_2_4_64_empty() {
        let params = SipHashParams {
            hash_size: Some(SIPHASH_SHORT_OUTPUT_SIZE),
            c_rounds: None,
            d_rounds: None,
        };
        let param_set = params.to_param_set();
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), Some(&param_set)).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 8);
        let expected = SIPHASH_2_4_64_VECTORS[0].to_le_bytes();
        assert_eq!(tag, expected, "SipHash-2-4-64 empty message mismatch");
    }

    #[test]
    fn test_siphash_2_4_64_all_vectors() {
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, SIPHASH_SHORT_OUTPUT_SIZE as u64)
            .build();

        for (i, &expected_u64) in SIPHASH_2_4_64_VECTORS.iter().enumerate() {
            let msg: Vec<u8> = (0..i).map(|x| x as u8).collect();
            let mut ctx = SipHashContext::new();
            ctx.init(&test_key(), Some(&params)).unwrap();
            ctx.update(&msg).unwrap();
            let tag = ctx.finalize().unwrap();
            let expected = expected_u64.to_le_bytes();
            assert_eq!(tag, expected, "SipHash-2-4-64 vector {} (len={}) failed", i, i);
        }
    }

    // ------------------------------------------------------------------
    // SipHash-2-4 128-bit vector tests
    // ------------------------------------------------------------------

    #[test]
    fn test_siphash_2_4_128_all_vectors() {
        for (i, expected) in SIPHASH_2_4_128_VECTORS.iter().enumerate() {
            let msg: Vec<u8> = (0..i).map(|x| x as u8).collect();
            let mut ctx = SipHashContext::new();
            // Default is 16-byte output.
            ctx.init(&test_key(), None).unwrap();
            ctx.update(&msg).unwrap();
            let tag = ctx.finalize().unwrap();
            assert_eq!(tag.len(), 16);
            assert_eq!(
                tag,
                expected.to_vec(),
                "SipHash-2-4-128 vector {} (len={}) failed",
                i,
                i
            );
        }
    }

    // ------------------------------------------------------------------
    // Output size tests
    // ------------------------------------------------------------------

    #[test]
    fn test_output_size_default_is_16() {
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        ctx.update(b"hello").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_output_size_8() {
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, 8)
            .build();
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), Some(&params)).unwrap();
        ctx.update(b"hello").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 8);
    }

    #[test]
    fn test_output_size_invalid_rejected() {
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, 12)
            .build();
        let mut ctx = SipHashContext::new();
        let result = ctx.init(&test_key(), Some(&params));
        assert!(result.is_err(), "Size 12 should be rejected");
    }

    // ------------------------------------------------------------------
    // Key validation tests
    // ------------------------------------------------------------------

    #[test]
    fn test_key_too_short() {
        let mut ctx = SipHashContext::new();
        let result = ctx.init(&[0u8; 8], None);
        assert!(result.is_err(), "8-byte key should be rejected");
    }

    #[test]
    fn test_key_too_long() {
        let mut ctx = SipHashContext::new();
        let result = ctx.init(&[0u8; 32], None);
        assert!(result.is_err(), "32-byte key should be rejected");
    }

    #[test]
    fn test_key_empty_without_snapshot_fails() {
        let mut ctx = SipHashContext::new();
        let result = ctx.init(&[], None);
        assert!(result.is_err(), "Empty key on fresh context should fail");
    }

    #[test]
    fn test_key_exactly_16_bytes() {
        let mut ctx = SipHashContext::new();
        let result = ctx.init(&[0u8; 16], None);
        assert!(result.is_ok(), "16-byte key should be accepted");
    }

    // ------------------------------------------------------------------
    // Snapshot / reinit tests
    // ------------------------------------------------------------------

    #[test]
    fn test_keyless_reinit_from_snapshot() {
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        ctx.update(b"data1").unwrap();
        let tag1 = ctx.finalize().unwrap();

        // Reinit without key — should restore from snapshot.
        ctx.init(&[], None).unwrap();
        ctx.update(b"data1").unwrap();
        let tag2 = ctx.finalize().unwrap();

        assert_eq!(tag1, tag2, "Keyless reinit should produce the same tag");
    }

    #[test]
    fn test_reinit_with_new_key() {
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        ctx.update(b"data").unwrap();
        let tag1 = ctx.finalize().unwrap();

        // Reinit with a different key — should produce different output.
        let new_key: Vec<u8> = (16u8..32).collect();
        ctx.init(&new_key, None).unwrap();
        ctx.update(b"data").unwrap();
        let tag2 = ctx.finalize().unwrap();

        assert_ne!(tag1, tag2, "Different keys should produce different tags");
    }

    #[test]
    fn test_reinit_after_finalize() {
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        ctx.update(b"first").unwrap();
        let _tag1 = ctx.finalize().unwrap();

        // After finalize, update should fail.
        assert!(ctx.update(b"fail").is_err());

        // But reinit (keyless) should succeed.
        ctx.init(&[], None).unwrap();
        ctx.update(b"second").unwrap();
        let _tag2 = ctx.finalize().unwrap();
    }

    // ------------------------------------------------------------------
    // State machine tests
    // ------------------------------------------------------------------

    #[test]
    fn test_update_before_init_fails() {
        let mut ctx = SipHashContext::new();
        assert!(ctx.update(b"data").is_err());
    }

    #[test]
    fn test_finalize_before_init_fails() {
        let mut ctx = SipHashContext::new();
        assert!(ctx.finalize().is_err());
    }

    #[test]
    fn test_double_finalize_fails() {
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        ctx.update(b"data").unwrap();
        let _tag = ctx.finalize().unwrap();
        assert!(ctx.finalize().is_err());
    }

    // ------------------------------------------------------------------
    // Parameter get/set tests
    // ------------------------------------------------------------------

    #[test]
    fn test_get_params_defaults() {
        let ctx = SipHashContext::new();
        let params = ctx.get_params().unwrap();
        assert_eq!(
            params.get(PARAM_SIZE).and_then(|v| v.as_u64()),
            Some(SIPHASH_DEFAULT_OUTPUT_SIZE as u64)
        );
        assert_eq!(
            params.get(PARAM_C_ROUNDS).and_then(|v| v.as_u64()),
            Some(u64::from(SIPHASH_DEFAULT_C_ROUNDS))
        );
        assert_eq!(
            params.get(PARAM_D_ROUNDS).and_then(|v| v.as_u64()),
            Some(u64::from(SIPHASH_DEFAULT_D_ROUNDS))
        );
    }

    #[test]
    fn test_set_params_changes_output_size() {
        let mut ctx = SipHashContext::new();
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, 8)
            .build();
        ctx.set_params(&params).unwrap();

        let got = ctx.get_params().unwrap();
        assert_eq!(got.get(PARAM_SIZE).and_then(|v| v.as_u64()), Some(8));
    }

    #[test]
    fn test_set_params_changes_rounds() {
        let mut ctx = SipHashContext::new();
        let params = ParamBuilder::new()
            .push_u64(PARAM_C_ROUNDS, 4)
            .push_u64(PARAM_D_ROUNDS, 8)
            .build();
        ctx.set_params(&params).unwrap();

        let got = ctx.get_params().unwrap();
        assert_eq!(got.get(PARAM_C_ROUNDS).and_then(|v| v.as_u64()), Some(4));
        assert_eq!(got.get(PARAM_D_ROUNDS).and_then(|v| v.as_u64()), Some(8));
    }

    #[test]
    fn test_set_params_with_key() {
        let mut ctx = SipHashContext::new();
        let params = ParamBuilder::new()
            .push_octet(PARAM_KEY, test_key())
            .build();
        ctx.set_params(&params).unwrap();

        // Context should now be active — update and finalize should work.
        ctx.update(b"data").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), SIPHASH_DEFAULT_OUTPUT_SIZE);
    }

    // ------------------------------------------------------------------
    // Clone tests
    // ------------------------------------------------------------------

    #[test]
    fn test_clone_produces_same_result() {
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        ctx.update(b"partial").unwrap();

        let mut cloned = ctx.clone();

        ctx.update(b" data").unwrap();
        cloned.update(b" data").unwrap();

        let tag1 = ctx.finalize().unwrap();
        let tag2 = cloned.finalize().unwrap();
        assert_eq!(tag1, tag2, "Cloned context should produce same result");
    }

    // ------------------------------------------------------------------
    // Incremental update tests
    // ------------------------------------------------------------------

    #[test]
    fn test_incremental_vs_single_update() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // Single update.
        let mut ctx1 = SipHashContext::new();
        ctx1.init(&test_key(), None).unwrap();
        ctx1.update(data).unwrap();
        let tag1 = ctx1.finalize().unwrap();

        // Byte-by-byte updates.
        let mut ctx2 = SipHashContext::new();
        ctx2.init(&test_key(), None).unwrap();
        for &b in data.iter() {
            ctx2.update(&[b]).unwrap();
        }
        let tag2 = ctx2.finalize().unwrap();

        assert_eq!(tag1, tag2, "Incremental updates should match single update");
    }

    #[test]
    fn test_incremental_various_chunk_sizes() {
        let data: Vec<u8> = (0..64).collect();

        // Reference: single update.
        let mut ctx_ref = SipHashContext::new();
        ctx_ref.init(&test_key(), None).unwrap();
        ctx_ref.update(&data).unwrap();
        let tag_ref = ctx_ref.finalize().unwrap();

        // Chunks of various sizes.
        for chunk_size in [1, 3, 5, 7, 8, 9, 13, 16, 31, 32, 64] {
            let mut ctx = SipHashContext::new();
            ctx.init(&test_key(), None).unwrap();
            for chunk in data.chunks(chunk_size) {
                ctx.update(chunk).unwrap();
            }
            let tag = ctx.finalize().unwrap();
            assert_eq!(
                tag, tag_ref,
                "Chunk size {} should produce same result as single update",
                chunk_size
            );
        }
    }

    // ------------------------------------------------------------------
    // Custom round tests
    // ------------------------------------------------------------------

    #[test]
    fn test_custom_rounds_siphash_1_3() {
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, 8)
            .push_u64(PARAM_C_ROUNDS, 1)
            .push_u64(PARAM_D_ROUNDS, 3)
            .build();

        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), Some(&params)).unwrap();
        ctx.update(b"test").unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 8);

        // Verify it differs from SipHash-2-4.
        let params24 = ParamBuilder::new()
            .push_u64(PARAM_SIZE, 8)
            .build();
        let mut ctx24 = SipHashContext::new();
        ctx24.init(&test_key(), Some(&params24)).unwrap();
        ctx24.update(b"test").unwrap();
        let tag24 = ctx24.finalize().unwrap();
        assert_ne!(tag, tag24, "SipHash-1-3 should differ from SipHash-2-4");
    }

    // ------------------------------------------------------------------
    // SipHashParams tests
    // ------------------------------------------------------------------

    #[test]
    fn test_siphash_params_default() {
        let params = SipHashParams::default();
        assert_eq!(params.hash_size, Some(SIPHASH_DEFAULT_OUTPUT_SIZE));
        assert_eq!(params.c_rounds, Some(SIPHASH_DEFAULT_C_ROUNDS));
        assert_eq!(params.d_rounds, Some(SIPHASH_DEFAULT_D_ROUNDS));
    }

    #[test]
    fn test_siphash_params_to_param_set() {
        let params = SipHashParams {
            hash_size: Some(8),
            c_rounds: Some(4),
            d_rounds: None,
        };
        let ps = params.to_param_set();
        assert_eq!(ps.get(PARAM_SIZE).and_then(|v| v.as_u64()), Some(8));
        assert_eq!(ps.get(PARAM_C_ROUNDS).and_then(|v| v.as_u64()), Some(4));
        assert!(!ps.contains(PARAM_D_ROUNDS));
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    #[test]
    fn test_empty_update() {
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        ctx.update(&[]).unwrap();
        let tag1 = ctx.finalize().unwrap();

        let mut ctx2 = SipHashContext::new();
        ctx2.init(&test_key(), None).unwrap();
        let tag2 = ctx2.finalize().unwrap();

        assert_eq!(tag1, tag2, "Empty update should not change result");
    }

    #[test]
    fn test_large_message() {
        let data = vec![0xab_u8; 4096];
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        ctx.update(&data).unwrap();
        let tag = ctx.finalize().unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_hash_size_toggle_on_active_state() {
        // Init with 16-byte output, change to 8-byte mid-session.
        let mut ctx = SipHashContext::new();
        ctx.init(&test_key(), None).unwrap();
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, 8)
            .build();
        ctx.set_params(&params).unwrap();
        let got = ctx.get_params().unwrap();
        assert_eq!(got.get(PARAM_SIZE).and_then(|v| v.as_u64()), Some(8));
    }

    #[test]
    fn test_determinism() {
        let mut ctx1 = SipHashContext::new();
        ctx1.init(&test_key(), None).unwrap();
        ctx1.update(b"determinism test").unwrap();
        let tag1 = ctx1.finalize().unwrap();

        let mut ctx2 = SipHashContext::new();
        ctx2.init(&test_key(), None).unwrap();
        ctx2.update(b"determinism test").unwrap();
        let tag2 = ctx2.finalize().unwrap();

        assert_eq!(tag1, tag2, "Same key+message must produce same tag");
    }
}
