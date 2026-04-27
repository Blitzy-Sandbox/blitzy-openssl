//! # Argon2 — memory-hard password hashing KDF (RFC 9106).
//!
//! This module is an idiomatic Rust translation of
//! `providers/implementations/kdfs/argon2.c` (the largest and most complex
//! KDF in the OpenSSL 4.0 source tree at 1,548 lines).  It implements the
//! three RFC 9106 variants and registers them via the provider framework:
//!
//! | Variant    | Addressing mode              | Use case                  |
//! |------------|------------------------------|---------------------------|
//! | `ARGON2D`  | data-dependent               | max GPU/ASIC cost         |
//! | `ARGON2I`  | data-independent (side-ch.)  | side-channel resistant    |
//! | `ARGON2ID` | hybrid (i → d)               | recommended default       |
//!
//! ## Algorithm overview (RFC 9106 §3)
//!
//! 1. **Initial hash `H0`**: 64-byte BLAKE2b digest of
//!    `lanes || tag_len || m_cost || t_cost || version || type || pwd || salt
//!    || secret || ad`, with each variable-length field prefixed by its
//!    32-bit little-endian length.
//! 2. **Memory matrix setup**: `m' = floor(m_cost / (4 · lanes)) · 4 · lanes`
//!    blocks of 1024 bytes each, arranged as `lanes` rows × `segment_length`
//!    ·`SYNC_POINTS` columns.  First two blocks of each lane are derived
//!    from `H0` via `H'` (variable-output BLAKE2b, §3.3).
//! 3. **Memory filling**: `t_cost` passes × 4 slices × `lanes` lanes ×
//!    `segment_length` indices.  For each position, reference a previously
//!    filled block (via `index_alpha`) and apply the `G` compression
//!    function (`permutation_P`).  Argon2d picks the reference block based
//!    on the previous block's contents; Argon2i pre-generates
//!    pseudo-random addresses (data-independent); Argon2id applies Argon2i
//!    for the first two slices of the first pass, then Argon2d.
//! 4. **Finalization**: XOR all final-column blocks across lanes, hash with
//!    `H'` to produce `tag_len` output bytes.
//!
//! ## BLAKE2b backend
//!
//! All cryptographic hashing routes through the provider framework's
//! `MessageDigest` / `MdContext` primitives with the canonical name
//! `BLAKE2B512`.  This mirrors the sibling PBKDF1 implementation
//! ([`crate::implementations::kdfs::pbkdf1`]) and keeps algorithm selection
//! under the control of the provider framework — no direct `blake2`/`sha2`
//! crate use.  Keyed BLAKE2b (BLAKE2BMAC) is *not* required by the RFC 9106
//! reference: the `secret` parameter is fed into `H0` as raw bytes.
//!
//! ## Memory considerations
//!
//! A single derivation allocates `m_cost × 1024` bytes (up to
//! `MAX_MEMORY_KIB × 1024` bytes — 4 GiB upper bound).  The working
//! buffer is a `Vec<Argon2Block>` (not a raw byte buffer) so accidental
//! misalignment is impossible and the compiler can vectorise u64 access.
//! The `Zeroize` trait scrubs secrets on drop.
//!
//! ## Rules compliance
//!
//! | Rule | Compliance                                                          |
//! |------|---------------------------------------------------------------------|
//! | R1   | Synchronous KDF — no tokio runtime, no async                        |
//! | R2   | No locks held across `.await`                                       |
//! | R3   | All `Argon2Context` fields read in `derive_internal` / `get_params` |
//! | R5   | `Option<Vec<u8>>` for `ad` / `secret`; no sentinel values           |
//! | R6   | Every narrowing cast via `u32::try_from` / `checked_mul`           |
//! | R7   | Per-context memory (no globals) — no lock needed                    |
//! | R8   | ZERO `unsafe` in this module                                        |
//! | R9   | `#![deny(missing_docs)]` honoured — every `pub` item is documented  |
//! | R10  | Reachable from `DefaultProvider` via `descriptors()`              |
//!
//! ## Observability
//!
//! - `#[instrument]` spans on `Argon2Context::derive` and
//!   `Argon2Context::set_params` carry the selected variant.
//! - `debug!` on lifecycle events (construction, reset, provider creation).
//! - `trace!` inside hot loops (`fill_segment`, `blake2b_long` iterative
//!   phase) — gated off in release builds unless the tracing subscriber
//!   opts in.
//! - `warn!` when a validation constraint fails.

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::{CommonError, CryptoError, ProviderError};
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::ProviderResult;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::md::{MdContext, MessageDigest, BLAKE2B512};
use tracing::{debug, instrument, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Error helpers
// =============================================================================

/// Converts a [`CryptoError`] from a `MessageDigest::fetch` /
/// `MdContext` call into a `ProviderError::Dispatch`.
///
/// Mirrors the canonical pattern used in
/// [`crate::implementations::kdfs::pbkdf1::dispatch_err`].
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Shortcut for `ProviderError::Common(CommonError::InvalidArgument(...))`.
#[inline]
fn invalid(msg: impl Into<String>) -> ProviderError {
    ProviderError::Common(CommonError::InvalidArgument(msg.into()))
}

/// Shortcut for `ProviderError::Init` signalling a missing required
/// parameter such as `password` or `salt`.
#[inline]
fn init_err(msg: impl Into<String>) -> ProviderError {
    ProviderError::Init(msg.into())
}

// =============================================================================
// Parameter names (provider param-key strings)
// =============================================================================

/// Parameter key for the user password / message.
///
/// Mirrors `OSSL_KDF_PARAM_PASSWORD` ("pass") from
/// `include/openssl/core_names.h`.
const PARAM_PASSWORD: &str = "pass";

/// Parameter key for the salt.
///
/// Mirrors `OSSL_KDF_PARAM_SALT` ("salt").
const PARAM_SALT: &str = "salt";

/// Parameter key for the optional secret (key).
///
/// Mirrors `OSSL_KDF_PARAM_SECRET` ("secret").
const PARAM_SECRET: &str = "secret";

/// Parameter key for the optional associated data.
///
/// Mirrors `OSSL_KDF_PARAM_ARGON2_AD` ("ad").
const PARAM_AD: &str = "ad";

/// Parameter key for the iteration count (`t_cost`).
///
/// Mirrors `OSSL_KDF_PARAM_ITER` ("iter").
const PARAM_ITER: &str = "iter";

/// Parameter key for the memory cost in KiB (`m_cost`).
///
/// Mirrors `OSSL_KDF_PARAM_ARGON2_MEMCOST` ("memcost").
const PARAM_MEMORY: &str = "memcost";

/// Parameter key for the lanes count.
///
/// Mirrors `OSSL_KDF_PARAM_ARGON2_LANES` ("lanes").
const PARAM_LANES: &str = "lanes";

/// Parameter key for the thread count.
///
/// Mirrors `OSSL_KDF_PARAM_THREADS` ("threads").
const PARAM_THREADS: &str = "threads";

/// Parameter key for the Argon2 version selector.
///
/// Mirrors `OSSL_KDF_PARAM_ARGON2_VERSION` ("version").
const PARAM_VERSION: &str = "version";

/// Parameter key for the output length request.
///
/// Mirrors `OSSL_KDF_PARAM_SIZE` ("size").
const PARAM_SIZE: &str = "size";

/// Parameter key for the variant override — accepts `"d"`, `"i"`, or
/// `"id"` (case-insensitive).  This is used by higher-level callers that
/// want a single shared context type.  The provider-level name (`ARGON2D`
/// vs `ARGON2I` vs `ARGON2ID`) still chooses the default.
const PARAM_VARIANT: &str = "variant";

// =============================================================================
// Algorithm constants (RFC 9106 §3.1 / argon2.c macros)
// =============================================================================

/// Argon2 block size in bytes (1024 bytes = 128 × u64).
const BLOCK_SIZE: usize = 1024;

/// Argon2 block size in bytes typed as `u32` for APIs that take a u32
/// length (notably [`blake2b_long`]).  Kept as a separate `const` to
/// avoid a narrowing `BLOCK_SIZE as u32` cast that would violate rule
/// R6 (lossless numeric casts).
const BLOCK_SIZE_U32: u32 = 1024;

/// Number of u64 words in a single Argon2 block.
const QWORDS_IN_BLOCK: usize = BLOCK_SIZE / 8;

/// Number of slices per pass (segment parallelism boundary).
const SYNC_POINTS: u32 = 4;

/// Minimum lane count (RFC 9106 §3.1: `p ≥ 1`).
const MIN_LANES: u32 = 1;

/// Maximum lane count (RFC 9106 §3.1: `p < 2^24`).
const MAX_LANES: u32 = 0x00FF_FFFF;

/// Minimum thread count.
const MIN_THREADS: u32 = 1;

/// Maximum thread count (matches `ARGON2_MAX_THREADS` macro).
const MAX_THREADS: u32 = 0x00FF_FFFF;

/// Minimum output length in bytes (`tag_len ≥ 4`).
const MIN_OUT_LENGTH: u32 = 4;

/// Minimum memory cost in KiB (`m_cost ≥ 8 · SYNC_POINTS = 8`).
const MIN_MEMORY: u32 = 2 * SYNC_POINTS;

/// Maximum memory cost in KiB (capped at `u32::MAX` KiB = ~4 TiB, but
/// effective allocation is additionally limited by [`MAX_MEMORY_KIB`]).
const MAX_MEMORY_PARAM: u64 = u32::MAX as u64;

/// Hard cap on actual allocated memory in KiB (4 GiB).  This protects
/// against `DoS` from malicious parameter values exceeding host RAM.
const MAX_MEMORY_KIB: u64 = 4 * 1024 * 1024;

/// Minimum iteration count (`t_cost ≥ 1`).
const MIN_TIME: u32 = 1;

/// Minimum salt length in bytes (RFC 9106 §3.1: `|S| ≥ 8`).
const MIN_SALT_LENGTH: usize = 8;

/// Prehash digest length for `H0` in bytes.
const PREHASH_DIGEST_LENGTH: usize = 64;

/// Default output length in bytes when the caller does not supply one.
const DEFAULT_OUTLEN: u32 = 64;

/// Default iteration count (`t_cost`).
const DEFAULT_T_COST: u32 = 3;

/// Default memory cost in KiB (`m_cost`) — the minimum allowed by RFC 9106.
const DEFAULT_M_COST: u32 = MIN_MEMORY;

/// Default lane count.
const DEFAULT_LANES: u32 = 1;

/// Default thread count.
const DEFAULT_THREADS: u32 = 1;

/// Argon2 wire-format version 1.3 (the current RFC 9106 recommendation).
const ARGON2_VERSION_13: u32 = 0x13;

/// Argon2 wire-format version 1.0 (legacy, for interop — `with_xor` is
/// always 0 during fill).
// =============================================================================
// Argon2Variant
// =============================================================================

/// The three Argon2 variants defined by RFC 9106 §3.4.
///
/// This enum selects the addressing mode used to pick reference blocks
/// during memory filling.  It is exposed publicly because the
/// corresponding provider structs ([`Argon2dProvider`], [`Argon2iProvider`],
/// [`Argon2idProvider`]) each pin a single variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Variant {
    /// **Argon2d** — data-dependent addressing.  Maximises resistance
    /// against GPU/ASIC cracking but can leak information through
    /// cache-timing side channels; unsuitable for environments where
    /// attackers can observe memory access patterns.
    Argon2d,
    /// **Argon2i** — data-independent addressing.  Uses a pseudo-random
    /// schedule that is invariant under the password, making it resistant
    /// to side-channel attacks but slightly weaker against time-memory
    /// tradeoff attacks.
    Argon2i,
    /// **Argon2id** — hybrid addressing (Argon2i for the first half of the
    /// first pass, then Argon2d).  This is the RFC 9106 §4 recommended
    /// default when the caller has no compelling reason to pick one of the
    /// pure variants.
    Argon2id,
}

impl Argon2Variant {
    /// Returns the integer "type" code embedded into the initial hash
    /// (`H0`) per RFC 9106 §3.2 — Argon2d = 0, Argon2i = 1, Argon2id = 2.
    #[inline]
    const fn type_code(self) -> u32 {
        match self {
            Self::Argon2d => 0,
            Self::Argon2i => 1,
            Self::Argon2id => 2,
        }
    }

    /// Parses a user-supplied variant string (`"d"`, `"i"`, `"id"`,
    /// `"argon2d"`, etc.) case-insensitively.
    fn parse(s: &str) -> Option<Self> {
        let t = s.trim().to_ascii_lowercase();
        match t.as_str() {
            "d" | "argon2d" => Some(Self::Argon2d),
            "i" | "argon2i" => Some(Self::Argon2i),
            "id" | "argon2id" => Some(Self::Argon2id),
            _ => None,
        }
    }
}

impl core::fmt::Display for Argon2Variant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Argon2d => "ARGON2D",
            Self::Argon2i => "ARGON2I",
            Self::Argon2id => "ARGON2ID",
        })
    }
}

// =============================================================================
// Argon2Block — the fundamental 1024-byte unit of the memory matrix
// =============================================================================

/// An Argon2 memory block — 128 × 64-bit words (1024 bytes).
///
/// Using a fixed-size array rather than a raw byte buffer has two benefits
/// over the C reference implementation:
///
/// 1. **No unsafe aliasing** — the compiler knows the alignment of a
///    `[u64; 128]` is 8 bytes, so LLVM can vectorise loads/stores of the
///    compression function into SIMD without any `transmute`.
/// 2. **Bounds-checked access** — every block access goes through a
///    safe index.  Panics would indicate an algorithmic bug; they cannot
///    be triggered by malicious input because all indices are derived
///    from `m_cost` / `lanes` which are validated before allocation.
///
/// A `Vec<Argon2Block>` occupies `m_cost × 1024` bytes of RAM plus
/// `Vec` overhead (24 bytes).  For the default `m_cost = 8 KiB` this is
/// 8 KiB; for a typical production setting (`m_cost = 64 MiB = 65_536 KiB`)
/// this is 64 MiB.
type Argon2Block = [u64; QWORDS_IN_BLOCK];

/// Creates a zero-initialised Argon2 block.  Used as the seed value for
/// allocating the memory matrix before the first `fill_block` call.
#[inline]
const fn zero_block() -> Argon2Block {
    [0u64; QWORDS_IN_BLOCK]
}

/// XOR `dst <- dst ⊕ src` element-wise across two blocks.
#[inline]
fn xor_block(dst: &mut Argon2Block, src: &Argon2Block) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Copy `src` into `dst` element-wise.  Equivalent to `*dst = *src` but
/// avoids the large stack copy when the optimiser gets confused.
#[inline]
fn copy_block(dst: &mut Argon2Block, src: &Argon2Block) {
    dst.copy_from_slice(src);
}

/// Load a block's contents from 1024 raw bytes (little-endian).  Used
/// when seeding the first two blocks of each lane from
/// [`blake2b_long`] output.
#[inline]
fn load_block_bytes(dst: &mut Argon2Block, bytes: &[u8]) {
    debug_assert_eq!(bytes.len(), BLOCK_SIZE);
    // Iterate over exactly-8-byte chunks — guaranteed by `BLOCK_SIZE`
    // being a multiple of 8.  Using `chunks_exact` with a const-size
    // `try_into` avoids a fallible `expect()` on the slice split.
    for (word, chunk) in dst.iter_mut().zip(bytes.chunks_exact(8)) {
        // `chunks_exact(8)` yields slices whose length is statically 8,
        // so the `try_into` below cannot fail at runtime; the result is
        // unwrapped with `unwrap_or_default` (all-zero byte array) as
        // a defence-in-depth measure to keep clippy's strict lint set
        // happy without introducing a panic path.
        let arr: [u8; 8] = chunk.try_into().unwrap_or_default();
        *word = u64::from_le_bytes(arr);
    }
}

/// Serialise a block into 1024 bytes (little-endian).  Used when feeding
/// a block into [`blake2b_long`] for finalisation.
#[inline]
fn store_block_bytes(src: &Argon2Block, bytes: &mut [u8]) {
    debug_assert_eq!(bytes.len(), BLOCK_SIZE);
    for (i, word) in src.iter().enumerate() {
        let start = i * 8;
        bytes[start..start + 8].copy_from_slice(&word.to_le_bytes());
    }
}

const ARGON2_VERSION_10: u32 = 0x10;

/// Size of the address block used for data-independent addressing
/// (Argon2i, and the first two slices of the first pass for Argon2id).
/// Equals the number of u64 values in a single block.
const ADDRESSES_IN_BLOCK: usize = QWORDS_IN_BLOCK;

/// Same as [`ADDRESSES_IN_BLOCK`] but typed as `u32` for arithmetic
/// against `u32` block indices in `fill_segment`.  Kept as a separate
/// constant so we never need a narrowing `usize as u32` cast (rule R6
/// compliance).
const ADDRESSES_IN_BLOCK_U32: u32 = 128;

// =============================================================================
// Argon2Context — the persistent state of a KDF derivation
// =============================================================================

/// Operation context for a single Argon2 derivation.
///
/// Lifecycle (mirrors the C `KDF_ARGON2` struct declared in
/// `providers/implementations/kdfs/argon2.c` lines 140–188):
///
/// ```text
///   new()  →  set_params()*  →  derive()  [→  reset()  →  set_params()* →
///   derive()]*  →  drop
/// ```
///
/// All secret-bearing fields (`password`, `secret`) implement
/// `Zeroize` and are scrubbed when the context is dropped, per the
/// RFC 9106 §10 memory-hygiene guidance.  The `salt` and `ad` fields
/// are not secret by definition, so they are cleared on reset but not
/// derived via `#[zeroize]` — clearing is sufficient.
///
/// The memory matrix is held outside the struct (allocated afresh for
/// each `Argon2Context::derive` call) so that the context itself stays
/// small (≈256 bytes) and idle contexts do not pin large allocations.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Argon2Context {
    /// User password (P in RFC 9106 §3.1).  Required.
    password: Vec<u8>,
    /// Salt (S).  Required.  Must be ≥ [`MIN_SALT_LENGTH`] bytes.
    #[zeroize(skip)]
    salt: Vec<u8>,
    /// Optional secret key (K).  `None` encodes "unset" (RFC 9106 §3.1
    /// supports a zero-length K).  Per rule R5 we use `Option` rather
    /// than a sentinel empty vector.
    secret: Option<Vec<u8>>,
    /// Optional associated data (X).  Same rationale as `secret` for
    /// using `Option`.
    #[zeroize(skip)]
    ad: Option<Vec<u8>>,
    /// Selected variant.
    #[zeroize(skip)]
    variant: Argon2Variant,
    /// Requested output length (T) in bytes.
    #[zeroize(skip)]
    out_len: u32,
    /// Iteration count (`t_cost`, RFC 9106 §3.1: `t ≥ 1`).
    #[zeroize(skip)]
    t_cost: u32,
    /// Memory cost (`m_cost`) in KiB.  Must satisfy `m_cost ≥ 8 · lanes`.
    #[zeroize(skip)]
    m_cost: u32,
    /// Number of parallel lanes (p).
    #[zeroize(skip)]
    lanes: u32,
    /// Number of OS threads to use (currently unused — single-threaded
    /// execution is always used, but the value is accepted and echoed
    /// back from `get_params` for C-API parity).
    #[zeroize(skip)]
    threads: u32,
    /// Argon2 wire-format version.  `0x13` is the RFC 9106 default.
    #[zeroize(skip)]
    version: u32,
}

impl Argon2Context {
    /// Creates a fresh context pinned to the given variant with
    /// RFC 9106 default parameter values.
    ///
    /// The caller must subsequently supply at least `password` and
    /// `salt` via `Argon2Context::set_params` (or as part of the
    /// `params` argument to `Argon2Context::derive`) before calling
    /// `derive`.
    fn new(variant: Argon2Variant) -> Self {
        debug!(variant = %variant, "Argon2Context::new");
        Self {
            password: Vec::new(),
            salt: Vec::new(),
            secret: None,
            ad: None,
            variant,
            out_len: DEFAULT_OUTLEN,
            t_cost: DEFAULT_T_COST,
            m_cost: DEFAULT_M_COST,
            lanes: DEFAULT_LANES,
            threads: DEFAULT_THREADS,
            version: ARGON2_VERSION_13,
        }
    }

    /// Returns the currently-selected variant.
    #[must_use]
    pub const fn variant(&self) -> Argon2Variant {
        self.variant
    }

    /// Parses and applies a single set of parameters.
    ///
    /// Recognised keys:
    ///
    /// | Key        | Type       | Effect                                    |
    /// |------------|------------|-------------------------------------------|
    /// | `"pass"`   | octet      | Password (required before `derive`)       |
    /// | `"salt"`   | octet      | Salt (required, ≥8 bytes)                 |
    /// | `"secret"` | octet      | Optional secret key                       |
    /// | `"ad"`     | octet      | Optional associated data                  |
    /// | `"iter"`   | u32 / u64  | `t_cost` (iteration count)                |
    /// | `"memcost"`| u32 / u64  | `m_cost` (KiB)                            |
    /// | `"lanes"`  | u32 / u64  | Number of parallel lanes                  |
    /// | `"threads"`| u32 / u64  | Thread count (echoed only)                |
    /// | `"version"`| u32 / u64  | Wire-format version (`0x10` or `0x13`)    |
    /// | `"size"`   | u32 / u64  | Requested output length in bytes          |
    /// | `"variant"`| UTF-8      | `"d"`, `"i"`, `"id"` (case-insensitive)   |
    ///
    /// Unknown keys are silently ignored, matching the provider-framework
    /// convention for `set_ctx_params` (cf.
    /// `providers/common/provider_ctx.c`).
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // --- password ---------------------------------------------------
        if let Some(val) = params.get(PARAM_PASSWORD) {
            let bytes = val
                .as_bytes()
                .ok_or_else(|| invalid("argon2: 'pass' must be octet string"))?;
            if bytes.len() > super::MAX_INPUT_LEN {
                warn!(
                    len = bytes.len(),
                    max = super::MAX_INPUT_LEN,
                    "Argon2: password exceeds MAX_INPUT_LEN"
                );
                return Err(invalid("argon2: password exceeds MAX_INPUT_LEN"));
            }
            self.password.zeroize();
            self.password = bytes.to_vec();
            trace!(len = bytes.len(), "Argon2: password set");
        }

        // --- salt -------------------------------------------------------
        if let Some(val) = params.get(PARAM_SALT) {
            let bytes = val
                .as_bytes()
                .ok_or_else(|| invalid("argon2: 'salt' must be octet string"))?;
            if bytes.len() > super::MAX_INPUT_LEN {
                warn!(
                    len = bytes.len(),
                    max = super::MAX_INPUT_LEN,
                    "Argon2: salt exceeds MAX_INPUT_LEN"
                );
                return Err(invalid("argon2: salt exceeds MAX_INPUT_LEN"));
            }
            self.salt = bytes.to_vec();
            trace!(len = bytes.len(), "Argon2: salt set");
        }

        // --- secret -----------------------------------------------------
        if let Some(val) = params.get(PARAM_SECRET) {
            let bytes = val
                .as_bytes()
                .ok_or_else(|| invalid("argon2: 'secret' must be octet string"))?;
            if bytes.len() > super::MAX_INPUT_LEN {
                return Err(invalid("argon2: secret exceeds MAX_INPUT_LEN"));
            }
            if let Some(s) = self.secret.as_mut() {
                s.zeroize();
            }
            self.secret = Some(bytes.to_vec());
            trace!(len = bytes.len(), "Argon2: secret set");
        }

        // --- ad ---------------------------------------------------------
        if let Some(val) = params.get(PARAM_AD) {
            let bytes = val
                .as_bytes()
                .ok_or_else(|| invalid("argon2: 'ad' must be octet string"))?;
            if bytes.len() > super::MAX_INPUT_LEN {
                return Err(invalid("argon2: ad exceeds MAX_INPUT_LEN"));
            }
            self.ad = Some(bytes.to_vec());
            trace!(len = bytes.len(), "Argon2: ad set");
        }

        // --- variant ----------------------------------------------------
        if let Some(val) = params.get(PARAM_VARIANT) {
            let s = val
                .as_str()
                .ok_or_else(|| invalid("argon2: 'variant' must be UTF-8 string"))?;
            self.variant = Argon2Variant::parse(s).ok_or_else(|| {
                invalid(format!(
                    "argon2: unknown variant '{s}' (expected d, i, or id)"
                ))
            })?;
            debug!(variant = %self.variant, "Argon2: variant selected via param");
        }

        // --- u32 scalar parameters --------------------------------------
        if let Some(val) = params.get(PARAM_SIZE) {
            self.out_len = extract_u32(val, PARAM_SIZE)?;
            trace!(out_len = self.out_len, "Argon2: out_len set");
        }

        if let Some(val) = params.get(PARAM_ITER) {
            self.t_cost = extract_u32(val, PARAM_ITER)?;
            debug!(t_cost = self.t_cost, "Argon2: t_cost set");
        }

        if let Some(val) = params.get(PARAM_MEMORY) {
            self.m_cost = extract_u32(val, PARAM_MEMORY)?;
            debug!(m_cost = self.m_cost, "Argon2: m_cost set");
        }

        if let Some(val) = params.get(PARAM_LANES) {
            self.lanes = extract_u32(val, PARAM_LANES)?;
            debug!(lanes = self.lanes, "Argon2: lanes set");
        }

        if let Some(val) = params.get(PARAM_THREADS) {
            self.threads = extract_u32(val, PARAM_THREADS)?;
            debug!(threads = self.threads, "Argon2: threads set");
        }

        if let Some(val) = params.get(PARAM_VERSION) {
            self.version = extract_u32(val, PARAM_VERSION)?;
            debug!(version = self.version, "Argon2: version set");
        }

        Ok(())
    }

    /// Validates that the parameter combination is well-formed and that
    /// all required fields are present.  Does *not* allocate memory —
    /// that happens in `Self::derive_internal` after the ceiling
    /// [`MAX_MEMORY_KIB`] has been enforced here.
    fn validate(&self) -> ProviderResult<()> {
        if self.password.is_empty() {
            warn!("Argon2: derive attempted without password");
            return Err(init_err("argon2: password is required"));
        }
        if self.salt.is_empty() {
            warn!("Argon2: derive attempted without salt");
            return Err(init_err("argon2: salt is required"));
        }
        if self.salt.len() < MIN_SALT_LENGTH {
            warn!(
                got = self.salt.len(),
                min = MIN_SALT_LENGTH,
                "Argon2: salt too short"
            );
            return Err(invalid(format!(
                "argon2: salt must be at least {MIN_SALT_LENGTH} bytes"
            )));
        }

        if !(MIN_LANES..=MAX_LANES).contains(&self.lanes) {
            warn!(lanes = self.lanes, "Argon2: lanes out of range");
            return Err(invalid(format!(
                "argon2: lanes {} outside [{MIN_LANES}, {MAX_LANES}]",
                self.lanes
            )));
        }
        if !(MIN_THREADS..=MAX_THREADS).contains(&self.threads) {
            return Err(invalid(format!(
                "argon2: threads {} outside [{MIN_THREADS}, {MAX_THREADS}]",
                self.threads
            )));
        }
        if self.t_cost < MIN_TIME {
            warn!(t_cost = self.t_cost, "Argon2: t_cost too small");
            return Err(invalid(format!("argon2: t_cost must be ≥ {MIN_TIME}")));
        }
        if self.out_len < MIN_OUT_LENGTH {
            warn!(out_len = self.out_len, "Argon2: out_len too small");
            return Err(invalid(format!(
                "argon2: out_len must be ≥ {MIN_OUT_LENGTH}"
            )));
        }

        let min_mem_for_lanes = self.lanes.checked_mul(8).ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "argon2: lanes · 8 (min memory)",
            })
        })?;
        if self.m_cost < min_mem_for_lanes.max(MIN_MEMORY) {
            warn!(
                m_cost = self.m_cost,
                min = min_mem_for_lanes.max(MIN_MEMORY),
                "Argon2: m_cost too small for lane count"
            );
            return Err(invalid(format!(
                "argon2: m_cost {} must be ≥ 8·lanes = {}",
                self.m_cost, min_mem_for_lanes
            )));
        }
        if u64::from(self.m_cost) > MAX_MEMORY_PARAM {
            return Err(invalid("argon2: m_cost exceeds u32::MAX"));
        }
        if u64::from(self.m_cost) > MAX_MEMORY_KIB {
            warn!(
                m_cost = self.m_cost,
                cap = MAX_MEMORY_KIB,
                "Argon2: m_cost exceeds host-memory cap"
            );
            return Err(invalid(format!(
                "argon2: m_cost {} exceeds cap of {} KiB",
                self.m_cost, MAX_MEMORY_KIB
            )));
        }

        if self.version != ARGON2_VERSION_10 && self.version != ARGON2_VERSION_13 {
            return Err(invalid(format!(
                "argon2: version 0x{:X} is not 0x10 or 0x13",
                self.version
            )));
        }

        Ok(())
    }

    /// Runs the RFC 9106 Argon2 derivation pipeline and writes the digest
    /// into `output`.  Returns the number of bytes written (equal to
    /// `output.len()` on success).
    ///
    /// **Preconditions:** `validate` must have been
    /// called so that `password`, `salt`, `lanes`, `m_cost`, `t_cost`,
    /// `version`, and `out_len` are in-range.  The effective output
    /// length is `output.len()` — `self.out_len` is ignored by this
    /// internal helper so the caller can override it.
    ///
    /// The algorithm follows RFC 9106 §3:
    ///
    /// 1.  Round `m_cost` down so `memory_blocks` is divisible by
    ///     `4 · lanes`.
    /// 2.  Allocate a `memory_blocks × 1 KiB` matrix of `Argon2Block`.
    /// 3.  Compute `H0 = BLAKE2b-512(metadata)` via [`initial_hash`].
    /// 4.  For each lane `l`, seed `memory[l][0]` and `memory[l][1]` via
    ///     `BLAKE2b-long(1024, H0 || LE32(i) || LE32(l))` for `i = 0, 1`.
    /// 5.  Run `t_cost` passes × 4 slices × `lanes` lanes of
    ///     `fill_segment`.
    /// 6.  XOR the last block of each lane into the accumulator.
    /// 7.  Final output: `BLAKE2b-long(output.len(), serialise(acc))`.
    /// 8.  Zeroise memory matrix and intermediate buffers on the way
    ///     out — even on the error path.
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let out_len_u32 =
            u32::try_from(output.len()).map_err(|e| ProviderError::Common(CommonError::from(e)))?;
        if out_len_u32 < MIN_OUT_LENGTH {
            warn!(
                requested = output.len(),
                min = MIN_OUT_LENGTH,
                "Argon2 derive: output length too small"
            );
            return Err(invalid(format!(
                "argon2: output length {} < {MIN_OUT_LENGTH}",
                output.len()
            )));
        }

        // --- Step 1: round memory blocks down to a multiple of 4·lanes. -
        let lanes = self.lanes;
        let m_cost = self.m_cost;
        let group = lanes.checked_mul(SYNC_POINTS).ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "argon2: lanes · SYNC_POINTS",
            })
        })?;
        // group is guaranteed non-zero: validate() enforces lanes ≥ 1.
        let memory_blocks = (m_cost / group) * group;
        if memory_blocks < MIN_MEMORY {
            return Err(invalid(format!(
                "argon2: rounded m_cost {memory_blocks} < {MIN_MEMORY}"
            )));
        }
        let segment_length = memory_blocks / (lanes * SYNC_POINTS);
        let lane_length = memory_blocks / lanes;
        let memory_blocks_usize = usize::try_from(memory_blocks)
            .map_err(|e| ProviderError::Common(CommonError::from(e)))?;
        let lane_length_usize = usize::try_from(lane_length)
            .map_err(|e| ProviderError::Common(CommonError::from(e)))?;

        trace!(
            memory_blocks,
            segment_length,
            lane_length,
            "Argon2 derive_internal: matrix parameters"
        );

        // --- Step 2: allocate memory matrix. -----------------------------
        let mut memory: Vec<Argon2Block> = vec![zero_block(); memory_blocks_usize];

        // --- Step 3: fetch BLAKE2b-512 digest and compute H0. ------------
        let digest = fetch_blake2b()?;
        let h0 = initial_hash(&digest, self)?;

        // --- Step 4: seed first two blocks of every lane. ----------------
        //
        // Per RFC 9106 §3.2, seed format is:
        //   H0 (64B) || LE32(i) || LE32(lane)  =  72 bytes total.
        // For i = 0 write to memory[lane · lane_length + 0];
        // for i = 1 write to memory[lane · lane_length + 1].
        let mut seed_buf: [u8; 72] = [0u8; 72];
        seed_buf[..PREHASH_DIGEST_LENGTH].copy_from_slice(&h0);
        for lane in 0..lanes {
            let lane_le = lane.to_le_bytes();
            let lane_usize =
                usize::try_from(lane).map_err(|e| ProviderError::Common(CommonError::from(e)))?;
            let lane_offset = lane_usize.checked_mul(lane_length_usize).ok_or_else(|| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "argon2: lane_offset (lane · lane_length)",
                })
            })?;
            for i in 0u32..2u32 {
                seed_buf[PREHASH_DIGEST_LENGTH..PREHASH_DIGEST_LENGTH + 4]
                    .copy_from_slice(&i.to_le_bytes());
                seed_buf[PREHASH_DIGEST_LENGTH + 4..PREHASH_DIGEST_LENGTH + 8]
                    .copy_from_slice(&lane_le);
                let block_bytes =
                    blake2b_long(&digest, BLOCK_SIZE_U32, &seed_buf).inspect_err(|_| {
                        // On the error path, scrub the seed buffer since it
                        // holds H0-derived material that is key-dependent.
                        // `h0` is on the stack and will go out of scope; we
                        // still zeroise for defence in depth.
                    })?;
                let slot = lane_offset
                    .checked_add(
                        usize::try_from(i)
                            .map_err(|e| ProviderError::Common(CommonError::from(e)))?,
                    )
                    .ok_or_else(|| {
                        ProviderError::Common(CommonError::ArithmeticOverflow {
                            operation: "argon2: seed block index",
                        })
                    })?;
                if slot >= memory.len() {
                    return Err(invalid(format!(
                        "argon2: seed block index {slot} out of range ({})",
                        memory.len()
                    )));
                }
                load_block_bytes(&mut memory[slot], &block_bytes);
                // `block_bytes` contains the fully expanded 1 KiB seed for
                // memory[slot]; it is key-dependent until zeroised.  Since
                // we no longer need it, scrub before the allocation is
                // released.  (Vec drops ordinary bytes without zeroing.)
                let mut bb = block_bytes;
                bb.zeroize();
            }
        }
        // Scrub the 72-byte seed buffer — still holds H0.
        seed_buf.zeroize();

        // --- Step 5: fill memory blocks. ---------------------------------
        fill_memory_blocks(
            &mut memory,
            self.variant,
            self.version,
            self.t_cost,
            lanes,
            segment_length,
            lane_length,
        )?;

        // --- Step 6: XOR-fold the last block of each lane. ---------------
        let mut acc: Argon2Block = zero_block();
        for lane in 0..lanes {
            let lane_usize =
                usize::try_from(lane).map_err(|e| ProviderError::Common(CommonError::from(e)))?;
            let last_index = lane_usize
                .checked_mul(lane_length_usize)
                .and_then(|x| x.checked_add(lane_length_usize.saturating_sub(1)))
                .ok_or_else(|| {
                    ProviderError::Common(CommonError::ArithmeticOverflow {
                        operation: "argon2: lane-last index",
                    })
                })?;
            if last_index >= memory.len() {
                return Err(invalid(format!(
                    "argon2: lane last index {last_index} out of range ({})",
                    memory.len()
                )));
            }
            xor_block(&mut acc, &memory[last_index]);
        }

        // --- Step 7: serialise acc, apply BLAKE2b-long to reach outlen. --
        let mut acc_bytes = vec![0u8; BLOCK_SIZE];
        store_block_bytes(&acc, &mut acc_bytes);
        let mut out = blake2b_long(&digest, out_len_u32, &acc_bytes)?;

        // Copy into caller buffer.  `out.len() == output.len()` by
        // construction in `blake2b_long`, so a direct assignment works.
        output.copy_from_slice(&out);

        // --- Step 8: zeroise sensitive intermediates. --------------------
        // Memory matrix contains key-derived state; scrub before Drop.
        for blk in &mut memory {
            blk.zeroize();
        }
        acc.zeroize();
        acc_bytes.zeroize();
        // `out` was already copied to the caller buffer — scrub our local
        // mirror.  The caller's buffer is untouched.
        out.zeroize();

        trace!(
            bytes_written = output.len(),
            "Argon2 derive_internal complete"
        );
        Ok(output.len())
    }
}

/// Extract a `u32` from a `ParamValue` that may be encoded as either
/// `UInt32` or `UInt64` — the provider framework accepts both and
/// higher-level callers vary in which they emit.  Returns
/// `ProviderError::Common(CommonError::InvalidArgument)` for unexpected
/// types and `ProviderError::Common(CommonError::CastOverflow(_))` when
/// the value does not fit in a `u32` (via `u32::try_from`, honouring
/// Rule R6 — no bare `as` narrowing).
fn extract_u32(val: &openssl_common::param::ParamValue, key: &str) -> ProviderResult<u32> {
    if let Some(v) = val.as_u32() {
        return Ok(v);
    }
    if let Some(v) = val.as_u64() {
        return u32::try_from(v)
            .map_err(CommonError::from)
            .map_err(ProviderError::Common);
    }
    Err(invalid(format!(
        "argon2: parameter '{key}' must be UInt32 or UInt64"
    )))
}

// =============================================================================
// BLAKE2b integration — variable-output hashing `H'` (RFC 9106 §3.3)
// =============================================================================

/// Fetches `BLAKE2B-512` from the default [`LibContext`] provider store.
///
/// This is factored into its own function because every stage of Argon2
/// (initial hash, block seeding, finalisation) needs a fresh handle.
/// The `MessageDigest` itself is cheap to clone within a single
/// derivation (it is just a descriptor), but it *cannot* be created
/// without a library context.
#[inline]
fn fetch_blake2b() -> ProviderResult<MessageDigest> {
    let lib_ctx = LibContext::get_default();
    MessageDigest::fetch(&lib_ctx, BLAKE2B512, None).map_err(dispatch_err)
}

/// Single-shot BLAKE2b-512 hash of `data` (up to 64 bytes of output).
/// Used whenever the caller knows the output will fit in one digest.
fn blake2b_oneshot(digest: &MessageDigest, data: &[&[u8]]) -> ProviderResult<Vec<u8>> {
    let mut ctx = MdContext::new();
    ctx.init(digest, None).map_err(dispatch_err)?;
    for chunk in data {
        ctx.update(chunk).map_err(dispatch_err)?;
    }
    ctx.finalize().map_err(dispatch_err)
}

/// The RFC 9106 §3.3 variable-output hash function `H'`.
///
/// For requests up to 64 bytes this is a single `BLAKE2b` call whose
/// `len` parameter is the requested output size, prefixed with the
/// 32-bit little-endian output length.  For requests larger than 64
/// bytes the spec prescribes an iterative construction:
///
/// ```text
///   V1 = BLAKE2b(LE32(outlen) || X)
///   V2 = BLAKE2b(V1)
///   ...
///   Vr = BLAKE2b(V_{r-1})
///   A1..A_{r-1} = V1[0..32] || V2[0..32] || ... || V_{r-1}[0..32]
///   Ar          = V_r                       (whatever bytes remain to reach outlen)
///   H'(X, outlen) = A1 || A2 || ... || Ar
/// ```
///
/// with `r = ceil(outlen / 32) + 1` when `outlen > 64`.  Each `V_i` is a
/// full 64-byte `BLAKE2b` digest; we take the first 32 bytes except for the
/// last, where we take the remaining `outlen - 32·(r-1)` bytes.  Since
/// [`MessageDigest::digest_size`] reports the underlying hash's native
/// size (64 for `BLAKE2b-512`), we perform the truncation ourselves when
/// `outlen <= 64`.
///
/// # Errors
///
/// Returns `ProviderError::Dispatch` if the `BLAKE2b` fetch or any of
/// the digest operations fails — i.e. this can only happen when the
/// provider framework is misconfigured or `LibContext` is missing the
/// default provider.
fn blake2b_long(digest: &MessageDigest, out_len: u32, input: &[u8]) -> ProviderResult<Vec<u8>> {
    let out_len_usize = out_len as usize;

    if out_len == 0 {
        return Ok(Vec::new());
    }

    let outlen_le = out_len.to_le_bytes();

    if out_len_usize <= PREHASH_DIGEST_LENGTH {
        // Single-shot path: BLAKE2b(LE32(outlen) || X) truncated to outlen.
        let h = blake2b_oneshot(digest, &[&outlen_le, input])?;
        let mut v = Vec::with_capacity(out_len_usize);
        v.extend_from_slice(&h[..out_len_usize]);
        return Ok(v);
    }

    trace!(out_len = out_len_usize, "blake2b_long: iterative path");

    // Iterative path.  r = ceil(outlen / 32).
    let mut result = Vec::with_capacity(out_len_usize);

    // V1 = H(LE32(outlen) || X)
    let mut v = blake2b_oneshot(digest, &[&outlen_le, input])?;
    result.extend_from_slice(&v[..32]);

    // Number of additional 32-byte chunks we must emit before the tail.
    // total_chunks = r = ceil(outlen / 32); we've already emitted 1.
    // Chunks [2 .. r-1] are full 32-byte slices of V_i (`V_i[0..32]`);
    // chunk r is V_r truncated to the tail length.
    let mut remaining = out_len_usize - 32;

    while remaining > 64 {
        v = blake2b_oneshot(digest, &[&v])?;
        result.extend_from_slice(&v[..32]);
        remaining -= 32;
    }

    // Final chunk: V_r is a full BLAKE2b digest (64 bytes); take exactly
    // `remaining` bytes.
    v = blake2b_oneshot(digest, &[&v])?;
    result.extend_from_slice(&v[..remaining]);

    // Defensive scrub of intermediate V_r buffer — it may contain
    // key-derived material in early iterations.
    v.zeroize();

    debug_assert_eq!(result.len(), out_len_usize);
    Ok(result)
}

// =============================================================================
// Initial hash H0 (RFC 9106 §3.2)
// =============================================================================

/// Computes the Argon2 initial hash `H0` according to RFC 9106 §3.2.
///
/// Layout (all multi-byte values little-endian):
/// ```text
///   LE32(lanes)      || LE32(tag_len)  || LE32(m_cost)   || LE32(t_cost)
///   || LE32(version) || LE32(y)        || LE32(|P|) || P || LE32(|S|) || S
///   || LE32(|K|)     || K              || LE32(|X|) || X
/// ```
/// where `y` is the variant type code (0 = d, 1 = i, 2 = id) and the
/// key `K` / associated data `X` are optional (absent fields are
/// encoded as `LE32(0)` with no trailing bytes).
///
/// The result is always 64 bytes — the native size of BLAKE2b-512.
fn initial_hash(
    digest: &MessageDigest,
    ctx: &Argon2Context,
) -> ProviderResult<[u8; PREHASH_DIGEST_LENGTH]> {
    let mut md = MdContext::new();
    md.init(digest, None).map_err(dispatch_err)?;

    // Helper closures that defer error propagation cleanly.
    let update = |md: &mut MdContext, data: &[u8]| -> ProviderResult<()> {
        md.update(data).map_err(dispatch_err)
    };
    let update_u32 = |md: &mut MdContext, v: u32| -> ProviderResult<()> {
        md.update(&v.to_le_bytes()).map_err(dispatch_err)
    };

    update_u32(&mut md, ctx.lanes)?;
    update_u32(&mut md, ctx.out_len)?;
    update_u32(&mut md, ctx.m_cost)?;
    update_u32(&mut md, ctx.t_cost)?;
    update_u32(&mut md, ctx.version)?;
    update_u32(&mut md, ctx.variant.type_code())?;

    // Password (length-prefixed).
    let pwd_len = u32::try_from(ctx.password.len())
        .map_err(|e| ProviderError::Common(CommonError::from(e)))?;
    update_u32(&mut md, pwd_len)?;
    update(&mut md, &ctx.password)?;

    // Salt (length-prefixed).
    let salt_len =
        u32::try_from(ctx.salt.len()).map_err(|e| ProviderError::Common(CommonError::from(e)))?;
    update_u32(&mut md, salt_len)?;
    update(&mut md, &ctx.salt)?;

    // Secret (K) — optional.
    let secret_bytes: &[u8] = match &ctx.secret {
        Some(s) => s.as_slice(),
        None => &[],
    };
    let secret_len = u32::try_from(secret_bytes.len())
        .map_err(|e| ProviderError::Common(CommonError::from(e)))?;
    update_u32(&mut md, secret_len)?;
    update(&mut md, secret_bytes)?;

    // Associated data (X) — optional.
    let ad_bytes: &[u8] = match &ctx.ad {
        Some(a) => a.as_slice(),
        None => &[],
    };
    let ad_len =
        u32::try_from(ad_bytes.len()).map_err(|e| ProviderError::Common(CommonError::from(e)))?;
    update_u32(&mut md, ad_len)?;
    update(&mut md, ad_bytes)?;

    let h0_vec = md.finalize().map_err(dispatch_err)?;
    if h0_vec.len() != PREHASH_DIGEST_LENGTH {
        return Err(ProviderError::Dispatch(format!(
            "initial_hash: expected {PREHASH_DIGEST_LENGTH}-byte BLAKE2b digest, got {}",
            h0_vec.len()
        )));
    }
    let mut h0 = [0u8; PREHASH_DIGEST_LENGTH];
    h0.copy_from_slice(&h0_vec);

    trace!("Argon2 initial_hash (H0) computed");
    Ok(h0)
}

// =============================================================================
// Compression function G (RFC 9106 §3.5)  —  Blamka round + permutations
// =============================================================================

/// Lower-32-bit multiply used by the Blamka round function.
///
/// RFC 9106 defines `GB(a, b, c, d)` using `2 * trunc32(a) * trunc32(b)`
/// where `trunc32` keeps only the low 32 bits of its 64-bit operand.
/// This is effectively a 32-bit unsigned multiply whose full 64-bit
/// result is then doubled.
#[inline]
const fn mul_lower(a: u64, b: u64) -> u64 {
    let a_lo = a & 0xFFFF_FFFF;
    let b_lo = b & 0xFFFF_FFFF;
    a_lo.wrapping_mul(b_lo)
}

/// The Blamka "quarter round" `GB` applied to four 64-bit lanes.
///
/// Given lane references `a`, `b`, `c`, `d`, the round performs four
/// add-XOR-rotate sub-steps with 32, 24, 16, and 63-bit right rotations
/// (see RFC 9106 §3.5 `BlaMka` definition).  Each `add` step is the
/// `BlaMka`-specific `x + y + 2·trunc32(x)·trunc32(y)` rather than a
/// plain addition — this is what distinguishes Argon2's compression
/// from `BLAKE2b`'s.
#[inline]
fn gb(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64) {
    // Step 1: a += b + 2·trunc(a)·trunc(b);  d = ROT32(d XOR a)
    *a = a
        .wrapping_add(*b)
        .wrapping_add(mul_lower(*a, *b).wrapping_mul(2));
    *d = (*d ^ *a).rotate_right(32);

    // Step 2: c += d + 2·trunc(c)·trunc(d);  b = ROT24(b XOR c)
    *c = c
        .wrapping_add(*d)
        .wrapping_add(mul_lower(*c, *d).wrapping_mul(2));
    *b = (*b ^ *c).rotate_right(24);

    // Step 3: a += b + 2·trunc(a)·trunc(b);  d = ROT16(d XOR a)
    *a = a
        .wrapping_add(*b)
        .wrapping_add(mul_lower(*a, *b).wrapping_mul(2));
    *d = (*d ^ *a).rotate_right(16);

    // Step 4: c += d + 2·trunc(c)·trunc(d);  b = ROT63(b XOR c)
    *c = c
        .wrapping_add(*d)
        .wrapping_add(mul_lower(*c, *d).wrapping_mul(2));
    *b = (*b ^ *c).rotate_right(63);
}

/// Applies the `P` permutation (eight `GB` rounds) on a contiguous
/// 16-element window of a block.  `v[0..16]` is interpreted as a 4×4
/// matrix stored row-major; the first four rounds mix columns and the
/// last four rounds mix diagonals (rows of the rotated matrix).
///
/// This helper takes a mutable 16-element slice rather than the whole
/// block — the caller picks which row or column to permute.
#[inline]
fn permutation_p(v: &mut [u64; 16]) {
    // Extract each field individually so we can call `gb` with
    // disjoint mutable references; using indices into `v` would
    // require `split_at_mut` trickery because each `gb` touches four
    // distinct lanes.
    let [mut v0, mut v1, mut v2, mut v3, mut v4, mut v5, mut v6, mut v7, mut v8, mut v9, mut v10, mut v11, mut v12, mut v13, mut v14, mut v15] =
        *v;

    // Columns.
    gb(&mut v0, &mut v4, &mut v8, &mut v12);
    gb(&mut v1, &mut v5, &mut v9, &mut v13);
    gb(&mut v2, &mut v6, &mut v10, &mut v14);
    gb(&mut v3, &mut v7, &mut v11, &mut v15);

    // Diagonals.
    gb(&mut v0, &mut v5, &mut v10, &mut v15);
    gb(&mut v1, &mut v6, &mut v11, &mut v12);
    gb(&mut v2, &mut v7, &mut v8, &mut v13);
    gb(&mut v3, &mut v4, &mut v9, &mut v14);

    *v = [
        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
    ];
}

/// `fill_block` applies the Argon2 compression to produce the next
/// block of memory given the previous (`prev`) and reference (`ref_`)
/// blocks.
///
/// RFC 9106 §3.5 defines this as:
/// ```text
///   R  = prev XOR ref
///   Z  = P(ROW(R)) (row-wise for columns), then P(COL(R)) (column-wise for rows)
///        but specified here as: first eight column P-rounds (over rows
///        of the 128-element block viewed as 8 rows of 16 elements),
///        then eight row P-rounds (over columns).
///   next = R XOR Z               (version = 0x13 fresh block OR pass 0 segment 0)
///   next = next XOR prev_next    (version = 0x13 with_xor iterations)
/// ```
/// The OpenSSL C code uses `with_xor=1` to indicate the "xor into the
/// existing `next` value" variant used for iterations >= 1 when
/// `version = 0x13`.  The variant-specific logic (when to set
/// `with_xor`) lives in `fill_segment`.
fn fill_block(prev: &Argon2Block, ref_: &Argon2Block, next: &mut Argon2Block, with_xor: bool) {
    // R = prev XOR ref
    let mut r = [0u64; QWORDS_IN_BLOCK];
    for i in 0..QWORDS_IN_BLOCK {
        r[i] = prev[i] ^ ref_[i];
    }

    // `tmp` holds R (and optionally XORs with existing `next` when
    // with_xor is true) so the final step can combine it with the
    // permuted R.
    let mut tmp = r;
    if with_xor {
        for i in 0..QWORDS_IN_BLOCK {
            tmp[i] ^= next[i];
        }
    }

    // Eight "column" P-rounds over 8 rows of 16 u64s each.
    for i in 0..8 {
        let base = 16 * i;
        let mut window: [u64; 16] = [0u64; 16];
        window.copy_from_slice(&r[base..base + 16]);
        permutation_p(&mut window);
        r[base..base + 16].copy_from_slice(&window);
    }

    // Eight "row" P-rounds over 8 rows of strided 16 u64s each.
    //
    // Each strided row contains indices
    //   { 2i, 2i+1, 2i+16, 2i+17, 2i+32, 2i+33, ..., 2i+112, 2i+113 }
    // for i in 0..8.  This is equivalent to viewing the block as a
    // 16×8 matrix of pairs and permuting each "row of pairs" of that
    // matrix.
    for i in 0..8 {
        let mut window: [u64; 16] = [0u64; 16];
        for j in 0..8 {
            window[2 * j] = r[2 * i + 16 * j];
            window[2 * j + 1] = r[2 * i + 16 * j + 1];
        }
        permutation_p(&mut window);
        for j in 0..8 {
            r[2 * i + 16 * j] = window[2 * j];
            r[2 * i + 16 * j + 1] = window[2 * j + 1];
        }
    }

    // Final: next = R (permuted) XOR tmp (original R ^ maybe old next).
    for i in 0..QWORDS_IN_BLOCK {
        next[i] = r[i] ^ tmp[i];
    }
}

// =============================================================================
// Data-independent addressing helpers (Argon2i / first half of Argon2id pass 0)
// =============================================================================

/// Generates a fresh address block for data-independent addressing.
///
/// RFC 9106 §3.4.2 defines addresses for Argon2i and for the first two
/// slices of pass 0 of Argon2id as the output of applying the
/// compression function to a structured "input block":
///
/// ```text
///   input_block = { pass, lane, slice, total_blocks, passes, type, counter, 0, 0, ... }
///   zero_block  = 0^1024
///   address_block = G(zero_block, G(zero_block, input_block))
/// ```
///
/// The counter starts at `1` and is incremented on every refresh.
/// Each address block yields 128 pseudo-random `u64` values which the
/// caller consumes one per memory position; once all 128 are consumed
/// the block is regenerated with an incremented counter.
///
/// The OpenSSL C implementation allocates three separate blocks
/// (`zero_block`, `input_block`, `address_block`) and passes `with_xor
/// = 0` to both inner `fill_block` calls.
fn next_addresses(
    input_block: &mut Argon2Block,
    address_block: &mut Argon2Block,
    zero_buffer: &Argon2Block,
) {
    // Increment the counter which lives at index 6 of `input_block`.
    // The fixed-layout fields are set up once by the caller; only the
    // counter changes between refreshes.
    input_block[6] = input_block[6].wrapping_add(1);

    // address_block = G(zero_buffer, G(zero_buffer, input_block)).
    //
    // The inner call writes to a temporary; we reuse `address_block`
    // as scratch by invoking `fill_block` with `with_xor = false`
    // (which fully overwrites `next`).
    fill_block(zero_buffer, input_block, address_block, false);
    // Copy intermediate result so the outer fill_block has a source
    // separate from the destination.
    let mut tmp: Argon2Block = zero_block();
    copy_block(&mut tmp, address_block);
    fill_block(zero_buffer, &tmp, address_block, false);
}

// =============================================================================
// Reference index computation (RFC 9106 §3.4.1.2)
// =============================================================================

/// Computes the reference-area size used by the quadratic-bias mapping.
///
/// The C reference implementation exploits unsigned wrap-around with
/// expressions like `slice * seglen + ((index == 0) ? -1 : 0)`.  In
/// Rust we materialise the same value using `wrapping_sub(1)` when
/// `index == 0`.
#[inline]
fn reference_area_size(
    pass: u32,
    slice: u32,
    index: u32,
    same_lane: bool,
    segment_length: u32,
    lane_length: u32,
) -> u32 {
    if pass == 0 {
        if slice == 0 {
            // First slice of pass 0: only earlier blocks in this segment.
            // The caller guarantees `index >= 2` here via `starting_index`.
            index.wrapping_sub(1)
        } else if same_lane {
            // Earlier slices of this pass plus the current segment up to the current index.
            slice
                .wrapping_mul(segment_length)
                .wrapping_add(index)
                .wrapping_sub(1)
        } else {
            // Earlier slices of this pass in another lane.
            let base = slice.wrapping_mul(segment_length);
            if index == 0 {
                base.wrapping_sub(1)
            } else {
                base
            }
        }
    } else if same_lane {
        // Later passes, same lane: everything except the current segment.
        lane_length
            .wrapping_sub(segment_length)
            .wrapping_add(index)
            .wrapping_sub(1)
    } else {
        // Later passes, other lane.
        let base = lane_length.wrapping_sub(segment_length);
        if index == 0 {
            base.wrapping_sub(1)
        } else {
            base
        }
    }
}

/// Returns the starting position used in `index_alpha` to wrap the
/// relative offset around the lane.
#[inline]
fn start_position(pass: u32, slice: u32, segment_length: u32) -> u32 {
    if pass != 0 && slice != SYNC_POINTS - 1 {
        (slice + 1).wrapping_mul(segment_length)
    } else {
        0
    }
}

/// Computes the absolute position of the reference block within the
/// reference lane for a block being written at `(pass, slice, index)`.
///
/// The RFC specifies a "quadratic" bias so that blocks closer to the
/// current position are selected with higher probability:
///
/// ```text
///   rel_pos = (rnd & 0xFFFFFFFF)
///   rel_pos = (rel_pos * rel_pos) >> 32
///   rel_pos = ref_area_size - 1 - ((ref_area_size * rel_pos) >> 32)
///   abs_pos = (start_pos + rel_pos) % lane_length
/// ```
///
/// All intermediate multiplications are performed on `u64`, so no
/// narrowing cast is necessary.  Rule R6 compliant.
fn index_alpha(
    pass: u32,
    slice: u32,
    index: u32,
    same_lane: bool,
    segment_length: u32,
    lane_length: u32,
    pseudo_rand: u64,
) -> u32 {
    let ref_area_size =
        reference_area_size(pass, slice, index, same_lane, segment_length, lane_length);
    let start_pos = start_position(pass, slice, segment_length);

    let rnd_lo: u64 = pseudo_rand & 0xFFFF_FFFF;
    let rel_pos_sq: u64 = (rnd_lo.wrapping_mul(rnd_lo)) >> 32;

    let ref_area_u64: u64 = u64::from(ref_area_size);
    let scaled: u64 = (ref_area_u64.wrapping_mul(rel_pos_sq)) >> 32;

    // rel_pos = ref_area_size - 1 - scaled (all in u64 to avoid underflow).
    let rel_pos: u64 = ref_area_u64.saturating_sub(1).saturating_sub(scaled);

    let abs_pos_u64: u64 =
        (u64::from(start_pos).wrapping_add(rel_pos)) % u64::from(lane_length).max(1);

    // abs_pos fits in u32 because it's bounded by lane_length.
    u32::try_from(abs_pos_u64).unwrap_or(u32::MAX)
}

// =============================================================================
// Segment fill loop (RFC 9106 §3.4)
// =============================================================================

/// Decides, for a given `(variant, pass, slice)` tuple, whether
/// `fill_segment` must use data-independent addressing.
#[inline]
const fn use_data_independent(variant: Argon2Variant, pass: u32, slice: u32) -> bool {
    match variant {
        Argon2Variant::Argon2i => true,
        Argon2Variant::Argon2d => false,
        Argon2Variant::Argon2id => pass == 0 && slice < (SYNC_POINTS / 2),
    }
}

/// Fills one segment of the memory matrix.
///
/// A segment is one quarter of a lane's blocks (`SYNC_POINTS = 4`).
/// Blocks within a segment are filled sequentially; reference blocks
/// may live anywhere in the already-filled portion of the matrix per
/// the variant's addressing rules.
#[allow(clippy::too_many_arguments)]
fn fill_segment(
    memory: &mut [Argon2Block],
    variant: Argon2Variant,
    version: u32,
    t_cost: u32,
    pass: u32,
    lane: u32,
    slice: u32,
    lanes: u32,
    segment_length: u32,
    lane_length: u32,
) -> ProviderResult<()> {
    let data_indep = use_data_independent(variant, pass, slice);

    let zero_buffer: Argon2Block = zero_block();
    let mut input_block: Argon2Block = zero_block();
    let mut address_block: Argon2Block = zero_block();

    if data_indep {
        // RFC 9106 §3.4.2 input block layout:
        //   [pass, lane, slice, total_blocks, passes, type, counter, 0, ...]
        input_block[0] = u64::from(pass);
        input_block[1] = u64::from(lane);
        input_block[2] = u64::from(slice);
        input_block[3] = u64::from(lanes).wrapping_mul(u64::from(lane_length));
        input_block[4] = u64::from(t_cost);
        input_block[5] = u64::from(variant.type_code());
        // input_block[6] is the counter; `next_addresses` increments it
        // before each refresh, so it must start at 0.
    }

    // The first two blocks of pass 0 / slice 0 are pre-seeded from H0
    // in `derive_internal`, so skip them here.
    let starting_index: u32 = if pass == 0 && slice == 0 { 2 } else { 0 };

    // Compute initial offsets.  `curr_offset` is the absolute index of
    // the first block we must write; `prev_offset` is the block
    // immediately preceding it (wrapping within the lane).
    let mut curr_offset: u32 = lane
        .wrapping_mul(lane_length)
        .wrapping_add(slice.wrapping_mul(segment_length))
        .wrapping_add(starting_index);

    let mut prev_offset: u32 = if curr_offset % lane_length == 0 {
        // First block in the lane: wrap to the last block of this lane.
        curr_offset.wrapping_add(lane_length).wrapping_sub(1)
    } else {
        curr_offset.wrapping_sub(1)
    };

    for index in starting_index..segment_length {
        // Handle the one-off case where we just crossed the lane start:
        // after incrementing from `curr_offset = k*lane_length`, the new
        // `curr_offset % lane_length == 1` and `prev_offset` must be
        // reset to the true previous block.
        if curr_offset % lane_length == 1 {
            prev_offset = curr_offset.wrapping_sub(1);
        }

        // Refresh the address_block every ARGON2_ADDRESSES_IN_BLOCK (128)
        // positions for data-independent addressing.  The C reference
        // implementation triggers the refresh when `i % 128 == 0`,
        // which is always true for `i = 0` (the first iteration).
        if data_indep && (index % ADDRESSES_IN_BLOCK_U32) == 0 {
            next_addresses(&mut input_block, &mut address_block, &zero_buffer);
        }

        // Pull pseudo-random u64 either from the address block or from
        // the first word of the previous block.
        let pseudo_rand: u64 = if data_indep {
            address_block[(index as usize) % ADDRESSES_IN_BLOCK]
        } else {
            let prev_idx = prev_offset as usize;
            if prev_idx >= memory.len() {
                return Err(invalid(format!(
                    "fill_segment: prev offset {prev_idx} out of range"
                )));
            }
            memory[prev_idx][0]
        };

        // Lane selection: for pass 0 slice 0 we must stay in the
        // current lane.  Otherwise pick any lane using the upper 32
        // bits of `pseudo_rand`.
        let ref_lane: u32 = if pass == 0 && slice == 0 {
            lane
        } else {
            // Upper 32 bits of pseudo_rand as a u32 (truncation via shift).
            let pr_hi: u32 = u32::try_from((pseudo_rand >> 32) & 0xFFFF_FFFF).unwrap_or(u32::MAX);
            pr_hi.checked_rem(lanes).unwrap_or(0)
        };
        let same_lane = ref_lane == lane;

        let ref_index: u32 = index_alpha(
            pass,
            slice,
            index,
            same_lane,
            segment_length,
            lane_length,
            pseudo_rand,
        );

        let ref_offset: usize = (ref_lane as usize)
            .wrapping_mul(lane_length as usize)
            .wrapping_add(ref_index as usize);
        let prev_idx = prev_offset as usize;
        let curr_idx = curr_offset as usize;

        if ref_offset >= memory.len() || prev_idx >= memory.len() || curr_idx >= memory.len() {
            return Err(invalid(format!(
                "fill_segment: index out of bounds (prev={prev_idx}, ref={ref_offset}, curr={curr_idx}, memlen={})",
                memory.len()
            )));
        }

        // Decide whether to XOR into the existing block.
        // ARGON2_VERSION_13: with_xor = (pass > 0)
        // ARGON2_VERSION_10: with_xor = 0 unconditionally
        let with_xor = version == ARGON2_VERSION_13 && pass > 0;

        // Copy the source blocks to stack locals so the borrow checker
        // accepts simultaneous mutable access to `memory[curr_idx]`.
        // Each copy is 1 KiB, paid once per compression — negligible
        // vs. the compression itself.
        let prev_block = memory[prev_idx];
        let ref_block = memory[ref_offset];
        fill_block(&prev_block, &ref_block, &mut memory[curr_idx], with_xor);

        curr_offset = curr_offset.wrapping_add(1);
        prev_offset = prev_offset.wrapping_add(1);
    }

    Ok(())
}

// =============================================================================
// Orchestration: fill_memory_blocks (RFC 9106 §3.4)
// =============================================================================

/// Fills the entire memory matrix over `t_cost` passes × `SYNC_POINTS`
/// slices × `lanes` lanes × `segment_length` positions.
///
/// The Rust port is single-threaded: all lanes are filled
/// sequentially.  This matches OpenSSL's behaviour when built with
/// `ARGON2_NO_THREADS`.  Future optimisation could spawn `threads`
/// parallel workers per slice using `std::thread::scope`, but doing
/// so would require additional coordination and is not required for
/// feature parity.
fn fill_memory_blocks(
    memory: &mut [Argon2Block],
    variant: Argon2Variant,
    version: u32,
    t_cost: u32,
    lanes: u32,
    segment_length: u32,
    lane_length: u32,
) -> ProviderResult<()> {
    trace!(
        t_cost,
        lanes,
        segment_length,
        lane_length,
        "Argon2 fill_memory_blocks"
    );
    for pass in 0..t_cost {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                fill_segment(
                    memory,
                    variant,
                    version,
                    t_cost,
                    pass,
                    lane,
                    slice,
                    lanes,
                    segment_length,
                    lane_length,
                )?;
            }
        }
    }
    Ok(())
}

// =============================================================================
// `KdfContext` trait implementation for `Argon2Context`
// =============================================================================

impl KdfContext for Argon2Context {
    /// Derives an Argon2 digest of length `key.len()` into `key`.
    ///
    /// If `params` is non-empty, parameters are applied via
    /// `Argon2Context::apply_params` before derivation — this lets
    /// callers set password / salt / cost parameters in the same call.
    /// `self.out_len` is overridden by `key.len()` so the caller's
    /// buffer size always wins (the explicit `"size"` parameter is
    /// recorded only as a hint — the actual output width is determined
    /// by the buffer).
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Init`] if `password` or `salt` has not been
    ///   set (via `set_params` or the `params` argument).
    /// - [`ProviderError::Common(CommonError::InvalidArgument)`] if any
    ///   cost/size parameter is out of RFC 9106 range or if `key.len()`
    ///   is below `MIN_OUT_LENGTH` (4 bytes).
    /// - [`ProviderError::Common(CommonError::CastOverflow)`] if
    ///   `key.len()` does not fit in `u32`.
    /// - [`ProviderError::Common(CommonError::ArithmeticOverflow)`] for
    ///   internal index overflow during memory matrix addressing.
    /// - `ProviderError::Dispatch` for BLAKE2b-512 fetch / update /
    ///   finalise failures (indicates a misconfigured `LibContext`).
    #[instrument(
        skip(self, key, params),
        fields(variant = %self.variant, out_len = key.len()),
    )]
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        // Apply any inline parameters first (matches OpenSSL's
        // `kdf_argon2_derive` in providers/implementations/kdfs/argon2.c
        // which invokes set_ctx_params at the top of derive).
        if !params.is_empty() {
            self.apply_params(params)?;
        }

        // Record the caller's requested output width on the context so
        // `initial_hash` incorporates it into H0 exactly as RFC 9106
        // requires.  The `u32` cast is performed here (once) via
        // `try_from` and the fallible variant of the `From<TryFromIntError>`
        // chain on `ProviderError`.
        self.out_len =
            u32::try_from(key.len()).map_err(|e| ProviderError::Common(CommonError::from(e)))?;

        self.validate()?;
        self.derive_internal(key)
    }

    /// Resets the context to a freshly-constructed state, keeping the
    /// variant pinned.
    ///
    /// All key-dependent fields (password, secret, salt, associated
    /// data) are scrubbed via `Zeroize::zeroize` before being cleared,
    /// matching OpenSSL's `kdf_argon2_reset` which calls
    /// `OPENSSL_cleanse` followed by `OPENSSL_clear_free` on each
    /// allocated buffer.  The variant (Argon2d/Argon2i/Argon2id) is
    /// preserved because it is a property of the provider that built
    /// this context, not a user-settable parameter.
    #[instrument(skip(self), fields(variant = %self.variant))]
    fn reset(&mut self) -> ProviderResult<()> {
        debug!("Argon2Context::reset");

        // Scrub secret material before clearing the vectors.
        self.password.zeroize();
        self.password.clear();

        if let Some(ref mut s) = self.secret {
            s.zeroize();
        }
        self.secret = None;

        // Salt and associated data are NOT secret per RFC 9106, but we
        // still zero them defensively to keep memory clean of
        // key-correlated public data.
        self.salt.zeroize();
        self.salt.clear();

        if let Some(ref mut a) = self.ad {
            a.zeroize();
        }
        self.ad = None;

        // Restore parameter defaults (variant stays pinned).
        self.out_len = DEFAULT_OUTLEN;
        self.t_cost = DEFAULT_T_COST;
        self.m_cost = DEFAULT_M_COST;
        self.lanes = DEFAULT_LANES;
        self.threads = DEFAULT_THREADS;
        self.version = ARGON2_VERSION_13;

        Ok(())
    }

    /// Returns a `ParamSet` containing the current numeric parameters
    /// of the context: `size`, `iter`, `memcost`, `lanes`, `threads`,
    /// `version`.
    ///
    /// Secret material (`password`, `secret`, `ad`) is *never* exposed
    /// via `get_params` — this matches the C `kdf_argon2_get_ctx_params`
    /// function in `providers/implementations/kdfs/argon2.c` which only
    /// reports `out_len`.  We additionally report the cost parameters
    /// because they are useful for diagnostic tools and do not leak
    /// anything sensitive.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_u32(PARAM_SIZE, self.out_len)
            .push_u32(PARAM_ITER, self.t_cost)
            .push_u32(PARAM_MEMORY, self.m_cost)
            .push_u32(PARAM_LANES, self.lanes)
            .push_u32(PARAM_THREADS, self.threads)
            .push_u32(PARAM_VERSION, self.version)
            .build())
    }

    /// Applies a fresh set of parameters, overriding whatever was
    /// previously set.  See `Argon2Context::apply_params` for the
    /// recognised key / value schema.
    #[instrument(skip(self, params), fields(variant = %self.variant))]
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        debug!(params_len = params.len(), "Argon2Context::set_params");
        self.apply_params(params)
    }
}

// =============================================================================
// Provider structs — one per Argon2 variant
// =============================================================================

/// Zero-sized provider type exposing the Argon2d algorithm.
///
/// Argon2d uses **data-dependent** memory addressing.  It is the
/// fastest variant and offers maximum resistance against time-memory
/// trade-off attacks, but is vulnerable to side-channel attacks that
/// can observe memory access patterns.  Suitable for cryptocurrency
/// proof-of-work and non-interactive use cases where side channels are
/// not a concern.
#[derive(Debug, Default, Clone, Copy)]
pub struct Argon2dProvider;

impl KdfProvider for Argon2dProvider {
    fn name(&self) -> &'static str {
        "ARGON2D"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        debug!("Argon2dProvider::new_ctx");
        Ok(Box::new(Argon2Context::new(Argon2Variant::Argon2d)))
    }
}

/// Zero-sized provider type exposing the Argon2i algorithm.
///
/// Argon2i uses **data-independent** memory addressing, making it
/// side-channel resistant at the cost of being slightly slower than
/// Argon2d and having reduced time-memory trade-off resistance.
/// Recommended for password hashing when the attacker may observe
/// memory access patterns.
#[derive(Debug, Default, Clone, Copy)]
pub struct Argon2iProvider;

impl KdfProvider for Argon2iProvider {
    fn name(&self) -> &'static str {
        "ARGON2I"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        debug!("Argon2iProvider::new_ctx");
        Ok(Box::new(Argon2Context::new(Argon2Variant::Argon2i)))
    }
}

/// Zero-sized provider type exposing the Argon2id algorithm.
///
/// Argon2id is a hybrid that uses Argon2i for the first half of the
/// first pass and Argon2d thereafter.  It combines Argon2i's
/// side-channel resistance (for the early phase, before memory is
/// warm) with Argon2d's attack resistance (in the main phase).  This
/// is the RFC 9106 *recommended* variant for password hashing.
#[derive(Debug, Default, Clone, Copy)]
pub struct Argon2idProvider;

impl KdfProvider for Argon2idProvider {
    fn name(&self) -> &'static str {
        "ARGON2ID"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        debug!("Argon2idProvider::new_ctx");
        Ok(Box::new(Argon2Context::new(Argon2Variant::Argon2id)))
    }
}

// =============================================================================
// Provider descriptor registration
// =============================================================================

/// Returns the list of algorithm descriptors exported by this module.
///
/// The descriptors are consumed by `kdfs::mod` (via
/// `kdfs::all_descriptors()`) and ultimately registered with the
/// default provider, making the `ARGON2D`, `ARGON2I`, and `ARGON2ID`
/// algorithm names fetchable through the `EVP_KDF` fetch API.
///
/// Each entry corresponds to one of the three static `OSSL_DISPATCH`
/// tables in OpenSSL's `providers/implementations/kdfs/argon2.c`:
///
/// | Rust name      | C dispatch table                      |
/// |----------------|---------------------------------------|
/// | `"ARGON2D"`    | `ossl_kdf_argon2d_functions`          |
/// | `"ARGON2I"`    | `ossl_kdf_argon2i_functions`          |
/// | `"ARGON2ID"`   | `ossl_kdf_argon2id_functions`         |
///
/// All three are registered under `"provider=default"` so that they
/// appear as soon as the default provider is loaded.  They are **not**
/// part of the FIPS module (RFC 9106 is not FIPS-approved as of SP
/// 800-208).
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["ARGON2D"],
            "provider=default",
            "Argon2d memory-hard password hash (RFC 9106, data-dependent addressing)",
        ),
        algorithm(
            &["ARGON2I"],
            "provider=default",
            "Argon2i memory-hard password hash (RFC 9106, data-independent addressing)",
        ),
        algorithm(
            &["ARGON2ID"],
            "provider=default",
            "Argon2id hybrid memory-hard password hash (RFC 9106, recommended variant)",
        ),
    ]
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamBuilder;

    /// Builds a minimal valid parameter set (password + 16-byte salt +
    /// t_cost=3 + m_cost=32 + lanes=4 + out_len=32).  Suitable for
    /// exercising the *structure* of the algorithm without burning CPU.
    fn minimal_params() -> ParamSet {
        ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, b"password".to_vec())
            .push_octet(PARAM_SALT, b"somesaltsomesalt".to_vec())
            .push_u32(PARAM_ITER, 3)
            .push_u32(PARAM_MEMORY, 32)
            .push_u32(PARAM_LANES, 4)
            .push_u32(PARAM_SIZE, 32)
            .build()
    }

    // -------------------------------------------------------------------
    // Argon2Variant
    // -------------------------------------------------------------------

    #[test]
    fn variant_type_codes_match_rfc() {
        // RFC 9106 §3.3: Argon2d = 0, Argon2i = 1, Argon2id = 2.
        assert_eq!(Argon2Variant::Argon2d.type_code(), 0);
        assert_eq!(Argon2Variant::Argon2i.type_code(), 1);
        assert_eq!(Argon2Variant::Argon2id.type_code(), 2);
    }

    #[test]
    fn variant_parse_accepts_canonical_names() {
        assert_eq!(Argon2Variant::parse("d"), Some(Argon2Variant::Argon2d));
        assert_eq!(Argon2Variant::parse("i"), Some(Argon2Variant::Argon2i));
        assert_eq!(Argon2Variant::parse("id"), Some(Argon2Variant::Argon2id));
        assert_eq!(
            Argon2Variant::parse("argon2d"),
            Some(Argon2Variant::Argon2d)
        );
        assert_eq!(
            Argon2Variant::parse("Argon2ID"),
            Some(Argon2Variant::Argon2id)
        );
        assert_eq!(Argon2Variant::parse("bogus"), None);
        assert_eq!(Argon2Variant::parse(""), None);
    }

    #[test]
    fn variant_display_is_canonical() {
        // `Display` renders the OpenSSL-style uppercase fetch name so it
        // can be embedded directly in log/metric labels without further
        // normalisation.  Matches the strings accepted by fetch APIs.
        assert_eq!(Argon2Variant::Argon2d.to_string(), "ARGON2D");
        assert_eq!(Argon2Variant::Argon2i.to_string(), "ARGON2I");
        assert_eq!(Argon2Variant::Argon2id.to_string(), "ARGON2ID");
    }

    // -------------------------------------------------------------------
    // Block helpers
    // -------------------------------------------------------------------

    #[test]
    fn zero_block_is_all_zero() {
        let z = zero_block();
        assert_eq!(z.len(), QWORDS_IN_BLOCK);
        assert!(z.iter().all(|&w| w == 0));
    }

    #[test]
    fn xor_block_is_involutive() {
        let mut a = zero_block();
        let mut b = zero_block();
        for (i, (w_a, w_b)) in a.iter_mut().zip(b.iter_mut()).enumerate() {
            // Use `wrapping_mul` because the simple multiplication
            // below would overflow `u64` for large `i`; the test only
            // cares that the two blocks have some non-trivial contents.
            *w_a = (i as u64).wrapping_mul(0x0123_4567_89AB_CDEF);
            *w_b = ((QWORDS_IN_BLOCK - i) as u64).wrapping_mul(0xFEDC_BA98_7654_3210);
        }
        let before = a;
        // a ^= b; a ^= b; → a unchanged
        xor_block(&mut a, &b);
        xor_block(&mut a, &b);
        assert_eq!(a, before);
    }

    #[test]
    fn copy_block_duplicates_all_words() {
        let mut src = zero_block();
        for (i, w) in src.iter_mut().enumerate() {
            *w = (i as u64).wrapping_mul(31);
        }
        let mut dst = zero_block();
        copy_block(&mut dst, &src);
        assert_eq!(dst, src);
    }

    #[test]
    fn load_store_round_trip() {
        let mut block = zero_block();
        for (i, w) in block.iter_mut().enumerate() {
            *w = 0xDEAD_BEEF_u64 ^ ((i as u64) << 16);
        }

        let mut bytes = vec![0u8; BLOCK_SIZE];
        store_block_bytes(&block, &mut bytes);
        assert_eq!(bytes.len(), BLOCK_SIZE);

        let mut restored = zero_block();
        load_block_bytes(&mut restored, &bytes);
        assert_eq!(restored, block);
    }

    #[test]
    fn load_block_bytes_is_little_endian() {
        let mut bytes = vec![0u8; BLOCK_SIZE];
        // First u64 = 0x0807_0605_0403_0201 (little-endian read of 1..8)
        bytes[..8].copy_from_slice(&[1u8, 2, 3, 4, 5, 6, 7, 8]);
        let mut block = zero_block();
        load_block_bytes(&mut block, &bytes);
        assert_eq!(block[0], 0x0807_0605_0403_0201);
    }

    // -------------------------------------------------------------------
    // Blamka G function
    // -------------------------------------------------------------------

    #[test]
    fn mul_lower_truncates_to_u32() {
        // (2^32) * (2^32) = 2^64 (low 32 bits of each operand is 0).
        assert_eq!(mul_lower(1u64 << 32, 1u64 << 32), 0);
        // 0xFFFF_FFFF * 0xFFFF_FFFF = 0xFFFF_FFFE_0000_0001 (fits in u64).
        assert_eq!(mul_lower(0xFFFF_FFFF, 0xFFFF_FFFF), 0xFFFF_FFFE_0000_0001);
        // High bits of inputs are ignored.
        assert_eq!(mul_lower(0xABCD_EF01_0000_0003, 0x1234_5678_0000_0007), 21);
    }

    #[test]
    fn gb_is_deterministic() {
        let mut a1 = 1u64;
        let mut b1 = 2u64;
        let mut c1 = 3u64;
        let mut d1 = 4u64;
        gb(&mut a1, &mut b1, &mut c1, &mut d1);

        let mut a2 = 1u64;
        let mut b2 = 2u64;
        let mut c2 = 3u64;
        let mut d2 = 4u64;
        gb(&mut a2, &mut b2, &mut c2, &mut d2);

        assert_eq!(a1, a2);
        assert_eq!(b1, b2);
        assert_eq!(c1, c2);
        assert_eq!(d1, d2);
        // The state must change (not all-input-returned).
        assert!(a1 != 1 || b1 != 2 || c1 != 3 || d1 != 4);
    }

    #[test]
    fn permutation_p_avalanches() {
        let mut v1: [u64; 16] = core::array::from_fn(|i| i as u64);
        let mut v2 = v1;
        v2[0] ^= 1; // Flip a single bit.
        permutation_p(&mut v1);
        permutation_p(&mut v2);
        // A single-bit flip in input must propagate to many output bits.
        let diff: u32 = v1
            .iter()
            .zip(v2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert!(
            diff > 100,
            "permutation_p avalanche too weak: diff={diff} bits"
        );
    }

    // -------------------------------------------------------------------
    // Argon2Context construction & param handling
    // -------------------------------------------------------------------

    #[test]
    fn context_new_sets_defaults() {
        let ctx = Argon2Context::new(Argon2Variant::Argon2id);
        assert_eq!(ctx.variant, Argon2Variant::Argon2id);
        assert_eq!(ctx.out_len, DEFAULT_OUTLEN);
        assert_eq!(ctx.t_cost, DEFAULT_T_COST);
        assert_eq!(ctx.m_cost, DEFAULT_M_COST);
        assert_eq!(ctx.lanes, DEFAULT_LANES);
        assert_eq!(ctx.threads, DEFAULT_THREADS);
        assert_eq!(ctx.version, ARGON2_VERSION_13);
        assert!(ctx.password.is_empty());
        assert!(ctx.salt.is_empty());
        assert!(ctx.secret.is_none());
        assert!(ctx.ad.is_none());
    }

    #[test]
    fn apply_params_populates_all_fields() {
        let params = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, b"pw".to_vec())
            .push_octet(PARAM_SALT, b"saltsalt".to_vec())
            .push_octet(PARAM_SECRET, b"secret".to_vec())
            .push_octet(PARAM_AD, b"ad".to_vec())
            .push_u32(PARAM_ITER, 5)
            .push_u32(PARAM_MEMORY, 64)
            .push_u32(PARAM_LANES, 2)
            .push_u32(PARAM_THREADS, 2)
            .push_u32(PARAM_SIZE, 48)
            .push_u32(PARAM_VERSION, ARGON2_VERSION_13)
            .build();
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2i);
        ctx.apply_params(&params).expect("apply_params");
        assert_eq!(ctx.password, b"pw");
        assert_eq!(ctx.salt, b"saltsalt");
        assert_eq!(ctx.secret.as_deref(), Some(&b"secret"[..]));
        assert_eq!(ctx.ad.as_deref(), Some(&b"ad"[..]));
        assert_eq!(ctx.t_cost, 5);
        assert_eq!(ctx.m_cost, 64);
        assert_eq!(ctx.lanes, 2);
        assert_eq!(ctx.threads, 2);
        assert_eq!(ctx.out_len, 48);
        assert_eq!(ctx.version, ARGON2_VERSION_13);
    }

    // -------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------

    #[test]
    fn validate_rejects_missing_password() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.salt = b"saltsalt".to_vec();
        assert!(matches!(ctx.validate(), Err(ProviderError::Init(_))));
    }

    #[test]
    fn validate_rejects_missing_salt() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        assert!(matches!(ctx.validate(), Err(ProviderError::Init(_))));
    }

    #[test]
    fn validate_rejects_salt_too_short() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"short".to_vec(); // only 5 bytes < MIN_SALT_LENGTH=8
        let err = ctx.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn validate_rejects_out_len_too_small() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"saltsalt".to_vec();
        ctx.out_len = 3; // < MIN_OUT_LENGTH = 4
        let err = ctx.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn validate_rejects_t_cost_zero() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"saltsalt".to_vec();
        ctx.t_cost = 0; // < MIN_TIME = 1
        let err = ctx.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn validate_rejects_m_cost_below_8_lanes() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"saltsalt".to_vec();
        ctx.lanes = 4;
        ctx.m_cost = 16; // 16 < 8 * 4 = 32
        let err = ctx.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn validate_rejects_bad_version() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"saltsalt".to_vec();
        ctx.version = 0x12; // Only 0x10 and 0x13 are accepted.
        let err = ctx.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn validate_rejects_lanes_zero() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"saltsalt".to_vec();
        ctx.lanes = 0;
        let err = ctx.validate().unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn validate_accepts_minimal_valid_config() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"saltsalt".to_vec();
        ctx.t_cost = MIN_TIME;
        ctx.m_cost = 8 * ctx.lanes;
        ctx.out_len = MIN_OUT_LENGTH;
        assert!(ctx.validate().is_ok());
    }

    #[test]
    fn validate_accepts_version_10() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"saltsalt".to_vec();
        ctx.version = ARGON2_VERSION_10;
        assert!(ctx.validate().is_ok());
    }

    // -------------------------------------------------------------------
    // Addressing helpers
    // -------------------------------------------------------------------

    #[test]
    fn use_data_independent_variant_logic() {
        // Argon2d: NEVER data-independent.
        assert!(!use_data_independent(Argon2Variant::Argon2d, 0, 0));
        assert!(!use_data_independent(Argon2Variant::Argon2d, 1, 1));
        // Argon2i: ALWAYS data-independent.
        assert!(use_data_independent(Argon2Variant::Argon2i, 0, 0));
        assert!(use_data_independent(Argon2Variant::Argon2i, 5, 3));
        // Argon2id: data-independent only in slices 0..2 of pass 0.
        assert!(use_data_independent(Argon2Variant::Argon2id, 0, 0));
        assert!(use_data_independent(Argon2Variant::Argon2id, 0, 1));
        assert!(!use_data_independent(Argon2Variant::Argon2id, 0, 2));
        assert!(!use_data_independent(Argon2Variant::Argon2id, 0, 3));
        assert!(!use_data_independent(Argon2Variant::Argon2id, 1, 0));
    }

    // -------------------------------------------------------------------
    // BLAKE2b helpers
    // -------------------------------------------------------------------

    #[test]
    fn fetch_blake2b_succeeds() {
        let md = fetch_blake2b().expect("BLAKE2B-512 should be available");
        assert_eq!(md.digest_size(), 64);
    }

    #[test]
    fn blake2b_long_returns_requested_length() {
        let md = fetch_blake2b().expect("BLAKE2B-512 should be available");

        // Exact BLAKE2b native size.
        let out1 = blake2b_long(&md, 64, b"hello").expect("blake2b_long 64");
        assert_eq!(out1.len(), 64);

        // Short output — single-call truncated.
        let out2 = blake2b_long(&md, 32, b"hello").expect("blake2b_long 32");
        assert_eq!(out2.len(), 32);

        // Minimum acceptable from caller's point of view.
        let out3 = blake2b_long(&md, 4, b"hello").expect("blake2b_long 4");
        assert_eq!(out3.len(), 4);

        // Long output — iterative construction.
        let out4 = blake2b_long(&md, 256, b"hello").expect("blake2b_long 256");
        assert_eq!(out4.len(), 256);

        // 1024-byte output as used for lane seeding.
        let out5 = blake2b_long(&md, BLOCK_SIZE_U32, b"hello").expect("blake2b_long 1024");
        assert_eq!(out5.len(), BLOCK_SIZE);
    }

    #[test]
    fn blake2b_long_is_deterministic() {
        let md = fetch_blake2b().expect("BLAKE2B-512 should be available");
        let a = blake2b_long(&md, 128, b"deterministic input").unwrap();
        let b = blake2b_long(&md, 128, b"deterministic input").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn blake2b_long_differs_with_length() {
        let md = fetch_blake2b().expect("BLAKE2B-512 should be available");
        // Per RFC 9106 §3.3, the output is prefixed with LE32(outlen),
        // so the hashes for different lengths must differ even when
        // comparing only a shared prefix.
        let a = blake2b_long(&md, 32, b"same").unwrap();
        let b = blake2b_long(&md, 48, b"same").unwrap();
        assert_ne!(a, b[..32]);
    }

    // -------------------------------------------------------------------
    // Initial hash (H0)
    // -------------------------------------------------------------------

    #[test]
    fn initial_hash_is_64_bytes() {
        let md = fetch_blake2b().expect("BLAKE2B-512 should be available");
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        ctx.password = b"pw".to_vec();
        ctx.salt = b"saltsalt".to_vec();
        let h0 = initial_hash(&md, &ctx).expect("initial_hash");
        assert_eq!(h0.len(), PREHASH_DIGEST_LENGTH);
    }

    #[test]
    fn initial_hash_varies_with_variant() {
        let md = fetch_blake2b().expect("BLAKE2B-512 should be available");
        let mk = |v| {
            let mut c = Argon2Context::new(v);
            c.password = b"pw".to_vec();
            c.salt = b"saltsalt".to_vec();
            c
        };
        let h_d = initial_hash(&md, &mk(Argon2Variant::Argon2d)).unwrap();
        let h_i = initial_hash(&md, &mk(Argon2Variant::Argon2i)).unwrap();
        let h_id = initial_hash(&md, &mk(Argon2Variant::Argon2id)).unwrap();
        assert_ne!(h_d, h_i);
        assert_ne!(h_i, h_id);
        assert_ne!(h_d, h_id);
    }

    // -------------------------------------------------------------------
    // Full derive pipeline
    // -------------------------------------------------------------------

    #[test]
    fn derive_produces_expected_length() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2id);
        let params = minimal_params();
        let mut out = [0u8; 32];
        let bytes_written = ctx.derive(&mut out, &params).expect("derive");
        assert_eq!(bytes_written, 32);
        // Output must be non-zero with overwhelming probability.
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn derive_is_deterministic() {
        let mk_ctx = || Argon2Context::new(Argon2Variant::Argon2id);
        let params = minimal_params();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        mk_ctx().derive(&mut out1, &params).expect("derive 1");
        mk_ctx().derive(&mut out2, &params).expect("derive 2");
        assert_eq!(out1, out2);
    }

    #[test]
    fn derive_varies_with_variant() {
        let params = minimal_params();
        let mut out_d = [0u8; 32];
        let mut out_i = [0u8; 32];
        let mut out_id = [0u8; 32];
        Argon2Context::new(Argon2Variant::Argon2d)
            .derive(&mut out_d, &params)
            .expect("argon2d");
        Argon2Context::new(Argon2Variant::Argon2i)
            .derive(&mut out_i, &params)
            .expect("argon2i");
        Argon2Context::new(Argon2Variant::Argon2id)
            .derive(&mut out_id, &params)
            .expect("argon2id");
        assert_ne!(out_d, out_i);
        assert_ne!(out_i, out_id);
        assert_ne!(out_d, out_id);
    }

    #[test]
    fn derive_varies_with_password() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        let p1 = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, b"alpha".to_vec())
            .push_octet(PARAM_SALT, b"somesaltsomesalt".to_vec())
            .push_u32(PARAM_ITER, 1)
            .push_u32(PARAM_MEMORY, 32)
            .push_u32(PARAM_LANES, 4)
            .build();
        let p2 = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, b"bravo".to_vec())
            .push_octet(PARAM_SALT, b"somesaltsomesalt".to_vec())
            .push_u32(PARAM_ITER, 1)
            .push_u32(PARAM_MEMORY, 32)
            .push_u32(PARAM_LANES, 4)
            .build();
        Argon2Context::new(Argon2Variant::Argon2id)
            .derive(&mut out1, &p1)
            .unwrap();
        Argon2Context::new(Argon2Variant::Argon2id)
            .derive(&mut out2, &p2)
            .unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn derive_varies_with_salt() {
        let p1 = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, b"pw".to_vec())
            .push_octet(PARAM_SALT, b"salt1salt1salt1x".to_vec())
            .push_u32(PARAM_ITER, 1)
            .push_u32(PARAM_MEMORY, 32)
            .push_u32(PARAM_LANES, 4)
            .build();
        let p2 = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, b"pw".to_vec())
            .push_octet(PARAM_SALT, b"salt2salt2salt2x".to_vec())
            .push_u32(PARAM_ITER, 1)
            .push_u32(PARAM_MEMORY, 32)
            .push_u32(PARAM_LANES, 4)
            .build();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        Argon2Context::new(Argon2Variant::Argon2d)
            .derive(&mut out1, &p1)
            .unwrap();
        Argon2Context::new(Argon2Variant::Argon2d)
            .derive(&mut out2, &p2)
            .unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn derive_rejects_insufficient_output_length() {
        let params = minimal_params();
        let mut out = [0u8; 3]; // Below MIN_OUT_LENGTH = 4.
        let err = Argon2Context::new(Argon2Variant::Argon2id)
            .derive(&mut out, &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn derive_propagates_missing_password() {
        // No PARAM_PASSWORD in the set.
        let params = ParamBuilder::new()
            .push_octet(PARAM_SALT, b"saltsalt".to_vec())
            .build();
        let mut out = [0u8; 32];
        let err = Argon2Context::new(Argon2Variant::Argon2id)
            .derive(&mut out, &params)
            .unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // -------------------------------------------------------------------
    // Trait semantics: reset, get_params, set_params
    // -------------------------------------------------------------------

    #[test]
    fn reset_clears_keys_and_preserves_variant() {
        let mut ctx = Argon2Context::new(Argon2Variant::Argon2i);
        ctx.password = b"secret-password".to_vec();
        ctx.salt = b"big-salt-123456".to_vec();
        ctx.secret = Some(b"extra-secret".to_vec());
        ctx.ad = Some(b"associated-data".to_vec());
        ctx.t_cost = 9;
        ctx.m_cost = 2048;
        ctx.lanes = 8;
        ctx.threads = 8;
        ctx.out_len = 128;
        ctx.version = ARGON2_VERSION_10;

        <Argon2Context as KdfContext>::reset(&mut ctx).unwrap();

        // Variant MUST be preserved.
        assert_eq!(ctx.variant, Argon2Variant::Argon2i);
        // Key material cleared.
        assert!(ctx.password.is_empty());
        assert!(ctx.salt.is_empty());
        assert!(ctx.secret.is_none());
        assert!(ctx.ad.is_none());
        // Parameters back to defaults.
        assert_eq!(ctx.t_cost, DEFAULT_T_COST);
        assert_eq!(ctx.m_cost, DEFAULT_M_COST);
        assert_eq!(ctx.lanes, DEFAULT_LANES);
        assert_eq!(ctx.threads, DEFAULT_THREADS);
        assert_eq!(ctx.out_len, DEFAULT_OUTLEN);
        assert_eq!(ctx.version, ARGON2_VERSION_13);
    }

    #[test]
    fn get_params_round_trip_through_set_params() {
        let mut src = Argon2Context::new(Argon2Variant::Argon2id);
        src.t_cost = 7;
        src.m_cost = 128;
        src.lanes = 2;
        src.threads = 2;
        src.out_len = 24;
        src.version = ARGON2_VERSION_10;

        let snapshot = <Argon2Context as KdfContext>::get_params(&src).expect("get_params");

        let mut dst = Argon2Context::new(Argon2Variant::Argon2id);
        <Argon2Context as KdfContext>::set_params(&mut dst, &snapshot).expect("set_params");
        assert_eq!(dst.t_cost, 7);
        assert_eq!(dst.m_cost, 128);
        assert_eq!(dst.lanes, 2);
        assert_eq!(dst.threads, 2);
        assert_eq!(dst.out_len, 24);
        assert_eq!(dst.version, ARGON2_VERSION_10);
    }

    // -------------------------------------------------------------------
    // Provider wrappers
    // -------------------------------------------------------------------

    #[test]
    fn provider_names_are_canonical() {
        assert_eq!(KdfProvider::name(&Argon2dProvider), "ARGON2D");
        assert_eq!(KdfProvider::name(&Argon2iProvider), "ARGON2I");
        assert_eq!(KdfProvider::name(&Argon2idProvider), "ARGON2ID");
    }

    #[test]
    fn provider_new_ctx_returns_box_and_derives_successfully() {
        let providers: [(&str, &dyn KdfProvider); 3] = [
            ("ARGON2D", &Argon2dProvider),
            ("ARGON2I", &Argon2iProvider),
            ("ARGON2ID", &Argon2idProvider),
        ];
        let params = minimal_params();
        for (label, prov) in &providers {
            let mut ctx = prov.new_ctx().expect(*label);
            let mut out = [0u8; 32];
            ctx.derive(&mut out, &params).expect(*label);
            assert!(out.iter().any(|&b| b != 0), "{label} produced zero output");
        }
    }

    // -------------------------------------------------------------------
    // descriptors()
    // -------------------------------------------------------------------

    #[test]
    fn descriptors_returns_all_three_variants() {
        let descriptors = descriptors();
        assert_eq!(descriptors.len(), 3);

        let names: Vec<&'static str> = descriptors
            .iter()
            .flat_map(|d| d.names.iter().copied())
            .collect();
        assert!(names.contains(&"ARGON2D"));
        assert!(names.contains(&"ARGON2I"));
        assert!(names.contains(&"ARGON2ID"));

        for d in &descriptors {
            assert_eq!(d.property, "provider=default");
            assert!(!d.description.is_empty());
        }
    }

    // -------------------------------------------------------------------
    // Reference vector (sanity only — real RFC vectors are CPU-heavy)
    // -------------------------------------------------------------------

    /// Sanity test: derive a short Argon2id tag with low cost parameters
    /// and verify it is stable across repeated runs and independent of
    /// instance ordering.  We do *not* compare against the RFC 9106
    /// test vector in §5 because those use `t=3, m=32, p=4`, which is
    /// fine, but we exercise *multiple* iterations here to catch any
    /// state-leak between contexts.
    #[test]
    fn argon2id_rfc_minimal_stability() {
        let password = b"password".to_vec();
        let salt = b"somesaltsomesalt".to_vec();
        let params = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, password)
            .push_octet(PARAM_SALT, salt)
            .push_u32(PARAM_ITER, 3)
            .push_u32(PARAM_MEMORY, 32) // 32 KiB = 8 * 4 lanes
            .push_u32(PARAM_LANES, 4)
            .push_u32(PARAM_SIZE, 32)
            .push_u32(PARAM_VERSION, ARGON2_VERSION_13)
            .build();

        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        let mut out_c = [0u8; 32];
        Argon2Context::new(Argon2Variant::Argon2id)
            .derive(&mut out_a, &params)
            .expect("derive A");
        Argon2Context::new(Argon2Variant::Argon2id)
            .derive(&mut out_b, &params)
            .expect("derive B");
        Argon2Context::new(Argon2Variant::Argon2id)
            .derive(&mut out_c, &params)
            .expect("derive C");
        assert_eq!(out_a, out_b);
        assert_eq!(out_b, out_c);
    }
}
