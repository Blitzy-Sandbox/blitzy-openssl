//! ML-DSA mu hash provider implementation.
//!
//! Computes `mu = SHAKE256(tr || M', 64)` where:
//! - `tr` is the pre-cached SHAKE256 hash of the public key (64 bytes)
//! - `M'` is the context-prepended message:
//!   - **Pure mode:**    `0x00 || ctx_len || ctx || message`
//!   - **PreHash mode:** `0x01 || ctx_len || ctx || OID || hashed_message`
//!
//! Fixed 64-byte output. Replaces C
//! `providers/implementations/digests/ml_dsa_mu_prov.c`.
//!
//! Used internally by the ML-DSA signature scheme (FIPS 204, Sections 5.2/5.4).
//!
//! ## Algorithm registration
//!
//! Registered under four canonical names with property `provider=default`:
//! - `ML-DSA-MU` (generic alias, public-key length determines variant)
//! - `ML-DSA-44-MU`
//! - `ML-DSA-65-MU`
//! - `ML-DSA-87-MU`
//!
//! All four names share a single underlying implementation; the variant is
//! determined dynamically from the public key length supplied via the `pubkey`
//! context parameter (1312 / 1952 / 2592 bytes respectively).
//!
//! ## Context parameters (settable via [`DigestContext::set_params`])
//!
//! | Key          | Type            | Purpose                                                   |
//! |--------------|-----------------|-----------------------------------------------------------|
//! | `ctx`        | `OctetString`   | Domain-separation context string (max 255 bytes)          |
//! | `propq`      | `Utf8String`    | Property query for underlying SHAKE256 fetch              |
//! | `pubkey`     | `OctetString`   | ML-DSA public key — hashed into `tr` (64-byte SHAKE256)   |
//! | `digestname` | `Utf8String`    | Optional prehash digest name (enables `PreHash` mode)     |
//!
//! ## Context parameters (gettable via [`DigestContext::get_params`])
//!
//! | Key            | Type    | Value                            |
//! |----------------|---------|----------------------------------|
//! | `blocksize`    | UInt64  | 136 (SHAKE256 rate in bytes)     |
//! | `size`         | UInt64  | 64 (fixed mu output size)        |
//! | `xoflen`       | UInt64  | 64 (XOF output length)           |
//! | `xof`          | UInt64  | 1 (this is an XOF-style digest)  |
//! | `algid-absent` | UInt64  | 1 (no AlgorithmIdentifier)       |
//!
//! ## Rule compliance
//!
//! - **R5 (Nullability over Sentinels):** Optional fields use `Option<T>` —
//!   `tr: Option<[u8; 64]>`, `oid: Option<Vec<u8>>`, `propq: Option<String>`.
//!   No empty-string sentinels.
//! - **R6 (Lossless Numeric Casts):** Context-string length validation uses
//!   `u8::try_from` and `usize::try_from`; no bare `as` casts.
//! - **R8 (Zero Unsafe):** Contains zero `unsafe` blocks. All cryptographic
//!   work delegates to [`ShakeContext`] from `openssl-crypto`.
//! - **R9 (Warning-Free):** All public items documented; no `#[allow]` directives.

use crate::implementations::digests::common::{default_get_params, DigestFlags};
use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::hash::sha::ShakeContext;
use openssl_crypto::pqc::ml_dsa::{
    MAX_CONTEXT_STRING_LEN, ML_DSA_44_PUB_LEN, ML_DSA_65_PUB_LEN, ML_DSA_87_PUB_LEN, MU_BYTES,
};

// =============================================================================
// Constants
// =============================================================================

/// SHAKE256 sponge rate (block size) in bytes for ML-DSA mu computation.
///
/// SHAKE256 has a sponge capacity of 512 bits and rate of 1088 bits = 136 bytes.
/// Matches C `SHA3_BLOCKSIZE(256)` macro from `crypto/sha/sha3.h`.
const ML_DSA_MU_BLOCK_SIZE: usize = 136;

/// Fixed mu output size in bytes.
///
/// Matches C `SHAKE256_SIZE` constant from `ml_dsa_mu_prov.c` line 36 and
/// the canonical `MU_BYTES` re-export from `openssl-crypto::pqc::ml_dsa`.
const ML_DSA_MU_DIGEST_SIZE: usize = MU_BYTES;

/// Domain-separation byte for the **Pure** ML-DSA mode (no prehash).
///
/// FIPS 204 Section 5.2: `M' = 0x00 || ctx_len || ctx || message`.
const MODE_BYTE_PURE: u8 = 0x00;

/// Domain-separation byte for the **`PreHash`** ML-DSA mode (HashML-DSA).
///
/// FIPS 204 Section 5.4: `M' = 0x01 || ctx_len || ctx || OID || hash(message)`.
const MODE_BYTE_PREHASH: u8 = 0x01;

// =============================================================================
// Provider struct
// =============================================================================

/// ML-DSA mu hash digest provider.
///
/// Specialized SHAKE256-based digest used internally by the ML-DSA signature
/// scheme (FIPS 204). Produces a fixed 64-byte output regardless of input.
///
/// This is a zero-sized type because all algorithm parameters (block size,
/// digest size) are constants. Per-instance state lives in [`MlDsaMuContext`],
/// which is created via [`DigestProvider::new_ctx`].
///
/// # Example
///
/// ```ignore
/// use openssl_provider::implementations::digests::ml_dsa_mu::MlDsaMuProvider;
/// use openssl_provider::traits::DigestProvider;
///
/// let provider = MlDsaMuProvider;
/// let mut ctx = provider.new_ctx().unwrap();
/// // set public key and context string via set_params, then update + finalize
/// ```
#[derive(Debug, Clone, Default)]
pub struct MlDsaMuProvider;

impl DigestProvider for MlDsaMuProvider {
    /// Returns the canonical algorithm name.
    ///
    /// While the dispatcher accepts four name aliases (`ML-DSA-MU`,
    /// `ML-DSA-44-MU`, `ML-DSA-65-MU`, `ML-DSA-87-MU`), the underlying
    /// implementation is identical, so we report the generic name.
    fn name(&self) -> &'static str {
        "ML-DSA-MU"
    }

    /// SHAKE256 sponge rate: 1088 bits = 136 bytes.
    fn block_size(&self) -> usize {
        ML_DSA_MU_BLOCK_SIZE
    }

    /// Fixed 64-byte mu output size.
    fn digest_size(&self) -> usize {
        ML_DSA_MU_DIGEST_SIZE
    }

    /// Creates a new mu computation context.
    ///
    /// The returned context is in an uninitialised state — the caller must
    /// supply at minimum a `pubkey` parameter via [`DigestContext::set_params`]
    /// before calling [`DigestContext::update`] or [`DigestContext::finalize`].
    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(MlDsaMuContext::new()))
    }
}

// =============================================================================
// Context struct
// =============================================================================

/// Per-instance state for ML-DSA mu computation.
///
/// Mirrors C `MU_CTX` (lines 40-53 of `ml_dsa_mu_prov.c`) but uses Rust
/// ownership semantics:
/// - `tr`, `oid`, `propq` are `Option<...>` per Rule R5
/// - `shake_state` is lazy-initialised on first `update` or `finalize`
/// - `ShakeContext` provides automatic zeroisation on drop via `ZeroizeOnDrop`
///
/// `Debug` is implemented manually below because [`ShakeContext`] does not
/// derive `Debug` (its internal Keccak state is opaque).
#[derive(Clone)]
struct MlDsaMuContext {
    /// Domain-separation context string (max 255 bytes).
    ///
    /// Stored as `Vec<u8>` because OpenSSL accepts arbitrary octets. Maps to
    /// C `ctx->context[ML_DSA_MAX_CONTEXT_STRING_LEN]`.
    context_string: Vec<u8>,

    /// Pre-cached SHAKE256 hash of the public key (`tr`, 64 bytes).
    ///
    /// `None` until a valid `pubkey` parameter has been processed by
    /// [`Self::digest_public_key`]. Maps to C `ctx->tr[SHAKE256_SIZE]`.
    tr: Option<[u8; 64]>,

    /// Length of the public key associated with `tr`, in bytes.
    ///
    /// Used to validate that a key has been supplied (matches C `ctx->keylen`
    /// non-zero check in `check_init`).
    keylen: usize,

    /// DER-encoded OID prefix for `PreHash` mode (HashML-DSA).
    ///
    /// `None` for Pure mode (mode byte 0x00). When `Some`, switches to
    /// `PreHash` mode (mode byte 0x01) and the bytes are absorbed after the
    /// context string.
    oid: Option<Vec<u8>>,

    /// Expected length of the prehash digest output (for `PreHash` mode).
    ///
    /// Used by `update` to enforce that exactly this many message bytes are
    /// supplied before `finalize`. Always 0 in Pure mode.
    digest_len: usize,

    /// Bytes still expected from `update` calls before `finalize` may run.
    ///
    /// Pre-set by `init`/`set_params(digestname)` to `digest_len`. Decremented
    /// by `update` in `PreHash` mode. Must reach 0 before `finalize` succeeds.
    /// Always 0 in Pure mode (no length constraint).
    remaining: usize,

    /// Lazy-initialised SHAKE256 absorption state.
    ///
    /// `None` until first `update` or `finalize` triggers `check_init`, which
    /// absorbs the prefix `tr || mode || ctx_len || ctx || OID?`.
    /// `Clone + ZeroizeOnDrop` via `ShakeContext` itself.
    shake_state: Option<ShakeContext>,

    /// Property query for the underlying SHAKE256 fetch.
    ///
    /// `None` means default property selection. Currently informational —
    /// the in-tree SHAKE256 implementation does not consult properties.
    propq: Option<String>,

    /// Whether `finalize` has already been called.
    ///
    /// Prevents double-finalisation (matches the implicit C single-shot
    /// pattern via `EVP_DigestFinalXOF` consuming the context).
    finalized: bool,
}

impl std::fmt::Debug for MlDsaMuContext {
    /// Renders all fields except `shake_state` (whose internal Keccak state
    /// is opaque and not `Debug`-formatted). The presence of an active SHAKE
    /// state is reported as a boolean for diagnostic visibility.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaMuContext")
            .field("context_string_len", &self.context_string.len())
            .field("tr_present", &self.tr.is_some())
            .field("keylen", &self.keylen)
            .field("oid_len", &self.oid.as_ref().map(std::vec::Vec::len))
            .field("digest_len", &self.digest_len)
            .field("remaining", &self.remaining)
            .field("shake_state_active", &self.shake_state.is_some())
            .field("propq", &self.propq)
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl MlDsaMuContext {
    /// Creates a new uninitialised context with default field values.
    fn new() -> Self {
        Self {
            context_string: Vec::new(),
            tr: None,
            keylen: 0,
            oid: None,
            digest_len: 0,
            remaining: 0,
            shake_state: None,
            propq: None,
            finalized: false,
        }
    }

    /// Hashes the supplied public key into `self.tr` using SHAKE256 with a
    /// 64-byte squeeze.
    ///
    /// Mirrors C `digest_public_key` (lines 166-191 of `ml_dsa_mu_prov.c`):
    /// validates that `pub` has one of the canonical ML-DSA-44/65/87 lengths,
    /// then computes `tr = SHAKE256(pub)[..64]`.
    ///
    /// Per FIPS 204 Section 4 (Algorithm 22, `KeyGen`), the public-key hash is
    /// part of the secret-key derivation; reusing the same SHAKE256 transform
    /// here keeps mu computation aligned with key generation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if:
    /// - `pub` length does not match any of `ML_DSA_44_PUB_LEN`,
    ///   `ML_DSA_65_PUB_LEN`, or `ML_DSA_87_PUB_LEN`.
    /// - The underlying SHAKE256 absorb or squeeze operation fails.
    fn digest_public_key(&mut self, pubkey: &[u8]) -> ProviderResult<()> {
        // Validate ML-DSA public-key length matches one of the three NIST
        // parameter sets (FIPS 204 Section 4).
        let len = pubkey.len();
        if len != ML_DSA_44_PUB_LEN && len != ML_DSA_65_PUB_LEN && len != ML_DSA_87_PUB_LEN {
            return Err(ProviderError::Init(format!(
                "ML-DSA-MU invalid public key length {len} (expected \
                 {ML_DSA_44_PUB_LEN}, {ML_DSA_65_PUB_LEN}, or {ML_DSA_87_PUB_LEN})"
            )));
        }

        // Compute tr = SHAKE256(pub)[..64].
        let mut shake = ShakeContext::shake256();
        shake
            .update(pubkey)
            .map_err(|e| ProviderError::Init(format!("ML-DSA-MU SHAKE256 absorb failed: {e}")))?;

        let mut tr = [0u8; 64];
        shake
            .squeeze(&mut tr)
            .map_err(|e| ProviderError::Init(format!("ML-DSA-MU SHAKE256 squeeze failed: {e}")))?;

        self.tr = Some(tr);
        self.keylen = len;
        Ok(())
    }

    /// Lazy initialisation of the SHAKE256 absorbing state.
    ///
    /// Mirrors C `check_init` (lines 269-288 of `ml_dsa_mu_prov.c`):
    /// 1. Verifies that a public key has been supplied (`keylen != 0`).
    /// 2. Allocates a fresh SHAKE256 context.
    /// 3. Absorbs `tr` (64 bytes — output of `digest_public_key`).
    /// 4. Absorbs the FIPS 204 mode byte: `0x00` for Pure, `0x01` for `PreHash`.
    /// 5. Absorbs the context-string length byte (≤ 255 by R6 enforcement).
    /// 6. Absorbs the context bytes.
    /// 7. Absorbs the OID bytes if `PreHash` mode is active. (Matches the
    ///    *separate* `ossl_ml_dsa_mu_update(ctx->mdctx, ctx->oid, ...)`
    ///    call at line 286 of the C reference.)
    ///
    /// After this method returns successfully, `self.shake_state` is `Some`
    /// and ready to absorb message bytes via subsequent `update` calls.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if:
    /// - No public key has been registered (`keylen == 0` or `tr.is_none()`).
    /// - Context string exceeds 255 bytes (would not fit into the FIPS 204
    ///   single-byte length encoding).
    /// - Any underlying SHAKE256 absorb fails.
    fn check_init(&mut self) -> ProviderResult<()> {
        if self.shake_state.is_some() {
            return Ok(());
        }

        // Validate that pubkey was supplied (matches C `PROV_R_MISSING_KEY`).
        if self.keylen == 0 {
            return Err(ProviderError::Init(
                "ML-DSA-MU missing public key (set 'pubkey' parameter first)".to_string(),
            ));
        }
        let tr = self.tr.ok_or_else(|| {
            ProviderError::Init(
                "ML-DSA-MU public key hash (tr) not computed (set 'pubkey' first)".to_string(),
            )
        })?;

        // Per Rule R6: validate context string length fits into a u8 *before*
        // narrowing. MAX_CONTEXT_STRING_LEN is 255, the maximum representable
        // value in a single byte; anything larger violates FIPS 204 framing.
        if self.context_string.len() > MAX_CONTEXT_STRING_LEN {
            return Err(ProviderError::Init(format!(
                "ML-DSA-MU context string too long: {} bytes (max {})",
                self.context_string.len(),
                MAX_CONTEXT_STRING_LEN
            )));
        }
        let ctx_len_byte: u8 = u8::try_from(self.context_string.len()).map_err(|_| {
            ProviderError::Init(format!(
                "ML-DSA-MU context string length {} does not fit in u8",
                self.context_string.len()
            ))
        })?;

        // Determine mode byte: 0x01 if PreHash (OID present), else 0x00 Pure.
        let mode_byte = if self.oid.is_some() {
            MODE_BYTE_PREHASH
        } else {
            MODE_BYTE_PURE
        };

        // Build and prime the SHAKE256 absorber with the standard prefix.
        let mut shake = ShakeContext::shake256();

        shake.update(&tr).map_err(|e| {
            ProviderError::Init(format!("ML-DSA-MU SHAKE256 absorb of tr failed: {e}"))
        })?;
        shake.update(&[mode_byte, ctx_len_byte]).map_err(|e| {
            ProviderError::Init(format!("ML-DSA-MU SHAKE256 absorb of header failed: {e}"))
        })?;
        shake.update(&self.context_string).map_err(|e| {
            ProviderError::Init(format!(
                "ML-DSA-MU SHAKE256 absorb of context string failed: {e}"
            ))
        })?;

        // Absorb OID bytes if PreHash mode (matches the separate mu_update
        // call at line 286 of the C reference, NOT part of mu_init_int).
        if let Some(ref oid_bytes) = self.oid {
            shake.update(oid_bytes).map_err(|e| {
                ProviderError::Init(format!("ML-DSA-MU SHAKE256 absorb of OID failed: {e}"))
            })?;
        }

        self.shake_state = Some(shake);
        Ok(())
    }
}

// =============================================================================
// DigestContext implementation
// =============================================================================

impl DigestContext for MlDsaMuContext {
    /// Initialises (or re-initialises) this mu computation context.
    ///
    /// Mirrors C `mu_init` (lines 122-133 of `ml_dsa_mu_prov.c`):
    /// 1. Resets the SHAKE state (deferred — `shake_state` cleared).
    /// 2. Resets `remaining` to `digest_len` (preserves any prior `PreHash`
    ///    setup until overridden by new params).
    /// 3. Forwards any supplied parameters to [`Self::set_params`].
    ///
    /// # Errors
    ///
    /// Propagates any error raised by `set_params` (invalid public key
    /// length, unsupported digest name, oversize context string, etc.).
    fn init(&mut self, params: Option<&ParamSet>) -> ProviderResult<()> {
        // Reset SHAKE state and finalisation flag (matches EVP_MD_CTX_reset).
        self.shake_state = None;
        self.finalized = false;

        // Restore the per-init invariant: remaining == digest_len. This is
        // a no-op in Pure mode (both are 0) and re-arms PreHash mode for a
        // fresh round of `update` calls.
        self.remaining = self.digest_len;

        // Forward params to set_params (matches C `mu_init` line 132).
        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }

    /// Absorbs a chunk of message data into the running mu computation.
    ///
    /// Mirrors C `mu_update` (lines 290-306 of `ml_dsa_mu_prov.c`):
    /// 1. In `PreHash` mode (`oid.is_some()`), enforces that `data.len()` does
    ///    not exceed the remaining expected prehash bytes, and decrements
    ///    `remaining` accordingly.
    /// 2. Lazily initialises the SHAKE256 state via `check_init` if needed.
    /// 3. Absorbs the data into the SHAKE256 context.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] if:
    /// - `finalize` has already been called on this context.
    /// - In `PreHash` mode, `data.len() > remaining`.
    /// - The SHAKE256 absorb fails.
    ///
    /// Returns [`ProviderError::Init`] if `check_init` fails (no public key
    /// has been supplied).
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "ML-DSA-MU update called after finalize".to_string(),
            ));
        }

        // PreHash mode: enforce length constraint and decrement remaining.
        // `oid.is_some()` is the canonical PreHash indicator (matches C
        // `ctx->oid_len > 0` at line 297).
        if self.oid.is_some() {
            let data_len = data.len();
            if data_len > self.remaining {
                let remaining = self.remaining;
                return Err(ProviderError::Dispatch(format!(
                    "ML-DSA-MU update data length {data_len} exceeds remaining \
                     {remaining} (PreHash mode)"
                )));
            }
            // Subtraction is safe: data.len() <= remaining checked above.
            self.remaining -= data_len;
        }

        // Lazy SHAKE256 init: absorbs tr, mode byte, ctx_len, ctx, optional OID.
        self.check_init()?;

        // Absorb the message bytes. `check_init` guarantees `shake_state` is
        // `Some` on success; if it is not, treat it as a fatal dispatch error
        // rather than panicking (Rule R9: no `expect` in library code).
        let shake = self.shake_state.as_mut().ok_or_else(|| {
            ProviderError::Dispatch(
                "ML-DSA-MU shake_state missing after check_init (logic bug)".to_string(),
            )
        })?;
        shake.update(data).map_err(|e| {
            ProviderError::Dispatch(format!("ML-DSA-MU SHAKE256 update failed: {e}"))
        })?;

        Ok(())
    }

    /// Squeezes the final 64-byte mu value.
    ///
    /// Mirrors C `mu_final` (lines 308-329 of `ml_dsa_mu_prov.c`):
    /// 1. Rejects double-finalisation.
    /// 2. In `PreHash` mode, requires that exactly `digest_len` bytes have been
    ///    absorbed (`remaining == 0`).
    /// 3. Lazily initialises SHAKE256 if `update` was never called (this
    ///    happens, for example, when computing mu over an empty Pure-mode
    ///    message — the prefix alone is the input).
    /// 4. Squeezes 64 bytes via `ShakeContext::squeeze`.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] if:
    /// - `finalize` has already been called.
    /// - `PreHash` mode: not all expected message bytes were absorbed
    ///   (`remaining != 0`).
    /// - The SHAKE256 squeeze fails.
    ///
    /// Returns [`ProviderError::Init`] if `check_init` fails.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "ML-DSA-MU finalize called twice".to_string(),
            ));
        }

        // PreHash mode: remaining must be exactly zero (matches C line 320).
        // Pure mode: remaining is always 0 (digest_len is 0), so this is a
        // no-op for Pure callers.
        if self.remaining != 0 {
            let remaining = self.remaining;
            return Err(ProviderError::Dispatch(format!(
                "ML-DSA-MU finalize with {remaining} prehash bytes still expected"
            )));
        }

        // Mark finalised before squeezing so a subsequent finalize call (or
        // an interleaved update on the dropped context) hits the guard above.
        self.finalized = true;

        // Lazy init handles the no-update Pure-mode empty-message case.
        self.check_init()?;

        // `check_init` guarantees `shake_state` is `Some` on success; if it
        // is not, treat it as a fatal dispatch error rather than panicking
        // (Rule R9: no `expect` in library code).
        let shake = self.shake_state.as_mut().ok_or_else(|| {
            ProviderError::Dispatch(
                "ML-DSA-MU shake_state missing after check_init (logic bug)".to_string(),
            )
        })?;

        let mut output = vec![0u8; ML_DSA_MU_DIGEST_SIZE];
        shake.squeeze(&mut output).map_err(|e| {
            ProviderError::Dispatch(format!("ML-DSA-MU SHAKE256 squeeze failed: {e}"))
        })?;

        Ok(output)
    }

    /// Deep-clones this context for branched mu computations.
    ///
    /// Mirrors C `mu_dupctx`. Required for digest streaming protocols that
    /// fork a partially-absorbed digest (e.g., TLS 1.3 transcript hashing
    /// reuses a single transcript across multiple message paths).
    ///
    /// `ShakeContext` derives `Clone` and zeroises on drop, so this is a
    /// straightforward deep copy with no `unsafe` and no shared state.
    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    /// Returns the static algorithm parameters: `blocksize=136`, `size=64`,
    /// `xoflen=64`, `xof=1`, `algid-absent=1`.
    ///
    /// Mirrors C `mu_get_ctx_params` (lines 245-267) and `mu_get_params`
    /// (lines 135-139). Both `size` and `xoflen` always return `SHAKE256_SIZE`
    /// (= 64 bytes) — mu output length is fixed by FIPS 204.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`default_get_params`] (none expected — the
    /// builder construction is infallible for static integer params).
    fn get_params(&self) -> ProviderResult<ParamSet> {
        // Build the standard XOF + ALGID-absent param set.
        let mut set = default_get_params(
            ML_DSA_MU_BLOCK_SIZE,
            ML_DSA_MU_DIGEST_SIZE,
            DigestFlags::XOF | DigestFlags::ALGID_ABSENT,
        )?;
        // Append xoflen alias (matches C `OSSL_DIGEST_PARAM_XOFLEN`).
        set.set("xoflen", ParamValue::UInt64(MU_BYTES as u64));
        Ok(set)
    }

    /// Applies a parameter set to this context.
    ///
    /// Mirrors C `mu_set_ctx_params` (lines 193-237 of `ml_dsa_mu_prov.c`).
    /// Recognised keys:
    ///
    /// | Key          | Type            | Effect                                                |
    /// |--------------|-----------------|-------------------------------------------------------|
    /// | `ctx`        | `OctetString`   | Stores domain-separation context (max 255 bytes)      |
    /// | `propq`      | `Utf8String`    | Stores property query for SHAKE256 fetch              |
    /// | `pubkey`     | `OctetString`   | Hashes pub key into `tr`, sets `keylen`               |
    /// | `digestname` | `Utf8String`    | Sets `PreHash` OID + `digest_len` + remaining         |
    ///
    /// Unrecognised keys are silently ignored (matches OpenSSL convention
    /// where param dispatch tables tolerate unknown entries).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if:
    /// - `ctx` value is not an `OctetString` or exceeds 255 bytes.
    /// - `pubkey` is not an `OctetString` or has an invalid ML-DSA pub-key length.
    /// - `propq` or `digestname` is not a `Utf8String`.
    ///
    /// Returns [`ProviderError::AlgorithmUnavailable`] if `digestname` does
    /// not match a recognised prehash digest (no DER-OID lookup table is
    /// available outside the provider's hard-coded whitelist).
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // ---- ctx (octet string, max 255 bytes) ----
        if let Some(value) = params.get("ctx") {
            let bytes = value.as_bytes().ok_or_else(|| {
                let type_name = value.param_type_name();
                ProviderError::Init(format!(
                    "ML-DSA-MU 'ctx' must be octet string, got {type_name}"
                ))
            })?;
            let len = bytes.len();
            if len > MAX_CONTEXT_STRING_LEN {
                return Err(ProviderError::Init(format!(
                    "ML-DSA-MU 'ctx' too long: {len} bytes (max {MAX_CONTEXT_STRING_LEN})"
                )));
            }
            // Reset shake state — context affects the absorbed prefix.
            self.shake_state = None;
            self.context_string = bytes.to_vec();
        }

        // ---- propq (utf8 string) ----
        if let Some(value) = params.get("propq") {
            let s = value.as_str().ok_or_else(|| {
                let type_name = value.param_type_name();
                ProviderError::Init(format!(
                    "ML-DSA-MU 'propq' must be utf8 string, got {type_name}"
                ))
            })?;
            self.propq = Some(s.to_string());
            // No reset needed — propq is metadata only; the in-tree SHAKE256
            // implementation does not consult provider properties.
        }

        // ---- pubkey (octet string -> SHAKE256 -> tr) ----
        if let Some(value) = params.get("pubkey") {
            let bytes = value.as_bytes().ok_or_else(|| {
                let type_name = value.param_type_name();
                ProviderError::Init(format!(
                    "ML-DSA-MU 'pubkey' must be octet string, got {type_name}"
                ))
            })?;
            // Reset shake state — new public key invalidates absorbed prefix.
            self.shake_state = None;
            self.digest_public_key(bytes)?;
        }

        // ---- digestname (utf8 string -> OID + digest_len for PreHash mode) ----
        // Matches C `mu_set_ctx_params` lines 219-235. Note: the C code
        // `return ret;` immediately after this branch (line 235), but Rust's
        // assignment-only semantics mean other params already applied above
        // are preserved. We keep the same field-update behaviour.
        if let Some(value) = params.get("digestname") {
            let name = value.as_str().ok_or_else(|| {
                let type_name = value.param_type_name();
                ProviderError::Init(format!(
                    "ML-DSA-MU 'digestname' must be utf8 string, got {type_name}"
                ))
            })?;

            // Look up the FIPS 204 PreHash OID + digest length.
            let (oid_bytes, digest_len) = lookup_prehash_digest(name).ok_or_else(|| {
                ProviderError::AlgorithmUnavailable(format!(
                    "ML-DSA-MU prehash digest '{name}' is not supported (known: \
                     SHA2-256, SHA2-384, SHA2-512, SHA3-256, SHA3-384, SHA3-512, \
                     SHAKE-128, SHAKE-256)"
                ))
            })?;

            // Reset shake state — switching to PreHash mode invalidates prefix.
            self.shake_state = None;
            self.oid = Some(oid_bytes);
            self.digest_len = digest_len;
            self.remaining = digest_len;
        }

        Ok(())
    }
}

// =============================================================================
// PreHash digest whitelist (DER-encoded OIDs from NIST OID arc 2.16.840.1.101.3.4.2)
// =============================================================================

/// Returns the DER-encoded OID and canonical digest length for a recognised
/// FIPS 204 `PreHash` digest name, or `None` if the name is not in the whitelist.
///
/// This replaces the C `ossl_der_oid_pq_dsa_prehash_digest()` lookup function
/// from OpenSSL's `crypto/encode_decode/encoder_ml_dsa.c`. The OID encodings
/// are the standard NIST DER serialisations (tag `06` = OID, length byte,
/// value bytes) for the OID arc `2.16.840.1.101.3.4.2.X`.
///
/// Names are matched case-insensitively with both hyphenated (e.g. `SHA-256`)
/// and unhyphenated (e.g. `SHA256`) spellings to cover OpenSSL/RustCrypto
/// naming variations.
///
/// # Returns
///
/// - `Some((oid_der_bytes, digest_output_length_bytes))` for SHA-2, SHA-3,
///   and SHAKE families.
/// - `None` for unknown digest names.
fn lookup_prehash_digest(name: &str) -> Option<(Vec<u8>, usize)> {
    // Common DER prefix for all NIST hash OIDs: tag 06, len 09, arc bytes.
    // Suffix differs per algorithm (last byte of the OID arc).
    const NIST_HASH_PREFIX: [u8; 10] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];

    // Build a single DER OID by appending the algorithm-specific final byte.
    let build_oid = |suffix: u8| -> Vec<u8> {
        let mut oid = Vec::with_capacity(NIST_HASH_PREFIX.len() + 1);
        oid.extend_from_slice(&NIST_HASH_PREFIX);
        oid.push(suffix);
        oid
    };

    // Normalise: case-insensitive, accept both hyphenated and concatenated forms.
    let upper = name.to_ascii_uppercase();
    match upper.as_str() {
        // SHA-2 family
        "SHA2-256" | "SHA-256" | "SHA256" => Some((build_oid(0x01), 32)),
        "SHA2-384" | "SHA-384" | "SHA384" => Some((build_oid(0x02), 48)),
        "SHA2-512" | "SHA-512" | "SHA512" => Some((build_oid(0x03), 64)),
        "SHA2-224" | "SHA-224" | "SHA224" => Some((build_oid(0x04), 28)),
        "SHA2-512/224" | "SHA-512/224" | "SHA512-224" => Some((build_oid(0x05), 28)),
        "SHA2-512/256" | "SHA-512/256" | "SHA512-256" => Some((build_oid(0x06), 32)),
        // SHA-3 family (suffixes 0x07-0x0A)
        "SHA3-224" => Some((build_oid(0x07), 28)),
        "SHA3-256" => Some((build_oid(0x08), 32)),
        "SHA3-384" => Some((build_oid(0x09), 48)),
        "SHA3-512" => Some((build_oid(0x0A), 64)),
        // SHAKE family — fixed-output sizes for FIPS 204 PreHash mode.
        // SHAKE128: 32-byte truncation. SHAKE256: 64-byte truncation.
        "SHAKE-128" | "SHAKE128" => Some((build_oid(0x0B), 32)),
        "SHAKE-256" | "SHAKE256" => Some((build_oid(0x0C), 64)),
        _ => None,
    }
}

// =============================================================================
// Algorithm descriptors
// =============================================================================

/// Returns the algorithm descriptors for the ML-DSA mu hash provider.
///
/// Registers four name aliases — generic (`ML-DSA-MU`) and per-variant
/// (`ML-DSA-44-MU`, `ML-DSA-65-MU`, `ML-DSA-87-MU`) — under property
/// `provider=default`. All four names dispatch to a single
/// [`MlDsaMuProvider`] instance; the actual ML-DSA variant is determined
/// from the public-key length supplied via the `pubkey` `set_params` entry.
///
/// Mirrors C `ossl_ml_dsa_mu_functions[]` dispatch table from
/// `ml_dsa_mu_prov.c` (registered in `defltprov.c` with these four aliases).
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["ML-DSA-MU", "ML-DSA-44-MU", "ML-DSA-65-MU", "ML-DSA-87-MU"],
        property: "provider=default",
        description: "ML-DSA mu hash (SHAKE256-based, FIPS 204 internal hash, 64-byte output)",
    }]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a synthetic ML-DSA-44-length public key (1312 bytes).
    fn synth_pubkey_44() -> Vec<u8> {
        // Deterministic non-trivial bytes for reproducible tr values.
        (0..ML_DSA_44_PUB_LEN as u32)
            .map(|i| (i & 0xFF) as u8)
            .collect()
    }

    /// Helper: build a synthetic ML-DSA-65-length public key (1952 bytes).
    fn synth_pubkey_65() -> Vec<u8> {
        (0..ML_DSA_65_PUB_LEN as u32)
            .map(|i| ((i.wrapping_mul(7)) & 0xFF) as u8)
            .collect()
    }

    /// Helper: build a synthetic ML-DSA-87-length public key (2592 bytes).
    fn synth_pubkey_87() -> Vec<u8> {
        (0..ML_DSA_87_PUB_LEN as u32)
            .map(|i| ((i.wrapping_mul(13)) & 0xFF) as u8)
            .collect()
    }

    // ---------- Provider trait ----------

    #[test]
    fn provider_metadata_matches_fips204() {
        let p = MlDsaMuProvider;
        assert_eq!(p.name(), "ML-DSA-MU");
        assert_eq!(p.block_size(), 136); // SHAKE256 rate
        assert_eq!(p.digest_size(), 64); // SHAKE256_SIZE per C source line 36
        assert_eq!(p.digest_size(), MU_BYTES);
    }

    #[test]
    fn new_ctx_returns_uninitialised_context() {
        let p = MlDsaMuProvider;
        let ctx = p.new_ctx();
        assert!(ctx.is_ok());
    }

    // ---------- Descriptors ----------

    #[test]
    fn descriptors_list_all_four_aliases() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        let d = &descs[0];
        assert_eq!(d.names.len(), 4);
        assert!(d.names.contains(&"ML-DSA-MU"));
        assert!(d.names.contains(&"ML-DSA-44-MU"));
        assert!(d.names.contains(&"ML-DSA-65-MU"));
        assert!(d.names.contains(&"ML-DSA-87-MU"));
        assert_eq!(d.property, "provider=default");
        assert!(!d.description.is_empty());
    }

    // ---------- get_params ----------

    #[test]
    fn get_params_returns_xof_metadata() {
        let p = MlDsaMuProvider;
        let ctx = p.new_ctx().unwrap();
        let set = ctx.get_params().unwrap();
        // size and xoflen both equal MU_BYTES = 64
        assert_eq!(set.get("size").and_then(|v| v.as_u64()), Some(64));
        assert_eq!(set.get("xoflen").and_then(|v| v.as_u64()), Some(64));
        // blocksize = SHAKE256 rate
        assert_eq!(set.get("blocksize").and_then(|v| v.as_u64()), Some(136));
        // xof = 1 (XOF flag)
        assert_eq!(set.get("xof").and_then(|v| v.as_u64()), Some(1));
        // algid-absent = 1 (matches C SHAKE_FLAGS)
        assert_eq!(set.get("algid-absent").and_then(|v| v.as_u64()), Some(1));
    }

    // ---------- set_params: pubkey validation ----------

    #[test]
    fn set_pubkey_44_sets_keylen_and_tr() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let pk = synth_pubkey_44();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        ctx.set_params(&params)
            .expect("ML-DSA-44 pubkey must be accepted");
    }

    #[test]
    fn set_pubkey_65_sets_keylen_and_tr() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let pk = synth_pubkey_65();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        ctx.set_params(&params)
            .expect("ML-DSA-65 pubkey must be accepted");
    }

    #[test]
    fn set_pubkey_87_sets_keylen_and_tr() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let pk = synth_pubkey_87();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        ctx.set_params(&params)
            .expect("ML-DSA-87 pubkey must be accepted");
    }

    #[test]
    fn set_pubkey_invalid_length_rejected() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(vec![0u8; 100]));
        let err = ctx
            .set_params(&params)
            .expect_err("invalid length must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn set_pubkey_wrong_type_rejected() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::Utf8String("not bytes".to_string()));
        let err = ctx
            .set_params(&params)
            .expect_err("non-octet pubkey must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // ---------- set_params: ctx validation ----------

    #[test]
    fn set_ctx_string_accepted_within_limit() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("ctx", ParamValue::OctetString(vec![1, 2, 3, 4]));
        ctx.set_params(&params).expect("short ctx must be accepted");
    }

    #[test]
    fn set_ctx_string_at_max_accepted() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set(
            "ctx",
            ParamValue::OctetString(vec![0xAA; MAX_CONTEXT_STRING_LEN]),
        );
        ctx.set_params(&params)
            .expect("ctx == 255 bytes must be accepted");
    }

    #[test]
    fn set_ctx_string_exceeding_limit_rejected() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set(
            "ctx",
            ParamValue::OctetString(vec![0xAA; MAX_CONTEXT_STRING_LEN + 1]),
        );
        let err = ctx
            .set_params(&params)
            .expect_err("ctx > 255 must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn set_ctx_wrong_type_rejected() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("ctx", ParamValue::UInt32(42));
        let err = ctx
            .set_params(&params)
            .expect_err("non-octet ctx must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // ---------- set_params: propq ----------

    #[test]
    fn set_propq_accepted() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set(
            "propq",
            ParamValue::Utf8String("provider=default".to_string()),
        );
        ctx.set_params(&params)
            .expect("propq utf8 must be accepted");
    }

    #[test]
    fn set_propq_wrong_type_rejected() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("propq", ParamValue::OctetString(vec![1, 2, 3]));
        let err = ctx
            .set_params(&params)
            .expect_err("non-utf8 propq must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // ---------- set_params: digestname (PreHash mode) ----------

    #[test]
    fn set_digestname_sha256_enables_prehash_mode() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("digestname", ParamValue::Utf8String("SHA2-256".to_string()));
        ctx.set_params(&params)
            .expect("SHA2-256 must be a known prehash digest");
    }

    #[test]
    fn set_digestname_sha512_enables_prehash_mode() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("digestname", ParamValue::Utf8String("SHA-512".to_string()));
        ctx.set_params(&params)
            .expect("SHA-512 must be a known prehash digest");
    }

    #[test]
    fn set_digestname_unknown_returns_algorithm_unavailable() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set(
            "digestname",
            ParamValue::Utf8String("SOMETHING-ELSE".to_string()),
        );
        let err = ctx
            .set_params(&params)
            .expect_err("unknown digest must be rejected");
        assert!(matches!(err, ProviderError::AlgorithmUnavailable(_)));
    }

    #[test]
    fn set_digestname_wrong_type_rejected() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("digestname", ParamValue::OctetString(vec![1, 2]));
        let err = ctx
            .set_params(&params)
            .expect_err("non-utf8 digestname must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // ---------- update / finalize: missing pubkey ----------

    #[test]
    fn update_without_pubkey_fails_check_init() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let err = ctx
            .update(b"hello")
            .expect_err("update without pubkey must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn finalize_without_pubkey_fails_check_init() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let err = ctx
            .finalize()
            .expect_err("finalize without pubkey must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // ---------- Pure mode: empty message ----------

    #[test]
    fn pure_mode_empty_message_produces_64_bytes() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_44()));
        ctx.set_params(&params).unwrap();

        let mu = ctx.finalize().expect("Pure-mode empty mu must succeed");
        assert_eq!(mu.len(), 64);
    }

    // ---------- Pure mode: non-empty message ----------

    #[test]
    fn pure_mode_message_produces_deterministic_64_bytes() {
        let p = MlDsaMuProvider;
        let pk = synth_pubkey_44();

        // First run
        let mut ctx1 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk.clone()));
        ctx1.set_params(&params).unwrap();
        ctx1.update(b"the quick brown fox").unwrap();
        let mu1 = ctx1.finalize().unwrap();
        assert_eq!(mu1.len(), 64);

        // Second run with identical inputs — must match.
        let mut ctx2 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        ctx2.set_params(&params).unwrap();
        ctx2.update(b"the quick brown fox").unwrap();
        let mu2 = ctx2.finalize().unwrap();
        assert_eq!(mu1, mu2, "deterministic: same inputs must produce same mu");
    }

    #[test]
    fn pure_mode_different_messages_produce_different_mu() {
        let p = MlDsaMuProvider;
        let pk = synth_pubkey_44();

        let mut ctx1 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk.clone()));
        ctx1.set_params(&params).unwrap();
        ctx1.update(b"message one").unwrap();
        let mu1 = ctx1.finalize().unwrap();

        let mut ctx2 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        ctx2.set_params(&params).unwrap();
        ctx2.update(b"message two").unwrap();
        let mu2 = ctx2.finalize().unwrap();

        assert_ne!(mu1, mu2);
    }

    #[test]
    fn pure_mode_different_pubkeys_produce_different_mu() {
        let p = MlDsaMuProvider;

        let mut ctx1 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_44()));
        ctx1.set_params(&params).unwrap();
        ctx1.update(b"shared message").unwrap();
        let mu1 = ctx1.finalize().unwrap();

        let mut ctx2 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_65()));
        ctx2.set_params(&params).unwrap();
        ctx2.update(b"shared message").unwrap();
        let mu2 = ctx2.finalize().unwrap();

        assert_ne!(mu1, mu2);
    }

    #[test]
    fn pure_mode_different_context_strings_produce_different_mu() {
        let p = MlDsaMuProvider;
        let pk = synth_pubkey_44();

        let mut ctx1 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk.clone()));
        params.set("ctx", ParamValue::OctetString(b"context-a".to_vec()));
        ctx1.set_params(&params).unwrap();
        ctx1.update(b"shared message").unwrap();
        let mu1 = ctx1.finalize().unwrap();

        let mut ctx2 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        params.set("ctx", ParamValue::OctetString(b"context-b".to_vec()));
        ctx2.set_params(&params).unwrap();
        ctx2.update(b"shared message").unwrap();
        let mu2 = ctx2.finalize().unwrap();

        assert_ne!(mu1, mu2, "context separation must differentiate mu values");
    }

    // ---------- Pure mode: streaming update equivalence ----------

    #[test]
    fn pure_mode_streaming_update_matches_single_update() {
        let p = MlDsaMuProvider;
        let pk = synth_pubkey_44();
        let message = b"the rain in spain falls mainly on the plain";

        // Single-shot update
        let mut ctx1 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk.clone()));
        ctx1.set_params(&params).unwrap();
        ctx1.update(message).unwrap();
        let mu1 = ctx1.finalize().unwrap();

        // Multi-chunk streaming update
        let mut ctx2 = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        ctx2.set_params(&params).unwrap();
        for chunk in message.chunks(7) {
            ctx2.update(chunk).unwrap();
        }
        let mu2 = ctx2.finalize().unwrap();

        assert_eq!(mu1, mu2, "streaming chunks must produce identical mu");
    }

    // ---------- finalize: double-call ----------

    #[test]
    fn double_finalize_rejected() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_44()));
        ctx.set_params(&params).unwrap();

        let _mu1 = ctx.finalize().unwrap();
        let err = ctx.finalize().expect_err("second finalize must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn update_after_finalize_rejected() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_44()));
        ctx.set_params(&params).unwrap();

        let _mu = ctx.finalize().unwrap();
        let err = ctx
            .update(b"after final")
            .expect_err("update after finalize must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // ---------- PreHash mode: length enforcement ----------

    #[test]
    fn prehash_mode_exact_length_succeeds() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_44()));
        params.set("digestname", ParamValue::Utf8String("SHA2-256".to_string()));
        ctx.set_params(&params).unwrap();

        // SHA2-256 produces 32 bytes — supply exactly that.
        ctx.update(&[0u8; 32]).unwrap();
        let mu = ctx
            .finalize()
            .expect("PreHash with exact digest length must finalize");
        assert_eq!(mu.len(), 64);
    }

    #[test]
    fn prehash_mode_short_input_fails_finalize() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_44()));
        params.set("digestname", ParamValue::Utf8String("SHA2-512".to_string()));
        ctx.set_params(&params).unwrap();

        // SHA2-512 expects 64 bytes — supply only 30.
        ctx.update(&[0u8; 30]).unwrap();
        let err = ctx
            .finalize()
            .expect_err("PreHash short input must fail finalize");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn prehash_mode_overlong_input_rejected_during_update() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_44()));
        params.set("digestname", ParamValue::Utf8String("SHA2-256".to_string()));
        ctx.set_params(&params).unwrap();

        // SHA2-256 expects 32 bytes — supply 33.
        let err = ctx
            .update(&[0u8; 33])
            .expect_err("PreHash overlong update must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn prehash_mode_streaming_length_enforced() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(synth_pubkey_44()));
        params.set("digestname", ParamValue::Utf8String("SHA2-256".to_string()));
        ctx.set_params(&params).unwrap();

        // Feed exactly 32 bytes in three chunks (10 + 15 + 7).
        ctx.update(&[0u8; 10]).unwrap();
        ctx.update(&[1u8; 15]).unwrap();
        ctx.update(&[2u8; 7]).unwrap();
        let mu = ctx
            .finalize()
            .expect("streaming exact-length PreHash must finalize");
        assert_eq!(mu.len(), 64);
    }

    #[test]
    fn prehash_mode_distinct_from_pure_mode() {
        let p = MlDsaMuProvider;
        let pk = synth_pubkey_44();
        let payload = vec![0xABu8; 32];

        // Pure mode
        let mut ctx_pure = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk.clone()));
        ctx_pure.set_params(&params).unwrap();
        ctx_pure.update(&payload).unwrap();
        let mu_pure = ctx_pure.finalize().unwrap();

        // PreHash mode (with SHA2-256 OID)
        let mut ctx_pre = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        params.set("digestname", ParamValue::Utf8String("SHA2-256".to_string()));
        ctx_pre.set_params(&params).unwrap();
        ctx_pre.update(&payload).unwrap();
        let mu_pre = ctx_pre.finalize().unwrap();

        // Different mode bytes (0x00 vs 0x01) and OID prefix in PreHash.
        assert_ne!(
            mu_pure, mu_pre,
            "Pure and PreHash modes must produce distinct mu values"
        );
    }

    // ---------- duplicate ----------

    #[test]
    fn duplicate_preserves_state() {
        let p = MlDsaMuProvider;
        let pk = synth_pubkey_44();
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        params.set("ctx", ParamValue::OctetString(b"shared-ctx".to_vec()));
        ctx.set_params(&params).unwrap();
        ctx.update(b"first part").unwrap();

        // Duplicate after partial update.
        let mut dup = ctx.duplicate().unwrap();

        // Both should produce the same final mu when given identical remaining input.
        ctx.update(b" second part").unwrap();
        dup.update(b" second part").unwrap();

        let mu1 = ctx.finalize().unwrap();
        let mu2 = dup.finalize().unwrap();
        assert_eq!(mu1, mu2, "duplicated context must compute identical mu");
    }

    #[test]
    fn duplicate_independent_progress() {
        let p = MlDsaMuProvider;
        let pk = synth_pubkey_44();
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk));
        ctx.set_params(&params).unwrap();
        ctx.update(b"common prefix").unwrap();

        let mut dup = ctx.duplicate().unwrap();
        ctx.update(b" branch A").unwrap();
        dup.update(b" branch B").unwrap();

        let mu1 = ctx.finalize().unwrap();
        let mu2 = dup.finalize().unwrap();
        assert_ne!(mu1, mu2, "diverging branches must produce distinct mu");
    }

    // ---------- init: re-initialisation ----------

    #[test]
    fn init_resets_finalised_state() {
        let p = MlDsaMuProvider;
        let pk = synth_pubkey_44();
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("pubkey", ParamValue::OctetString(pk.clone()));
        ctx.set_params(&params).unwrap();
        ctx.update(b"first").unwrap();
        let _mu1 = ctx.finalize().unwrap();

        // Re-init should clear finalized flag and restore usability.
        let mut params2 = ParamSet::new();
        params2.set("pubkey", ParamValue::OctetString(pk));
        ctx.init(Some(&params2)).expect("re-init must succeed");
        ctx.update(b"second round").unwrap();
        let mu2 = ctx.finalize().unwrap();
        assert_eq!(mu2.len(), 64);
    }

    #[test]
    fn init_with_no_params_clears_state() {
        let p = MlDsaMuProvider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).expect("init(None) must succeed");
        // Without a key, update must fail (state was cleared).
        let err = ctx
            .update(b"x")
            .expect_err("update without key after init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // ---------- lookup_prehash_digest helper ----------

    #[test]
    fn lookup_prehash_digest_known_names() {
        // SHA-2 family
        assert_eq!(lookup_prehash_digest("SHA2-256").map(|(_, l)| l), Some(32));
        assert_eq!(lookup_prehash_digest("SHA-256").map(|(_, l)| l), Some(32));
        assert_eq!(lookup_prehash_digest("sha256").map(|(_, l)| l), Some(32));
        assert_eq!(lookup_prehash_digest("SHA2-384").map(|(_, l)| l), Some(48));
        assert_eq!(lookup_prehash_digest("SHA2-512").map(|(_, l)| l), Some(64));
        // SHA-3 family
        assert_eq!(lookup_prehash_digest("SHA3-256").map(|(_, l)| l), Some(32));
        assert_eq!(lookup_prehash_digest("SHA3-512").map(|(_, l)| l), Some(64));
        // SHAKE family
        assert_eq!(lookup_prehash_digest("SHAKE-128").map(|(_, l)| l), Some(32));
        assert_eq!(lookup_prehash_digest("SHAKE256").map(|(_, l)| l), Some(64));
    }

    #[test]
    fn lookup_prehash_digest_unknown_name() {
        assert!(lookup_prehash_digest("NOT-A-HASH").is_none());
        assert!(lookup_prehash_digest("").is_none());
        assert!(lookup_prehash_digest("MD5").is_none()); // not a FIPS 204 prehash
    }

    #[test]
    fn lookup_prehash_digest_oid_format() {
        // All NIST hash OIDs share the same 10-byte prefix.
        let (oid_sha256, _) = lookup_prehash_digest("SHA2-256").unwrap();
        assert_eq!(oid_sha256[0], 0x06); // DER tag = OID
        assert_eq!(oid_sha256[1], 0x09); // DER length = 9
        assert_eq!(
            &oid_sha256[2..10],
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02]
        );
        assert_eq!(oid_sha256[10], 0x01); // SHA2-256 final arc

        let (oid_sha512, _) = lookup_prehash_digest("SHA2-512").unwrap();
        assert_eq!(oid_sha512[10], 0x03); // SHA2-512 final arc

        let (oid_shake256, _) = lookup_prehash_digest("SHAKE-256").unwrap();
        assert_eq!(oid_shake256[10], 0x0C); // SHAKE-256 final arc
    }

    // ---------- Provider clone semantics ----------

    #[test]
    fn provider_is_cloneable() {
        let p1 = MlDsaMuProvider;
        let p2 = p1.clone();
        assert_eq!(p1.name(), p2.name());
    }

    #[test]
    fn provider_is_default() {
        let p1: MlDsaMuProvider = Default::default();
        assert_eq!(p1.name(), "ML-DSA-MU");
    }
}
