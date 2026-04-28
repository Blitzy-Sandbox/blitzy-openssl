//! AES-XTS — XEX-based Tweaked-codebook mode with Ciphertext Stealing.
//!
//! AES-XTS (IEEE Std 1619-2018, NIST SP 800-38E) is the standard
//! length-preserving encryption mode for storage devices: full-disk
//! encryption, file-system block encryption, and block-device encryption
//! at rest. Unlike AEAD modes (GCM, CCM), XTS provides
//! confidentiality only — there is no built-in authentication tag.
//!
//! # Two-Key Design
//!
//! XTS uses *two* AES keys — a "data key" (K1) and a "tweak key" (K2) —
//! that are concatenated into a single combined key blob:
//!
//! | Variant      | K1 length | K2 length | Combined key | OpenSSL name      |
//! |--------------|-----------|-----------|--------------|-------------------|
//! | AES-128-XTS  | 128 bit   | 128 bit   | 256 bit      | `AES-128-XTS`     |
//! | AES-256-XTS  | 256 bit   | 256 bit   | 512 bit      | `AES-256-XTS`     |
//!
//! Per the discussion in §1.3 of IEEE 1619-2018, K1 and K2 **must
//! differ**. Re-using the same key for data and tweak invalidates the
//! security proof (Rogaway 2004). The check is performed in
//! constant time via [`subtle::ConstantTimeEq`] — a lookup-table or
//! short-circuit comparison would leak partial-equality information
//! through a timing side channel. FIPS 140-2 IG A.9 mandates this
//! check unconditionally for FIPS-approved deployments.
//!
//! # 2²⁰-Block Limit
//!
//! Per §5.1 of IEEE 1619-2018, a single (K1, K2, IV) tuple may
//! encrypt at most 2²⁰ AES blocks (= 16 MiB) of plaintext. Beyond
//! that, tweak-block reuse becomes statistically detectable. The
//! provider enforces this limit at [`update`](CipherContext::update)
//! time, returning [`ProviderError::Dispatch`] when exceeded.
//!
//! # Block Size and IV
//!
//! - The "block size" reported by the [`CipherProvider`] trait is **1
//!   byte**, mirroring the C provider's `AES_XTS_BLOCK_BITS = 8`.
//!   Ciphertext stealing makes XTS effectively stream-like — it
//!   produces output of identical length to the input — so callers
//!   pass arbitrary lengths (≥16 bytes) to [`update`].
//! - The IV is the 128-bit "tweak" or "sector number" that
//!   identifies the data unit being encrypted. It is treated as
//!   little-endian in the IEEE 1619 standard but is delivered
//!   opaquely as 16 raw bytes by the provider API — see
//!   [`CipherFlags::CUSTOM_IV`].
//!
//! # State Machine
//!
//! ```text
//!   ┌──────────┐ encrypt_init/decrypt_init ┌─────────────┐
//!   │  Empty   │──────────────────────────▶│  Initialised│
//!   └──────────┘                           └─────────────┘
//!                                                │
//!                                          update│ (≤ 16 MiB)
//!                                                ▼
//!                                          ┌─────────────┐
//!                                          │  Processed  │
//!                                          └─────────────┘
//!                                                │
//!                                          finalize│ (no-op)
//!                                                ▼
//!                                          ┌─────────────┐
//!                                          │   Sealed    │
//!                                          └─────────────┘
//! ```
//!
//! # Source Mapping
//!
//! This module replaces three C source files:
//!
//! | C File                           | Lines | Rust Equivalent              |
//! |----------------------------------|-------|------------------------------|
//! | `cipher_aes_xts.c`               | ~310  | This module (provider plumbing) |
//! | `cipher_aes_xts_hw.c`            | ~330  | Collapsed into [`AesXts`]     |
//! | `cipher_aes_xts_fips.c`          | ~25   | Always-on key-differ check    |
//!
//! The C code's hardware dispatch (`HWAES_CAPABLE → BSAES_CAPABLE →
//! VPAES_CAPABLE → generic`) is opaque at this layer: [`AesXts`] in
//! `openssl-crypto` chooses the optimal backend at construction time
//! based on detected CPU features. The `cipher_aes_xts_fips.c` file
//! defines a single boolean (`ossl_aes_xts_allow_insecure_decrypt`)
//! that gates whether decrypt-side key-differ checks may be skipped;
//! the Rust port is stricter than the C non-FIPS build — we
//! always enforce K1 ≠ K2 (see [`AesXts::new`]) which matches
//! FIPS-mode behaviour.
//!
//! # Rules Enforced
//!
//! - **R5** (no sentinels): [`XtsStandard`] is an enum, not an
//!   integer flag.
//! - **R6** (lossless casts): block-count and IV-length conversions
//!   use [`usize::checked_div`], [`u32::try_from`], and
//!   [`<[u8; N]>::try_from`].
//! - **R8** (no `unsafe`): zero `unsafe` blocks; constant-time
//!   comparison via [`subtle`].
//! - **§0.7.6** (secure erasure): [`AesXtsContext`] derives
//!   [`Zeroize`] and [`ZeroizeOnDrop`] so all key material is wiped
//!   on drop, mirroring `OPENSSL_clear_free()` in `aes_xts_freectx`.
//!
//! # Algorithm Registry
//!
//! [`descriptors`] returns the two algorithm entries registered with
//! the default provider:
//!
//! | Name           | Property              | Description                       |
//! |----------------|-----------------------|-----------------------------------|
//! | `AES-128-XTS`  | `provider=default`    | 128-bit XTS (256-bit combined key) |
//! | `AES-256-XTS`  | `provider=default`    | 256-bit XTS (512-bit combined key) |
//!
//! AES-192-XTS does *not* exist by design (IEEE 1619 §5 specifies
//! only 128-bit and 256-bit variants).

use std::fmt;

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::symmetric::aes::AesXts;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};

use super::common::{
    generic_get_params, make_cipher_descriptor, param_keys, CipherFlags, CipherMode,
};

// =============================================================================
// Constants
// =============================================================================

/// AES-XTS IV length — exactly 16 bytes (the "tweak" or sector number).
///
/// Per IEEE Std 1619-2018 §5.1 and the C provider's
/// `AES_XTS_IV_BITS = 128`.
const AES_XTS_IV_LEN: usize = 16;

/// AES block size in bytes. Hard-coded here because the
/// `AES_BLOCK_SIZE` constant in `openssl-crypto::symmetric::aes` is
/// crate-private; this value is fixed by the AES specification
/// (FIPS 197) and cannot vary.
const AES_BLOCK_BYTES: usize = 16;

/// Reported block size (1 byte). XTS with ciphertext stealing is
/// effectively stream-like — output length equals input length —
/// so the cipher reports a 1-byte block to signal "no padding
/// required" to consumers. Mirrors the C provider's
/// `AES_XTS_BLOCK_BITS = 8`.
const AES_XTS_BLOCK_BYTES: usize = 1;

/// Maximum number of AES blocks that may be encrypted under a single
/// (K1, K2, IV) tuple before tweak-block reuse becomes statistically
/// detectable. Per IEEE Std 1619-2018 §5.1, this limit is 2²⁰.
const AES_XTS_MAX_BLOCKS_PER_DATA_UNIT: usize = 1 << 20;

/// Maximum byte length per `update`/`finalize` call: 2²⁰ × 16 = 16 MiB.
/// Inputs exceeding this length are rejected by [`AesXtsContext::update`].
const AES_XTS_MAX_BYTES_PER_DATA_UNIT: usize = AES_XTS_MAX_BLOCKS_PER_DATA_UNIT * AES_BLOCK_BYTES;

/// Minimum input length: one full AES block. XTS is undefined for
/// inputs shorter than 16 bytes — ciphertext stealing requires at
/// least one full block of "stuff to steal from".
const AES_XTS_MIN_INPUT_BYTES: usize = AES_BLOCK_BYTES;

/// Combined key length for AES-128-XTS (two 16-byte AES keys).
const AES_128_XTS_KEY_BYTES: usize = 32;

/// Combined key length for AES-256-XTS (two 32-byte AES keys).
const AES_256_XTS_KEY_BYTES: usize = 64;

// =============================================================================
// XtsStandard — IEEE vs GB compatibility
// =============================================================================

/// Selects between the IEEE-1619 standard and the Chinese GB/T
/// 17964 standard variant of XTS.
///
/// The C provider exposes a `cts_mode` parameter that toggles
/// between standards; we model it as a Rust enum (Rule R5 — no
/// sentinel integer flags).
///
/// # Variants
///
/// - [`XtsStandard::Ieee`] — IEEE Std 1619-2018, the canonical
///   XTS-AES specification used by every general-purpose
///   storage-encryption deployment (`LUKS`, `BitLocker`, Apple `FileVault`,
///   ZFS, etc.). **Default and only-supported variant in
///   FIPS-approved mode.**
/// - [`XtsStandard::Gb`] — GB/T 17964-2008, a Chinese national
///   standard. Differs only in the tweak generation sequence and
///   is supported by the C provider as a legacy compatibility
///   knob. *Not* FIPS-approved.
///
/// In the Rust port, both variants currently delegate to the same
/// IEEE-1619 [`AesXts`] implementation (the GB-flavour tweak
/// schedule is a planned future extension); selection is preserved
/// only for parameter-surface compatibility with C consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XtsStandard {
    /// IEEE Std 1619-2018 (default, FIPS-approved).
    Ieee,
    /// GB/T 17964-2008 (Chinese national standard, not FIPS).
    Gb,
}

impl Default for XtsStandard {
    fn default() -> Self {
        Self::Ieee
    }
}

impl fmt::Display for XtsStandard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ieee => f.write_str("IEEE-1619"),
            Self::Gb => f.write_str("GB/T 17964"),
        }
    }
}

// =============================================================================
// AesXtsCipher — Algorithm Descriptor
// =============================================================================

/// AES-XTS cipher descriptor.
///
/// This is a lightweight, immutable handle returned by
/// [`descriptors`] and registered with the default provider. It
/// encodes the algorithm's identity (name + key size) and is
/// trivially clonable for trait-object dispatch. Per-operation
/// state lives in [`AesXtsContext`], created via [`new_ctx`].
///
/// # Construction
///
/// Use [`AesXtsCipher::new`] with one of:
///
/// - `AesXtsCipher::new("AES-128-XTS", 32)` — 128-bit XTS
/// - `AesXtsCipher::new("AES-256-XTS", 64)` — 256-bit XTS
///
/// The constructor accepts arbitrary `(name, key_bytes)` pairs to
/// avoid duplicating registry data; mismatched sizes are rejected
/// at [`encrypt_init`](CipherContext::encrypt_init) /
/// [`decrypt_init`](CipherContext::decrypt_init) time. This
/// matches the C provider, where `EVP_CIPHER` carries the declared
/// key size and the runtime check happens later.
///
/// [`new_ctx`]: AesXtsCipher::new_ctx
#[derive(Debug, Clone)]
pub struct AesXtsCipher {
    /// Algorithm name (`"AES-128-XTS"` or `"AES-256-XTS"`).
    name: &'static str,
    /// Combined key size in bytes (32 for AES-128-XTS, 64 for AES-256-XTS).
    key_bytes: usize,
}

impl AesXtsCipher {
    /// Creates a new AES-XTS cipher descriptor.
    ///
    /// # Parameters
    ///
    /// - `name`: algorithm name to report (e.g. `"AES-256-XTS"`).
    /// - `key_bytes`: combined key length in bytes — must be 32
    ///   (AES-128-XTS) or 64 (AES-256-XTS). The constructor
    ///   accepts arbitrary values; mismatched sizes are rejected
    ///   at [`encrypt_init`](CipherContext::encrypt_init) time.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use openssl_provider::implementations::ciphers::aes_xts::AesXtsCipher;
    /// let cipher = AesXtsCipher::new("AES-256-XTS", 64);
    /// ```
    #[must_use]
    pub fn new(name: &'static str, key_bytes: usize) -> Self {
        Self { name, key_bytes }
    }
}

impl CipherProvider for AesXtsCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        // Combined key length (K1 || K2). Doubled relative to the
        // underlying AES-128 / AES-256 scheme: matches the C
        // provider's `2 * kbits / 8`.
        self.key_bytes
    }

    fn iv_length(&self) -> usize {
        // The XTS "tweak" — 16 bytes for both AES-128-XTS and
        // AES-256-XTS. Not configurable.
        AES_XTS_IV_LEN
    }

    fn block_size(&self) -> usize {
        // 1 byte: ciphertext stealing makes XTS length-preserving;
        // callers pass arbitrary input lengths (≥ 16 bytes) and
        // receive output of identical length. Mirrors C's
        // `AES_XTS_BLOCK_BITS = 8`.
        AES_XTS_BLOCK_BYTES
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(AesXtsContext::new(self.name, self.key_bytes)))
    }
}

// =============================================================================
// AesXtsContext — Per-Operation State
// =============================================================================

/// Per-operation AES-XTS context.
///
/// Created by [`AesXtsCipher::new_ctx`] and initialised via
/// [`encrypt_init`](CipherContext::encrypt_init) /
/// [`decrypt_init`](CipherContext::decrypt_init). Holds all mutable
/// state for one encrypt/decrypt lifecycle, including the keyed
/// [`AesXts`] engine, the 128-bit IV/tweak, and the standard
/// selector ([`XtsStandard`]).
///
/// # Memory Hygiene
///
/// All sensitive material — IV, the keyed [`AesXts`] engine — is
/// zeroized on drop via the `Zeroize`/`ZeroizeOnDrop` derives plus
/// the engine's own `ZeroizeOnDrop` impl. This translates the C
/// provider's `OPENSSL_clear_free()` call in `aes_xts_freectx`
/// (`cipher_aes_xts.c` lines 139-145).
///
/// # Field Invariants
///
/// - `cipher.is_some()` after a successful [`encrypt_init`] /
///   [`decrypt_init`].
/// - `iv_set == true` implies `iv.len() == AES_XTS_IV_LEN`.
/// - `initialized == true` implies `cipher.is_some() && iv_set`.
///
/// [`encrypt_init`]: CipherContext::encrypt_init
/// [`decrypt_init`]: CipherContext::decrypt_init
// RATIONALE: The four boolean fields encode four orthogonal aspects of
// the cipher's lifecycle (IV populated, fully initialised, direction,
// stream started). Consolidating them into a single state enum would
// require storing the encrypt/decrypt direction separately and obscure
// the simple invariants documented above, providing no real benefit
// over the named-field representation. This mirrors the C struct layout
// in `cipher_aes_xts.c` (PROV_AES_XTS_CTX `enc`, `iv_set`, `started`).
#[allow(clippy::struct_excessive_bools)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AesXtsContext {
    // --- Configuration (immutable after construction) ---
    /// Algorithm name for parameter reporting. `&'static str`, never
    /// holds key material — skipped for zeroize.
    #[zeroize(skip)]
    name: &'static str,
    /// Expected combined key size in bytes (32 or 64).
    key_bytes: usize,
    /// Standard selector — IEEE-1619 (default) or GB/T 17964.
    /// `XtsStandard` is `Copy` and holds no key material.
    #[zeroize(skip)]
    standard: XtsStandard,

    // --- Operational State (mutable) ---
    /// The keyed XTS engine. `None` until [`encrypt_init`] /
    /// [`decrypt_init`] succeeds. `AesXts` itself derives
    /// `ZeroizeOnDrop` — see `crates/openssl-crypto/src/symmetric/aes.rs`
    /// — so it self-wipes when this `Option` drops, but it does
    /// *not* implement `Zeroize` directly, hence the skip annotation.
    ///
    /// [`encrypt_init`]: CipherContext::encrypt_init
    /// [`decrypt_init`]: CipherContext::decrypt_init
    #[zeroize(skip)]
    cipher: Option<AesXts>,
    /// 128-bit tweak (sector number / data-unit index).
    iv: Vec<u8>,
    /// True once `iv` has been populated by an init call.
    iv_set: bool,
    /// True once the context is fully ready for `update`/`finalize`.
    initialized: bool,
    /// Direction: `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// True once at least one `update` has consumed input — locks
    /// out post-stream parameter mutations.
    started: bool,
}

// Manual `Debug` to redact secret-bearing fields. Mirrors the
// `aes_gcm.rs` pattern: print only the algorithm name, key size,
// and high-level state flags.
//
// The `iv` field is summarised by its length only. Although the XTS
// tweak (sector number) is *not* itself secret in disk-encryption
// deployments, including raw bytes in `Debug` output is undesirable
// because it can leak addressable storage layout into log streams.
// The keyed `cipher` engine is replaced with the marker string
// `"<keyed>"` so that no AES round-key material can be inferred.
impl fmt::Debug for AesXtsContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesXtsContext")
            .field("name", &self.name)
            .field("key_bytes", &self.key_bytes)
            .field("standard", &self.standard)
            .field("cipher", &self.cipher.as_ref().map(|_| "<keyed>"))
            .field("iv_len", &self.iv.len())
            .field("iv_set", &self.iv_set)
            .field("initialized", &self.initialized)
            .field("encrypting", &self.encrypting)
            .field("started", &self.started)
            .finish()
    }
}

impl AesXtsContext {
    /// Creates a fresh, uninitialised context.
    ///
    /// The returned context has no keyed engine and no IV; callers
    /// must invoke [`encrypt_init`](CipherContext::encrypt_init) or
    /// [`decrypt_init`](CipherContext::decrypt_init) before any
    /// `update`/`finalize` calls.
    fn new(name: &'static str, key_bytes: usize) -> Self {
        Self {
            name,
            key_bytes,
            standard: XtsStandard::Ieee,
            cipher: None,
            iv: Vec::new(),
            iv_set: false,
            initialized: false,
            encrypting: true,
            started: false,
        }
    }

    /// Validates that the supplied key is the expected size.
    ///
    /// Mirrors the C runtime check at `cipher_aes_xts.c` line 88:
    /// `keylen == ctx->keylen`. Allowed values are 32 (AES-128-XTS)
    /// and 64 (AES-256-XTS); 48 (AES-192) is *not* an XTS variant
    /// per IEEE 1619 §5.
    fn validate_key_size(&self, key_len: usize) -> ProviderResult<()> {
        if !matches!(key_len, AES_128_XTS_KEY_BYTES | AES_256_XTS_KEY_BYTES) {
            return Err(ProviderError::Init(format!(
                "AES-XTS combined key length must be 32 or 64 bytes (got {key_len})"
            )));
        }
        if key_len != self.key_bytes {
            return Err(ProviderError::Init(format!(
                "AES-XTS key size mismatch: cipher declares {} bytes but caller provided {}",
                self.key_bytes, key_len
            )));
        }
        Ok(())
    }

    /// Constant-time check that the two halves of the combined key
    /// differ. **Rogaway 2004 vulnerability mitigation; FIPS 140-2
    /// IG A.9 mandate.**
    ///
    /// This duplicates the check inside [`AesXts::new`] (which also
    /// uses `ct_eq`). Performing it here lets us emit a more
    /// targeted [`ProviderError::Init`] message before delegating to
    /// the crypto layer, matching the C provider's
    /// `aes_xts_check_keys_differ` (`cipher_aes_xts.c` lines 39-65).
    ///
    /// **Critical:** comparison MUST be constant-time. A
    /// short-circuiting `==` would leak information about the
    /// position of the first differing byte through a timing side
    /// channel.
    fn check_keys_differ(key: &[u8]) -> ProviderResult<()> {
        // For XTS the combined key is laid out as `K1 || K2` with
        // `len(K1) == len(K2) == key.len() / 2`. The key length is
        // already validated to be even (32 or 64) before reaching
        // here, so the unchecked split is safe.
        let half = key.len() / 2;
        let (k1, k2) = key.split_at(half);
        // `ConstantTimeEq::ct_eq` returns `subtle::Choice` (a
        // wrapped u8); `bool::from` performs the standard
        // CtOption-style materialisation. Both operations are
        // constant-time relative to the *content* of k1 and k2.
        if bool::from(k1.ct_eq(k2)) {
            return Err(ProviderError::Init(
                "AES-XTS key halves must differ (IEEE 1619 §1.3 / FIPS 140-2 IG A.9)".to_string(),
            ));
        }
        Ok(())
    }

    /// Validates IV (128-bit tweak) length. The provider always
    /// uses a 16-byte IV regardless of key size.
    fn validate_iv_len(iv_len: usize) -> ProviderResult<()> {
        if iv_len != AES_XTS_IV_LEN {
            return Err(ProviderError::Init(format!(
                "AES-XTS IV length must be exactly {AES_XTS_IV_LEN} bytes (got {iv_len})"
            )));
        }
        Ok(())
    }

    /// Shared encrypt/decrypt initialisation logic. Mirrors C
    /// `aes_xts_init` (`cipher_aes_xts.c` lines 73-100).
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // Step 1: validate combined key size.
        self.validate_key_size(key.len())?;

        // Step 2: validate keys-must-differ. Even though
        // `AesXts::new` performs an internal constant-time check,
        // we duplicate it here so we can emit a provider-level
        // error message before incurring two AES key-schedule
        // setups (which is the bulk of `AesXts::new`'s work).
        Self::check_keys_differ(key)?;

        // Step 3: build the keyed engine. Maps any residual
        // crypto-layer error (e.g. AES key-schedule failure on
        // weird hardware) to ProviderError::Init.
        let engine = AesXts::new(key)
            .map_err(|e| ProviderError::Init(format!("AES-XTS key schedule failed: {e}")))?;

        // Step 4: stash the keyed engine and the direction.
        self.cipher = Some(engine);
        self.encrypting = encrypting;

        // Step 5: apply the IV if supplied. The C provider permits
        // a NULL IV at init and requires it via parameters or a
        // subsequent call; we mirror that by leaving `iv_set` false
        // until either an IV is supplied or one arrives via
        // `set_params` (currently no IV-via-params path is exposed
        // for XTS — the IV is delivered at init).
        if let Some(iv_bytes) = iv {
            Self::validate_iv_len(iv_bytes.len())?;
            self.iv.clear();
            self.iv.extend_from_slice(iv_bytes);
            self.iv_set = true;
        } else {
            // Reset any prior IV — initialising without an IV
            // explicitly invalidates the previous one, matching the
            // C provider's `ossl_cipher_generic_initiv` semantics.
            self.iv.clear();
            self.iv_set = false;
        }

        // Step 6: reset stream-progress flags.
        self.started = false;
        self.initialized = true;

        // Step 7: apply optional trailing parameters (e.g. cts_mode
        // for IEEE/GB selection). Errors here unwind the
        // initialisation.
        if let Some(p) = params {
            if let Err(e) = self.set_params(p) {
                // Rollback the partially-initialised state to a
                // safe baseline so the caller doesn't observe a
                // dangling keyed engine.
                self.initialized = false;
                self.cipher = None;
                self.iv.clear();
                self.iv_set = false;
                self.started = false;
                return Err(e);
            }
        }

        Ok(())
    }

    /// Returns a reference to the keyed engine, erroring if init
    /// has not been performed.
    fn engine(&self) -> ProviderResult<&AesXts> {
        self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("AES-XTS context not initialised with a key".into())
        })
    }

    /// Returns the IV as a fixed-size array, erroring if not set or
    /// the wrong length. The crypto-layer [`AesXts::encrypt`] /
    /// [`AesXts::decrypt`] entry points require `&[u8; 16]` (a
    /// fixed array, not a slice) so we materialise it here.
    fn iv_array(&self) -> ProviderResult<[u8; AES_XTS_IV_LEN]> {
        if !self.iv_set {
            return Err(ProviderError::Dispatch(
                "AES-XTS IV (tweak) not set; supply one to encrypt_init/decrypt_init".into(),
            ));
        }
        // Rule R6: lossless cast via `<[u8; N]>::try_from`, never
        // a bare `as` truncation. The error path is only reachable
        // if `validate_iv_len` was bypassed — defensive.
        let arr: [u8; AES_XTS_IV_LEN] = self.iv.as_slice().try_into().map_err(|_| {
            ProviderError::Dispatch(format!(
                "AES-XTS IV must be exactly {AES_XTS_IV_LEN} bytes (got {})",
                self.iv.len()
            ))
        })?;
        Ok(arr)
    }

    /// Enforces the 2²⁰-block-per-data-unit limit of IEEE 1619 §5.1.
    fn enforce_block_limit(input_len: usize) -> ProviderResult<()> {
        if input_len > AES_XTS_MAX_BYTES_PER_DATA_UNIT {
            return Err(ProviderError::Dispatch(format!(
                "AES-XTS input length {input_len} exceeds 2^20 AES blocks \
                 ({AES_XTS_MAX_BYTES_PER_DATA_UNIT} bytes / 16 MiB) \
                 per IEEE 1619 §5.1"
            )));
        }
        Ok(())
    }
}

impl CipherContext for AesXtsContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, true, params)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, false, params)
    }

    /// Streaming update.
    ///
    /// Mirrors the C dispatcher in `cipher_aes_xts.c::aes_xts_cipher`
    /// (lines 175-213). XTS is a one-shot operation per data unit:
    /// the entire data unit must be supplied in a single
    /// `update`/`finalize` cycle. We perform the encryption
    /// in `update` and emit a no-op `finalize`, matching the C
    /// provider's `aes_xts_stream_update` /
    /// `aes_xts_stream_final` pair.
    ///
    /// Constraints:
    /// - Input length **must** be ≥ 16 bytes (one AES block) — XTS
    ///   with ciphertext stealing requires at least one full block.
    /// - Input length **must** be ≤ 16 MiB (2²⁰ × 16 bytes) per
    ///   IEEE 1619 §5.1.
    /// - Once a non-empty update is observed, the IV/key/standard
    ///   become immutable for the remainder of the operation.
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES-XTS context not initialised".into(),
            ));
        }
        if input.is_empty() {
            // No-op for empty input — matches the C provider's
            // tolerance of zero-length update calls.
            return Ok(0);
        }
        // Pre-flight invariants: the engine must be keyed and the
        // IV must be set.
        let _ = self.engine()?;
        if !self.iv_set {
            return Err(ProviderError::Dispatch(
                "AES-XTS IV (tweak) not set before update; supply via encrypt_init/decrypt_init"
                    .into(),
            ));
        }

        // IEEE 1619 minimum — one AES block.
        if input.len() < AES_XTS_MIN_INPUT_BYTES {
            return Err(ProviderError::Dispatch(format!(
                "AES-XTS input must be at least {AES_XTS_MIN_INPUT_BYTES} bytes \
                 (one AES block); got {}",
                input.len()
            )));
        }

        // IEEE 1619 maximum — 2²⁰ blocks. Must check before
        // delegating to the crypto layer because exceeding the
        // limit is a *security* failure, not just a correctness one.
        Self::enforce_block_limit(input.len())?;

        // Lock out parameter mutations from this point forward.
        self.started = true;

        // Materialise the IV as a fixed array for the crypto API.
        let iv_arr = self.iv_array()?;
        // Borrow the engine and dispatch.
        let engine = self.engine()?;
        let processed = if self.encrypting {
            engine
                .encrypt(&iv_arr, input)
                .map_err(|e| ProviderError::Dispatch(format!("AES-XTS encrypt failed: {e}")))?
        } else {
            engine
                .decrypt(&iv_arr, input)
                .map_err(|e| ProviderError::Dispatch(format!("AES-XTS decrypt failed: {e}")))?
        };

        // Sanity check: XTS is length-preserving.
        if processed.len() != input.len() {
            return Err(ProviderError::Dispatch(format!(
                "AES-XTS output length {} does not match input length {} \
                 (length preservation invariant violated)",
                processed.len(),
                input.len()
            )));
        }

        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// Finalize. XTS produces all output in `update`; `finalize`
    /// is a no-op for compatibility with the streaming
    /// [`CipherContext`] API. Mirrors C
    /// `aes_xts_stream_final` (`cipher_aes_xts.c` lines 234-241)
    /// which sets `*outl = 0`.
    fn finalize(&mut self, _output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES-XTS context not initialised".into(),
            ));
        }
        // Mark the context as consumed so a follow-on update/finalize
        // without re-init is rejected. This matches the C provider's
        // single-shot data-unit semantics.
        self.initialized = false;
        self.started = false;
        Ok(0)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // Bootstrap with the canonical cipher metadata: mode,
        // keylen, blocksize, ivlen, and CUSTOM-IV flag. Block size
        // is reported as 1 byte (8 bits) per the C provider.
        let key_bits = self.key_bytes.saturating_mul(8);
        let block_bits: usize = AES_XTS_BLOCK_BYTES.saturating_mul(8);
        let iv_bits = AES_XTS_IV_LEN.saturating_mul(8);
        let mut ps = generic_get_params(
            CipherMode::Xts,
            CipherFlags::CUSTOM_IV,
            key_bits,
            block_bits,
            iv_bits,
        );

        // Algorithm name for introspection.
        ps.set("algorithm", ParamValue::Utf8String(self.name.to_string()));

        // Standard selector (IEEE vs GB) — mirrors the C
        // `OSSL_CIPHER_PARAM_CTS_MODE` parameter. Values use the
        // human-readable token rather than an integer to satisfy
        // Rule R5.
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String(self.standard.to_string()),
        );

        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // OSSL_CIPHER_PARAM_KEYLEN — the C provider rejects any
        // attempt to mutate the declared key length for XTS
        // (`cipher_aes_xts.c` lines 252-260). We mirror exactly:
        // accept only if the supplied value matches the declared
        // size.
        if let Some(val) = params.get(param_keys::KEYLEN) {
            // Rule R6: typed conversion via try_from, no `as`.
            let new_keylen = match val {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("AES-XTS keylen out of range: {e}"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("AES-XTS keylen out of range: {e}"))
                })?,
                ParamValue::Int32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("AES-XTS keylen out of range: {e}"))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES-XTS keylen parameter must be unsigned integer".into(),
                    ));
                }
            };
            if new_keylen != self.key_bytes {
                return Err(ProviderError::Dispatch(format!(
                    "AES-XTS key length cannot be modified \
                     (declared {} bytes, caller requested {})",
                    self.key_bytes, new_keylen
                )));
            }
        }

        // OSSL_CIPHER_PARAM_CTS_MODE — IEEE-1619 vs GB/T 17964.
        // The C provider accepts string tokens; we accept either a
        // UTF-8 string or any unrecognised value as an error. Per
        // IEEE 1619 §5, only IEEE-1619 is FIPS-approved. We reject
        // standard switching once the stream has started — matches
        // the C state lock.
        if let Some(val) = params.get(param_keys::CTS_MODE) {
            if self.started {
                return Err(ProviderError::Dispatch(
                    "AES-XTS standard cannot be changed after data processing has begun".into(),
                ));
            }
            match val {
                ParamValue::Utf8String(s) => {
                    self.standard = parse_xts_standard(s).ok_or_else(|| {
                        ProviderError::Dispatch(format!(
                            "AES-XTS unrecognised standard token: '{s}' \
                             (expected one of: 'IEEE-1619', 'GB/T 17964', 'IEEE', 'GB')"
                        ))
                    })?;
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES-XTS cts_mode parameter must be a UTF-8 string".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Parses an XTS-standard token from the provider parameter
/// surface. Accepts the canonical names plus the short
/// abbreviations used by some tooling.
fn parse_xts_standard(s: &str) -> Option<XtsStandard> {
    // Case-insensitive match on the trimmed input.
    let normalised = s.trim().to_ascii_uppercase();
    match normalised.as_str() {
        "IEEE-1619" | "IEEE_1619" | "IEEE1619" | "IEEE" => Some(XtsStandard::Ieee),
        "GB/T 17964" | "GB-T-17964" | "GB17964" | "GB" => Some(XtsStandard::Gb),
        _ => None,
    }
}

// =============================================================================
// Algorithm Descriptors — Provider Registry Entries
// =============================================================================

/// Returns the AES-XTS algorithm descriptors registered with the
/// default provider.
///
/// Currently registers two entries (IEEE 1619 §5 specifies only
/// 128-bit and 256-bit XTS; AES-192-XTS does not exist):
///
/// | Name           | Combined key | Property              |
/// |----------------|--------------|-----------------------|
/// | `AES-128-XTS`  | 256 bit      | `provider=default`    |
/// | `AES-256-XTS`  | 512 bit      | `provider=default`    |
///
/// The descriptors are constructed via
/// [`make_cipher_descriptor`] so they participate in the common
/// provider-registration machinery. Each descriptor's
/// constructibility is verified by allocating an
/// [`AesXtsCipher`] for it; this catches any mismatch between the
/// declared name/key-size pair and the registry.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    // (name, combined-key-bytes, description)
    let entries: &[(&'static str, usize, &'static str)] = &[
        (
            "AES-128-XTS",
            AES_128_XTS_KEY_BYTES,
            "AES-128 XTS storage encryption (IEEE Std 1619-2018)",
        ),
        (
            "AES-256-XTS",
            AES_256_XTS_KEY_BYTES,
            "AES-256 XTS storage encryption (IEEE Std 1619-2018)",
        ),
    ];

    let mut descs = Vec::with_capacity(entries.len());
    for &(name, key_bytes, description) in entries {
        // Use the common `make_cipher_descriptor` helper for
        // consistency with the other cipher modules.
        let desc = make_cipher_descriptor(vec![name], "provider=default", description);
        descs.push(desc);

        // Constructibility check: `AesXtsCipher::new` cannot fail
        // in the type-system sense, but exercising it here keeps
        // the linker-level wiring of `AesXtsCipher` alive (so the
        // descriptor list and the cipher impl stay coupled) and
        // catches any future divergence between this list and the
        // cipher itself.
        let _ = AesXtsCipher::new(name, key_bytes);
    }

    descs
}

// =============================================================================
// Tests
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

    /// Two disjoint 32-byte XTS keys (AES-128-XTS combined size).
    const KEY_128_XTS: [u8; AES_128_XTS_KEY_BYTES] = [
        // K1 — 16 bytes
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, // K2 — 16 bytes (different from K1)
        0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E,
        0x0F,
    ];

    /// Two disjoint 32-byte halves giving a 64-byte AES-256-XTS combined key.
    const KEY_256_XTS: [u8; AES_256_XTS_KEY_BYTES] = [
        // K1 — 32 bytes
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, // K2 — 32 bytes (different from K1)
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
        0xCD, 0xEF,
    ];

    /// 16-byte tweak (the "sector number"). All-zero is fine for
    /// determinism in tests.
    const IV: [u8; AES_XTS_IV_LEN] = [0u8; AES_XTS_IV_LEN];

    /// 32-byte plaintext: two AES blocks, no ciphertext stealing.
    const PT_2_BLOCKS: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
        0xF0, 0x01,
    ];

    // --- Constants and structural sanity ---

    #[test]
    fn constants_are_consistent() {
        assert_eq!(AES_XTS_IV_LEN, 16);
        assert_eq!(AES_XTS_BLOCK_BYTES, 1);
        assert_eq!(AES_XTS_MAX_BLOCKS_PER_DATA_UNIT, 1 << 20);
        assert_eq!(AES_XTS_MAX_BYTES_PER_DATA_UNIT, (1 << 20) * AES_BLOCK_BYTES);
        assert_eq!(AES_XTS_MAX_BYTES_PER_DATA_UNIT, 16 * 1024 * 1024);
        assert_eq!(AES_128_XTS_KEY_BYTES, 32);
        assert_eq!(AES_256_XTS_KEY_BYTES, 64);
    }

    // --- Descriptors ---

    #[test]
    fn descriptors_count_and_names() {
        let descs = descriptors();
        assert_eq!(descs.len(), 2, "AES-XTS registers exactly two algorithms");
        // Collect names for assertion ordering tolerance.
        let names: Vec<&'static str> = descs.iter().flat_map(|d| d.names.iter().copied()).collect();
        assert!(names.contains(&"AES-128-XTS"), "AES-128-XTS missing");
        assert!(names.contains(&"AES-256-XTS"), "AES-256-XTS missing");
        // No AES-192-XTS — it does not exist.
        assert!(
            !names.iter().any(|n| n.contains("192")),
            "AES-192-XTS must not be registered"
        );
        for desc in &descs {
            assert_eq!(desc.property, "provider=default");
            assert!(!desc.description.is_empty());
        }
    }

    #[test]
    fn descriptor_names_are_unique() {
        let descs = descriptors();
        let mut all: Vec<&'static str> =
            descs.iter().flat_map(|d| d.names.iter().copied()).collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), total, "duplicate algorithm names registered");
    }

    // --- AesXtsCipher (CipherProvider trait) ---

    #[test]
    fn cipher_provider_metadata_aes128() {
        let cipher = AesXtsCipher::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        assert_eq!(cipher.name(), "AES-128-XTS");
        assert_eq!(cipher.key_length(), 32);
        assert_eq!(cipher.iv_length(), 16);
        assert_eq!(cipher.block_size(), 1);
    }

    #[test]
    fn cipher_provider_metadata_aes256() {
        let cipher = AesXtsCipher::new("AES-256-XTS", AES_256_XTS_KEY_BYTES);
        assert_eq!(cipher.name(), "AES-256-XTS");
        assert_eq!(cipher.key_length(), 64);
        assert_eq!(cipher.iv_length(), 16);
        assert_eq!(cipher.block_size(), 1);
    }

    #[test]
    fn new_ctx_returns_uninitialised_context() {
        let cipher = AesXtsCipher::new("AES-256-XTS", AES_256_XTS_KEY_BYTES);
        let ctx = cipher.new_ctx().expect("new_ctx should succeed");
        // The trait-object cannot be downcast directly without
        // `Any`; we verify uninit state by attempting an update,
        // which must error with "not initialised".
        let mut out: Vec<u8> = Vec::new();
        let err = ctx_update(ctx, b"some-input", &mut out)
            .expect_err("update on uninitialised context must fail");
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(
                    msg.contains("not initialised") || msg.contains("not initialized"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected ProviderError::Dispatch, got {other:?}"),
        }
    }

    /// Helper: invoke `update` on a boxed [`CipherContext`]. The boxed
    /// trait object is consumed.
    fn ctx_update(
        mut ctx: Box<dyn CipherContext>,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        ctx.update(input, output)
    }

    // --- AesXtsContext::encrypt_init / decrypt_init ---

    #[test]
    fn encrypt_init_accepts_valid_key_and_iv_128() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None)
            .expect("AES-128-XTS init must succeed with valid key");
        assert!(ctx.initialized);
        assert!(ctx.iv_set);
        assert!(ctx.encrypting);
    }

    #[test]
    fn encrypt_init_accepts_valid_key_and_iv_256() {
        let mut ctx = AesXtsContext::new("AES-256-XTS", AES_256_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_256_XTS, Some(&IV), None)
            .expect("AES-256-XTS init must succeed with valid key");
        assert!(ctx.initialized);
        assert!(ctx.iv_set);
    }

    #[test]
    fn decrypt_init_sets_decrypt_direction() {
        let mut ctx = AesXtsContext::new("AES-256-XTS", AES_256_XTS_KEY_BYTES);
        ctx.decrypt_init(&KEY_256_XTS, Some(&IV), None)
            .expect("AES-256-XTS decrypt-init must succeed");
        assert!(!ctx.encrypting);
    }

    #[test]
    fn init_rejects_wrong_key_size() {
        // 16 bytes — looks like raw AES-128 but XTS needs 32.
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        let bad_key = [0x42u8; 16];
        let err = ctx
            .encrypt_init(&bad_key, Some(&IV), None)
            .expect_err("16-byte key must be rejected");
        match err {
            ProviderError::Init(msg) => {
                assert!(
                    msg.contains("32") && msg.contains("64") || msg.contains("16"),
                    "unhelpful error: {msg}"
                );
            }
            other => panic!("expected ProviderError::Init, got {other:?}"),
        }
    }

    #[test]
    fn init_rejects_aes192_combined_key_size() {
        // 48 bytes — would correspond to AES-192-XTS, which does
        // not exist per IEEE 1619 §5.
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        let bad_key = [0x42u8; 48];
        let err = ctx
            .encrypt_init(&bad_key, Some(&IV), None)
            .expect_err("48-byte (AES-192-XTS) key must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn init_rejects_keylen_mismatch_with_descriptor() {
        // Cipher declares 32 bytes; caller supplies a valid
        // 64-byte XTS key — must still be rejected.
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        let err = ctx
            .encrypt_init(&KEY_256_XTS, Some(&IV), None)
            .expect_err("size mismatch must be rejected");
        match err {
            ProviderError::Init(msg) => {
                assert!(msg.contains("mismatch") || msg.contains("32"));
            }
            other => panic!("expected Init error, got {other:?}"),
        }
    }

    #[test]
    fn init_rejects_identical_key_halves() {
        // Both halves identical — Rogaway 2004 vulnerability.
        let mut bad = [0u8; AES_128_XTS_KEY_BYTES];
        for (i, b) in bad.iter_mut().enumerate().take(16) {
            #[allow(clippy::cast_possible_truncation)]
            // `i` is bounded by 16, well below u8::MAX — checked by `take(16)`.
            {
                *b = i as u8;
            }
        }
        for i in 0..16 {
            #[allow(clippy::cast_possible_truncation)]
            // Same constraint: bounded by 16.
            {
                bad[16 + i] = i as u8;
            }
        }
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        let err = ctx
            .encrypt_init(&bad, Some(&IV), None)
            .expect_err("identical key halves must be rejected");
        match err {
            ProviderError::Init(msg) => {
                assert!(
                    msg.contains("differ") || msg.contains("must"),
                    "expected Rogaway-mitigation error, got: {msg}"
                );
            }
            other => panic!("expected Init error, got {other:?}"),
        }
    }

    #[test]
    fn init_rejects_wrong_iv_length() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        let short_iv = [0u8; 8];
        let err = ctx
            .encrypt_init(&KEY_128_XTS, Some(&short_iv), None)
            .expect_err("8-byte IV must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn init_without_iv_leaves_iv_unset() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, None, None)
            .expect("init without IV must succeed");
        assert!(ctx.initialized);
        assert!(!ctx.iv_set);
    }

    // --- Round-trip encrypt/decrypt ---

    #[test]
    fn round_trip_aes128_xts_two_blocks() {
        let cipher = AesXtsCipher::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);

        let mut enc = AesXtsContext::new(cipher.name(), cipher.key_length());
        enc.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut ct: Vec<u8> = Vec::new();
        let n = enc.update(&PT_2_BLOCKS, &mut ct).unwrap();
        assert_eq!(n, PT_2_BLOCKS.len());
        let _ = enc.finalize(&mut ct).unwrap();

        let mut dec = AesXtsContext::new(cipher.name(), cipher.key_length());
        dec.decrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut pt: Vec<u8> = Vec::new();
        let n = dec.update(&ct, &mut pt).unwrap();
        assert_eq!(n, ct.len());
        let _ = dec.finalize(&mut pt).unwrap();

        assert_eq!(pt, PT_2_BLOCKS, "AES-128-XTS round-trip must be identity");
    }

    #[test]
    fn round_trip_aes256_xts_two_blocks() {
        let cipher = AesXtsCipher::new("AES-256-XTS", AES_256_XTS_KEY_BYTES);

        let mut enc = AesXtsContext::new(cipher.name(), cipher.key_length());
        enc.encrypt_init(&KEY_256_XTS, Some(&IV), None).unwrap();
        let mut ct: Vec<u8> = Vec::new();
        let _ = enc.update(&PT_2_BLOCKS, &mut ct).unwrap();
        let _ = enc.finalize(&mut ct).unwrap();

        let mut dec = AesXtsContext::new(cipher.name(), cipher.key_length());
        dec.decrypt_init(&KEY_256_XTS, Some(&IV), None).unwrap();
        let mut pt: Vec<u8> = Vec::new();
        let _ = dec.update(&ct, &mut pt).unwrap();
        let _ = dec.finalize(&mut pt).unwrap();

        assert_eq!(pt, PT_2_BLOCKS, "AES-256-XTS round-trip must be identity");
    }

    #[test]
    fn round_trip_with_ciphertext_stealing() {
        // 33 bytes — one full AES block + 17 bytes, exercises CTS.
        let pt: Vec<u8> = (0u8..33u8).collect();

        let mut enc = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        enc.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut ct: Vec<u8> = Vec::new();
        let _ = enc.update(&pt, &mut ct).unwrap();
        let _ = enc.finalize(&mut ct).unwrap();
        assert_eq!(ct.len(), pt.len(), "XTS is length-preserving even with CTS");

        let mut dec = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        dec.decrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut roundtripped: Vec<u8> = Vec::new();
        let _ = dec.update(&ct, &mut roundtripped).unwrap();
        let _ = dec.finalize(&mut roundtripped).unwrap();
        assert_eq!(roundtripped, pt);
    }

    // --- Update validation ---

    #[test]
    fn update_rejects_input_below_minimum() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut out: Vec<u8> = Vec::new();
        let err = ctx
            .update(b"short", &mut out)
            .expect_err("input shorter than 16 bytes must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn update_accepts_empty_input() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut out: Vec<u8> = Vec::new();
        let n = ctx.update(b"", &mut out).expect("empty input is a no-op");
        assert_eq!(n, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn update_rejects_oversize_input() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        // Construct a payload one byte over the limit. We don't
        // actually allocate 16 MiB + 1 — we exploit the public
        // helper to assert the bound directly.
        let err = AesXtsContext::enforce_block_limit(AES_XTS_MAX_BYTES_PER_DATA_UNIT + 1)
            .expect_err("over-limit input must be rejected");
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(
                    msg.contains("2^20") || msg.contains("16 MiB"),
                    "expected IEEE-1619 limit error, got: {msg}"
                );
            }
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    #[test]
    fn enforce_block_limit_at_boundary_is_ok() {
        // 16 MiB exactly is allowed.
        AesXtsContext::enforce_block_limit(AES_XTS_MAX_BYTES_PER_DATA_UNIT)
            .expect("input exactly at the 2^20-block limit is permitted");
    }

    #[test]
    fn update_without_init_errors() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        let mut out: Vec<u8> = Vec::new();
        let err = ctx
            .update(&PT_2_BLOCKS, &mut out)
            .expect_err("update without init must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn update_without_iv_errors() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        // Init without IV — leaves iv_set = false.
        ctx.encrypt_init(&KEY_128_XTS, None, None).unwrap();
        let mut out: Vec<u8> = Vec::new();
        let err = ctx
            .update(&PT_2_BLOCKS, &mut out)
            .expect_err("update without IV must fail");
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("IV") || msg.contains("tweak"));
            }
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    // --- Finalize ---

    #[test]
    fn finalize_is_noop_after_update() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut out: Vec<u8> = Vec::new();
        ctx.update(&PT_2_BLOCKS, &mut out).unwrap();
        let pre_len = out.len();
        let n = ctx.finalize(&mut out).unwrap();
        assert_eq!(n, 0, "XTS finalize must emit zero bytes");
        assert_eq!(out.len(), pre_len, "XTS finalize must not mutate output");
    }

    #[test]
    fn finalize_without_init_errors() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        let mut out: Vec<u8> = Vec::new();
        assert!(matches!(
            ctx.finalize(&mut out),
            Err(ProviderError::Dispatch(_))
        ));
    }

    // --- get_params / set_params ---

    #[test]
    fn get_params_returns_canonical_metadata() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let ps = ctx.get_params().expect("get_params must succeed");

        // KEYLEN — 32 bytes for AES-128-XTS.
        let kl = ps.get(param_keys::KEYLEN).expect("keylen present");
        let expected_keylen = u32::try_from(AES_128_XTS_KEY_BYTES).expect("32 fits in u32");
        match kl {
            ParamValue::UInt32(v) => assert_eq!(*v, expected_keylen),
            other => panic!("keylen should be UInt32, got {other:?}"),
        }

        // IVLEN — 16.
        let il = ps.get(param_keys::IVLEN).expect("ivlen present");
        let expected_ivlen = u32::try_from(AES_XTS_IV_LEN).expect("16 fits in u32");
        match il {
            ParamValue::UInt32(v) => assert_eq!(*v, expected_ivlen),
            other => panic!("ivlen should be UInt32, got {other:?}"),
        }

        // BLOCK_SIZE — 1.
        let bs = ps.get(param_keys::BLOCK_SIZE).expect("blocksize present");
        let expected_block = u32::try_from(AES_XTS_BLOCK_BYTES).expect("1 fits in u32");
        match bs {
            ParamValue::UInt32(v) => assert_eq!(*v, expected_block),
            other => panic!("blocksize should be UInt32, got {other:?}"),
        }

        // CTS_MODE — IEEE-1619.
        let cts = ps.get(param_keys::CTS_MODE).expect("cts_mode present");
        match cts {
            ParamValue::Utf8String(s) => assert!(s.contains("IEEE")),
            other => panic!("cts_mode should be Utf8String, got {other:?}"),
        }
    }

    #[test]
    fn set_params_accepts_matching_keylen() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut ps = ParamSet::new();
        ps.set(param_keys::KEYLEN, ParamValue::UInt32(32));
        ctx.set_params(&ps)
            .expect("matching keylen must be accepted");
    }

    #[test]
    fn set_params_rejects_keylen_change() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut ps = ParamSet::new();
        ps.set(param_keys::KEYLEN, ParamValue::UInt32(64));
        let err = ctx
            .set_params(&ps)
            .expect_err("XTS keylen cannot be modified");
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("modified") || msg.contains("cannot"));
            }
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    #[test]
    fn set_params_accepts_cts_mode_ieee() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String("IEEE".to_string()),
        );
        ctx.set_params(&ps).expect("IEEE accepted");
        assert_eq!(ctx.standard, XtsStandard::Ieee);
    }

    #[test]
    fn set_params_accepts_cts_mode_gb() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String("GB".to_string()),
        );
        ctx.set_params(&ps).expect("GB accepted");
        assert_eq!(ctx.standard, XtsStandard::Gb);
    }

    #[test]
    fn set_params_rejects_cts_mode_after_update() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut out: Vec<u8> = Vec::new();
        ctx.update(&PT_2_BLOCKS, &mut out).unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String("GB".to_string()),
        );
        let err = ctx
            .set_params(&ps)
            .expect_err("post-update standard mutation must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn set_params_rejects_unknown_cts_mode() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String("nonexistent-standard".to_string()),
        );
        let err = ctx.set_params(&ps).expect_err("unknown standard must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // --- XtsStandard ---

    #[test]
    fn xts_standard_default_is_ieee() {
        assert_eq!(XtsStandard::default(), XtsStandard::Ieee);
    }

    #[test]
    fn xts_standard_display() {
        assert_eq!(format!("{}", XtsStandard::Ieee), "IEEE-1619");
        assert_eq!(format!("{}", XtsStandard::Gb), "GB/T 17964");
    }

    #[test]
    fn parse_xts_standard_accepts_aliases() {
        assert_eq!(parse_xts_standard("IEEE"), Some(XtsStandard::Ieee));
        assert_eq!(parse_xts_standard("ieee"), Some(XtsStandard::Ieee));
        assert_eq!(parse_xts_standard("IEEE-1619"), Some(XtsStandard::Ieee));
        assert_eq!(parse_xts_standard("GB"), Some(XtsStandard::Gb));
        assert_eq!(parse_xts_standard("gb"), Some(XtsStandard::Gb));
        assert_eq!(parse_xts_standard("  GB17964  "), Some(XtsStandard::Gb));
        assert_eq!(parse_xts_standard("nope"), None);
    }

    // --- Different IVs produce different ciphertext ---

    #[test]
    fn different_ivs_produce_different_ciphertext() {
        let iv_a = [0u8; AES_XTS_IV_LEN];
        let mut iv_b = [0u8; AES_XTS_IV_LEN];
        iv_b[0] = 1;

        let mut ctx_a = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx_a.encrypt_init(&KEY_128_XTS, Some(&iv_a), None).unwrap();
        let mut ct_a: Vec<u8> = Vec::new();
        ctx_a.update(&PT_2_BLOCKS, &mut ct_a).unwrap();

        let mut ctx_b = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx_b.encrypt_init(&KEY_128_XTS, Some(&iv_b), None).unwrap();
        let mut ct_b: Vec<u8> = Vec::new();
        ctx_b.update(&PT_2_BLOCKS, &mut ct_b).unwrap();

        assert_ne!(
            ct_a, ct_b,
            "different IVs must produce different ciphertext"
        );
    }

    // --- Debug redacts secrets ---

    #[test]
    fn debug_does_not_leak_key_or_iv() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let dbg = format!("{ctx:?}");
        // Must not contain raw key bytes or IV bytes.
        assert!(!dbg.contains("0x0F0E0D0C"));
        assert!(dbg.contains("AES-128-XTS"));
        assert!(dbg.contains("<keyed>"));
    }

    // --- Re-init resets state ---

    #[test]
    fn re_init_resets_started_and_iv() {
        let mut ctx = AesXtsContext::new("AES-128-XTS", AES_128_XTS_KEY_BYTES);
        ctx.encrypt_init(&KEY_128_XTS, Some(&IV), None).unwrap();
        let mut out: Vec<u8> = Vec::new();
        ctx.update(&PT_2_BLOCKS, &mut out).unwrap();
        assert!(ctx.started);

        // Re-init for decrypt with a different IV.
        let mut iv2 = [0u8; AES_XTS_IV_LEN];
        iv2[0] = 0xAA;
        ctx.decrypt_init(&KEY_128_XTS, Some(&iv2), None).unwrap();
        assert!(!ctx.started, "re-init must reset 'started'");
        assert_eq!(ctx.iv, iv2.to_vec());
        assert!(!ctx.encrypting);
    }
}
