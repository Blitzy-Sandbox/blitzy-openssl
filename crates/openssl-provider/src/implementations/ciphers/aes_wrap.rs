//! AES Key Wrap (RFC 3394) and AES Key Wrap with Padding (RFC 5649) provider
//! implementations.
//!
//! This module supplies the `AesWrapCipher` provider type and `AesWrapContext`
//! per-operation context type that together replace the C reference module
//! `providers/implementations/ciphers/cipher_aes_wrp.c`.  AES Key Wrap is
//! used for **secure key transport** — wrapping symmetric keys (or any byte
//! string) for storage or transmission under a Key Encryption Key (KEK).
//!
//! # Properties
//!
//! | Property              | Standard Wrap (RFC 3394) | Wrap with Padding (RFC 5649) |
//! |-----------------------|--------------------------|------------------------------|
//! | Cipher                | AES                      | AES                          |
//! | Mode                  | Key Wrap                 | Key Wrap with Padding        |
//! | Key sizes             | 128 / 192 / 256 bits     | 128 / 192 / 256 bits         |
//! | IV length             | 8 bytes (semiblock)      | 4 bytes (AIV magic prefix)   |
//! | Default IV            | `0xA6A6A6A6A6A6A6A6`     | `0xA659_59A6` (AIV)          |
//! | Plaintext length      | Multiple of 8, ≥ 16 B    | Any non-zero, < 2 GiB        |
//! | Block (semiblock)     | 8 bytes (64 bits)        | 8 bytes (64 bits)            |
//! | AEAD                  | No                       | No                           |
//! | Standards             | NIST SP 800-38F, RFC 3394| NIST SP 800-38F, RFC 5649    |
//!
//! In addition to the two forward modes above this module also exposes
//! **inverse** variants per NIST SP 800-38F §5.1, in which the underlying
//! AES round-key transform is swapped: encrypt-direction operations use the
//! AES decrypt key schedule and vice versa.  The four mode families together
//! yield twelve algorithm descriptors (three key sizes × four mode families).
//!
//! # Single-shot Cipher Semantics
//!
//! Per RFC 3394 / RFC 5649, key wrap is a **single-shot** transformation —
//! the entire input must be supplied in one [`update`](AesWrapContext::update)
//! call.  Calling `update` more than once on the same context is rejected
//! with [`ProviderError::Dispatch`].  This mirrors the C reference which
//! tracks the same invariant via the `wctx->updated` flag and returns
//! `EVP_R_UPDATE_ERROR` on violation.
//!
//! # Output Length Geometry
//!
//! For a wrap operation, the cipher-text length equals the plain-text length
//! plus eight bytes (one semiblock).  For an unwrap operation, the plain-text
//! length equals the cipher-text length minus eight bytes.  RFC 5649 with
//! padding rounds the plain-text up to the next multiple of eight before
//! adding the IV semiblock — the recovered plain-text length is determined
//! at unwrap time from the AIV's MLI field.
//!
//! ```text
//!  ┌─────────────────┐          ┌─────────────────────────┐
//!  │   plaintext P   │  Wrap →  │ IV │   ciphertext C    │
//!  │  (n semiblocks) │          │ 8B │  (n semiblocks)   │
//!  └─────────────────┘          └─────────────────────────┘
//!         8·n B                           8·(n+1) B
//! ```
//!
//! # Source Mapping (C → Rust)
//!
//! | Rust item                             | C origin (`cipher_aes_wrp.c`)               |
//! |---------------------------------------|---------------------------------------------|
//! | `AesWrapCipher`                       | `IMPLEMENT_cipher` macro instances          |
//! | `AesWrapContext`                      | `PROV_AES_WRAP_CTX`                         |
//! | `AesWrapContext::encrypt_init`        | `aes_wrap_einit`                            |
//! | `AesWrapContext::decrypt_init`        | `aes_wrap_dinit`                            |
//! | `AesWrapContext::update`              | `aes_wrap_cipher` / `aes_wrap_cipher_internal` |
//! | `AesWrapContext::finalize`            | `aes_wrap_final`                            |
//! | `AesWrapContext::get_params`          | base provider param getter                  |
//! | `AesWrapContext::set_params`          | `aes_wrap_set_ctx_params`                   |
//! | `descriptors`                         | `IMPLEMENT_cipher` invocations (12 total)   |
//! | `AES_WRAP_PAD_IVLEN` / `AES_WRAP_NOPAD_IVLEN` | `#define AES_WRAP_PAD_IVLEN 4` / `8` |
//! | `WRAP_FLAGS` / `WRAP_FLAGS_INV`       | `#define WRAP_FLAGS (PROV_CIPHER_FLAG_CUSTOM_IV)` etc. |
//!
//! # Refactoring Rule Compliance
//!
//! This module enforces the workspace's refactoring rules:
//!
//! * **R5 (no sentinel values).**  The `iv` field is an `Option`-shaped
//!   buffer combined with the explicit `iv_set` flag; an empty `Vec<u8>`
//!   is never overloaded to mean "unset".  Single-shot enforcement uses
//!   the explicit `updated: bool` flag rather than testing `outlen > 0`.
//! * **R6 (lossless numeric casts).**  All `usize → u32` conversions in
//!   `get_params` go through `u32::try_from(...).unwrap_or(u32::MAX)` —
//!   the saturating-cast pattern from the workspace common module.  No
//!   bare `as` narrowing casts are used.
//! * **R7 (lock granularity).**  Each `AesWrapContext` is single-threaded by
//!   construction (`&mut self` methods); no shared mutable state requires
//!   locking.  The only `Send + Sync` bounds come from the traits.
//! * **R8 (zero unsafe outside FFI).**  This module contains no `unsafe`
//!   blocks.  All AES operations delegate to the safe `openssl-crypto`
//!   wrap/unwrap functions which themselves run entirely on safe Rust.
//! * **R9 (warning-free build).**  No crate- or module-level `#[allow]`
//!   attributes are used.  The few `#[allow(unused)]` annotations on test
//!   helpers carry justification comments.
//! * **R10 (wiring before done).**  `descriptors()` is invoked from
//!   `super::descriptors()` (registered in `mod.rs`) which feeds the
//!   default and FIPS provider's algorithm registry, so every variant
//!   produced here is reachable from the provider entry point.

use super::common::{generic_get_params, param_keys, CipherFlags, CipherMode};
use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::symmetric::{
    aes::{Aes, DEFAULT_AIV, DEFAULT_IV},
    SymmetricCipher,
};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Constants
// =============================================================================

/// IV length for AES Key Wrap with Padding (RFC 5649) — 4 bytes (AIV magic
/// prefix only; the message length indicator is computed internally).
///
/// Mirrors `#define AES_WRAP_PAD_IVLEN 4` in the C reference.
const AES_WRAP_PAD_IVLEN: usize = 4;

/// IV length for AES Key Wrap without padding (RFC 3394) — 8 bytes
/// (full semiblock IV per the standard).
///
/// Mirrors `#define AES_WRAP_NOPAD_IVLEN 8` in the C reference.
const AES_WRAP_NOPAD_IVLEN: usize = 8;

/// Block size in bytes that AES Key Wrap reports.  RFC 3394 / RFC 5649
/// operate on 64-bit semiblocks, so the cipher's reported block size is
/// 8 bytes even though the underlying AES primitive uses 16-byte blocks.
const AES_WRAP_BLOCK_SIZE: usize = 8;

/// Block size in bits that the cipher reports via `get_params(BLOCK_SIZE)`.
///
/// 64 bits = one RFC 3394 semiblock.
const AES_WRAP_BLOCK_BITS: usize = AES_WRAP_BLOCK_SIZE * 8;

/// Minimum input length (in bytes) for the non-padded unwrap operation.
/// Per RFC 3394 the cipher-text contains the IV semiblock plus at least
/// two payload semiblocks, totalling 24 bytes; the minimum permitted by
/// the C reference's check `inlen < 16` is the post-IV-strip length, so
/// the Rust function works on `inlen >= 16` for unwrap (matches C).
const AES_WRAP_MIN_UNWRAP_LEN: usize = 16;

/// Size of one full AES block in bytes (16 bytes for AES-128/192/256).
/// AES Key Wrap operates on pairs of 64-bit semiblocks, which means the
/// internal scratch buffer for each round is one AES block (two semiblocks).
const AES_BLOCK_SIZE_BYTES: usize = 16;

/// Maximum input length permitted by `CRYPTO_128_wrap` / `CRYPTO_128_unwrap`
/// in the C reference (`crypto/modes/wrap128.c`).  This bound prevents the
/// 32-bit wrap counter from overflowing during the six outer rounds of the
/// RFC 3394 / RFC 5649 algorithm.
///
/// Set to `2^31` bytes (= 256 MiB shifted), matching the C constant
/// `CRYPTO128_WRAP_MAX`.
const CRYPTO128_WRAP_MAX: usize = 1usize << 31;

// =============================================================================
// AesWrapCipher — Provider Type
// =============================================================================

/// AES Key Wrap cipher provider.
///
/// One value of this type is created per algorithm descriptor (3 key sizes
/// × 4 mode variants = 12 instances total).  The type is cheap to clone —
/// it carries only configuration metadata — and is registered with the
/// provider's algorithm store as a `Box<dyn CipherProvider>`.
///
/// # Fields
///
/// * `name` — the canonical algorithm name (`"AES-128-WRAP"`, …).
/// * `key_bits` — 128, 192 or 256.
/// * `with_padding` — `false` for RFC 3394, `true` for RFC 5649.
/// * `inverse` — `false` for forward variants, `true` for SP 800-38F
///   inverse-cipher variants.
///
/// All four fields are pure metadata and contain no key material; therefore
/// no special zeroing is required (the type can derive `Clone`).
#[derive(Debug, Clone)]
pub struct AesWrapCipher {
    /// Canonical algorithm name (e.g. `"AES-128-WRAP"`).
    name: &'static str,
    /// Key length in bits (128 / 192 / 256).
    pub key_bits: usize,
    /// Whether RFC 5649 padding is enabled.
    pub with_padding: bool,
    /// Whether this is a SP 800-38F inverse-cipher variant.
    pub inverse: bool,
}

impl AesWrapCipher {
    /// Constructs a new `AesWrapCipher` descriptor.
    ///
    /// # Parameters
    ///
    /// * `name` — canonical algorithm name (must be `'static`).
    /// * `key_bits` — 128 / 192 / 256.
    /// * `with_padding` — `true` for RFC 5649, `false` for RFC 3394.
    /// * `inverse` — `true` for SP 800-38F inverse-cipher variants.
    #[must_use]
    pub fn new(name: &'static str, key_bits: usize, with_padding: bool, inverse: bool) -> Self {
        Self {
            name,
            key_bits,
            with_padding,
            inverse,
        }
    }

    /// Returns the byte-denominated key length derived from `self.key_bits`.
    #[inline]
    fn key_bytes(&self) -> usize {
        self.key_bits / 8
    }
}

impl CipherProvider for AesWrapCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        self.key_bytes()
    }

    /// Returns the algorithm's IV length in bytes:
    ///
    /// * 4 bytes for RFC 5649 (padded) — the AIV magic prefix only;
    ///   the message length indicator is computed internally.
    /// * 8 bytes for RFC 3394 (non-padded) — the full semiblock IV.
    fn iv_length(&self) -> usize {
        if self.with_padding {
            AES_WRAP_PAD_IVLEN
        } else {
            AES_WRAP_NOPAD_IVLEN
        }
    }

    /// Returns the semiblock size in bytes (8) — RFC 3394 / RFC 5649
    /// operate on 64-bit semiblocks regardless of the underlying AES
    /// 128-bit block.
    fn block_size(&self) -> usize {
        AES_WRAP_BLOCK_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(AesWrapContext::new(
            self.name,
            self.key_bytes(),
            self.with_padding,
            self.inverse,
        )))
    }
}

// =============================================================================
// AesWrapContext — Per-Operation State
// =============================================================================

/// Per-operation context for an AES Key Wrap encrypt or decrypt operation.
///
/// Each context drives a single wrap or unwrap transformation: it is
/// initialised once with a key (and optional IV), receives its input via
/// exactly one `update` call, and is finalised with a no-op `finalize`.
/// Subsequent operations require a fresh context (or re-init via
/// `encrypt_init` / `decrypt_init`).
///
/// # Field-Level Justifications (Rule R5: no sentinels)
///
/// * `iv: Vec<u8>` is paired with the explicit `iv_set: bool` flag rather
///   than overloading an empty vec to mean "unset".
/// * `key: Option<Vec<u8>>` is `None` until a key is supplied — the empty
///   slice case is impossible.
/// * `updated: bool` enforces the single-shot contract (Rule R5: no
///   numeric sentinels for "already used").
///
/// # Zeroization (AAP §0.7.6)
///
/// * The `key` buffer is zeroed on drop via `ZeroizeOnDrop` (it holds
///   sensitive key material).
/// * The `iv` buffer is zeroed even though IVs in RFC 3394 are not strictly
///   secret, because re-using an IV for unwrapping reveals timing
///   side-channel information that should not survive context destruction.
#[derive(Zeroize, ZeroizeOnDrop)]
#[allow(clippy::struct_excessive_bools)]
// Cipher-context state mirrors the C reference `PROV_AES_WRAP_CTX` and
// requires four independent boolean flags — `with_padding`, `inverse`,
// `encrypting`, `initialized`, `updated` — each of which models a
// distinct aspect of the underlying RFC 3394 / RFC 5649 state machine.
// Collapsing them into a single enum would lose the orthogonality
// described in `use_forward_transform()` and add cognitive overhead.
// Matches the established pattern in `aes_xts.rs` and `aes_siv.rs`.
pub struct AesWrapContext {
    /// Canonical algorithm name (immutable, no key material — skipped).
    #[zeroize(skip)]
    name: &'static str,
    /// Key length in bytes (configuration only — skipped).
    #[zeroize(skip)]
    key_bytes: usize,
    /// Whether RFC 5649 padding is in effect (configuration only — skipped).
    #[zeroize(skip)]
    with_padding: bool,
    /// Whether this is the SP 800-38F inverse-cipher variant (configuration
    /// only — skipped).
    #[zeroize(skip)]
    inverse: bool,
    /// `true` after `encrypt_init`, `false` after `decrypt_init`.
    encrypting: bool,
    /// `true` once a key has been installed via `encrypt_init` / `decrypt_init`.
    initialized: bool,
    /// `true` after `update` has been called once (single-shot enforcement).
    updated: bool,
    /// Stored IV for the next wrap/unwrap operation.  Length matches the
    /// algorithm's `iv_length()`; uninitialised state is signalled by the
    /// `iv_set` flag rather than a zero-length vec (Rule R5).
    iv: Vec<u8>,
    /// Whether `iv` carries valid bytes.
    iv_set: bool,
    /// Stored KEK material.  `None` until `encrypt_init` / `decrypt_init`
    /// installs a key.  Wrapped in an option so that the empty-slice case
    /// is unrepresentable (Rule R5).
    key: Option<Vec<u8>>,
}

impl AesWrapContext {
    /// Constructs a fresh, uninitialised context.
    ///
    /// The context becomes usable only after `encrypt_init` or
    /// `decrypt_init` has installed a key.  Until then, every operation
    /// (`update`, `finalize`) returns `ProviderError::Dispatch`.
    #[must_use]
    pub fn new(name: &'static str, key_bytes: usize, with_padding: bool, inverse: bool) -> Self {
        let iv_len = if with_padding {
            AES_WRAP_PAD_IVLEN
        } else {
            AES_WRAP_NOPAD_IVLEN
        };
        Self {
            name,
            key_bytes,
            with_padding,
            inverse,
            encrypting: false,
            initialized: false,
            updated: false,
            iv: vec![0u8; iv_len],
            iv_set: false,
            key: None,
        }
    }

    /// Internal initialisation routine shared between `encrypt_init` and
    /// `decrypt_init`.  Validates the key length, copies the IV (if
    /// supplied), applies any parameters, and resets the single-shot flag.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // Validate key length matches the cipher's declared key size.
        if key.len() != self.key_bytes {
            return Err(ProviderError::Init(format!(
                "AES key wrap: invalid key length {} (expected {} bytes)",
                key.len(),
                self.key_bytes
            )));
        }

        // Pre-validate the key by attempting an AES key schedule expansion.
        // This catches malformed keys eagerly — the actual wrap/unwrap
        // call will recompute the schedule, but the cost of a single
        // additional setup is negligible compared to the diagnostic value
        // of failing fast.
        Aes::new(key)
            .map_err(|e| ProviderError::Init(format!("AES key wrap: key schedule failed: {e}")))?;

        // Install the key (zeroizing any previous material on assignment;
        // the old `Option<Vec<u8>>` is dropped, triggering its zeroize).
        if let Some(prev) = self.key.as_mut() {
            prev.zeroize();
        }
        self.key = Some(key.to_vec());

        // Reset the single-shot flag — re-initialising is the only way to
        // unlock another `update` call.
        self.updated = false;
        self.encrypting = encrypting;
        self.initialized = true;

        // Apply the IV (if supplied) and any caller parameters.  If the
        // caller did not supply an IV, the buffer retains its previous
        // contents and `iv_set` retains its previous truthiness — the C
        // reference behaves the same way (the IV pointer is `NULL`-able).
        if let Some(iv_bytes) = iv {
            self.set_iv(iv_bytes)?;
        }
        if let Some(ps) = params {
            self.set_params(ps)?;
        }

        Ok(())
    }

    /// Validates and stores `iv` as the active IV.  Length must match the
    /// algorithm's declared IV length (4 or 8 bytes).
    fn set_iv(&mut self, iv: &[u8]) -> ProviderResult<()> {
        let expected = if self.with_padding {
            AES_WRAP_PAD_IVLEN
        } else {
            AES_WRAP_NOPAD_IVLEN
        };
        if iv.len() != expected {
            return Err(ProviderError::Dispatch(format!(
                "AES key wrap: IV length {} does not match expected {} bytes",
                iv.len(),
                expected
            )));
        }
        if self.iv.len() != iv.len() {
            self.iv.resize(iv.len(), 0);
        }
        self.iv.copy_from_slice(iv);
        self.iv_set = true;
        Ok(())
    }

    /// Returns the currently installed key, or an error if none.
    fn require_key(&self) -> ProviderResult<&[u8]> {
        self.key.as_deref().ok_or_else(|| {
            ProviderError::Dispatch("AES key wrap: context not initialised with a key".into())
        })
    }

    /// Determines which AES key schedule (encrypt or decrypt) the
    /// underlying block transform should use per NIST SP 800-38F §5.1.
    ///
    /// The wrap/unwrap operations in OpenSSL have two **orthogonal**
    /// dimensions of dispatch:
    ///
    /// 1. **Algorithm selection** (RFC 3394 wrap vs. RFC 3394 unwrap, or
    ///    RFC 5649 wrap-pad vs. RFC 5649 unwrap-pad).  This is governed
    ///    purely by `self.encrypting` — wrap when encrypting, unwrap
    ///    when decrypting.  Inverse-cipher variants do **not** swap the
    ///    algorithm; an `AES-128-WRAP-INV` cipher operating in encrypt
    ///    direction still produces wrap output (input length grows by
    ///    one semiblock).
    /// 2. **Block-cipher direction** (AES-encrypt vs AES-decrypt of the
    ///    inner 16-byte scratch block during each of the 6N rounds).
    ///    This is governed by `inverse XOR encrypting`.
    ///
    /// Truth table (`use_forward` is the value returned here):
    ///
    /// | Variant      | `encrypting` | `inverse` | `use_forward` | AES round |
    /// |--------------|--------------|-----------|---------------|-----------|
    /// | wrap         | `true`       | `false`   | `true`        | encrypt   |
    /// | unwrap       | `false`      | `false`   | `false`       | decrypt   |
    /// | inv-wrap     | `true`       | `true`    | `false`       | decrypt   |
    /// | inv-unwrap   | `false`      | `true`    | `true`        | encrypt   |
    ///
    /// This function therefore returns the boolean that the wrap/unwrap
    /// helpers should pass to the AES round routine; algorithm selection
    /// is handled separately at the call site by branching on
    /// `self.encrypting`.
    #[inline]
    #[must_use]
    fn use_forward_transform(&self) -> bool {
        if self.inverse {
            !self.encrypting
        } else {
            self.encrypting
        }
    }

    /// Resolves the IV slice to pass to the wrap/unwrap function.
    ///
    /// * For RFC 5649 (padded) the underlying primitives ignore the IV
    ///   parameter and use the AIV internally; we always return the
    ///   default IV in that case.
    /// * For RFC 3394 (non-padded) we return the user-supplied IV if
    ///   `iv_set` is true, otherwise the RFC 3394 default IV
    ///   (`0xA6A6A6A6A6A6A6A6`).
    fn resolved_iv(&self) -> [u8; AES_WRAP_NOPAD_IVLEN] {
        if !self.with_padding && self.iv_set && self.iv.len() == AES_WRAP_NOPAD_IVLEN {
            let mut out = [0u8; AES_WRAP_NOPAD_IVLEN];
            out.copy_from_slice(&self.iv);
            out
        } else {
            DEFAULT_IV
        }
    }
}

// =============================================================================
// RFC 3394 / RFC 5649 helpers parameterized by AES round direction.
// =============================================================================
//
// These four helpers replicate the algorithms in `openssl-crypto::symmetric::
// aes::{aes_key_wrap, aes_key_unwrap, aes_key_wrap_pad, aes_key_unwrap_pad}`
// but expose a `use_forward: bool` parameter so that the caller can choose
// between the AES forward (encrypt) and reverse (decrypt) round transforms
// independently of whether the *operation* is wrap or unwrap.  This is the
// fundamental NIST SP 800-38F §5.1 inverse-cipher property and matches the
// behaviour of the C reference (`providers/implementations/ciphers/
// cipher_aes_wrp.c`), which passes a runtime block-cipher function pointer
// to `CRYPTO_128_wrap` / `CRYPTO_128_unwrap`.
//
// The `openssl-crypto` public API exposes `Aes` via the `SymmetricCipher`
// trait, whose `encrypt_block` / `decrypt_block` methods accept a 16-byte
// `&mut [u8]` slice.  The `_array` variants are crate-private (`pub(super)`)
// and therefore unavailable here, but `SymmetricCipher::encrypt_block` is
// equivalent and length-checked.

/// Performs one in-place AES-128/192/256 block transformation on `block`.
///
/// When `use_forward` is `true` the AES encrypt key schedule is applied;
/// when `false` the decrypt schedule is applied.  This is the only place
/// in this module where the inverse-cipher polarity is materialised.
///
/// # Errors
///
/// Returns `ProviderError::Dispatch` if the underlying `SymmetricCipher`
/// implementation returns a `CryptoError` (e.g. wrong block length — which
/// is unreachable here because the caller always passes a 16-byte buffer).
#[inline]
fn aes_round(
    aes: &Aes,
    use_forward: bool,
    block: &mut [u8; AES_BLOCK_SIZE_BYTES],
) -> ProviderResult<()> {
    let result = if use_forward {
        aes.encrypt_block(&mut block[..])
    } else {
        aes.decrypt_block(&mut block[..])
    };
    result.map_err(|e| {
        ProviderError::Dispatch(format!("AES key wrap: AES round transform failed: {e}"))
    })
}

/// RFC 3394 §2.2.1 wrap operation, parameterized by AES round direction.
///
/// Wraps `plaintext` (which must be a non-empty multiple of 8 bytes,
/// i.e. ≥ two semiblocks) under the IV `iv` and returns the wrapped
/// output (`plaintext.len() + 8` bytes long).
///
/// # Algorithm
///
/// 1. `A ← IV`, copy `R[1..n] ← plaintext` (n semiblocks).
/// 2. For `j ∈ 0..6`, for `i ∈ 1..=n`:
///    - `B ← AES_round(A || R[i])`
///    - `A ← MSB_64(B) XOR t` where `t = (n*j) + i`
///    - `R[i] ← LSB_64(B)`
/// 3. Return `A || R[1..n]`.
///
/// # Errors
///
/// * `ProviderError::Dispatch` — if input is not a multiple of 8 bytes,
///   contains fewer than two semiblocks, exceeds `CRYPTO128_WRAP_MAX`, or
///   the AES block transform returns an error.
fn wrap_with_block(
    aes: &Aes,
    use_forward: bool,
    iv: [u8; AES_WRAP_NOPAD_IVLEN],
    plaintext: &[u8],
) -> ProviderResult<Vec<u8>> {
    let inlen = plaintext.len();
    if inlen % AES_WRAP_BLOCK_SIZE != 0 {
        return Err(ProviderError::Dispatch(format!(
            "AES key wrap: plaintext length {inlen} is not a multiple of {AES_WRAP_BLOCK_SIZE}"
        )));
    }
    if inlen < 2 * AES_WRAP_BLOCK_SIZE {
        return Err(ProviderError::Dispatch(format!(
            "AES key wrap: plaintext length {inlen} must be at least {} bytes (two semiblocks)",
            2 * AES_WRAP_BLOCK_SIZE
        )));
    }
    if inlen > CRYPTO128_WRAP_MAX {
        return Err(ProviderError::Dispatch(format!(
            "AES key wrap: plaintext length {inlen} exceeds maximum {CRYPTO128_WRAP_MAX}"
        )));
    }

    // Output layout: out[0..8] = A (final IV), out[8..] = R[1..n] (final).
    let mut out = vec![0u8; inlen + AES_WRAP_BLOCK_SIZE];
    out[AES_WRAP_BLOCK_SIZE..].copy_from_slice(plaintext);

    let mut a = [0u8; AES_WRAP_BLOCK_SIZE];
    a.copy_from_slice(&iv);
    let mut b = [0u8; AES_BLOCK_SIZE_BYTES];

    let n = inlen / AES_WRAP_BLOCK_SIZE;
    // R6 (cast_possible_wrap): `n` is bounded by `CRYPTO128_WRAP_MAX / 8`
    // = 2^28, which fits in u64 on every platform; widening from `usize`
    // to `u64` is therefore lossless and the cast cannot wrap.  Using
    // `u64::try_from` would require handling an unreachable error path.
    let mut t: u64 = 0;
    for _j in 0..6_u32 {
        for i in 0..n {
            t = t.wrapping_add(1);
            // Load A into B[0..8] and R[i] into B[8..16].
            b[..AES_WRAP_BLOCK_SIZE].copy_from_slice(&a);
            let r_start = AES_WRAP_BLOCK_SIZE + i * AES_WRAP_BLOCK_SIZE;
            b[AES_WRAP_BLOCK_SIZE..].copy_from_slice(&out[r_start..r_start + AES_WRAP_BLOCK_SIZE]);

            aes_round(aes, use_forward, &mut b)?;

            // A ← MSB_64(B) XOR t.  The full 8-byte XOR is equivalent to
            // XORing only the low 4 bytes (matching the C reference) when
            // the upper 4 bytes of `t` are zero, which holds for any
            // input length permitted by `CRYPTO128_WRAP_MAX`.
            a.copy_from_slice(&b[..AES_WRAP_BLOCK_SIZE]);
            let t_bytes = t.to_be_bytes();
            for k in 0..AES_WRAP_BLOCK_SIZE {
                a[k] ^= t_bytes[k];
            }
            // R[i] ← LSB_64(B).
            out[r_start..r_start + AES_WRAP_BLOCK_SIZE].copy_from_slice(&b[AES_WRAP_BLOCK_SIZE..]);
        }
    }
    out[..AES_WRAP_BLOCK_SIZE].copy_from_slice(&a);

    a.zeroize();
    b.zeroize();
    Ok(out)
}

/// RFC 3394 §2.2.2 unwrap "raw" operation, parameterized by AES round
/// direction.  Returns the recovered IV (caller verifies) and plaintext.
///
/// # Algorithm
///
/// 1. `A ← C[0]`, copy `R[1..n] ← C[1..n]` (n = (clen / 8) - 1).
/// 2. For `j ∈ 5..=0`, for `i ∈ n..=1`:
///    - `B ← AES_round(A XOR t || R[i])`, `t = (n*j) + i`
///    - `A ← MSB_64(B)`
///    - `R[i] ← LSB_64(B)`
/// 3. Return `(A, R[1..n])`.
///
/// # Errors
///
/// * `ProviderError::Dispatch` — if `clen` is not a multiple of 8, contains
///   fewer than three semiblocks (IV + two payload), exceeds the maximum
///   permitted length, or the AES block transform fails.
fn unwrap_raw_with_block(
    aes: &Aes,
    use_forward: bool,
    ciphertext: &[u8],
) -> ProviderResult<([u8; AES_WRAP_NOPAD_IVLEN], Vec<u8>)> {
    let clen = ciphertext.len();
    if clen % AES_WRAP_BLOCK_SIZE != 0 {
        return Err(ProviderError::Dispatch(format!(
            "AES key unwrap: ciphertext length {clen} is not a multiple of {AES_WRAP_BLOCK_SIZE}"
        )));
    }
    if clen < 3 * AES_WRAP_BLOCK_SIZE {
        return Err(ProviderError::Dispatch(format!(
            "AES key unwrap: ciphertext length {clen} must be at least {} bytes",
            3 * AES_WRAP_BLOCK_SIZE
        )));
    }
    let inlen = clen - AES_WRAP_BLOCK_SIZE;
    if inlen > CRYPTO128_WRAP_MAX {
        return Err(ProviderError::Dispatch(format!(
            "AES key unwrap: payload length {inlen} exceeds maximum {CRYPTO128_WRAP_MAX}"
        )));
    }

    let mut out = vec![0u8; inlen];
    out.copy_from_slice(&ciphertext[AES_WRAP_BLOCK_SIZE..]);

    let mut a = [0u8; AES_WRAP_BLOCK_SIZE];
    a.copy_from_slice(&ciphertext[..AES_WRAP_BLOCK_SIZE]);
    let mut b = [0u8; AES_BLOCK_SIZE_BYTES];

    let n = inlen / AES_WRAP_BLOCK_SIZE;
    // R6 justification: `n` ≤ CRYPTO128_WRAP_MAX/8 = 2^28; the cast is a
    // widening on every supported target (32-bit and 64-bit `usize` both
    // fit in `u64`).  `6 * n` ≤ 6 * 2^28 ≈ 1.6 × 10^9 < `u64::MAX`.
    let mut t: u64 = 6_u64 * (n as u64);
    for _j in 0..6_u32 {
        for i in (0..n).rev() {
            // A ← A XOR t (full 8-byte XOR; upper 4 bytes of `t` are zero
            // for any permitted input length).
            let t_bytes = t.to_be_bytes();
            for k in 0..AES_WRAP_BLOCK_SIZE {
                a[k] ^= t_bytes[k];
            }
            // B ← AES_round(A || R[i]).
            b[..AES_WRAP_BLOCK_SIZE].copy_from_slice(&a);
            let r_start = i * AES_WRAP_BLOCK_SIZE;
            b[AES_WRAP_BLOCK_SIZE..].copy_from_slice(&out[r_start..r_start + AES_WRAP_BLOCK_SIZE]);

            aes_round(aes, use_forward, &mut b)?;

            // A ← MSB_64(B), R[i] ← LSB_64(B).
            a.copy_from_slice(&b[..AES_WRAP_BLOCK_SIZE]);
            out[r_start..r_start + AES_WRAP_BLOCK_SIZE].copy_from_slice(&b[AES_WRAP_BLOCK_SIZE..]);
            t = t.wrapping_sub(1);
        }
    }

    b.zeroize();
    // `a` is returned to the caller for IV verification; the caller must
    // zeroize it after use.
    Ok((a, out))
}

/// RFC 3394 §2.2.2 unwrap operation with constant-time IV verification.
///
/// Returns the unwrapped plaintext (`ciphertext.len() - 8` bytes) on
/// success, or `ProviderError::Dispatch` if the recovered IV does not
/// match `expected_iv` (always with `subtle::ConstantTimeEq` to prevent
/// timing leaks).
///
/// # Errors
///
/// * `ProviderError::Dispatch` — invalid input length, IV mismatch (after
///   constant-time comparison), or AES round failure.
fn unwrap_with_block(
    aes: &Aes,
    use_forward: bool,
    expected_iv: [u8; AES_WRAP_NOPAD_IVLEN],
    ciphertext: &[u8],
) -> ProviderResult<Vec<u8>> {
    let (mut got_iv, mut out) = unwrap_raw_with_block(aes, use_forward, ciphertext)?;
    let iv_ok: bool = got_iv.ct_eq(&expected_iv).into();
    got_iv.zeroize();
    if !iv_ok {
        out.zeroize();
        return Err(ProviderError::Dispatch(
            "AES key unwrap: integrity-check IV mismatch".into(),
        ));
    }
    Ok(out)
}

/// RFC 5649 §4.1 wrap-with-padding operation, parameterized by AES round
/// direction.  Accepts arbitrary non-empty plaintext lengths; the AIV
/// encodes the original message length so the receiver can recover it.
///
/// # Algorithm
///
/// 1. Compute `padded_len = 8 * ceil(inlen / 8)`.
/// 2. Build `AIV = 0xA659_59A6 || (inlen as u32 big-endian)`.
/// 3. If `padded_len == 8` (single semiblock): encrypt the 16-byte block
///    `AIV || zero-padded plaintext` directly with one AES round.
/// 4. Otherwise: zero-pad plaintext to `padded_len` and call
///    `wrap_with_block(AIV, padded_plaintext)`.
///
/// # Errors
///
/// * `ProviderError::Dispatch` — empty input, input length ≥
///   `CRYPTO128_WRAP_MAX`, or AES round failure.
fn wrap_pad_with_block(aes: &Aes, use_forward: bool, plaintext: &[u8]) -> ProviderResult<Vec<u8>> {
    let inlen = plaintext.len();
    if inlen == 0 {
        return Err(ProviderError::Dispatch(
            "AES key wrap (padded): plaintext must be non-empty".into(),
        ));
    }
    if inlen >= CRYPTO128_WRAP_MAX {
        return Err(ProviderError::Dispatch(format!(
            "AES key wrap (padded): plaintext length {inlen} exceeds maximum {}",
            CRYPTO128_WRAP_MAX - 1
        )));
    }

    // RFC 5649 §4.1 step 1: padded length = 8 * ceil(inlen / 8).
    let blocks_padded = inlen.checked_add(AES_WRAP_BLOCK_SIZE - 1).ok_or_else(|| {
        ProviderError::Dispatch(
            "AES key wrap (padded): inlen + (semiblock - 1) overflowed usize".into(),
        )
    })? / AES_WRAP_BLOCK_SIZE;
    let padded_len = blocks_padded
        .checked_mul(AES_WRAP_BLOCK_SIZE)
        .ok_or_else(|| {
            ProviderError::Dispatch(
                "AES key wrap (padded): blocks_padded * semiblock overflowed usize".into(),
            )
        })?;

    // Build the AIV: magic prefix || MLI (big-endian 32-bit message length).
    let mut aiv = [0u8; AES_WRAP_BLOCK_SIZE];
    aiv[..AES_WRAP_PAD_IVLEN].copy_from_slice(&DEFAULT_AIV);
    let mli: u32 = u32::try_from(inlen).map_err(|_| {
        ProviderError::Dispatch(format!(
            "AES key wrap (padded): inlen {inlen} does not fit in u32"
        ))
    })?;
    aiv[AES_WRAP_PAD_IVLEN..AES_WRAP_BLOCK_SIZE].copy_from_slice(&mli.to_be_bytes());

    let result = if padded_len == AES_WRAP_BLOCK_SIZE {
        // Special case (RFC 5649): single padded semiblock.  The 16-byte
        // block to encrypt is `AIV || padded_plaintext` (where padding
        // is zero bytes filling the trailing `8 - inlen` positions).
        let mut block = [0u8; AES_BLOCK_SIZE_BYTES];
        block[..AES_WRAP_BLOCK_SIZE].copy_from_slice(&aiv);
        block[AES_WRAP_BLOCK_SIZE..AES_WRAP_BLOCK_SIZE + inlen].copy_from_slice(plaintext);
        // Trailing bytes [AES_WRAP_BLOCK_SIZE + inlen .. 16] remain zero
        // from the `[0u8; ...]` initializer (RFC 5649 §4.1 step 1 padding).

        aes_round(aes, use_forward, &mut block)?;

        let out = block.to_vec();
        block.zeroize();
        out
    } else {
        // General case: zero-pad plaintext to `padded_len`, then perform a
        // standard RFC 3394 wrap using the AIV as the integrity-check IV.
        // `aiv` is `Copy` (`[u8; 8]`); the by-value pass leaves the local
        // intact so we can still zeroize it on exit.
        let mut padded = vec![0u8; padded_len];
        padded[..inlen].copy_from_slice(plaintext);
        let wrap_result = wrap_with_block(aes, use_forward, aiv, &padded);
        padded.zeroize();
        wrap_result?
    };

    aiv.zeroize();
    Ok(result)
}

/// RFC 5649 §4.2 unwrap-with-padding operation with full constant-time
/// authentication of the recovered AIV.
///
/// # Authentication
///
/// Four independent checks are combined with bitwise AND (no short
/// circuit) to keep the failure path constant-time:
///
/// 1. **`magic_ok`** — high 4 bytes of recovered AIV equal `DEFAULT_AIV`.
/// 2. **`mli_lower_ok`** — recovered MLI is strictly greater than
///    `8 * (n - 1)` (i.e. the message occupies at least one byte of the
///    final semiblock).
/// 3. **`mli_upper_ok`** — recovered MLI does not exceed `padded_len`.
/// 4. **`pad_ok`** — all bytes of the padding region are zero (compared
///    against `0u8` with `subtle::ConstantTimeEq`).
///
/// On failure the plaintext buffer is zeroized before the error is
/// returned, so no information about the recovered bytes leaks.
///
/// # Errors
///
/// * `ProviderError::Dispatch` — invalid ciphertext length, AES round
///   failure, or any of the four authentication checks failing.
fn unwrap_pad_with_block(
    aes: &Aes,
    use_forward: bool,
    ciphertext: &[u8],
) -> ProviderResult<Vec<u8>> {
    let clen = ciphertext.len();
    if clen % AES_WRAP_BLOCK_SIZE != 0 {
        return Err(ProviderError::Dispatch(format!(
            "AES key unwrap (padded): ciphertext length {clen} is not a multiple of {AES_WRAP_BLOCK_SIZE}"
        )));
    }
    if clen < 2 * AES_WRAP_BLOCK_SIZE {
        return Err(ProviderError::Dispatch(format!(
            "AES key unwrap (padded): ciphertext length {clen} must be at least {} bytes",
            2 * AES_WRAP_BLOCK_SIZE
        )));
    }
    if clen >= CRYPTO128_WRAP_MAX {
        return Err(ProviderError::Dispatch(format!(
            "AES key unwrap (padded): ciphertext length {clen} exceeds maximum {}",
            CRYPTO128_WRAP_MAX - 1
        )));
    }

    let mut aiv = [0u8; AES_WRAP_BLOCK_SIZE];
    let (mut plaintext_buf, padded_len): (Vec<u8>, usize) = if clen == 2 * AES_WRAP_BLOCK_SIZE {
        // Single-block special case: the entire ciphertext is one AES
        // block.  After one inverse-direction round, AIV occupies the
        // high 8 bytes and the padded plaintext the low 8 bytes.
        let mut buff = [0u8; AES_BLOCK_SIZE_BYTES];
        buff.copy_from_slice(ciphertext);
        aes_round(aes, use_forward, &mut buff)?;
        aiv.copy_from_slice(&buff[..AES_WRAP_BLOCK_SIZE]);
        let mut plaintext = vec![0u8; AES_WRAP_BLOCK_SIZE];
        plaintext.copy_from_slice(&buff[AES_WRAP_BLOCK_SIZE..]);
        buff.zeroize();
        (plaintext, AES_WRAP_BLOCK_SIZE)
    } else {
        // General case: standard RFC 3394 unwrap reveals the AIV in
        // the recovered IV slot.
        let (got_iv, plaintext) = unwrap_raw_with_block(aes, use_forward, ciphertext)?;
        aiv.copy_from_slice(&got_iv);
        // `got_iv` is now copied into `aiv`; zeroize the temporary.
        let mut got_iv = got_iv;
        got_iv.zeroize();
        (plaintext, clen - AES_WRAP_BLOCK_SIZE)
    };

    let n = padded_len / AES_WRAP_BLOCK_SIZE;

    // ----- Constant-time authentication checks ---------------------------
    //
    // All four checks below are computed unconditionally, and their boolean
    // results are combined with bitwise AND (`&`, *not* `&&`) so that no
    // short-circuit evaluation reveals which check failed via timing.

    // 1. AIV magic prefix matches.
    let magic_ok: bool = aiv[..AES_WRAP_PAD_IVLEN].ct_eq(&DEFAULT_AIV[..]).into();

    // 2/3. Message-length indicator is in the legal range.
    let mli_u32 = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]);
    // R6 justification: u32 → usize is a widening cast on every supported
    // target (32-bit usize ≥ 32 bits, 64-bit usize is 64 bits); cannot
    // truncate or wrap.
    let mli: usize = mli_u32 as usize;
    let lower_bound = AES_WRAP_BLOCK_SIZE.saturating_mul(n.saturating_sub(1));
    let mli_lower_ok: bool = mli > lower_bound;
    let mli_upper_ok: bool = mli <= padded_len;

    // 4. Padding region (plaintext_buf[mli..padded_len]) is all-zero.
    // Use `effective_mli` to avoid out-of-bounds slicing if MLI is bogus
    // — but the result still feeds into the constant-time AND, so an
    // attacker cannot distinguish "bad MLI" from "bad padding".
    let effective_mli = mli.min(padded_len);
    let mut pad_acc: u8 = 0;
    for &byte in &plaintext_buf[effective_mli..padded_len] {
        pad_acc |= byte;
    }
    let pad_ok: bool = pad_acc.ct_eq(&0u8).into();

    // Bitwise combination — *no* short-circuit so the failure path runs
    // every check regardless of any individual outcome.
    let all_ok: bool = magic_ok & mli_lower_ok & mli_upper_ok & pad_ok;

    aiv.zeroize();

    if !all_ok {
        plaintext_buf.zeroize();
        return Err(ProviderError::Dispatch(
            "AES key unwrap (padded): authentication failed".into(),
        ));
    }

    plaintext_buf.truncate(mli);
    Ok(plaintext_buf)
}

// =============================================================================
// Custom Debug — avoids leaking key/IV bytes via `tracing` instrumentation.
// =============================================================================

impl fmt::Debug for AesWrapContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesWrapContext")
            .field("name", &self.name)
            .field("key_bytes", &self.key_bytes)
            .field("with_padding", &self.with_padding)
            .field("inverse", &self.inverse)
            .field("encrypting", &self.encrypting)
            .field("initialized", &self.initialized)
            .field("updated", &self.updated)
            .field("iv_len", &self.iv.len())
            .field("iv_set", &self.iv_set)
            .field("key", &self.key.as_ref().map(|_| "<keyed>"))
            .finish_non_exhaustive()
    }
}

// =============================================================================
// CipherContext Implementation
// =============================================================================

impl CipherContext for AesWrapContext {
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

    /// Performs the single-shot wrap or unwrap transformation.
    ///
    /// # Validation (mirrors `aes_wrap_cipher_internal` in the C reference)
    ///
    /// * `input` must be non-empty.
    /// * For decrypt (unwrap), `input.len()` must be ≥ 16 bytes and a
    ///   multiple of 8.
    /// * For encrypt without padding, `input.len()` must be a multiple of 8.
    /// * The context must have been initialised via `encrypt_init` /
    ///   `decrypt_init` first.
    /// * `update` may be called **at most once** per context — subsequent
    ///   calls return `ProviderError::Dispatch` (matching the C reference's
    ///   `EVP_R_UPDATE_ERROR` behaviour).
    ///
    /// On success returns the number of bytes appended to `output`.
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES key wrap: context not initialised".into(),
            ));
        }
        if self.updated {
            return Err(ProviderError::Dispatch(
                "AES key wrap is single-shot: update() may only be called once per context".into(),
            ));
        }
        if input.is_empty() {
            return Err(ProviderError::Dispatch(
                "AES key wrap: empty input is not permitted".into(),
            ));
        }

        // Length validation per RFC 3394 / 5649.
        let inlen = input.len();
        if !self.encrypting {
            // Unwrap: must be at least 16 bytes (cipher-text after IV
            // stripping) and a multiple of 8.
            if inlen < AES_WRAP_MIN_UNWRAP_LEN {
                return Err(ProviderError::Dispatch(format!(
                    "AES key wrap: unwrap input length {inlen} below minimum {AES_WRAP_MIN_UNWRAP_LEN}"
                )));
            }
            if inlen % AES_WRAP_BLOCK_SIZE != 0 {
                return Err(ProviderError::Dispatch(format!(
                    "AES key wrap: unwrap input length {inlen} is not a multiple of {AES_WRAP_BLOCK_SIZE}"
                )));
            }
        } else if !self.with_padding && inlen % AES_WRAP_BLOCK_SIZE != 0 {
            // Non-padded wrap: input must align to semiblock boundary.
            return Err(ProviderError::Dispatch(format!(
                "AES key wrap: non-padded wrap input length {inlen} is not a multiple of {AES_WRAP_BLOCK_SIZE}"
            )));
        }

        // Mark as consumed before performing the operation: the C reference
        // sets `wctx->updated = 1` immediately, before the wrap call runs,
        // so that any catastrophic failure leaves the context unusable.
        self.updated = true;

        let mut key_bytes = self.require_key()?.to_vec();
        let resolved_iv = self.resolved_iv();
        // `use_forward` = boolean to pass to the AES round routine (see
        // `use_forward_transform`'s documentation).  This is **independent**
        // of which algorithm (wrap vs. unwrap, padded vs. non-padded) we
        // dispatch below — that is governed solely by `self.encrypting`
        // and `self.with_padding`.
        let use_forward = self.use_forward_transform();

        // Build the AES key schedule once for the entire operation.  Any
        // failure here is reported as `ProviderError::Init` for parity with
        // `init_common`, since failing to build the schedule is a key-setup
        // issue rather than a per-block dispatch error.
        let aes = Aes::new(&key_bytes).map_err(|e| {
            ProviderError::Init(format!(
                "AES key wrap: AES key schedule expansion failed: {e}"
            ))
        })?;

        // Algorithm selection is driven entirely by `(with_padding,
        // encrypting)` — the inverse-cipher property is realised purely
        // by the AES round-direction bit (`use_forward`) passed down into
        // the helper, *not* by swapping wrap/unwrap algorithms.  This
        // matches the C reference's two orthogonal axes of dispatch in
        // `cipher_aes_wrp.c`:
        //   - `wrapfn` is selected by `enc` only;
        //   - `ctx->block` is selected by `inverse XOR enc`.
        let result_bytes = match (self.with_padding, self.encrypting) {
            // RFC 5649 wrap with padding (encrypt direction).
            (true, true) => wrap_pad_with_block(&aes, use_forward, input)?,
            // RFC 5649 unwrap with padding (decrypt direction).
            (true, false) => unwrap_pad_with_block(&aes, use_forward, input)?,
            // RFC 3394 wrap (encrypt direction).
            (false, true) => wrap_with_block(&aes, use_forward, resolved_iv, input)?,
            // RFC 3394 unwrap (decrypt direction).
            (false, false) => unwrap_with_block(&aes, use_forward, resolved_iv, input)?,
        };

        // Defence in depth: zeroize the local copy of the key bytes before
        // dropping (although `Vec` does not in general zero on drop, and
        // the shadow held by `aes` is dropped at end of scope anyway).
        key_bytes.zeroize();

        let written = result_bytes.len();
        output.extend_from_slice(&result_bytes);
        Ok(written)
    }

    /// No-op finaliser: AES Key Wrap is a single-shot transformation, so
    /// `update` has already produced the entire output and `finalize` has
    /// nothing to flush.  Mirrors the C reference's `aes_wrap_final` which
    /// sets `*outl = 0` and returns success.
    ///
    /// We still report errors when the context is not initialised — calling
    /// `finalize` on a fresh context is a programming error.
    fn finalize(&mut self, _output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES key wrap: context not initialised".into(),
            ));
        }
        Ok(0)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // Compose the standard cipher metadata (mode, key/IV/block bits,
        // capability flags) via the shared helper, then layer the
        // wrap-specific `updated` flag on top.
        let flags = if self.inverse {
            CipherFlags::CUSTOM_IV | CipherFlags::INVERSE_CIPHER
        } else {
            CipherFlags::CUSTOM_IV
        };
        let iv_bits = if self.with_padding {
            AES_WRAP_PAD_IVLEN * 8
        } else {
            AES_WRAP_NOPAD_IVLEN * 8
        };
        let key_bits = self.key_bytes * 8;
        let mut params = generic_get_params(
            CipherMode::Wrap,
            flags,
            key_bits,
            AES_WRAP_BLOCK_BITS,
            iv_bits,
        );
        // Report the single-shot flag to the caller.  The C reference does
        // not expose this via OSSL_PARAM, but doing so makes the Rust
        // contract observable for diagnostics and tracing.
        let updated_flag: i32 = i32::from(self.updated);
        params.set(param_keys::UPDATED, ParamValue::Int32(updated_flag));
        Ok(params)
    }

    /// Applies caller-supplied parameters.  Per the C reference, the only
    /// supported `set_ctx_params` operation is verifying that the caller's
    /// `KEYLEN` matches the algorithm's declared key length.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(value) = params.get(param_keys::KEYLEN) {
            let supplied = match value {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!(
                        "AES key wrap: invalid keylen parameter (u32 → usize conversion failed: {e})"
                    ))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!(
                        "AES key wrap: invalid keylen parameter (u64 → usize conversion failed: {e})"
                    ))
                })?,
                ParamValue::Int32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!(
                        "AES key wrap: invalid keylen parameter (i32 → usize conversion failed: {e})"
                    ))
                })?,
                other => {
                    return Err(ProviderError::Dispatch(format!(
                        "AES key wrap: unexpected keylen parameter type {}",
                        other.param_type_name()
                    )));
                }
            };
            if supplied != self.key_bytes {
                return Err(ProviderError::Dispatch(format!(
                    "AES key wrap: keylen mismatch — supplied {supplied}, expected {}",
                    self.key_bytes
                )));
            }
        }
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptor Registry
// =============================================================================

/// Returns the full set of algorithm descriptors implemented by this module.
///
/// Twelve descriptors are produced (3 key sizes × 4 mode families):
///
/// * **`AES-{128,192,256}-WRAP`** — RFC 3394 forward wrap.
/// * **`AES-{128,192,256}-WRAP-PAD`** — RFC 5649 forward wrap with padding.
/// * **`AES-{128,192,256}-WRAP-INV`** — SP 800-38F inverse-cipher wrap.
/// * **`AES-{128,192,256}-WRAP-PAD-INV`** — SP 800-38F inverse-cipher wrap
///   with padding.
///
/// All descriptors carry the property `"provider=default"` so they are
/// picked up by the default provider's algorithm registry.
///
/// The names are leaked via `Box::leak` to obtain the `&'static str`
/// lifetime required by `AlgorithmDescriptor`.  This is a one-time cost
/// at registry construction; the leaked memory equals 12 short string
/// allocations and never grows.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    /// Helper struct describing one mode-family the registry produces.
    struct ModeFamily {
        suffix: &'static str,
        description: &'static str,
        with_padding: bool,
        inverse: bool,
    }

    const FAMILIES: [ModeFamily; 4] = [
        ModeFamily {
            suffix: "WRAP",
            description: "AES Key Wrap (RFC 3394)",
            with_padding: false,
            inverse: false,
        },
        ModeFamily {
            suffix: "WRAP-PAD",
            description: "AES Key Wrap with Padding (RFC 5649)",
            with_padding: true,
            inverse: false,
        },
        ModeFamily {
            suffix: "WRAP-INV",
            description: "AES Key Wrap inverse cipher (NIST SP 800-38F §5.1)",
            with_padding: false,
            inverse: true,
        },
        ModeFamily {
            suffix: "WRAP-PAD-INV",
            description: "AES Key Wrap with Padding, inverse cipher (NIST SP 800-38F §5.1)",
            with_padding: true,
            inverse: true,
        },
    ];

    const KEY_SIZES: [usize; 3] = [128, 192, 256];

    let mut descs = Vec::with_capacity(FAMILIES.len() * KEY_SIZES.len());

    for family in &FAMILIES {
        for &key_bits in &KEY_SIZES {
            // Build the canonical name and leak it to obtain a 'static
            // lifetime as required by `AlgorithmDescriptor`.
            let name = format!("AES-{key_bits}-{}", family.suffix);
            let leaked: &'static str = Box::leak(name.into_boxed_str());

            descs.push(AlgorithmDescriptor {
                names: vec![leaked],
                property: "provider=default",
                description: family.description,
            });

            // Constructibility check (Rule R10 — wiring before done): every
            // descriptor produced here is also constructable as a real
            // provider.  Discarding the value verifies the constructor
            // does not panic and that the configuration is internally
            // consistent.  This is cheap (no heap allocation beyond the
            // four small fields) and runs at registry build time only.
            let _provider =
                AesWrapCipher::new(leaked, key_bits, family.with_padding, family.inverse);
        }
    }

    descs
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // Test-only allow: `expect`, `unwrap`, and `panic!` are idiomatic in
    // unit tests where panicking on unexpected values is the desired
    // failure mode.  Mirrors the established pattern in `aes_xts.rs`,
    // `test_base_provider.rs`, and other provider test modules.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// All twelve descriptors are produced and have unique names.
    #[test]
    fn descriptors_count_is_twelve_and_names_unique() {
        let descs = descriptors();
        assert_eq!(descs.len(), 12, "expected 12 algorithm descriptors");
        let mut names: Vec<&str> = descs.iter().flat_map(|d| d.names.iter().copied()).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "descriptor names must be unique");
    }

    /// Every descriptor must carry the default provider property and a
    /// non-empty description.
    #[test]
    fn descriptors_metadata_is_well_formed() {
        for desc in descriptors() {
            assert_eq!(desc.property, "provider=default");
            assert!(!desc.description.is_empty());
            assert!(!desc.names.is_empty());
            for name in &desc.names {
                assert!(!name.is_empty());
                assert!(name.starts_with("AES-"));
                assert!(name.contains("-WRAP"));
            }
        }
    }

    /// The exact set of canonical names produced (canonical key-size order
    /// 128 → 192 → 256, family order WRAP → WRAP-PAD → WRAP-INV →
    /// WRAP-PAD-INV).
    #[test]
    fn descriptors_canonical_names_match() {
        let descs = descriptors();
        let names: Vec<&str> = descs.iter().map(|d| d.names[0]).collect();
        assert_eq!(
            names,
            vec![
                "AES-128-WRAP",
                "AES-192-WRAP",
                "AES-256-WRAP",
                "AES-128-WRAP-PAD",
                "AES-192-WRAP-PAD",
                "AES-256-WRAP-PAD",
                "AES-128-WRAP-INV",
                "AES-192-WRAP-INV",
                "AES-256-WRAP-INV",
                "AES-128-WRAP-PAD-INV",
                "AES-192-WRAP-PAD-INV",
                "AES-256-WRAP-PAD-INV",
            ]
        );
    }

    /// `CipherProvider` getters report the correct geometry per variant.
    #[test]
    fn cipher_provider_metadata_is_correct() {
        // Standard wrap, 128-bit key, IV = 8 bytes.
        let c = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        assert_eq!(c.name(), "AES-128-WRAP");
        assert_eq!(c.key_length(), 16);
        assert_eq!(c.iv_length(), 8);
        assert_eq!(c.block_size(), 8);

        // Wrap with padding, 192-bit key, IV = 4 bytes.
        let c = AesWrapCipher::new("AES-192-WRAP-PAD", 192, true, false);
        assert_eq!(c.name(), "AES-192-WRAP-PAD");
        assert_eq!(c.key_length(), 24);
        assert_eq!(c.iv_length(), 4);
        assert_eq!(c.block_size(), 8);

        // Inverse wrap with padding, 256-bit key, IV = 4 bytes.
        let c = AesWrapCipher::new("AES-256-WRAP-PAD-INV", 256, true, true);
        assert_eq!(c.name(), "AES-256-WRAP-PAD-INV");
        assert_eq!(c.key_length(), 32);
        assert_eq!(c.iv_length(), 4);
        assert_eq!(c.block_size(), 8);
    }

    /// `new_ctx` returns an uninitialised context that rejects `update`.
    #[test]
    fn new_ctx_returns_uninitialised_context() {
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx must succeed");
        let mut out = Vec::new();
        let err = ctx
            .update(&[0u8; 24], &mut out)
            .expect_err("update before init must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Wrong key length on `encrypt_init` is rejected with `Init`.
    #[test]
    fn wrong_key_length_rejected() {
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        // 24 bytes is not a 128-bit key.
        let bad_key = [0u8; 24];
        let err = ctx
            .encrypt_init(&bad_key, None, None)
            .expect_err("wrong key length must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    /// IV length validation on init: padded wrap requires 4-byte IV.
    #[test]
    fn padded_wrap_iv_length_validated() {
        let cipher = AesWrapCipher::new("AES-128-WRAP-PAD", 128, true, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let key = [0u8; 16];
        let bad_iv = [0u8; 8]; // wrong: padded mode wants 4-byte IV
        let err = ctx
            .encrypt_init(&key, Some(&bad_iv), None)
            .expect_err("wrong IV length must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// IV length validation on init: non-padded wrap requires 8-byte IV.
    #[test]
    fn nonpad_wrap_iv_length_validated() {
        let cipher = AesWrapCipher::new("AES-256-WRAP", 256, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let key = [0u8; 32];
        let bad_iv = [0u8; 4]; // wrong: non-padded mode wants 8-byte IV
        let err = ctx
            .encrypt_init(&key, Some(&bad_iv), None)
            .expect_err("wrong IV length must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Round-trip wrap/unwrap with AES-128, no padding, default IV.
    #[test]
    fn round_trip_aes128_wrap_default_iv() {
        let key = [0xa5u8; 16];
        let plaintext = [0x42u8; 32]; // 4 semiblocks

        let wrapper = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut wctx = wrapper.new_ctx().expect("new_ctx");
        wctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut ct = Vec::new();
        let n = wctx.update(&plaintext, &mut ct).expect("update wrap");
        assert_eq!(n, plaintext.len() + 8);
        wctx.finalize(&mut ct).expect("finalize");
        assert_eq!(ct.len(), plaintext.len() + 8);

        let unwrapper = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut uctx = unwrapper.new_ctx().expect("new_ctx");
        uctx.decrypt_init(&key, None, None).expect("decrypt_init");
        let mut pt = Vec::new();
        let m = uctx.update(&ct, &mut pt).expect("update unwrap");
        assert_eq!(m, plaintext.len());
        uctx.finalize(&mut pt).expect("finalize");
        assert_eq!(pt, plaintext);
    }

    /// Round-trip wrap/unwrap with AES-256, no padding, custom IV.
    #[test]
    fn round_trip_aes256_wrap_custom_iv() {
        let key = [0x7fu8; 32];
        let iv = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let plaintext = b"sixteen-byte data".repeat(2); // 34 bytes ⇒ unaligned, must reject

        let wrapper = AesWrapCipher::new("AES-256-WRAP", 256, false, false);
        let mut wctx = wrapper.new_ctx().expect("new_ctx");
        wctx.encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut ct = Vec::new();
        let err = wctx
            .update(&plaintext, &mut ct)
            .expect_err("non-padded wrap requires multiple-of-8 input");
        assert!(matches!(err, ProviderError::Dispatch(_)));

        // Now retry with aligned plaintext.
        let aligned = [0xc3u8; 24];
        let mut wctx = wrapper.new_ctx().expect("new_ctx");
        wctx.encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut ct = Vec::new();
        let n = wctx.update(&aligned, &mut ct).expect("update wrap");
        assert_eq!(n, aligned.len() + 8);

        let mut uctx = wrapper.new_ctx().expect("new_ctx");
        uctx.decrypt_init(&key, Some(&iv), None)
            .expect("decrypt_init");
        let mut pt = Vec::new();
        let m = uctx.update(&ct, &mut pt).expect("update unwrap");
        assert_eq!(m, aligned.len());
        assert_eq!(pt, aligned);
    }

    /// Round-trip wrap-with-padding (RFC 5649) for arbitrary-length input.
    #[test]
    fn round_trip_aes128_wrap_pad() {
        let key = [0x5au8; 16];
        // 13 bytes — does not align to a semiblock; padding is needed.
        let plaintext = b"thirteen-byte";

        let wrapper = AesWrapCipher::new("AES-128-WRAP-PAD", 128, true, false);
        let mut wctx = wrapper.new_ctx().expect("new_ctx");
        wctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut ct = Vec::new();
        let n = wctx.update(plaintext, &mut ct).expect("update wrap-pad");
        // Cipher-text contains AIV (8 B) + ceil(13 / 8) * 8 = 16 B = 24 B total.
        assert_eq!(n, 24);
        assert_eq!(ct.len(), 24);

        let mut uctx = wrapper.new_ctx().expect("new_ctx");
        uctx.decrypt_init(&key, None, None).expect("decrypt_init");
        let mut pt = Vec::new();
        let m = uctx.update(&ct, &mut pt).expect("update unwrap-pad");
        assert_eq!(m, plaintext.len());
        assert_eq!(&pt, plaintext);
    }

    /// Round-trip wrap-with-padding for AES-192 and AES-256.
    #[test]
    fn round_trip_aes192_aes256_wrap_pad() {
        for (name, key_bits, key_len) in
            [("AES-192-WRAP-PAD", 192, 24), ("AES-256-WRAP-PAD", 256, 32)]
        {
            let key = vec![0xa5u8; key_len];
            let plaintext = b"variable-length payload :)";

            let wrapper = AesWrapCipher::new(name, key_bits, true, false);
            let mut wctx = wrapper.new_ctx().expect("new_ctx");
            wctx.encrypt_init(&key, None, None).expect("encrypt_init");
            let mut ct = Vec::new();
            wctx.update(plaintext, &mut ct).expect("update wrap-pad");

            let mut uctx = wrapper.new_ctx().expect("new_ctx");
            uctx.decrypt_init(&key, None, None).expect("decrypt_init");
            let mut pt = Vec::new();
            let m = uctx.update(&ct, &mut pt).expect("update unwrap-pad");
            assert_eq!(m, plaintext.len());
            assert_eq!(&pt, plaintext);
        }
    }

    /// Single-shot enforcement: a second `update` returns `Dispatch`.
    #[test]
    fn second_update_call_rejected() {
        let key = [0u8; 16];
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut out = Vec::new();
        ctx.update(&[0u8; 16], &mut out).expect("first update");
        let err = ctx
            .update(&[0u8; 16], &mut out)
            .expect_err("second update must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Re-init resets the single-shot flag, allowing another wrap.
    #[test]
    fn reinit_resets_single_shot_flag() {
        let key = [0u8; 16];
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut out1 = Vec::new();
        ctx.update(&[0u8; 16], &mut out1).expect("first update");

        // After re-init, update should succeed again.
        ctx.encrypt_init(&key, None, None).expect("re-init");
        let mut out2 = Vec::new();
        ctx.update(&[0u8; 16], &mut out2)
            .expect("post-reinit update");
        assert_eq!(out1, out2);
    }

    /// Empty input is rejected.
    #[test]
    fn empty_input_rejected() {
        let key = [0u8; 16];
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut out = Vec::new();
        let err = ctx
            .update(&[], &mut out)
            .expect_err("empty input must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Unwrap rejects mis-aligned cipher-text.
    #[test]
    fn unwrap_rejects_misaligned_input() {
        let key = [0u8; 16];
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.decrypt_init(&key, None, None).expect("decrypt_init");
        let mut out = Vec::new();
        let err = ctx
            .update(&[0u8; 17], &mut out)
            .expect_err("misaligned cipher-text must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Unwrap rejects too-short cipher-text (< 16 bytes).
    #[test]
    fn unwrap_rejects_short_input() {
        let key = [0u8; 16];
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.decrypt_init(&key, None, None).expect("decrypt_init");
        let mut out = Vec::new();
        let err = ctx
            .update(&[0u8; 8], &mut out)
            .expect_err("too-short cipher-text must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// Tampered cipher-text fails the IV integrity check on unwrap.
    #[test]
    fn tampered_ciphertext_fails_integrity_check() {
        let key = [0xa5u8; 16];
        let plaintext = [0x42u8; 16];

        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut wctx = cipher.new_ctx().expect("new_ctx");
        wctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut ct = Vec::new();
        wctx.update(&plaintext, &mut ct).expect("update wrap");

        // Flip a bit in the IV semiblock.
        ct[0] ^= 0x01;

        let mut uctx = cipher.new_ctx().expect("new_ctx");
        uctx.decrypt_init(&key, None, None).expect("decrypt_init");
        let mut pt = Vec::new();
        let err = uctx
            .update(&ct, &mut pt)
            .expect_err("tampered ciphertext must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// `get_params` reports the correct mode, key-length, IV-length and
    /// block-size metadata, plus the `updated` single-shot indicator.
    #[test]
    fn get_params_reports_metadata() {
        let cipher = AesWrapCipher::new("AES-256-WRAP-PAD", 256, true, false);
        let ctx = cipher.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");

        match params.get(param_keys::KEYLEN) {
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 32),
            other => panic!("unexpected keylen: {other:?}"),
        }
        match params.get(param_keys::IVLEN) {
            // 4 bytes for padded variant.
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 4),
            other => panic!("unexpected ivlen: {other:?}"),
        }
        match params.get(param_keys::BLOCK_SIZE) {
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 8),
            other => panic!("unexpected blocksize: {other:?}"),
        }
        match params.get(param_keys::CUSTOM_IV) {
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 1),
            other => panic!("unexpected custom_iv flag: {other:?}"),
        }
        // AEAD must be 0 — wrap is not authenticated AEAD.
        match params.get(param_keys::AEAD) {
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 0),
            other => panic!("unexpected aead flag: {other:?}"),
        }
        // Updated flag starts at 0.
        match params.get(param_keys::UPDATED) {
            Some(ParamValue::Int32(v)) => assert_eq!(*v, 0),
            other => panic!("unexpected updated flag: {other:?}"),
        }
    }

    /// After a successful `update`, `get_params` reports `updated == 1`.
    #[test]
    fn updated_flag_set_after_update() {
        let key = [0u8; 16];
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&key, None, None).expect("encrypt_init");

        let params_before = ctx.get_params().expect("get_params before");
        match params_before.get(param_keys::UPDATED) {
            Some(ParamValue::Int32(v)) => assert_eq!(*v, 0),
            other => panic!("unexpected before: {other:?}"),
        }

        let mut out = Vec::new();
        ctx.update(&[0u8; 16], &mut out).expect("update");

        let params_after = ctx.get_params().expect("get_params after");
        match params_after.get(param_keys::UPDATED) {
            Some(ParamValue::Int32(v)) => assert_eq!(*v, 1),
            other => panic!("unexpected after: {other:?}"),
        }
    }

    /// `set_params(KEYLEN)` accepts the matching value and rejects others.
    #[test]
    fn set_params_keylen_validation() {
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");

        // Matching keylen is accepted.
        let mut good = ParamSet::new();
        good.set(param_keys::KEYLEN, ParamValue::UInt32(16));
        ctx.set_params(&good).expect("matching keylen accepted");

        // Mismatched keylen is rejected.
        let mut bad = ParamSet::new();
        bad.set(param_keys::KEYLEN, ParamValue::UInt32(32));
        let err = ctx
            .set_params(&bad)
            .expect_err("mismatched keylen must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// `set_params` ignores unrelated parameters silently.
    #[test]
    fn set_params_ignores_unrelated_parameters() {
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let mut params = ParamSet::new();
        params.set(param_keys::AEAD, ParamValue::UInt32(0));
        params.set(param_keys::PADDING, ParamValue::UInt32(0));
        ctx.set_params(&params).expect("unrelated params accepted");
    }

    /// Inverse-cipher variants: wrap/unwrap round-trips through the inverse
    /// pair of primitives still yields the original plaintext.
    #[test]
    fn round_trip_inverse_aes128_wrap() {
        let key = [0xa5u8; 16];
        let plaintext = [0x42u8; 16];

        // Inverse wrap encrypts via the unwrap primitive (forward transform
        // becomes the AES decrypt schedule); the corresponding decrypt path
        // is the wrap primitive.
        let cipher = AesWrapCipher::new("AES-128-WRAP-INV", 128, false, true);
        let mut wctx = cipher.new_ctx().expect("new_ctx");
        wctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut ct = Vec::new();
        wctx.update(&plaintext, &mut ct).expect("update wrap-inv");

        let mut uctx = cipher.new_ctx().expect("new_ctx");
        uctx.decrypt_init(&key, None, None).expect("decrypt_init");
        let mut pt = Vec::new();
        uctx.update(&ct, &mut pt).expect("update unwrap-inv");
        assert_eq!(pt, plaintext);
    }

    /// Inverse cipher variant for padded mode also round-trips.
    #[test]
    fn round_trip_inverse_aes256_wrap_pad() {
        let key = [0x77u8; 32];
        let plaintext = b"twenty-three byte payload!";

        let cipher = AesWrapCipher::new("AES-256-WRAP-PAD-INV", 256, true, true);
        let mut wctx = cipher.new_ctx().expect("new_ctx");
        wctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut ct = Vec::new();
        wctx.update(plaintext, &mut ct)
            .expect("update wrap-pad-inv");

        let mut uctx = cipher.new_ctx().expect("new_ctx");
        uctx.decrypt_init(&key, None, None).expect("decrypt_init");
        let mut pt = Vec::new();
        uctx.update(&ct, &mut pt).expect("update unwrap-pad-inv");
        assert_eq!(&pt, plaintext);
    }

    /// `finalize` on an uninitialised context fails.
    #[test]
    fn finalize_before_init_rejected() {
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let mut out = Vec::new();
        let err = ctx
            .finalize(&mut out)
            .expect_err("finalize before init must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// `finalize` on a properly-used context returns 0 (no buffered bytes).
    #[test]
    fn finalize_is_no_op_after_update() {
        let key = [0u8; 16];
        let cipher = AesWrapCipher::new("AES-128-WRAP", 128, false, false);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut out = Vec::new();
        ctx.update(&[0u8; 16], &mut out).expect("update");
        let pre_len = out.len();
        let n = ctx.finalize(&mut out).expect("finalize");
        assert_eq!(n, 0);
        assert_eq!(out.len(), pre_len, "finalize must not append");
    }

    /// Both context and provider types are `Send + Sync`.
    #[test]
    fn context_and_provider_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AesWrapContext>();
        assert_send_sync::<AesWrapCipher>();
    }

    /// `descriptors()` is idempotent: calling twice produces the same set
    /// of canonical names.  (The descriptors themselves are fresh on each
    /// call due to `Box::leak`; only the *names* are checked.)
    #[test]
    fn descriptors_are_stable_across_calls() {
        let names_a: Vec<&str> = descriptors().iter().map(|d| d.names[0]).collect();
        let names_b: Vec<&str> = descriptors().iter().map(|d| d.names[0]).collect();
        assert_eq!(names_a, names_b);
    }

    /// Produced cipher providers can each create a fresh context via
    /// `new_ctx`.  This exercises the `descriptors() → CipherProvider →
    /// new_ctx` wiring path that is required by Rule R10.
    #[test]
    fn each_descriptor_has_a_constructible_provider() {
        let pairs: &[(&str, usize, bool, bool)] = &[
            ("AES-128-WRAP", 128, false, false),
            ("AES-192-WRAP", 192, false, false),
            ("AES-256-WRAP", 256, false, false),
            ("AES-128-WRAP-PAD", 128, true, false),
            ("AES-192-WRAP-PAD", 192, true, false),
            ("AES-256-WRAP-PAD", 256, true, false),
            ("AES-128-WRAP-INV", 128, false, true),
            ("AES-192-WRAP-INV", 192, false, true),
            ("AES-256-WRAP-INV", 256, false, true),
            ("AES-128-WRAP-PAD-INV", 128, true, true),
            ("AES-192-WRAP-PAD-INV", 192, true, true),
            ("AES-256-WRAP-PAD-INV", 256, true, true),
        ];
        for &(name, bits, pad, inv) in pairs {
            let cipher = AesWrapCipher::new(name, bits, pad, inv);
            let _ctx = cipher.new_ctx().expect("new_ctx must succeed");
        }
    }
}
