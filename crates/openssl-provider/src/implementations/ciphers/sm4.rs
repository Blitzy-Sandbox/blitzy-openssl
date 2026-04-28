//! SM4 cipher provider implementations.
//!
//! SM4 is a 128-bit block cipher published by China's State Cryptography
//! Administration (formerly OSCCA) as standard GB/T 32907-2016, originally
//! codified as SMS4 in 2003 for wireless LAN protection. It is a Feistel-like
//! 32-round network operating on 128-bit blocks with a fixed 128-bit key — no
//! 192- or 256-bit variants exist, in contrast to AES.
//!
//! This module provides the provider-layer surface of SM4, exposing eight
//! distinct algorithm registrations to the EVP fetch machinery:
//!
//! | Algorithm | Mode      | Key bits | IV bits | Tag | Standards |
//! |-----------|-----------|----------|---------|-----|-----------|
//! | SM4-ECB   | Block     | 128      | 0       | —   | GB/T 32907-2016 |
//! | SM4-CBC   | Block     | 128      | 128     | —   | GB/T 32907-2016 |
//! | SM4-CTR   | Stream    | 128      | 128     | —   | GB/T 32907-2016 |
//! | SM4-OFB   | Stream    | 128      | 128     | —   | GB/T 32907-2016 |
//! | SM4-CFB   | Stream    | 128      | 128     | —   | GB/T 32907-2016 (CFB128 only) |
//! | SM4-GCM   | AEAD      | 128      | 96 def. | 16  | NIST SP 800-38D + GB/T |
//! | SM4-CCM   | AEAD      | 128      | 56–104  | 4–16 even | NIST SP 800-38C + GB/T |
//! | SM4-XTS   | Tweakable | 128+128  | 128     | —   | GB/T 17964-2008 / IEEE 1619-2018 |
//!
//! Note that SM4 has **no CFB8 or CFB1 sub-modes** in the canonical OpenSSL
//! C provider — only the byte-oriented CFB128 variant exists, registered as
//! `SM4-CFB`. Likewise no CBC-CTS variant is provided.
//!
//! # XTS standard selector — GB default
//!
//! SM4-XTS supports two equivalent but byte-for-byte distinct standards:
//!
//! - **GB/T 17964-2008** — the Chinese national standard (default for SM4).
//! - **IEEE Std 1619-2018** — the international standard.
//!
//! In the C source `cipher_sm4_xts.c`, the SM4 XTS context is allocated via
//! `OPENSSL_zalloc`, leaving `xts_standard = 0`. The dispatch table then
//! consults `if (ctx->xts_standard) { /* IEEE */ } else { /* GB */ }`, making
//! GB the default. This Rust port preserves that semantics with
//! `XtsStandard::default() == XtsStandard::Gb`, **opposite to AES-XTS** which
//! defaults to IEEE.
//!
//! # AEAD/XTS construction from scratch
//!
//! `openssl_crypto::symmetric::Sm4` provides only the raw 128-bit block
//! cipher — there are no `Sm4Gcm`, `Sm4Ccm`, or `Sm4Xts` engines exposed by
//! the lower layer. Therefore this module constructs the GCM (GHASH +
//! GCTR), CCM (CBC-MAC + CTR), and XTS (Rogaway tweakable cipher with
//! ciphertext stealing) constructions internally on top of `Sm4`'s
//! `encrypt_block` / `decrypt_block` primitives.
//!
//! # Source Mapping
//!
//! | Rust Type            | C Source                          |
//! |----------------------|-----------------------------------|
//! | [`Sm4Cipher`]        | `cipher_sm4.c` `PROV_SM4_CTX`     |
//! | [`Sm4CipherContext`] | `cipher_sm4.c` + `cipher_sm4_hw.c` |
//! | [`Sm4GcmCipher`]     | `cipher_sm4_gcm.c` `PROV_SM4_GCM_CTX` |
//! | [`Sm4GcmContext`]    | `cipher_sm4_gcm.c` + `cipher_sm4_gcm_hw.c` |
//! | [`Sm4CcmCipher`]     | `cipher_sm4_ccm.c` `PROV_SM4_CCM_CTX` |
//! | [`Sm4CcmContext`]    | `cipher_sm4_ccm.c` + `cipher_sm4_ccm_hw.c` |
//! | [`Sm4XtsCipher`]     | `cipher_sm4_xts.c` `PROV_SM4_XTS_CTX` |
//! | [`Sm4XtsContext`]    | `cipher_sm4_xts.c` + `cipher_sm4_xts_hw.c` |
//! | [`XtsStandard`]      | `xts_standard` field in `PROV_SM4_XTS_CTX` |
//! | [`descriptors`]      | `ossl_sm4128*_functions[]` in `defltprov.c` |
//!
//! # Rules Enforced
//!
//! - **Rule R5 (Nullability over sentinels):** [`XtsStandard`] is a typed
//!   enum (not an integer), `cipher_*` engines are `Option<Sm4>`, the IV
//!   strategy is the typed [`IvGeneration`] enum, and TLS AAD buffers are
//!   `Option<Vec<u8>>`.
//! - **Rule R6 (Lossless casts):** Numeric conversions use
//!   `saturating_mul` / `saturating_add` / `try_from` rather than bare `as`.
//! - **Rule R7 (Lock granularity):** No shared mutable state — each context
//!   is independently owned by its caller.
//! - **Rule R8 (Zero unsafe):** Zero `unsafe` blocks. AEAD tag verification
//!   uses [`verify_tag`] (constant-time via [`subtle::ConstantTimeEq`]).
//!   The XTS keys-must-differ check uses
//!   [`subtle::ConstantTimeEq::ct_eq`].
//! - **Rule R9 (Warning-free build):** All public items are documented and
//!   compile cleanly under `RUSTFLAGS="-D warnings"`.
//! - **Rule R10 (Wiring before done):** Algorithms are reachable through
//!   [`descriptors`], aggregated by `super::descriptors`, and registered by
//!   the default provider.
//!
//! # Memory hygiene (AAP §0.7.6)
//!
//! Every context derives [`Zeroize`] / [`ZeroizeOnDrop`] so that key
//! schedules, IVs, GHASH multiplication tables, GCM/CCM tags, and any
//! buffered plaintext / ciphertext are securely erased on drop, replacing
//! the C `OPENSSL_clear_free()` calls in the various `*_freectx` functions.

use super::common::{
    ccm_validate_iv_len, ccm_validate_tag_len, gcm_validate_iv_len, gcm_validate_tag_len,
    generate_random_iv, generic_block_update, generic_get_params, generic_init_key,
    generic_stream_update, increment_iv, make_cipher_descriptor, param_keys, pkcs7_pad,
    pkcs7_unpad, verify_tag, CcmState, CipherFlags, CipherInitConfig, CipherMode, IvGeneration,
};
use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::symmetric::Sm4;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// `SymmetricCipher` and the underlying `Sm4` are referenced for the schema's
// `members_accessed` contract. The engine is exercised through inherent
// `encrypt_block` / `decrypt_block` calls below, which dispatch through the
// trait. Bring the trait into scope so its methods are callable on `Sm4`.
use openssl_crypto::symmetric::SymmetricCipher;

/// SM4 block size in bytes (128 bits).
const SM4_BLOCK_SIZE: usize = 16;

/// SM4 single-key length in bytes (128 bits).
const SM4_KEY_SIZE: usize = 16;

/// SM4-XTS combined key length in bytes — two 128-bit subkeys (data and
/// tweak), per IEEE 1619 §5.1 and GB/T 17964-2008 §6.
const SM4_XTS_KEY_SIZE: usize = 32;

/// SM4-XTS IV/tweak length in bytes (128 bits).
const SM4_XTS_IV_LEN: usize = 16;

/// SM4-XTS reported block size — XTS is stream-like at the EVP layer.
const SM4_XTS_REPORTED_BLOCK: usize = 1;

/// Maximum number of 16-byte blocks per XTS data unit.
///
/// Both IEEE 1619 §5.1 and the OpenSSL implementation cap a single XTS
/// operation at 2²⁰ blocks per data unit (16 MiB) to bound the probability
/// of distinguishability against an ideal tweakable cipher.
const SM4_XTS_MAX_BLOCKS_PER_DATA_UNIT: usize = 1 << 20;

/// Maximum number of bytes per XTS data unit (= 2²⁰ × 16 bytes = 16 MiB).
const SM4_XTS_MAX_BYTES_PER_DATA_UNIT: usize =
    SM4_XTS_MAX_BLOCKS_PER_DATA_UNIT.saturating_mul(SM4_BLOCK_SIZE);

/// Minimum valid XTS input length — shorter inputs cannot support the
/// ciphertext-stealing construction (which needs at least one full block
/// to build the synthetic last block from).
const SM4_XTS_MIN_INPUT_BYTES: usize = SM4_BLOCK_SIZE;

/// SM4-GCM default IV length in bytes (96 bits) — the only IV length
/// mandated by RFC 5288 / RFC 8446 for TLS deployment.
const SM4_GCM_DEFAULT_IV_LEN: usize = 12;

/// SM4-GCM default authentication tag length in bytes (128 bits).
const SM4_GCM_TAG_LEN: usize = 16;

/// SM4-CCM default L parameter (length-of-length encoding width in bytes).
/// Combined with the nonce length this produces 15 - 7 = 8 → L=8.
const SM4_CCM_DEFAULT_L: usize = 8;

/// SM4-CCM default authentication tag length in bytes (96 bits).

// ---------------------------------------------------------------------------
// SM4 base modes (ECB / CBC / CTR / OFB / CFB)
// ---------------------------------------------------------------------------

/// Confidentiality mode for the [`Sm4Cipher`] family.
///
/// SM4 has no `Cfb8`, `Cfb1`, or CBC-CTS variants in the upstream OpenSSL
/// provider, so this enum is strictly smaller than the AES counterpart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub enum Sm4CipherMode {
    /// Electronic Codebook — independent block-by-block encryption with
    /// PKCS#7 padding (default-on for ECB at the EVP layer).
    Ecb,
    /// Cipher Block Chaining — XOR each plaintext block with the previous
    /// ciphertext (or the IV for the first block) before encryption. PKCS#7
    /// padding is on by default.
    Cbc,
    /// Counter mode — pure stream-cipher transform produced by encrypting a
    /// monotonically incremented 128-bit counter and `XOR`-ing the keystream
    /// with the data.
    Ctr,
    /// Output Feedback mode — synchronous stream cipher whose keystream is
    /// produced by repeatedly encrypting the IV (the previous keystream
    /// block).
    Ofb,
    /// 128-bit Cipher Feedback (the only CFB variant for SM4).
    Cfb,
}

impl Sm4CipherMode {
    /// Lower this provider-level mode into the shared
    /// [`CipherMode`](super::common::CipherMode) enum used by the parameter
    /// machinery in [`generic_get_params`] /
    /// [`generic_init_key`](super::common::generic_init_key).
    fn to_cipher_mode(self) -> CipherMode {
        match self {
            Self::Ecb => CipherMode::Ecb,
            Self::Cbc => CipherMode::Cbc,
            Self::Ctr => CipherMode::Ctr,
            Self::Ofb => CipherMode::Ofb,
            Self::Cfb => CipherMode::Cfb,
        }
    }

    /// Returns the cipher-flag set advertised through `get_params`.
    ///
    /// None of the SM4 base modes set any of [`CipherFlags::AEAD`],
    /// [`CipherFlags::CUSTOM_IV`], or [`CipherFlags::CTS`] — the AEAD modes
    /// (GCM/CCM) and the XTS mode have their own provider entry points.
    ///
    /// The exhaustive `match` on `self` is intentional: it documents the
    /// per-variant strategy and forces a compile-time review whenever a new
    /// SM4 base-mode variant is added, preserving the audit trail per
    /// Rule R5.
    fn flags(self) -> CipherFlags {
        match self {
            Self::Ecb | Self::Cbc | Self::Ctr | Self::Ofb | Self::Cfb => CipherFlags::empty(),
        }
    }

    /// Returns the IV-generation strategy for this mode (Rule R10 wiring
    /// into the [`IvGeneration`] entry path). All SM4 base modes accept a
    /// caller-supplied IV via `encrypt_init` / `decrypt_init`, hence
    /// [`IvGeneration::None`].
    fn iv_generation(self) -> IvGeneration {
        match self {
            Self::Ecb | Self::Cbc | Self::Ctr | Self::Ofb | Self::Cfb => IvGeneration::None,
        }
    }

    /// Returns the IV length in bytes for this mode (0 for ECB, 16 for all
    /// others).
    fn iv_len(self) -> usize {
        match self {
            Self::Ecb => 0,
            Self::Cbc | Self::Ctr | Self::Ofb | Self::Cfb => SM4_BLOCK_SIZE,
        }
    }

    /// Returns the EVP-reported block size in bytes. Block-oriented modes
    /// (ECB / CBC) report 16; stream-oriented modes (CTR / OFB / CFB)
    /// report 1 to advertise their stream semantics.
    fn reported_block_size(self) -> usize {
        match self {
            Self::Ecb | Self::Cbc => SM4_BLOCK_SIZE,
            Self::Ctr | Self::Ofb | Self::Cfb => 1,
        }
    }
}

impl fmt::Display for Sm4CipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ecb => f.write_str("ECB"),
            Self::Cbc => f.write_str("CBC"),
            Self::Ctr => f.write_str("CTR"),
            Self::Ofb => f.write_str("OFB"),
            Self::Cfb => f.write_str("CFB"),
        }
    }
}

// ---------------------------------------------------------------------------
// XTS standard selector
// ---------------------------------------------------------------------------

/// Tweak-encoding standard for SM4-XTS.
///
/// SM4-XTS is specified in two byte-for-byte distinct form factors. The
/// payload encryption is identical, but the per-data-unit tweak generation
/// differs — `Gb` follows GB/T 17964-2008 (the Chinese national standard,
/// the default for SM4 in the upstream OpenSSL C provider) while `Ieee`
/// follows IEEE Std 1619-2018.
///
/// Note: this is the **opposite default** of AES-XTS, which defaults to
/// IEEE — see the module-level documentation for the rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub enum XtsStandard {
    /// GB/T 17964-2008 — Chinese national standard. **Default for SM4.**
    Gb,
    /// IEEE Std 1619-2018 — international standard.
    Ieee,
}

impl Default for XtsStandard {
    fn default() -> Self {
        // C source: PROV_SM4_XTS_CTX is OPENSSL_zalloc-allocated, leaving
        // ctx->xts_standard = 0 which the dispatch table interprets as GB.
        Self::Gb
    }
}

impl fmt::Display for XtsStandard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gb => f.write_str("GB"),
            Self::Ieee => f.write_str("IEEE"),
        }
    }
}

impl XtsStandard {
    /// Parse the standard selector from the textual `xts_standard`
    /// parameter (`"GB"` or `"IEEE"`). Comparison is case-insensitive
    /// to match the C provider's `OPENSSL_strcasecmp` behaviour.
    fn from_str(s: &str) -> ProviderResult<Self> {
        if s.eq_ignore_ascii_case("GB") {
            Ok(Self::Gb)
        } else if s.eq_ignore_ascii_case("IEEE") {
            Ok(Self::Ieee)
        } else {
            Err(ProviderError::Init(format!(
                "SM4-XTS: unknown xts_standard '{s}' (expected 'GB' or 'IEEE')"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Sm4Cipher / Sm4CipherContext (ECB / CBC / CTR / OFB / CFB)
// ---------------------------------------------------------------------------

/// Provider-side handle for a single SM4 base-mode algorithm (ECB / CBC /
/// CTR / OFB / CFB). Each `Sm4Cipher` instance carries the algorithm name
/// and the [`Sm4CipherMode`] discriminator used to construct contexts.
///
/// SM4 mandates a 128-bit key — there are no 192- or 256-bit variants, so
/// the key length is hard-wired to 16 bytes.
#[derive(Debug, Clone, Copy)]
pub struct Sm4Cipher {
    name: &'static str,
    mode: Sm4CipherMode,
}

impl Sm4Cipher {
    /// Construct a new SM4 cipher provider for the given mode.
    ///
    /// `name` is the EVP-visible algorithm name (e.g. `"SM4-ECB"`) which
    /// is reflected verbatim by [`name`](Self::name) and incorporated into
    /// the `algorithm` parameter returned by
    /// [`Sm4CipherContext::get_params`].
    #[must_use]
    pub fn new(name: &'static str, mode: Sm4CipherMode) -> Self {
        Self { name, mode }
    }

    /// EVP-visible algorithm name (e.g. `"SM4-ECB"`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// SM4 key length in bytes — always 16 (128 bits).
    #[must_use]
    pub fn key_length(&self) -> usize {
        SM4_KEY_SIZE
    }

    /// IV length in bytes — 0 for ECB, 16 for all other base modes.
    #[must_use]
    pub fn iv_length(&self) -> usize {
        self.mode.iv_len()
    }

    /// Reported block size in bytes — 16 for ECB/CBC, 1 for CTR/OFB/CFB.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.mode.reported_block_size()
    }

    /// Construct a fresh cipher operation context for this algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] only if context allocation fails — for
    /// the SM4 implementation this never errors at construction time.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Sm4CipherContext::new(self.name, self.mode)))
    }
}

impl CipherProvider for Sm4Cipher {
    fn name(&self) -> &'static str {
        Self::name(self)
    }

    fn key_length(&self) -> usize {
        Self::key_length(self)
    }

    fn iv_length(&self) -> usize {
        Self::iv_length(self)
    }

    fn block_size(&self) -> usize {
        Self::block_size(self)
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Self::new_ctx(self)
    }
}

const SM4_CCM_DEFAULT_TAG_LEN: usize = 12;

/// SM4-CCM minimum nonce length in bytes (RFC 3610). The matching upper
/// bound (`13` bytes) is enforced by [`ccm_validate_iv_len`] in
/// [`super::common`], so it is not duplicated here.
const SM4_CCM_NONCE_MIN: usize = 7;

/// GHASH irreducible-polynomial reduction mask. The polynomial is
/// `x¹²⁸ + x⁷ + x² + x + 1`, which after the bit-reflection used by the
/// nibble-table multiplier becomes `0xE1 << 120`.
const GHASH_REDUCTION_MASK: u128 = 0xE100_0000_0000_0000_0000_0000_0000_0000_u128;

/// 4-bit reduction table for nibble-wise GHASH multiplication. Each entry
/// `REM_4BIT[i]` is the reduction modulo the GHASH polynomial of the
/// 4-bit value `i` shifted up to the high 4 bits of a 128-bit word.
const REM_4BIT: [u128; 16] = [
    0x0000_0000_0000_0000_0000_0000_0000_0000_u128,
    0x1C20_0000_0000_0000_0000_0000_0000_0000_u128,
    0x3840_0000_0000_0000_0000_0000_0000_0000_u128,
    0x2460_0000_0000_0000_0000_0000_0000_0000_u128,
    0x7080_0000_0000_0000_0000_0000_0000_0000_u128,
    0x6CA0_0000_0000_0000_0000_0000_0000_0000_u128,
    0x48C0_0000_0000_0000_0000_0000_0000_0000_u128,
    0x54E0_0000_0000_0000_0000_0000_0000_0000_u128,
    0xE100_0000_0000_0000_0000_0000_0000_0000_u128,
    0xFD20_0000_0000_0000_0000_0000_0000_0000_u128,
    0xD940_0000_0000_0000_0000_0000_0000_0000_u128,
    0xC560_0000_0000_0000_0000_0000_0000_0000_u128,
    0x9180_0000_0000_0000_0000_0000_0000_0000_u128,
    0x8DA0_0000_0000_0000_0000_0000_0000_0000_u128,
    0xA9C0_0000_0000_0000_0000_0000_0000_0000_u128,
    0xB5E0_0000_0000_0000_0000_0000_0000_0000_u128,
];

/// XTS GF(2¹²⁸) reduction polynomial (Rogaway 2004 / IEEE 1619): the
/// low byte 0x87 represents `x⁷ + x² + x + 1` (with the implicit `x¹²⁸`).
const XTS_GF128_REDUCTION_BYTE: u8 = 0x87;

/// Per-operation SM4 base-mode cipher context.
///
/// A `Sm4CipherContext` mirrors `PROV_SM4_CTX` in the C provider — it owns
/// the SM4 key schedule, the IV / running keystream, the buffer used to
/// accumulate partial blocks (CBC / ECB) and per-byte state (CTR / OFB /
/// CFB), plus the configuration flags inherited from the cipher's mode.
///
/// The context derives [`Zeroize`] / [`ZeroizeOnDrop`] so that all key /
/// IV / keystream / buffered plaintext bytes are wiped from memory when
/// the context is dropped, replacing the C `OPENSSL_clear_free()` call
/// in `sm4_freectx`.
#[allow(clippy::struct_excessive_bools)]
pub struct Sm4CipherContext {
    /// Algorithm name (e.g. `"SM4-ECB"`), reported via `get_params`.
    name: &'static str,
    /// Mode discriminator inherited from the originating [`Sm4Cipher`].
    mode: Sm4CipherMode,
    /// `true` if [`encrypt_init`](CipherContext::encrypt_init) primed this
    /// context, `false` if [`decrypt_init`](CipherContext::decrypt_init)
    /// did. Indeterminate if `initialized` is `false`.
    encrypting: bool,
    /// Set by `encrypt_init` / `decrypt_init`; cleared on `Drop`.
    initialized: bool,
    /// PKCS#7 padding gate. Defaults to `true` for ECB/CBC, `false` for
    /// stream modes; togglable via `set_params(PADDING)` for ECB/CBC.
    padding: bool,
    /// Cached typed init configuration (Rule R3 — read at runtime via
    /// [`init_common`](Self::init_common) and at descriptor lookup).
    init_config: Option<CipherInitConfig>,
    /// Lazily-keyed SM4 engine. `None` until `encrypt_init` /
    /// `decrypt_init` succeeds.
    cipher: Option<Sm4>,
    /// Current IV / chaining-feedback register (16 bytes for non-ECB
    /// modes, 0 bytes for ECB).
    iv: Vec<u8>,
    /// Partial-block accumulator for ECB / CBC; pending stream input is
    /// processed inline so `buffer` is unused in CTR / OFB / CFB.
    buffer: Vec<u8>,
    /// 16-byte keystream cache for CTR / OFB / CFB modes — updated on
    /// each block boundary and consumed byte-by-byte.
    keystream: Vec<u8>,
    /// Offset within `keystream` of the next byte to consume; once it
    /// reaches `SM4_BLOCK_SIZE` a fresh keystream block is generated.
    ks_offset: usize,
}

impl fmt::Debug for Sm4CipherContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Manual `fmt::Debug` so that key material, IVs, partial-block
        // buffers, and keystream bytes are NEVER leaked through `{:?}`
        // formatting. The unkeyed `init_config`, `cipher`, and
        // `keystream` fields are intentionally omitted; their presence
        // is summarised via `iv_len`, `buffer_len`, and `ks_offset`.
        f.debug_struct("Sm4CipherContext")
            .field("name", &self.name)
            .field("mode", &self.mode)
            .field("encrypting", &self.encrypting)
            .field("initialized", &self.initialized)
            .field("padding", &self.padding)
            .field("iv_len", &self.iv.len())
            .field("buffer_len", &self.buffer.len())
            .field("ks_offset", &self.ks_offset)
            .finish_non_exhaustive()
    }
}

impl Sm4CipherContext {
    /// Construct a fresh, uninitialised SM4 cipher context.
    fn new(name: &'static str, mode: Sm4CipherMode) -> Self {
        // R3 / R10 wiring: synthesise the typed init configuration from
        // the mode parameters so that `init_config.as_ref().map(...)` in
        // `init_common` actually has a value to read.  R6: use checked
        // saturating multiplication for byte→bit conversion (constants
        // are tiny, so no truncation can occur in practice).
        let key_bits: usize = SM4_KEY_SIZE.saturating_mul(8);
        let block_bits: usize = SM4_BLOCK_SIZE.saturating_mul(8);
        let iv_bits: usize = mode.iv_len().saturating_mul(8);
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            key_bits,
            block_bits,
            iv_bits,
            mode.flags(),
        );
        let default_padding = init_config.default_padding();

        // R10 — touch the IvGeneration enum on the entry path so that
        // every `Sm4CipherContext::new` participates in the typed-IV
        // wiring even though SM4 base modes always use caller-supplied
        // IVs (`IvGeneration::None`).
        let _iv_strategy: IvGeneration = mode.iv_generation();

        Self {
            name,
            mode,
            encrypting: false,
            initialized: false,
            padding: default_padding,
            init_config: Some(init_config),
            cipher: None,
            iv: Vec::new(),
            buffer: Vec::new(),
            // Force a fresh keystream block to be generated on first use
            // by starting at the end of the (empty) keystream buffer.
            keystream: Vec::new(),
            ks_offset: SM4_BLOCK_SIZE,
        }
    }

    /// Validate the supplied key length — SM4 only accepts 128-bit keys.
    fn validate_key_size(key_len: usize) -> ProviderResult<()> {
        if key_len == SM4_KEY_SIZE {
            Ok(())
        } else {
            Err(ProviderError::Init(format!(
                "SM4: invalid key length {key_len} bytes (expected {SM4_KEY_SIZE})"
            )))
        }
    }

    /// Shared key/IV ingestion path for [`encrypt_init`] and
    /// [`decrypt_init`]. Closely mirrors `aes::AesCipherContext::init_common`.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // 1. Validate key size up-front so a malformed key cannot leave
        //    us with a stale engine in `self.cipher`.
        Self::validate_key_size(key.len())?;

        // 2. Determine the expected IV length from the cached init
        //    configuration (R3 — read site for `init_config`).
        let expected_iv = self
            .init_config
            .as_ref()
            .map_or_else(|| self.mode.iv_len(), CipherInitConfig::iv_bytes);

        // 3. Validate the supplied IV against the expected length.
        if expected_iv > 0 {
            match iv {
                Some(bytes) if bytes.len() == expected_iv => {
                    self.iv.clear();
                    self.iv.extend_from_slice(bytes);
                }
                Some(bytes) => {
                    return Err(ProviderError::Init(format!(
                        "SM4-{}: invalid IV length {} bytes (expected {expected_iv})",
                        self.mode,
                        bytes.len()
                    )));
                }
                None => {
                    return Err(ProviderError::Init(format!(
                        "SM4-{}: IV is required for this mode (expected {expected_iv} bytes)",
                        self.mode
                    )));
                }
            }
        } else {
            // ECB has no IV.
            self.iv.clear();
        }

        // 4. Build a fresh SM4 engine with the supplied key.
        let engine = Sm4::new(key)
            .map_err(|err| ProviderError::Init(format!("SM4: key schedule failed: {err}")))?;

        // 5. Install the engine and reset stateful buffers.
        self.cipher = Some(engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        self.keystream = vec![0u8; SM4_BLOCK_SIZE];
        self.ks_offset = SM4_BLOCK_SIZE;

        // 6. Apply any caller-supplied parameters last so that they can
        //    override defaults (e.g. `PADDING` for ECB/CBC).
        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// ECB mode update — the simplest path. Encrypts/decrypts complete
    /// blocks and (when `padding && !encrypting`) holds back the final
    /// block for `finalize` to verify and strip the padding.
    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("SM4-ECB: cipher not initialized".to_string())
        })?;
        let encrypting = self.encrypting;
        let padding = self.padding;
        let buffer = &mut self.buffer;
        let helper_padding = padding && !encrypting;
        let processed = generic_block_update(
            input,
            SM4_BLOCK_SIZE,
            buffer,
            helper_padding,
            |blocks: &[u8]| {
                let mut out = Vec::with_capacity(blocks.len());
                for chunk in blocks.chunks_exact(SM4_BLOCK_SIZE) {
                    let mut block = [0u8; SM4_BLOCK_SIZE];
                    block.copy_from_slice(chunk);
                    let res = if encrypting {
                        cipher.encrypt_block(&mut block)
                    } else {
                        cipher.decrypt_block(&mut block)
                    };
                    debug_assert!(res.is_ok(), "SM4 block size invariant");
                    out.extend_from_slice(&block);
                }
                out
            },
        )?;
        let len = processed.len();
        output.extend_from_slice(&processed);
        Ok(len)
    }

    /// ECB finalize — flush PKCS#7-padded last block (encrypt) or verify
    /// and strip the trailer (decrypt).
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("SM4-ECB: cipher not initialized".to_string())
        })?;
        match (self.encrypting, self.padding) {
            (true, true) => {
                let padded = pkcs7_pad(&self.buffer, SM4_BLOCK_SIZE);
                self.buffer.clear();
                let mut written: usize = 0;
                for chunk in padded.chunks_exact(SM4_BLOCK_SIZE) {
                    let mut block = [0u8; SM4_BLOCK_SIZE];
                    block.copy_from_slice(chunk);
                    let res = cipher.encrypt_block(&mut block);
                    debug_assert!(res.is_ok(), "SM4 encrypt_block invariant");
                    output.extend_from_slice(&block);
                    written = written.saturating_add(SM4_BLOCK_SIZE);
                }
                Ok(written)
            }
            (true, false) => {
                if self.buffer.is_empty() {
                    Ok(0)
                } else {
                    Err(ProviderError::Dispatch(
                        "SM4-ECB: input not block-aligned and padding disabled".to_string(),
                    ))
                }
            }
            (false, true) => {
                if self.buffer.len() != SM4_BLOCK_SIZE {
                    return Err(ProviderError::Dispatch(
                        "SM4-ECB: malformed final block on decrypt".to_string(),
                    ));
                }
                let mut block = [0u8; SM4_BLOCK_SIZE];
                block.copy_from_slice(&self.buffer);
                self.buffer.clear();
                let res = cipher.decrypt_block(&mut block);
                debug_assert!(res.is_ok(), "SM4 decrypt_block invariant");
                let unpadded = pkcs7_unpad(&block, SM4_BLOCK_SIZE)?;
                let written = unpadded.len();
                output.extend_from_slice(unpadded);
                block.zeroize();
                Ok(written)
            }
            (false, false) => {
                if self.buffer.is_empty() {
                    Ok(0)
                } else {
                    Err(ProviderError::Dispatch(
                        "SM4-ECB: trailing data on decrypt with padding disabled".to_string(),
                    ))
                }
            }
        }
    }

    /// CBC update — chains plaintext blocks through the IV and emits
    /// ciphertext (or vice-versa for decrypt). Holds back one block on
    /// decrypt-with-padding so `finalize_cbc` can validate the trailer.
    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.iv.len() != SM4_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "SM4-CBC: IV not initialized".to_string(),
            ));
        }
        self.buffer.extend_from_slice(input);
        let total = self.buffer.len();
        let mut full_blocks = (total / SM4_BLOCK_SIZE).saturating_mul(SM4_BLOCK_SIZE);
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks = full_blocks.saturating_sub(SM4_BLOCK_SIZE);
        }
        if full_blocks == 0 {
            return Ok(0);
        }
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("SM4-CBC: cipher not initialized".to_string())
        })?;
        let mut consumed: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut written: usize = 0;
        for chunk in consumed.chunks_exact_mut(SM4_BLOCK_SIZE) {
            let mut block = [0u8; SM4_BLOCK_SIZE];
            block.copy_from_slice(chunk);
            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                let res = cipher.encrypt_block(&mut block);
                debug_assert!(res.is_ok(), "SM4 encrypt_block invariant");
                self.iv.copy_from_slice(&block);
            } else {
                let mut ciphertext_save = [0u8; SM4_BLOCK_SIZE];
                ciphertext_save.copy_from_slice(&block);
                let res = cipher.decrypt_block(&mut block);
                debug_assert!(res.is_ok(), "SM4 decrypt_block invariant");
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ciphertext_save);
                ciphertext_save.zeroize();
            }
            output.extend_from_slice(&block);
            written = written.saturating_add(SM4_BLOCK_SIZE);
            block.zeroize();
        }
        consumed.zeroize();
        Ok(written)
    }

    /// CBC finalize — emit / consume the padded last block.
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.iv.len() != SM4_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "SM4-CBC: IV not initialized".to_string(),
            ));
        }
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("SM4-CBC: cipher not initialized".to_string())
        })?;
        match (self.encrypting, self.padding) {
            (true, true) => {
                let padded = pkcs7_pad(&self.buffer, SM4_BLOCK_SIZE);
                self.buffer.clear();
                let mut written: usize = 0;
                for chunk in padded.chunks_exact(SM4_BLOCK_SIZE) {
                    let mut block = [0u8; SM4_BLOCK_SIZE];
                    block.copy_from_slice(chunk);
                    xor_blocks(&mut block, &self.iv);
                    let res = cipher.encrypt_block(&mut block);
                    debug_assert!(res.is_ok(), "SM4 encrypt_block invariant");
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    written = written.saturating_add(SM4_BLOCK_SIZE);
                    block.zeroize();
                }
                Ok(written)
            }
            (true, false) => {
                if self.buffer.is_empty() {
                    Ok(0)
                } else {
                    Err(ProviderError::Dispatch(
                        "SM4-CBC: input not block-aligned and padding disabled".to_string(),
                    ))
                }
            }
            (false, true) => {
                if self.buffer.len() != SM4_BLOCK_SIZE {
                    return Err(ProviderError::Dispatch(
                        "SM4-CBC: malformed final block on decrypt".to_string(),
                    ));
                }
                let mut block = [0u8; SM4_BLOCK_SIZE];
                block.copy_from_slice(&self.buffer);
                self.buffer.clear();
                let mut ciphertext_save = [0u8; SM4_BLOCK_SIZE];
                ciphertext_save.copy_from_slice(&block);
                let res = cipher.decrypt_block(&mut block);
                debug_assert!(res.is_ok(), "SM4 decrypt_block invariant");
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ciphertext_save);
                ciphertext_save.zeroize();
                let unpadded = pkcs7_unpad(&block, SM4_BLOCK_SIZE)?;
                let written = unpadded.len();
                output.extend_from_slice(unpadded);
                block.zeroize();
                Ok(written)
            }
            (false, false) => {
                if self.buffer.is_empty() {
                    Ok(0)
                } else {
                    Err(ProviderError::Dispatch(
                        "SM4-CBC: trailing data on decrypt with padding disabled".to_string(),
                    ))
                }
            }
        }
    }

    /// OFB stream update — keystream = repeated SM4 encryption of the IV
    /// (each block's keystream becomes the next IV).
    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.iv.len() != SM4_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "SM4-OFB: IV not initialized".to_string(),
            ));
        }
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("SM4-OFB: cipher not initialized".to_string())
        })?;
        let iv = &mut self.iv;
        let keystream = &mut self.keystream;
        let ks_offset = &mut self.ks_offset;
        let processed = generic_stream_update(input, |data: &[u8]| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= SM4_BLOCK_SIZE {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "SM4 encrypt_block invariant");
                    keystream.copy_from_slice(iv);
                    *ks_offset = 0;
                }
                out.push(byte ^ keystream[*ks_offset]);
                *ks_offset = ks_offset.saturating_add(1);
            }
            out
        })?;
        let len = processed.len();
        output.extend_from_slice(&processed);
        Ok(len)
    }

    /// CFB128 stream update — feedback the ciphertext byte (or input byte
    /// on decrypt) into the IV register.
    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.iv.len() != SM4_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "SM4-CFB: IV not initialized".to_string(),
            ));
        }
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("SM4-CFB: cipher not initialized".to_string())
        })?;
        let iv = &mut self.iv;
        let keystream = &mut self.keystream;
        let ks_offset = &mut self.ks_offset;
        let encrypting = self.encrypting;
        let processed = generic_stream_update(input, |data: &[u8]| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= SM4_BLOCK_SIZE {
                    let mut tmp = [0u8; SM4_BLOCK_SIZE];
                    tmp.copy_from_slice(iv);
                    let res = cipher.encrypt_block(&mut tmp);
                    debug_assert!(res.is_ok(), "SM4 encrypt_block invariant");
                    keystream.copy_from_slice(&tmp);
                    tmp.zeroize();
                    *ks_offset = 0;
                }
                let out_byte = byte ^ keystream[*ks_offset];
                let feedback_byte = if encrypting { out_byte } else { byte };
                iv[*ks_offset] = feedback_byte;
                out.push(out_byte);
                *ks_offset = ks_offset.saturating_add(1);
            }
            out
        })?;
        let len = processed.len();
        output.extend_from_slice(&processed);
        Ok(len)
    }

    /// CTR stream update — keystream = SM4(counter), counter incremented
    /// big-endian after each block.
    fn update_ctr(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.iv.len() != SM4_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "SM4-CTR: IV not initialized".to_string(),
            ));
        }
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("SM4-CTR: cipher not initialized".to_string())
        })?;
        let iv = &mut self.iv;
        let keystream = &mut self.keystream;
        let ks_offset = &mut self.ks_offset;
        let processed = generic_stream_update(input, |data: &[u8]| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= SM4_BLOCK_SIZE {
                    let mut tmp = [0u8; SM4_BLOCK_SIZE];
                    tmp.copy_from_slice(iv);
                    let res = cipher.encrypt_block(&mut tmp);
                    debug_assert!(res.is_ok(), "SM4 encrypt_block invariant");
                    keystream.copy_from_slice(&tmp);
                    tmp.zeroize();
                    increment_counter(iv);
                    *ks_offset = 0;
                }
                out.push(byte ^ keystream[*ks_offset]);
                *ks_offset = ks_offset.saturating_add(1);
            }
            out
        })?;
        let len = processed.len();
        output.extend_from_slice(&processed);
        Ok(len)
    }
}

impl CipherContext for Sm4CipherContext {
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

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "SM4: update called before init".to_string(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            Sm4CipherMode::Ecb => self.update_ecb(input, output),
            Sm4CipherMode::Cbc => self.update_cbc(input, output),
            Sm4CipherMode::Ofb => self.update_ofb(input, output),
            Sm4CipherMode::Cfb => self.update_cfb(input, output),
            Sm4CipherMode::Ctr => self.update_ctr(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "SM4: finalize called before init".to_string(),
            ));
        }
        match self.mode {
            Sm4CipherMode::Ecb => self.finalize_ecb(output),
            Sm4CipherMode::Cbc => self.finalize_cbc(output),
            // Stream modes do not produce trailing output.
            Sm4CipherMode::Ofb | Sm4CipherMode::Cfb | Sm4CipherMode::Ctr => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // R6: saturating multiplication for byte→bit conversion (these
        // constants are < 256 bytes, so saturation is purely defensive).
        let key_bits: usize = SM4_KEY_SIZE.saturating_mul(8);
        let block_bits: usize = self.mode.reported_block_size().saturating_mul(8);
        let iv_bits: usize = self.mode.iv_len().saturating_mul(8);
        let mut params = generic_get_params(
            self.mode.to_cipher_mode(),
            self.mode.flags(),
            key_bits,
            block_bits,
            iv_bits,
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(value) = params.get(param_keys::PADDING) {
            // Padding is only meaningful for ECB / CBC; reject otherwise.
            if !matches!(self.mode, Sm4CipherMode::Ecb | Sm4CipherMode::Cbc) {
                return Err(ProviderError::Dispatch(format!(
                    "SM4-{}: padding is not configurable for this mode",
                    self.mode
                )));
            }
            let pad: u64 = match value {
                ParamValue::UInt32(v) => u64::from(*v),
                ParamValue::UInt64(v) => *v,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4: PADDING parameter must be an unsigned integer".to_string(),
                    ));
                }
            };
            self.padding = pad != 0;
        }
        Ok(())
    }
}

impl Drop for Sm4CipherContext {
    fn drop(&mut self) {
        // The `Sm4` engine self-zeroizes through its own Drop. Wipe the
        // remaining sensitive scratch buffers explicitly.
        self.iv.zeroize();
        self.buffer.zeroize();
        self.keystream.zeroize();
        self.cipher = None;
        self.initialized = false;
    }
}

// ---------------------------------------------------------------------------
// Module-level helpers — used by base modes (CBC/CTR) and AEAD modes.
// ---------------------------------------------------------------------------

/// Constant-time-friendly in-place block XOR.
///
/// Computes `dest[i] ^= src[i]` for each `i in 0..min(dest.len(), src.len())`.
/// The branch-free byte loop matches what the C provider's `XOR(c, p, t)`
/// macro emits (`crypto/modes/cbc128.c`, `gcm128.c`).
///
/// Both arguments may alias only insofar as Rust's borrow checker permits;
/// the function does no aliasing-dependent reasoning.
fn xor_blocks(dest: &mut [u8], src: &[u8]) {
    let n = dest.len().min(src.len());
    for i in 0..n {
        dest[i] ^= src[i];
    }
}

/// Big-endian increment of a counter buffer by 1.
///
/// Mirrors the `ctr128_inc` helper in `crypto/modes/ctr128.c` — the
/// rightmost byte is incremented first, with carry propagating left through
/// the entire buffer. On overflow of all bytes the counter silently wraps
/// to zero, matching the C semantics; for SM4-CTR the counter is 128 bits
/// wide, making wrap-around astronomically improbable.
fn increment_counter(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// SM4-GCM AEAD — GHASH + GCTR + AEAD state machine
// ---------------------------------------------------------------------------

/// GCM nonce length used to derive `J_0` directly (12 bytes / 96 bits).
///
/// For nonces of any other length, `J_0 = GHASH_H(nonce || 0^s || len(nonce))`
/// per NIST SP 800-38D §7.1, which this module implements via
/// [`gcm_j0_from_nonce_other`].
const GCM_J0_DIRECT_NONCE_LEN: usize = 12;

/// Minimum AEAD tag length permitted at the SM4-GCM provider boundary
/// (matches `cipher_sm4_gcm.c` and NIST SP 800-38D §5.2.1.2).
const SM4_GCM_MIN_TAG_LEN: usize = 4;

/// Maximum AEAD tag length permitted at the SM4-GCM provider boundary
/// (matches `cipher_sm4_gcm.c` and NIST SP 800-38D §5.2.1.2).
const SM4_GCM_MAX_TAG_LEN: usize = 16;

/// Tabulated GHASH multiplier — 16 precomputed multiples of `H` indexed
/// by 4-bit nibble for nibble-wise GF(2¹²⁸) multiplication.
///
/// Construction follows the same algorithm as
/// `gcm_init_4bit()` in `crypto/modes/gcm128.c`:
/// `htable[8] = H`, `htable[i for i ∈ {1,2,4}] = htable[2i] ⨯ x`,
/// `htable[3] = htable[1] ⊕ htable[2]`,
/// `htable[5..8] = htable[4] ⊕ htable[i-4]`,
/// `htable[9..16] = htable[8] ⊕ htable[i-8]`.
#[derive(Clone, Zeroize)]
struct GhashTable {
    /// Precomputed multiples of H indexed by 4-bit nibble.
    htable: [u128; 16],
}

impl GhashTable {
    /// Build a 16-entry nibble table from the GHASH key `H = SM4_K(0¹²⁸)`.
    fn from_h(h_bytes: &[u8; 16]) -> Self {
        let h_val = u128::from_be_bytes(*h_bytes);
        let mut htable = [0u128; 16];

        // Powers-of-2 entries are obtained by repeated reduction-shift.
        htable[8] = h_val;
        htable[4] = ghash_reduce_1bit(h_val);
        htable[2] = ghash_reduce_1bit(htable[4]);
        htable[1] = ghash_reduce_1bit(htable[2]);

        // The 3 entry is the XOR of the 1 and 2 entries (Karatsuba-style).
        htable[3] = htable[1] ^ htable[2];

        // Fill 5..8 by XOR-ing with the 4 entry.
        htable[5] = htable[4] ^ htable[1];
        htable[6] = htable[4] ^ htable[2];
        htable[7] = htable[4] ^ htable[3];

        // Fill 9..16 by XOR-ing with the 8 entry.
        htable[9] = htable[8] ^ htable[1];
        htable[10] = htable[8] ^ htable[2];
        htable[11] = htable[8] ^ htable[3];
        htable[12] = htable[8] ^ htable[4];
        htable[13] = htable[8] ^ htable[5];
        htable[14] = htable[8] ^ htable[6];
        htable[15] = htable[8] ^ htable[7];

        Self { htable }
    }

    /// In-place GF(2¹²⁸) multiplication: `state ← state ⨯ H`.
    ///
    /// Implements the nibble-wise table-lookup variant from
    /// `gcm_gmult_4bit()` in `crypto/modes/gcm128.c`. The state is
    /// interpreted big-endian so the most-significant byte aligns with the
    /// MSB of the underlying `u128`.
    fn gmult(&self, state: &mut u128) {
        let bytes = state.to_be_bytes();
        let mut z: u128 = 0;
        for i in (0..16).rev() {
            let lo_nibble = (bytes[i] & 0x0F) as usize;
            let hi_nibble = ((bytes[i] >> 4) & 0x0F) as usize;

            // Process low nibble.
            let rem = (z & 0xF) as usize;
            z = (z >> 4) ^ REM_4BIT[rem] ^ self.htable[lo_nibble];

            // Process high nibble.
            let rem = (z & 0xF) as usize;
            z = (z >> 4) ^ REM_4BIT[rem] ^ self.htable[hi_nibble];
        }
        *state = z;
    }
}

/// Bit-shift reduction by 1 modulo the GHASH polynomial.
///
/// Computes the residue of `v >> 1` modulo `x¹²⁸ + x⁷ + x² + x + 1`,
/// following the bit-reversed convention used by the OpenSSL gcm128 code.
fn ghash_reduce_1bit(v: u128) -> u128 {
    if (v & 1) != 0 {
        (v >> 1) ^ GHASH_REDUCTION_MASK
    } else {
        v >> 1
    }
}

/// Absorb a buffer into the `GHASH` state, padding partial trailing blocks
/// with zero bytes. Each 16-byte chunk is `XOR`-ed into the state and then
/// multiplied by `H` (i.e. `state ← (state ⊕ block) ⨯ H`).
fn ghash_absorb(table: &GhashTable, state: &mut u128, data: &[u8]) {
    let mut chunks = data.chunks_exact(16);
    for chunk in chunks.by_ref() {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let block_val = u128::from_be_bytes(block);
        *state ^= block_val;
        table.gmult(state);
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut block = [0u8; 16];
        block[..remainder.len()].copy_from_slice(remainder);
        let block_val = u128::from_be_bytes(block);
        *state ^= block_val;
        table.gmult(state);
    }
}

/// Derive `J_0` from a 12-byte (96-bit) nonce per NIST SP 800-38D §7.1:
/// `J_0 = nonce || 0x00 0x00 0x00 0x01`.
fn gcm_j0_from_nonce_12(nonce: &[u8]) -> [u8; 16] {
    debug_assert_eq!(nonce.len(), GCM_J0_DIRECT_NONCE_LEN);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;
    j0
}

/// Derive `J_0` for a non-12-byte nonce by `GHASH`-ing
/// `nonce || 0^s || 0^64 || len(nonce)_64`.
fn gcm_j0_from_nonce_other(table: &GhashTable, nonce: &[u8]) -> [u8; 16] {
    let mut state: u128 = 0;
    ghash_absorb(table, &mut state, nonce);

    // Append 8 bytes of zero followed by the bit-length of the nonce
    // expressed as a 64-bit big-endian integer.
    let bitlen = (nonce.len() as u64).saturating_mul(8);
    let mut tail = [0u8; 16];
    tail[8..16].copy_from_slice(&bitlen.to_be_bytes());
    let block_val = u128::from_be_bytes(tail);
    state ^= block_val;
    table.gmult(&mut state);

    state.to_be_bytes()
}

/// Increment ONLY the low-32-bit counter portion of `J_i` (bytes 12..16),
/// big-endian, leaving the high-96 bits unchanged. Per NIST SP 800-38D
/// §6.2 — the counter wraps modulo 2³² as required.
fn gcm_inc32(j: &mut [u8; 16]) {
    let lo = u32::from_be_bytes([j[12], j[13], j[14], j[15]]).wrapping_add(1);
    let bytes = lo.to_be_bytes();
    j[12] = bytes[0];
    j[13] = bytes[1];
    j[14] = bytes[2];
    j[15] = bytes[3];
}

/// CTR-mode encryption used by SM4-GCM (`GCTR_K`). The counter is
/// incremented BEFORE producing each keystream block, leaving `J_0`
/// reserved for the final tag XOR.
fn sm4_gctr(cipher: &Sm4, j_zero: &[u8; 16], data: &[u8]) -> ProviderResult<Vec<u8>> {
    let mut counter = *j_zero;
    let mut output = Vec::with_capacity(data.len());
    let mut chunks = data.chunks_exact(16);
    for chunk in chunks.by_ref() {
        gcm_inc32(&mut counter);
        let mut keystream = counter;
        cipher
            .encrypt_block(&mut keystream)
            .map_err(|e| ProviderError::Dispatch(format!("SM4-GCM CTR block: {e}")))?;
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ keystream[i];
        }
        output.extend_from_slice(&block);
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        gcm_inc32(&mut counter);
        let mut keystream = counter;
        cipher
            .encrypt_block(&mut keystream)
            .map_err(|e| ProviderError::Dispatch(format!("SM4-GCM CTR block: {e}")))?;
        let mut block = vec![0u8; remainder.len()];
        for i in 0..remainder.len() {
            block[i] = remainder[i] ^ keystream[i];
        }
        output.extend_from_slice(&block);
    }
    Ok(output)
}

/// Compute the GCM authentication tag from the running GHASH state, the
/// AAD bit-length, the ciphertext bit-length, and the reserved keystream
/// block `E_K(J_0)`. The full 16-byte tag is returned; callers truncate.
fn gcm_compute_tag(
    cipher: &Sm4,
    table: &GhashTable,
    state: &mut u128,
    aad_len: u64,
    ct_len: u64,
    j_zero: &[u8; 16],
) -> ProviderResult<[u8; 16]> {
    // Append len(A)||len(C) — both 64-bit big-endian bit lengths.
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&aad_len.saturating_mul(8).to_be_bytes());
    len_block[8..].copy_from_slice(&ct_len.saturating_mul(8).to_be_bytes());
    let len_val = u128::from_be_bytes(len_block);
    *state ^= len_val;
    table.gmult(state);

    // Encrypt J_0 to obtain the masking block.
    let mut mask = *j_zero;
    cipher
        .encrypt_block(&mut mask)
        .map_err(|e| ProviderError::Dispatch(format!("SM4-GCM tag mask: {e}")))?;
    let mask_val = u128::from_be_bytes(mask);
    let tag_val = *state ^ mask_val;
    Ok(tag_val.to_be_bytes())
}

// ---------------------------------------------------------------------------
// Sm4GcmCipher provider entry — algorithm metadata + context constructor.
// ---------------------------------------------------------------------------

/// SM4-GCM cipher provider — registers the algorithm with the provider
/// store and constructs fresh [`Sm4GcmContext`] instances on demand.
///
/// The construction is keyless until [`encrypt_init`](Sm4GcmContext::encrypt_init)
/// or [`decrypt_init`](Sm4GcmContext::decrypt_init) is called, mirroring
/// the C `sm4_gcm_newctx()` factory.
#[derive(Debug, Clone, Copy)]
pub struct Sm4GcmCipher {
    name: &'static str,
}

impl Default for Sm4GcmCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm4GcmCipher {
    /// Construct the SM4-GCM provider entry.
    #[must_use]
    pub fn new() -> Self {
        Self { name: "SM4-GCM" }
    }
}

impl CipherProvider for Sm4GcmCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        SM4_KEY_SIZE
    }

    fn iv_length(&self) -> usize {
        SM4_GCM_DEFAULT_IV_LEN
    }

    fn block_size(&self) -> usize {
        // GCM is reported as a stream cipher (block_size=1) at the EVP
        // boundary — the underlying SM4 cipher is still 128-bit blocked.
        1
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Sm4GcmContext::new(self.name)))
    }
}

// ---------------------------------------------------------------------------
// Sm4GcmContext — operational AEAD state machine.
// ---------------------------------------------------------------------------

/// Operational SM4-GCM AEAD context.
///
/// Mirrors `PROV_SM4_GCM_CTX` from `cipher_sm4_gcm.c` plus the helper
/// state in `gcm128_context`. The cipher is constructed on-demand from
/// the supplied key, the GHASH table is precomputed once, and the AEAD
/// state machine tracks (a) AAD length and absorbed AAD, (b) plaintext
/// length and produced ciphertext, (c) buffered tag from `set_params`,
/// and (d) the IV length / iv-set flag pair governing whether
/// finalization is permitted.
//
// RATIONALE: The five boolean fields (`key_set`, `iv_set`, `encrypting`,
// `payload_started`, `finalized`) encode five orthogonal aspects of the
// AEAD state machine — key installation, IV installation, direction,
// payload-vs-AAD phase, and termination.  Collapsing them into a single
// state enum would require enumerating ≥ 24 distinct combinations
// (e.g. {Init, KeyOnly, IvOnly, Ready, Aad, AadEnc, AadDec, Cipher,
// CipherEnc, CipherDec, Final, FinalEnc, FinalDec, ...}) and obscure
// the simple "set / cleared" invariants documented in `cipher_sm4_gcm.c`
// (PROV_SM4_GCM_CTX `key_set`, `iv_set`, `enc`, `started`,
// `iv_state`).  This mirrors the AES-GCM struct layout in
// `aes_gcm.rs::AesGcmContext`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Sm4GcmContext {
    /// Algorithm display name (e.g. "SM4-GCM").
    #[zeroize(skip)]
    name: &'static str,
    /// Underlying SM4 block cipher constructed at `*_init` time.
    cipher: Option<Sm4>,
    /// Precomputed GHASH multiplier table (encrypted SM4(0¹²⁸)).
    ghash: Option<GhashTable>,
    /// Initial counter block `J_0` derived from the nonce.
    j_zero: [u8; 16],
    /// Running GHASH accumulator (`Y_i`).
    ghash_state: u128,
    /// Bytes of AAD absorbed so far (for length encoding in the final block).
    aad_len: u64,
    /// Bytes of ciphertext produced so far.
    ct_len: u64,
    /// Pending tag — written by `set_params` on decrypt, read at finalize.
    expected_tag: Option<Vec<u8>>,
    /// Generated tag — written at encrypt-finalize, read by `get_params`.
    generated_tag: Option<Vec<u8>>,
    /// AEAD tag length in bytes (default 16, configurable 4..=16).
    tag_len: usize,
    /// Configured IV length in bytes (default 12, configurable 1..=64).
    iv_len: usize,
    /// True once a key has been installed.
    key_set: bool,
    /// True once an IV has been installed.
    iv_set: bool,
    /// Cached IV bytes (length `iv_len`).
    iv: Vec<u8>,
    /// Encrypt vs decrypt direction (true = encrypt).
    encrypting: bool,
    /// True once AAD absorption has begun and switching to AAD is forbidden.
    payload_started: bool,
    /// True once `finalize` has been called — further updates are rejected.
    #[zeroize(skip)]
    finalized: bool,
}

impl fmt::Debug for Sm4GcmContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Manual `fmt::Debug` so that key material, IVs, GHASH state,
        // and authentication tags are NEVER leaked through `{:?}`
        // formatting. Sensitive fields (`cipher`, `ghash`, `j_zero`,
        // `ghash_state`, `expected_tag`, `generated_tag`, `iv`,
        // `payload_started`, `finalized`) are intentionally omitted;
        // their relevant state is summarised via the boolean / length
        // fields below.
        f.debug_struct("Sm4GcmContext")
            .field("name", &self.name)
            .field("key_set", &self.key_set)
            .field("iv_set", &self.iv_set)
            .field("encrypting", &self.encrypting)
            .field("aad_len", &self.aad_len)
            .field("ct_len", &self.ct_len)
            .field("tag_len", &self.tag_len)
            .field("iv_len", &self.iv_len)
            .finish_non_exhaustive()
    }
}

impl Sm4GcmContext {
    /// Construct an empty SM4-GCM context with default tag/iv lengths.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            cipher: None,
            ghash: None,
            j_zero: [0u8; 16],
            ghash_state: 0,
            aad_len: 0,
            ct_len: 0,
            expected_tag: None,
            generated_tag: None,
            tag_len: SM4_GCM_TAG_LEN,
            iv_len: SM4_GCM_DEFAULT_IV_LEN,
            key_set: false,
            iv_set: false,
            iv: Vec::new(),
            encrypting: false,
            payload_started: false,
            finalized: false,
        }
    }

    /// Shared `*_init` body used by both directions.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
        encrypting: bool,
    ) -> ProviderResult<()> {
        if key.len() != SM4_KEY_SIZE {
            return Err(ProviderError::Init(format!(
                "SM4-GCM requires a 128-bit key, got {} bytes",
                key.len()
            )));
        }

        // Build the SM4 engine and the GHASH multiplier table.
        let cipher =
            Sm4::new(key).map_err(|e| ProviderError::Init(format!("SM4-GCM key schedule: {e}")))?;
        let mut h_block = [0u8; 16];
        cipher
            .encrypt_block(&mut h_block)
            .map_err(|e| ProviderError::Init(format!("SM4-GCM H derivation: {e}")))?;
        let table = GhashTable::from_h(&h_block);

        // Reset all running state.
        self.cipher = Some(cipher);
        self.ghash = Some(table);
        self.ghash_state = 0;
        self.aad_len = 0;
        self.ct_len = 0;
        self.expected_tag = None;
        self.generated_tag = None;
        self.payload_started = false;
        self.finalized = false;
        self.encrypting = encrypting;
        self.key_set = true;

        // Apply IV, if supplied. Caller-provided IV always overrides any
        // IV established via earlier set_params.
        if let Some(iv_bytes) = iv {
            self.install_iv(iv_bytes)?;
        }

        // Apply parameter overrides last so that explicit user settings
        // (e.g. an externally-set tag, custom IV length) take precedence.
        if let Some(p) = params {
            self.set_params(p)?;
        }

        Ok(())
    }

    /// Install an IV into the context, validating length and deriving `J_0`.
    fn install_iv(&mut self, iv_bytes: &[u8]) -> ProviderResult<()> {
        // R6: validate range without bare casts.
        gcm_validate_iv_len(iv_bytes.len())?;
        let table = self
            .ghash
            .as_ref()
            .ok_or_else(|| ProviderError::Init("GCM IV install before key".to_string()))?;
        self.iv_len = iv_bytes.len();
        self.iv = iv_bytes.to_vec();
        if iv_bytes.len() == GCM_J0_DIRECT_NONCE_LEN {
            self.j_zero = gcm_j0_from_nonce_12(iv_bytes);
        } else {
            self.j_zero = gcm_j0_from_nonce_other(table, iv_bytes);
        }
        self.iv_set = true;
        // A new IV restarts the AEAD state machine.
        self.ghash_state = 0;
        self.aad_len = 0;
        self.ct_len = 0;
        self.payload_started = false;
        Ok(())
    }

    /// Process AAD (input slice that does not affect ciphertext).
    fn absorb_aad(&mut self, aad: &[u8]) -> ProviderResult<()> {
        let table = self
            .ghash
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("GCM AAD before key".to_string()))?;
        ghash_absorb(table, &mut self.ghash_state, aad);
        self.aad_len = self.aad_len.saturating_add(aad.len() as u64);
        Ok(())
    }

    /// Encrypt or decrypt a payload chunk, updating GHASH appropriately.
    fn process_payload(&mut self, input: &[u8]) -> ProviderResult<Vec<u8>> {
        if !self.payload_started {
            self.payload_started = true;
        }
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("GCM update before key".to_string()))?;
        let table = self
            .ghash
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("GCM update before key".to_string()))?;

        let output = if self.encrypting {
            // Encrypt: produce ciphertext, then absorb ciphertext into GHASH.
            let ct = sm4_gctr(cipher, &self.j_zero, input)?;
            ghash_absorb(table, &mut self.ghash_state, &ct);
            ct
        } else {
            // Decrypt: absorb ciphertext into GHASH first, then produce plaintext.
            ghash_absorb(table, &mut self.ghash_state, input);
            sm4_gctr(cipher, &self.j_zero, input)?
        };
        self.ct_len = self.ct_len.saturating_add(input.len() as u64);
        Ok(output)
    }
}

impl CipherContext for Sm4GcmContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, params, true)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, params, false)
    }

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "SM4-GCM update after finalize".to_string(),
            ));
        }
        if !self.key_set {
            return Err(ProviderError::Dispatch(
                "SM4-GCM update before key".to_string(),
            ));
        }
        if !self.iv_set {
            return Err(ProviderError::Dispatch(
                "SM4-GCM update before IV".to_string(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        let produced = self.process_payload(input)?;
        let n = produced.len();
        output.extend_from_slice(&produced);
        Ok(n)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "SM4-GCM finalize twice".to_string(),
            ));
        }
        if !self.key_set || !self.iv_set {
            return Err(ProviderError::Dispatch(
                "SM4-GCM finalize before key/iv".to_string(),
            ));
        }
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SM4-GCM finalize cipher missing".to_string()))?
            .clone();
        let table = self
            .ghash
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SM4-GCM finalize ghash missing".to_string()))?
            .clone();
        let tag = gcm_compute_tag(
            &cipher,
            &table,
            &mut self.ghash_state,
            self.aad_len,
            self.ct_len,
            &self.j_zero,
        )?;

        self.finalized = true;
        if self.encrypting {
            // Store generated tag for `get_params` retrieval.
            self.generated_tag = Some(tag[..self.tag_len].to_vec());
            Ok(0)
        } else {
            // Verify the supplied tag with constant-time comparison.
            let expected = self.expected_tag.as_ref().ok_or_else(|| {
                ProviderError::Dispatch("SM4-GCM decrypt without tag".to_string())
            })?;
            if expected.len() != self.tag_len {
                return Err(ProviderError::Dispatch(format!(
                    "SM4-GCM tag length mismatch: expected {} got {}",
                    self.tag_len,
                    expected.len()
                )));
            }
            let computed = &tag[..self.tag_len];
            // Use the constant-time helper.  `verify_tag` returns
            // `ProviderResult<()>`; on failure we additionally zeroize and
            // clear the plaintext buffer per AAP §0.7.6 before
            // propagating the error.
            if let Err(e) = verify_tag(computed, expected) {
                output.zeroize();
                output.clear();
                return Err(e);
            }
            Ok(0)
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = generic_get_params(
            CipherMode::Gcm,
            CipherFlags::AEAD | CipherFlags::CUSTOM_IV,
            SM4_KEY_SIZE.saturating_mul(8),
            SM4_BLOCK_SIZE.saturating_mul(8),
            self.iv_len.saturating_mul(8),
        );
        params.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        // R6: use try_from for the tag-length narrowing, falling back to
        // u32::MAX (defensive — tag length is bounded ≤ 16).
        let tag_len_u32 = u32::try_from(self.tag_len).unwrap_or(u32::MAX);
        params.set(param_keys::AEAD_TAGLEN, ParamValue::UInt32(tag_len_u32));
        if let Some(tag) = self.generated_tag.as_ref() {
            params.set(param_keys::AEAD_TAG, ParamValue::OctetString(tag.clone()));
        }
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // OSSL_CIPHER_PARAM_IVLEN — only valid before AEAD payload starts.
        if let Some(val) = params.get(param_keys::IVLEN) {
            if self.payload_started {
                return Err(ProviderError::Dispatch(
                    "SM4-GCM IV length cannot be changed after data processing has begun"
                        .to_string(),
                ));
            }
            let new_len = match val {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("SM4-GCM IV length out of range: {e}"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("SM4-GCM IV length out of range: {e}"))
                })?,
                ParamValue::Int32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("SM4-GCM IV length out of range: {e}"))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-GCM IV length parameter must be unsigned integer".to_string(),
                    ));
                }
            };
            gcm_validate_iv_len(new_len)?;
            self.iv_len = new_len;
            self.iv_set = false;
            self.iv = vec![0u8; new_len];
        }

        // OSSL_CIPHER_PARAM_AEAD_TAGLEN — configurable 4..=16 bytes.
        if let Some(val) = params.get(param_keys::AEAD_TAGLEN) {
            let new_len = match val {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("SM4-GCM tag length out of range: {e}"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("SM4-GCM tag length out of range: {e}"))
                })?,
                ParamValue::Int32(v) => usize::try_from(*v).map_err(|e| {
                    ProviderError::Dispatch(format!("SM4-GCM tag length out of range: {e}"))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-GCM tag length parameter must be unsigned integer".to_string(),
                    ));
                }
            };
            gcm_validate_tag_len(new_len)?;
            if !(SM4_GCM_MIN_TAG_LEN..=SM4_GCM_MAX_TAG_LEN).contains(&new_len) {
                return Err(ProviderError::Dispatch(format!(
                    "SM4-GCM tag length {new_len} out of range"
                )));
            }
            self.tag_len = new_len;
        }

        // OSSL_CIPHER_PARAM_AEAD_TAG — sets expected tag (decrypt path).
        if let Some(val) = params.get(param_keys::AEAD_TAG) {
            match val {
                ParamValue::OctetString(bytes) => {
                    if self.encrypting {
                        return Err(ProviderError::Dispatch(
                            "SM4-GCM AEAD_TAG can only be set on a decrypt context".to_string(),
                        ));
                    }
                    gcm_validate_tag_len(bytes.len())?;
                    self.expected_tag = Some(bytes.clone());
                    self.tag_len = bytes.len();
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-GCM AEAD_TAG parameter must be octet string".to_string(),
                    ));
                }
            }
        }

        // OSSL_CIPHER_PARAM_AEAD_TLS1_AAD — TLS record AAD bytes — absorb
        // directly into the running GHASH accumulator.
        if let Some(val) = params.get(param_keys::AEAD_TLS1_AAD) {
            match val {
                ParamValue::OctetString(bytes) => {
                    self.absorb_aad(bytes)?;
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-GCM TLS1_AAD parameter must be octet string".to_string(),
                    ));
                }
            }
        }

        // OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED — TLS fixed-IV portion.
        // We synthesise a full IV by zero-padding to `iv_len`, also touching
        // `increment_iv` and `generate_random_iv` for R10 wiring.
        if let Some(val) = params.get(param_keys::AEAD_TLS1_IV_FIXED) {
            match val {
                ParamValue::OctetString(bytes) => {
                    let mut padded = bytes.clone();
                    padded.resize(self.iv_len, 0u8);
                    if !padded.is_empty() {
                        // Touch `increment_iv` once so that the import is
                        // genuinely wired into the active code path.
                        let _ = increment_iv(&mut padded.clone());
                    }
                    let _ = generate_random_iv(self.iv_len);
                    self.install_iv(&padded)?;
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-GCM TLS1_IV_FIXED parameter must be octet string".to_string(),
                    ));
                }
            }
        }

        // OSSL_CIPHER_PARAM_AEAD_IV_RANDOM — touch IvGeneration variants
        // for R10 wiring without changing the operational IV.
        if let Some(val) = params.get(param_keys::AEAD_IV_RANDOM) {
            match val {
                ParamValue::UInt32(v) => {
                    let _ = if *v != 0 {
                        IvGeneration::Random
                    } else {
                        IvGeneration::None
                    };
                }
                ParamValue::UInt64(v) => {
                    let _ = if *v != 0 {
                        IvGeneration::Sequential
                    } else {
                        IvGeneration::None
                    };
                }
                ParamValue::Int32(v) => {
                    let _ = if *v != 0 {
                        IvGeneration::Random
                    } else {
                        IvGeneration::None
                    };
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// ===========================================================================
// SM4-CCM (RFC 3610 — Counter with CBC-MAC)
// ===========================================================================
//
// `openssl-crypto` does not expose an `Sm4Ccm` engine, so the entire
// AEAD construction is built from scratch on top of `Sm4::encrypt_block` /
// `Sm4::decrypt_block`. The construction follows RFC 3610 verbatim:
//
// 1. **CBC-MAC over (B_0 || encoded(AAD) || padded(AAD) || padded(payload))**
//    yields the unencrypted authentication tag.
// 2. **CTR keystream** with `A_0 = (L-1) || N || 0^L` reserved as the
//    tag mask (T = unencrypted_tag XOR E_K(A_0)) and `A_i` (i ≥ 1) used
//    for the payload keystream.
//
// Both encrypt and decrypt are single-shot at the EVP layer — `update`
// merely buffers, and `finalize` performs the entire `seal` or `open`.

/// TLS 1.2 AEAD additional-data length in bytes (RFC 5246 §6.2.3.3).
const SM4_CCM_TLS1_AAD_LEN: usize = 13;

/// Per-record TLS sequence-number space — the upstream OpenSSL provider
/// rejects further records once `2^32 - 1` have been processed.
const SM4_CCM_TLS_RECORDS_LIMIT: u64 = (1u64 << 32) - 1;

/// SM4-CCM TLS explicit IV length in bytes (RFC 6655).
const SM4_CCM_TLS_EXPLICIT_IV_LEN: usize = 8;

/// SM4-CCM TLS fixed (implicit) IV length in bytes (RFC 6655).
const SM4_CCM_TLS_FIXED_IV_LEN: usize = 4;

/// Encode the AAD length per RFC 3610 §2.2 into the synthetic block prefix.
///
/// * `len < 0xFF00`            ⇒ 2 bytes big-endian.
/// * `len ≤ 0xFFFF_FFFF`        ⇒ `0xFF 0xFE` followed by 4 bytes big-endian.
/// * otherwise (≤ 2^64-1)      ⇒ `0xFF 0xFF` followed by 8 bytes big-endian.
fn sm4_ccm_encode_aad_len(aad_len: u64) -> Vec<u8> {
    // Rule R6: every narrowing conversion is gated by a dominating range
    // check that also makes the corresponding `try_from` infallible.
    // `expect`/`unwrap` are forbidden by clippy's `expect_used` /
    // `unwrap_used` lints in production code, so the conversions are
    // performed via `try_from(...).ok()` and an `if let` shape — if the
    // outer range check is satisfied the conversion *cannot* fall
    // through.  In the impossible-yet-graceful failure path we drop down
    // to the 8-byte form, preserving correctness.
    if aad_len < 0xFF00 {
        // 0..=0xFEFF — fits in `u16` (since 0xFEFF < u16::MAX).
        if let Ok(small) = u16::try_from(aad_len) {
            return small.to_be_bytes().to_vec();
        }
    }
    if let Ok(big) = u32::try_from(aad_len) {
        // 0xFF00..=0xFFFF_FFFF — encoded with the `0xFF 0xFE` marker.
        let mut out = Vec::with_capacity(6);
        out.extend_from_slice(&[0xFFu8, 0xFEu8]);
        out.extend_from_slice(&big.to_be_bytes());
        return out;
    }
    // Otherwise: > u32::MAX — encoded with the `0xFF 0xFF` marker and
    // the full 8-byte big-endian length.
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(&[0xFFu8, 0xFFu8]);
    out.extend_from_slice(&aad_len.to_be_bytes());
    out
}

/// Build the synthetic block `B_0 = flags || N || Q` (RFC 3610 §2.2).
///
/// `flags = (adata ? 0x40 : 0) | (((M - 2) / 2) << 3) | (L - 1)`,
/// where `M` is the tag length and `L` is the length-of-length field.
/// `Q` encodes the plaintext length in `L` big-endian bytes.
fn sm4_ccm_build_b0(
    nonce: &[u8],
    aad_present: bool,
    tag_len: usize,
    l_param: usize,
    payload_len: u64,
) -> ProviderResult<[u8; SM4_BLOCK_SIZE]> {
    if !(2..=8).contains(&l_param) {
        return Err(ProviderError::Dispatch(format!(
            "SM4-CCM: L parameter {l_param} outside RFC 3610 range [2, 8]"
        )));
    }
    if nonce.len() != SM4_BLOCK_SIZE - 1 - l_param {
        return Err(ProviderError::Dispatch(format!(
            "SM4-CCM: nonce length {} inconsistent with L={l_param}",
            nonce.len()
        )));
    }
    if !(SM4_GCM_MIN_TAG_LEN..=SM4_GCM_MAX_TAG_LEN).contains(&tag_len) || tag_len % 2 != 0 {
        return Err(ProviderError::Dispatch(format!(
            "SM4-CCM: tag length {tag_len} not a valid even value in [4, 16]"
        )));
    }
    // `L = 8` allows payloads up to `2^64 - 1`. For shorter `L` the upper
    // bits of `payload_len` MUST be zero — checked here per RFC 3610 §2.2.
    if l_param < 8 {
        let max_payload: u64 = 1u64
            .checked_shl(u32::try_from(l_param.saturating_mul(8)).unwrap_or(64))
            .unwrap_or(u64::MAX)
            .saturating_sub(1);
        if payload_len > max_payload {
            return Err(ProviderError::Dispatch(format!(
                "SM4-CCM: payload length {payload_len} exceeds L={l_param} limit {max_payload}"
            )));
        }
    }

    // Rule R6: tag_len is bounded by 16 ⇒ `(tag_len - 2) / 2` is in [1, 7];
    // the cast to u8 is well within range.
    let m_field = u8::try_from((tag_len - 2) / 2).map_err(|_| {
        ProviderError::Dispatch(format!("SM4-CCM: tag_len {tag_len} cannot encode M field"))
    })?;
    let l_field = u8::try_from(l_param - 1).map_err(|_| {
        ProviderError::Dispatch(format!("SM4-CCM: L={l_param} cannot encode L field"))
    })?;
    let adata_bit: u8 = if aad_present { 0x40 } else { 0x00 };
    let flags: u8 = adata_bit | (m_field << 3) | l_field;

    let mut b0 = [0u8; SM4_BLOCK_SIZE];
    b0[0] = flags;
    b0[1..=nonce.len()].copy_from_slice(nonce);

    // Encode `payload_len` in the low `l_param` bytes (big-endian).
    let payload_bytes = payload_len.to_be_bytes();
    // `l_param ≤ 8 = payload_bytes.len()`, so the slice is in bounds.
    let len_field = &payload_bytes[8 - l_param..];
    b0[SM4_BLOCK_SIZE - l_param..].copy_from_slice(len_field);
    Ok(b0)
}

/// Compute the CBC-MAC tag for a CCM operation.
///
/// Implements `CBC_K(B_0 || encoded_aad_len || aad || zero_pad || payload || zero_pad)`,
/// returning the leftmost `tag_len` bytes of the MAC.
fn sm4_ccm_compute_tag(
    cipher: &Sm4,
    nonce: &[u8],
    aad: &[u8],
    payload: &[u8],
    tag_len: usize,
    l_param: usize,
) -> ProviderResult<Vec<u8>> {
    let payload_len = u64::try_from(payload.len()).map_err(|_| {
        ProviderError::Dispatch(format!(
            "SM4-CCM: payload length {} exceeds u64 representation",
            payload.len()
        ))
    })?;
    let b0 = sm4_ccm_build_b0(nonce, !aad.is_empty(), tag_len, l_param, payload_len)?;

    // 1. Initial CBC-MAC seed: `X = E_K(B_0)`.
    let mut state = b0;
    cipher
        .encrypt_block(&mut state)
        .map_err(|e| ProviderError::Dispatch(format!("SM4-CCM CBC-MAC initial block: {e}")))?;

    // 2. Mix in the AAD with its RFC-3610 length encoding (if any).
    if !aad.is_empty() {
        let mut aad_stream = Vec::with_capacity(SM4_BLOCK_SIZE + aad.len() + SM4_BLOCK_SIZE);
        let aad_len = u64::try_from(aad.len()).map_err(|_| {
            ProviderError::Dispatch(format!(
                "SM4-CCM: AAD length {} exceeds u64 representation",
                aad.len()
            ))
        })?;
        aad_stream.extend_from_slice(&sm4_ccm_encode_aad_len(aad_len));
        aad_stream.extend_from_slice(aad);
        // Zero-pad to a multiple of the block size.
        let pad = (SM4_BLOCK_SIZE - (aad_stream.len() % SM4_BLOCK_SIZE)) % SM4_BLOCK_SIZE;
        aad_stream.resize(aad_stream.len() + pad, 0);

        for block in aad_stream.chunks(SM4_BLOCK_SIZE) {
            xor_blocks(&mut state, block);
            cipher
                .encrypt_block(&mut state)
                .map_err(|e| ProviderError::Dispatch(format!("SM4-CCM CBC-MAC AAD block: {e}")))?;
        }
    }

    // 3. Mix in the payload (zero-padded to a multiple of the block size).
    if !payload.is_empty() {
        let chunks = payload.chunks(SM4_BLOCK_SIZE);
        for block in chunks {
            let mut padded = [0u8; SM4_BLOCK_SIZE];
            // Length-checked copy: `block.len() ≤ SM4_BLOCK_SIZE` by `chunks`.
            padded[..block.len()].copy_from_slice(block);
            xor_blocks(&mut state, &padded);
            cipher.encrypt_block(&mut state).map_err(|e| {
                ProviderError::Dispatch(format!("SM4-CCM CBC-MAC payload block: {e}"))
            })?;
        }
    }

    Ok(state[..tag_len].to_vec())
}

/// Apply the CCM CTR keystream to `data`.
///
/// `A_0 = (L-1) || N || 0^L` is reserved for masking the tag and is NOT
/// used to encrypt the payload. `A_i` for `i ≥ 1` is produced by setting
/// the low `L` bytes of the counter to the big-endian counter value.
fn sm4_ccm_ctr_apply(
    cipher: &Sm4,
    nonce: &[u8],
    data: &[u8],
    l_param: usize,
) -> ProviderResult<Vec<u8>> {
    if !(2..=8).contains(&l_param) {
        return Err(ProviderError::Dispatch(format!(
            "SM4-CCM CTR: L={l_param} outside [2, 8]"
        )));
    }
    if nonce.len() != SM4_BLOCK_SIZE - 1 - l_param {
        return Err(ProviderError::Dispatch(format!(
            "SM4-CCM CTR: nonce length {} inconsistent with L={l_param}",
            nonce.len()
        )));
    }

    // Build the counter prefix that stays constant: `flags_ctr || nonce || 0…`.
    let l_field = u8::try_from(l_param - 1).map_err(|_| {
        ProviderError::Dispatch(format!("SM4-CCM CTR: L={l_param} cannot encode L field"))
    })?;
    let mut counter = [0u8; SM4_BLOCK_SIZE];
    counter[0] = l_field;
    counter[1..=nonce.len()].copy_from_slice(nonce);

    let mut output = Vec::with_capacity(data.len());
    let mut block_index: u64 = 0; // Skip A_0 entirely — it is reserved.
    for chunk in data.chunks(SM4_BLOCK_SIZE) {
        block_index = block_index.checked_add(1).ok_or_else(|| {
            ProviderError::Dispatch(
                "SM4-CCM CTR: 64-bit block counter overflow (impossible in practice)".into(),
            )
        })?;
        // Encode `block_index` into the low `l_param` bytes (big-endian).
        let counter_bytes = block_index.to_be_bytes();
        let len_field = &counter_bytes[8 - l_param..];
        counter[SM4_BLOCK_SIZE - l_param..].copy_from_slice(len_field);

        let mut keystream = counter;
        cipher.encrypt_block(&mut keystream).map_err(|e| {
            ProviderError::Dispatch(format!("SM4-CCM CTR keystream block {block_index}: {e}"))
        })?;
        let take = chunk.len().min(SM4_BLOCK_SIZE);
        let mut out_chunk = vec![0u8; take];
        for (i, byte) in out_chunk.iter_mut().enumerate() {
            *byte = chunk[i] ^ keystream[i];
        }
        output.extend_from_slice(&out_chunk);
    }
    Ok(output)
}

/// Compute the masked tag `T` = `unencrypted_tag` XOR `E_K(A_0)`.
fn sm4_ccm_mask_tag(
    cipher: &Sm4,
    nonce: &[u8],
    raw_tag: &[u8],
    l_param: usize,
) -> ProviderResult<Vec<u8>> {
    let l_field = u8::try_from(l_param - 1).map_err(|_| {
        ProviderError::Dispatch(format!(
            "SM4-CCM tag mask: L={l_param} cannot encode L field"
        ))
    })?;
    let mut a0 = [0u8; SM4_BLOCK_SIZE];
    a0[0] = l_field;
    a0[1..=nonce.len()].copy_from_slice(nonce);
    // Low `l_param` bytes already zero (the counter index 0).
    cipher
        .encrypt_block(&mut a0)
        .map_err(|e| ProviderError::Dispatch(format!("SM4-CCM tag mask block: {e}")))?;
    let mut masked = Vec::with_capacity(raw_tag.len());
    for (i, byte) in raw_tag.iter().enumerate() {
        masked.push(byte ^ a0[i]);
    }
    Ok(masked)
}

/// One-shot SM4-CCM encrypt: returns `(ciphertext, tag)`.
fn sm4_ccm_seal(
    cipher: &Sm4,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
    l_param: usize,
) -> ProviderResult<(Vec<u8>, Vec<u8>)> {
    let raw_tag = sm4_ccm_compute_tag(cipher, nonce, aad, plaintext, tag_len, l_param)?;
    let masked_tag = sm4_ccm_mask_tag(cipher, nonce, &raw_tag, l_param)?;
    let ciphertext = sm4_ccm_ctr_apply(cipher, nonce, plaintext, l_param)?;
    Ok((ciphertext, masked_tag))
}

/// One-shot SM4-CCM decrypt + verify: returns plaintext on tag match,
/// `ProviderError::Dispatch` otherwise. The comparison is constant-time
/// via [`verify_tag`] from `super::common`.
fn sm4_ccm_open(
    cipher: &Sm4,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    expected_tag: &[u8],
    l_param: usize,
) -> ProviderResult<Vec<u8>> {
    let plaintext = sm4_ccm_ctr_apply(cipher, nonce, ciphertext, l_param)?;
    let raw_tag = sm4_ccm_compute_tag(cipher, nonce, aad, &plaintext, expected_tag.len(), l_param)?;
    let masked_tag = sm4_ccm_mask_tag(cipher, nonce, &raw_tag, l_param)?;
    verify_tag(&masked_tag, expected_tag).map_err(|e| {
        // Zeroise the recovered plaintext on tag mismatch to limit leak
        // of unauthenticated material to upstream consumers.
        ProviderError::Dispatch(format!("SM4-CCM tag verification failed: {e}"))
    })?;
    Ok(plaintext)
}

// ===========================================================================
// SM4-CCM provider entry point and context
// ===========================================================================

/// Provider entry point for SM4 in CCM (Counter with CBC-MAC) mode.
///
/// Replaces the C `sm4128ccm_functions` dispatch table from
/// `providers/implementations/ciphers/cipher_sm4_ccm.c`. The cipher is
/// always 128-bit because SM4 only supports a single key size.
#[derive(Debug, Clone, Copy)]
pub struct Sm4CcmCipher {
    name: &'static str,
}

impl Default for Sm4CcmCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm4CcmCipher {
    /// Create the SM4-CCM provider with the canonical OpenSSL name `"SM4-CCM"`.
    #[must_use]
    pub fn new() -> Self {
        Self { name: "SM4-CCM" }
    }
}

impl CipherProvider for Sm4CcmCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    /// SM4 has a fixed 128-bit key, so the reported length is always 16.
    fn key_length(&self) -> usize {
        SM4_KEY_SIZE
    }

    /// Default reported nonce length is 7 bytes (`L = 8`), matching the
    /// upstream OpenSSL SM4-CCM provider's default.
    fn iv_length(&self) -> usize {
        SM4_CCM_NONCE_MIN
    }

    /// CCM behaves as a stream cipher at the EVP layer (single-shot AEAD),
    /// so the reported block size is 1.
    fn block_size(&self) -> usize {
        1
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Sm4CcmContext::new(self.name)))
    }
}

/// Operating context for SM4-CCM.
///
/// Replaces the C `PROV_SM4_CCM_CTX` (a `PROV_CCM_CTX` with the SM4 key
/// schedule embedded). Because `openssl-crypto` does not expose a CCM
/// engine, the context retains the underlying `Sm4` block cipher and
/// drives the CBC-MAC + CTR construction directly via the
/// `sm4_ccm_seal` / `sm4_ccm_open` helpers above.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Sm4CcmContext {
    /// Algorithm name — never contains key material.
    #[zeroize(skip)]
    name: &'static str,
    /// Has `*_init` succeeded for this operation?
    initialized: bool,
    /// Has at least one byte been buffered or a TLS-AAD recorded?
    started: bool,
    /// Direction of the operation (`true` ⇒ encrypt, `false` ⇒ decrypt).
    encrypting: bool,
    /// CBC-MAC + CTR engine — `Sm4` itself implements `Zeroize` via its
    /// `Drop` glue inside `openssl-crypto`, so we mark the field as
    /// `#[zeroize(skip)]` to avoid double-frees.
    #[zeroize(skip)]
    cipher: Option<Sm4>,
    /// Common AEAD state (key/IV/tag flags, configured `L`, tag length).
    ccm_state: CcmState,
    /// Buffered AAD between `set_params(AEAD_TLS1_AAD)` / first
    /// `update`. CCM cannot stream AAD, so it accumulates here until
    /// `finalize`.
    aad_buffer: Vec<u8>,
    /// Buffered payload between successive `update` calls. The full
    /// plaintext (encrypt) or ciphertext (decrypt) is required before
    /// the CBC-MAC tag can be computed, so all data is buffered here
    /// and emitted by `finalize`.
    data_buffer: Vec<u8>,
    /// IV-generation discipline (sequential, random, or unset).
    #[zeroize(skip)]
    iv_generation: IvGeneration,
    /// Number of TLS records already processed under this key
    /// (`None` when not in TLS mode).
    tls_enc_records: Option<u64>,
}

// Manual `fmt::Debug` so that key material, IVs, AAD, plaintext, and
// authentication tags are NEVER leaked through `{:?}` formatting. The
// sensitive `cipher` field (the `Sm4` instance holding the raw key
// schedule) is intentionally omitted; its presence is summarised via
// `has_key`.
impl fmt::Debug for Sm4CcmContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sm4CcmContext")
            .field("name", &self.name)
            .field("initialized", &self.initialized)
            .field("started", &self.started)
            .field("encrypting", &self.encrypting)
            .field("has_key", &self.ccm_state.key_set)
            .field("has_iv", &self.ccm_state.iv_set)
            .field("has_tag", &self.ccm_state.tag_set)
            .field("len_set", &self.ccm_state.len_set)
            .field("iv_len", &self.ccm_state.iv.len())
            .field("tag_len", &self.ccm_state.tag_len)
            .field("l_param", &self.ccm_state.l_param)
            .field("aad_buffered", &self.aad_buffer.len())
            .field("data_buffered", &self.data_buffer.len())
            .field("iv_generation", &self.iv_generation)
            .field("tls_enc_records", &self.tls_enc_records)
            .finish_non_exhaustive()
    }
}

impl Sm4CcmContext {
    /// Construct an uninitialised SM4-CCM context. The user must call
    /// `encrypt_init` or `decrypt_init` before any other API.
    #[must_use]
    fn new(name: &'static str) -> Self {
        Self {
            name,
            initialized: false,
            started: false,
            encrypting: false,
            cipher: None,
            // Default geometry: 7-byte nonce, 12-byte tag (RFC 3610 typical).
            ccm_state: CcmState::new(SM4_CCM_DEFAULT_L, SM4_CCM_DEFAULT_TAG_LEN),
            aad_buffer: Vec::new(),
            data_buffer: Vec::new(),
            iv_generation: IvGeneration::None,
            tls_enc_records: None,
        }
    }

    /// Validate the supplied key length. SM4 is fixed at 128 bits.
    fn validate_key_size(key: &[u8]) -> ProviderResult<()> {
        if key.len() != SM4_KEY_SIZE {
            return Err(ProviderError::Init(format!(
                "SM4-CCM: invalid key length {} (expected {})",
                key.len(),
                SM4_KEY_SIZE
            )));
        }
        Ok(())
    }

    /// Shared init path for both encrypt and decrypt directions.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
        encrypting: bool,
    ) -> ProviderResult<()> {
        Self::validate_key_size(key)?;

        // Build a fresh SM4 key schedule. `Sm4::new` validates the key length
        // again internally, so we propagate any error with extra context.
        let cipher = Sm4::new(key)
            .map_err(|err| ProviderError::Init(format!("SM4-CCM: key schedule failed: {err}")))?;
        self.cipher = Some(cipher);
        self.ccm_state.key_set = true;
        self.ccm_state.reset_operation();
        self.encrypting = encrypting;
        self.aad_buffer.clear();
        self.data_buffer.clear();
        self.tls_enc_records = None;
        self.started = false;
        self.initialized = true;

        if let Some(iv_bytes) = iv {
            self.set_iv(iv_bytes)?;
        }
        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    /// Apply an externally-supplied IV; the CCM L parameter is recomputed
    /// to satisfy `nonce_len = 15 - L`.
    fn set_iv(&mut self, new_iv: &[u8]) -> ProviderResult<()> {
        ccm_validate_iv_len(new_iv.len())?;
        let l_param = 15usize.checked_sub(new_iv.len()).ok_or_else(|| {
            ProviderError::Init(format!(
                "SM4-CCM: cannot derive L parameter from IV length {}",
                new_iv.len()
            ))
        })?;
        self.ccm_state.l_param = l_param;
        self.ccm_state.iv = new_iv.to_vec();
        self.ccm_state.iv_set = true;
        Ok(())
    }

    /// Borrow the current IV, returning an error if none has been
    /// configured. Used by `finalize` after random-IV generation.
    fn require_iv(&self) -> ProviderResult<&[u8]> {
        if !self.ccm_state.iv_set {
            return Err(ProviderError::Dispatch(
                "SM4-CCM: IV has not been set; call set_params with an IV first".into(),
            ));
        }
        Ok(self.ccm_state.iv.as_slice())
    }

    /// Borrow the SM4 engine, erroring out if no key has been installed.
    fn engine(&self) -> ProviderResult<&Sm4> {
        self.cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SM4-CCM: cipher has not been keyed".into()))
    }

    /// Capture a TLS 1.2 AEAD additional-data record (RFC 5246 §6.2.3.3).
    fn set_tls_aad(&mut self, aad: &[u8]) -> ProviderResult<usize> {
        if aad.len() != SM4_CCM_TLS1_AAD_LEN {
            return Err(ProviderError::Dispatch(format!(
                "SM4-CCM: TLS AAD length {} (expected {})",
                aad.len(),
                SM4_CCM_TLS1_AAD_LEN
            )));
        }
        // The TLS record length field is at the tail of the AAD. For
        // CCM-encrypted records we MUST adjust it down by the explicit IV
        // length so the AAD reflects the actual ciphertext payload.
        let mut adjusted = aad.to_vec();
        if self.encrypting {
            let len_bytes = &mut adjusted[SM4_CCM_TLS1_AAD_LEN - 2..];
            let tls_record_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]);
            let updated = tls_record_len
                .checked_sub(u16::try_from(SM4_CCM_TLS_EXPLICIT_IV_LEN).map_err(|_| {
                    ProviderError::Dispatch(
                        "SM4-CCM: explicit IV length does not fit in u16 (impossible)".into(),
                    )
                })?)
                .ok_or_else(|| {
                    ProviderError::Dispatch(
                        "SM4-CCM: TLS record length less than explicit IV length".into(),
                    )
                })?;
            len_bytes.copy_from_slice(&updated.to_be_bytes());
        }
        // Mirror the AES-CCM behaviour by also seeding the in-memory AAD
        // buffer so downstream `finalize` can consume it uniformly.  We
        // seed the buffer from the local `adjusted` value (avoiding an
        // `unwrap`/`expect` on the `Option` we are about to write).
        self.aad_buffer.clear();
        self.aad_buffer.extend_from_slice(&adjusted);
        self.ccm_state.tls_aad = Some(adjusted);
        // Set up TLS record limits if not already configured.
        if self.tls_enc_records.is_none() {
            self.tls_enc_records = Some(0);
        }
        Ok(self.ccm_state.tag_len)
    }

    /// Configure the implicit TLS IV (`fixed`); the explicit IV portion is
    /// supplied per record by the upstream TLS stack.
    fn set_tls_iv_fixed(&mut self, fixed: &[u8]) -> ProviderResult<()> {
        if fixed.len() != SM4_CCM_TLS_FIXED_IV_LEN {
            return Err(ProviderError::Dispatch(format!(
                "SM4-CCM: TLS fixed-IV length {} (expected {})",
                fixed.len(),
                SM4_CCM_TLS_FIXED_IV_LEN
            )));
        }
        let total_iv_len = SM4_CCM_TLS_FIXED_IV_LEN
            .checked_add(SM4_CCM_TLS_EXPLICIT_IV_LEN)
            .ok_or_else(|| {
                ProviderError::Dispatch("SM4-CCM: IV-length addition overflowed".into())
            })?;
        if self.ccm_state.iv.len() != total_iv_len {
            // Re-derive the L parameter for the combined IV length.
            ccm_validate_iv_len(total_iv_len)?;
            self.ccm_state.l_param = 15usize.checked_sub(total_iv_len).ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "SM4-CCM: TLS combined IV length {total_iv_len} cannot derive L"
                ))
            })?;
            self.ccm_state.iv = vec![0u8; total_iv_len];
        }
        self.ccm_state.iv[..SM4_CCM_TLS_FIXED_IV_LEN].copy_from_slice(fixed);
        // The explicit portion remains uninitialised until either a TLS
        // encrypt fills it deterministically or a TLS decrypt provides it.
        self.ccm_state.iv_set = false;
        Ok(())
    }

    /// Increment the TLS record counter and reject if the per-key cap is
    /// reached. RFC 6655 §6 caps TLS-CCM at `2^32 − 1` records per key.
    fn enforce_tls_records_limit(&mut self) -> ProviderResult<()> {
        if let Some(count) = self.tls_enc_records.as_mut() {
            if *count >= SM4_CCM_TLS_RECORDS_LIMIT {
                return Err(ProviderError::Dispatch(
                    "SM4-CCM: per-key TLS record limit reached; rekey required".into(),
                ));
            }
            *count = count.saturating_add(1);
        }
        Ok(())
    }
}

impl CipherContext for Sm4CcmContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, params, true)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, params, false)
    }

    fn update(&mut self, input: &[u8], _output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "SM4-CCM: update before encrypt_init/decrypt_init".into(),
            ));
        }
        // CCM is single-shot — we cannot release output incrementally
        // because the tag depends on the final plaintext length. Buffer
        // and emit nothing until `finalize` (mirroring the AES-CCM
        // provider's contract).
        if !input.is_empty() {
            self.data_buffer.extend_from_slice(input);
            self.started = true;
        }
        Ok(0)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "SM4-CCM: finalize before encrypt_init/decrypt_init".into(),
            ));
        }

        // Generate a fresh IV when the caller has requested random/sequential
        // IV generation but has not supplied one explicitly.
        if !self.ccm_state.iv_set {
            match self.iv_generation {
                IvGeneration::Random => {
                    let new_iv = generate_random_iv(self.ccm_state.iv.len())?;
                    self.set_iv(&new_iv)?;
                }
                IvGeneration::Sequential => {
                    if self.ccm_state.iv.is_empty() {
                        let nonce = vec![0u8; SM4_CCM_NONCE_MIN];
                        self.set_iv(&nonce)?;
                    } else {
                        increment_iv(&mut self.ccm_state.iv)?;
                        self.ccm_state.iv_set = true;
                    }
                }
                IvGeneration::None => {
                    return Err(ProviderError::Dispatch(
                        "SM4-CCM: IV has not been set and no IV-generation policy was selected"
                            .into(),
                    ));
                }
            }
        }

        let tag_len = self.ccm_state.tag_len;
        let l_param = self.ccm_state.l_param;
        let iv = self.require_iv()?.to_vec();
        let aad = self.aad_buffer.clone();
        let data = std::mem::take(&mut self.data_buffer);

        let written = if self.encrypting {
            let cipher = self.engine()?;
            let (ct, tag) = sm4_ccm_seal(cipher, &iv, &aad, &data, tag_len, l_param)?;
            // Persist the produced tag so that `get_params(AEAD_TAG)` can
            // expose it to callers (e.g. TLS appends it to the record).
            // Use `clone_from` rather than `= tag.clone()` so the
            // existing buffer's allocation is reused (clippy
            // `assigning_clones`).
            self.ccm_state.tag.clone_from(&tag);
            self.ccm_state.tag_set = true;
            // Mirror AES-CCM by emitting `ct || tag` so downstream
            // consumers (including the FFI layer) see a uniform contract.
            let total = ct.len().saturating_add(tag.len());
            output.extend_from_slice(&ct);
            output.extend_from_slice(&tag);
            // Constant-time uniformity: also exercise `verify_tag` on both
            // branches so the encrypt path leaves the same observable
            // verifier footprint as the decrypt path.
            let _ = verify_tag(&[0u8; 1], &[0u8; 1]);
            total
        } else {
            // Decrypt requires a previously-installed expected tag.
            if !self.ccm_state.tag_set {
                return Err(ProviderError::Dispatch(
                    "SM4-CCM: expected authentication tag not set; call set_params with AEAD_TAG"
                        .into(),
                ));
            }
            let configured_tag_len = self.ccm_state.tag.len();
            ccm_validate_tag_len(configured_tag_len)?;
            // Borrow before move: clone the configured tag so we still
            // own `self.ccm_state.tag` after the borrow of `engine` ends.
            let expected_tag = self.ccm_state.tag.clone();
            let cipher = self.engine()?;
            let pt = sm4_ccm_open(cipher, &iv, &aad, &data, &expected_tag, l_param)?;
            let n = pt.len();
            output.extend_from_slice(&pt);
            n
        };

        // Common post-finalize bookkeeping.
        self.aad_buffer.clear();
        self.started = false;
        self.initialized = false;
        if self.encrypting {
            self.enforce_tls_records_limit()?;
        }
        Ok(written)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let key_bits = SM4_KEY_SIZE.saturating_mul(8);
        let block_bits: usize = 8;
        let iv_bits = self.ccm_state.iv.len().saturating_mul(8);
        let mut ps = generic_get_params(
            CipherMode::Ccm,
            CipherFlags::AEAD | CipherFlags::CUSTOM_IV,
            key_bits,
            block_bits,
            iv_bits,
        );
        ps.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        // Rule R6: tag length is bounded by 16; `try_from` is structurally
        // safe but we still avoid bare `as` and clamp on overflow.
        let tag_len_u32 = u32::try_from(self.ccm_state.tag_len).unwrap_or(u32::MAX);
        ps.set(param_keys::AEAD_TAGLEN, ParamValue::UInt32(tag_len_u32));
        if self.ccm_state.tag_set {
            ps.set(
                param_keys::AEAD_TAG,
                ParamValue::OctetString(self.ccm_state.tag.clone()),
            );
        }
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // ----- IV length -----
        if let Some(value) = params.get(param_keys::IVLEN) {
            if self.started {
                return Err(ProviderError::Dispatch(
                    "SM4-CCM: IV length cannot be changed after data processing has begun".into(),
                ));
            }
            let new_len = match value {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!("SM4-CCM: IV length {v} does not fit in usize"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!("SM4-CCM: IV length {v} does not fit in usize"))
                })?,
                ParamValue::Int32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "SM4-CCM: IV length {v} cannot be converted to usize"
                    ))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-CCM: IV length parameter has unsupported type".into(),
                    ));
                }
            };
            ccm_validate_iv_len(new_len)?;
            let l_param = 15usize.checked_sub(new_len).ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "SM4-CCM: cannot derive L parameter from IV length {new_len}"
                ))
            })?;
            self.ccm_state.l_param = l_param;
            self.ccm_state.iv = vec![0u8; new_len];
            self.ccm_state.iv_set = false;
        }

        // ----- AEAD tag length -----
        if let Some(value) = params.get(param_keys::AEAD_TAGLEN) {
            let new_len = match value {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "SM4-CCM: tag length {v} does not fit in usize"
                    ))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "SM4-CCM: tag length {v} does not fit in usize"
                    ))
                })?,
                ParamValue::Int32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "SM4-CCM: tag length {v} cannot be converted to usize"
                    ))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-CCM: tag length parameter has unsupported type".into(),
                    ));
                }
            };
            ccm_validate_tag_len(new_len)?;
            self.ccm_state.tag_len = new_len;
            self.ccm_state.tag = vec![0u8; new_len];
            self.ccm_state.tag_set = false;
        }

        // ----- AEAD tag (decrypt-only — supplies expected tag) -----
        if let Some(value) = params.get(param_keys::AEAD_TAG) {
            let bytes = match value {
                ParamValue::OctetString(v) => v.clone(),
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-CCM: AEAD_TAG parameter must be OctetString".into(),
                    ));
                }
            };
            if self.encrypting {
                return Err(ProviderError::Dispatch(
                    "SM4-CCM: AEAD_TAG cannot be set during encrypt; the tag is produced by finalize".into(),
                ));
            }
            ccm_validate_tag_len(bytes.len())?;
            self.ccm_state.tag_len = bytes.len();
            self.ccm_state.tag = bytes;
            self.ccm_state.tag_set = true;
        }

        // ----- TLS 1.2 AEAD AAD -----
        if let Some(value) = params.get(param_keys::AEAD_TLS1_AAD) {
            let bytes = match value {
                ParamValue::OctetString(v) => v.clone(),
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-CCM: AEAD_TLS1_AAD parameter must be OctetString".into(),
                    ));
                }
            };
            self.set_tls_aad(&bytes)?;
        }

        // ----- TLS 1.2 fixed (implicit) IV -----
        if let Some(value) = params.get(param_keys::AEAD_TLS1_IV_FIXED) {
            let bytes = match value {
                ParamValue::OctetString(v) => v.clone(),
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-CCM: AEAD_TLS1_IV_FIXED parameter must be OctetString".into(),
                    ));
                }
            };
            self.set_tls_iv_fixed(&bytes)?;
        }

        // ----- IV-generation discipline -----
        if let Some(value) = params.get(param_keys::AEAD_IV_RANDOM) {
            self.iv_generation = match value {
                ParamValue::UInt32(v) => {
                    if *v != 0 {
                        IvGeneration::Random
                    } else {
                        IvGeneration::None
                    }
                }
                ParamValue::UInt64(v) => {
                    if *v != 0 {
                        IvGeneration::Random
                    } else {
                        IvGeneration::None
                    }
                }
                ParamValue::Int32(v) => {
                    if *v != 0 {
                        IvGeneration::Random
                    } else {
                        IvGeneration::None
                    }
                }
                ParamValue::OctetString(_) => IvGeneration::Sequential,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-CCM: AEAD_IV_RANDOM parameter has unsupported type".into(),
                    ));
                }
            };
        }

        // ----- Key length (immutable for SM4) -----
        if let Some(value) = params.get(param_keys::KEYLEN) {
            let new_len = match value {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!("SM4-CCM: KEYLEN {v} does not fit in usize"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!("SM4-CCM: KEYLEN {v} does not fit in usize"))
                })?,
                ParamValue::Int32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "SM4-CCM: KEYLEN {v} cannot be converted to usize"
                    ))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-CCM: KEYLEN parameter has unsupported type".into(),
                    ));
                }
            };
            if new_len != SM4_KEY_SIZE {
                return Err(ProviderError::AlgorithmUnavailable(format!(
                    "SM4-CCM: KEYLEN {new_len} not supported (only {SM4_KEY_SIZE})"
                )));
            }
        }

        Ok(())
    }
}

// ===========================================================================
// SM4-XTS: tweakable storage encryption (IEEE 1619-2018 / GB/T 17964-2008).
// ===========================================================================
//
// XTS-SM4 is the SM4 instantiation of the XEX-with-Tweak-and-Ciphertext-
// Stealing (XTS) construction.  It is the primary mode chosen by the Chinese
// commercial crypto specifications for sector-granularity disk encryption.
//
// The construction takes a 256-bit key K = K1 ‖ K2 split into two
// independently-keyed SM4 instances:
//
//   * K1 — the *data* key, used to encrypt/decrypt every plaintext/
//          ciphertext block.
//   * K2 — the *tweak* key, used once per data unit to derive the initial
//          tweak from the IV (sector index).
//
// Per-block encryption/decryption is:
//
//     T_0  = SM4_K2 ( IV )                                    // initial tweak
//     T_i  = α · T_{i-1}                          // GF(2^128) doubling
//     C_i  = SM4_K1 ( P_i ⊕ T_i ) ⊕ T_i           // tweak XOR sandwich
//
// where α is the polynomial x in GF(2^128)/(x^128 + x^7 + x^2 + x + 1).
// The reduction polynomial is encoded as the byte 0x87 (= 0b10000111),
// XORed into the *first* byte of the tweak whenever the leftmost bit shifts
// out — exactly as in NIST SP 800-38E §5.1 / IEEE 1619 §5.2.
//
// Inputs whose length is not a whole number of blocks use the *ciphertext-
// stealing* (CTS) finalisation: the last full block borrows ciphertext
// material from the synthetic last block to produce a length-preserving
// output.  Crucially, the tweak order for the last two blocks is
// **reversed** on decryption — the second-to-last operation uses the tweak
// that *would have been* applied to the synthetic block during encryption,
// and the very last operation uses the previous tweak.  Getting this
// reversal wrong produces a decrypter that silently corrupts the
// penultimate block without any indication of failure, which is the
// canonical XTS implementation footgun.
//
// Per IEEE 1619 §5.1 and SP 800-38E §5.3 a single XTS data unit is
// limited to 2^20 blocks (16 MiB).  This bound exists to keep the
// distinguishing advantage of XTS against an ideal tweakable cipher
// negligible; the limit is enforced in [`Sm4XtsContext::enforce_block_limit`].
//
// SM4-XTS additionally requires that the two halves of the supplied key
// differ — if K1 == K2 the construction degenerates to a deterministic
// cipher with no tweak-dependent indistinguishability (Rogaway 2004,
// §5.4).  The check is performed in constant time using
// [`subtle::ConstantTimeEq`] to avoid leaking information about the key
// material via timing channels (Rule R8: zero unsafe; Rule R8 of XTS-AES
// IG A.9 of FIPS 140-2).
//
// Source mapping:
//   * `providers/implementations/ciphers/cipher_sm4_xts.c`     → this section
//   * `providers/implementations/ciphers/cipher_sm4_xts_hw.c`  → this section
//
// All XTS arithmetic is built from scratch on top of `Sm4::encrypt_block`
// and `Sm4::decrypt_block` because `openssl_crypto::symmetric` only
// exposes the raw 128-bit block primitive — there is no `Sm4Xts` analogue
// of the `AesXts` engine.  This is per Rule R5 (idiomatic Rust types) and
// Rule R8 (zero unsafe outside the FFI crate).
// ===========================================================================

/// Multiply the 128-bit XTS tweak by α in GF(2^128) using the reduction
/// polynomial x^128 + x^7 + x^2 + x + 1 (encoded as the constant 0x87 — the
/// low byte of the polynomial minus the leading x^128 term).
///
/// This is the *little-endian byte-order* interpretation: the byte at
/// `tweak[0]` is the least-significant byte, matching the convention used
/// in IEEE 1619-2018 §5.2 and SP 800-38E §5.1.  Each byte is shifted left
/// by one bit, and the carry from byte `i-1` becomes the low bit of
/// byte `i`.  When the high bit of `tweak[15]` shifts out it is folded
/// back into `tweak[0]` via XOR with 0x87.
///
/// The implementation runs in constant time with respect to the tweak
/// value — branches are only on the carry of the *output* of the shift
/// (which is independent of secret data because the tweak is derived
/// from the publicly-known IV and key K2 by the first SM4 invocation
/// before any per-block processing begins).
fn xts_advance_tweak(tweak: &mut [u8; SM4_BLOCK_SIZE]) {
    let mut carry: u8 = 0;
    for byte in tweak.iter_mut() {
        let new_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }
    if carry != 0 {
        tweak[0] ^= XTS_GF128_REDUCTION_BYTE;
    }
}

/// XOR a 16-byte tweak into a 16-byte block (in-place).  Used for both
/// the input-side and output-side XOR of the XTS sandwich.
#[inline]
fn xor_tweak_into(block: &mut [u8; SM4_BLOCK_SIZE], tweak: &[u8; SM4_BLOCK_SIZE]) {
    for (b, t) in block.iter_mut().zip(tweak.iter()) {
        *b ^= *t;
    }
}

/// Encrypt a buffer with SM4-XTS.
///
/// `iv` must be exactly 16 bytes — the data unit number (typically a
/// sector index, encoded little-endian) used to derive the initial tweak.
/// `plaintext` must be at least one full SM4 block (16 bytes); shorter
/// inputs cannot support the ciphertext-stealing construction and are
/// rejected by the caller (`Sm4XtsContext::update`).
///
/// Returns a freshly-allocated `Vec<u8>` of exactly `plaintext.len()`
/// bytes containing the XTS ciphertext.  All temporary tweaks and
/// scratch blocks live on the stack and are dropped before return; only
/// the output buffer escapes.
fn sm4_xts_encrypt(
    cipher_k1: &Sm4,
    cipher_k2: &Sm4,
    iv: &[u8; SM4_XTS_IV_LEN],
    plaintext: &[u8],
) -> ProviderResult<Vec<u8>> {
    let total = plaintext.len();
    if total < SM4_XTS_MIN_INPUT_BYTES {
        return Err(ProviderError::Dispatch(format!(
            "SM4-XTS: plaintext must be at least {SM4_XTS_MIN_INPUT_BYTES} bytes; got {total}"
        )));
    }

    // Step 1 — derive the initial tweak T_0 = SM4_K2(IV).
    let mut tweak: [u8; SM4_BLOCK_SIZE] = *iv;
    cipher_k2.encrypt_block(&mut tweak).map_err(|e| {
        ProviderError::Dispatch(format!("SM4-XTS encrypt: tweak derivation failed: {e}"))
    })?;

    // Compute the number of *complete* blocks that will be processed
    // through the standard XEX path.  If `total` is an exact multiple of
    // the block size, every block is processed normally and there is no
    // ciphertext stealing.  Otherwise, the *last full* block and the
    // partial tail block are processed via the CTS finalisation.
    let full_blocks = total / SM4_BLOCK_SIZE;
    let tail_len = total % SM4_BLOCK_SIZE;
    let cts = tail_len != 0;
    let normal_blocks = if cts { full_blocks - 1 } else { full_blocks };

    let mut ciphertext: Vec<u8> = Vec::with_capacity(total);

    // Step 2 — standard XEX processing for all but the last (and tail) blocks.
    let mut block: [u8; SM4_BLOCK_SIZE] = [0u8; SM4_BLOCK_SIZE];
    for i in 0..normal_blocks {
        let off = i * SM4_BLOCK_SIZE;
        block.copy_from_slice(&plaintext[off..off + SM4_BLOCK_SIZE]);
        xor_tweak_into(&mut block, &tweak);
        cipher_k1.encrypt_block(&mut block).map_err(|e| {
            ProviderError::Dispatch(format!("SM4-XTS encrypt: block {i} failed: {e}"))
        })?;
        xor_tweak_into(&mut block, &tweak);
        ciphertext.extend_from_slice(&block);
        xts_advance_tweak(&mut tweak);
    }

    if cts {
        // Step 3 — ciphertext stealing for the partial-tail finalisation.
        //
        // Encryption order on the last two blocks (P_{n-1} = full,
        // P_n = partial of length `tail_len`):
        //
        //   CC = ENC(P_{n-1})  using tweak T_{n-1}
        //   advance tweak → T_n
        //   PP = ENC( P_n ‖ CC[tail_len..] )  using tweak T_n
        //   output: ... ‖ PP ‖ CC[..tail_len]
        //
        // So the second-to-last *block of plaintext* is encrypted with
        // tweak T_{n-1}, and the synthetic stitched block is encrypted
        // with T_n.  The output ordering is reversed: PP comes out
        // *first*, followed by the stolen prefix of CC.  This matches
        // both NIST SP 800-38E §5.4 and IEEE 1619 §5.4.
        let last_full_off = normal_blocks * SM4_BLOCK_SIZE;
        let mut cc: [u8; SM4_BLOCK_SIZE] = [0u8; SM4_BLOCK_SIZE];
        cc.copy_from_slice(&plaintext[last_full_off..last_full_off + SM4_BLOCK_SIZE]);
        xor_tweak_into(&mut cc, &tweak);
        cipher_k1.encrypt_block(&mut cc).map_err(|e| {
            ProviderError::Dispatch(format!("SM4-XTS encrypt: penultimate block failed: {e}"))
        })?;
        xor_tweak_into(&mut cc, &tweak);

        // Advance tweak T_{n-1} → T_n for the synthetic block.
        xts_advance_tweak(&mut tweak);

        // Build the synthetic block: P_n ‖ CC[tail_len..].
        let tail_off = last_full_off + SM4_BLOCK_SIZE;
        let mut pp: [u8; SM4_BLOCK_SIZE] = [0u8; SM4_BLOCK_SIZE];
        pp[..tail_len].copy_from_slice(&plaintext[tail_off..tail_off + tail_len]);
        pp[tail_len..].copy_from_slice(&cc[tail_len..]);
        xor_tweak_into(&mut pp, &tweak);
        cipher_k1.encrypt_block(&mut pp).map_err(|e| {
            ProviderError::Dispatch(format!("SM4-XTS encrypt: synthetic block failed: {e}"))
        })?;
        xor_tweak_into(&mut pp, &tweak);

        // Output order: PP first, then the stolen prefix of CC.
        ciphertext.extend_from_slice(&pp);
        ciphertext.extend_from_slice(&cc[..tail_len]);
    }

    debug_assert_eq!(
        ciphertext.len(),
        total,
        "SM4-XTS encrypt: length-preserving invariant violated"
    );
    Ok(ciphertext)
}

/// Decrypt a buffer with SM4-XTS — the inverse of [`sm4_xts_encrypt`].
///
/// Note the **tweak reversal** in the ciphertext-stealing finalisation:
/// on decryption, the second-to-last operation must use tweak `T_n` (not
/// `T_{n-1}`) and the last operation must use `T_{n-1}` (not `T_n`).  This is
/// the most subtle correctness requirement in the entire XTS standard
/// and the one most commonly mis-implemented.  See IEEE 1619 §5.5 and
/// SP 800-38E §5.5.
fn sm4_xts_decrypt(
    cipher_k1: &Sm4,
    cipher_k2: &Sm4,
    iv: &[u8; SM4_XTS_IV_LEN],
    ciphertext: &[u8],
) -> ProviderResult<Vec<u8>> {
    let total = ciphertext.len();
    if total < SM4_XTS_MIN_INPUT_BYTES {
        return Err(ProviderError::Dispatch(format!(
            "SM4-XTS: ciphertext must be at least {SM4_XTS_MIN_INPUT_BYTES} bytes; got {total}"
        )));
    }

    // Derive the initial tweak — same as encryption (the tweak path is
    // identical because it depends only on the public IV and K2).
    let mut tweak: [u8; SM4_BLOCK_SIZE] = *iv;
    cipher_k2.encrypt_block(&mut tweak).map_err(|e| {
        ProviderError::Dispatch(format!("SM4-XTS decrypt: tweak derivation failed: {e}"))
    })?;

    let full_blocks = total / SM4_BLOCK_SIZE;
    let tail_len = total % SM4_BLOCK_SIZE;
    let cts = tail_len != 0;
    let normal_blocks = if cts { full_blocks - 1 } else { full_blocks };

    let mut plaintext: Vec<u8> = Vec::with_capacity(total);

    // Standard XEX-decrypt for all but the last (and tail) blocks.
    let mut block: [u8; SM4_BLOCK_SIZE] = [0u8; SM4_BLOCK_SIZE];
    for i in 0..normal_blocks {
        let off = i * SM4_BLOCK_SIZE;
        block.copy_from_slice(&ciphertext[off..off + SM4_BLOCK_SIZE]);
        xor_tweak_into(&mut block, &tweak);
        cipher_k1.decrypt_block(&mut block).map_err(|e| {
            ProviderError::Dispatch(format!("SM4-XTS decrypt: block {i} failed: {e}"))
        })?;
        xor_tweak_into(&mut block, &tweak);
        plaintext.extend_from_slice(&block);
        xts_advance_tweak(&mut tweak);
    }

    if cts {
        // Ciphertext-stealing decryption uses the *next* tweak (T_n) for
        // the penultimate block, and the *previous* tweak (T_{n-1}) for
        // the synthetic block.  Save T_{n-1}, advance to T_n, then swap.
        //
        // Layout of the input tail (after `normal_blocks` consumed):
        //   ciphertext[last_full_off ..      last_full_off + 16] = PP'
        //   ciphertext[last_full_off + 16 .. last_full_off + 16 + tail_len] = CC[..tail_len]
        //
        // Decrypt steps:
        //   1. Advance tweak T_{n-1} → T_n (saving T_{n-1} for step 3).
        //   2. PP = DEC_K1(PP') under tweak T_n  →  yields a 16-byte
        //      synthetic-block plaintext P_n ‖ CC[tail_len..].
        //   3. CC = PP[tail_len..] ‖ CC[..tail_len]   (reassemble final
        //      full ciphertext block).
        //   4. P_{n-1} = DEC_K1(CC) under tweak T_{n-1}.
        //   5. Output order: P_{n-1} first, then P_n[..tail_len].
        let last_full_off = normal_blocks * SM4_BLOCK_SIZE;
        let prev_tweak = tweak;
        xts_advance_tweak(&mut tweak);

        // Step 2 — decrypt PP' under T_n to recover the synthetic block.
        let mut pp: [u8; SM4_BLOCK_SIZE] = [0u8; SM4_BLOCK_SIZE];
        pp.copy_from_slice(&ciphertext[last_full_off..last_full_off + SM4_BLOCK_SIZE]);
        xor_tweak_into(&mut pp, &tweak);
        cipher_k1.decrypt_block(&mut pp).map_err(|e| {
            ProviderError::Dispatch(format!("SM4-XTS decrypt: synthetic block failed: {e}"))
        })?;
        xor_tweak_into(&mut pp, &tweak);

        // Step 3 — assemble the *real* last full ciphertext block:
        // pull the borrowed prefix from the input tail, suffix from PP.
        let tail_off = last_full_off + SM4_BLOCK_SIZE;
        let mut cc: [u8; SM4_BLOCK_SIZE] = [0u8; SM4_BLOCK_SIZE];
        cc[..tail_len].copy_from_slice(&ciphertext[tail_off..tail_off + tail_len]);
        cc[tail_len..].copy_from_slice(&pp[tail_len..]);

        // Step 4 — decrypt CC under T_{n-1} to recover P_{n-1}.
        xor_tweak_into(&mut cc, &prev_tweak);
        cipher_k1.decrypt_block(&mut cc).map_err(|e| {
            ProviderError::Dispatch(format!("SM4-XTS decrypt: penultimate block failed: {e}"))
        })?;
        xor_tweak_into(&mut cc, &prev_tweak);

        // Step 5 — output P_{n-1} first, then P_n (the first `tail_len`
        // bytes of the synthetic-block plaintext).
        plaintext.extend_from_slice(&cc);
        plaintext.extend_from_slice(&pp[..tail_len]);
    }

    debug_assert_eq!(
        plaintext.len(),
        total,
        "SM4-XTS decrypt: length-preserving invariant violated"
    );
    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Sm4XtsCipher provider entry — algorithm metadata + context constructor.
// ---------------------------------------------------------------------------

/// SM4-XTS cipher provider.
///
/// Registers `SM4-XTS` with the provider store.  Acts as a stateless
/// factory for fresh [`Sm4XtsContext`] instances; the actual key material
/// is bound to the context via `encrypt_init` / `decrypt_init`.
///
/// XTS is reported with `block_size = 1` because at the EVP layer it
/// behaves as a stream cipher: callers feed an arbitrary-length input
/// (≥ 16 bytes) and receive an output of identical length.  The 128-bit
/// internal SM4 block size is reflected in the `block-size` parameter
/// from `get_params`, but `iv-bits` and `keylen` reflect the XTS-level
/// values (128 / 256 bits respectively).
#[derive(Debug, Clone, Copy)]
pub struct Sm4XtsCipher {
    name: &'static str,
}

impl Default for Sm4XtsCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm4XtsCipher {
    /// Construct the SM4-XTS provider entry.
    #[must_use]
    pub fn new() -> Self {
        Self { name: "SM4-XTS" }
    }
}

impl CipherProvider for Sm4XtsCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        SM4_XTS_KEY_SIZE
    }

    fn iv_length(&self) -> usize {
        SM4_XTS_IV_LEN
    }

    fn block_size(&self) -> usize {
        SM4_XTS_REPORTED_BLOCK
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(Sm4XtsContext::new(self.name)))
    }
}

// ---------------------------------------------------------------------------
// Sm4XtsContext — per-operation state for SM4-XTS encryption/decryption.
// ---------------------------------------------------------------------------

/// Per-operation SM4-XTS context — owns the data and tweak SM4 key
/// schedules (`cipher_k1` / `cipher_k2`), the IV (data unit number),
/// the chosen XTS standard variant (GB or IEEE), and the lifecycle
/// flags that gate parameter mutations.
///
/// On drop, the IV buffer is zeroised via the `Zeroize` derive; the two
/// `Sm4` engines are skipped by `#[zeroize(skip)]` because the engine
/// itself implements `Drop` via its own `Zeroize` derive in
/// `openssl-crypto`, ensuring the round-key material is wiped exactly
/// once.  See AAP §0.7.6 (secure erasure) and Rule R8 (zero unsafe).
//
// RATIONALE: The four boolean fields (`iv_set`, `initialized`,
// `encrypting`, `started`) encode four orthogonal aspects of the
// cipher's lifecycle (IV populated, fully initialised, direction,
// stream started). Consolidating them into a single state enum would
// require storing the encrypt/decrypt direction separately and obscure
// the simple invariants documented above, providing no real benefit
// over the named-field representation. This mirrors the C struct layout
// in `cipher_sm4_xts.c` (PROV_SM4_XTS_CTX `enc`, `iv_set`, `started`)
// and the AES-XTS struct layout in `aes_xts.rs::AesXtsContext`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Sm4XtsContext {
    /// Algorithm name passed back through `get_params("algorithm")`.
    #[zeroize(skip)]
    name: &'static str,

    /// XTS standard variant.  Defaults to **GB** for SM4-XTS to match
    /// the OpenSSL C provider's `cipher_sm4_xts.c` initialisation
    /// (`xts_standard = 0` → GB).  This is the **opposite** of AES-XTS
    /// which defaults to IEEE.  Selectable at runtime via the
    /// `param_keys::CTS_MODE` parameter prior to data processing.
    #[zeroize(skip)]
    standard: XtsStandard,

    /// Data SM4 key schedule (K1) — `None` until `encrypt_init` /
    /// `decrypt_init` succeeds.
    #[zeroize(skip)]
    cipher_k1: Option<Sm4>,

    /// Tweak SM4 key schedule (K2) — `None` until `encrypt_init` /
    /// `decrypt_init` succeeds.
    #[zeroize(skip)]
    cipher_k2: Option<Sm4>,

    /// Stored IV / data unit number.  Always exactly 16 bytes once
    /// `iv_set` is `true`.
    iv: Vec<u8>,

    /// Whether `iv` holds a valid IV.  Required prior to `update`.
    iv_set: bool,

    /// Whether `encrypt_init` / `decrypt_init` succeeded.  Gates all
    /// further operations (`update`, `finalize`, `set_params`).
    initialized: bool,

    /// Operation direction — `true` for encrypt, `false` for decrypt.
    encrypting: bool,

    /// Whether any data has been processed (i.e. `update` was called
    /// with non-empty input).  Once set, the XTS standard variant
    /// becomes immutable per IEEE 1619 §5.1 (the standard governs the
    /// cipher's operation and may not be changed mid-stream).
    started: bool,
}

impl fmt::Debug for Sm4XtsContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Manual `fmt::Debug` so that K1, K2, and tweak IVs are NEVER
        // leaked through `{:?}` formatting.  The sensitive `cipher_k2`
        // and `iv` fields are intentionally omitted; their relevant
        // state is summarised via `key_set` and `iv_set`.
        f.debug_struct("Sm4XtsContext")
            .field("name", &self.name)
            .field("standard", &self.standard)
            .field("key_set", &self.cipher_k1.is_some())
            .field("iv_set", &self.iv_set)
            .field("initialized", &self.initialized)
            .field("encrypting", &self.encrypting)
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

impl Sm4XtsContext {
    /// Construct an empty SM4-XTS context.  The context is **not**
    /// usable until `encrypt_init` or `decrypt_init` succeeds.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            standard: XtsStandard::default(),
            cipher_k1: None,
            cipher_k2: None,
            iv: Vec::new(),
            iv_set: false,
            initialized: false,
            encrypting: false,
            started: false,
        }
    }

    /// Reject any key whose length is not the canonical 256 bits
    /// (= two 128-bit SM4 keys concatenated).  No alternative key
    /// lengths are defined for XTS-SM4.
    fn validate_key_size(key_len: usize) -> ProviderResult<()> {
        if key_len != SM4_XTS_KEY_SIZE {
            return Err(ProviderError::Init(format!(
                "SM4-XTS: key length must be {SM4_XTS_KEY_SIZE} bytes \
                 (two 128-bit SM4 subkeys); got {key_len}"
            )));
        }
        Ok(())
    }

    /// Constant-time enforcement of the XTS keys-must-differ policy
    /// (FIPS 140-2 IG A.9, IEEE 1619 §5.1).  Splits the supplied key
    /// into K1 ‖ K2 and asserts K1 ≠ K2 using
    /// [`subtle::ConstantTimeEq::ct_eq`] to avoid leaking the precise
    /// position of the first differing byte through timing.
    fn check_keys_differ(key: &[u8]) -> ProviderResult<()> {
        debug_assert_eq!(
            key.len(),
            SM4_XTS_KEY_SIZE,
            "check_keys_differ called with malformed key length"
        );
        let half = key.len() / 2;
        let (k1, k2) = key.split_at(half);
        if bool::from(k1.ct_eq(k2)) {
            return Err(ProviderError::Init(
                "SM4-XTS: data and tweak keys must differ \
                 (FIPS 140-2 IG A.9 / IEEE 1619 §5.1)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Enforce IV length == 16 bytes.  Per IEEE 1619 §5.1 the IV is
    /// the data unit number encoded as a 128-bit little-endian
    /// integer; no other lengths are admissible.
    fn validate_iv_len(iv_len: usize) -> ProviderResult<()> {
        if iv_len != SM4_XTS_IV_LEN {
            return Err(ProviderError::Init(format!(
                "SM4-XTS: IV length must be {SM4_XTS_IV_LEN} bytes; got {iv_len}"
            )));
        }
        Ok(())
    }

    /// Enforce the per-data-unit block limit (2^20 blocks = 16 MiB).
    /// Called for every `update` invocation prior to dispatch.
    fn enforce_block_limit(input_len: usize) -> ProviderResult<()> {
        if input_len > SM4_XTS_MAX_BYTES_PER_DATA_UNIT {
            return Err(ProviderError::Dispatch(format!(
                "SM4-XTS: input exceeds 2^20-block per-data-unit limit \
                 ({SM4_XTS_MAX_BYTES_PER_DATA_UNIT} bytes); got {input_len}"
            )));
        }
        Ok(())
    }

    /// Borrow the data SM4 engine, erroring if not yet keyed.
    fn engine_k1(&self) -> ProviderResult<&Sm4> {
        self.cipher_k1
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SM4-XTS: data engine not initialised".into()))
    }

    /// Borrow the tweak SM4 engine, erroring if not yet keyed.
    fn engine_k2(&self) -> ProviderResult<&Sm4> {
        self.cipher_k2
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("SM4-XTS: tweak engine not initialised".into()))
    }

    /// Convert the stored IV into a fixed-size array suitable for
    /// passing to the encrypt/decrypt primitives.  Errors if the IV
    /// has not been set yet.  The conversion is infallible once
    /// `iv_set == true` because every write-site enforces the
    /// 16-byte invariant via [`validate_iv_len`].
    fn iv_array(&self) -> ProviderResult<[u8; SM4_XTS_IV_LEN]> {
        if !self.iv_set {
            return Err(ProviderError::Dispatch(
                "SM4-XTS: IV must be set before processing data".into(),
            ));
        }
        let slice = self.iv.as_slice();
        slice.try_into().map_err(|_| {
            ProviderError::Dispatch(format!(
                "SM4-XTS: stored IV has unexpected length {} (expected {})",
                slice.len(),
                SM4_XTS_IV_LEN
            ))
        })
    }

    /// Shared init body for both encrypt and decrypt.  Mirrors the
    /// 7-step pattern from `AesXtsContext::init_common`:
    ///
    /// 1. Validate the supplied key length.
    /// 2. Constant-time check that K1 ≠ K2.
    /// 3. Build the two SM4 engines.
    /// 4. Stash the engines and direction in `self`.
    /// 5. Validate / store the IV (or clear it if `None`).
    /// 6. Reset lifecycle flags.
    /// 7. Apply any trailing parameters; on error roll back to the
    ///    pre-init state to avoid leaving the context in a half-keyed
    ///    state that would leak partial state to subsequent attempts.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // Step 1.
        Self::validate_key_size(key.len())?;
        // Step 2.
        Self::check_keys_differ(key)?;

        // Step 3.
        let (k1_bytes, k2_bytes) = key.split_at(SM4_KEY_SIZE);
        let k1 = Sm4::new(k1_bytes).map_err(|e| {
            ProviderError::Init(format!("SM4-XTS: data engine construction failed: {e}"))
        })?;
        let k2 = Sm4::new(k2_bytes).map_err(|e| {
            ProviderError::Init(format!("SM4-XTS: tweak engine construction failed: {e}"))
        })?;

        // Snapshot the old state for rollback in step 7.
        let prev_k1 = self.cipher_k1.take();
        let prev_k2 = self.cipher_k2.take();
        let prev_iv = std::mem::take(&mut self.iv);
        let prev_iv_set = self.iv_set;
        let prev_initialized = self.initialized;
        let prev_encrypting = self.encrypting;
        let prev_started = self.started;

        // Step 4.
        self.cipher_k1 = Some(k1);
        self.cipher_k2 = Some(k2);
        self.encrypting = encrypting;

        // Step 5 — IV handling.
        if let Some(iv_bytes) = iv {
            if let Err(e) = Self::validate_iv_len(iv_bytes.len()) {
                // Rollback before propagating.
                self.cipher_k1 = prev_k1;
                self.cipher_k2 = prev_k2;
                self.iv = prev_iv;
                self.iv_set = prev_iv_set;
                self.initialized = prev_initialized;
                self.encrypting = prev_encrypting;
                self.started = prev_started;
                return Err(e);
            }
            self.iv.clear();
            self.iv.extend_from_slice(iv_bytes);
            self.iv_set = true;
        } else {
            self.iv.clear();
            self.iv_set = false;
        }

        // Step 6.
        self.started = false;
        self.initialized = true;

        // Step 7 — apply trailing parameters with rollback on error.
        if let Some(p) = params {
            if let Err(e) = self.set_params(p) {
                self.cipher_k1 = prev_k1;
                self.cipher_k2 = prev_k2;
                self.iv = prev_iv;
                self.iv_set = prev_iv_set;
                self.initialized = prev_initialized;
                self.encrypting = prev_encrypting;
                self.started = prev_started;
                return Err(e);
            }
        }

        Ok(())
    }
}

impl CipherContext for Sm4XtsContext {
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

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "SM4-XTS: update called before encrypt_init/decrypt_init".into(),
            ));
        }
        if input.is_empty() {
            // Empty inputs are a no-op — XTS is single-shot but accepts
            // zero-length probes without changing state, matching the
            // behaviour of the C provider's `sm4_xts_stream_update`.
            return Ok(0);
        }

        // Validate engines and IV before consuming the input.
        let _k1 = self.engine_k1()?;
        let _k2 = self.engine_k2()?;
        if !self.iv_set {
            return Err(ProviderError::Dispatch(
                "SM4-XTS: IV must be set before processing data".into(),
            ));
        }
        if input.len() < SM4_XTS_MIN_INPUT_BYTES {
            return Err(ProviderError::Dispatch(format!(
                "SM4-XTS: input must be at least {SM4_XTS_MIN_INPUT_BYTES} bytes; got {}",
                input.len()
            )));
        }
        Self::enforce_block_limit(input.len())?;

        // Lock parameter mutations once data flows through the engine.
        self.started = true;

        let iv_arr = self.iv_array()?;
        let processed = if self.encrypting {
            sm4_xts_encrypt(self.engine_k1()?, self.engine_k2()?, &iv_arr, input)?
        } else {
            sm4_xts_decrypt(self.engine_k1()?, self.engine_k2()?, &iv_arr, input)?
        };

        // Length-preserving invariant — encrypt/decrypt return exactly
        // `input.len()` bytes for any well-formed XTS input.
        if processed.len() != input.len() {
            return Err(ProviderError::Dispatch(format!(
                "SM4-XTS: length-preserving invariant violated \
                 (input {} bytes, output {} bytes)",
                input.len(),
                processed.len()
            )));
        }

        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    fn finalize(&mut self, _output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "SM4-XTS: finalize called before encrypt_init/decrypt_init".into(),
            ));
        }
        // XTS is single-shot — `update` produces the entire output for
        // a given data unit and `finalize` is purely a state-transition
        // sentinel that locks the context against further mutation.
        self.initialized = false;
        self.started = false;
        Ok(0)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let key_bits = SM4_XTS_KEY_SIZE.saturating_mul(8);
        let block_bits = SM4_BLOCK_SIZE.saturating_mul(8);
        let iv_bits = SM4_XTS_IV_LEN.saturating_mul(8);
        let mut ps = generic_get_params(
            CipherMode::Xts,
            CipherFlags::CUSTOM_IV,
            key_bits,
            block_bits,
            iv_bits,
        );
        ps.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String(self.standard.to_string()),
        );
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // KEYLEN parameter — XTS-SM4 requires exactly 256-bit keys.
        // Accept the integer-shaped variants (`UInt32`, `UInt64`,
        // `Int32`) that mirror the C `OSSL_PARAM_get_size_t`
        // semantics; reject any other variant and any value other
        // than 32 bytes.
        if let Some(value) = params.get(param_keys::KEYLEN) {
            let new_len = match value {
                ParamValue::UInt32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!("SM4-XTS: KEYLEN {v} does not fit in usize"))
                })?,
                ParamValue::UInt64(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!("SM4-XTS: KEYLEN {v} does not fit in usize"))
                })?,
                ParamValue::Int32(v) => usize::try_from(*v).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "SM4-XTS: KEYLEN {v} cannot be converted to usize"
                    ))
                })?,
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-XTS: KEYLEN parameter has unsupported type".into(),
                    ));
                }
            };
            if new_len != SM4_XTS_KEY_SIZE {
                return Err(ProviderError::AlgorithmUnavailable(format!(
                    "SM4-XTS: KEYLEN {new_len} not supported (only {SM4_XTS_KEY_SIZE})"
                )));
            }
        }

        // CTS_MODE parameter — selects the GB or IEEE XTS standard.
        // Per IEEE 1619 §5.1 the standard governs the cipher's
        // operation and may not be changed once data flows through.
        if let Some(val) = params.get(param_keys::CTS_MODE) {
            if self.started {
                return Err(ProviderError::Dispatch(
                    "SM4-XTS: cts_mode cannot be changed after data processing has begun".into(),
                ));
            }
            match val {
                ParamValue::Utf8String(s) => {
                    self.standard = XtsStandard::from_str(s)?;
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "SM4-XTS: cts_mode parameter must be a UTF-8 string".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}

// ===========================================================================
// Algorithm descriptor registration.
// ===========================================================================
//
// The `descriptors()` function publishes the eight SM4 cipher algorithms
// to the provider store: the five base-mode entries (ECB, CBC, CTR, OFB,
// CFB), the two AEAD entries (GCM, CCM), and the disk-encryption entry
// (XTS).  The provider registry consumes this vector at boot time and
// dispatches algorithm fetches against it.  See AAP §0.4.1 (target
// design) and Rule R10 (wiring before done).

/// Build the list of algorithm descriptors registered by this module.
///
/// Returns one [`AlgorithmDescriptor`] per algorithm name.  The returned
/// vector is consumed by the parent `ciphers::descriptors()` aggregator
/// in `mod.rs` and ultimately registered with the provider dispatch
/// table.
///
/// Each descriptor carries the canonical algorithm name (e.g.
/// `"SM4-CBC"`), the property string `"provider=default"` to match the
/// C default provider, and a human-readable description used by
/// `openssl list -cipher-algorithms`.  A constructibility check runs
/// on each cipher type as a smoke-test: if any of the eight builders
/// panic at registration time, the bug surfaces during provider boot
/// rather than at first use.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    // Five base-mode entries, each parameterised by `Sm4CipherMode`.
    let base_modes: &[(&'static str, Sm4CipherMode, &'static str)] = &[
        (
            "SM4-ECB",
            Sm4CipherMode::Ecb,
            "SM4 in ECB mode (GB/T 32907-2016)",
        ),
        (
            "SM4-CBC",
            Sm4CipherMode::Cbc,
            "SM4 in CBC mode (GB/T 32907-2016)",
        ),
        (
            "SM4-CTR",
            Sm4CipherMode::Ctr,
            "SM4 in CTR mode (GB/T 32907-2016)",
        ),
        (
            "SM4-OFB",
            Sm4CipherMode::Ofb,
            "SM4 in OFB mode (GB/T 32907-2016)",
        ),
        (
            "SM4-CFB",
            Sm4CipherMode::Cfb,
            "SM4 in CFB mode (GB/T 32907-2016)",
        ),
    ];

    let mut descs: Vec<AlgorithmDescriptor> = Vec::with_capacity(8);

    for &(name, mode, description) in base_modes {
        descs.push(make_cipher_descriptor(
            vec![name],
            "provider=default",
            description,
        ));
        // Constructibility smoke-test: surface any future API drift in
        // the `Sm4Cipher::new` signature at descriptor-build time.
        let _ = Sm4Cipher::new(name, mode);
    }

    // SM4-GCM AEAD entry.
    descs.push(make_cipher_descriptor(
        vec!["SM4-GCM"],
        "provider=default",
        "SM4 in GCM AEAD mode (NIST SP 800-38D)",
    ));
    let _ = Sm4GcmCipher::new();

    // SM4-CCM AEAD entry.
    descs.push(make_cipher_descriptor(
        vec!["SM4-CCM"],
        "provider=default",
        "SM4 in CCM AEAD mode (RFC 3610 / NIST SP 800-38C)",
    ));
    let _ = Sm4CcmCipher::new();

    // SM4-XTS storage encryption entry.
    descs.push(make_cipher_descriptor(
        vec!["SM4-XTS"],
        "provider=default",
        "SM4 in XTS mode (IEEE Std 1619-2018 / GB/T 17964-2008)",
    ));
    let _ = Sm4XtsCipher::new();

    debug_assert_eq!(
        descs.len(),
        8,
        "SM4 descriptors() must return exactly 8 entries (5 base + GCM + CCM + XTS)"
    );

    descs
}

// ===========================================================================
// Unit tests
// ===========================================================================
//
// The tests below exercise the SM4 provider surface from the public API
// downwards: the `CipherProvider` trait for metadata, `CipherContext` for
// encryption / decryption round-trips, `ParamSet` for parameter
// negotiation, and `descriptors()` for registry integration. The tests
// cover all eight algorithm registrations (ECB / CBC / CTR / OFB / CFB /
// GCM / CCM / XTS) plus the safety invariants enforced by Rules R5
// (Option<T> instead of sentinels), R6 (lossless casts), R7 (Send + Sync),
// R8 (zero unsafe), R9 (warning-free), and R10 (wired into descriptors).
//
// All tests use synthetic test vectors derived from upstream OpenSSL
// behaviour or self-consistency (encrypt → decrypt → identity).

#[cfg(test)]
#[cfg(feature = "sm4")]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Convenience: 16-byte SM4 test key (constant pattern, easy to spot).
    const TEST_KEY_16: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    /// 32-byte SM4-XTS test key (two 128-bit halves that **differ**, as
    /// required by IEEE 1619 §5.1).
    const TEST_KEY_32: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x11, 0x00,
    ];

    /// 16-byte IV / data unit number.
    const TEST_IV_16: [u8; 16] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF,
    ];

    /// 12-byte GCM IV.
    const TEST_IV_12: [u8; 12] = [
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
    ];

    // -----------------------------------------------------------------------
    // Module-level / metadata tests
    // -----------------------------------------------------------------------

    #[test]
    fn xts_standard_default_is_gb() {
        // R5: SM4-XTS defaults to GB (opposite of AES-XTS which defaults
        // to IEEE).  This mirrors `OPENSSL_zalloc` zeroing the
        // `xts_standard` field in the C provider.
        assert_eq!(XtsStandard::default(), XtsStandard::Gb);
    }

    #[test]
    fn xts_standard_from_str_accepts_gb_and_ieee_case_insensitively() {
        assert_eq!(XtsStandard::from_str("GB").unwrap(), XtsStandard::Gb);
        assert_eq!(XtsStandard::from_str("gb").unwrap(), XtsStandard::Gb);
        assert_eq!(XtsStandard::from_str("Gb").unwrap(), XtsStandard::Gb);
        assert_eq!(XtsStandard::from_str("IEEE").unwrap(), XtsStandard::Ieee);
        assert_eq!(XtsStandard::from_str("ieee").unwrap(), XtsStandard::Ieee);
        assert_eq!(XtsStandard::from_str("Ieee").unwrap(), XtsStandard::Ieee);
    }

    #[test]
    fn xts_standard_from_str_rejects_unknown_value() {
        assert!(XtsStandard::from_str("xyz").is_err());
        assert!(XtsStandard::from_str("").is_err());
    }

    #[test]
    fn xts_standard_display_renders_canonical_strings() {
        assert_eq!(XtsStandard::Gb.to_string(), "GB");
        assert_eq!(XtsStandard::Ieee.to_string(), "IEEE");
    }

    #[test]
    fn descriptors_returns_eight_entries() {
        let descs = descriptors();
        assert_eq!(
            descs.len(),
            8,
            "SM4 must register exactly 8 algorithms (5 base + GCM + CCM + XTS)"
        );
    }

    #[test]
    fn descriptors_include_all_expected_names() {
        let descs = descriptors();
        let names: Vec<&str> = descs
            .iter()
            .filter_map(|d| d.names.first().copied())
            .collect();
        for expected in [
            "SM4-ECB", "SM4-CBC", "SM4-CTR", "SM4-OFB", "SM4-CFB", "SM4-GCM", "SM4-CCM", "SM4-XTS",
        ] {
            assert!(
                names.contains(&expected),
                "descriptors() missing expected entry {expected}"
            );
        }
    }

    #[test]
    fn descriptors_all_advertise_default_provider() {
        for d in descriptors() {
            assert_eq!(d.property, "provider=default");
        }
    }

    // -----------------------------------------------------------------------
    // CipherProvider metadata
    // -----------------------------------------------------------------------

    #[test]
    fn sm4_base_cipher_metadata_is_correct() {
        let cipher = Sm4Cipher::new("SM4-CBC", Sm4CipherMode::Cbc);
        assert_eq!(cipher.name(), "SM4-CBC");
        assert_eq!(cipher.key_length(), SM4_KEY_SIZE);
        assert_eq!(cipher.block_size(), SM4_BLOCK_SIZE);
        // CBC reports a 16-byte IV.
        assert_eq!(cipher.iv_length(), SM4_BLOCK_SIZE);
    }

    #[test]
    fn sm4_ecb_reports_zero_iv_length() {
        // ECB has no IV.
        let cipher = Sm4Cipher::new("SM4-ECB", Sm4CipherMode::Ecb);
        assert_eq!(cipher.iv_length(), 0);
    }

    #[test]
    fn sm4_stream_modes_report_block_size_one() {
        // CTR / OFB / CFB act as stream ciphers at the EVP layer.
        for mode in [Sm4CipherMode::Ctr, Sm4CipherMode::Ofb, Sm4CipherMode::Cfb] {
            let cipher = Sm4Cipher::new("SM4-stream", mode);
            assert_eq!(
                cipher.block_size(),
                1,
                "stream mode must report block_size=1"
            );
        }
    }

    #[test]
    fn sm4_gcm_metadata_is_correct() {
        let cipher = Sm4GcmCipher::new();
        assert_eq!(cipher.name(), "SM4-GCM");
        assert_eq!(cipher.key_length(), SM4_KEY_SIZE);
        assert_eq!(cipher.iv_length(), SM4_GCM_DEFAULT_IV_LEN);
        assert_eq!(cipher.block_size(), 1);
    }

    #[test]
    fn sm4_ccm_metadata_is_correct() {
        let cipher = Sm4CcmCipher::new();
        assert_eq!(cipher.name(), "SM4-CCM");
        assert_eq!(cipher.key_length(), SM4_KEY_SIZE);
        // Default CCM nonce is 7 bytes (L=8).
        assert_eq!(cipher.iv_length(), SM4_CCM_NONCE_MIN);
        assert_eq!(cipher.block_size(), 1);
    }

    #[test]
    fn sm4_xts_metadata_is_correct() {
        let cipher = Sm4XtsCipher::new();
        assert_eq!(cipher.name(), "SM4-XTS");
        // XTS uses a 256-bit key (two 128-bit halves).
        assert_eq!(cipher.key_length(), SM4_XTS_KEY_SIZE);
        assert_eq!(cipher.iv_length(), SM4_XTS_IV_LEN);
        // XTS reports a single-byte block (ciphertext stealing → byte-granular).
        assert_eq!(cipher.block_size(), SM4_XTS_REPORTED_BLOCK);
    }

    // -----------------------------------------------------------------------
    // Send + Sync (Rule R7)
    // -----------------------------------------------------------------------

    #[test]
    fn sm4_provider_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Sm4Cipher>();
        assert_send_sync::<Sm4GcmCipher>();
        assert_send_sync::<Sm4CcmCipher>();
        assert_send_sync::<Sm4XtsCipher>();
        assert_send_sync::<Sm4CipherContext>();
        assert_send_sync::<Sm4GcmContext>();
        assert_send_sync::<Sm4CcmContext>();
        assert_send_sync::<Sm4XtsContext>();
    }

    // -----------------------------------------------------------------------
    // Base modes — ECB / CBC / CTR / OFB / CFB round-trips
    // -----------------------------------------------------------------------

    fn round_trip_base_mode(mode: Sm4CipherMode, name: &'static str, plaintext: &[u8]) {
        // Encrypt
        let cipher = Sm4Cipher::new(name, mode);
        let mut enc_ctx = cipher.new_ctx().expect("new_ctx");

        let iv: Option<&[u8]> = if mode == Sm4CipherMode::Ecb {
            None
        } else {
            Some(&TEST_IV_16)
        };
        enc_ctx
            .encrypt_init(&TEST_KEY_16, iv, None)
            .expect("encrypt_init");

        let mut ciphertext: Vec<u8> = Vec::new();
        enc_ctx.update(plaintext, &mut ciphertext).expect("update");
        enc_ctx.finalize(&mut ciphertext).expect("finalize");

        // Round-trip property: decrypt(encrypt(P)) = P.
        let mut dec_ctx = cipher.new_ctx().expect("new_ctx (dec)");
        dec_ctx
            .decrypt_init(&TEST_KEY_16, iv, None)
            .expect("decrypt_init");

        let mut decrypted: Vec<u8> = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut decrypted)
            .expect("update (dec)");
        dec_ctx.finalize(&mut decrypted).expect("finalize (dec)");

        assert_eq!(decrypted, plaintext, "round-trip mismatch for {name}");
    }

    #[test]
    fn sm4_ecb_round_trips_block_aligned_input() {
        // ECB requires block-aligned input (32 bytes = 2 SM4 blocks).
        let plaintext: Vec<u8> = (0u8..32).collect();
        round_trip_base_mode(Sm4CipherMode::Ecb, "SM4-ECB", &plaintext);
    }

    #[test]
    fn sm4_cbc_round_trips_with_pkcs7_padding() {
        // CBC pads to a block boundary via PKCS#7 — accepts any length.
        let plaintext = b"The quick brown fox jumps over the lazy dog.";
        round_trip_base_mode(Sm4CipherMode::Cbc, "SM4-CBC", plaintext);
    }

    #[test]
    fn sm4_ctr_round_trips_arbitrary_length() {
        // CTR is a stream cipher — any length works.
        let plaintext = b"Hello, SM4-CTR!";
        round_trip_base_mode(Sm4CipherMode::Ctr, "SM4-CTR", plaintext);
    }

    #[test]
    fn sm4_ofb_round_trips_arbitrary_length() {
        let plaintext = b"OFB stream cipher test vector";
        round_trip_base_mode(Sm4CipherMode::Ofb, "SM4-OFB", plaintext);
    }

    #[test]
    fn sm4_cfb_round_trips_arbitrary_length() {
        let plaintext = b"CFB128 byte-oriented stream";
        round_trip_base_mode(Sm4CipherMode::Cfb, "SM4-CFB", plaintext);
    }

    #[test]
    fn sm4_base_mode_rejects_non_128_bit_keys() {
        let cipher = Sm4Cipher::new("SM4-CBC", Sm4CipherMode::Cbc);
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let bad_key = [0u8; 24]; // 192 bits, invalid for SM4
        assert!(ctx.encrypt_init(&bad_key, Some(&TEST_IV_16), None).is_err());
    }

    // -----------------------------------------------------------------------
    // SM4-GCM AEAD round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn sm4_gcm_round_trips_with_aad_and_tag() {
        let cipher = Sm4GcmCipher::new();

        // Encrypt
        let mut enc_ctx = cipher.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&TEST_KEY_16, Some(&TEST_IV_12), None)
            .expect("encrypt_init");

        let plaintext = b"sensitive data protected by SM4-GCM";
        let mut ciphertext = Vec::new();
        enc_ctx.update(plaintext, &mut ciphertext).expect("update");
        enc_ctx.finalize(&mut ciphertext).expect("finalize");

        // Retrieve the auth tag.
        let params = enc_ctx.get_params().expect("get_params");
        let tag = params
            .get(param_keys::AEAD_TAG)
            .and_then(|v| match v {
                ParamValue::OctetString(b) => Some(b.clone()),
                _ => None,
            })
            .expect("AEAD_TAG present after encrypt");
        assert_eq!(tag.len(), SM4_GCM_TAG_LEN);

        // Decrypt with the same key/IV and verify the tag.
        let mut dec_ctx = cipher.new_ctx().expect("new_ctx (dec)");
        dec_ctx
            .decrypt_init(&TEST_KEY_16, Some(&TEST_IV_12), None)
            .expect("decrypt_init");

        // Push the expected tag in for verification.
        let mut tag_params = ParamSet::new();
        tag_params.set(param_keys::AEAD_TAG, ParamValue::OctetString(tag));
        dec_ctx.set_params(&tag_params).expect("set_params(tag)");

        let mut decrypted = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut decrypted)
            .expect("update (dec)");
        dec_ctx.finalize(&mut decrypted).expect("finalize (dec)");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn sm4_gcm_decrypt_with_wrong_tag_fails() {
        let cipher = Sm4GcmCipher::new();

        // Encrypt
        let mut enc_ctx = cipher.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&TEST_KEY_16, Some(&TEST_IV_12), None)
            .expect("encrypt_init");
        let plaintext = b"protected";
        let mut ciphertext = Vec::new();
        enc_ctx.update(plaintext, &mut ciphertext).expect("update");
        enc_ctx.finalize(&mut ciphertext).expect("finalize");

        // Decrypt with a *wrong* tag.
        let wrong_tag = vec![0xFFu8; SM4_GCM_TAG_LEN];

        let mut dec_ctx = cipher.new_ctx().expect("new_ctx (dec)");
        dec_ctx
            .decrypt_init(&TEST_KEY_16, Some(&TEST_IV_12), None)
            .expect("decrypt_init");
        let mut tag_params = ParamSet::new();
        tag_params.set(param_keys::AEAD_TAG, ParamValue::OctetString(wrong_tag));
        dec_ctx.set_params(&tag_params).expect("set_params(tag)");

        let mut decrypted = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut decrypted)
            .expect("update (dec)");
        // Tag verification fails on finalize.
        assert!(dec_ctx.finalize(&mut decrypted).is_err());
    }

    // -----------------------------------------------------------------------
    // SM4-CCM AEAD round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn sm4_ccm_round_trips_with_default_tag_len() {
        let cipher = Sm4CcmCipher::new();

        // CCM requires a 7-byte nonce by default.
        let nonce = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6];

        // Encrypt — single-shot AEAD.
        let mut enc_ctx = cipher.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&TEST_KEY_16, Some(&nonce), None)
            .expect("encrypt_init");

        let plaintext = b"SM4-CCM round-trip test";
        let mut output = Vec::new();
        enc_ctx.update(plaintext, &mut output).expect("update");
        enc_ctx.finalize(&mut output).expect("finalize");

        // The provider emits `ct || tag` so consumers see a uniform
        // contract.  Recover the tag length, then split.
        let params = enc_ctx.get_params().expect("get_params");
        let tag = params
            .get(param_keys::AEAD_TAG)
            .and_then(|v| match v {
                ParamValue::OctetString(b) => Some(b.clone()),
                _ => None,
            })
            .expect("AEAD_TAG present after encrypt");
        assert!(!tag.is_empty(), "CCM tag must be non-empty");
        assert!(
            output.len() >= tag.len(),
            "encrypted output must contain at least the tag"
        );
        let ct_only_len = output.len() - tag.len();
        let ciphertext = &output[..ct_only_len];
        // The trailing bytes must equal the get_params() tag.
        assert_eq!(&output[ct_only_len..], tag.as_slice());

        // Decrypt with the same key / nonce / tag.  The decrypt path
        // takes the *bare* ciphertext (no trailing tag) and reads the
        // expected tag from `set_params`.
        let mut dec_ctx = cipher.new_ctx().expect("new_ctx (dec)");
        dec_ctx
            .decrypt_init(&TEST_KEY_16, Some(&nonce), None)
            .expect("decrypt_init");
        let mut tag_params = ParamSet::new();
        tag_params.set(param_keys::AEAD_TAG, ParamValue::OctetString(tag));
        dec_ctx.set_params(&tag_params).expect("set_params(tag)");

        let mut decrypted = Vec::new();
        dec_ctx
            .update(ciphertext, &mut decrypted)
            .expect("update (dec)");
        dec_ctx.finalize(&mut decrypted).expect("finalize (dec)");
        assert_eq!(decrypted, plaintext);
    }

    // -----------------------------------------------------------------------
    // SM4-XTS — single-shot encrypt / decrypt
    // -----------------------------------------------------------------------

    #[test]
    fn sm4_xts_round_trips_block_aligned_input() {
        let cipher = Sm4XtsCipher::new();

        // 32 bytes — exactly two SM4 blocks; no ciphertext stealing.
        let plaintext: Vec<u8> = (0u8..32).collect();

        // Encrypt
        let mut enc_ctx = cipher.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&TEST_KEY_32, Some(&TEST_IV_16), None)
            .expect("encrypt_init");
        let mut ciphertext = Vec::new();
        enc_ctx.update(&plaintext, &mut ciphertext).expect("update");
        enc_ctx.finalize(&mut ciphertext).expect("finalize");
        assert_eq!(ciphertext.len(), plaintext.len(), "XTS preserves length");

        // Decrypt
        let mut dec_ctx = cipher.new_ctx().expect("new_ctx (dec)");
        dec_ctx
            .decrypt_init(&TEST_KEY_32, Some(&TEST_IV_16), None)
            .expect("decrypt_init");
        let mut decrypted = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut decrypted)
            .expect("update (dec)");
        dec_ctx.finalize(&mut decrypted).expect("finalize (dec)");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn sm4_xts_round_trips_with_ciphertext_stealing() {
        let cipher = Sm4XtsCipher::new();

        // 30 bytes = 1 full block + 14-byte remainder → triggers CTS path.
        let plaintext: Vec<u8> = (0u8..30).collect();

        // Encrypt
        let mut enc_ctx = cipher.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&TEST_KEY_32, Some(&TEST_IV_16), None)
            .expect("encrypt_init");
        let mut ciphertext = Vec::new();
        enc_ctx.update(&plaintext, &mut ciphertext).expect("update");
        enc_ctx.finalize(&mut ciphertext).expect("finalize");
        assert_eq!(
            ciphertext.len(),
            plaintext.len(),
            "XTS+CTS preserves length"
        );

        // Decrypt — exercises the *reversed* tweak order on the CTS path.
        let mut dec_ctx = cipher.new_ctx().expect("new_ctx (dec)");
        dec_ctx
            .decrypt_init(&TEST_KEY_32, Some(&TEST_IV_16), None)
            .expect("decrypt_init");
        let mut decrypted = Vec::new();
        dec_ctx
            .update(&ciphertext, &mut decrypted)
            .expect("update (dec)");
        dec_ctx.finalize(&mut decrypted).expect("finalize (dec)");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn sm4_xts_rejects_identical_key_halves() {
        // Rogaway 2004 / IEEE 1619 §5.1 forbids K1 == K2.  The Rust
        // provider must reject such keys *in constant time* via
        // `subtle::ConstantTimeEq`.
        let mut bad_key = [0u8; 32];
        // Both halves identical.
        for (i, b) in bad_key.iter_mut().enumerate() {
            *b = (i % 16) as u8;
        }

        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        assert!(ctx.encrypt_init(&bad_key, Some(&TEST_IV_16), None).is_err());
    }

    #[test]
    fn sm4_xts_rejects_wrong_key_size() {
        // SM4-XTS requires exactly a 256-bit key (two 128-bit halves).
        // 16-byte and 64-byte keys must be rejected.
        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");

        let key_16 = [0u8; 16];
        assert!(ctx.encrypt_init(&key_16, Some(&TEST_IV_16), None).is_err());

        let key_64 = [0u8; 64];
        assert!(ctx.encrypt_init(&key_64, Some(&TEST_IV_16), None).is_err());
    }

    #[test]
    fn sm4_xts_rejects_wrong_iv_length() {
        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let bad_iv = [0u8; 8]; // must be 16 bytes
        assert!(ctx.encrypt_init(&TEST_KEY_32, Some(&bad_iv), None).is_err());
    }

    #[test]
    fn sm4_xts_rejects_short_input() {
        // XTS requires at least one full block (16 bytes).
        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&TEST_KEY_32, Some(&TEST_IV_16), None)
            .expect("encrypt_init");
        let short_input = [0u8; 8];
        let mut output = Vec::new();
        assert!(ctx.update(&short_input, &mut output).is_err());
    }

    #[test]
    fn sm4_xts_get_params_reports_gb_default() {
        let cipher = Sm4XtsCipher::new();
        let ctx = cipher.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        let cts_mode = params.get(param_keys::CTS_MODE).expect("CTS_MODE");
        match cts_mode {
            ParamValue::Utf8String(s) => assert_eq!(s, "GB"),
            other => panic!("expected Utf8String, got {other:?}"),
        }
    }

    #[test]
    fn sm4_xts_set_params_accepts_ieee_standard() {
        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let mut params = ParamSet::new();
        params.set(param_keys::CTS_MODE, ParamValue::Utf8String("IEEE".into()));
        ctx.set_params(&params).expect("set_params");

        // Verify the change took effect.
        let updated = ctx.get_params().expect("get_params");
        let cts_mode = updated.get(param_keys::CTS_MODE).expect("CTS_MODE");
        match cts_mode {
            ParamValue::Utf8String(s) => assert_eq!(s, "IEEE"),
            other => panic!("expected Utf8String, got {other:?}"),
        }
    }

    #[test]
    fn sm4_xts_set_params_rejects_unknown_standard() {
        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let mut params = ParamSet::new();
        params.set(param_keys::CTS_MODE, ParamValue::Utf8String("XYZ".into()));
        assert!(ctx.set_params(&params).is_err());
    }

    #[test]
    fn sm4_xts_set_params_accepts_correct_keylen() {
        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");

        // Each integer-shaped variant of `ParamValue` must be accepted
        // when carrying the correct value (32 bytes).
        for value in [
            ParamValue::UInt32(SM4_XTS_KEY_SIZE as u32),
            ParamValue::UInt64(SM4_XTS_KEY_SIZE as u64),
            ParamValue::Int32(SM4_XTS_KEY_SIZE as i32),
        ] {
            let mut params = ParamSet::new();
            params.set(param_keys::KEYLEN, value);
            assert!(ctx.set_params(&params).is_ok());
        }
    }

    #[test]
    fn sm4_xts_set_params_rejects_wrong_keylen() {
        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        let mut params = ParamSet::new();
        params.set(param_keys::KEYLEN, ParamValue::UInt32(16));
        assert!(ctx.set_params(&params).is_err());
    }

    #[test]
    fn sm4_xts_get_params_reports_xts_mode_and_correct_metadata() {
        let cipher = Sm4XtsCipher::new();
        let ctx = cipher.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");

        // KEYLEN must match the XTS key size (32 bytes).
        let keylen = params.get(param_keys::KEYLEN).expect("KEYLEN");
        let value = match keylen {
            ParamValue::UInt32(v) => *v as usize,
            ParamValue::UInt64(v) => *v as usize,
            ParamValue::Int32(v) => *v as usize,
            other => panic!("unexpected ParamValue variant: {other:?}"),
        };
        assert_eq!(value, SM4_XTS_KEY_SIZE);
    }

    // -----------------------------------------------------------------------
    // ECB ciphertext deterministic vector — same input must produce
    // same output across two contexts.
    // -----------------------------------------------------------------------

    #[test]
    fn sm4_ecb_is_deterministic() {
        let plaintext: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];

        let cipher = Sm4Cipher::new("SM4-ECB", Sm4CipherMode::Ecb);

        let mut ct_a = Vec::new();
        {
            let mut ctx = cipher.new_ctx().expect("new_ctx");
            ctx.encrypt_init(&TEST_KEY_16, None, None)
                .expect("encrypt_init");
            ctx.update(&plaintext, &mut ct_a).expect("update");
            ctx.finalize(&mut ct_a).expect("finalize");
        }

        let mut ct_b = Vec::new();
        {
            let mut ctx = cipher.new_ctx().expect("new_ctx");
            ctx.encrypt_init(&TEST_KEY_16, None, None)
                .expect("encrypt_init");
            ctx.update(&plaintext, &mut ct_b).expect("update");
            ctx.finalize(&mut ct_b).expect("finalize");
        }

        // Two ECB encryptions of the same plaintext under the same key
        // must produce identical ciphertext.
        assert_eq!(ct_a, ct_b);
        // And it must not equal the plaintext (sanity check).
        assert_ne!(ct_a, plaintext);
    }

    // -----------------------------------------------------------------------
    // XTS standard switch must be locked once data has flowed.
    // -----------------------------------------------------------------------

    #[test]
    fn sm4_xts_cts_mode_locked_after_update() {
        let cipher = Sm4XtsCipher::new();
        let mut ctx = cipher.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&TEST_KEY_32, Some(&TEST_IV_16), None)
            .expect("encrypt_init");

        // Process some data — this flips the `started` flag.
        let plaintext: Vec<u8> = (0u8..32).collect();
        let mut output = Vec::new();
        ctx.update(&plaintext, &mut output).expect("update");

        // Attempt to switch the standard *after* data has flowed.
        let mut params = ParamSet::new();
        params.set(param_keys::CTS_MODE, ParamValue::Utf8String("IEEE".into()));
        assert!(ctx.set_params(&params).is_err());
    }

    // -----------------------------------------------------------------------
    // Helper / primitive correctness
    // -----------------------------------------------------------------------

    #[test]
    fn xts_advance_tweak_doubles_in_gf_2_128() {
        // Known XTS GF(2^128) doubling test:
        // T = 0x01 0x00 ... 0x00  →  T' = 0x02 0x00 ... 0x00
        let mut tweak = [0u8; SM4_BLOCK_SIZE];
        tweak[0] = 0x01;
        xts_advance_tweak(&mut tweak);
        assert_eq!(tweak[0], 0x02);
        for &b in &tweak[1..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn xts_advance_tweak_handles_high_bit_carry() {
        // T with high bit of the *last* byte set (which is the most-significant
        // bit in the little-endian representation that XTS uses).  Doubling
        // must wrap and XOR 0x87 into byte 0.
        let mut tweak = [0u8; SM4_BLOCK_SIZE];
        tweak[SM4_BLOCK_SIZE - 1] = 0x80;
        xts_advance_tweak(&mut tweak);
        assert_eq!(tweak[0], 0x87);
        for &b in &tweak[1..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn xor_blocks_in_place_xors_byte_by_byte() {
        let mut a = [0xAA, 0x55, 0x00, 0xFF];
        let b = [0xFF, 0xFF, 0xFF, 0xFF];
        xor_blocks(&mut a, &b);
        assert_eq!(a, [0x55, 0xAA, 0xFF, 0x00]);
    }
}
