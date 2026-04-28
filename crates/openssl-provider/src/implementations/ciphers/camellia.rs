//! Camellia block cipher provider implementations.
//!
//! Camellia is a 128-bit block cipher standardized in RFC 3713 and ISO/IEC
//! 18033-3, jointly designed by Mitsubishi Electric and NTT. It supports
//! 128/192/256-bit key sizes with the same block size and key schedule
//! complexity profile as AES, making it a drop-in replacement in many
//! standards (TLS, IPSec, S/MIME, Kerberos).
//!
//! # Translation Source
//!
//! This module is a Rust translation of the upstream C provider files:
//!
//! * `providers/implementations/ciphers/cipher_camellia.c` — Provider
//!   dispatch tables, parameter wiring, and `IMPLEMENT_*_cipher` macro
//!   expansion for ECB/CBC/OFB/CFB/CTR/CFB1/CFB8 algorithms.
//! * `providers/implementations/ciphers/cipher_camellia_hw.c` — Key
//!   schedule wrapper invoking `Camellia_set_key`/`Camellia_encrypt`/
//!   `Camellia_decrypt`.
//! * `providers/implementations/ciphers/cipher_camellia_cts.inc` — CTS
//!   wrapper: routes `OSSL_CIPHER_PARAM_CTS_MODE` through
//!   `ossl_cipher_cbc_cts_mode_name2id` / `id2name` and registers the
//!   CTS dispatch tables.
//! * `providers/implementations/ciphers/cipher_cts.c` — Underlying CS1 /
//!   CS2 / CS3 ciphertext-stealing algorithms (NIST SP 800-38A Addendum
//!   and Kerberos5 RFC 3962).
//!
//! # Algorithm Coverage
//!
//! 18 algorithm descriptors are exposed (matching the AAP §0.4.4 target):
//!
//! | Mode    | Key bits | Algorithm name        |
//! |---------|----------|-----------------------|
//! | ECB     | 128/192/256 | `CAMELLIA-{N}-ECB` |
//! | CBC     | 128/192/256 | `CAMELLIA-{N}-CBC` |
//! | OFB     | 128/192/256 | `CAMELLIA-{N}-OFB` |
//! | CFB     | 128/192/256 | `CAMELLIA-{N}-CFB` |
//! | CTR     | 128/192/256 | `CAMELLIA-{N}-CTR` |
//! | CBC-CTS | 128/192/256 | `CAMELLIA-{N}-CBC-CTS` |
//!
//! The CFB1/CFB8 variants present in the C source are intentionally
//! omitted from this initial translation per AAP §0.5.1; they will be
//! reintroduced in a follow-up scope expansion if required.
//!
//! # CTS (Ciphertext Stealing) Variants
//!
//! Three CTS sub-variants are supported via the `OSSL_CIPHER_PARAM_CTS_MODE`
//! UTF-8 string parameter (`param_keys::CTS_MODE`):
//!
//! * **CS1** (default, NIST SP 800-38A Addendum): emits
//!   `C(0)..C(n-2) || C(n-1)* || C(n)`. If the input is a multiple of
//!   the block size it is identical to plain CBC.
//! * **CS2**: like CS1 when the input is a multiple of the block size,
//!   otherwise emits `C(0)..C(n-2) || C(n) || C(n-1)*` (CS3 layout).
//! * **CS3** (Kerberos5, RFC 3962): always emits
//!   `C(0)..C(n-2) || C(n) || C(n-1)*` regardless of partial-block status,
//!   yielding identical output structure for residue==0 with the last
//!   two blocks swapped.
//!
//! All CTS modes are **single-shot** — the C reference enforces this via
//! `ctx->updated == 1`; we mirror this with the
//! [`CamelliaCipherContext::cts_updated`] flag.
//!
//! # Cryptographic Primitive
//!
//! All actual block transforms delegate to
//! [`openssl_crypto::symmetric::legacy::Camellia`], which implements the
//! [`SymmetricCipher`] trait with constant-time pure-Rust round functions
//! and `Zeroize` / `ZeroizeOnDrop` semantics for the round-key schedule.
//!
//! # Compliance Rules (per AAP §0.8.1)
//!
//! * **R5 — Nullability over sentinels:** Cipher mode is the
//!   [`CamelliaCipherMode`] enum (never an integer). The CTS sub-variant
//!   selection is `Option<CtsVariant>` with `None` meaning "default
//!   (CS1)" — never a magic `0` sentinel.
//! * **R6 — Lossless casts:** Every `* 8` conversion uses
//!   [`usize::saturating_mul`]; every potentially narrowing cast uses
//!   [`usize::try_from`].
//! * **R8 — Zero unsafe outside FFI:** This module contains zero `unsafe`
//!   blocks; key material handling is mediated entirely by `Vec<u8>` and
//!   the `Zeroize` trait.
//! * **R9 — Warning-free build:** All public items carry `///` doc
//!   comments; no `#[allow(warnings)]` is present.
//!
//! # Memory Hygiene
//!
//! [`CamelliaCipherContext`] derives `Zeroize` (transitively via the
//! [`Zeroize`] impl on `Camellia`) and explicitly zeroizes its IV,
//! buffer, and keystream slabs in its [`Drop`] implementation, mirroring
//! the C `OPENSSL_clear_free()` calls in `camellia_freectx()`.
//!
//! # Feature gating
//!
//! This module is gated behind the `camellia` Cargo feature in its parent
//! `mod.rs` (`#[cfg(feature = "camellia")] pub mod camellia;`). No inner
//! `#![cfg(...)]` attribute is required here — adding one would be a
//! `clippy::duplicated_attributes` violation.

use super::common::{
    generic_block_update, generic_get_params, generic_init_key, generic_stream_update, param_keys,
    pkcs7_pad, pkcs7_unpad, CipherFlags, CipherInitConfig, CipherMode,
};
use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::symmetric::legacy::Camellia;
use openssl_crypto::symmetric::SymmetricCipher;
use std::fmt;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Module constants
// ---------------------------------------------------------------------------

/// Camellia block size in bytes (128 bits).
///
/// Per RFC 3713 §3, Camellia processes data in 128-bit blocks regardless
/// of key length. This matches the C `CAMELLIA_BLOCK_SIZE` constant in
/// `include/openssl/camellia.h`.
const CAMELLIA_BLOCK_SIZE: usize = 16;

/// Default IV length in bytes (matches block size for every IV-using
/// mode — CBC, OFB, CFB, CTR, and CBC-CTS).
const CAMELLIA_DEFAULT_IV_LEN: usize = 16;

// ---------------------------------------------------------------------------
// CTS variant selector
// ---------------------------------------------------------------------------

/// Ciphertext-stealing sub-variant selector for CBC-CTS modes.
///
/// Replaces the C `unsigned int cts_mode` integer field on
/// `PROV_CIPHER_CTX` and the `CTS_CS{1,2,3}` integer constants from
/// `cipher_cts.c`. Following AAP rule **R5**, the runtime value is an
/// enum (never a sentinel integer).
///
/// The string spelling on the wire (set via `OSSL_CIPHER_PARAM_CTS_MODE`)
/// matches the upstream C constants `OSSL_CIPHER_CTS_MODE_CS{1,2,3}` from
/// `include/openssl/core_names.h`. Parsing is **case-insensitive**,
/// matching the C `OPENSSL_strcasecmp` behaviour in
/// `ossl_cipher_cbc_cts_mode_name2id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum CtsVariant {
    /// NIST SP 800-38A Addendum CS1 (default per upstream).
    ///
    /// If the input is an integer multiple of the block size, output is
    /// indistinguishable from plain CBC. Otherwise output is
    /// `C(0)..C(n-2) || C(n-1)* || C(n)` where `C(n-1)*` is the partial
    /// block with the stolen suffix.
    Cs1,
    /// CS2: like CS1 when input length is a block multiple, otherwise
    /// produces the CS3 layout `C(0)..C(n-2) || C(n) || C(n-1)*`.
    Cs2,
    /// CS3 (Kerberos5, RFC 3962). Always produces
    /// `C(0)..C(n-2) || C(n) || C(n-1)*` regardless of partial-block
    /// status, yielding swap-of-last-two-blocks semantics for aligned
    /// inputs.
    Cs3,
}

impl CtsVariant {
    /// Returns the canonical wire string for this variant
    /// (`"CS1"` / `"CS2"` / `"CS3"`).
    ///
    /// Mirrors the C `ossl_cipher_cbc_cts_mode_id2name` lookup table
    /// in `cipher_cts.c`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CtsVariant::Cs1 => "CS1",
            CtsVariant::Cs2 => "CS2",
            CtsVariant::Cs3 => "CS3",
        }
    }

    /// Parses a CTS mode name (case-insensitive).
    ///
    /// Returns `Err(ProviderError::Init)` for unrecognised names. This
    /// mirrors the C `ossl_cipher_cbc_cts_mode_name2id` function which
    /// returns `-1` on invalid input — the Rust translation surfaces the
    /// failure as a typed error rather than a sentinel value (rule R5).
    pub fn from_str_ci(name: &str) -> ProviderResult<Self> {
        if name.eq_ignore_ascii_case("CS1") {
            Ok(CtsVariant::Cs1)
        } else if name.eq_ignore_ascii_case("CS2") {
            Ok(CtsVariant::Cs2)
        } else if name.eq_ignore_ascii_case("CS3") {
            Ok(CtsVariant::Cs3)
        } else {
            Err(ProviderError::Init(format!(
                "unrecognised CTS mode name '{name}'"
            )))
        }
    }

    /// Returns the default CTS variant (CS1), matching the C convention
    /// where `cts_mode` is initialised to `CTS_CS1 = 0` in
    /// `cipher_camellia.c::camellia_newctx()`.
    #[must_use]
    pub const fn default_value() -> Self {
        CtsVariant::Cs1
    }
}

impl Default for CtsVariant {
    fn default() -> Self {
        CtsVariant::default_value()
    }
}

impl fmt::Display for CtsVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CamelliaCipherMode — operating-mode selector
// ---------------------------------------------------------------------------

/// Camellia operating mode.
///
/// Replaces the per-mode dispatch tables generated by
/// `IMPLEMENT_generic_cipher` / `IMPLEMENT_cts_cipher` macros in the C
/// source. The enum encodes which IV/block-size/flag profile applies and
/// which update routine to dispatch to (rule R5: no integer sentinels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CamelliaCipherMode {
    /// Electronic Codebook — 128-bit block, no IV.
    Ecb,
    /// Cipher Block Chaining — 128-bit block, 128-bit IV.
    Cbc,
    /// Output Feedback — 128-bit IV, byte-granularity stream operation.
    Ofb,
    /// Cipher Feedback (full-width: CFB128) — 128-bit IV.
    Cfb,
    /// Counter — 128-bit IV (used as initial counter).
    Ctr,
    /// CBC with ciphertext stealing — 128-bit block, 128-bit IV.
    /// CTS sub-variant is selected separately via [`CtsVariant`].
    CbcCts,
}

impl CamelliaCipherMode {
    /// IV length in bytes for this mode.
    ///
    /// ECB takes no IV (returns 0); every other mode uses a single
    /// block of IV state.
    #[must_use]
    pub const fn iv_len(self) -> usize {
        match self {
            CamelliaCipherMode::Ecb => 0,
            CamelliaCipherMode::Cbc
            | CamelliaCipherMode::Ofb
            | CamelliaCipherMode::Cfb
            | CamelliaCipherMode::Ctr
            | CamelliaCipherMode::CbcCts => CAMELLIA_DEFAULT_IV_LEN,
        }
    }

    /// Block size reported through `EVP_CIPHER_block_size()`.
    ///
    /// Block-aligned modes (ECB/CBC/CBC-CTS) report 16; stream modes
    /// (OFB/CFB/CTR) report 1 to indicate byte-granularity operation —
    /// matching the C `IMPLEMENT_generic_cipher(..., 1, ...)` invocations
    /// for stream-mode dispatch tables.
    #[must_use]
    pub const fn reported_block_size(self) -> usize {
        match self {
            CamelliaCipherMode::Ecb | CamelliaCipherMode::Cbc | CamelliaCipherMode::CbcCts => {
                CAMELLIA_BLOCK_SIZE
            }
            CamelliaCipherMode::Ofb | CamelliaCipherMode::Cfb | CamelliaCipherMode::Ctr => 1,
        }
    }

    /// Maps to the shared [`CipherMode`] enum used by
    /// [`generic_get_params`] / [`generic_init_key`].
    #[must_use]
    pub const fn to_cipher_mode(self) -> CipherMode {
        match self {
            CamelliaCipherMode::Ecb => CipherMode::Ecb,
            CamelliaCipherMode::Cbc => CipherMode::Cbc,
            CamelliaCipherMode::Ofb => CipherMode::Ofb,
            CamelliaCipherMode::Cfb => CipherMode::Cfb,
            CamelliaCipherMode::Ctr => CipherMode::Ctr,
            CamelliaCipherMode::CbcCts => CipherMode::CbcCts,
        }
    }

    /// Cipher capability flags associated with this mode.
    ///
    /// Returns [`CipherFlags::CTS`] for [`CamelliaCipherMode::CbcCts`]
    /// (matching `CTS_FLAGS = PROV_CIPHER_FLAG_CTS` in
    /// `cipher_camellia_cts.inc`); empty for every other mode.
    #[must_use]
    pub fn flags(self) -> CipherFlags {
        match self {
            CamelliaCipherMode::CbcCts => CipherFlags::CTS,
            _ => CipherFlags::empty(),
        }
    }

    /// Whether this mode applies PKCS#7 padding by default.
    ///
    /// ECB and CBC pad by default. CBC-CTS does NOT pad (the whole point
    /// of ciphertext stealing is to avoid padding while preserving
    /// length). Stream modes (OFB/CFB/CTR) never pad.
    #[must_use]
    pub const fn default_padding(self) -> bool {
        matches!(self, CamelliaCipherMode::Ecb | CamelliaCipherMode::Cbc)
    }
}

impl fmt::Display for CamelliaCipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CamelliaCipherMode::Ecb => "ECB",
            CamelliaCipherMode::Cbc => "CBC",
            CamelliaCipherMode::Ofb => "OFB",
            CamelliaCipherMode::Cfb => "CFB",
            CamelliaCipherMode::Ctr => "CTR",
            CamelliaCipherMode::CbcCts => "CBC-CTS",
        })
    }
}

// ---------------------------------------------------------------------------
// CamelliaCipher — the algorithm factory (CipherProvider implementation)
// ---------------------------------------------------------------------------

/// Camellia cipher provider/factory.
///
/// One instance of this struct exists per registered algorithm
/// descriptor (e.g. one for `CAMELLIA-128-ECB`, one for
/// `CAMELLIA-256-CBC-CTS`, etc.). It owns the canonical algorithm name,
/// the configured key length, and the operating mode; calling
/// [`CamelliaCipher::new_ctx`] produces a fresh
/// [`CamelliaCipherContext`] that holds the per-operation key schedule
/// and IV state.
///
/// Replaces the C `OSSL_DISPATCH camellia_<size>_<mode>_functions[]`
/// arrays expanded by `IMPLEMENT_generic_cipher` /
/// `IMPLEMENT_cts_cipher` in `cipher_camellia.c`.
#[derive(Debug, Clone)]
pub struct CamelliaCipher {
    /// Canonical algorithm name (e.g. `"CAMELLIA-128-ECB"`).
    name: &'static str,
    /// Key length in bytes — exactly 16, 24, or 32.
    key_bytes: usize,
    /// Operating mode.
    mode: CamelliaCipherMode,
}

impl CamelliaCipher {
    /// Constructs a new Camellia provider entry.
    ///
    /// `name` is stored verbatim and surfaced via [`CipherProvider::name`].
    /// `key_bytes` must be 16, 24, or 32 — this is enforced lazily by
    /// the [`CamelliaCipherContext`] on `*_init`. `mode` selects the
    /// dispatch path.
    #[must_use]
    pub const fn new(name: &'static str, key_bytes: usize, mode: CamelliaCipherMode) -> Self {
        Self {
            name,
            key_bytes,
            mode,
        }
    }

    /// Returns the canonical algorithm name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the configured key length in bytes.
    #[must_use]
    pub const fn key_length(&self) -> usize {
        self.key_bytes
    }

    /// Returns the IV length in bytes (0 for ECB, 16 for every other
    /// mode).
    #[must_use]
    pub const fn iv_length(&self) -> usize {
        self.mode.iv_len()
    }

    /// Returns the EVP-reported block size (16 for ECB/CBC/CBC-CTS,
    /// 1 for OFB/CFB/CTR).
    #[must_use]
    pub const fn block_size(&self) -> usize {
        self.mode.reported_block_size()
    }

    /// Constructs a fresh per-operation [`CamelliaCipherContext`].
    ///
    /// Errors are surfaced via [`ProviderError`] but the inherent
    /// constructor cannot currently fail — the `Result` return type is
    /// reserved for future allocation-checked variants.
    pub fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(CamelliaCipherContext::new(
            self.name,
            self.key_bytes,
            self.mode,
        )))
    }
}

impl CipherProvider for CamelliaCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        self.key_bytes
    }

    fn iv_length(&self) -> usize {
        self.iv_length()
    }

    fn block_size(&self) -> usize {
        self.block_size()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        self.new_ctx()
    }
}

// ---------------------------------------------------------------------------
// CamelliaCipherContext — per-operation cipher state
// ---------------------------------------------------------------------------

/// Per-operation Camellia cipher context.
///
/// Mirrors the C `PROV_CAMELLIA_CTX = PROV_CIPHER_CTX base + CAMELLIA_KEY ks`
/// composite struct. Holds the operating mode, the encryption flag, the
/// IV register (used as next-block-state for CBC, keystream-generator
/// state for OFB/CFB/CTR, and as the chaining IV for CBC-CTS), the
/// pending input buffer for block modes, the keystream slab for stream
/// modes, and — for CBC-CTS only — the selected sub-variant and a
/// one-shot guard.
///
/// Lifecycle:
///   1. `CamelliaCipher::new_ctx` constructs a zero-initialised context.
///   2. `encrypt_init` / `decrypt_init` validates the key/IV and runs
///      the Camellia key schedule.
///   3. `update` may be called multiple times for ECB/CBC/OFB/CFB/CTR.
///      For CBC-CTS, exactly **one** non-empty `update` is permitted —
///      subsequent calls return `Err(ProviderError::Dispatch)`.
///   4. `finalize` flushes any pending partial block (with PKCS#7 pad
///      applied/removed for ECB/CBC); returns 0 for stream modes and
///      CBC-CTS (which finalises inside its single-shot `update`).
///   5. `Drop` zeroizes IV, buffer, and keystream slabs.
//
// The struct intentionally carries four orthogonal `bool` flags that map
// directly to distinct C-level state bits in `PROV_CIPHER_CTX` /
// `PROV_CAMELLIA_CTX`:
//   - `encrypting`  → `ctx->enc`
//   - `initialized` → `ctx->key_set` / fresh-context check
//   - `padding`     → `EVP_CIPHER_CTX_set_padding(...)` / `ctx->pad`
//   - `cts_updated` → `ctx->updated` one-shot guard in `cipher_cts.c`
// Collapsing them into a state-machine enum would obscure the 1:1
// correspondence with the C source (TRACEABILITY) without enabling any
// invalid combinations to be ruled out at the type level — every
// pairwise combination is reachable along legitimate API flows.
#[allow(clippy::struct_excessive_bools)]
pub struct CamelliaCipherContext {
    /// Algorithm name (used for diagnostic messages and the
    /// `"algorithm"` parameter exposed by `get_params`).
    name: &'static str,
    /// Configured key length in bytes (16/24/32).
    key_bytes: usize,
    /// Operating mode.
    mode: CamelliaCipherMode,
    /// `true` for encrypt, `false` for decrypt.
    encrypting: bool,
    /// `true` once a `*_init` call has completed successfully.
    initialized: bool,
    /// PKCS#7 padding flag (only consulted for ECB/CBC).
    padding: bool,
    /// Cached generic-init descriptor used by `get_params`.
    init_config: Option<CipherInitConfig>,
    /// Underlying Camellia key schedule (None until init).
    cipher: Option<Camellia>,
    /// IV / chaining register (length = `mode.iv_len()` once init).
    iv: Vec<u8>,
    /// Pending input bytes for block-mode buffering (ECB/CBC).
    buffer: Vec<u8>,
    /// Pre-computed keystream block for OFB/CFB/CTR.
    keystream: Vec<u8>,
    /// Offset into `keystream` indicating consumed bytes; when
    /// `>= CAMELLIA_BLOCK_SIZE` the next byte triggers a fresh
    /// keystream block generation.
    ks_offset: usize,
    /// CTS sub-variant selection (CBC-CTS only).
    ///
    /// Defaults to [`CtsVariant::Cs1`] and is overridden via
    /// `set_params({"cts_mode": "CS1"|"CS2"|"CS3"})`. Stored as
    /// `Option<CtsVariant>` per rule **R5** — `None` semantically
    /// means "default (CS1)" without any sentinel integer.
    cts_variant: Option<CtsVariant>,
    /// CBC-CTS one-shot guard.
    ///
    /// Mirrors the C `ctx->updated == 1` check in
    /// `cipher_cts.c::ossl_cipher_cbc_cts_block_update`. After the
    /// first non-empty `update` for a CBC-CTS context this flag is
    /// set; subsequent `update` calls return an error.
    cts_updated: bool,
}

impl CamelliaCipherContext {
    /// Constructs a fresh, uninitialised cipher context.
    ///
    /// All buffers start empty; the key schedule is None until
    /// `*_init` is called.
    #[must_use]
    pub fn new(name: &'static str, key_bytes: usize, mode: CamelliaCipherMode) -> Self {
        let key_bits = key_bytes.saturating_mul(8);
        let iv_bits = mode.iv_len().saturating_mul(8);
        let block_bits = CAMELLIA_BLOCK_SIZE.saturating_mul(8);
        // `mode.flags()` is per-instance (CbcCts contributes CTS); every
        // other mode contributes empty flags. Match the C
        // `PROV_CIPHER_FLAG_CTS` per-table flag value.
        let init_config = generic_init_key(
            mode.to_cipher_mode(),
            key_bits,
            block_bits,
            iv_bits,
            mode.flags(),
        );
        Self {
            name,
            key_bytes,
            mode,
            encrypting: false,
            initialized: false,
            padding: mode.default_padding(),
            init_config: Some(init_config),
            cipher: None,
            iv: Vec::new(),
            buffer: Vec::new(),
            keystream: vec![0u8; CAMELLIA_BLOCK_SIZE],
            ks_offset: CAMELLIA_BLOCK_SIZE,
            cts_variant: None,
            cts_updated: false,
        }
    }

    /// Validates that `key.len()` is 16/24/32 AND matches the
    /// configured `key_bytes` for this provider entry.
    fn validate_key_size(&self, key: &[u8]) -> ProviderResult<()> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(ProviderError::Init(format!(
                "Camellia key length must be 16, 24, or 32 bytes, got {}",
                key.len()
            )));
        }
        if key.len() != self.key_bytes {
            return Err(ProviderError::Init(format!(
                "Camellia key length mismatch: expected {} bytes for {}, got {}",
                self.key_bytes,
                self.name,
                key.len()
            )));
        }
        Ok(())
    }

    /// Shared init logic for `encrypt_init` and `decrypt_init`.
    ///
    /// Validates the key and IV, runs the Camellia key schedule, and
    /// resets all per-operation state (buffer, keystream, CTS one-shot
    /// guard). Optionally consumes a `ParamSet` to apply post-init
    /// parameters such as padding and CTS sub-variant.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
        encrypting: bool,
    ) -> ProviderResult<()> {
        self.validate_key_size(key)?;
        let expected_iv = self
            .init_config
            .as_ref()
            .map_or_else(|| self.mode.iv_len(), CipherInitConfig::iv_bytes);
        if let Some(supplied) = iv {
            if supplied.len() != expected_iv {
                return Err(ProviderError::Init(format!(
                    "Camellia IV length mismatch: expected {expected_iv} bytes, got {}",
                    supplied.len()
                )));
            }
            self.iv = supplied.to_vec();
        } else {
            if expected_iv != 0 {
                return Err(ProviderError::Init(format!(
                    "Camellia mode {} requires {expected_iv}-byte IV but none provided",
                    self.mode
                )));
            }
            self.iv = Vec::new();
        }

        let cipher = Camellia::new(key)
            .map_err(|e| ProviderError::Init(format!("Camellia key schedule failed: {e}")))?;

        self.cipher = Some(cipher);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        self.keystream = vec![0u8; CAMELLIA_BLOCK_SIZE];
        self.ks_offset = CAMELLIA_BLOCK_SIZE;
        self.cts_updated = false;
        // CTS variant resets to Cs1 default unless explicitly set via
        // params; mirrors the C `ctx->cts_mode = CTS_CS1` reset on
        // re-init.
        self.cts_variant = None;

        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // ECB mode
    // -----------------------------------------------------------------
    //
    // ECB encrypts/decrypts each 16-byte block independently. Padding
    // (PKCS#7) is applied on encrypt-finalise and stripped on
    // decrypt-finalise. Mirrors the C
    // `ossl_cipher_generic_block_update` + `cipher_hw_camellia_block`
    // dispatch.

    fn update_ecb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        // Split-borrow so we can call `cipher.encrypt_block(...)` while
        // also passing a `&mut Vec<u8>` buffer to the helper closure.
        let CamelliaCipherContext {
            cipher,
            encrypting,
            padding,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let encrypting = *encrypting;
        // When decrypting with padding enabled, hold back the final
        // 16-byte block from the helper so `finalize_ecb` can strip
        // PKCS#7 padding from it.
        let helper_padding = *padding && !encrypting;

        let processed = generic_block_update(
            input,
            CAMELLIA_BLOCK_SIZE,
            buffer,
            helper_padding,
            |blocks| {
                // The closure type required by `generic_block_update`
                // is `FnMut(&[u8]) -> Vec<u8>` — it cannot propagate
                // errors directly. Camellia `encrypt_block` /
                // `decrypt_block` only fail when the slice length is
                // not a block multiple, which is impossible here
                // (verified by the loop condition). We assert this
                // invariant in debug builds to catch drift.
                let mut out = blocks.to_vec();
                let mut offset = 0;
                while offset + CAMELLIA_BLOCK_SIZE <= out.len() {
                    let block = &mut out[offset..offset + CAMELLIA_BLOCK_SIZE];
                    let res = if encrypting {
                        cipher.encrypt_block(block)
                    } else {
                        cipher.decrypt_block(block)
                    };
                    debug_assert!(res.is_ok(), "Camellia block size invariant");
                    let _ = res;
                    offset += CAMELLIA_BLOCK_SIZE;
                }
                out
            },
        )?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, CAMELLIA_BLOCK_SIZE);
                self.buffer.clear();
                let mut processed = Vec::with_capacity(padded.len());
                let mut offset = 0;
                while offset + CAMELLIA_BLOCK_SIZE <= padded.len() {
                    let mut block = [0u8; CAMELLIA_BLOCK_SIZE];
                    block.copy_from_slice(&padded[offset..offset + CAMELLIA_BLOCK_SIZE]);
                    cipher.encrypt_block(&mut block).map_err(|e| {
                        ProviderError::Dispatch(format!("Camellia ECB finalize: {e}"))
                    })?;
                    processed.extend_from_slice(&block);
                    offset += CAMELLIA_BLOCK_SIZE;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "Camellia ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            // Decrypt-with-padding: helper holds back exactly one block.
            if self.buffer.len() != CAMELLIA_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "Camellia ECB decrypt finalize: expected {CAMELLIA_BLOCK_SIZE} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..CAMELLIA_BLOCK_SIZE])
                .map_err(|e| {
                    ProviderError::Dispatch(format!("Camellia ECB decrypt finalize: {e}"))
                })?;
            let unpadded = pkcs7_unpad(&block, CAMELLIA_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "Camellia ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    // -----------------------------------------------------------------
    // CBC mode
    // -----------------------------------------------------------------
    //
    // Standard CBC: encrypt P_i = E_K(P_i XOR C_{i-1}) with C_0 = IV;
    // decrypt P_i = D_K(C_i) XOR C_{i-1}. PKCS#7 padding on finalise.

    fn update_cbc(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let CamelliaCipherContext {
            cipher,
            encrypting,
            padding,
            iv,
            buffer,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let encrypting = *encrypting;
        let helper_padding = *padding && !encrypting;

        // Manual buffering — the helper closure doesn't get the IV.
        buffer.extend_from_slice(input);
        let total = buffer.len();
        let mut full_blocks = (total / CAMELLIA_BLOCK_SIZE) * CAMELLIA_BLOCK_SIZE;
        if helper_padding && full_blocks == total && full_blocks > 0 {
            full_blocks -= CAMELLIA_BLOCK_SIZE;
        }
        if full_blocks == 0 {
            return Ok(0);
        }
        let to_process: Vec<u8> = buffer.drain(..full_blocks).collect();
        let mut processed = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + CAMELLIA_BLOCK_SIZE <= to_process.len() {
            let mut block = [0u8; CAMELLIA_BLOCK_SIZE];
            block.copy_from_slice(&to_process[offset..offset + CAMELLIA_BLOCK_SIZE]);
            if encrypting {
                xor_blocks(&mut block, iv);
                cipher
                    .encrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("Camellia CBC encrypt: {e}")))?;
                iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher
                    .decrypt_block(&mut block)
                    .map_err(|e| ProviderError::Dispatch(format!("Camellia CBC decrypt: {e}")))?;
                xor_blocks(&mut block, iv);
                iv.copy_from_slice(&ct_save);
            }
            processed.extend_from_slice(&block);
            offset += CAMELLIA_BLOCK_SIZE;
        }
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, CAMELLIA_BLOCK_SIZE);
                self.buffer.clear();
                let mut processed = Vec::with_capacity(padded.len());
                let mut offset = 0;
                while offset + CAMELLIA_BLOCK_SIZE <= padded.len() {
                    let mut block = [0u8; CAMELLIA_BLOCK_SIZE];
                    block.copy_from_slice(&padded[offset..offset + CAMELLIA_BLOCK_SIZE]);
                    xor_blocks(&mut block, &self.iv);
                    cipher.encrypt_block(&mut block).map_err(|e| {
                        ProviderError::Dispatch(format!("Camellia CBC finalize: {e}"))
                    })?;
                    self.iv.copy_from_slice(&block);
                    processed.extend_from_slice(&block);
                    offset += CAMELLIA_BLOCK_SIZE;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "Camellia CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != CAMELLIA_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "Camellia CBC decrypt finalize: expected {CAMELLIA_BLOCK_SIZE} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            let ct_save = {
                let mut tmp = [0u8; CAMELLIA_BLOCK_SIZE];
                tmp.copy_from_slice(&block[..CAMELLIA_BLOCK_SIZE]);
                tmp
            };
            cipher
                .decrypt_block(&mut block[..CAMELLIA_BLOCK_SIZE])
                .map_err(|e| {
                    ProviderError::Dispatch(format!("Camellia CBC decrypt finalize: {e}"))
                })?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            let unpadded = pkcs7_unpad(&block, CAMELLIA_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "Camellia CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    // -----------------------------------------------------------------
    // OFB mode (stream)
    // -----------------------------------------------------------------
    //
    // OFB encrypts the IV in-place to produce keystream blocks; the
    // encrypted block becomes the next IV. Encryption == decryption.

    fn update_ofb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let CamelliaCipherContext {
            cipher,
            iv,
            keystream,
            ks_offset,
            ..
        } = self;
        let cipher = cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let processed = generic_stream_update(input, |data| {
            let mut out = Vec::with_capacity(data.len());
            for &byte in data {
                if *ks_offset >= CAMELLIA_BLOCK_SIZE {
                    let res = cipher.encrypt_block(iv);
                    debug_assert!(res.is_ok(), "Camellia block size invariant");
                    let _ = res;
                    keystream.copy_from_slice(iv);
                    *ks_offset = 0;
                }
                out.push(byte ^ keystream[*ks_offset]);
                *ks_offset += 1;
            }
            out
        })?;
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    // -----------------------------------------------------------------
    // CFB-128 mode (stream, byte-granular)
    // -----------------------------------------------------------------
    //
    // CFB-128 produces the keystream by encrypting the IV register, then
    // installs the *output ciphertext* (encrypt) or *input ciphertext*
    // (decrypt) byte into the IV at the same offset, providing
    // self-synchronisation.

    fn update_cfb(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher_ref = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let encrypting = self.encrypting;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= CAMELLIA_BLOCK_SIZE {
                self.keystream.copy_from_slice(&self.iv);
                cipher_ref
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("Camellia CFB encrypt: {e}")))?;
                self.ks_offset = 0;
            }
            let out_byte = byte ^ self.keystream[self.ks_offset];
            // Feedback byte: encrypt installs ciphertext (out_byte);
            // decrypt installs the input (which is the ciphertext).
            let fb = if encrypting { out_byte } else { byte };
            self.iv[self.ks_offset] = fb;
            out.push(out_byte);
            self.ks_offset += 1;
        }
        let written = out.len();
        output.extend_from_slice(&out);
        Ok(written)
    }

    // -----------------------------------------------------------------
    // CTR mode (stream)
    // -----------------------------------------------------------------
    //
    // CTR encrypts the counter (initialised from IV) to produce the
    // keystream; the counter is incremented big-endian after each
    // keystream block. Encryption == decryption.

    fn update_ctr(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher_ref = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.ks_offset >= CAMELLIA_BLOCK_SIZE {
                self.keystream.copy_from_slice(&self.iv);
                cipher_ref
                    .encrypt_block(&mut self.keystream)
                    .map_err(|e| ProviderError::Dispatch(format!("Camellia CTR encrypt: {e}")))?;
                increment_counter(&mut self.iv);
                self.ks_offset = 0;
            }
            out.push(byte ^ self.keystream[self.ks_offset]);
            self.ks_offset += 1;
        }
        let written = out.len();
        output.extend_from_slice(&out);
        Ok(written)
    }

    // -----------------------------------------------------------------
    // CBC-CTS mode (one-shot)
    // -----------------------------------------------------------------
    //
    // CBC ciphertext stealing operates on the entire message in one
    // call. Mirrors the C `ossl_cipher_cbc_cts_block_update` dispatcher
    // in `cipher_cts.c`, which routes to one of CS1/CS2/CS3 helpers
    // based on `ctx->cts_mode`. The C implementation enforces single-
    // shot semantics via `ctx->updated == 1` guard — we replicate via
    // [`Self::cts_updated`].
    //
    // Reference: NIST SP 800-38A Addendum (CS1/CS2/CS3) and RFC 3962
    // §5 (CS3 == Kerberos5 mode).

    fn update_cbc_cts(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if self.cts_updated {
            return Err(ProviderError::Dispatch(
                "Camellia CBC-CTS: only a single update call is permitted per operation".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        let variant = self.cts_variant.unwrap_or_default();
        let result = match (variant, self.encrypting) {
            (CtsVariant::Cs1, true) => self.cts_cs1_encrypt(input, output),
            (CtsVariant::Cs1, false) => self.cts_cs1_decrypt(input, output),
            (CtsVariant::Cs2, true) => self.cts_cs2_encrypt(input, output),
            (CtsVariant::Cs2, false) => self.cts_cs2_decrypt(input, output),
            (CtsVariant::Cs3, true) => self.cts_cs3_encrypt(input, output),
            (CtsVariant::Cs3, false) => self.cts_cs3_decrypt(input, output),
        };
        if result.is_ok() {
            self.cts_updated = true;
        }
        result
    }

    /// Plain CBC over the entire input (used for full-block-multiple
    /// inputs in CS1 / CS2). Returns the number of bytes appended to
    /// `output` on success.
    fn cbc_full_blocks_encrypt(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        debug_assert_eq!(input.len() % CAMELLIA_BLOCK_SIZE, 0);
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let mut processed = Vec::with_capacity(input.len());
        let mut offset = 0;
        while offset + CAMELLIA_BLOCK_SIZE <= input.len() {
            let mut block = [0u8; CAMELLIA_BLOCK_SIZE];
            block.copy_from_slice(&input[offset..offset + CAMELLIA_BLOCK_SIZE]);
            xor_blocks(&mut block, &self.iv);
            cipher
                .encrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("Camellia CBC-CTS encrypt: {e}")))?;
            self.iv.copy_from_slice(&block);
            processed.extend_from_slice(&block);
            offset += CAMELLIA_BLOCK_SIZE;
        }
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    fn cbc_full_blocks_decrypt(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        debug_assert_eq!(input.len() % CAMELLIA_BLOCK_SIZE, 0);
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let mut processed = Vec::with_capacity(input.len());
        let mut offset = 0;
        while offset + CAMELLIA_BLOCK_SIZE <= input.len() {
            let mut block = [0u8; CAMELLIA_BLOCK_SIZE];
            block.copy_from_slice(&input[offset..offset + CAMELLIA_BLOCK_SIZE]);
            let ct_save = block;
            cipher
                .decrypt_block(&mut block)
                .map_err(|e| ProviderError::Dispatch(format!("Camellia CBC-CTS decrypt: {e}")))?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            processed.extend_from_slice(&block);
            offset += CAMELLIA_BLOCK_SIZE;
        }
        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    // ----- CS1 (NIST SP 800-38A Addendum) -----------------------------
    //
    // CS1 layout when residue > 0:
    //     C(0) || C(1) || ... || C(n-2) || C(n-1)* || C(n)
    // where C(n-1)* is the partial last block and C(n) is a full
    // block. When residue == 0 it falls through to plain CBC.

    fn cts_cs1_encrypt(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let total_len = input.len();
        let residue = total_len % CAMELLIA_BLOCK_SIZE;
        if residue == 0 {
            // No stealing — plain CBC end-to-end.
            return self.cbc_full_blocks_encrypt(input, output);
        }
        if total_len < CAMELLIA_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "Camellia CBC-CTS encrypt: input too short for ciphertext stealing".into(),
            ));
        }
        let aligned_len = total_len - residue;
        // Snapshot the starting offset of `output` so we can compute
        // the swap point regardless of pre-existing content.
        let output_start = output.len();
        // Encrypt the leading aligned blocks; this also updates
        // `self.iv` to C(n-1).
        let _ = self.cbc_full_blocks_encrypt(&input[..aligned_len], output)?;

        // Build the stolen-from block: residue bytes of plaintext
        // followed by zero padding from C(n-1).
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let mut tmp = [0u8; CAMELLIA_BLOCK_SIZE];
        tmp[..residue].copy_from_slice(&input[aligned_len..]);
        xor_blocks(&mut tmp, &self.iv);
        cipher
            .encrypt_block(&mut tmp)
            .map_err(|e| ProviderError::Dispatch(format!("Camellia CS1 encrypt: {e}")))?;
        // C(n) is the full encrypted final block; C(n-1)* is the
        // residue-length prefix of the previous ciphertext (currently
        // the last 16 bytes of `output`). CS1 layout: write C(n-1)*
        // first, then C(n).
        let prev_block_start = output.len() - CAMELLIA_BLOCK_SIZE;
        let c_n_minus_1_full = output[prev_block_start..].to_vec();
        output.truncate(prev_block_start);
        output.extend_from_slice(&c_n_minus_1_full[..residue]);
        output.extend_from_slice(&tmp);
        // Update IV to C(n) for chaining hygiene.
        self.iv.copy_from_slice(&tmp);

        // Final added length must equal `total_len`.
        let written = output.len() - output_start;
        debug_assert_eq!(written, total_len);
        Ok(written)
    }

    fn cts_cs1_decrypt(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let total_len = input.len();
        let residue = total_len % CAMELLIA_BLOCK_SIZE;
        if residue == 0 {
            return self.cbc_full_blocks_decrypt(input, output);
        }
        // For CS1 decrypt with non-zero residue we require at least one
        // full block plus the residue bytes (i.e. `total_len >=
        // BLOCK_SIZE + residue`). Since `residue >= 1` here (we
        // returned early for `residue == 0`), this is equivalent to
        // `total_len >= BLOCK_SIZE + 1`, i.e. `total_len > BLOCK_SIZE`.
        // Inputs strictly shorter than one block cannot host a stolen
        // pair regardless of the residue value.
        if total_len < CAMELLIA_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "Camellia CBC-CTS decrypt: input too short (need ≥ 1 full block plus residue)"
                    .into(),
            ));
        }
        // Process leading aligned blocks except the last full block.
        let leading_len = total_len - CAMELLIA_BLOCK_SIZE - residue;
        if leading_len > 0 {
            self.cbc_full_blocks_decrypt(&input[..leading_len], output)?;
        }
        // After processing leading blocks, `self.iv` holds the
        // ciphertext of the (n-2)th block, which is the chaining IV
        // for decrypting the stolen-block pair.
        let mid_iv = {
            let mut tmp = [0u8; CAMELLIA_BLOCK_SIZE];
            tmp.copy_from_slice(&self.iv);
            tmp
        };
        // CS1: C(n) appears at offset `residue` (after C(n-1)*).
        let cn = {
            let mut tmp = [0u8; CAMELLIA_BLOCK_SIZE];
            tmp.copy_from_slice(
                &input[leading_len + residue..leading_len + residue + CAMELLIA_BLOCK_SIZE],
            );
            tmp
        };
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        // Decrypt C(n) with zero IV to get raw block (then XOR with
        // mid_iv at the right time).
        let mut pt_last_block = cn;
        cipher
            .decrypt_block(&mut pt_last_block)
            .map_err(|e| ProviderError::Dispatch(format!("Camellia CS1 decrypt: {e}")))?;
        // Build ct_mid = (C(n-1)* || pt_last_block[residue..]).
        let mut ct_mid = [0u8; CAMELLIA_BLOCK_SIZE];
        ct_mid[..residue].copy_from_slice(&input[leading_len..leading_len + residue]);
        ct_mid[residue..].copy_from_slice(&pt_last_block[residue..]);
        // Plaintext suffix of P(n) = pt_last_block[..residue] XOR
        // C(n-1)*[..residue].
        let mut p_n_suffix = [0u8; CAMELLIA_BLOCK_SIZE];
        p_n_suffix[..residue].copy_from_slice(&pt_last_block[..residue]);
        xor_blocks(
            &mut p_n_suffix[..residue],
            &input[leading_len..leading_len + residue],
        );
        // Decrypt ct_mid using mid_iv to recover P(n-1).
        let mut p_n_minus_1 = ct_mid;
        cipher
            .decrypt_block(&mut p_n_minus_1)
            .map_err(|e| ProviderError::Dispatch(format!("Camellia CS1 decrypt: {e}")))?;
        xor_blocks(&mut p_n_minus_1, &mid_iv);
        // Append P(n-1) (full block) + P(n) (residue bytes).
        output.extend_from_slice(&p_n_minus_1);
        output.extend_from_slice(&p_n_suffix[..residue]);
        // Update IV to C(n) for chaining hygiene.
        self.iv.copy_from_slice(&cn);

        let written = leading_len + CAMELLIA_BLOCK_SIZE + residue;
        debug_assert_eq!(written, total_len);
        Ok(written)
    }

    // ----- CS2 -- like CS1 if aligned, else CS3 -----------------------

    fn cts_cs2_encrypt(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if input.len() % CAMELLIA_BLOCK_SIZE == 0 {
            self.cbc_full_blocks_encrypt(input, output)
        } else {
            self.cts_cs3_encrypt(input, output)
        }
    }

    fn cts_cs2_decrypt(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if input.len() % CAMELLIA_BLOCK_SIZE == 0 {
            self.cbc_full_blocks_decrypt(input, output)
        } else {
            self.cts_cs3_decrypt(input, output)
        }
    }

    // ----- CS3 (Kerberos5, RFC 3962) ----------------------------------
    //
    // CS3 layout (always swap-of-last-two):
    //     C(0) || C(1) || ... || C(n-2) || C(n) || C(n-1)*
    // The aligned-input case yields a swap of the last two ciphertext
    // blocks — distinguishing CS3 from CS2/CS1.

    fn cts_cs3_encrypt(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let total_len = input.len();
        if total_len < CAMELLIA_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "Camellia CBC-CTS (CS3) encrypt: input must be ≥ 1 block".into(),
            ));
        }
        if total_len == CAMELLIA_BLOCK_SIZE {
            // Single-block input: plain CBC, no swap.
            return self.cbc_full_blocks_encrypt(input, output);
        }
        let mut residue = total_len % CAMELLIA_BLOCK_SIZE;
        if residue == 0 {
            residue = CAMELLIA_BLOCK_SIZE;
        }
        let aligned_len = total_len - residue;
        // Encrypt the leading aligned blocks (bringing iv to C(n-1)).
        if aligned_len > 0 {
            self.cbc_full_blocks_encrypt(&input[..aligned_len], output)?;
        }
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        // Build tmp = (P(n) || zero padding); encrypt under the chaining IV.
        let mut tmp = [0u8; CAMELLIA_BLOCK_SIZE];
        tmp[..residue].copy_from_slice(&input[aligned_len..]);
        xor_blocks(&mut tmp, &self.iv);
        cipher
            .encrypt_block(&mut tmp)
            .map_err(|e| ProviderError::Dispatch(format!("Camellia CS3 encrypt: {e}")))?;
        // Replace the last full block in output with C(n) (= tmp), then
        // append C(n-1)* (residue bytes of the original C(n-1)).
        let prev_block_start = output.len() - CAMELLIA_BLOCK_SIZE;
        let c_n_minus_1_full = output[prev_block_start..].to_vec();
        output.truncate(prev_block_start);
        output.extend_from_slice(&tmp);
        output.extend_from_slice(&c_n_minus_1_full[..residue]);
        // Update IV to C(n).
        self.iv.copy_from_slice(&tmp);

        let written = aligned_len + residue;
        debug_assert_eq!(written, total_len);
        Ok(written)
    }

    fn cts_cs3_decrypt(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        let total_len = input.len();
        if total_len < CAMELLIA_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(
                "Camellia CBC-CTS (CS3) decrypt: input must be ≥ 1 block".into(),
            ));
        }
        if total_len == CAMELLIA_BLOCK_SIZE {
            return self.cbc_full_blocks_decrypt(input, output);
        }
        let mut residue = total_len % CAMELLIA_BLOCK_SIZE;
        if residue == 0 {
            residue = CAMELLIA_BLOCK_SIZE;
        }
        // Process all leading full blocks except the last block-pair
        // (last full block + residue tail).
        let leading_len = total_len - CAMELLIA_BLOCK_SIZE - residue;
        if leading_len > 0 {
            self.cbc_full_blocks_decrypt(&input[..leading_len], output)?;
        }
        // After processing, self.iv = C(n-2) ciphertext (the chaining
        // value for decrypting the stolen pair).
        let mid_iv = {
            let mut tmp = [0u8; CAMELLIA_BLOCK_SIZE];
            tmp.copy_from_slice(&self.iv);
            tmp
        };
        // CS3: C(n) is FIRST in the stolen pair (offset leading_len),
        // C(n-1)* follows.
        let cn = {
            let mut tmp = [0u8; CAMELLIA_BLOCK_SIZE];
            tmp.copy_from_slice(&input[leading_len..leading_len + CAMELLIA_BLOCK_SIZE]);
            tmp
        };
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| ProviderError::Dispatch("Camellia cipher not initialised".into()))?;
        let mut pt_last_block = cn;
        cipher
            .decrypt_block(&mut pt_last_block)
            .map_err(|e| ProviderError::Dispatch(format!("Camellia CS3 decrypt: {e}")))?;
        // Build ct_mid = C(n-1)* || pt_last_block[residue..] (zero-pad
        // suffix of plaintext from C(n) decryption, then C(n-1)* prefix).
        let mut ct_mid = [0u8; CAMELLIA_BLOCK_SIZE];
        ct_mid[..residue].copy_from_slice(
            &input[leading_len + CAMELLIA_BLOCK_SIZE..leading_len + CAMELLIA_BLOCK_SIZE + residue],
        );
        if residue != CAMELLIA_BLOCK_SIZE {
            ct_mid[residue..].copy_from_slice(&pt_last_block[residue..]);
        }
        // P(n) suffix = pt_last_block[..residue] XOR C(n-1)*[..residue].
        let mut p_n = [0u8; CAMELLIA_BLOCK_SIZE];
        p_n[..residue].copy_from_slice(&pt_last_block[..residue]);
        xor_blocks(
            &mut p_n[..residue],
            &input[leading_len + CAMELLIA_BLOCK_SIZE..leading_len + CAMELLIA_BLOCK_SIZE + residue],
        );
        // Decrypt ct_mid (= reconstructed C(n-1)) under mid_iv to
        // recover P(n-1).
        let mut p_n_minus_1 = ct_mid;
        cipher
            .decrypt_block(&mut p_n_minus_1)
            .map_err(|e| ProviderError::Dispatch(format!("Camellia CS3 decrypt: {e}")))?;
        xor_blocks(&mut p_n_minus_1, &mid_iv);
        output.extend_from_slice(&p_n_minus_1);
        output.extend_from_slice(&p_n[..residue]);
        // Update IV to C(n) for chaining hygiene.
        self.iv.copy_from_slice(&cn);

        let written = leading_len + CAMELLIA_BLOCK_SIZE + residue;
        debug_assert_eq!(written, total_len);
        Ok(written)
    }
}

// =====================================================================
// CipherContext trait implementation
// =====================================================================
//
// Provider-facing dispatch surface. The C source uses an OSSL_DISPATCH
// table populated by `cipher_camellia.c` plus the cts_inc patterns —
// here we use a Rust trait-object so callers (the EVP layer) can drive
// every Camellia mode through a uniform interface.

impl CipherContext for CamelliaCipherContext {
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
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "Camellia cipher context not initialised".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            CamelliaCipherMode::Ecb => self.update_ecb(input, output),
            CamelliaCipherMode::Cbc => self.update_cbc(input, output),
            CamelliaCipherMode::Ofb => self.update_ofb(input, output),
            CamelliaCipherMode::Cfb => self.update_cfb(input, output),
            CamelliaCipherMode::Ctr => self.update_ctr(input, output),
            CamelliaCipherMode::CbcCts => self.update_cbc_cts(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "Camellia cipher context not initialised".into(),
            ));
        }
        match self.mode {
            CamelliaCipherMode::Ecb => self.finalize_ecb(output),
            CamelliaCipherMode::Cbc => self.finalize_cbc(output),
            // Stream modes (OFB/CFB/CTR) and CBC-CTS finalise inside
            // `update`: the former consume bytes incrementally with no
            // pending state; the latter is one-shot, mirroring
            // `ossl_cipher_cbc_cts_block_final` in `cipher_cts.c` which
            // simply returns 0 bytes.
            CamelliaCipherMode::Ofb
            | CamelliaCipherMode::Cfb
            | CamelliaCipherMode::Ctr
            | CamelliaCipherMode::CbcCts => Ok(0),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let key_bits = self.key_bytes.saturating_mul(8);
        let block_bits = self.mode.reported_block_size().saturating_mul(8);
        let iv_bits = self.mode.iv_len().saturating_mul(8);
        let cipher_mode = self.mode.to_cipher_mode();
        let flags = self.mode.flags();
        let mut ps = generic_get_params(cipher_mode, flags, key_bits, block_bits, iv_bits);
        ps.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        // Surface the active CTS variant for callers that introspect
        // it (FIPS indicator, EVP_CIPHER_CTX_get_params).
        if matches!(self.mode, CamelliaCipherMode::CbcCts) {
            let variant = self.cts_variant.unwrap_or_default();
            ps.set(
                param_keys::CTS_MODE,
                ParamValue::Utf8String(variant.as_str().to_string()),
            );
        }
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Padding (PKCS#7) toggle. Only meaningful for ECB and CBC —
        // stream and CTS modes ignore it. Mirrors the C check in
        // ciphercommon.c which silently drops the parameter for
        // non-padded modes.
        if let Some(value) = params.get(param_keys::PADDING) {
            let int_value: u64 = match value {
                ParamValue::UInt32(v) => u64::from(*v),
                ParamValue::UInt64(v) => *v,
                ParamValue::Int32(v) => {
                    if *v < 0 {
                        return Err(ProviderError::Dispatch(format!(
                            "Camellia set_params: negative padding value {v}"
                        )));
                    }
                    u64::try_from(*v).map_err(|e| {
                        ProviderError::Dispatch(format!(
                            "Camellia set_params: padding conversion failed: {e}"
                        ))
                    })?
                }
                ParamValue::Int64(v) => {
                    if *v < 0 {
                        return Err(ProviderError::Dispatch(format!(
                            "Camellia set_params: negative padding value {v}"
                        )));
                    }
                    u64::try_from(*v).map_err(|e| {
                        ProviderError::Dispatch(format!(
                            "Camellia set_params: padding conversion failed: {e}"
                        ))
                    })?
                }
                other => {
                    return Err(ProviderError::Dispatch(format!(
                        "Camellia set_params: unexpected type for padding: {other:?}"
                    )));
                }
            };
            if matches!(self.mode, CamelliaCipherMode::Ecb | CamelliaCipherMode::Cbc) {
                self.padding = int_value != 0;
            }
        }

        // CTS mode (CS1/CS2/CS3). Only honoured for CBC-CTS; emitted
        // via `OSSL_CIPHER_PARAM_CTS_MODE` as a UTF-8 string.
        if let Some(value) = params.get(param_keys::CTS_MODE) {
            match value {
                ParamValue::Utf8String(s) => {
                    if matches!(self.mode, CamelliaCipherMode::CbcCts) {
                        let variant = CtsVariant::from_str_ci(s).map_err(|_| {
                            ProviderError::Dispatch(format!(
                                "Camellia set_params: unknown CTS mode '{s}' (expected CS1, CS2, or CS3)"
                            ))
                        })?;
                        self.cts_variant = Some(variant);
                    } else {
                        return Err(ProviderError::Dispatch(format!(
                            "Camellia set_params: cts_mode parameter is not valid for {} mode",
                            self.mode
                        )));
                    }
                }
                other => {
                    return Err(ProviderError::Dispatch(format!(
                        "Camellia set_params: cts_mode must be a UTF-8 string, got {other:?}"
                    )));
                }
            }
        }

        Ok(())
    }
}

// =====================================================================
// Drop / secure cleanup
// =====================================================================
//
// Replaces the C `ossl_cipher_generic_freectx` that calls
// `OPENSSL_clear_free`. Rust's ownership model handles deallocation; we
// only need to scrub key-derived buffers. The `Camellia` field already
// derives `ZeroizeOnDrop` so its key schedule is wiped automatically.

impl Drop for CamelliaCipherContext {
    fn drop(&mut self) {
        self.iv.zeroize();
        self.buffer.zeroize();
        self.keystream.zeroize();
    }
}

// =====================================================================
// Free-standing helpers
// =====================================================================

/// XORs `src` into `dest` byte-wise. Equivalent to the inline
/// `for (i = 0; i < n; i++) a[i] ^= b[i]` idiom in `cipher_cts.c`.
#[inline]
fn xor_blocks(dest: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dest.len(), src.len());
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Big-endian 128-bit counter increment used by CTR mode.
///
/// Mirrors `ctr128_inc` in `crypto/modes/ctr128.c`. Wraps cleanly when
/// the entire counter rolls over (CTR security boundary — the caller
/// must not reuse keys past 2^128 blocks; that's enforced at the EVP
/// layer for production paths).
fn increment_counter(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        let (val, overflow) = byte.overflowing_add(1);
        *byte = val;
        if !overflow {
            return;
        }
    }
}

// =====================================================================
// Algorithm descriptors (exposed to the provider registry)
// =====================================================================
//
// 18 total entries:
//   * 5 base modes (ECB, CBC, OFB, CFB, CTR) × 3 key sizes (128/192/256)
//   * CBC-CTS × 3 key sizes
//
// Naming matches the C provider: `CAMELLIA-{KEYBITS}-{MODE}` with
// `provider=default` property advertising the default provider role
// (legacy provider mounts identical names through its own descriptor
// vector elsewhere).

/// Returns the full vector of algorithm descriptors exposed by this
/// module. Designed for one-shot registration during provider load —
/// each call leaks `'static` strings (matching ARIA / generic AES
/// patterns elsewhere in the workspace).
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::with_capacity(18);

    // Base modes: ECB / CBC / OFB / CFB / CTR.
    let basic_modes: &[(&str, CamelliaCipherMode, &'static str)] = &[
        (
            "ECB",
            CamelliaCipherMode::Ecb,
            "Camellia Electronic Codebook mode cipher",
        ),
        (
            "CBC",
            CamelliaCipherMode::Cbc,
            "Camellia Cipher Block Chaining mode cipher",
        ),
        (
            "OFB",
            CamelliaCipherMode::Ofb,
            "Camellia Output Feedback mode cipher",
        ),
        (
            "CFB",
            CamelliaCipherMode::Cfb,
            "Camellia Cipher Feedback (128-bit) mode cipher",
        ),
        (
            "CTR",
            CamelliaCipherMode::Ctr,
            "Camellia Counter mode cipher",
        ),
    ];

    let key_sizes: &[(usize, usize)] = &[(128, 16), (192, 24), (256, 32)];

    for (mode_suffix, mode, description) in basic_modes {
        for &(key_bits, key_bytes) in key_sizes {
            let name = format!("CAMELLIA-{key_bits}-{mode_suffix}");
            let leaked: &'static str = Box::leak(name.into_boxed_str());
            descs.push(AlgorithmDescriptor {
                names: vec![leaked],
                property: "provider=default",
                description,
            });
            // Sanity instantiation — guarantees the descriptor is
            // wired to a constructable cipher (rule R10).
            let _ = CamelliaCipher::new(leaked, key_bytes, *mode);
        }
    }

    // CBC-CTS variants (CS1/CS2/CS3 picked at runtime via cts_mode
    // parameter). The descriptor itself does not encode the variant —
    // only the high-level "CBC-CTS" mode.
    let cts_descriptions: &[(usize, usize, &'static str)] = &[
        (
            128,
            16,
            "Camellia-128 CBC mode with NIST SP 800-38A ciphertext stealing",
        ),
        (
            192,
            24,
            "Camellia-192 CBC mode with NIST SP 800-38A ciphertext stealing",
        ),
        (
            256,
            32,
            "Camellia-256 CBC mode with NIST SP 800-38A ciphertext stealing",
        ),
    ];

    for &(key_bits, key_bytes, description) in cts_descriptions {
        let name = format!("CAMELLIA-{key_bits}-CBC-CTS");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description,
        });
        let _ = CamelliaCipher::new(leaked, key_bytes, CamelliaCipherMode::CbcCts);
    }

    debug_assert_eq!(
        descs.len(),
        18,
        "Camellia must expose exactly 18 descriptors (5 base modes × 3 key sizes + 3 CBC-CTS)"
    );
    descs
}

// =====================================================================
// Unit tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // --- Descriptor surface tests ------------------------------------

    #[test]
    fn descriptor_count_is_18() {
        let descs = descriptors();
        assert_eq!(
            descs.len(),
            18,
            "Camellia must expose exactly 18 descriptors"
        );
    }

    #[test]
    fn descriptor_names_are_unique_and_well_formed() {
        let descs = descriptors();
        let mut seen: HashSet<&'static str> = HashSet::new();
        for desc in &descs {
            assert_eq!(
                desc.names.len(),
                1,
                "each descriptor advertises exactly one name"
            );
            let name = desc.names[0];
            assert!(
                name.starts_with("CAMELLIA-"),
                "descriptor name {name} must start with 'CAMELLIA-'"
            );
            assert!(
                name.contains("128") || name.contains("192") || name.contains("256"),
                "descriptor name {name} must encode key size"
            );
            assert!(seen.insert(name), "descriptor name {name} is duplicated");
            assert_eq!(desc.property, "provider=default");
            assert!(!desc.description.is_empty());
        }
    }

    #[test]
    fn descriptor_spot_checks() {
        let descs = descriptors();
        let names: HashSet<&'static str> = descs.iter().flat_map(|d| d.names.clone()).collect();
        for expected in [
            "CAMELLIA-128-ECB",
            "CAMELLIA-192-CBC",
            "CAMELLIA-256-OFB",
            "CAMELLIA-128-CFB",
            "CAMELLIA-256-CTR",
            "CAMELLIA-128-CBC-CTS",
            "CAMELLIA-192-CBC-CTS",
            "CAMELLIA-256-CBC-CTS",
        ] {
            assert!(
                names.contains(expected),
                "expected descriptor '{expected}' missing"
            );
        }
    }

    // --- CtsVariant parsing ------------------------------------------

    #[test]
    fn cts_variant_parsing_is_case_insensitive() {
        assert_eq!(
            CtsVariant::from_str_ci("CS1").expect("CS1 valid"),
            CtsVariant::Cs1
        );
        assert_eq!(
            CtsVariant::from_str_ci("cs1").expect("cs1 valid"),
            CtsVariant::Cs1
        );
        assert_eq!(
            CtsVariant::from_str_ci("Cs2").expect("Cs2 valid"),
            CtsVariant::Cs2
        );
        assert_eq!(
            CtsVariant::from_str_ci("CS3").expect("CS3 valid"),
            CtsVariant::Cs3
        );
        assert!(CtsVariant::from_str_ci("cs4").is_err());
        assert!(CtsVariant::from_str_ci("").is_err());
    }

    #[test]
    fn cts_variant_default_is_cs1() {
        assert_eq!(CtsVariant::default(), CtsVariant::Cs1);
    }

    // --- Provider-level introspection --------------------------------

    #[test]
    fn cipher_provider_metadata_is_consistent() {
        let cipher = CamelliaCipher::new("CAMELLIA-128-ECB", 16, CamelliaCipherMode::Ecb);
        assert_eq!(cipher.name(), "CAMELLIA-128-ECB");
        assert_eq!(cipher.key_length(), 16);
        assert_eq!(cipher.iv_length(), 0);
        assert_eq!(cipher.block_size(), 16);

        let cbc_cipher = CamelliaCipher::new("CAMELLIA-256-CBC", 32, CamelliaCipherMode::Cbc);
        assert_eq!(cbc_cipher.key_length(), 32);
        assert_eq!(cbc_cipher.iv_length(), 16);
        assert_eq!(cbc_cipher.block_size(), 16);

        let ctr_cipher = CamelliaCipher::new("CAMELLIA-192-CTR", 24, CamelliaCipherMode::Ctr);
        assert_eq!(ctr_cipher.iv_length(), 16);
        assert_eq!(ctr_cipher.block_size(), 1);
    }

    // --- Round-trip tests with a known key ---------------------------

    fn make_cipher_ctx(
        name: &'static str,
        key_bytes: usize,
        mode: CamelliaCipherMode,
    ) -> CamelliaCipherContext {
        CamelliaCipherContext::new(name, key_bytes, mode)
    }

    #[test]
    fn ecb_round_trip_128() {
        let key = vec![0x11u8; 16];
        let plaintext = b"Camellia ECB hello!"; // 19 bytes - PKCS7 will pad
        let mut enc = make_cipher_ctx("CAMELLIA-128-ECB", 16, CamelliaCipherMode::Ecb);
        enc.encrypt_init(&key, None, None).expect("encrypt_init");
        let mut ct = Vec::new();
        enc.update(plaintext, &mut ct).expect("update");
        enc.finalize(&mut ct).expect("finalize");

        let mut dec = make_cipher_ctx("CAMELLIA-128-ECB", 16, CamelliaCipherMode::Ecb);
        dec.decrypt_init(&key, None, None).expect("decrypt_init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");
        dec.finalize(&mut pt).expect("finalize");
        assert_eq!(pt.as_slice(), plaintext);
    }

    #[test]
    fn cbc_round_trip_192() {
        let key = vec![0x22u8; 24];
        let iv = vec![0x44u8; 16];
        let plaintext: Vec<u8> = (0..50u8).collect();
        let mut enc = make_cipher_ctx("CAMELLIA-192-CBC", 24, CamelliaCipherMode::Cbc);
        enc.encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut ct = Vec::new();
        enc.update(&plaintext, &mut ct).expect("update");
        enc.finalize(&mut ct).expect("finalize");

        let mut dec = make_cipher_ctx("CAMELLIA-192-CBC", 24, CamelliaCipherMode::Cbc);
        dec.decrypt_init(&key, Some(&iv), None)
            .expect("decrypt_init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");
        dec.finalize(&mut pt).expect("finalize");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn ctr_round_trip_256() {
        let key = vec![0x33u8; 32];
        let iv = vec![0x55u8; 16];
        let plaintext = b"Camellia 256-bit CTR mode end-to-end";
        let mut enc = make_cipher_ctx("CAMELLIA-256-CTR", 32, CamelliaCipherMode::Ctr);
        enc.encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut ct = Vec::new();
        enc.update(plaintext, &mut ct).expect("update");
        enc.finalize(&mut ct).expect("finalize");
        assert_eq!(ct.len(), plaintext.len());
        assert_ne!(ct, plaintext);

        let mut dec = make_cipher_ctx("CAMELLIA-256-CTR", 32, CamelliaCipherMode::Ctr);
        dec.decrypt_init(&key, Some(&iv), None)
            .expect("decrypt_init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");
        dec.finalize(&mut pt).expect("finalize");
        assert_eq!(pt.as_slice(), plaintext);
    }

    #[test]
    fn ofb_round_trip_128() {
        let key = vec![0x44u8; 16];
        let iv = vec![0x77u8; 16];
        let plaintext = b"Camellia OFB stream";
        let mut enc = make_cipher_ctx("CAMELLIA-128-OFB", 16, CamelliaCipherMode::Ofb);
        enc.encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut ct = Vec::new();
        enc.update(plaintext, &mut ct).expect("update");
        enc.finalize(&mut ct).expect("finalize");

        let mut dec = make_cipher_ctx("CAMELLIA-128-OFB", 16, CamelliaCipherMode::Ofb);
        dec.decrypt_init(&key, Some(&iv), None)
            .expect("decrypt_init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");
        dec.finalize(&mut pt).expect("finalize");
        assert_eq!(pt.as_slice(), plaintext);
    }

    #[test]
    fn cfb_round_trip_256() {
        let key = vec![0x66u8; 32];
        let iv = vec![0x88u8; 16];
        let plaintext: Vec<u8> = (0..23u8).collect();
        let mut enc = make_cipher_ctx("CAMELLIA-256-CFB", 32, CamelliaCipherMode::Cfb);
        enc.encrypt_init(&key, Some(&iv), None)
            .expect("encrypt_init");
        let mut ct = Vec::new();
        enc.update(&plaintext, &mut ct).expect("update");
        enc.finalize(&mut ct).expect("finalize");

        let mut dec = make_cipher_ctx("CAMELLIA-256-CFB", 32, CamelliaCipherMode::Cfb);
        dec.decrypt_init(&key, Some(&iv), None)
            .expect("decrypt_init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");
        dec.finalize(&mut pt).expect("finalize");
        assert_eq!(pt, plaintext);
    }

    // --- CBC-CTS round-trip tests ------------------------------------

    fn cts_round_trip(variant: CtsVariant, key_bytes: usize, plaintext_len: usize) {
        let key: Vec<u8> = (0..key_bytes as u8).collect();
        let iv = vec![0xA5u8; 16];
        let plaintext: Vec<u8> = (0..plaintext_len as u32)
            .map(|i| (i & 0xFF) as u8)
            .collect();

        let name: &'static str = match key_bytes {
            16 => "CAMELLIA-128-CBC-CTS",
            24 => "CAMELLIA-192-CBC-CTS",
            32 => "CAMELLIA-256-CBC-CTS",
            _ => unreachable!(),
        };

        let mut enc = make_cipher_ctx(name, key_bytes, CamelliaCipherMode::CbcCts);
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String(variant.as_str().to_string()),
        );
        enc.encrypt_init(&key, Some(&iv), Some(&ps))
            .expect("encrypt_init");
        let mut ct = Vec::new();
        enc.update(&plaintext, &mut ct).expect("CTS update");
        enc.finalize(&mut ct).expect("CTS finalize");
        assert_eq!(
            ct.len(),
            plaintext.len(),
            "CBC-CTS preserves length (variant={variant:?}, len={plaintext_len})"
        );

        let mut dec = make_cipher_ctx(name, key_bytes, CamelliaCipherMode::CbcCts);
        let mut ps2 = ParamSet::new();
        ps2.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String(variant.as_str().to_string()),
        );
        dec.decrypt_init(&key, Some(&iv), Some(&ps2))
            .expect("decrypt_init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("CTS update (dec)");
        dec.finalize(&mut pt).expect("CTS finalize (dec)");
        assert_eq!(
            pt, plaintext,
            "CBC-CTS round-trip mismatch (variant={variant:?}, len={plaintext_len})"
        );
    }

    #[test]
    fn cts_cs1_round_trip_unaligned() {
        cts_round_trip(CtsVariant::Cs1, 16, 23);
        cts_round_trip(CtsVariant::Cs1, 24, 47);
        cts_round_trip(CtsVariant::Cs1, 32, 33);
    }

    #[test]
    fn cts_cs1_round_trip_aligned() {
        // residue == 0 → plain CBC.
        cts_round_trip(CtsVariant::Cs1, 16, 32);
        cts_round_trip(CtsVariant::Cs1, 32, 64);
    }

    #[test]
    fn cts_cs2_round_trip() {
        // CS2 mirrors CS1 when aligned and CS3 otherwise.
        cts_round_trip(CtsVariant::Cs2, 16, 32);
        cts_round_trip(CtsVariant::Cs2, 24, 33);
        cts_round_trip(CtsVariant::Cs2, 32, 47);
    }

    #[test]
    fn cts_cs3_round_trip() {
        cts_round_trip(CtsVariant::Cs3, 16, 17);
        cts_round_trip(CtsVariant::Cs3, 24, 32);
        cts_round_trip(CtsVariant::Cs3, 32, 65);
    }

    #[test]
    fn cts_one_shot_guard() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        let mut ctx = make_cipher_ctx("CAMELLIA-128-CBC-CTS", 16, CamelliaCipherMode::CbcCts);
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String("CS1".to_string()),
        );
        ctx.encrypt_init(&key, Some(&iv), Some(&ps))
            .expect("encrypt_init");
        let mut out = Vec::new();
        ctx.update(&[0u8; 33], &mut out).expect("first update");
        // Second update must fail per cipher_cts.c semantics.
        let result = ctx.update(&[0u8; 16], &mut out);
        assert!(result.is_err(), "second CTS update must error");
    }

    #[test]
    fn cts_too_short_errors() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        // CS3 requires at least 16 bytes (1 block).
        let mut ctx = make_cipher_ctx("CAMELLIA-128-CBC-CTS", 16, CamelliaCipherMode::CbcCts);
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String("CS3".to_string()),
        );
        ctx.encrypt_init(&key, Some(&iv), Some(&ps))
            .expect("encrypt_init");
        let mut out = Vec::new();
        let result = ctx.update(&[0u8; 8], &mut out);
        assert!(result.is_err(), "CS3 with < 16 bytes must error");
    }

    // --- Helper function tests ---------------------------------------

    #[test]
    fn xor_blocks_works() {
        let mut a = [0xAAu8; 4];
        let b = [0x55u8; 4];
        xor_blocks(&mut a, &b);
        assert_eq!(a, [0xFF, 0xFF, 0xFF, 0xFF]);
        xor_blocks(&mut a, &[0xFFu8; 4]);
        assert_eq!(a, [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn increment_counter_no_overflow() {
        let mut counter = [0u8; 4];
        increment_counter(&mut counter);
        assert_eq!(counter, [0, 0, 0, 1]);
        increment_counter(&mut counter);
        assert_eq!(counter, [0, 0, 0, 2]);
    }

    #[test]
    fn increment_counter_carries_correctly() {
        let mut counter = [0x00u8, 0x00, 0x00, 0xFF];
        increment_counter(&mut counter);
        assert_eq!(counter, [0x00, 0x00, 0x01, 0x00]);

        let mut counter = [0xFFu8, 0xFF, 0xFF, 0xFE];
        increment_counter(&mut counter);
        assert_eq!(counter, [0xFF, 0xFF, 0xFF, 0xFF]);
        increment_counter(&mut counter);
        assert_eq!(counter, [0x00, 0x00, 0x00, 0x00]); // wrap
    }

    // --- CTS mode parameter handling ---------------------------------

    #[test]
    fn cts_params_round_trip_via_get_params() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        let mut ctx = make_cipher_ctx("CAMELLIA-128-CBC-CTS", 16, CamelliaCipherMode::CbcCts);
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String("CS3".to_string()),
        );
        ctx.encrypt_init(&key, Some(&iv), Some(&ps))
            .expect("encrypt_init");
        let out = ctx.get_params().expect("get_params");
        let actual = out.get(param_keys::CTS_MODE).expect("cts_mode present");
        match actual {
            ParamValue::Utf8String(s) => assert_eq!(s, "CS3"),
            other => panic!("expected Utf8String, got {other:?}"),
        }
    }

    #[test]
    fn cts_unknown_variant_errors() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        let mut ctx = make_cipher_ctx("CAMELLIA-128-CBC-CTS", 16, CamelliaCipherMode::CbcCts);
        let mut ps = ParamSet::new();
        ps.set(
            param_keys::CTS_MODE,
            ParamValue::Utf8String("CS9".to_string()),
        );
        let result = ctx.encrypt_init(&key, Some(&iv), Some(&ps));
        assert!(result.is_err(), "unknown CTS variant must error");
    }

    // --- Key validation ----------------------------------------------

    #[test]
    fn invalid_key_size_rejected() {
        let mut ctx = make_cipher_ctx("CAMELLIA-128-ECB", 16, CamelliaCipherMode::Ecb);
        let bad_key = vec![0u8; 15];
        assert!(ctx.encrypt_init(&bad_key, None, None).is_err());
    }
}
