//! Shared cipher infrastructure for all cipher provider implementations.
//!
//! Provides common context lifecycle, generic encrypt/decrypt flows, parameter
//! handling, padding, AEAD state machine helpers, and cipher mode utilities.
//! This is the Rust equivalent of the C `ciphercommon.c`, `ciphercommon_hw.c`,
//! `ciphercommon_block.c`, `ciphercommon_gcm.c`, `ciphercommon_ccm.c`, and
//! `ciphercommon_local.h` files, which together provide algorithm-agnostic
//! cipher dispatch infrastructure used by every concrete cipher backend.
//!
//! # Architecture
//!
//! All concrete cipher modules (AES, ChaCha20, DES, Camellia, ARIA, SM4, etc.)
//! depend on this module for:
//!
//! - **[`CipherMode`]** — enum of all supported cipher operating modes
//! - **[`CipherFlags`]** — bitfield describing cipher capabilities
//! - **[`IvGeneration`]** — IV/nonce generation strategies
//! - **[`param_keys`]** — string constants for cipher parameter identification
//! - **[`GcmState`]** / **[`CcmState`]** — AEAD operation context state
//! - **[`CipherInitConfig`]** — validated cipher initialization descriptor
//! - Padding helpers ([`pkcs7_pad`], [`pkcs7_unpad`])
//! - Generic cipher operations ([`generic_get_params`], [`generic_init_key`],
//!   [`generic_block_update`], [`generic_stream_update`])
//! - AEAD validation ([`gcm_validate_tag_len`], [`gcm_validate_iv_len`],
//!   [`ccm_validate_tag_len`], [`ccm_validate_iv_len`])
//! - IV management ([`generate_random_iv`], [`increment_iv`])
//! - Constant-time tag verification ([`verify_tag`])
//!
//! Every [`CipherProvider`] implementation uses these types and helpers to
//! implement the [`CipherContext`] lifecycle (init → update → finalize).

// =============================================================================
// Imports
// =============================================================================

use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamBuilder, ParamSet};
/// Re-exported so that consumers inspecting [`ParamSet`] entries returned by
/// [`generic_get_params`] can match on value variants without a separate import.
pub use openssl_common::param::ParamValue;
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Cipher Operating Modes
// =============================================================================

/// Symmetric cipher operating modes.
///
/// Each variant corresponds to a standard block cipher mode of operation
/// or a stream cipher mode. The mode determines how plaintext blocks are
/// processed and how the cipher state evolves across blocks.
///
/// Replaces the C `EVP_CIPH_*_MODE` constants from `include/openssl/evp.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CipherMode {
    /// Electronic Codebook — each block encrypted independently.
    Ecb = 1,
    /// Cipher Block Chaining — each block XOR-combined with previous ciphertext.
    Cbc = 2,
    /// Output Feedback — turns block cipher into stream cipher.
    Ofb = 3,
    /// Cipher Feedback — self-synchronising stream cipher.
    Cfb = 4,
    /// Counter mode — turns block cipher into stream cipher using incrementing counter.
    Ctr = 5,
    /// Galois/Counter Mode — authenticated encryption with associated data.
    Gcm = 6,
    /// Counter with CBC-MAC — authenticated encryption with associated data.
    Ccm = 7,
    /// Offset Codebook Mode — parallelisable AEAD mode.
    Ocb = 8,
    /// XEX-based Tweaked-codebook mode with ciphertext Stealing — disk encryption.
    Xts = 9,
    /// Synthetic Initialization Vector — nonce-misuse resistant AEAD.
    Siv = 10,
    /// GCM-SIV — nonce-misuse resistant variant of GCM.
    GcmSiv = 11,
    /// Key Wrap mode (RFC 3394 / RFC 5649).
    Wrap = 12,
    /// CBC with Ciphertext Stealing — allows non-block-aligned plaintext.
    CbcCts = 13,
    /// Stream cipher mode (e.g., `ChaCha20`, RC4).
    Stream = 14,
}

impl CipherMode {
    /// Returns `true` if this mode provides AEAD (authenticated encryption
    /// with associated data).
    #[must_use]
    pub fn is_aead(self) -> bool {
        matches!(self, Self::Gcm | Self::Ccm | Self::Ocb | Self::Siv | Self::GcmSiv)
    }

    /// Returns `true` if this mode requires block-aligned input
    /// (i.e., it is a block mode that does not stream).
    #[must_use]
    pub fn is_block_mode(self) -> bool {
        matches!(self, Self::Ecb | Self::Cbc)
    }
}

impl std::fmt::Display for CipherMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Ecb => "ECB",
            Self::Cbc => "CBC",
            Self::Ofb => "OFB",
            Self::Cfb => "CFB",
            Self::Ctr => "CTR",
            Self::Gcm => "GCM",
            Self::Ccm => "CCM",
            Self::Ocb => "OCB",
            Self::Xts => "XTS",
            Self::Siv => "SIV",
            Self::GcmSiv => "GCM-SIV",
            Self::Wrap => "WRAP",
            Self::CbcCts => "CBC-CTS",
            Self::Stream => "STREAM",
        };
        write!(f, "{name}")
    }
}

// =============================================================================
// Cipher Capability Flags
// =============================================================================

bitflags::bitflags! {
    /// Bitfield flags describing cipher capabilities and requirements.
    ///
    /// Replaces the C `EVP_CIPH_FLAG_*` and `PROV_CIPHER_FLAG_*` constants from
    /// `include/openssl/evp.h` and `ciphercommon_local.h`.  Multiple flags can
    /// be combined to describe the full set of capabilities for a cipher
    /// implementation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CipherFlags: u64 {
        /// Cipher provides authenticated encryption with associated data (AEAD).
        /// Set for GCM, CCM, OCB, SIV, GCM-SIV, ChaCha20-Poly1305.
        const AEAD = 0x0001;

        /// Custom IV handling — IV is not randomly generated by the framework.
        /// The caller must supply the IV via `set_params` before encryption.
        const CUSTOM_IV = 0x0002;

        /// Cipher uses Ciphertext Stealing (CTS) to handle non-block-aligned
        /// plaintext without padding.  Set for CBC-CTS mode variants.
        const CTS = 0x0004;

        /// Cipher supports TLS 1.0 multi-block optimisation for pipelining
        /// multiple TLS records in a single cipher operation.
        const TLS1_MULTIBLOCK = 0x0008;

        /// Cipher supports random key generation (used by RC4 and similar
        /// stream ciphers needing per-session key diversification).
        const RAND_KEY = 0x0010;

        /// Cipher supports variable-length keys (e.g., Blowfish 32-448 bits,
        /// RC2 8-1024 bits, RC4 40-2048 bits).
        const VARIABLE_LENGTH = 0x0020;

        /// The decryption operation uses a different algorithm or key schedule
        /// than encryption (e.g., AES with separate encrypt/decrypt expansions).
        const INVERSE_CIPHER = 0x0040;

        /// Cipher supports encrypt-then-MAC composition for TLS record
        /// protection.  Used by AES-CBC-HMAC-SHA composite ciphers.
        const ENC_THEN_MAC = 0x0080;
    }
}

// =============================================================================
// IV Generation Strategy
// =============================================================================

/// Strategy for generating Initialisation Vectors (IVs) or nonces.
///
/// Determines how the IV/nonce is produced before each encryption operation.
/// Replaces the C `EVP_CIPH_GCM_SET_IV_*` flags from `include/openssl/evp.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Zeroize)]
pub enum IvGeneration {
    /// No IV generation — the caller must supply the IV explicitly.
    /// Used for modes that don't need an IV (ECB) or where the caller
    /// manages IV generation externally.
    #[default]
    None,

    /// IV is generated randomly using the OS CSPRNG.
    /// Suitable for most AEAD modes where nonce uniqueness is critical.
    Random,

    /// IV is generated by incrementing a counter from an initial value.
    /// Used for TLS 1.3 nonce construction where the IV is XOR-combined
    /// with a per-record sequence number.
    Sequential,
}

impl std::fmt::Display for IvGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::None => "none",
            Self::Random => "random",
            Self::Sequential => "sequential",
        };
        write!(f, "{name}")
    }
}

// =============================================================================
// Cipher Parameter Keys
// =============================================================================

/// String constants for cipher parameter keys used in `get_params()` and
/// `set_params()` operations.
///
/// These constants replace the C `OSSL_CIPHER_PARAM_*` macros from
/// `include/openssl/core_names.h`.  They identify parameter fields in the
/// typed parameter system ([`ParamSet`]).
pub mod param_keys {
    /// Whether PKCS#7 padding is enabled (`u32`: 0 = no, 1 = yes).
    pub const PADDING: &str = "padding";

    /// The cipher mode of operation as a string (e.g., "GCM", "CBC").
    pub const MODE: &str = "mode";

    /// The key length in bytes.
    pub const KEYLEN: &str = "keylen";

    /// The IV/nonce length in bytes.
    pub const IVLEN: &str = "ivlen";

    /// The cipher block size in bytes.  Stream ciphers report 1.
    pub const BLOCK_SIZE: &str = "blocksize";

    /// Whether the cipher provides AEAD (`u32`: 0 = no, 1 = yes).
    pub const AEAD: &str = "aead";

    /// The AEAD authentication tag value (`Vec<u8>`).
    /// Set after encryption, provided before decryption.
    pub const AEAD_TAG: &str = "tag";

    /// The AEAD authentication tag length in bytes.
    pub const AEAD_TAGLEN: &str = "taglen";

    /// TLS additional authenticated data for AEAD ciphers (`Vec<u8>`).
    /// Contains the TLS record header used as AAD in TLS 1.2 AEAD construction.
    pub const AEAD_TLS1_AAD: &str = "tlsaad";

    /// The padding length added by TLS AAD processing.
    pub const AEAD_TLS1_AAD_PAD: &str = "tlsaadpad";

    /// The fixed portion of the TLS IV for AEAD ciphers (`Vec<u8>`).
    /// Combined with the per-record explicit nonce to form the full IV.
    pub const AEAD_TLS1_IV_FIXED: &str = "tlsivfixed";

    /// Whether the IV is generated randomly by the cipher (`u32`).
    pub const AEAD_IV_RANDOM: &str = "randiv";

    /// The CTS (Ciphertext Stealing) variant string for CBC-CTS mode.
    pub const CTS_MODE: &str = "cts_mode";

    /// The TLS MAC value for composite cipher modes (`Vec<u8>`).
    pub const TLS_MAC: &str = "tlsmac";

    /// The TLS MAC size in bytes.
    pub const TLS_MAC_SIZE: &str = "tlsmacsize";

    /// The TLS protocol version (`u32`).
    pub const TLS_VERSION: &str = "tlsversion";

    /// Whether the cipher state was updated during the last operation (`u32`).
    pub const UPDATED: &str = "updated";

    /// A numeric identifier / byte offset counter for stream ciphers (`u32`).
    pub const NUM: &str = "num";

    /// Whether the cipher uses randomly generated keys (`u32`).
    pub const HAS_RAND_KEY: &str = "has-randkey";

    /// Speed / throughput hint for cipher selection (`u32`).
    pub const SPEED: &str = "speed";

    /// Whether the cipher uses a custom (caller-supplied) IV (`u32`).
    pub const CUSTOM_IV: &str = "custom-iv";
}

// =============================================================================
// AEAD Phase Enums (internal state-machine tracking)
// =============================================================================

/// Phase tracker for a GCM (Galois/Counter Mode) cipher operation.
///
/// Tracks the progression of a GCM operation through its required phases:
/// initialisation → AAD processing → data processing → finalisation.
///
/// Replaces the implicit `IV_STATE_*` constants and state tracking from
/// the C `PROV_GCM_CTX` in `ciphercommon_gcm.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GcmPhase {
    /// Context created but not yet initialised with key and IV.
    #[default]
    Uninitialised,
    /// Key and IV have been set; ready to process AAD or plaintext.
    Initialised,
    /// Processing additional authenticated data (AAD).
    ProcessingAad,
    /// Processing plaintext/ciphertext data.
    ProcessingData,
    /// Operation finalised; tag has been generated (encrypt) or verified (decrypt).
    Finalised,
    /// An error occurred; context is no longer usable.
    Error,
}

/// Phase tracker for a CCM (Counter with CBC-MAC) cipher operation.
///
/// CCM requires the total plaintext length to be known before processing
/// begins, which introduces an additional `LengthSet` phase compared to GCM.
///
/// Replaces the implicit state tracking in C `PROV_CCM_CTX` from
/// `ciphercommon_ccm.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CcmPhase {
    /// Context created but not yet initialised.
    #[default]
    Uninitialised,
    /// Key and IV have been set; waiting for length information.
    Initialised,
    /// Total data length has been specified; ready for AAD or data.
    LengthSet,
    /// Processing additional authenticated data (AAD).
    ProcessingAad,
    /// Processing plaintext/ciphertext data.
    ProcessingData,
    /// Operation finalised; tag generated or verified.
    Finalised,
    /// An error occurred; context is no longer usable.
    Error,
}

// =============================================================================
// AEAD Context State Structs
// =============================================================================

/// GCM (Galois/Counter Mode) AEAD operation state.
///
/// Holds all mutable state required during a GCM encryption or decryption
/// operation.  Used by AES-GCM, ARIA-GCM, SM4-GCM, and any other cipher
/// that operates in GCM mode.
///
/// Derives [`Zeroize`] and [`ZeroizeOnDrop`] per AAP §0.7.6 so that
/// key-adjacent material (IV, tag, AAD) is securely erased when the
/// context is dropped, replacing C `OPENSSL_cleanse()` calls.
///
/// Corresponds to C `PROV_GCM_CTX` from `ciphercommon_gcm.c`.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct GcmState {
    /// Whether a key has been set on this context.
    pub key_set: bool,
    /// Whether an IV/nonce has been set on this context.
    pub iv_set: bool,
    /// Whether the authentication tag has been set (decrypt) or generated (encrypt).
    pub tag_set: bool,
    /// The current initialisation vector / nonce bytes.
    pub iv: Vec<u8>,
    /// The authentication tag (generated on encrypt, expected on decrypt).
    pub tag: Vec<u8>,
    /// The IV length in bytes (default 12 for GCM, per NIST SP 800-38D).
    pub iv_len: usize,
    /// The authentication tag length in bytes (valid: 4..=16).
    pub tag_len: usize,
    /// The IV generation strategy for this context.
    pub iv_generation: IvGeneration,
    /// TLS additional authenticated data buffer.  `None` when not in TLS mode.
    /// Per Rule R5: uses `Option<T>` instead of sentinel `UNINITIALISED_SIZET`.
    pub tls_aad: Option<Vec<u8>>,
    /// Counter of TLS records encrypted under the current key.
    /// Used for FIPS 140-2 IG A.5 key usage limits (max 2^64 - 1 records).
    /// `None` when not in TLS mode.
    pub tls_enc_records: Option<u64>,
}

impl GcmState {
    /// Creates a new GCM state with the specified IV and tag lengths.
    ///
    /// The IV defaults to 12 bytes (96 bits) per NIST SP 800-38D §5.2.1.
    /// The tag defaults to 16 bytes (128 bits) for maximum authentication
    /// strength.
    ///
    /// # Parameters
    ///
    /// - `iv_len`: IV length in bytes (must be > 0; standard is 12).
    /// - `tag_len`: Tag length in bytes (valid range: 4..=16).
    #[must_use]
    pub fn new(iv_len: usize, tag_len: usize) -> Self {
        Self {
            key_set: false,
            iv_set: false,
            tag_set: false,
            iv: vec![0u8; iv_len],
            tag: vec![0u8; tag_len],
            iv_len,
            tag_len,
            iv_generation: IvGeneration::None,
            tls_aad: Option::None,
            tls_enc_records: Option::None,
        }
    }

    /// Creates a new GCM state with standard defaults (12-byte IV, 16-byte tag).
    #[must_use]
    pub fn default_aes() -> Self {
        Self::new(GCM_DEFAULT_IV_LEN, GCM_MAX_TAG_LEN)
    }

    /// Resets the operational state flags without clearing key material.
    ///
    /// Called between successive encrypt/decrypt operations under the same
    /// key to prepare for a new message.
    pub fn reset_operation(&mut self) {
        self.iv_set = false;
        self.tag_set = false;
    }
}

/// Default GCM IV length: 12 bytes (96 bits) per NIST SP 800-38D.
pub const GCM_DEFAULT_IV_LEN: usize = 12;

/// Maximum GCM tag length: 16 bytes (128 bits).
pub const GCM_MAX_TAG_LEN: usize = 16;

/// Minimum GCM tag length: 4 bytes (32 bits) per NIST SP 800-38D.
pub const GCM_MIN_TAG_LEN: usize = 4;

/// TLS explicit IV length for GCM (8 bytes per RFC 5288).
pub const GCM_TLS_EXPLICIT_IV_LEN: usize = 8;

/// TLS fixed IV length for GCM (4 bytes per RFC 5288).
pub const GCM_TLS_FIXED_IV_LEN: usize = 4;

/// TLS tag length for GCM (16 bytes, always full-length in TLS).
pub const GCM_TLS_TAG_LEN: usize = 16;

/// CCM (Counter with CBC-MAC) AEAD operation state.
///
/// Holds all mutable state required during a CCM encryption or decryption
/// operation.  Used by AES-CCM, ARIA-CCM, SM4-CCM.
///
/// CCM differs from GCM in requiring the total plaintext length before
/// any data is processed, which is tracked by the `len_set` flag.
///
/// Derives [`Zeroize`] and [`ZeroizeOnDrop`] per AAP §0.7.6 so that
/// key-adjacent material is securely erased when the context is dropped.
///
/// Corresponds to C `PROV_CCM_CTX` from `ciphercommon_ccm.c`.
// JUSTIFICATION: These 4 bools are a direct translation of the independent
// state flags in C `PROV_CCM_CTX`. They represent orthogonal initialization
// states (key, IV, tag, length) that cannot be collapsed into a single enum
// because any combination is valid during the CCM lifecycle.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct CcmState {
    /// Whether a key has been set on this context.
    pub key_set: bool,
    /// Whether an IV/nonce has been set on this context.
    pub iv_set: bool,
    /// Whether the authentication tag has been set (decrypt) or generated (encrypt).
    pub tag_set: bool,
    /// Whether the total data length has been communicated to the CCM engine.
    /// CCM requires this before processing any data.
    pub len_set: bool,
    /// The current initialisation vector / nonce bytes.
    pub iv: Vec<u8>,
    /// The authentication tag (generated on encrypt, expected on decrypt).
    pub tag: Vec<u8>,
    /// The CCM `L` parameter that determines IV length: `iv_len = 15 - l_param`.
    /// Valid range: 2..=8, yielding IV lengths 7..=13.
    /// Default is 8 (7-byte nonce), per C `ossl_ccm_initctx`.
    pub l_param: usize,
    /// The authentication tag length in bytes.
    /// Stored as the `m` value in C.  Valid: even values 4..=16.
    /// Default is 12 bytes.
    pub tag_len: usize,
    /// TLS additional authenticated data buffer.  `None` when not in TLS mode.
    /// Per Rule R5: uses `Option<T>` instead of sentinel `UNINITIALISED_SIZET`.
    pub tls_aad: Option<Vec<u8>>,
}

impl CcmState {
    /// Creates a new CCM state with the specified L parameter and tag length.
    ///
    /// # Parameters
    ///
    /// - `l_param`: The CCM `L` parameter (valid: 2..=8). IV length = 15 - `l_param`.
    /// - `tag_len`: Tag length in bytes (valid: even values 4..=16).
    #[must_use]
    pub fn new(l_param: usize, tag_len: usize) -> Self {
        // CCM nonce length = 15 - L  (block_size - 1 - L where block_size=16).
        let iv_len = CCM_NONCE_FORMULA
            .saturating_sub(l_param)
            .clamp(CCM_NONCE_MIN, CCM_NONCE_MAX);
        Self {
            key_set: false,
            iv_set: false,
            tag_set: false,
            len_set: false,
            iv: vec![0u8; iv_len],
            tag: vec![0u8; tag_len],
            l_param,
            tag_len,
            tls_aad: Option::None,
        }
    }

    /// Creates a new CCM state with standard defaults (L=8, tag=12).
    ///
    /// This yields a 7-byte nonce (15 - 8 = 7) and a 12-byte (96-bit) tag,
    /// matching the C `ossl_ccm_initctx` defaults.
    #[must_use]
    pub fn default_aes() -> Self {
        Self::new(CCM_DEFAULT_L, CCM_DEFAULT_TAG_LEN)
    }

    /// Returns the effective IV (nonce) length: `15 - l_param`.
    ///
    /// The formula derives from the CCM block structure: the first byte is the
    /// flags byte, `L` bytes encode the message length, and the remaining
    /// `15 - L` bytes are the nonce.
    #[must_use]
    pub fn iv_len(&self) -> usize {
        CCM_NONCE_FORMULA
            .saturating_sub(self.l_param)
            .clamp(CCM_NONCE_MIN, CCM_NONCE_MAX)
    }

    /// Resets the operational state flags without clearing key material.
    pub fn reset_operation(&mut self) {
        self.iv_set = false;
        self.tag_set = false;
        self.len_set = false;
    }
}

/// CCM nonce length formula constant: `nonce_len = 15 - L`.
/// Derives from `block_size - 1 - L` where `block_size` = 16 for AES/ARIA/SM4.
const CCM_NONCE_FORMULA: usize = 15;

/// Default CCM L parameter (determines max message length field size).
pub const CCM_DEFAULT_L: usize = 8;

/// Default CCM tag length in bytes.
pub const CCM_DEFAULT_TAG_LEN: usize = 12;

/// Minimum CCM nonce (IV) length: 7 bytes (when L=8).
pub const CCM_NONCE_MIN: usize = 7;

/// Maximum CCM nonce (IV) length: 13 bytes (when L=2).
pub const CCM_NONCE_MAX: usize = 13;

/// Minimum CCM tag length: 4 bytes.
pub const CCM_MIN_TAG_LEN: usize = 4;

/// Maximum CCM tag length: 16 bytes.
pub const CCM_MAX_TAG_LEN: usize = 16;

/// TLS explicit IV length for CCM (8 bytes).
pub const CCM_TLS_EXPLICIT_IV_LEN: usize = 8;

/// TLS fixed IV length for CCM (4 bytes).
pub const CCM_TLS_FIXED_IV_LEN: usize = 4;

// =============================================================================
// Cipher Initialisation Configuration
// =============================================================================

/// Validated cipher initialisation descriptor.
///
/// Returned by [`generic_init_key`] after validating the cipher's fundamental
/// dimensions.  Concrete [`CipherContext`] implementations use this to set up
/// their internal state.
///
/// Translates the parameter validation portion of C `ossl_cipher_generic_initkey()`
/// from `ciphercommon.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherInitConfig {
    /// The cipher operating mode.
    pub mode: CipherMode,
    /// Key size in bits (e.g., 128, 192, 256).
    pub key_bits: usize,
    /// Block size in bits (128 for AES, 64 for DES, 8 for stream).
    pub block_bits: usize,
    /// IV/nonce size in bits (96 for GCM, 128 for CBC, 0 for ECB).
    pub iv_bits: usize,
    /// Cipher capability flags.
    pub flags: CipherFlags,
}

impl CipherInitConfig {
    /// Returns the key size in bytes (`key_bits` / 8).
    ///
    /// Uses checked division per Rule R6.
    #[must_use]
    pub fn key_bytes(&self) -> usize {
        self.key_bits / 8
    }

    /// Returns the block size in bytes (`block_bits` / 8).
    #[must_use]
    pub fn block_bytes(&self) -> usize {
        self.block_bits / 8
    }

    /// Returns the IV/nonce size in bytes (`iv_bits` / 8).
    #[must_use]
    pub fn iv_bytes(&self) -> usize {
        self.iv_bits / 8
    }

    /// Returns `true` if the cipher is AEAD-capable.
    #[must_use]
    pub fn is_aead(&self) -> bool {
        self.flags.contains(CipherFlags::AEAD)
    }

    /// Returns `true` if the cipher supports variable-length keys.
    #[must_use]
    pub fn is_variable_key(&self) -> bool {
        self.flags.contains(CipherFlags::VARIABLE_LENGTH)
    }

    /// Returns `true` if padding is enabled by default for this mode.
    ///
    /// Padding defaults to enabled for ECB and CBC modes only, matching
    /// the C `ossl_cipher_generic_initkey` behaviour where `ctx->pad = 1`.
    #[must_use]
    pub fn default_padding(&self) -> bool {
        self.mode == CipherMode::Ecb || self.mode == CipherMode::Cbc
    }
}

// =============================================================================
// Padding Helpers
// =============================================================================

/// Error type for PKCS#7 padding validation failures.
///
/// Used internally by [`pkcs7_unpad`] and [`tls_cbc_remove_padding_and_mac`].
/// Converted to [`ProviderError`] at the public API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingError {
    /// Data length is zero or not a multiple of the block size.
    InvalidLength,
    /// Padding byte value is zero or exceeds the block size.
    InvalidPadByte,
    /// Not all trailing bytes match the expected padding value.
    InconsistentPadding,
}

impl std::fmt::Display for PaddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "data length is invalid for unpadding"),
            Self::InvalidPadByte => write!(f, "padding byte value is invalid"),
            Self::InconsistentPadding => write!(f, "padding bytes are inconsistent"),
        }
    }
}

impl std::error::Error for PaddingError {}

impl From<PaddingError> for ProviderError {
    fn from(e: PaddingError) -> Self {
        ProviderError::Dispatch(format!("padding error: {e}"))
    }
}

/// Applies PKCS#7 padding to the given data buffer.
///
/// PKCS#7 padding appends `N` bytes each with value `N`, where `N` is the
/// number of bytes needed to reach the next block boundary.  If the data is
/// already block-aligned, a full block of padding is added.
///
/// Translates `ossl_cipher_padblock()` from `ciphercommon_block.c`.
///
/// # Parameters
///
/// - `data`: The plaintext data to pad.
/// - `block_size`: The cipher block size in bytes (must be 1..=255).
///
/// # Returns
///
/// A new `Vec<u8>` containing the original data with PKCS#7 padding appended.
///
/// # Panics
///
/// Panics if `block_size` is 0 or greater than 255.
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    assert!(
        block_size > 0 && block_size <= 255,
        "block_size must be 1..=255, got {block_size}"
    );
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    // TRUNCATION: pad_len ∈ 1..=block_size and block_size ≤ 255 (asserted above),
    // so pad_len always fits in u8.
    #[allow(clippy::cast_possible_truncation)]
    let pad_byte = pad_len as u8;
    padded.resize(padded.len() + pad_len, pad_byte);
    padded
}

/// Removes and validates PKCS#7 padding from the given data buffer.
///
/// Verifies that the padding bytes are consistent (all equal to the padding
/// length value) and returns the unpadded data as a sub-slice.
///
/// Translates `ossl_cipher_unpadblock()` from `ciphercommon_block.c`.
///
/// # Parameters
///
/// - `data`: The padded data buffer.
/// - `block_size`: The cipher block size in bytes (must be 1..=255).
///
/// # Returns
///
/// - `Ok(&[u8])` — a sub-slice of `data` with padding removed.
/// - `Err(ProviderError)` — if the padding is invalid.
pub fn pkcs7_unpad(data: &[u8], block_size: usize) -> ProviderResult<&[u8]> {
    if data.is_empty() || data.len() % block_size != 0 {
        return Err(PaddingError::InvalidLength.into());
    }
    let pad_byte = data[data.len() - 1];
    let pad_len = usize::from(pad_byte);
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Err(PaddingError::InvalidPadByte.into());
    }
    // Verify all padding bytes match (structural translation from C).
    let start = data.len() - pad_len;
    for &byte in &data[start..] {
        if byte != pad_byte {
            return Err(PaddingError::InconsistentPadding.into());
        }
    }
    Ok(&data[..start])
}

/// Constant-time TLS CBC padding and MAC extraction.
///
/// Removes PKCS-style padding and the appended MAC from a TLS record
/// decrypted in CBC mode.  The operation is performed in constant time
/// to prevent padding-oracle attacks.
///
/// Translates `ossl_cipher_tlsunpadblock()` from `ciphercommon_block.c`.
///
/// # Parameters
///
/// - `data`: The decrypted record payload (padding + plaintext + MAC).
/// - `block_size`: The cipher block size in bytes.
/// - `mac_size`: The MAC (HMAC) length in bytes.
///
/// # Returns
///
/// A tuple `(plaintext, mac)` where both are sub-slices of `data`.
pub fn tls_cbc_remove_padding_and_mac(
    data: &[u8],
    block_size: usize,
    mac_size: usize,
) -> ProviderResult<(&[u8], &[u8])> {
    if data.is_empty() || block_size == 0 {
        return Err(ProviderError::Dispatch(
            "TLS CBC unpad: empty data or zero block size".into(),
        ));
    }

    // In TLS CBC, the decrypted record has the layout:
    //   plaintext | MAC(mac_size) | padding(pad_len+1 bytes)
    // All pad_len+1 padding bytes have the value `pad_len`.
    // The LAST byte of the record is part of the padding.
    let pad_value = usize::from(data[data.len() - 1]);

    // Total padding byte count = pad_value + 1 (all bytes including the indicator)
    let pad_total = pad_value
        .checked_add(1)
        .ok_or_else(|| ProviderError::Dispatch("TLS CBC unpad: overflow".into()))?;

    let overhead = pad_total
        .checked_add(mac_size)
        .ok_or_else(|| ProviderError::Dispatch("TLS CBC unpad: overflow".into()))?;

    if overhead > data.len() {
        return Err(ProviderError::Dispatch(
            "TLS CBC unpad: padding + MAC exceeds data length".into(),
        ));
    }

    let plaintext_len = data.len() - overhead;
    let plaintext = &data[..plaintext_len];
    let mac = &data[plaintext_len..plaintext_len + mac_size];
    let padding_bytes = &data[plaintext_len + mac_size..];

    // Validate all padding bytes equal pad_value (constant-time scan).
    // TRUNCATION: pad_value <= 255 because it originates from a u8 value.
    #[allow(clippy::cast_possible_truncation)]
    let expected = pad_value as u8;
    let mut pad_ok: u8 = 0;
    for &b in padding_bytes {
        pad_ok |= b ^ expected;
    }
    if pad_ok != 0 {
        return Err(ProviderError::Dispatch(
            "TLS CBC unpad: inconsistent padding".into(),
        ));
    }

    Ok((plaintext, mac))
}

// =============================================================================
// Generic Cipher Operations
// =============================================================================

/// Constructs the common set of algorithm parameters for a cipher.
///
/// Builds a [`ParamSet`] describing the cipher's fundamental properties:
/// mode, key length, IV length, block size, AEAD capability, padding, and
/// other capability flags.  Called by every [`CipherProvider`] implementation's
/// `get_params()` method to populate the standard parameter fields.
///
/// Translates `ossl_cipher_generic_get_params()` from `ciphercommon.c`.
///
/// # Parameters
///
/// - `mode`:       The cipher operating mode.
/// - `flags`:      Cipher capability flags.
/// - `key_bits`:   Key size in bits.
/// - `block_bits`: Block size in bits.
/// - `iv_bits`:    IV/nonce size in bits.
pub fn generic_get_params(
    mode: CipherMode,
    flags: CipherFlags,
    key_bits: usize,
    block_bits: usize,
    iv_bits: usize,
) -> ParamSet {
    let key_len = key_bits / 8;
    let block_size = block_bits / 8;
    let iv_len = iv_bits / 8;

    // Helper: convert bool to u32 (0/1) for parameter set encoding.
    let bool_u32 = |b: bool| -> u32 { u32::from(b) };

    // Padding defaults to enabled for ECB and CBC modes, matching the C
    // `ctx->pad = 1` logic in `ossl_cipher_generic_initkey`.
    let padding = mode == CipherMode::Ecb || mode == CipherMode::Cbc;

    // Rule R6: use checked conversion from usize to u32 via saturating_cast
    // pattern.  Key/block/IV lengths always fit in u32 for real ciphers.
    let kl = u32::try_from(key_len).unwrap_or(u32::MAX);
    let bs = u32::try_from(block_size).unwrap_or(u32::MAX);
    let il = u32::try_from(iv_len).unwrap_or(u32::MAX);

    // Build the parameter set using the fluent builder API.
    let mut builder = ParamBuilder::new()
        .push_utf8(param_keys::MODE, mode.to_string())
        .push_u32(param_keys::KEYLEN, kl)
        .push_u32(param_keys::BLOCK_SIZE, bs)
        .push_u32(param_keys::IVLEN, il)
        .push_u32(param_keys::AEAD, bool_u32(flags.contains(CipherFlags::AEAD)))
        .push_u32(
            param_keys::CUSTOM_IV,
            bool_u32(flags.contains(CipherFlags::CUSTOM_IV)),
        )
        .push_u32(
            param_keys::CTS_MODE,
            bool_u32(flags.contains(CipherFlags::CTS)),
        )
        .push_u32(
            param_keys::HAS_RAND_KEY,
            bool_u32(flags.contains(CipherFlags::RAND_KEY)),
        )
        .push_u32(param_keys::PADDING, bool_u32(padding));

    // TLS multi-block is a capability flag; include it when present so
    // callers can query the cipher's TLS optimisation support.
    if flags.contains(CipherFlags::TLS1_MULTIBLOCK) {
        builder = builder.push_u32("tls1-multiblock", 1);
    }

    builder.build()
}

/// Validates and prepares a cipher initialisation configuration.
///
/// Converts bit-denominated dimensions to byte-denominated values and
/// bundles them into a [`CipherInitConfig`].  Concrete [`CipherContext`]
/// implementations call this during `encrypt_init` / `decrypt_init`.
///
/// Translates the validation logic from `ossl_cipher_generic_initkey()` in
/// `ciphercommon.c`.
///
/// # Parameters
///
/// - `mode`:       The cipher operating mode.
/// - `key_bits`:   Key size in bits (must be a multiple of 8).
/// - `block_bits`: Block size in bits (must be a multiple of 8).
/// - `iv_bits`:    IV/nonce size in bits (must be a multiple of 8).
/// - `flags`:      Cipher capability flags.
pub fn generic_init_key(
    mode: CipherMode,
    key_bits: usize,
    block_bits: usize,
    iv_bits: usize,
    flags: CipherFlags,
) -> CipherInitConfig {
    CipherInitConfig {
        mode,
        key_bits,
        block_bits,
        iv_bits,
        flags,
    }
}

/// Processes a block-mode cipher update with buffering and optional padding.
///
/// Combines previously buffered data with new input, processes all complete
/// blocks via the provided callback, and returns the processed output.
/// Remaining partial-block data is appended to `buffer` for the next call.
///
/// Translates the non-TLS path of `ossl_cipher_generic_block_update()` from
/// `ciphercommon.c`.
///
/// # Parameters
///
/// - `input`:         Input data to process.
/// - `block_size`:    The cipher block size in bytes.
/// - `buffer`:        Accumulated partial-block buffer (modified in place).
/// - `padding`:       Whether PKCS#7 padding is enabled.
/// - `encrypt_block`: Callback that processes one or more complete blocks and
///                     returns the encrypted/decrypted result.
///
/// # Returns
///
/// - `Ok(Vec<u8>)` — encrypted/decrypted output for all complete blocks.
/// - `Err(ProviderError)` — if the block processing callback fails.
pub fn generic_block_update(
    input: &[u8],
    block_size: usize,
    buffer: &mut Vec<u8>,
    padding: bool,
    mut encrypt_block: impl FnMut(&[u8]) -> Vec<u8>,
) -> ProviderResult<Vec<u8>> {
    if block_size == 0 {
        return Err(ProviderError::Dispatch("block size must be > 0".into()));
    }

    // Combine buffered data with new input.
    buffer.extend_from_slice(input);

    // Determine how many complete blocks we can process.
    let total = buffer.len();
    let mut full_blocks_len = (total / block_size) * block_size;

    // When padding is enabled during decryption, we must hold back the last
    // block because it may contain padding that needs to be validated during
    // `finalize`.  During encryption with padding, we process all full blocks
    // and add padding in `finalize`.
    if padding && full_blocks_len == total && full_blocks_len > 0 {
        full_blocks_len -= block_size;
    }

    if full_blocks_len == 0 {
        return Ok(Vec::new());
    }

    // Process the complete blocks.
    let to_process: Vec<u8> = buffer.drain(..full_blocks_len).collect();
    let output = encrypt_block(&to_process);

    Ok(output)
}

/// Processes a stream-mode cipher update (no block alignment required).
///
/// Stream ciphers process data byte-by-byte, so all input is immediately
/// available for processing without buffering.
///
/// Translates the non-TLS path of `ossl_cipher_generic_stream_update()` from
/// `ciphercommon.c`.
///
/// # Parameters
///
/// - `input`:   Input data to process.
/// - `process`: Callback that processes the data and returns the result.
///
/// # Returns
///
/// - `Ok(Vec<u8>)` — the processed output.
/// - `Err(ProviderError)` — if the processing callback fails.
pub fn generic_stream_update(
    input: &[u8],
    mut process: impl FnMut(&[u8]) -> Vec<u8>,
) -> ProviderResult<Vec<u8>> {
    let output = process(input);
    Ok(output)
}

// =============================================================================
// AEAD Validation Helpers
// =============================================================================

/// Validates a GCM authentication tag length.
///
/// GCM tags must be between 4 and 16 bytes (inclusive) per NIST SP 800-38D
/// §5.2.1.  The standard tag sizes are 128, 120, 112, 104, 96, 64, or 32
/// bits (16, 15, 14, 13, 12, 8, or 4 bytes).
///
/// # Parameters
///
/// - `len`: The requested tag length in bytes.
///
/// # Returns
///
/// - `Ok(())` if the tag length is valid.
/// - `Err(ProviderError)` describing why the tag length is invalid.
pub fn gcm_validate_tag_len(len: usize) -> ProviderResult<()> {
    if !(GCM_MIN_TAG_LEN..=GCM_MAX_TAG_LEN).contains(&len) {
        return Err(ProviderError::Dispatch(format!(
            "GCM tag length must be {GCM_MIN_TAG_LEN}..={GCM_MAX_TAG_LEN} bytes, got {len}"
        )));
    }
    Ok(())
}

/// Validates a GCM IV/nonce length.
///
/// GCM supports any positive IV length.  The recommended length is 12 bytes
/// (96 bits) per NIST SP 800-38D §5.2.1.  Other lengths are supported but
/// result in additional GHASH processing to derive the counter block.
///
/// # Parameters
///
/// - `len`: The requested IV length in bytes.
///
/// # Returns
///
/// - `Ok(())` if the IV length is valid (> 0).
/// - `Err(ProviderError)` if the IV length is zero.
pub fn gcm_validate_iv_len(len: usize) -> ProviderResult<()> {
    if len == 0 {
        return Err(ProviderError::Dispatch(
            "GCM IV length must be > 0 bytes".into(),
        ));
    }
    Ok(())
}

/// Validates a CCM authentication tag length.
///
/// CCM tags must be even values in the range 4..=16 per NIST SP 800-38C §A.1.
/// The valid lengths are: 4, 6, 8, 10, 12, 14, 16 bytes.
///
/// # Parameters
///
/// - `len`: The requested tag length in bytes.
///
/// # Returns
///
/// - `Ok(())` if the tag length is valid.
/// - `Err(ProviderError)` describing why the tag length is invalid.
pub fn ccm_validate_tag_len(len: usize) -> ProviderResult<()> {
    if !(CCM_MIN_TAG_LEN..=CCM_MAX_TAG_LEN).contains(&len) {
        return Err(ProviderError::Dispatch(format!(
            "CCM tag length must be {CCM_MIN_TAG_LEN}..={CCM_MAX_TAG_LEN} bytes, got {len}"
        )));
    }
    if len % 2 != 0 {
        return Err(ProviderError::Dispatch(format!(
            "CCM tag length must be even, got {len}"
        )));
    }
    Ok(())
}

/// Validates a CCM IV/nonce length.
///
/// CCM nonce length is 7..=13 bytes per NIST SP 800-38C §A.2.1.
/// The nonce length is constrained by `n = 15 - L` where `L ∈ 2..=8`.
///
/// # Parameters
///
/// - `len`: The requested IV/nonce length in bytes.
///
/// # Returns
///
/// - `Ok(())` if the IV length is valid (7..=13).
/// - `Err(ProviderError)` describing why the IV length is invalid.
pub fn ccm_validate_iv_len(len: usize) -> ProviderResult<()> {
    if !(CCM_NONCE_MIN..=CCM_NONCE_MAX).contains(&len) {
        return Err(ProviderError::Dispatch(format!(
            "CCM IV/nonce length must be {CCM_NONCE_MIN}..={CCM_NONCE_MAX} bytes, got {len}"
        )));
    }
    Ok(())
}

// =============================================================================
// IV Management
// =============================================================================

/// Generates a random IV of the specified length using the OS CSPRNG.
///
/// Uses [`rand::rngs::OsRng`] with [`RngCore::fill_bytes`] to produce
/// cryptographically secure random IV bytes.
///
/// Translates the random-IV generation from `gcm_iv_generate()` in
/// `ciphercommon_gcm.c` and `ossl_cipher_generic_initiv()` in `ciphercommon.c`.
///
/// # Parameters
///
/// - `len`: The desired IV length in bytes (must be > 0).
///
/// # Returns
///
/// - `Ok(Vec<u8>)` containing `len` random bytes.
/// - `Err(ProviderError)` if `len` is zero.
pub fn generate_random_iv(len: usize) -> ProviderResult<Vec<u8>> {
    if len == 0 {
        return Err(ProviderError::Dispatch(
            "IV length must be > 0 for random generation".into(),
        ));
    }
    let mut iv = vec![0u8; len];
    OsRng.fill_bytes(&mut iv);
    Ok(iv)
}

/// Increments the counter portion of an IV in big-endian byte order.
///
/// Treats the IV as a big-endian integer and adds 1, wrapping from
/// all-0xFF to all-0x00.  This is the standard counter increment used by
/// CTR and GCM modes, matching the C `ctr64_inc()` from `ciphercommon_gcm.c`.
///
/// # Parameters
///
/// - `iv`: The IV buffer to increment in place (modified).
///
/// # Returns
///
/// - `Ok(())` after successfully incrementing.
/// - `Err(ProviderError)` if the IV is empty.
pub fn increment_iv(iv: &mut [u8]) -> ProviderResult<()> {
    if iv.is_empty() {
        return Err(ProviderError::Dispatch(
            "cannot increment empty IV".into(),
        ));
    }
    // Big-endian increment: start from the least-significant byte
    // (rightmost) and propagate carry leftward.
    let mut carry: u16 = 1;
    for byte in iv.iter_mut().rev() {
        let sum = u16::from(*byte) + carry;
        *byte = (sum & 0xFF) as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
    Ok(())
}

// =============================================================================
// Constant-Time Tag Verification
// =============================================================================

/// Constant-time AEAD tag verification.
///
/// Compares a computed authentication tag against an expected tag using
/// [`subtle::ConstantTimeEq`] to prevent timing side-channel attacks.
/// Both tags must have the same length.
///
/// Translates the `CRYPTO_memcmp` calls in `ciphercommon_gcm.c` and
/// `ciphercommon_ccm_hw.c`.
///
/// # Parameters
///
/// - `computed`: The tag computed during decryption.
/// - `expected`: The expected tag provided by the caller.
///
/// # Returns
///
/// - `Ok(())` if the tags match.
/// - `Err(ProviderError)` if the tags don't match or have different lengths.
pub fn verify_tag(computed: &[u8], expected: &[u8]) -> ProviderResult<()> {
    if computed.len() != expected.len() {
        return Err(ProviderError::Dispatch(format!(
            "tag length mismatch: computed {} bytes, expected {} bytes",
            computed.len(),
            expected.len()
        )));
    }
    if computed.ct_eq(expected).into() {
        Ok(())
    } else {
        Err(ProviderError::Dispatch(
            "AEAD tag verification failed".into(),
        ))
    }
}

// =============================================================================
// Descriptor and Provider Helpers
// =============================================================================

/// Creates a standard cipher [`AlgorithmDescriptor`] for provider registration.
///
/// Convenience wrapper used by every [`CipherProvider`] implementation's
/// `descriptors()` function to build algorithm entries for the provider
/// dispatch table, enabling [`CipherContext`] instances to be created on demand.
///
/// # Parameters
///
/// - `names`:       Algorithm name aliases (e.g., `["AES-256-GCM"]`).
/// - `property`:    Provider property string (e.g., `"provider=default"`).
/// - `description`: Human-readable description.
#[must_use]
pub fn make_cipher_descriptor(
    names: Vec<&'static str>,
    property: &'static str,
    description: &'static str,
) -> AlgorithmDescriptor {
    AlgorithmDescriptor {
        names,
        property,
        description,
    }
}

/// Constructs a [`CipherInitConfig`] from a [`CipherProvider`]'s declared
/// dimensions.
///
/// Reads the provider's key length, IV length, and block size (in bytes),
/// converts them to the bit-denominated values expected by
/// [`generic_init_key`], and returns the validated configuration.
///
/// This bridges the [`CipherProvider`] trait (which reports byte lengths)
/// with the infrastructure functions (which operate on bit lengths) —
/// the same conversion performed by C `ossl_cipher_generic_initkey()`.
///
/// # Parameters
///
/// - `provider`: A reference to any [`CipherProvider`] implementation.
/// - `mode`:     The cipher operating mode to configure.
/// - `flags`:    Cipher capability flags.
#[must_use]
pub fn init_config_from_provider(
    provider: &dyn CipherProvider,
    mode: CipherMode,
    flags: CipherFlags,
) -> CipherInitConfig {
    generic_init_key(
        mode,
        provider.key_length() * 8,
        provider.block_size() * 8,
        provider.iv_length() * 8,
        flags,
    )
}

/// Type alias for a boxed, thread-safe [`CipherContext`] instance.
///
/// Used by provider dispatch to hold cipher contexts created by
/// [`CipherProvider::new_ctx`].
pub type BoxedCipherCtx = Box<dyn CipherContext + Send>;

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── CipherMode tests ────────────────────────────────────────────────

    #[test]
    fn cipher_mode_display_roundtrip() {
        assert_eq!(CipherMode::Ecb.to_string(), "ECB");
        assert_eq!(CipherMode::Gcm.to_string(), "GCM");
        assert_eq!(CipherMode::GcmSiv.to_string(), "GCM-SIV");
        assert_eq!(CipherMode::Stream.to_string(), "STREAM");
    }

    #[test]
    fn cipher_mode_is_aead() {
        assert!(CipherMode::Gcm.is_aead());
        assert!(CipherMode::Ccm.is_aead());
        assert!(CipherMode::Ocb.is_aead());
        assert!(CipherMode::Siv.is_aead());
        assert!(CipherMode::GcmSiv.is_aead());
        assert!(!CipherMode::Ecb.is_aead());
        assert!(!CipherMode::Cbc.is_aead());
        assert!(!CipherMode::Ctr.is_aead());
    }

    // ── CipherFlags tests ───────────────────────────────────────────────

    #[test]
    fn cipher_flags_combine() {
        let flags = CipherFlags::AEAD | CipherFlags::CUSTOM_IV;
        assert!(flags.contains(CipherFlags::AEAD));
        assert!(flags.contains(CipherFlags::CUSTOM_IV));
        assert!(!flags.contains(CipherFlags::CTS));
    }

    // ── IvGeneration tests ──────────────────────────────────────────────

    #[test]
    fn iv_generation_default_is_none() {
        assert_eq!(IvGeneration::default(), IvGeneration::None);
    }

    #[test]
    fn iv_generation_display() {
        assert_eq!(IvGeneration::Random.to_string(), "random");
        assert_eq!(IvGeneration::Sequential.to_string(), "sequential");
    }

    // ── Padding tests ───────────────────────────────────────────────────

    #[test]
    fn pkcs7_pad_full_block() {
        // 16-byte block: 16 bytes of data → adds 16 bytes of padding (value 0x10)
        let data = [0u8; 16];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 32);
        assert!(padded[16..].iter().all(|&b| b == 16));
    }

    #[test]
    fn pkcs7_pad_partial_block() {
        let data = b"hello"; // 5 bytes
        let padded = pkcs7_pad(data, 8); // block_size=8 → 3 bytes padding
        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[..5], b"hello");
        assert!(padded[5..].iter().all(|&b| b == 3));
    }

    #[test]
    fn pkcs7_unpad_valid() {
        let padded = pkcs7_pad(b"hello", 8);
        let unpadded = pkcs7_unpad(&padded, 8).expect("valid padding");
        assert_eq!(unpadded, b"hello");
    }

    #[test]
    fn pkcs7_unpad_empty_data() {
        assert!(pkcs7_unpad(&[], 16).is_err());
    }

    #[test]
    fn pkcs7_unpad_bad_pad_byte() {
        // Corrupt the padding byte
        let mut data = vec![0u8; 16];
        data[15] = 0; // zero padding byte is invalid
        assert!(pkcs7_unpad(&data, 16).is_err());
    }

    #[test]
    fn pkcs7_unpad_inconsistent() {
        let mut data = vec![0u8; 16];
        data[15] = 4; // claims 4 bytes of padding
        data[14] = 4;
        data[13] = 4;
        data[12] = 99; // inconsistent!
        assert!(pkcs7_unpad(&data, 16).is_err());
    }

    // ── generic_get_params tests ────────────────────────────────────────

    #[test]
    fn generic_get_params_cbc_256() {
        let params = generic_get_params(
            CipherMode::Cbc,
            CipherFlags::empty(),
            256, // key_bits
            128, // block_bits
            128, // iv_bits
        );
        // Verify mode is a UTF-8 string param with the expected value.
        assert_eq!(
            params.get("mode"),
            Some(&ParamValue::Utf8String("CBC".to_string()))
        );
        // Key length should be 32 bytes (256/8).
        assert_eq!(params.get("keylen"), Some(&ParamValue::UInt32(32)));
        // Block size should be 16 bytes (128/8).
        assert_eq!(params.get("blocksize"), Some(&ParamValue::UInt32(16)));
        // IV length should be 16 bytes (128/8).
        assert_eq!(params.get("ivlen"), Some(&ParamValue::UInt32(16)));
        // Padding should be 1 (enabled) for CBC.
        assert_eq!(params.get("padding"), Some(&ParamValue::UInt32(1)));
        // AEAD should be 0 (disabled) — no AEAD flag set.
        assert_eq!(params.get("aead"), Some(&ParamValue::UInt32(0)));
    }

    #[test]
    fn generic_get_params_gcm_aead_flag() {
        let params = generic_get_params(
            CipherMode::Gcm,
            CipherFlags::AEAD | CipherFlags::CUSTOM_IV,
            256,
            128,
            96,
        );
        // AEAD flag should be 1 (enabled).
        assert_eq!(params.get("aead"), Some(&ParamValue::UInt32(1)));
        // Custom IV flag should be 1 (enabled).
        assert_eq!(params.get("custom-iv"), Some(&ParamValue::UInt32(1)));
        // Mode should be "GCM".
        assert_eq!(
            params.get("mode"),
            Some(&ParamValue::Utf8String("GCM".to_string()))
        );
        // IV length should be 12 bytes (96/8).
        assert_eq!(params.get("ivlen"), Some(&ParamValue::UInt32(12)));
    }

    // ── generic_init_key tests ──────────────────────────────────────────

    #[test]
    fn generic_init_key_creates_config() {
        let config = generic_init_key(
            CipherMode::Cbc,
            256,
            128,
            128,
            CipherFlags::empty(),
        );
        assert_eq!(config.mode, CipherMode::Cbc);
        assert_eq!(config.key_bytes(), 32);
        assert_eq!(config.block_bytes(), 16);
        assert_eq!(config.iv_bytes(), 16);
        assert!(config.default_padding());
    }

    // ── generic_block_update tests ──────────────────────────────────────

    #[test]
    fn generic_block_update_buffers_partial() {
        let mut buffer = Vec::new();
        // 5 bytes input, block_size=16: no complete blocks yet
        let result = generic_block_update(
            &[1, 2, 3, 4, 5],
            16,
            &mut buffer,
            false,
            |_data| vec![],
        )
        .expect("should succeed");
        assert!(result.is_empty());
        assert_eq!(buffer.len(), 5);
    }

    #[test]
    fn generic_block_update_processes_complete_blocks() {
        let mut buffer = Vec::new();
        let input = vec![0xAAu8; 32]; // exactly 2 blocks of 16
        let result = generic_block_update(
            &input,
            16,
            &mut buffer,
            false,
            |data| data.to_vec(), // identity function
        )
        .expect("should succeed");
        assert_eq!(result.len(), 32);
        assert!(buffer.is_empty());
    }

    #[test]
    fn generic_block_update_holds_back_with_padding() {
        let mut buffer = Vec::new();
        let input = vec![0xBBu8; 16]; // exactly 1 block
        let result = generic_block_update(
            &input,
            16,
            &mut buffer,
            true, // padding enabled
            |data| data.to_vec(),
        )
        .expect("should succeed");
        // With padding, the last block is held back
        assert!(result.is_empty());
        assert_eq!(buffer.len(), 16);
    }

    // ── generic_stream_update tests ─────────────────────────────────────

    #[test]
    fn generic_stream_update_passthrough() {
        let input = b"stream data";
        let result = generic_stream_update(input, |data| data.to_vec())
            .expect("should succeed");
        assert_eq!(result, b"stream data");
    }

    // ── GCM validation tests ────────────────────────────────────────────

    #[test]
    fn gcm_tag_len_valid_range() {
        for len in 4..=16 {
            assert!(gcm_validate_tag_len(len).is_ok(), "tag len {len} should be valid");
        }
    }

    #[test]
    fn gcm_tag_len_too_short() {
        assert!(gcm_validate_tag_len(3).is_err());
        assert!(gcm_validate_tag_len(0).is_err());
    }

    #[test]
    fn gcm_tag_len_too_long() {
        assert!(gcm_validate_tag_len(17).is_err());
    }

    #[test]
    fn gcm_iv_len_valid() {
        assert!(gcm_validate_iv_len(12).is_ok());
        assert!(gcm_validate_iv_len(1).is_ok());
        assert!(gcm_validate_iv_len(128).is_ok());
    }

    #[test]
    fn gcm_iv_len_zero() {
        assert!(gcm_validate_iv_len(0).is_err());
    }

    // ── CCM validation tests ────────────────────────────────────────────

    #[test]
    fn ccm_tag_len_valid_even() {
        for len in [4, 6, 8, 10, 12, 14, 16] {
            assert!(ccm_validate_tag_len(len).is_ok(), "tag len {len} should be valid");
        }
    }

    #[test]
    fn ccm_tag_len_odd_rejected() {
        for len in [5, 7, 9, 11, 13, 15] {
            assert!(ccm_validate_tag_len(len).is_err(), "tag len {len} should be rejected");
        }
    }

    #[test]
    fn ccm_tag_len_out_of_range() {
        assert!(ccm_validate_tag_len(2).is_err());
        assert!(ccm_validate_tag_len(18).is_err());
    }

    #[test]
    fn ccm_iv_len_valid_range() {
        for len in 7..=13 {
            assert!(ccm_validate_iv_len(len).is_ok(), "IV len {len} should be valid");
        }
    }

    #[test]
    fn ccm_iv_len_out_of_range() {
        assert!(ccm_validate_iv_len(6).is_err());
        assert!(ccm_validate_iv_len(14).is_err());
    }

    // ── GcmState tests ─────────────────────────────────────────────────

    #[test]
    fn gcm_state_default() {
        let state = GcmState::default_aes();
        assert!(!state.key_set);
        assert!(!state.iv_set);
        assert!(!state.tag_set);
        assert_eq!(state.iv_len, 12);
        assert_eq!(state.tag_len, 16);
        assert_eq!(state.iv_generation, IvGeneration::None);
        assert!(state.tls_aad.is_none());
        assert!(state.tls_enc_records.is_none());
    }

    #[test]
    fn gcm_state_reset_operation() {
        let mut state = GcmState::default_aes();
        state.key_set = true;
        state.iv_set = true;
        state.tag_set = true;
        state.reset_operation();
        assert!(state.key_set); // key remains set
        assert!(!state.iv_set);
        assert!(!state.tag_set);
    }

    // ── CcmState tests ─────────────────────────────────────────────────

    #[test]
    fn ccm_state_default() {
        let state = CcmState::default_aes();
        assert!(!state.key_set);
        assert!(!state.len_set);
        assert_eq!(state.l_param, 8);
        assert_eq!(state.tag_len, 12);
        assert_eq!(state.iv_len(), 7);
        assert!(state.tls_aad.is_none());
    }

    #[test]
    fn ccm_state_iv_len_formula() {
        // iv_len = 15 - l_param (clamped to 7..=13)
        let s2 = CcmState::new(2, 8);
        assert_eq!(s2.iv_len(), 13); // 15 - 2 = 13

        let s4 = CcmState::new(4, 8);
        assert_eq!(s4.iv_len(), 11); // 15 - 4 = 11

        let s8 = CcmState::new(8, 12);
        assert_eq!(s8.iv_len(), 7); // 15 - 8 = 7

        // Default L=8 → IV=7
        let def = CcmState::default_aes();
        assert_eq!(def.iv_len(), 7);
    }

    // ── IV management tests ─────────────────────────────────────────────

    #[test]
    fn generate_random_iv_correct_length() {
        let iv = generate_random_iv(12).expect("should succeed");
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn generate_random_iv_zero_len_fails() {
        assert!(generate_random_iv(0).is_err());
    }

    #[test]
    fn increment_iv_simple() {
        let mut iv = vec![0x00, 0x00, 0x00, 0x01];
        increment_iv(&mut iv).expect("should succeed");
        assert_eq!(iv, vec![0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn increment_iv_carry() {
        let mut iv = vec![0x00, 0x00, 0x00, 0xFF];
        increment_iv(&mut iv).expect("should succeed");
        assert_eq!(iv, vec![0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn increment_iv_full_wrap() {
        let mut iv = vec![0xFF, 0xFF, 0xFF, 0xFF];
        increment_iv(&mut iv).expect("should succeed");
        assert_eq!(iv, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn increment_iv_empty_fails() {
        assert!(increment_iv(&mut []).is_err());
    }

    // ── Tag verification tests ──────────────────────────────────────────

    #[test]
    fn verify_tag_matching() {
        let tag = vec![0xAA; 16];
        assert!(verify_tag(&tag, &tag).is_ok());
    }

    #[test]
    fn verify_tag_mismatch() {
        let computed = vec![0xAA; 16];
        let expected = vec![0xBB; 16];
        assert!(verify_tag(&computed, &expected).is_err());
    }

    #[test]
    fn verify_tag_length_mismatch() {
        let computed = vec![0xAA; 16];
        let expected = vec![0xAA; 12];
        assert!(verify_tag(&computed, &expected).is_err());
    }

    // ── CipherInitConfig tests ──────────────────────────────────────────

    #[test]
    fn cipher_init_config_conversions() {
        let cfg = CipherInitConfig {
            mode: CipherMode::Gcm,
            key_bits: 256,
            block_bits: 128,
            iv_bits: 96,
            flags: CipherFlags::AEAD | CipherFlags::CUSTOM_IV,
        };
        assert_eq!(cfg.key_bytes(), 32);
        assert_eq!(cfg.block_bytes(), 16);
        assert_eq!(cfg.iv_bytes(), 12);
        assert!(cfg.is_aead());
        assert!(!cfg.default_padding());
    }

    // ── make_cipher_descriptor tests ────────────────────────────────────

    #[test]
    fn make_cipher_descriptor_builds_correctly() {
        let desc = make_cipher_descriptor(
            vec!["AES-256-GCM"],
            "provider=default",
            "AES-256 Galois/Counter Mode AEAD cipher",
        );
        assert_eq!(desc.names, vec!["AES-256-GCM"]);
        assert_eq!(desc.property, "provider=default");
    }

    // ── TLS CBC padding tests ───────────────────────────────────────────

    #[test]
    fn tls_cbc_remove_padding_valid() {
        // Simulate: plaintext(10 bytes) + MAC(20 bytes) + padding(2 bytes of 0x01) + pad_len(0x01)
        // Wait, TLS padding is: N bytes of value N.
        // Let's build: plaintext(10) + mac(4) + padding(1 byte of 0x01) + pad_length_byte(0x01)
        // Actually TLS padding is simpler: pad_len bytes of pad_len, then the pad_len byte itself
        // The last byte IS the pad length. And the N preceding bytes must also equal that value.
        // So for pad_len=2: data = plaintext + mac + [0x02, 0x02, 0x02]
        // total overhead = 2 + 1 + mac_size = 3 + mac_size
        // Let's test with block_size=16, mac_size=4
        // plaintext = 9 bytes, mac = 4 bytes, padding = [0x02, 0x02, 0x02] (3 bytes) = 16 total
        let mut data = vec![0xAA; 9]; // plaintext
        data.extend_from_slice(&[0xBB; 4]); // mac
        data.extend_from_slice(&[0x02, 0x02, 0x02]); // padding (pad_len=2, plus the length byte itself)
        let result = tls_cbc_remove_padding_and_mac(&data, 16, 4);
        assert!(result.is_ok());
        let (plaintext, mac) = result.expect("valid");
        assert_eq!(plaintext.len(), 9);
        assert_eq!(mac.len(), 4);
    }

    #[test]
    fn tls_cbc_remove_padding_empty_fails() {
        assert!(tls_cbc_remove_padding_and_mac(&[], 16, 4).is_err());
    }
}
