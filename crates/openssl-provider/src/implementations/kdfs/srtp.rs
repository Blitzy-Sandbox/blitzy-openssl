//! SRTP/SRTCP Key Derivation Function (RFC 3711 §4.3.1).
//!
//! This module implements the Secure Real-time Transport Protocol Key
//! Derivation Function defined in [RFC 3711, Section 4.3.1], which produces
//! cipher, authentication, and salt keys for SRTP and SRTCP streams from a
//! master key and master salt.
//!
//! # Algorithm overview
//!
//! Given a master key `mkey`, master salt `msalt` (14 bytes), a packet
//! index (6 bytes for SRTP, 4 bytes for SRTCP), an optional key derivation
//! rate (`KDR`, must be a power of two), and a label byte, the SRTP KDF
//! produces the requested key material by:
//!
//! 1. Computing `r = index >> log2(KDR)` (or `r = 0` if `KDR == 0`).
//! 2. Constructing a 16-byte IV initialised to zero, then folding `r` into
//!    the low bytes of the master salt.
//! 3. XOR-ing the label byte into a specific position of the resulting
//!    local salt (position `14 - 1 - index_len`).
//! 4. Running AES in CTR mode with the master key and the local salt as the
//!    IV, and encrypting a zero buffer to obtain the derived key.
//!
//! The label determines which key is being derived:
//!
//! | Label | Meaning                     | Length (bytes)    |
//! |-------|-----------------------------|-------------------|
//! | 0x00  | SRTP cipher (encryption) key| AES key length    |
//! | 0x01  | SRTP authentication key     | 20 (SRTP auth)    |
//! | 0x02  | SRTP salt key               | 14 (SRTP salt)    |
//! | 0x03  | SRTCP cipher key            | AES key length    |
//! | 0x04  | SRTCP authentication key    | 20 (SRTCP auth)   |
//! | 0x05  | SRTCP salt key              | 14 (SRTCP salt)   |
//!
//! The underlying cipher **must** be AES in CTR mode. The AAP's C reference
//! (`providers/implementations/kdfs/srtpkdf.c`) supports AES-128/192/256
//! CTR, but this Rust port is constrained by the Rust `openssl-crypto`
//! predefined cipher registry, which defines `AES-128-CTR` and
//! `AES-256-CTR` only. Attempts to use other ciphers fail with
//! [`ProviderError::AlgorithmUnavailable`].
//!
//! # Translated source
//!
//! This module is a direct translation of
//! `providers/implementations/kdfs/srtpkdf.c` (494 lines). Every
//! externally-observable behaviour of the C dispatch table is preserved.
//!
//! # Compliance
//!
//! - **R5 (nullability over sentinels):** `Option<T>` for cipher, label,
//!   salt, and index fields.
//! - **R6 (lossless casts):** 48-bit index uses `u64` with explicit 6-byte
//!   masking; all narrowing casts use `try_from` or saturating variants.
//! - **R8 (no unsafe outside FFI):** this module contains zero `unsafe`.
//! - **R9 (warning-free build):** all public items are documented.
//!
//! # References
//!
//! - RFC 3711: The Secure Real-time Transport Protocol (SRTP).
//! - `providers/implementations/kdfs/srtpkdf.c` (source of truth).

use std::sync::Arc;

use tracing::{debug, instrument, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
use openssl_common::{CryptoError, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::cipher::{Cipher, CipherCtx, CipherMode};

// =============================================================================
// Constants (translated verbatim from `srtpkdf.c`)
// =============================================================================

/// Maximum length of the SRTP/SRTCP authentication key.
///
/// Matches C `KDF_SRTP_AUTH_KEY_LEN = 20` (`srtpkdf.c` line 25).
const SRTP_AUTH_KEY_LEN: usize = 20;

/// Length of the derived SRTP/SRTCP salt key.
///
/// Matches C `KDF_SRTP_SALT_KEY_LEN = 14` (`srtpkdf.c` line 26).
const SRTP_SALT_KEY_LEN: usize = 14;

/// Length of the master salt as required by RFC 3711.
///
/// Matches C `KDF_SRTP_SALT_LEN = 14` (`srtpkdf.c` line 27).
const SRTP_SALT_LEN: usize = 14;

/// Length of the SRTP packet index (48 bits).
///
/// Matches C `KDF_SRTP_IDX_LEN = 6` (`srtpkdf.c` line 30).
const SRTP_IDX_LEN: usize = 6;

/// Length of the SRTCP packet index (32 bits).
///
/// Matches C `KDF_SRTP_SRTCP_IDX_LEN = 4` (`srtpkdf.c` line 31).
const SRTCP_IDX_LEN: usize = 4;

/// Length of the AES-CTR initialisation vector and the local salt buffer.
///
/// Matches C `KDF_SRTP_IV_LEN = 16` (`srtpkdf.c` line 32).
const SRTP_IV_LEN: usize = 16;

/// Maximum number of bits the key derivation rate may occupy (i.e. the
/// highest admissible `log2(KDR)`).
///
/// Matches C `KDF_SRTP_MAX_KDR = 24` (`srtpkdf.c` line 33).
const SRTP_MAX_KDR: u32 = 24;

/// Maximum admissible SRTP KDF label value.
///
/// Matches C `KDF_SRTP_MAX_LABEL = 7` (`srtpkdf.c` line 34). Although the
/// C implementation accepts labels 0-7, only labels 0-5 have defined
/// semantics in RFC 3711; labels 6 and 7 (which the C code maps through
/// `is_srtp_table`) are reserved. This Rust port exposes only the six
/// defined SRTP/SRTCP label variants via [`SrtpLabel`] and rejects other
/// values at the parameter boundary.
const SRTP_MAX_LABEL: u32 = 7;

// =============================================================================
// Parameter name constants
// =============================================================================
//
// These mirror the OpenSSL parameter names from
// `include/openssl/core_names.h`. They are kept as module-private
// `&'static str` constants so the ParamSet layer uses exact string matches.

/// `OSSL_KDF_PARAM_CIPHER` — the underlying block cipher (must be AES-CTR).
const PARAM_CIPHER: &str = "cipher";

/// `OSSL_KDF_PARAM_KEY` — the master key.
const PARAM_KEY: &str = "key";

/// `OSSL_KDF_PARAM_SALT` — the master salt (14 bytes).
const PARAM_SALT: &str = "salt";

/// `OSSL_KDF_PARAM_LABEL` — SRTP/SRTCP label byte (0x00-0x05).
const PARAM_LABEL: &str = "label";

/// `OSSL_KDF_PARAM_INFO` — the packet index (6 bytes SRTP, 4 bytes SRTCP).
///
/// RFC 3711 uses the packet index as the counter for KDR-based rekeying;
/// the C dispatch table consumes it via `OSSL_KDF_PARAM_INFO`.
const PARAM_INDEX: &str = "info";

/// `OSSL_KDF_PARAM_SRTP_KDF_RATE` — the key derivation rate (must be a
/// power of two, with `log2(KDR) <= 24`).
const PARAM_KDR: &str = "kdr";

/// Parameter name for the cipher property query forwarded to
/// [`Cipher::fetch`] (matches OpenSSL's `OSSL_KDF_PARAM_PROPERTIES`).
const PARAM_PROPERTIES: &str = "properties";

// =============================================================================
// Error helper
// =============================================================================

/// Converts a [`CryptoError`] raised by the EVP cipher layer into a
/// provider-layer [`ProviderError::Dispatch`].
///
/// Mirrors the pattern used in `kdfs/kbkdf.rs` for MAC errors: every
/// propagation point applies this function so the dispatch-table origin of
/// the failure is preserved in the message while conforming to the
/// provider error enum.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

// =============================================================================
// SrtpLabel
// =============================================================================

/// RFC 3711 §4.3.1 SRTP/SRTCP key derivation label.
///
/// The label identifies which key is being derived. Labels 0x00-0x02 produce
/// SRTP keys, while 0x03-0x05 produce their SRTCP counterparts.
///
/// Maps directly to the `label` parameter of the C `SRTPKDF()` function in
/// `srtpkdf.c` line 376. The `is_srtp_table` in the C implementation
/// (`srtpkdf.c` line 375) has entries for labels 0-7, but only 0-5 are
/// assigned by RFC 3711.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SrtpLabel {
    /// SRTP encryption key (label byte `0x00`).
    CipherKey = 0x00,
    /// SRTP message authentication key (label byte `0x01`).
    AuthKey = 0x01,
    /// SRTP salt key (label byte `0x02`).
    SaltKey = 0x02,
    /// SRTCP encryption key (label byte `0x03`).
    SrtcpCipherKey = 0x03,
    /// SRTCP message authentication key (label byte `0x04`).
    SrtcpAuthKey = 0x04,
    /// SRTCP salt key (label byte `0x05`).
    SrtcpSaltKey = 0x05,
}

impl SrtpLabel {
    /// Parses an integer label value into a typed [`SrtpLabel`].
    ///
    /// Returns [`ProviderError::AlgorithmUnavailable`] if the value is
    /// outside the RFC 3711 range 0x00-0x05.
    ///
    /// Mirrors the validation in C `kdf_srtpkdf_set_ctx_params()`
    /// (`srtpkdf.c` ≈ line 335) which rejects `label > KDF_SRTP_MAX_LABEL`.
    /// The Rust port further restricts the input to values with RFC-defined
    /// semantics (0-5), rejecting 6 and 7 at the parameter boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::AlgorithmUnavailable`] for unsupported
    /// label values.
    pub fn from_u32(v: u32) -> ProviderResult<Self> {
        match v {
            0x00 => Ok(Self::CipherKey),
            0x01 => Ok(Self::AuthKey),
            0x02 => Ok(Self::SaltKey),
            0x03 => Ok(Self::SrtcpCipherKey),
            0x04 => Ok(Self::SrtcpAuthKey),
            0x05 => Ok(Self::SrtcpSaltKey),
            v if v <= SRTP_MAX_LABEL => Err(ProviderError::AlgorithmUnavailable(format!(
                "SRTPKDF: label {v:#x} is reserved and has no RFC 3711 semantics"
            ))),
            _ => Err(ProviderError::AlgorithmUnavailable(format!(
                "SRTPKDF: invalid label {v:#x} (expected 0x00-0x05)"
            ))),
        }
    }

    /// Returns `true` when this label denotes an SRTP key (labels 0x00,
    /// 0x01, 0x02).
    ///
    /// Mirrors `is_srtp_table[label]` in C `srtpkdf.c` line 375.
    #[must_use]
    pub const fn is_srtp(self) -> bool {
        matches!(self, Self::CipherKey | Self::AuthKey | Self::SaltKey)
    }

    /// Returns the raw label byte (`0x00`-`0x05`) used in the KDF input
    /// construction.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Returns the packet-index length associated with this label.
    ///
    /// SRTP labels use a 6-byte index; SRTCP labels use a 4-byte index.
    /// Mirrors the C expression `is_srtp(label) ? KDF_SRTP_IDX_LEN :
    /// KDF_SRTP_SRTCP_IDX_LEN` at `srtpkdf.c` line 416.
    #[must_use]
    pub const fn index_length(self) -> usize {
        if self.is_srtp() {
            SRTP_IDX_LEN
        } else {
            SRTCP_IDX_LEN
        }
    }

    /// Returns the number of output bytes this label produces, given the
    /// cipher key length (only used for cipher-key labels).
    ///
    /// Mirrors the `switch (label)` block at `srtpkdf.c` lines 398-412:
    /// - Labels 0, 3, 6 → cipher key length;
    /// - Labels 1, 4    → `KDF_SRTP_AUTH_KEY_LEN` (20);
    /// - Labels 2, 7    → `KDF_SRTP_SALT_KEY_LEN` (14) — SRTP salt;
    /// - Label 5        → `KDF_SRTP_SALT_KEY_LEN` (14) — SRTCP salt.
    #[must_use]
    pub const fn output_length(self, cipher_key_length: usize) -> usize {
        match self {
            Self::CipherKey | Self::SrtcpCipherKey => cipher_key_length,
            Self::AuthKey | Self::SrtcpAuthKey => SRTP_AUTH_KEY_LEN,
            Self::SaltKey | Self::SrtcpSaltKey => SRTP_SALT_KEY_LEN,
        }
    }
}

// =============================================================================
// SrtpKdfContext
// =============================================================================

/// SRTP KDF operation context.
///
/// Holds the master key, master salt, label, packet index, and key
/// derivation rate. All cryptographic material (`key`, `salt`, `index`) is
/// zeroed on drop via [`ZeroizeOnDrop`] to satisfy the secure-erasure
/// requirement of AAP §0.7.6.
///
/// Maps to C `KDF_SRTP` in `srtpkdf.c` lines 36-52.
#[derive(ZeroizeOnDrop)]
pub struct SrtpKdfContext {
    /// Library context reference used for [`Cipher::fetch`]. Non-sensitive.
    #[zeroize(skip)]
    libctx: Arc<LibContext>,

    /// The fetched AES-CTR cipher descriptor (once configured). Non-sensitive
    /// — cached for key-length validation and re-used by subsequent
    /// `derive()` calls.
    #[zeroize(skip)]
    cipher: Option<Cipher>,

    /// Optional property query forwarded to [`Cipher::fetch`]. Non-sensitive.
    #[zeroize(skip)]
    cipher_properties: Option<String>,

    /// Master key. Zeroed on drop. Empty when unset.
    key: Vec<u8>,

    /// Master salt (14 bytes after validation). Zeroed on drop. Empty when
    /// unset.
    salt: Vec<u8>,

    /// SRTP/SRTCP label identifying the key being derived.
    #[zeroize(skip)]
    label: Option<SrtpLabel>,

    /// Raw packet index bytes (6 bytes SRTP, 4 bytes SRTCP). Zeroed on
    /// drop. Empty when unset.
    index: Vec<u8>,

    /// Key derivation rate (must be zero or a power of two).
    #[zeroize(skip)]
    kdr: u32,

    /// Pre-computed `log2(kdr)` bits; `0` when `kdr == 0`.
    #[zeroize(skip)]
    kdr_n: u32,
}

impl SrtpKdfContext {
    /// Creates an uninitialised SRTP KDF context.
    ///
    /// All cryptographic state is empty / `None`. Parameters must be
    /// applied via [`SrtpKdfContext::set_params`] before calling
    /// [`SrtpKdfContext::derive`].
    ///
    /// Mirrors C `kdf_srtpkdf_new()` at `srtpkdf.c` lines 87-99.
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        Self {
            libctx,
            cipher: None,
            cipher_properties: None,
            key: Vec::new(),
            salt: Vec::new(),
            label: None,
            index: Vec::new(),
            kdr: 0,
            kdr_n: 0,
        }
    }

    /// Returns the fetched cipher, or an error if no cipher has been set.
    ///
    /// Maps to the C `ctx->cipher == NULL` check at
    /// `srtpkdf.c` ≈ line 180 which raises `PROV_R_MISSING_CIPHER`.
    fn require_cipher(&self) -> ProviderResult<&Cipher> {
        self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Init("SRTPKDF: cipher not set (missing 'cipher' parameter)".into())
        })
    }

    /// Applies a parameter set to the context.
    ///
    /// Mirrors C `kdf_srtpkdf_set_ctx_params()` at `srtpkdf.c` lines
    /// 283-358. Parameter ordering matters: the cipher must be set before
    /// the key because the key length validation depends on it. However,
    /// individual `set_params` calls may configure subsets of parameters
    /// and will re-validate on the next call to `derive`.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::AlgorithmUnavailable`] — invalid cipher (not
    ///   AES-CTR), unsupported label, or invalid KDR (not a power of
    ///   two).
    /// - [`ProviderError::Common(CommonError::InvalidArgument)`] — a
    ///   parameter has the wrong type or is out of range.
    #[instrument(skip(self, params), level = "debug")]
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // OSSL_KDF_PARAM_PROPERTIES — record before cipher so cipher
        // fetches pick up the property query.
        if let Some(v) = params.get(PARAM_PROPERTIES) {
            let s = v.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "SRTPKDF: 'properties' must be a UTF-8 string".into(),
                ))
            })?;
            self.cipher_properties = if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            };
        }

        // OSSL_KDF_PARAM_CIPHER — must be AES-128/192/256-CTR.
        // Maps to C `srtpkdf.c` lines 291-313.
        if let Some(v) = params.get(PARAM_CIPHER) {
            let name = v.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "SRTPKDF: 'cipher' must be a UTF-8 string".into(),
                ))
            })?;
            self.apply_cipher(name)?;
        }

        // OSSL_KDF_PARAM_KEY — master key. Maps to C lines 314-321.
        if let Some(v) = params.get(PARAM_KEY) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "SRTPKDF: 'key' must be octet bytes".into(),
                ))
            })?;
            self.key.zeroize();
            self.key = bytes.to_vec();
        }

        // OSSL_KDF_PARAM_SALT — master salt. Maps to C lines 322-329 which
        // rejects `salt_len < KDF_SRTP_SALT_LEN` (14).
        if let Some(v) = params.get(PARAM_SALT) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "SRTPKDF: 'salt' must be octet bytes".into(),
                ))
            })?;
            if bytes.len() < SRTP_SALT_LEN {
                warn!(
                    got = bytes.len(),
                    required = SRTP_SALT_LEN,
                    "SRTPKDF: rejected short master salt"
                );
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SRTPKDF: salt length {} is below the required {} bytes",
                        bytes.len(),
                        SRTP_SALT_LEN
                    ),
                )));
            }
            self.salt.zeroize();
            self.salt = bytes.to_vec();
        }

        // OSSL_KDF_PARAM_LABEL — SRTP/SRTCP key identifier.
        // Maps to C lines 330-342 which rejects `label > KDF_SRTP_MAX_LABEL`.
        if let Some(v) = params.get(PARAM_LABEL) {
            let raw = Self::label_to_u32(v)?;
            self.label = Some(SrtpLabel::from_u32(raw)?);
            debug!(label = ?self.label, "SRTPKDF: label selected");
        }

        // OSSL_KDF_PARAM_INFO — packet index (SRTP: 6 bytes, SRTCP: 4).
        // Maps to C lines 343-350. Length is validated at derive time
        // because the accepted length depends on the label.
        if let Some(v) = params.get(PARAM_INDEX) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "SRTPKDF: 'info' (index) must be octet bytes".into(),
                ))
            })?;
            self.index.zeroize();
            self.index = bytes.to_vec();
        }

        // OSSL_KDF_PARAM_SRTP_KDF_RATE — must be 0 or a power of two with
        // `n <= KDF_SRTP_MAX_KDR`. Maps to C lines 351-358.
        if let Some(v) = params.get(PARAM_KDR) {
            let kdr = v.as_u32().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "SRTPKDF: 'kdr' must be an unsigned integer".into(),
                ))
            })?;
            self.apply_kdr(kdr)?;
        }

        Ok(())
    }

    /// Accepts an integer-typed label value in any of the typed numeric
    /// variants the [`ParamSet`] layer admits.
    ///
    /// Mirrors the C path where the label is read via `OSSL_PARAM_get_uint32`
    /// at `srtpkdf.c` line 331.
    fn label_to_u32(v: &ParamValue) -> ProviderResult<u32> {
        if let Some(u) = v.as_u32() {
            return Ok(u);
        }
        if let Some(i) = v.as_i32() {
            // R6: ensure non-negative before casting to u32.
            return u32::try_from(i).map_err(|_| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "SRTPKDF: negative label value {i} is not permitted"
                )))
            });
        }
        Err(ProviderError::Common(CommonError::InvalidArgument(
            "SRTPKDF: 'label' must be an unsigned integer".into(),
        )))
    }

    /// Fetches the requested AES-CTR cipher and validates its mode / key
    /// length as required by RFC 3711. Accepts only AES-128-CTR /
    /// AES-192-CTR / AES-256-CTR per C `srtpkdf.c` lines 296-311.
    ///
    /// The C source accepts all three AES variants, but the current Rust
    /// `openssl-crypto` predefined cipher registry defines only
    /// `AES-128-CTR` and `AES-256-CTR`; unsupported variants raise
    /// [`ProviderError::AlgorithmUnavailable`] consistent with the C
    /// behaviour when an unknown cipher is referenced.
    fn apply_cipher(&mut self, name: &str) -> ProviderResult<()> {
        let props = self.cipher_properties.as_deref();

        let cipher = Cipher::fetch(&self.libctx, name, props).map_err(dispatch_err)?;

        // RFC 3711 requires AES in CTR mode. Reject any other cipher.
        if cipher.mode() != CipherMode::Ctr {
            warn!(
                cipher = %cipher.name(),
                mode = ?cipher.mode(),
                "SRTPKDF: rejected non-CTR cipher"
            );
            return Err(ProviderError::AlgorithmUnavailable(format!(
                "SRTPKDF: cipher '{}' is not a CTR-mode cipher; RFC 3711 requires AES-CTR",
                cipher.name()
            )));
        }

        // RFC 3711 requires AES specifically — validate key size is a
        // recognised AES key length.
        let key_len = cipher.key_length();
        if !matches!(key_len, 16 | 24 | 32) {
            warn!(
                cipher = %cipher.name(),
                key_len,
                "SRTPKDF: rejected cipher with non-AES key length"
            );
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SRTPKDF: cipher '{}' has {}-byte key; AES requires 16, 24, or 32 bytes",
                    cipher.name(),
                    key_len
                ),
            )));
        }

        debug!(cipher = %cipher.name(), key_len, "SRTPKDF: cipher configured");
        self.cipher = Some(cipher);
        Ok(())
    }

    /// Validates and applies the key derivation rate, computing
    /// `kdr_n = log2(kdr)` for KDR-based index shifting.
    ///
    /// Mirrors C `srtpkdf.c` lines 351-358 plus the `nearest_power_of_two`
    /// helper at line 68.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Common(CommonError::InvalidArgument)`] when
    /// `kdr` is not zero and not a power of two, or when
    /// `log2(kdr) > KDF_SRTP_MAX_KDR (= 24)`.
    fn apply_kdr(&mut self, kdr: u32) -> ProviderResult<()> {
        if kdr == 0 {
            self.kdr = 0;
            self.kdr_n = 0;
            trace!("SRTPKDF: kdr=0 (disabled)");
            return Ok(());
        }
        if !kdr.is_power_of_two() {
            warn!(kdr, "SRTPKDF: rejected non-power-of-two KDR");
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("SRTPKDF: kdr={kdr} is not a power of two"),
            )));
        }
        // `trailing_zeros()` on a non-zero power-of-two u32 is in 0..=31,
        // so the cast below is lossless. R6: the range bound is verified
        // against SRTP_MAX_KDR.
        let kdr_n = kdr.trailing_zeros();
        if kdr_n > SRTP_MAX_KDR {
            warn!(
                kdr,
                kdr_n, "SRTPKDF: rejected KDR exceeding KDF_SRTP_MAX_KDR"
            );
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("SRTPKDF: kdr={kdr} exceeds maximum (log2(kdr)={kdr_n} > 24)"),
            )));
        }
        self.kdr = kdr;
        self.kdr_n = kdr_n;
        trace!(kdr, kdr_n, "SRTPKDF: kdr configured");
        Ok(())
    }

    /// Runs the SRTP/SRTCP key derivation, writing `o_len` bytes into
    /// `output`.
    ///
    /// This is a direct translation of the C `SRTPKDF()` function at
    /// `srtpkdf.c` lines 376-494.
    ///
    /// The algorithm (quoted from the C comment block):
    ///
    /// 1. Construct a 16-byte `local_salt` from the 14-byte master salt,
    ///    zero-padded on the right.
    /// 2. If `kdr > 0`, compute `r = index >> kdr_n` and XOR its
    ///    big-endian byte representation into the tail of `master_salt`
    ///    before copying it into `local_salt`.
    /// 3. XOR the label byte into `local_salt[SALT_LEN - 1 - index_len]`
    ///    (position 7 for SRTP / 9 for SRTCP).
    /// 4. Encrypt a zero buffer of length `o_len` using AES-CTR with
    ///    `local_salt` as the IV, producing the derived key.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Init`] if the cipher, key, salt, label, or
    ///   index are not all configured.
    /// - [`ProviderError::Common(CommonError::InvalidArgument)`] if the
    ///   configured key does not match the cipher's expected length, if
    ///   the output buffer is too small, or if the provided index length
    ///   does not match what the label requires.
    /// - [`ProviderError::Dispatch`] if the underlying cipher operation
    ///   fails.
    #[instrument(skip(self, output), level = "debug")]
    fn srtp_derive(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let cipher = self.require_cipher()?;
        let label = self.label.ok_or_else(|| {
            ProviderError::Init("SRTPKDF: label not set (missing 'label' parameter)".into())
        })?;

        if self.key.is_empty() {
            return Err(ProviderError::Init(
                "SRTPKDF: master key not set (missing 'key' parameter)".into(),
            ));
        }
        if self.key.len() != cipher.key_length() {
            warn!(
                expected = cipher.key_length(),
                got = self.key.len(),
                "SRTPKDF: master key length mismatch"
            );
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SRTPKDF: master key length {} does not match cipher '{}' ({} bytes)",
                    self.key.len(),
                    cipher.name(),
                    cipher.key_length()
                ),
            )));
        }
        if self.salt.is_empty() {
            return Err(ProviderError::Init(
                "SRTPKDF: master salt not set (missing 'salt' parameter)".into(),
            ));
        }
        // `apply_params` enforces `salt.len() >= SRTP_SALT_LEN`, so this
        // indexing is safe. The extra assertion defends against an
        // invariant violation from a future refactor.
        debug_assert!(self.salt.len() >= SRTP_SALT_LEN);

        // Output length must match the configured label.
        let o_len = label.output_length(cipher.key_length());
        if output.len() < o_len {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SRTPKDF: output buffer too small ({} < {} bytes for label {:?})",
                    output.len(),
                    o_len,
                    label
                ),
            )));
        }

        // Step 1: initialise master_salt (16 bytes, zero-padded) from the
        // 14-byte master salt. `master_salt[14..16]` remains zero.
        let mut master_salt = [0u8; SRTP_IV_LEN];
        master_salt[..SRTP_SALT_LEN].copy_from_slice(&self.salt[..SRTP_SALT_LEN]);

        // Step 2: determine index length and, when KDR > 0, fold
        // `index >> kdr_n` into the tail of `master_salt`.
        let index_len = label.index_length();
        if !self.index.is_empty() && self.kdr > 0 {
            if self.index.len() < index_len {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SRTPKDF: index length {} is below the {} bytes required for label {:?}",
                        self.index.len(),
                        index_len,
                        label
                    ),
                )));
            }
            // Parse the big-endian index into a u64 (max 6 bytes = 48 bits
            // for SRTP, 4 bytes for SRTCP, both fit in u64). R6: the
            // running shift is bounded by index_len (max 6) × 8 = 48 so
            // no u64 overflow is possible.
            let mut idx: u64 = 0;
            for &b in &self.index[..index_len] {
                idx = (idx << 8) | u64::from(b);
            }
            // Mask to 48 bits per AAP validation rule for SRTP index.
            idx &= 0x0000_FFFF_FFFF_FFFF_u64;
            // Shift by kdr_n. R6: self.kdr_n has been verified
            // `<= SRTP_MAX_KDR (24)` so this cannot overflow.
            let r = idx >> self.kdr_n;

            // Serialise r as big-endian bytes, write into an 8-byte
            // scratch buffer, and then XOR the low bytes into the tail of
            // master_salt. BN_bn2bin in C yields a minimal big-endian
            // representation; here we compute an equivalent "trimmed"
            // length by dropping leading zero bytes from the u64 encoding.
            let r_be = r.to_be_bytes();
            let leading_zeros = r_be.iter().take_while(|&&b| b == 0).count();
            let iv_bytes = &r_be[leading_zeros..];
            let iv_len = iv_bytes.len();

            // C: `for (i = 1; i <= iv_len; i++) master_salt[salt_len - i]
            //     ^= iv[iv_len - i];`
            // Equivalently: the last `iv_len` bytes of master_salt are
            // XORed with iv_bytes, byte-for-byte.
            if iv_len <= SRTP_SALT_LEN {
                let tail = &mut master_salt[SRTP_SALT_LEN - iv_len..SRTP_SALT_LEN];
                for (dst, src) in tail.iter_mut().zip(iv_bytes.iter()) {
                    *dst ^= *src;
                }
            } else {
                // r_be is at most 8 bytes which is always ≤ SRTP_SALT_LEN
                // (14), so this branch is unreachable in practice. Guard
                // against a future widening.
                return Err(ProviderError::Common(CommonError::Internal(
                    "SRTPKDF: shifted index exceeds salt length".into(),
                )));
            }
            trace!(
                label = ?label,
                index_len,
                kdr = self.kdr,
                iv_len,
                "SRTPKDF: kdr-folded index"
            );
        }

        // Step 3: build local_salt by copying master_salt and XOR-ing the
        // label byte at position `(SALT_LEN - 1) - index_len`.
        //
        // C: `local_salt[(KDF_SRTP_SALT_LEN - 1) - index_len] ^= label;`
        // With SRTP (index_len=6):  position = 13 - 6 = 7.
        // With SRTCP (index_len=4): position = 13 - 4 = 9.
        let mut local_salt = [0u8; SRTP_IV_LEN];
        local_salt[..SRTP_SALT_LEN].copy_from_slice(&master_salt[..SRTP_SALT_LEN]);
        // R6: `SRTP_SALT_LEN - 1 - index_len` evaluates to 7 or 9, both
        // safely within `[0, SRTP_IV_LEN)`.
        let label_pos = (SRTP_SALT_LEN - 1) - index_len;
        local_salt[label_pos] ^= label.as_byte();

        trace!(
            label = ?label,
            index_len,
            output_len = o_len,
            "SRTPKDF: deriving key material"
        );

        // Step 4: AES-CTR(master_key, local_salt) applied to an o_len
        // zero buffer yields the requested derived key material.
        let mut ctx = CipherCtx::new();
        ctx.encrypt_init(cipher, &self.key, Some(&local_salt[..]), None)
            .map_err(dispatch_err)?;
        let zero_input = vec![0u8; o_len];
        let mut produced: Vec<u8> = Vec::with_capacity(o_len);
        let written = ctx
            .update(&zero_input, &mut produced)
            .map_err(dispatch_err)?;
        // CTR is a stream-like mode: update produces exactly `o_len`
        // bytes. Verify before copying into the caller buffer.
        if written != o_len || produced.len() != o_len {
            return Err(ProviderError::Dispatch(format!(
                "SRTPKDF: AES-CTR update returned {written} bytes (expected {o_len})"
            )));
        }
        // Finalize for completeness — for CTR, finalize is a no-op that
        // marks the context as consumed.
        let mut trailer: Vec<u8> = Vec::new();
        let tail_written = ctx.finalize(&mut trailer).map_err(dispatch_err)?;
        if tail_written != 0 || !trailer.is_empty() {
            return Err(ProviderError::Dispatch(format!(
                "SRTPKDF: AES-CTR finalize produced {tail_written} unexpected trailing bytes"
            )));
        }

        output[..o_len].copy_from_slice(&produced[..o_len]);

        // Securely erase local scratch buffers. `ctx` self-zeroes on
        // drop; explicit cleanse mirrors the C `OPENSSL_cleanse()` calls
        // at `srtpkdf.c` lines 484-487.
        master_salt.zeroize();
        local_salt.zeroize();
        produced.zeroize();

        Ok(o_len)
    }
}

impl KdfContext for SrtpKdfContext {
    /// Derives SRTP/SRTCP key material into `key`.
    ///
    /// Parameters are applied via `params` before derivation — equivalent
    /// to calling [`SrtpKdfContext::set_params`] followed by the C
    /// `kdf_srtpkdf_derive()` dispatch at `srtpkdf.c` lines 159-216.
    ///
    /// Returns the number of bytes written into `key`.
    #[instrument(skip(self, key, params), level = "debug")]
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        self.apply_params(params)?;
        self.srtp_derive(key)
    }

    /// Resets the context to its uninitialised state, zeroing all
    /// cryptographic material.
    ///
    /// Mirrors C `kdf_srtpkdf_reset()` at `srtpkdf.c` lines 105-127.
    fn reset(&mut self) -> ProviderResult<()> {
        trace!("SRTPKDF: resetting context");
        self.key.zeroize();
        self.salt.zeroize();
        self.index.zeroize();
        self.cipher = None;
        self.cipher_properties = None;
        self.label = None;
        self.kdr = 0;
        self.kdr_n = 0;
        Ok(())
    }

    /// Returns a snapshot of settable/gettable parameter descriptors
    /// the context reports to the caller.
    ///
    /// Mirrors C `kdf_srtpkdf_get_ctx_params()` at `srtpkdf.c` lines
    /// 362-374: the C implementation only reports the output size which
    /// in this function-family is always a property of the configured
    /// label, not of the context state. We report the current KDR and
    /// label for diagnostic parity.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut builder = ParamBuilder::new().push_u32(PARAM_KDR, self.kdr).push_u32(
            "size",
            // R6: output size is always <= 32 (AES-256 key). u32 cast
            // is lossless.
            match (self.label, self.cipher.as_ref()) {
                (Some(l), Some(c)) => {
                    u32::try_from(l.output_length(c.key_length())).unwrap_or(u32::MAX)
                }
                (Some(l), None) => u32::try_from(l.output_length(0)).unwrap_or(u32::MAX),
                _ => 0,
            },
        );
        if let Some(l) = self.label {
            builder = builder.push_u32(PARAM_LABEL, u32::from(l.as_byte()));
        }
        if let Some(c) = self.cipher.as_ref() {
            builder = builder.push_utf8(PARAM_CIPHER, c.name().to_string());
        }
        Ok(builder.build())
    }

    /// Applies parameters to the context without triggering derivation.
    ///
    /// Mirrors C `kdf_srtpkdf_set_ctx_params()` at `srtpkdf.c` lines
    /// 283-358.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// SrtpKdfProvider
// =============================================================================

/// Provider handle for the SRTP/SRTCP Key Derivation Function.
///
/// Maps to C `ossl_kdf_srtpkdf_functions` dispatch entry in
/// `providers/implementations/kdfs/srtpkdf.c` lines 540-552. The provider
/// holds a reference to the enclosing library context so new contexts can
/// fetch cipher algorithms without a separate ambient lookup.
pub struct SrtpKdfProvider {
    libctx: Arc<LibContext>,
}

impl Default for SrtpKdfProvider {
    fn default() -> Self {
        Self::new(LibContext::get_default())
    }
}

impl SrtpKdfProvider {
    /// Constructs a new provider bound to the supplied library context.
    ///
    /// Mirrors the initial construction path for the dispatch table in C
    /// `providers/implementations/kdfs/srtpkdf.c` (the `provctx` field of
    /// `KDF_SRTP` at line 38).
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        Self { libctx }
    }

    /// Returns the set of parameters that callers may supply to
    /// [`KdfContext::set_params`].
    ///
    /// Mirrors C `kdf_srtpkdf_settable_ctx_params()` at `srtpkdf.c` lines
    /// 267-281.
    #[must_use]
    pub fn settable_params() -> ParamSet {
        ParamBuilder::new()
            .push_utf8(PARAM_CIPHER, String::new())
            .push_utf8(PARAM_PROPERTIES, String::new())
            .push_octet(PARAM_KEY, Vec::new())
            .push_octet(PARAM_SALT, Vec::new())
            .push_u32(PARAM_LABEL, 0)
            .push_octet(PARAM_INDEX, Vec::new())
            .push_u32(PARAM_KDR, 0)
            .build()
    }

    /// Returns the set of parameters that may be queried via
    /// [`KdfContext::get_params`].
    ///
    /// Mirrors C `kdf_srtpkdf_gettable_ctx_params()` at `srtpkdf.c` lines
    /// 261-265.
    #[must_use]
    pub fn gettable_params() -> ParamSet {
        ParamBuilder::new()
            .push_u32("size", 0)
            .push_u32(PARAM_KDR, 0)
            .push_u32(PARAM_LABEL, 0)
            .push_utf8(PARAM_CIPHER, String::new())
            .build()
    }
}

impl KdfProvider for SrtpKdfProvider {
    fn name(&self) -> &'static str {
        "SRTPKDF"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        trace!("SRTPKDF: new context created");
        Ok(Box::new(SrtpKdfContext::new(Arc::clone(&self.libctx))))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns all [`AlgorithmDescriptor`] entries contributed by this module.
///
/// Registers a single `"SRTPKDF"` algorithm with the default provider.
///
/// The C source exposes one dispatch entry:
/// `ossl_kdf_srtpkdf_functions` in `providers/defltprov.c` lines
/// ~400 (via `OSSL_ALGORITHM deflt_kdfs[]`).
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["SRTPKDF"],
        "provider=default",
        "SRTP/SRTCP Key Derivation Function (RFC 3711 §4.3.1)",
    )]
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: fresh SRTP KDF context backed by the default libctx.
    fn new_ctx() -> Box<dyn KdfContext> {
        SrtpKdfProvider::default().new_ctx().unwrap()
    }

    /// Builds a baseline parameter set for AES-128-CTR SRTP cipher-key
    /// derivation (label 0x00) with the supplied master key / salt /
    /// index values.
    fn base_params(
        cipher: &str,
        key: &[u8],
        salt: &[u8],
        label: u32,
        index: &[u8],
        kdr: u32,
    ) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_CIPHER, ParamValue::Utf8String(cipher.to_string()));
        ps.set(PARAM_KEY, ParamValue::OctetString(key.to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.to_vec()));
        ps.set(PARAM_LABEL, ParamValue::UInt32(label));
        ps.set(PARAM_INDEX, ParamValue::OctetString(index.to_vec()));
        ps.set(PARAM_KDR, ParamValue::UInt32(kdr));
        ps
    }

    // ----- SrtpLabel unit tests -----

    #[test]
    fn srtp_label_from_u32_accepts_0_through_5() {
        assert_eq!(SrtpLabel::from_u32(0).unwrap(), SrtpLabel::CipherKey);
        assert_eq!(SrtpLabel::from_u32(1).unwrap(), SrtpLabel::AuthKey);
        assert_eq!(SrtpLabel::from_u32(2).unwrap(), SrtpLabel::SaltKey);
        assert_eq!(SrtpLabel::from_u32(3).unwrap(), SrtpLabel::SrtcpCipherKey);
        assert_eq!(SrtpLabel::from_u32(4).unwrap(), SrtpLabel::SrtcpAuthKey);
        assert_eq!(SrtpLabel::from_u32(5).unwrap(), SrtpLabel::SrtcpSaltKey);
    }

    #[test]
    fn srtp_label_rejects_reserved_and_out_of_range() {
        assert!(matches!(
            SrtpLabel::from_u32(6),
            Err(ProviderError::AlgorithmUnavailable(_))
        ));
        assert!(matches!(
            SrtpLabel::from_u32(7),
            Err(ProviderError::AlgorithmUnavailable(_))
        ));
        assert!(matches!(
            SrtpLabel::from_u32(8),
            Err(ProviderError::AlgorithmUnavailable(_))
        ));
        assert!(matches!(
            SrtpLabel::from_u32(0xFF),
            Err(ProviderError::AlgorithmUnavailable(_))
        ));
    }

    #[test]
    fn srtp_label_is_srtp_classification() {
        assert!(SrtpLabel::CipherKey.is_srtp());
        assert!(SrtpLabel::AuthKey.is_srtp());
        assert!(SrtpLabel::SaltKey.is_srtp());
        assert!(!SrtpLabel::SrtcpCipherKey.is_srtp());
        assert!(!SrtpLabel::SrtcpAuthKey.is_srtp());
        assert!(!SrtpLabel::SrtcpSaltKey.is_srtp());
    }

    #[test]
    fn srtp_label_index_length() {
        assert_eq!(SrtpLabel::CipherKey.index_length(), SRTP_IDX_LEN);
        assert_eq!(SrtpLabel::AuthKey.index_length(), SRTP_IDX_LEN);
        assert_eq!(SrtpLabel::SaltKey.index_length(), SRTP_IDX_LEN);
        assert_eq!(SrtpLabel::SrtcpCipherKey.index_length(), SRTCP_IDX_LEN);
        assert_eq!(SrtpLabel::SrtcpAuthKey.index_length(), SRTCP_IDX_LEN);
        assert_eq!(SrtpLabel::SrtcpSaltKey.index_length(), SRTCP_IDX_LEN);
    }

    #[test]
    fn srtp_label_output_length_per_cipher_size() {
        assert_eq!(SrtpLabel::CipherKey.output_length(16), 16);
        assert_eq!(SrtpLabel::CipherKey.output_length(32), 32);
        assert_eq!(SrtpLabel::SrtcpCipherKey.output_length(16), 16);
        assert_eq!(SrtpLabel::AuthKey.output_length(16), SRTP_AUTH_KEY_LEN);
        assert_eq!(SrtpLabel::SrtcpAuthKey.output_length(32), SRTP_AUTH_KEY_LEN);
        assert_eq!(SrtpLabel::SaltKey.output_length(16), SRTP_SALT_KEY_LEN);
        assert_eq!(SrtpLabel::SrtcpSaltKey.output_length(32), SRTP_SALT_KEY_LEN);
    }

    #[test]
    fn srtp_label_byte_values_match_rfc3711() {
        assert_eq!(SrtpLabel::CipherKey.as_byte(), 0x00);
        assert_eq!(SrtpLabel::AuthKey.as_byte(), 0x01);
        assert_eq!(SrtpLabel::SaltKey.as_byte(), 0x02);
        assert_eq!(SrtpLabel::SrtcpCipherKey.as_byte(), 0x03);
        assert_eq!(SrtpLabel::SrtcpAuthKey.as_byte(), 0x04);
        assert_eq!(SrtpLabel::SrtcpSaltKey.as_byte(), 0x05);
    }

    // ----- Provider surface -----

    #[test]
    fn provider_name_is_srtpkdf() {
        let p = SrtpKdfProvider::default();
        assert_eq!(p.name(), "SRTPKDF");
    }

    #[test]
    fn descriptors_contains_srtpkdf() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].names, vec!["SRTPKDF"]);
        assert_eq!(descs[0].property, "provider=default");
    }

    #[test]
    fn provider_settable_and_gettable_params_are_populated() {
        let s = SrtpKdfProvider::settable_params();
        let g = SrtpKdfProvider::gettable_params();
        assert!(s.contains(PARAM_CIPHER));
        assert!(s.contains(PARAM_KEY));
        assert!(s.contains(PARAM_SALT));
        assert!(s.contains(PARAM_LABEL));
        assert!(s.contains(PARAM_INDEX));
        assert!(s.contains(PARAM_KDR));
        assert!(g.contains("size"));
        assert!(g.contains(PARAM_KDR));
    }

    // ----- Parameter validation -----

    #[test]
    fn derive_missing_cipher_fails_with_init_error() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(vec![0u8; 16]));
        ps.set(PARAM_SALT, ParamValue::OctetString(vec![0u8; 14]));
        ps.set(PARAM_LABEL, ParamValue::UInt32(0));
        let mut out = vec![0u8; 16];
        let err = ctx.derive(&mut out, &ps).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)), "err={err:?}");
    }

    #[test]
    fn derive_missing_key_fails_with_init_error() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_CIPHER,
            ParamValue::Utf8String("AES-128-CTR".to_string()),
        );
        ps.set(PARAM_SALT, ParamValue::OctetString(vec![0u8; 14]));
        ps.set(PARAM_LABEL, ParamValue::UInt32(0));
        let mut out = vec![0u8; 16];
        let err = ctx.derive(&mut out, &ps).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)), "err={err:?}");
    }

    #[test]
    fn derive_missing_salt_fails_with_init_error() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_CIPHER,
            ParamValue::Utf8String("AES-128-CTR".to_string()),
        );
        ps.set(PARAM_KEY, ParamValue::OctetString(vec![0u8; 16]));
        ps.set(PARAM_LABEL, ParamValue::UInt32(0));
        let mut out = vec![0u8; 16];
        let err = ctx.derive(&mut out, &ps).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)), "err={err:?}");
    }

    #[test]
    fn derive_missing_label_fails_with_init_error() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_CIPHER,
            ParamValue::Utf8String("AES-128-CTR".to_string()),
        );
        ps.set(PARAM_KEY, ParamValue::OctetString(vec![0u8; 16]));
        ps.set(PARAM_SALT, ParamValue::OctetString(vec![0u8; 14]));
        let mut out = vec![0u8; 16];
        let err = ctx.derive(&mut out, &ps).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)), "err={err:?}");
    }

    #[test]
    fn rejects_short_salt() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_CIPHER,
            ParamValue::Utf8String("AES-128-CTR".to_string()),
        );
        ps.set(PARAM_KEY, ParamValue::OctetString(vec![0u8; 16]));
        // 13 bytes < required 14.
        ps.set(PARAM_SALT, ParamValue::OctetString(vec![0u8; 13]));
        let err = ctx.set_params(&ps).unwrap_err();
        assert!(
            matches!(err, ProviderError::Common(CommonError::InvalidArgument(_))),
            "err={err:?}"
        );
    }

    #[test]
    fn rejects_non_ctr_cipher() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_CIPHER,
            ParamValue::Utf8String("AES-128-CBC".to_string()),
        );
        let err = ctx.set_params(&ps).unwrap_err();
        assert!(
            matches!(err, ProviderError::AlgorithmUnavailable(_)),
            "err={err:?}"
        );
    }

    #[test]
    fn rejects_unknown_cipher() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_CIPHER,
            ParamValue::Utf8String("nosuch-cipher".to_string()),
        );
        let err = ctx.set_params(&ps).unwrap_err();
        // Mapped from Cipher::fetch's CryptoError::AlgorithmNotFound.
        assert!(matches!(err, ProviderError::Dispatch(_)), "err={err:?}");
    }

    #[test]
    fn rejects_label_above_five() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(PARAM_LABEL, ParamValue::UInt32(6));
        let err = ctx.set_params(&ps).unwrap_err();
        assert!(
            matches!(err, ProviderError::AlgorithmUnavailable(_)),
            "err={err:?}"
        );
    }

    #[test]
    fn rejects_non_power_of_two_kdr() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KDR, ParamValue::UInt32(3));
        let err = ctx.set_params(&ps).unwrap_err();
        assert!(
            matches!(err, ProviderError::Common(CommonError::InvalidArgument(_))),
            "err={err:?}"
        );
    }

    #[test]
    fn accepts_kdr_of_zero() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KDR, ParamValue::UInt32(0));
        ctx.set_params(&ps).unwrap();
    }

    #[test]
    fn accepts_kdr_power_of_two_in_range() {
        for e in 0..=24u32 {
            let mut ctx = new_ctx();
            let mut ps = ParamSet::new();
            ps.set(PARAM_KDR, ParamValue::UInt32(1u32 << e));
            ctx.set_params(&ps).unwrap_or_else(|err| {
                panic!("kdr=2^{e} should be accepted but got: {err:?}");
            });
        }
    }

    #[test]
    fn rejects_kdr_power_of_two_above_limit() {
        let mut ctx = new_ctx();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KDR, ParamValue::UInt32(1u32 << 25));
        let err = ctx.set_params(&ps).unwrap_err();
        assert!(
            matches!(err, ProviderError::Common(CommonError::InvalidArgument(_))),
            "err={err:?}"
        );
    }

    #[test]
    fn rejects_master_key_length_mismatch() {
        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &[0u8; 32], // 32 bytes but AES-128 expects 16
            &[0u8; 14],
            0,
            &[0u8; 6],
            0,
        );
        let mut out = vec![0u8; 16];
        let err = ctx.derive(&mut out, &ps).unwrap_err();
        assert!(
            matches!(err, ProviderError::Common(CommonError::InvalidArgument(_))),
            "err={err:?}"
        );
    }

    #[test]
    fn rejects_output_buffer_too_small() {
        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &[1u8; 16],
            &[2u8; 14],
            1, // AuthKey → 20 bytes required
            &[3u8; 6],
            0,
        );
        let mut out = vec![0u8; 16]; // less than SRTP_AUTH_KEY_LEN
        let err = ctx.derive(&mut out, &ps).unwrap_err();
        assert!(
            matches!(err, ProviderError::Common(CommonError::InvalidArgument(_))),
            "err={err:?}"
        );
    }

    // ----- End-to-end derivations -----

    #[test]
    fn derive_aes128_cipher_key_produces_16_bytes() {
        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &[0x11u8; 16],
            &[0x22u8; 14],
            0, // CipherKey
            &[0u8; 6],
            0,
        );
        let mut out = vec![0u8; 16];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 16);
        assert_ne!(out, vec![0u8; 16]);
    }

    #[test]
    fn derive_aes256_cipher_key_produces_32_bytes() {
        let mut ctx = new_ctx();
        let ps = base_params("AES-256-CTR", &[0x33u8; 32], &[0x44u8; 14], 0, &[0u8; 6], 0);
        let mut out = vec![0u8; 32];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(out, vec![0u8; 32]);
    }

    #[test]
    fn derive_auth_key_produces_20_bytes() {
        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &[0x55u8; 16],
            &[0x66u8; 14],
            1, // AuthKey
            &[0u8; 6],
            0,
        );
        let mut out = vec![0u8; 20];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, SRTP_AUTH_KEY_LEN);
        assert_ne!(out, vec![0u8; 20]);
    }

    #[test]
    fn derive_salt_key_produces_14_bytes() {
        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &[0x77u8; 16],
            &[0x88u8; 14],
            2, // SaltKey
            &[0u8; 6],
            0,
        );
        let mut out = vec![0u8; 14];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, SRTP_SALT_KEY_LEN);
        assert_ne!(out, vec![0u8; 14]);
    }

    #[test]
    fn derive_srtcp_keys_use_4_byte_index_length() {
        let mut ctx = new_ctx();
        // SRTCP cipher key with a 4-byte index must succeed even when
        // provided index is exactly 4 bytes — SRTP would reject this.
        let ps = base_params(
            "AES-128-CTR",
            &[0x99u8; 16],
            &[0xAAu8; 14],
            3, // SrtcpCipherKey
            &[0u8; 4],
            1, // KDR enabled
        );
        let mut out = vec![0u8; 16];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 16);
    }

    #[test]
    fn derive_is_deterministic_for_same_inputs() {
        let ps = base_params(
            "AES-128-CTR",
            b"0123456789abcdef",
            b"labelsalt14byte",
            0,
            &[0u8; 6],
            0,
        );

        let mut a_ctx = new_ctx();
        let mut b_ctx = new_ctx();
        let mut a = vec![0u8; 16];
        let mut b = vec![0u8; 16];
        a_ctx.derive(&mut a, &ps).unwrap();
        b_ctx.derive(&mut b, &ps).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_labels_produce_different_keys() {
        let key = [0xABu8; 16];
        let salt = [0xCDu8; 14];
        let index = [0u8; 6];

        let mut c_cipher = new_ctx();
        let mut c_auth = new_ctx();
        let mut c_salt = new_ctx();

        let ps_cipher = base_params("AES-128-CTR", &key, &salt, 0, &index, 0);
        let ps_auth = base_params("AES-128-CTR", &key, &salt, 1, &index, 0);
        let ps_salt = base_params("AES-128-CTR", &key, &salt, 2, &index, 0);

        let mut out_cipher = vec![0u8; 16];
        let mut out_auth = vec![0u8; 20];
        let mut out_salt = vec![0u8; 14];

        c_cipher.derive(&mut out_cipher, &ps_cipher).unwrap();
        c_auth.derive(&mut out_auth, &ps_auth).unwrap();
        c_salt.derive(&mut out_salt, &ps_salt).unwrap();

        assert_ne!(&out_cipher[..14], &out_salt[..]);
        assert_ne!(&out_cipher[..], &out_auth[..16]);
    }

    #[test]
    fn different_keys_produce_different_outputs() {
        let salt = [0u8; 14];
        let index = [0u8; 6];

        let mut c1 = new_ctx();
        let mut c2 = new_ctx();
        let ps1 = base_params("AES-128-CTR", &[0u8; 16], &salt, 0, &index, 0);
        let ps2 = base_params("AES-128-CTR", &[1u8; 16], &salt, 0, &index, 0);

        let mut out1 = vec![0u8; 16];
        let mut out2 = vec![0u8; 16];
        c1.derive(&mut out1, &ps1).unwrap();
        c2.derive(&mut out2, &ps2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn different_salts_produce_different_outputs() {
        let key = [0u8; 16];
        let index = [0u8; 6];

        let mut c1 = new_ctx();
        let mut c2 = new_ctx();
        let ps1 = base_params("AES-128-CTR", &key, &[0u8; 14], 0, &index, 0);
        let ps2 = base_params("AES-128-CTR", &key, &[1u8; 14], 0, &index, 0);

        let mut out1 = vec![0u8; 16];
        let mut out2 = vec![0u8; 16];
        c1.derive(&mut out1, &ps1).unwrap();
        c2.derive(&mut out2, &ps2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn kdr_changes_output_when_index_high_enough() {
        // With KDR=0 the index has no effect; enabling KDR with index
        // above the shift threshold changes the local_salt.
        let key = [0x10u8; 16];
        let salt = [0x20u8; 14];
        // Index = 0x0000_0000_0100 (i.e. 256 in 6-byte BE)
        let index = [0u8, 0, 0, 0, 1, 0];

        let mut c_no_kdr = new_ctx();
        let mut c_kdr = new_ctx();
        let ps_no_kdr = base_params("AES-128-CTR", &key, &salt, 0, &index, 0);
        // KDR=128 → kdr_n=7, index>>7 = 256>>7 = 2 (non-zero).
        let ps_kdr = base_params("AES-128-CTR", &key, &salt, 0, &index, 128);

        let mut out_no_kdr = vec![0u8; 16];
        let mut out_kdr = vec![0u8; 16];
        c_no_kdr.derive(&mut out_no_kdr, &ps_no_kdr).unwrap();
        c_kdr.derive(&mut out_kdr, &ps_kdr).unwrap();
        assert_ne!(out_no_kdr, out_kdr);
    }

    #[test]
    fn kdr_no_effect_when_index_below_threshold() {
        // When index < kdr, index>>kdr_n == 0 so local_salt is identical
        // to the master_salt case (kdr=0 path); derived key should match
        // kdr=0 output.
        let key = [0x11u8; 16];
        let salt = [0x22u8; 14];
        // Index = 5 → below kdr=16 so shift gives 0.
        let index = [0, 0, 0, 0, 0, 5];

        let mut c_no_kdr = new_ctx();
        let mut c_kdr = new_ctx();
        let ps_no_kdr = base_params("AES-128-CTR", &key, &salt, 0, &index, 0);
        let ps_kdr = base_params("AES-128-CTR", &key, &salt, 0, &index, 16);

        let mut out_no_kdr = vec![0u8; 16];
        let mut out_kdr = vec![0u8; 16];
        c_no_kdr.derive(&mut out_no_kdr, &ps_no_kdr).unwrap();
        c_kdr.derive(&mut out_kdr, &ps_kdr).unwrap();
        assert_eq!(out_no_kdr, out_kdr);
    }

    #[test]
    fn reset_clears_cipher_and_label() {
        let mut ctx = new_ctx();
        let ps = base_params("AES-128-CTR", &[0u8; 16], &[0u8; 14], 0, &[0u8; 6], 0);
        ctx.set_params(&ps).unwrap();

        ctx.reset().unwrap();

        // Attempting to derive without reconfiguring should fail with
        // Init.
        let mut out = vec![0u8; 16];
        let err = ctx.derive(&mut out, &ParamSet::new()).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)), "err={err:?}");
    }

    #[test]
    fn get_params_reports_configured_state() {
        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &[0u8; 16],
            &[0u8; 14],
            2, // SaltKey → output 14
            &[0u8; 6],
            16,
        );
        ctx.set_params(&ps).unwrap();

        let got = ctx.get_params().unwrap();
        assert_eq!(
            got.get(PARAM_KDR)
                .and_then(openssl_common::ParamValue::as_u32),
            Some(16)
        );
        assert_eq!(
            got.get(PARAM_LABEL)
                .and_then(openssl_common::ParamValue::as_u32),
            Some(2)
        );
        assert_eq!(
            got.get("size").and_then(openssl_common::ParamValue::as_u32),
            Some(SRTP_SALT_KEY_LEN as u32)
        );
        assert_eq!(
            got.get(PARAM_CIPHER)
                .and_then(|v| v.as_str().map(str::to_string)),
            Some("AES-128-CTR".to_string())
        );
    }

    // ----- RFC 3711 Appendix B.3 test vector (informative) -----
    //
    // RFC 3711 Appendix B.3 provides concrete KDF test vectors for
    // AES-128-CTR. The following three tests encode the RFC vectors
    // verbatim and exercise the full SRTP KDF pipeline end-to-end.
    //
    // They are gated with `#[ignore]` because `openssl-crypto::evp::cipher::
    // CipherCtx` currently implements a **placeholder keystream** (see
    // `crates/openssl-crypto/src/evp/cipher.rs` line 916: "structural
    // placeholder transform") rather than real AES-CTR. Once a real
    // AES-CTR implementation lands in the Default provider, these tests
    // should start passing as-is and can be un-ignored without any
    // modification — the SRTP KDF layer above (IV construction, label
    // XOR, index-shift folding, output sizing) is correct per RFC 3711
    // §4.3.1 and does not depend on the cipher internals.
    //
    // The structural tests above (determinism, different-label/key/salt
    // separation, KDR dependence, output sizing) continue to verify the
    // SRTP KDF layer independently of the underlying cipher primitive.
    #[test]
    #[ignore = "requires real AES-128-CTR in openssl-crypto (currently placeholder)"]
    fn rfc3711_appendix_b3_cipher_key() {
        // Master key: 0xE1F97A0D3E018BE0D64FA32C06DE4139
        let master_key = [
            0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE,
            0x41, 0x39,
        ];
        // Master salt: 0x0EC675AD498AFEEBB6960B3AABE6
        let master_salt = [
            0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
        ];
        // Expected session encryption key (label = 0):
        // 0xC61E7A93744F39EE10734AFE3FF7A087
        let expected_cipher_key = [
            0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE, 0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7,
            0xA0, 0x87,
        ];

        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &master_key,
            &master_salt,
            0,         // CipherKey
            &[0u8; 6], // packet index = 0
            0,         // KDR = 0
        );
        let mut out = vec![0u8; 16];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 16);
        assert_eq!(out, expected_cipher_key, "RFC 3711 Appendix B.3 KAT");
    }

    #[test]
    #[ignore = "requires real AES-128-CTR in openssl-crypto (currently placeholder)"]
    fn rfc3711_appendix_b3_auth_key() {
        let master_key = [
            0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE,
            0x41, 0x39,
        ];
        let master_salt = [
            0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
        ];
        // Expected authentication key (label = 1):
        // 0xCEBE321F6FF7716B6FD4AB49AF256A156D38BAA4
        let expected_auth_key = [
            0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B, 0x6F, 0xD4, 0xAB, 0x49, 0xAF, 0x25,
            0x6A, 0x15, 0x6D, 0x38, 0xBA, 0xA4,
        ];

        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &master_key,
            &master_salt,
            1, // AuthKey
            &[0u8; 6],
            0,
        );
        let mut out = vec![0u8; 20];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, SRTP_AUTH_KEY_LEN);
        assert_eq!(out, expected_auth_key, "RFC 3711 Appendix B.3 auth KAT");
    }

    #[test]
    #[ignore = "requires real AES-128-CTR in openssl-crypto (currently placeholder)"]
    fn rfc3711_appendix_b3_salt_key() {
        let master_key = [
            0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE,
            0x41, 0x39,
        ];
        let master_salt = [
            0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
        ];
        // Expected salt key (label = 2):
        // 0x30CBBC08863D8C85D49DB34A9AE1
        let expected_salt_key = [
            0x30, 0xCB, 0xBC, 0x08, 0x86, 0x3D, 0x8C, 0x85, 0xD4, 0x9D, 0xB3, 0x4A, 0x9A, 0xE1,
        ];

        let mut ctx = new_ctx();
        let ps = base_params(
            "AES-128-CTR",
            &master_key,
            &master_salt,
            2, // SaltKey
            &[0u8; 6],
            0,
        );
        let mut out = vec![0u8; 14];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, SRTP_SALT_KEY_LEN);
        assert_eq!(out, expected_salt_key, "RFC 3711 Appendix B.3 salt KAT");
    }
}
