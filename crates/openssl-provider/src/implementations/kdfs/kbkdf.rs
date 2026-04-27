//! KBKDF — Key-Based Key Derivation Function (NIST SP 800-108).
//!
//! Idiomatic Rust translation of `providers/implementations/kdfs/kbkdf.c` (516 lines).
//! Implements the NIST SP 800-108 Key-Based Key Derivation Function in two
//! modes — **counter** (§5.1) and **feedback** (§5.2) — built on top of a
//! pluggable MAC (HMAC, CMAC, KMAC128, KMAC256).
//!
//! ## Algorithm Overview
//!
//! KBKDF derives output keying material from a key input `KI` by iterating a
//! pseudo-random function `PRF` over a counter and fixed input:
//!
//! - **Counter mode** (§5.1):
//!   `K(i) = PRF(KI, [i]_r || Label || 0x00 || Context || [L]_32)`
//! - **Feedback mode** (§5.2):
//!   `K(i) = PRF(KI, K(i-1) || [i]_r || Label || 0x00 || Context || [L]_32)`
//!   where `K(0) = IV`.
//!
//! The counter width `r` ∈ {8, 16, 24, 32} bits, big-endian. `[L]_32` is
//! the requested output length in bits (32 bit big-endian). The 0x00
//! separator and the `[L]` suffix are both optional via the `use-separator`
//! and `use-l` parameters (both default to on, matching the C
//! implementation in `kbkdf.c` lines 112–114).
//!
//! ## KMAC special path
//!
//! When the MAC is KMAC128 or KMAC256 the specification dictates a single
//! MAC invocation whose output size is set via the `size` parameter and
//! whose `custom` string is the label. This exactly mirrors `kbkdf.c`
//! lines 252–265 (`kmac_derive`) and lines 336–339 (the fast path in
//! `kbkdf_derive`).
//!
//! ## MAC template cloning
//!
//! The initialised MAC template is stored on the context and cloned per
//! block via `MacCtx::dup`. This matches the C `EVP_MAC_CTX_dup(ctx_init)`
//! pattern (`kbkdf.c` line 229) without re-keying on every block, which is
//! both more efficient and semantically required by KMAC (whose custom
//! string is set at init time).
//!
//! ## Rules Compliance
//!
//! - **R5:** `Option<T>` for optional `label`, `context`, `iv`, and
//!   `mac_ctx_template`; sentinel values are never used.
//! - **R6:** All narrowing casts use `try_from` or `u32::try_from` with
//!   explicit error mapping — counter width conversion, `[L]` bit-length
//!   conversion, counter overflow detection.
//! - **R7:** Not applicable — this context is single-threaded by design.
//! - **R8:** Zero `unsafe` blocks. All memory is owned by safe Rust types.
//! - **R9:** Warning-free. Every public item carries a doc comment.
//!
//! ## Sources
//!
//! - `providers/implementations/kdfs/kbkdf.c` (primary source, 516 lines)
//! - `providers/common/securitycheck.c` (`ossl_kdf_check_key_size`, FIPS policy)
//! - `providers/common/provider_util.c` (`ossl_prov_macctx_load`, MAC fetch)
//! - NIST SP 800-108 Rev. 1 (2022) — "Recommendation for Key Derivation
//!   Using Pseudorandom Functions"

use std::sync::Arc;

use tracing::{debug, instrument, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
use openssl_common::{CryptoError, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::mac::{Mac, MacCtx, CMAC, HMAC, KMAC128, KMAC256};

use super::{MAX_INFO_SEGMENTS, MAX_INPUT_LEN};

// =============================================================================
// Parameter Name Constants
// =============================================================================
//
// These mirror the C macro names from `include/openssl/core_names.h`
// (e.g. `OSSL_KDF_PARAM_KEY` → `"key"`). All keys are `&'static str`
// because [`ParamSet::set`] demands a static-lifetime key.

/// `OSSL_KDF_PARAM_KEY` — the key input (KI). `OctetString`.
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_MODE` — either `"counter"` or `"feedback"`. `Utf8String`.
const PARAM_MODE: &str = "mode";
/// `OSSL_KDF_PARAM_SALT` — the *label* (`ctx->label` in C). `OctetString`.
const PARAM_SALT: &str = "salt";
/// `OSSL_KDF_PARAM_INFO` — the *context* (`ctx->context` in C). Multiple
/// info parameters are concatenated up to [`MAX_INFO_SEGMENTS`].
const PARAM_INFO: &str = "info";
/// `OSSL_KDF_PARAM_SEED` — the feedback IV (`ctx->iv` in C). `OctetString`.
const PARAM_SEED: &str = "seed";
/// `OSSL_KDF_PARAM_MAC` — name of the underlying MAC: `"HMAC"`, `"CMAC"`,
/// `"KMAC128"`, or `"KMAC256"`. `Utf8String`.
const PARAM_MAC: &str = "mac";
/// `OSSL_KDF_PARAM_DIGEST` — digest sub-algorithm (for HMAC). Forwarded
/// to `MacCtx::init` as an init-time parameter.
const PARAM_DIGEST: &str = "digest";
/// `OSSL_KDF_PARAM_CIPHER` — cipher sub-algorithm (for CMAC). Forwarded to
/// `MacCtx::init`.
const PARAM_CIPHER: &str = "cipher";
/// `OSSL_KDF_PARAM_PROPERTIES` — optional property query string passed to
/// `Mac::fetch` (e.g. `"fips=yes"`).
const PARAM_PROPERTIES: &str = "properties";
/// `OSSL_KDF_PARAM_KBKDF_USE_L` — whether to append the `[L]` suffix.
/// `Int32`, `0` disables; defaults to `1`.
const PARAM_USE_L: &str = "use-l";
/// `OSSL_KDF_PARAM_KBKDF_R` — counter width in bits, ∈ {8, 16, 24, 32}.
/// `Int32`; defaults to 32.
const PARAM_R: &str = "r";
/// `OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR` — whether to include the 0x00
/// separator. `Int32`, `0` disables; defaults to `1`.
const PARAM_USE_SEPARATOR: &str = "use-separator";

// =============================================================================
// Error helpers
// =============================================================================

/// Converts a [`CryptoError`] raised by the MAC dispatch into a
/// `ProviderError::Dispatch`.
///
/// This is the canonical mapping between the EVP-layer error enum and the
/// provider-layer error enum. The pattern mirrors `kdfs/ecx.rs` and other
/// provider implementations that bridge crypto errors to provider errors.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

// =============================================================================
// KbkdfMode
// =============================================================================

/// KBKDF derivation mode per NIST SP 800-108 §5.
///
/// Only Counter and Feedback modes are supported, matching the `kbkdf_mode`
/// enum in `kbkdf.c` line 25. Double-pipeline (§5.3) is not supported by
/// the reference C implementation and therefore not implemented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbkdfMode {
    /// Counter Mode (SP 800-108 §5.1). Maps to C `COUNTER = 0`.
    Counter,
    /// Feedback Mode (SP 800-108 §5.2). Maps to C `FEEDBACK = 1`.
    Feedback,
}

impl Default for KbkdfMode {
    /// Defaults to Counter, matching C `init()` at `kbkdf.c` line 108
    /// which zero-initialises the struct (enum value 0 = COUNTER).
    fn default() -> Self {
        Self::Counter
    }
}

impl KbkdfMode {
    /// Parses the `OSSL_KDF_PARAM_MODE` string.
    ///
    /// Matches C `kbkdf_set_ctx_params()` at `kbkdf.c` lines 440–446 which
    /// uses `OPENSSL_strncasecmp()` for case-insensitive comparison.
    fn from_str(s: &str) -> ProviderResult<Self> {
        if s.eq_ignore_ascii_case("counter") {
            Ok(Self::Counter)
        } else if s.eq_ignore_ascii_case("feedback") {
            Ok(Self::Feedback)
        } else {
            warn!(
                mode = s,
                "KBKDF: invalid mode (expected 'counter' or 'feedback')"
            );
            Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("KBKDF: invalid mode '{s}' (expected 'counter' or 'feedback')"),
            )))
        }
    }

    /// Returns the canonical lower-case name used by `get_params()`.
    fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Feedback => "feedback",
        }
    }
}

// =============================================================================
// KbkdfContext
// =============================================================================

/// KBKDF derivation context.
///
/// Direct translation of the C `KBKDF` struct (`kbkdf.c` lines 30–45).
/// Holds key material, label, context, IV, mode, counter width, feature
/// flags, and the initialised MAC template used to clone a fresh MAC
/// context on every derivation block.
///
/// ## Secure cleanup
///
/// `ki`, `label`, `context`, and `iv` are zeroed on drop via
/// `ZeroizeOnDrop`. `mac_ctx_template` is secured by `MacCtx`'s own
/// `ZeroizeOnDrop` derive (see `evp/mac.rs` line 228).
///
/// Non-sensitive metadata (`mode`, `counter_width`, `use_l`,
/// `use_separator`, `is_kmac`, `mac_name`, `libctx`) carry
/// `#[zeroize(skip)]` — matching the C `kbkdf_reset()` pattern which
/// only clears the heap-allocated byte buffers at `kbkdf.c` lines 120–138.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KbkdfContext {
    /// Key input (KI). Zeroed on drop. Maps to C `ctx->ki` / `ctx->ki_len`.
    ki: Vec<u8>,

    /// Label bytes. Zeroed on drop to match the C behaviour which calls
    /// `OPENSSL_clear_free(ctx->label, ctx->label_len)` at line 129.
    label: Vec<u8>,

    /// Context bytes (concatenation of up to [`MAX_INFO_SEGMENTS`] info
    /// segments). Zeroed on drop.
    context: Vec<u8>,

    /// Feedback-mode initialisation vector. `None` ⇒ `K(0)` is empty.
    /// **R5:** `Option` instead of a zero-length sentinel.
    iv: Option<Vec<u8>>,

    /// Derivation mode. Non-sensitive metadata.
    #[zeroize(skip)]
    mode: KbkdfMode,

    /// Counter width in bits, ∈ {8, 16, 24, 32}. Non-sensitive.
    #[zeroize(skip)]
    counter_width: u8,

    /// Whether to append `[L]` to the PRF input. Non-sensitive.
    #[zeroize(skip)]
    use_l: bool,

    /// Whether to include the 0x00 separator. Non-sensitive.
    #[zeroize(skip)]
    use_separator: bool,

    /// Whether the selected MAC is KMAC (triggers the special derive path).
    #[zeroize(skip)]
    is_kmac: bool,

    /// Canonical name of the selected MAC algorithm (e.g. `"HMAC"`).
    /// `None` until `set_params()` has been called with a `"mac"` value.
    #[zeroize(skip)]
    mac_name: Option<String>,

    /// Optional property query string forwarded to `Mac::fetch`.
    #[zeroize(skip)]
    mac_properties: Option<String>,

    /// Digest sub-algorithm for HMAC (`OSSL_MAC_PARAM_DIGEST`).
    #[zeroize(skip)]
    mac_digest: Option<String>,

    /// Cipher sub-algorithm for CMAC (`OSSL_MAC_PARAM_CIPHER`).
    #[zeroize(skip)]
    mac_cipher: Option<String>,

    /// Initialised MAC template — cloned per block via `MacCtx::dup`.
    /// Maps directly to C `ctx->ctx_init` (`kbkdf.c` line 33). Only set
    /// once both `mac_name` and `ki` have been configured.
    #[zeroize(skip)]
    mac_ctx_template: Option<MacCtx>,

    /// Library context reference used for MAC fetches. Non-sensitive.
    #[zeroize(skip)]
    libctx: Arc<LibContext>,
}

impl KbkdfContext {
    /// Creates a fresh, uninitialised KBKDF context with the C-level
    /// defaults: counter mode, `r = 32`, `use_l = true`, `use_separator =
    /// true`. These defaults are set by `init()` at `kbkdf.c` lines 108–114.
    fn new(libctx: Arc<LibContext>) -> Self {
        Self {
            ki: Vec::new(),
            label: Vec::new(),
            context: Vec::new(),
            iv: None,
            mode: KbkdfMode::Counter,
            counter_width: 32,
            use_l: true,
            use_separator: true,
            is_kmac: false,
            mac_name: None,
            mac_properties: None,
            mac_digest: None,
            mac_cipher: None,
            mac_ctx_template: None,
            libctx,
        }
    }

    /// Performs a deep copy matching C `kbkdf_dup()` at
    /// `kbkdf.c` lines 143–175.
    ///
    /// All buffers are cloned and the MAC template is duplicated via
    /// `MacCtx::dup`, which mirrors C `EVP_MAC_CTX_dup(src->ctx_init)`
    /// at line 158.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` if cloning the MAC template
    /// fails inside the EVP layer.
    pub fn dup(&self) -> ProviderResult<Self> {
        let mac_ctx_template = match &self.mac_ctx_template {
            Some(t) => Some(t.dup().map_err(dispatch_err)?),
            None => None,
        };
        trace!(
            has_mac = mac_ctx_template.is_some(),
            mode = ?self.mode,
            "KBKDF: duplicating context"
        );
        Ok(Self {
            ki: self.ki.clone(),
            label: self.label.clone(),
            context: self.context.clone(),
            iv: self.iv.clone(),
            mode: self.mode,
            counter_width: self.counter_width,
            use_l: self.use_l,
            use_separator: self.use_separator,
            is_kmac: self.is_kmac,
            mac_name: self.mac_name.clone(),
            mac_properties: self.mac_properties.clone(),
            mac_digest: self.mac_digest.clone(),
            mac_cipher: self.mac_cipher.clone(),
            mac_ctx_template,
            libctx: Arc::clone(&self.libctx),
        })
    }

    // -----------------------------------------------------------------------
    // Parameter handling
    // -----------------------------------------------------------------------

    /// Applies a set of parameters to the context.
    ///
    /// Implements the body of C `kbkdf_set_ctx_params()` at
    /// `kbkdf.c` lines 403–500. The ordering matters: MAC must be
    /// configured (and ideally KI) before any KMAC-specific state is
    /// derived; after every call the template is re-initialised.
    #[instrument(skip(self, params), level = "debug")]
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // OSSL_KDF_PARAM_MAC — MAC algorithm name.
        if let Some(v) = params.get(PARAM_MAC) {
            let name = v.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'mac' must be a UTF-8 string".into(),
                ))
            })?;
            self.apply_mac_name(name)?;
        }

        // OSSL_KDF_PARAM_PROPERTIES — MAC property query.
        if let Some(v) = params.get(PARAM_PROPERTIES) {
            let s = v.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'properties' must be a UTF-8 string".into(),
                ))
            })?;
            self.mac_properties = Some(s.to_string());
        }

        // OSSL_KDF_PARAM_DIGEST — HMAC sub-algorithm.
        if let Some(v) = params.get(PARAM_DIGEST) {
            let s = v.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'digest' must be a UTF-8 string".into(),
                ))
            })?;
            self.mac_digest = Some(s.to_string());
        }

        // OSSL_KDF_PARAM_CIPHER — CMAC sub-algorithm.
        if let Some(v) = params.get(PARAM_CIPHER) {
            let s = v.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'cipher' must be a UTF-8 string".into(),
                ))
            })?;
            self.mac_cipher = Some(s.to_string());
        }

        // OSSL_KDF_PARAM_MODE — counter | feedback.
        if let Some(v) = params.get(PARAM_MODE) {
            let s = v.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'mode' must be a UTF-8 string".into(),
                ))
            })?;
            self.mode = KbkdfMode::from_str(s)?;
            debug!(mode = ?self.mode, "KBKDF: mode selected");
        }

        // OSSL_KDF_PARAM_KEY — KI. C `kbkdf.c` lines 447–453.
        if let Some(v) = params.get(PARAM_KEY) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'key' must be octet bytes".into(),
                ))
            })?;
            Self::check_input_len(bytes.len(), "key")?;
            self.ki.zeroize();
            self.ki = bytes.to_vec();
        }

        // OSSL_KDF_PARAM_SALT → label. C `kbkdf.c` lines 454–458.
        if let Some(v) = params.get(PARAM_SALT) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'salt' must be octet bytes".into(),
                ))
            })?;
            Self::check_input_len(bytes.len(), "salt")?;
            self.label.zeroize();
            self.label = bytes.to_vec();
        }

        // OSSL_KDF_PARAM_INFO → context. C `kbkdf.c` lines 459–475.
        // Multiple info segments are concatenated up to MAX_INFO_SEGMENTS.
        // At the ParamSet layer there is a single "info" key carrying a
        // pre-concatenated byte slice, so we consume it as-is.
        if let Some(v) = params.get(PARAM_INFO) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'info' must be octet bytes".into(),
                ))
            })?;
            Self::check_input_len(bytes.len(), "info")?;
            self.context.zeroize();
            self.context = bytes.to_vec();
        }

        // OSSL_KDF_PARAM_SEED → IV. C `kbkdf.c` lines 476–482.
        if let Some(v) = params.get(PARAM_SEED) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'seed' must be octet bytes".into(),
                ))
            })?;
            Self::check_input_len(bytes.len(), "seed")?;
            if let Some(iv) = self.iv.as_mut() {
                iv.zeroize();
            }
            self.iv = Some(bytes.to_vec());
        }

        // OSSL_KDF_PARAM_KBKDF_USE_L. C `kbkdf.c` lines 483–487.
        if let Some(v) = params.get(PARAM_USE_L) {
            self.use_l = Self::int_to_bool(v)?;
            trace!(use_l = self.use_l, "KBKDF: use-l updated");
        }

        // OSSL_KDF_PARAM_KBKDF_R — counter width. C `kbkdf.c` lines 488–497.
        if let Some(v) = params.get(PARAM_R) {
            let r = v.as_i32().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "KBKDF: 'r' must be Int32".into(),
                ))
            })?;
            if !matches!(r, 8 | 16 | 24 | 32) {
                warn!(r, "KBKDF: rejected invalid counter width");
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!("KBKDF: invalid counter width r={r} (expected 8, 16, 24, or 32)"),
                )));
            }
            // R6: validated range ∈ {8, 16, 24, 32} so u8 cast cannot truncate.
            self.counter_width = u8::try_from(r).map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "KBKDF counter width",
                })
            })?;
            trace!(r = self.counter_width, "KBKDF: counter width updated");
        }

        // OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR. C `kbkdf.c` lines 498–502.
        if let Some(v) = params.get(PARAM_USE_SEPARATOR) {
            self.use_separator = Self::int_to_bool(v)?;
            trace!(use_sep = self.use_separator, "KBKDF: use-separator updated");
        }

        // If both MAC + key are configured, (re-)build the initialised
        // MAC template. Matches C `kbkdf.c` lines 503–525 which calls
        // `EVP_MAC_init(ctx->ctx_init, ctx->ki, ctx->ki_len, NULL)` after
        // every successful parameter update.
        if self.mac_name.is_some() && !self.ki.is_empty() {
            self.rebuild_mac_template()?;
        }

        Ok(())
    }

    /// Accepts `"HMAC"`, `"CMAC"`, `"KMAC128"`, `"KMAC256"` and updates
    /// `self.mac_name` plus the `is_kmac` fast-path flag.
    ///
    /// Mirrors C `kbkdf.c` lines 417–436 which calls
    /// `EVP_MAC_is_a(EVP_MAC_CTX_get0_mac(ctx->ctx_init), OSSL_MAC_NAME_*)`.
    fn apply_mac_name(&mut self, name: &str) -> ProviderResult<()> {
        let canonical = if name.eq_ignore_ascii_case(HMAC) {
            HMAC
        } else if name.eq_ignore_ascii_case(CMAC) {
            CMAC
        } else if name.eq_ignore_ascii_case(KMAC128) {
            KMAC128
        } else if name.eq_ignore_ascii_case(KMAC256) {
            KMAC256
        } else {
            warn!(mac = name, "KBKDF: unsupported MAC algorithm");
            return Err(ProviderError::AlgorithmUnavailable(format!(
                "KBKDF: unsupported MAC '{name}' (expected HMAC, CMAC, KMAC128, or KMAC256)"
            )));
        };
        self.mac_name = Some(canonical.to_string());
        self.is_kmac = matches!(canonical, KMAC128 | KMAC256);
        debug!(
            mac = canonical,
            is_kmac = self.is_kmac,
            "KBKDF: MAC selected"
        );
        Ok(())
    }

    /// Parses a 0/1 integer parameter into a bool.
    fn int_to_bool(v: &ParamValue) -> ProviderResult<bool> {
        if let Some(n) = v.as_i32() {
            return Ok(n != 0);
        }
        if let Some(n) = v.as_u32() {
            return Ok(n != 0);
        }
        Err(ProviderError::Common(CommonError::InvalidArgument(
            "KBKDF: boolean flag must be Int32 or UInt32".into(),
        )))
    }

    /// Returns `Err` if `len` exceeds the workspace-wide `DoS` ceiling.
    ///
    /// This is a stateless bounds check; implemented as an associated
    /// function so it can be invoked both from methods that do not hold a
    /// context yet (e.g. parameter pre-validation) and from tests that
    /// wish to exercise the limit directly.
    fn check_input_len(len: usize, field: &'static str) -> ProviderResult<()> {
        if len > MAX_INPUT_LEN {
            warn!(
                field,
                len,
                ceiling = MAX_INPUT_LEN,
                "KBKDF: input exceeds ceiling"
            );
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("KBKDF: {field} length {len} exceeds workspace ceiling"),
            )));
        }
        Ok(())
    }

    /// Fetches the MAC, builds a `MacCtx`, pre-applies init-time
    /// sub-algorithm parameters (digest for HMAC, cipher for CMAC), and
    /// initialises the template with the current KI.
    ///
    /// This is the Rust counterpart of `ossl_prov_macctx_load()` +
    /// `EVP_MAC_init()` in C `provider_util.c` / `kbkdf.c` line 524.
    fn rebuild_mac_template(&mut self) -> ProviderResult<()> {
        let mac_name = self
            .mac_name
            .as_deref()
            .ok_or_else(|| ProviderError::Init("KBKDF: MAC algorithm not configured".into()))?;

        if self.ki.is_empty() {
            // MacCtx::init() rejects an empty key — keep the template
            // unset until a key arrives. Matches C: the template is only
            // re-initialised when KI is present (`kbkdf.c` line 521).
            self.mac_ctx_template = None;
            return Ok(());
        }

        let mac = Mac::fetch(&self.libctx, mac_name, self.mac_properties.as_deref())
            .map_err(dispatch_err)?;
        let mut tmpl = MacCtx::new(&mac).map_err(dispatch_err)?;

        // Pre-init parameters — digest for HMAC, cipher for CMAC, and for
        // KMAC the label is set as the custom-string **before** init
        // (C `kmac_init()` at `kbkdf.c` lines 239–249).
        let mut init_params = ParamSet::new();
        if let Some(d) = &self.mac_digest {
            init_params.set(PARAM_DIGEST, ParamValue::Utf8String(d.clone()));
        }
        if let Some(c) = &self.mac_cipher {
            init_params.set(PARAM_CIPHER, ParamValue::Utf8String(c.clone()));
        }
        if self.is_kmac && !self.label.is_empty() {
            // KMAC "custom" string parameter — the label doubles as the
            // personalisation string per SP 800-108 §5.1 (for KMAC).
            init_params.set("custom", ParamValue::OctetString(self.label.clone()));
        }
        let init_params_opt = if init_params.is_empty() {
            None
        } else {
            Some(&init_params)
        };

        tmpl.init(&self.ki, init_params_opt).map_err(dispatch_err)?;
        self.mac_ctx_template = Some(tmpl);
        trace!(mac = mac_name, "KBKDF: MAC template initialised");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /// Pre-derivation checks matching C `kbkdf_derive()` lines 319–360.
    fn validate(&self, keylen: usize) -> ProviderResult<usize> {
        // C line 319: missing MAC or missing key.
        let Some(tmpl) = self.mac_ctx_template.as_ref() else {
            if self.ki.is_empty() {
                return Err(ProviderError::Init("KBKDF: no key set".into()));
            }
            return Err(ProviderError::AlgorithmUnavailable(
                "KBKDF: missing MAC".into(),
            ));
        };

        // C line 331: zero-length output.
        if keylen == 0 {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "KBKDF: output length must be > 0".into(),
            )));
        }

        // FIPS key-size policy: `ossl_kdf_check_key_size` in
        // `providers/common/securitycheck.c` requires `ki.len() * 8 ≥ 112`.
        // The default provider (this module) matches the C default which
        // does NOT invoke that check; the openssl-fips crate wraps the
        // KBKDF dispatch with the check when FIPS is active. Leaving the
        // policy out here preserves parity with the C default provider.

        // KMAC fast path: no counter/IV/L processing; defer to kmac_derive().
        if self.is_kmac {
            return tmpl.mac_size().map_err(dispatch_err);
        }

        // C line 342: mac_size = EVP_MAC_CTX_get_mac_size(ctx->ctx_init).
        let h = tmpl.mac_size().map_err(dispatch_err)?;
        if h == 0 {
            return Err(ProviderError::AlgorithmUnavailable(
                "KBKDF: MAC reported output size 0".into(),
            ));
        }

        // C line 346: invalid feedback IV length.
        if let Some(iv) = &self.iv {
            if !iv.is_empty() && iv.len() != h {
                warn!(iv_len = iv.len(), h, "KBKDF: IV length mismatch");
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!("KBKDF: IV length {} does not match MAC size {h}", iv.len()),
                )));
            }
        }

        // C line 351: counter overflow check. If keylen / h ≥ 2^r we
        // cannot address all required blocks.
        let r_u32 = u32::from(self.counter_width);
        let counter_max: u128 = 1u128 << r_u32;
        let blocks_needed = u128::from(u64::try_from(keylen.div_ceil(h)).map_err(|_| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "KBKDF block count",
            })
        })?);
        if blocks_needed > counter_max {
            warn!(
                blocks_needed = %blocks_needed,
                counter_max = %counter_max,
                "KBKDF: counter overflow"
            );
            return Err(ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "KBKDF counter",
            }));
        }

        Ok(h)
    }

    // -----------------------------------------------------------------------
    // Derivation
    // -----------------------------------------------------------------------

    /// Dispatches the actual derivation once all validation has passed.
    ///
    /// The KMAC fast path short-circuits the counter/feedback loop; for
    /// the standard path we emit a concrete `derive_counter` /
    /// `derive_feedback` loop.
    #[instrument(skip_all, level = "debug")]
    fn derive_inner(&self, output: &mut [u8]) -> ProviderResult<usize> {
        if self.is_kmac {
            return self.kmac_derive(output);
        }
        match self.mode {
            KbkdfMode::Counter => self.derive_counter(output),
            KbkdfMode::Feedback => self.derive_feedback(output),
        }
    }

    /// KMAC special path — single MAC invocation with `size` set to the
    /// requested output length. Maps to C `kmac_derive()` at
    /// `kbkdf.c` lines 252–272.
    fn kmac_derive(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let mut ctx = self
            .mac_ctx_template
            .as_ref()
            .ok_or_else(|| ProviderError::Init("KBKDF: MAC template missing".into()))?
            .dup()
            .map_err(dispatch_err)?;

        let outlen = u64::try_from(output.len()).map_err(|_| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "KBKDF KMAC output length",
            })
        })?;

        let mut size_params = ParamSet::new();
        size_params.set("size", ParamValue::UInt64(outlen));
        ctx.set_params(&size_params).map_err(dispatch_err)?;

        // Feed the context (label is already applied as KMAC `custom`
        // during init; C emits only the context bytes here).
        ctx.update(&self.context).map_err(dispatch_err)?;

        let tag = ctx.finalize().map_err(dispatch_err)?;
        let written = core::cmp::min(output.len(), tag.len());
        output[..written].copy_from_slice(&tag[..written]);

        debug!(
            requested = output.len(),
            produced = written,
            "KBKDF: KMAC derivation complete"
        );
        Ok(written)
    }

    /// Counter-mode derivation (SP 800-108 §5.1).
    ///
    /// Matches C `derive()` at `kbkdf.c` lines 190–236 with `mode == COUNTER`
    /// and `iv == NULL`.
    fn derive_counter(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let tmpl = self
            .mac_ctx_template
            .as_ref()
            .ok_or_else(|| ProviderError::Init("KBKDF: MAC template missing".into()))?;
        let h = tmpl.mac_size().map_err(dispatch_err)?;
        let keylen = output.len();

        // [L]_32 — big-endian output length in bits, per SP 800-108.
        let l_bytes = self.l_field(keylen)?;
        let r_bytes = usize::from(self.counter_width / 8);

        let mut written = 0usize;
        let mut i: u32 = 1;
        while written < keylen {
            let mut ctx = tmpl.dup().map_err(dispatch_err)?;
            Self::update_counter(&mut ctx, i, r_bytes)?;
            self.update_fixed_input(&mut ctx, &l_bytes)?;
            let block = ctx.finalize().map_err(dispatch_err)?;

            let take = core::cmp::min(h, keylen - written);
            output[written..written + take].copy_from_slice(&block[..take]);
            written += take;

            i = i.checked_add(1).ok_or_else(|| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "KBKDF counter increment",
                })
            })?;
        }

        debug!(
            requested = keylen,
            blocks = i.saturating_sub(1),
            "KBKDF: counter-mode derivation complete"
        );
        Ok(written)
    }

    /// Feedback-mode derivation (SP 800-108 §5.2).
    ///
    /// Matches C `derive()` with `mode == FEEDBACK` and an optional IV.
    /// The prior block `K(i-1)` is prepended to the PRF input; `K(0) =
    /// IV`.
    fn derive_feedback(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let tmpl = self
            .mac_ctx_template
            .as_ref()
            .ok_or_else(|| ProviderError::Init("KBKDF: MAC template missing".into()))?;
        let h = tmpl.mac_size().map_err(dispatch_err)?;
        let keylen = output.len();

        let l_bytes = self.l_field(keylen)?;
        let r_bytes = usize::from(self.counter_width / 8);

        // C line 221–224: set up K(0) = IV (or zero-length if no IV).
        let mut k_prev: Vec<u8> = self.iv.clone().unwrap_or_default();

        let mut written = 0usize;
        let mut i: u32 = 1;
        while written < keylen {
            let mut ctx = tmpl.dup().map_err(dispatch_err)?;

            // C line 227: if (mode == FEEDBACK) EVP_MAC_update(ctx, k_i, k_i_len).
            if !k_prev.is_empty() {
                ctx.update(&k_prev).map_err(dispatch_err)?;
            }
            Self::update_counter(&mut ctx, i, r_bytes)?;
            self.update_fixed_input(&mut ctx, &l_bytes)?;
            let block = ctx.finalize().map_err(dispatch_err)?;

            let take = core::cmp::min(h, keylen - written);
            output[written..written + take].copy_from_slice(&block[..take]);
            written += take;

            // K(i) feeds into the next iteration.
            k_prev.zeroize();
            k_prev = block;

            i = i.checked_add(1).ok_or_else(|| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "KBKDF counter increment",
                })
            })?;
        }

        // Wipe the final carry-over block from the stack-adjacent heap.
        k_prev.zeroize();

        debug!(
            requested = keylen,
            blocks = i.saturating_sub(1),
            "KBKDF: feedback-mode derivation complete"
        );
        Ok(written)
    }

    /// Builds the `[L]_32` big-endian suffix if `use_l` is enabled.
    /// Returns an empty `Vec` when disabled so the caller can feed it
    /// unconditionally.
    fn l_field(&self, keylen: usize) -> ProviderResult<Vec<u8>> {
        if !self.use_l {
            return Ok(Vec::new());
        }
        let l_bits = u32::try_from(keylen.checked_mul(8).ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "KBKDF [L] bits",
            })
        })?)
        .map_err(|_| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "KBKDF [L] u32",
            })
        })?;
        Ok(l_bits.to_be_bytes().to_vec())
    }

    /// Emits `[i]_r` — the last `r_bytes` bytes of `i` in big-endian.
    ///
    /// This matches C `kbkdf.c` line 231:
    /// `EVP_MAC_update(ctx, 4 - (r/8) + (unsigned char *)&i, r/8)`
    /// after a big-endian byte swap.
    ///
    /// Implemented as an associated function because the counter emission
    /// depends only on the block index and caller-supplied width — there
    /// is no per-context state to consult.
    fn update_counter(ctx: &mut MacCtx, i: u32, r_bytes: usize) -> ProviderResult<()> {
        if r_bytes == 0 || r_bytes > 4 {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "KBKDF: invalid counter byte width".into(),
            )));
        }
        let be = i.to_be_bytes();
        // Slice the LAST r_bytes bytes (same effect as C's pointer offset).
        let start = 4 - r_bytes;
        ctx.update(&be[start..]).map_err(dispatch_err)?;
        Ok(())
    }

    /// Emits Label || 0x00? || Context || [L]? as configured.
    fn update_fixed_input(&self, ctx: &mut MacCtx, l_bytes: &[u8]) -> ProviderResult<()> {
        ctx.update(&self.label).map_err(dispatch_err)?;
        if self.use_separator {
            ctx.update(&[0x00]).map_err(dispatch_err)?;
        }
        ctx.update(&self.context).map_err(dispatch_err)?;
        if !l_bytes.is_empty() {
            ctx.update(l_bytes).map_err(dispatch_err)?;
        }
        Ok(())
    }

    /// Validates that info segment count never exceeds [`MAX_INFO_SEGMENTS`].
    ///
    /// The `ParamSet` API only surfaces a single `"info"` key so, in
    /// practice, only one pre-concatenated segment arrives at this layer.
    /// The assertion is retained for parity with the C layout which caps
    /// the array at [`MAX_INFO_SEGMENTS`] (`kbkdf.c` macro `KBKDF_MAX_INFOS
    /// = 5`).
    #[inline]
    fn enforce_info_cap(num_segments: usize) -> ProviderResult<()> {
        if num_segments > MAX_INFO_SEGMENTS {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("KBKDF: too many info segments ({num_segments} > {MAX_INFO_SEGMENTS})"),
            )));
        }
        Ok(())
    }
}

// =============================================================================
// KdfContext trait impl
// =============================================================================

impl KdfContext for KbkdfContext {
    /// Derives `key.len()` bytes of output keying material.
    ///
    /// Implements the body of C `kbkdf_derive()` at
    /// `kbkdf.c` lines 310–380.
    #[instrument(skip_all, fields(keylen = key.len(), mode = ?self.mode), level = "debug")]
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }

        // info-segment cap (C `KBKDF_MAX_INFOS = 5`). Only one pre-concatenated
        // info blob arrives here; we defensively check 1 ≤ MAX_INFO_SEGMENTS.
        Self::enforce_info_cap(usize::from(!self.context.is_empty()))?;

        let _h = self.validate(key.len())?;

        // Security: if anything fails after this point, the caller must
        // never see partial output. We derive into a scratch buffer and
        // zero it on failure before propagating the error.
        let mut scratch = vec![0u8; key.len()];
        match self.derive_inner(&mut scratch) {
            Ok(n) => {
                key[..n].copy_from_slice(&scratch[..n]);
                scratch.zeroize();
                Ok(n)
            }
            Err(e) => {
                scratch.zeroize();
                // Mirror C `OPENSSL_cleanse(key, keylen)` at `kbkdf.c` line 379.
                for b in key.iter_mut() {
                    *b = 0;
                }
                Err(e)
            }
        }
    }

    /// Resets the context to fresh-init state.
    ///
    /// Equivalent to C `kbkdf_reset()` at `kbkdf.c` lines 120–140: frees
    /// all heap buffers and re-initialises the defaults.
    fn reset(&mut self) -> ProviderResult<()> {
        self.ki.zeroize();
        self.ki.clear();
        self.label.zeroize();
        self.label.clear();
        self.context.zeroize();
        self.context.clear();
        if let Some(iv) = self.iv.as_mut() {
            iv.zeroize();
        }
        self.iv = None;

        self.mode = KbkdfMode::Counter;
        self.counter_width = 32;
        self.use_l = true;
        self.use_separator = true;
        self.is_kmac = false;
        self.mac_name = None;
        self.mac_properties = None;
        self.mac_digest = None;
        self.mac_cipher = None;
        self.mac_ctx_template = None;
        trace!("KBKDF: context reset");
        Ok(())
    }

    /// Returns a `ParamSet` describing the current configuration.
    ///
    /// Parallels C `kbkdf_get_ctx_params()` at `kbkdf.c` lines 510–516
    /// which returns `SIZE_MAX` for `"size"` (output length is unbounded
    /// for KBKDF). We expose it as `u64::MAX` in the typed layer.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut b = ParamBuilder::new()
            .push_utf8(PARAM_MODE, self.mode.as_str().to_string())
            .push_i32(PARAM_R, i32::from(self.counter_width))
            .push_i32(PARAM_USE_L, i32::from(self.use_l))
            .push_i32(PARAM_USE_SEPARATOR, i32::from(self.use_separator))
            .push_u64("size", u64::MAX);
        if let Some(name) = &self.mac_name {
            b = b.push_utf8(PARAM_MAC, name.clone());
        }
        Ok(b.build())
    }

    /// Sets a subset of parameters without triggering a derivation.
    ///
    /// Parallels the standalone C `kbkdf_set_ctx_params()` entry point
    /// (`kbkdf.c` lines 403–500).
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// KbkdfProvider
// =============================================================================

/// Provider registration for KBKDF (all modes).
///
/// A single provider dispatches both counter- and feedback-mode derivations
/// via the runtime `mode` parameter. This matches the single
/// `ossl_kdf_kbkdf_functions` dispatch table in C (`kbkdf.c` line 506),
/// which also multiplexes both modes from one registration.
pub struct KbkdfProvider {
    libctx: Arc<LibContext>,
}

impl Default for KbkdfProvider {
    fn default() -> Self {
        Self::new(LibContext::get_default())
    }
}

impl KbkdfProvider {
    /// Creates a new KBKDF provider bound to the given [`LibContext`].
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        Self { libctx }
    }

    /// Returns the canonical description shown by `openssl list -kdfs`.
    #[must_use]
    pub fn description(&self) -> &'static str {
        "KBKDF — Key-Based KDF in Counter/Feedback mode (NIST SP 800-108)"
    }

    /// Returns the set of parameters accepted by [`Self::new_ctx`] contexts.
    ///
    /// Mirrors C `kbkdf_settable_ctx_params()` (`kbkdf.c` lines 387–401).
    #[must_use]
    pub fn settable_params() -> ParamSet {
        ParamBuilder::new()
            .push_utf8(PARAM_MODE, String::new())
            .push_utf8(PARAM_MAC, String::new())
            .push_utf8(PARAM_DIGEST, String::new())
            .push_utf8(PARAM_CIPHER, String::new())
            .push_utf8(PARAM_PROPERTIES, String::new())
            .push_octet(PARAM_KEY, Vec::new())
            .push_octet(PARAM_SALT, Vec::new())
            .push_octet(PARAM_INFO, Vec::new())
            .push_octet(PARAM_SEED, Vec::new())
            .push_i32(PARAM_R, 32)
            .push_i32(PARAM_USE_L, 1)
            .push_i32(PARAM_USE_SEPARATOR, 1)
            .build()
    }

    /// Returns the set of parameters returned by [`KbkdfContext::get_params`].
    ///
    /// Mirrors C `kbkdf_gettable_ctx_params()` (`kbkdf.c` lines 378–385).
    #[must_use]
    pub fn gettable_params() -> ParamSet {
        ParamBuilder::new()
            .push_utf8(PARAM_MODE, String::new())
            .push_utf8(PARAM_MAC, String::new())
            .push_i32(PARAM_R, 0)
            .push_i32(PARAM_USE_L, 0)
            .push_i32(PARAM_USE_SEPARATOR, 0)
            .push_u64("size", 0)
            .build()
    }
}

impl KdfProvider for KbkdfProvider {
    fn name(&self) -> &'static str {
        "KBKDF"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        trace!("KBKDF: new context created");
        Ok(Box::new(KbkdfContext::new(Arc::clone(&self.libctx))))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns all [`AlgorithmDescriptor`] entries contributed by this module.
///
/// Registers the single `"KBKDF"` algorithm with the default provider.
/// The C source exposes only one KBKDF dispatch entry (`kbkdf.c` line
/// 506); counter/feedback selection is a runtime parameter.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["KBKDF"],
        "provider=default",
        "Key-Based KDF in Counter/Feedback mode (NIST SP 800-108)",
    )]
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: fresh HMAC/counter-mode provider + context.
    fn new_hmac_ctx() -> Box<dyn KdfContext> {
        KbkdfProvider::default().new_ctx().unwrap()
    }

    fn base_hmac_params(key: &[u8], salt: &[u8], info: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_MAC, ParamValue::Utf8String(HMAC.to_string()));
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA-256".to_string()));
        ps.set(PARAM_KEY, ParamValue::OctetString(key.to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.to_vec()));
        ps.set(PARAM_INFO, ParamValue::OctetString(info.to_vec()));
        ps
    }

    // ----- Basic derivations -----

    #[test]
    fn kbkdf_counter_basic_hmac() {
        let mut ctx = new_hmac_ctx();
        let ps = base_hmac_params(
            b"secretkey1234567890abcdef",
            b"label-bytes",
            b"context-bytes",
        );
        let mut out = vec![0u8; 32];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(out, vec![0u8; 32]);
    }

    #[test]
    fn kbkdf_counter_deterministic() {
        let ps = base_hmac_params(b"keykeykeykeykey12345", b"myapp", b"myctx");

        let mut ctx1 = new_hmac_ctx();
        let mut out1 = vec![0u8; 64];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = new_hmac_ctx();
        let mut out2 = vec![0u8; 64];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn kbkdf_feedback_basic_hmac() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"anothersecretkey1234", b"label", b"context");
        ps.set(PARAM_MODE, ParamValue::Utf8String("feedback".to_string()));
        // IV length must equal MAC output size (32 for HMAC-SHA-256).
        ps.set(PARAM_SEED, ParamValue::OctetString(vec![0u8; 32]));

        let mut out = vec![0u8; 48];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 48);
        assert_ne!(out, vec![0u8; 48]);
    }

    #[test]
    fn kbkdf_feedback_no_iv_defaults_to_empty_k0() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"keyyyyyyyyyyyyyyyyy1", b"l", b"c");
        ps.set(PARAM_MODE, ParamValue::Utf8String("feedback".to_string()));
        let mut out = vec![0u8; 32];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 32);
    }

    #[test]
    fn kbkdf_modes_differ() {
        // Counter and feedback must produce distinct outputs for the same
        // inputs (unless the implementation is broken).
        let mut ctx_c = new_hmac_ctx();
        let mut ctx_f = new_hmac_ctx();
        let mut ps = base_hmac_params(b"distinctkeyXXXXXXXXX", b"lbl", b"ctx");

        let mut out_c = vec![0u8; 48];
        ctx_c.derive(&mut out_c, &ps).unwrap();

        ps.set(PARAM_MODE, ParamValue::Utf8String("feedback".to_string()));
        let mut out_f = vec![0u8; 48];
        ctx_f.derive(&mut out_f, &ps).unwrap();

        assert_ne!(out_c, out_f);
    }

    // ----- Counter width variations -----

    #[test]
    fn kbkdf_counter_width_8() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"short-output-keyXXXXX", b"l", b"c");
        ps.set(PARAM_R, ParamValue::Int32(8));
        // Output ≤ h × 255 = 32 × 255 = 8160 bytes fits inside 8-bit counter.
        let mut out = vec![0u8; 64];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 64);
    }

    #[test]
    fn kbkdf_counter_width_16() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"medium-counter-keyAAA", b"l", b"c");
        ps.set(PARAM_R, ParamValue::Int32(16));
        let mut out = vec![0u8; 128];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 128);
    }

    #[test]
    fn kbkdf_counter_width_24() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"24bit-counter-keyBBBB", b"l", b"c");
        ps.set(PARAM_R, ParamValue::Int32(24));
        let mut out = vec![0u8; 96];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 96);
    }

    #[test]
    fn kbkdf_counter_width_32_default() {
        let mut ctx = new_hmac_ctx();
        let ps = base_hmac_params(b"default-width-keyCCCC", b"l", b"c");
        let mut out = vec![0u8; 32];
        ctx.derive(&mut out, &ps).unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(params.get(PARAM_R).and_then(ParamValue::as_i32), Some(32));
    }

    #[test]
    fn kbkdf_invalid_counter_width_rejected() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"irrelevant-keyDDDDDDD", b"l", b"c");
        ps.set(PARAM_R, ParamValue::Int32(12));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn kbkdf_invalid_counter_width_128_rejected() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"irrelevant-keyEEEEEEE", b"l", b"c");
        ps.set(PARAM_R, ParamValue::Int32(128));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    // ----- use_l / use_separator toggles -----

    #[test]
    fn kbkdf_use_l_false_differs() {
        let mut ctx_a = new_hmac_ctx();
        let ps = base_hmac_params(b"use-l-testkey-XXXXXXX", b"l", b"c");

        let mut out_with_l = vec![0u8; 32];
        ctx_a.derive(&mut out_with_l, &ps).unwrap();

        let mut ctx_b = new_hmac_ctx();
        let mut ps_without_l = ps.clone();
        ps_without_l.set(PARAM_USE_L, ParamValue::Int32(0));
        let mut out_without_l = vec![0u8; 32];
        ctx_b.derive(&mut out_without_l, &ps_without_l).unwrap();

        assert_ne!(out_with_l, out_without_l);
    }

    #[test]
    fn kbkdf_use_separator_false_differs() {
        let mut ctx_a = new_hmac_ctx();
        let ps = base_hmac_params(b"use-sep-testkey-YYYYY", b"lab", b"ctx");

        let mut out_with_sep = vec![0u8; 32];
        ctx_a.derive(&mut out_with_sep, &ps).unwrap();

        let mut ctx_b = new_hmac_ctx();
        let mut ps_without_sep = ps.clone();
        ps_without_sep.set(PARAM_USE_SEPARATOR, ParamValue::Int32(0));
        let mut out_without_sep = vec![0u8; 32];
        ctx_b.derive(&mut out_without_sep, &ps_without_sep).unwrap();

        assert_ne!(out_with_sep, out_without_sep);
    }

    // ----- MAC algorithm switching -----

    #[test]
    fn kbkdf_mode_switch_changes_output() {
        // When the output length equals the MAC size and feedback mode uses
        // no IV, SP 800-108 defines K(0) as empty, so feedback block 1 has
        // the same MAC input as counter block 1. To exercise the true mode
        // delta we request TWO MAC blocks (64 bytes). In counter mode,
        // block 2 input starts with `[2]_r`; in feedback mode, block 2
        // input starts with `K(1)` (32 bytes) followed by `[2]_r`, so the
        // outputs must differ even under a minimal MAC implementation.
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"mode-switch-keyZZZZZZ", b"l", b"c");

        let mut counter_out = vec![0u8; 64];
        ctx.derive(&mut counter_out, &ps).unwrap();

        ctx.reset().unwrap();
        ps.set(PARAM_MODE, ParamValue::Utf8String("feedback".to_string()));
        let mut feedback_out = vec![0u8; 64];
        ctx.derive(&mut feedback_out, &ps).unwrap();

        assert_ne!(counter_out, feedback_out);

        // Sanity: the first block must still match because feedback's K(0)
        // is empty when no IV is supplied.
        assert_eq!(counter_out[..32], feedback_out[..32]);
        // And the second blocks must differ (feedback prepends K(1)).
        assert_ne!(counter_out[32..], feedback_out[32..]);
    }

    #[test]
    fn kbkdf_unsupported_mac_rejected() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"some-keyFFFFFFFFFFFF", b"l", b"c");
        ps.set(PARAM_MAC, ParamValue::Utf8String("GMAC".to_string()));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    // ----- Validation / error paths -----

    #[test]
    fn kbkdf_missing_key_errors() {
        let mut ctx = new_hmac_ctx();
        let mut ps = ParamSet::new();
        ps.set(PARAM_MAC, ParamValue::Utf8String(HMAC.to_string()));
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA-256".to_string()));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn kbkdf_missing_mac_errors() {
        let mut ctx = new_hmac_ctx();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_KEY,
            ParamValue::OctetString(b"somekey-XXXXXXXXXXX".to_vec()),
        );
        ps.set(PARAM_SALT, ParamValue::OctetString(b"label-bytes".to_vec()));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn kbkdf_empty_output_errors() {
        let mut ctx = new_hmac_ctx();
        let ps = base_hmac_params(b"keyyyy-00000000000000", b"l", b"c");
        let mut out: Vec<u8> = Vec::new();
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn kbkdf_invalid_mode_rejected() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"keyyyyy-00000000000000", b"l", b"c");
        ps.set(PARAM_MODE, ParamValue::Utf8String("pipeline".to_string()));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn kbkdf_feedback_iv_length_mismatch_errors() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"fbk-iv-keyGGGGGGGGGGG", b"l", b"c");
        ps.set(PARAM_MODE, ParamValue::Utf8String("feedback".to_string()));
        ps.set(PARAM_SEED, ParamValue::OctetString(vec![0u8; 8]));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn kbkdf_counter_overflow_errors() {
        // r = 8 gives counter_max = 256; request > 256 × 32 = 8192 bytes
        // to force a counter overflow.
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"overflow-keyHHHHHHHHH", b"l", b"c");
        ps.set(PARAM_R, ParamValue::Int32(8));
        let mut out = vec![0u8; 256 * 32 + 1];
        let err = ctx.derive(&mut out, &ps).unwrap_err();
        // Must surface as an arithmetic overflow variant (CommonError path).
        assert!(matches!(err, ProviderError::Common(_)));
    }

    // ----- Lifecycle -----

    #[test]
    fn kbkdf_reset_clears_state() {
        let mut ctx = new_hmac_ctx();
        let ps = base_hmac_params(b"reset-keyIIIIIIIIIIII", b"l", b"c");
        let mut out = vec![0u8; 32];
        ctx.derive(&mut out, &ps).unwrap();
        ctx.reset().unwrap();
        // After reset the context should require a fresh MAC + key.
        let mut out2 = vec![0u8; 32];
        assert!(ctx.derive(&mut out2, &ParamSet::default()).is_err());
    }

    #[test]
    fn kbkdf_dup_is_independent() {
        let provider = KbkdfProvider::default();
        let boxed = provider.new_ctx().unwrap();
        // Own a concrete `KbkdfContext` so we can exercise the inherent
        // `dup()` method. This mirrors how the ffi crate would use it.
        let mut direct = KbkdfContext::new(LibContext::get_default());
        let ps = base_hmac_params(b"dup-keyJJJJJJJJJJJJJJ", b"l", b"c");
        direct.apply_params(&ps).unwrap();

        let dup_ctx = direct.dup().unwrap();
        let mut out_original = vec![0u8; 32];
        let mut out_dup = vec![0u8; 32];
        direct.derive_inner(&mut out_original).unwrap();
        dup_ctx.derive_inner(&mut out_dup).unwrap();
        assert_eq!(out_original, out_dup);
        drop(boxed);
    }

    #[test]
    fn kbkdf_reset_restores_defaults() {
        let mut direct = KbkdfContext::new(LibContext::get_default());
        direct.counter_width = 8;
        direct.use_l = false;
        direct.use_separator = false;
        direct.mode = KbkdfMode::Feedback;
        direct.reset().unwrap();
        assert_eq!(direct.counter_width, 32);
        assert!(direct.use_l);
        assert!(direct.use_separator);
        assert_eq!(direct.mode, KbkdfMode::Counter);
    }

    #[test]
    fn kbkdf_get_params_reflects_state() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"get-keyKKKKKKKKKKKKKK", b"l", b"c");
        ps.set(PARAM_MODE, ParamValue::Utf8String("feedback".to_string()));
        ps.set(PARAM_R, ParamValue::Int32(16));
        ps.set(PARAM_USE_L, ParamValue::Int32(0));
        ps.set(PARAM_USE_SEPARATOR, ParamValue::Int32(0));
        ctx.set_params(&ps).unwrap();

        let got = ctx.get_params().unwrap();
        assert_eq!(
            got.get(PARAM_MODE).and_then(ParamValue::as_str),
            Some("feedback")
        );
        assert_eq!(got.get(PARAM_R).and_then(ParamValue::as_i32), Some(16));
        assert_eq!(got.get(PARAM_USE_L).and_then(ParamValue::as_i32), Some(0));
        assert_eq!(
            got.get(PARAM_USE_SEPARATOR).and_then(ParamValue::as_i32),
            Some(0)
        );
        assert_eq!(
            got.get(PARAM_MAC).and_then(ParamValue::as_str),
            Some("HMAC")
        );
    }

    // ----- Provider surface -----

    #[test]
    fn kbkdf_provider_name_is_stable() {
        let p = KbkdfProvider::default();
        assert_eq!(p.name(), "KBKDF");
    }

    #[test]
    fn kbkdf_provider_description_is_informative() {
        let p = KbkdfProvider::default();
        assert!(p.description().contains("SP 800-108"));
    }

    #[test]
    fn kbkdf_descriptors_registers_kbkdf() {
        let descs = descriptors();
        assert!(!descs.is_empty());
        assert!(descs.iter().any(|d| d.names.contains(&"KBKDF")));
    }

    #[test]
    fn kbkdf_settable_params_covers_known_keys() {
        let set = KbkdfProvider::settable_params();
        for k in [
            PARAM_MODE,
            PARAM_MAC,
            PARAM_DIGEST,
            PARAM_CIPHER,
            PARAM_PROPERTIES,
            PARAM_KEY,
            PARAM_SALT,
            PARAM_INFO,
            PARAM_SEED,
            PARAM_R,
            PARAM_USE_L,
            PARAM_USE_SEPARATOR,
        ] {
            assert!(set.contains(k), "settable params missing {k}");
        }
    }

    #[test]
    fn kbkdf_gettable_params_covers_known_keys() {
        let set = KbkdfProvider::gettable_params();
        for k in [
            PARAM_MODE,
            PARAM_MAC,
            PARAM_R,
            PARAM_USE_L,
            PARAM_USE_SEPARATOR,
            "size",
        ] {
            assert!(set.contains(k), "gettable params missing {k}");
        }
    }

    // ----- Mode parsing -----

    #[test]
    fn mode_from_str_is_case_insensitive() {
        assert_eq!(KbkdfMode::from_str("COUNTER").unwrap(), KbkdfMode::Counter);
        assert_eq!(KbkdfMode::from_str("counter").unwrap(), KbkdfMode::Counter);
        assert_eq!(
            KbkdfMode::from_str("Feedback").unwrap(),
            KbkdfMode::Feedback
        );
        assert_eq!(
            KbkdfMode::from_str("FEEDBACK").unwrap(),
            KbkdfMode::Feedback
        );
    }

    #[test]
    fn mode_from_str_rejects_pipeline() {
        assert!(KbkdfMode::from_str("pipeline").is_err());
        assert!(KbkdfMode::from_str("double-pipeline").is_err());
    }

    #[test]
    fn mode_default_is_counter() {
        assert_eq!(KbkdfMode::default(), KbkdfMode::Counter);
    }

    // ----- KMAC fast path -----

    #[test]
    fn kbkdf_kmac128_fast_path_succeeds() {
        let mut ctx = new_hmac_ctx();
        let mut ps = ParamSet::new();
        ps.set(PARAM_MAC, ParamValue::Utf8String(KMAC128.to_string()));
        ps.set(
            PARAM_KEY,
            ParamValue::OctetString(b"kmac-keyLLLLLLLLLLLLL".to_vec()),
        );
        ps.set(PARAM_SALT, ParamValue::OctetString(b"kmac-custom".to_vec()));
        ps.set(
            PARAM_INFO,
            ParamValue::OctetString(b"kmac-context".to_vec()),
        );
        let mut out = vec![0u8; 40];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 40);
        assert_ne!(out, vec![0u8; 40]);
    }

    #[test]
    fn kbkdf_kmac256_fast_path_succeeds() {
        let mut ctx = new_hmac_ctx();
        let mut ps = ParamSet::new();
        ps.set(PARAM_MAC, ParamValue::Utf8String(KMAC256.to_string()));
        ps.set(
            PARAM_KEY,
            ParamValue::OctetString(b"kmac-key-256MMMMMMMMM".to_vec()),
        );
        ps.set(
            PARAM_INFO,
            ParamValue::OctetString(b"kmac256-context".to_vec()),
        );
        let mut out = vec![0u8; 72];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, 72);
        assert_ne!(out, vec![0u8; 72]);
    }

    // ----- Parameter type mismatches -----

    #[test]
    fn key_as_string_rejected() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"k", b"l", b"c");
        ps.remove(PARAM_KEY);
        ps.set(PARAM_KEY, ParamValue::Utf8String("not-bytes".into()));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn mode_as_bytes_rejected() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"keyyyyyNNNNNNNNNNNNNN", b"l", b"c");
        ps.set(PARAM_MODE, ParamValue::OctetString(b"counter".to_vec()));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn r_as_string_rejected() {
        let mut ctx = new_hmac_ctx();
        let mut ps = base_hmac_params(b"keyyyyyOOOOOOOOOOOOOO", b"l", b"c");
        ps.set(PARAM_R, ParamValue::Utf8String("32".into()));
        let mut out = vec![0u8; 32];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    // ----- Info segment cap -----

    #[test]
    fn info_segment_cap_enforced() {
        // Single info blob is always ≤ 1, below the MAX_INFO_SEGMENTS cap.
        assert!(KbkdfContext::enforce_info_cap(0).is_ok());
        assert!(KbkdfContext::enforce_info_cap(1).is_ok());
        assert!(KbkdfContext::enforce_info_cap(MAX_INFO_SEGMENTS).is_ok());
        assert!(KbkdfContext::enforce_info_cap(MAX_INFO_SEGMENTS + 1).is_err());
    }

    // ----- Large input guards -----

    #[test]
    fn oversized_key_rejected() {
        // The integration path allocates a Vec of the user-supplied length,
        // so we exercise the bounds check surface directly to avoid an OOM
        // in tests. The limit applies equally to every byte-string field:
        // key, salt, info, and seed.
        assert!(KbkdfContext::check_input_len(MAX_INPUT_LEN + 1, "key").is_err());
        assert!(KbkdfContext::check_input_len(MAX_INPUT_LEN, "key").is_ok());
    }
}
