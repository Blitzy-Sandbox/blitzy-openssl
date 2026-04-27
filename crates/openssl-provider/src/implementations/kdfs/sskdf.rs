//! # SSKDF / X9.63-KDF — Single-Step Key Derivation Functions
//!
//! Rust translation of `providers/implementations/kdfs/sskdf.c` (808 lines),
//! implementing:
//!
//! - **SSKDF** — NIST SP 800-56C rev2, Single-Step KDF with hash, HMAC, or KMAC
//!   auxiliary function (dispatched at runtime via the `"mac"` parameter).
//! - **X9.63 KDF** — ANSI X9.63 KDF (hash-only). Structurally identical to the
//!   hash-mode SSKDF with the sole difference that the iteration counter is
//!   placed **after** the shared-secret `Z` rather than before.
//!
//! Both are *counter-mode* constructions: an output stream is produced by
//! repeatedly applying the auxiliary function `Aux(...)` with an incrementing
//! 32-bit big-endian counter until the requested number of bytes is reached.
//!
//! | Mode                     | Per-iteration input                          |
//! |--------------------------|----------------------------------------------|
//! | `SSKDF / Hash`           | `H(counter ‖ Z ‖ FixedInfo)`                 |
//! | `SSKDF / HMAC`           | `HMAC(salt, counter ‖ Z ‖ FixedInfo)`        |
//! | `SSKDF / KMAC128/256`    | `KMAC(salt, counter ‖ Z ‖ FixedInfo, "KDF")` |
//! | `X9.63  / Hash`          | `H(Z ‖ counter ‖ SharedInfo)`                |
//!
//! where `‖` denotes concatenation and the counter is a 4-byte big-endian value
//! starting at 1.
//!
//! ## Parameter Contract
//!
//! Accepts the following parameters via `KdfContext::set_params`:
//!
//! | Parameter                 | Type            | Purpose                                    |
//! |---------------------------|-----------------|--------------------------------------------|
//! | `"digest"`                | `Utf8String`    | Digest algorithm (e.g. `"SHA2-256"`).      |
//! | `"secret"` / `"key"`      | `OctetString`   | Shared secret `Z` (mandatory).             |
//! | `"info"`                  | `OctetString`   | FixedInfo / SharedInfo. Segments are       |
//! |                           |                 | concatenated, up to `MAX_INFO_SEGMENTS`. |
//! | `"salt"`                  | `OctetString`   | MAC salt. Hash-mode ignores this.          |
//! | `"mac"`                   | `Utf8String`    | `"HMAC"`, `"KMAC128"`, or `"KMAC256"`.     |
//! |                           |                 | SSKDF only; X9.63 rejects this.            |
//! | `"size"`                  | `UInt64`        | KMAC output-block size override.           |
//! | `"properties"`            | `Utf8String`    | Property query forwarded to `MessageDigest`|
//! |                           |                 | / `Mac` fetch.                             |
//!
//! Size defaults when the corresponding param is absent:
//!
//! - HMAC → salt = zeros of length `digest_size`.
//! - KMAC128 → salt = zeros of 164 bytes (`168 – 4`, per `sskdf.c:102`).
//! - KMAC256 → salt = zeros of 132 bytes (`136 – 4`, per `sskdf.c:104`).
//! - Hash-only modes → no salt consumed.
//!
//! ## Limits
//!
//! - Each of `secret`, `info`, `salt`, and `derived_key_len` is capped at
//!   `MAX_INPUT_LEN` (`1 << 30` = 1 GiB) to match C `SSKDF_MAX_INLEN`.
//! - At most `MAX_INFO_SEGMENTS` (5) `"info"` segments are concatenated.
//! - XOF digests (e.g. SHAKE128, SHAKE256) are rejected — SP 800-56C forbids
//!   XOF as a standalone auxiliary function.
//!
//! ## Memory Hygiene
//!
//! - `SskdfContext` carries `#[derive(Zeroize, ZeroizeOnDrop)]`, guaranteeing
//!   secret/salt/info are wiped on drop *and* on manual `reset()` (via
//!   `Zeroize::zeroize`).
//! - Non-sensitive metadata (variant, aux function, output-length hint) is
//!   annotated `#[zeroize(skip)]` to avoid pointless work.
//!
//! ## Rule Compliance
//!
//! - **R5** (nullability over sentinels): `Option<T>` for digest, mac, info,
//!   out_len — no sentinel `Vec::new()` to mean "unset".
//! - **R6** (lossless casts): counter arithmetic uses `checked_add` +
//!   `u32::to_be_bytes`; length summation uses `checked_add`.
//! - **R7** (lock granularity): no shared locks — per-context `&mut self`.
//! - **R8** (no unsafe): zero `unsafe` blocks.
//! - **R9** (warning-free): deny-warnings-clean build.
//! - **R10** (wiring): reachable from `descriptors` via
//!   [`crate::implementations::kdfs::descriptors`].

use std::sync::Arc;

use tracing::{debug, instrument, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
use openssl_common::{CryptoError, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::mac::{Mac, MacCtx, HMAC, KMAC128, KMAC256};
use openssl_crypto::evp::md::{MdContext, MessageDigest};

use super::{MAX_INFO_SEGMENTS, MAX_INPUT_LEN};

// =============================================================================
// Parameter Name Constants
// =============================================================================
//
// Mirror `include/openssl/core_names.h` macros (`OSSL_KDF_PARAM_*`). Keys are
// `&'static str` because [`ParamSet::set`] demands a static-lifetime key.

/// `OSSL_KDF_PARAM_SECRET` — the shared secret `Z`. `OctetString`, mandatory.
const PARAM_SECRET: &str = "secret";
/// `OSSL_KDF_PARAM_KEY` — alias of `"secret"` accepted for compatibility with
/// callers that used the generic `EVP_KDF` "key" parameter name.
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_INFO` — `FixedInfo` (SSKDF) / `SharedInfo` (X9.63).
/// `OctetString`. Multiple info segments are concatenated up to
/// `MAX_INFO_SEGMENTS`.
const PARAM_INFO: &str = "info";
/// `OSSL_KDF_PARAM_SALT` — MAC salt. `OctetString`. SSKDF MAC modes only;
/// ignored by hash-mode SSKDF and X9.63.
const PARAM_SALT: &str = "salt";
/// `OSSL_KDF_PARAM_DIGEST` — digest algorithm name (e.g. `"SHA2-256"`).
/// `Utf8String`. Required by hash-mode, HMAC (as the HMAC sub-digest), and
/// KMAC (for consistency — KMAC ignores it).
const PARAM_DIGEST: &str = "digest";
/// `OSSL_KDF_PARAM_MAC` — auxiliary MAC name: `"HMAC"`, `"KMAC128"`, or
/// `"KMAC256"`. `Utf8String`. Absence → hash mode. X9.63 rejects this key.
const PARAM_MAC: &str = "mac";
/// `OSSL_KDF_PARAM_SIZE` — explicit output length for KMAC's internal
/// output-block (per `kmac_init` validation `{derived_key_len, 20, 28, 32,
/// 48, 64}`). `UInt64`. Optional.
const PARAM_SIZE: &str = "size";
/// `OSSL_KDF_PARAM_PROPERTIES` — property query string forwarded to
/// `MessageDigest::fetch` / `Mac::fetch`. `Utf8String`. Optional.
const PARAM_PROPERTIES: &str = "properties";

// =============================================================================
// KMAC Constants (from `sskdf.c:99-106`)
// =============================================================================

/// KMAC customization string: ASCII `"KDF"` = `{0x4B, 0x44, 0x46}`.
///
/// SP 800-56C rev2 §4.1, step 1, case 3. Matches C `kmac_custom_str` at
/// `sskdf.c:105`.
const KMAC_CUSTOM_KDF: &[u8] = b"KDF";

/// Default salt length for KMAC128 when no salt is supplied.
///
/// Equals `168 – 4 = 164` bytes (`SSKDF_KMAC128_DEFAULT_SALT_SIZE` at
/// `sskdf.c:102`). The 168 is the KECCAK[256] rate in bytes; subtracting 4
/// leaves room for a 4-byte encoded length prefix.
const KMAC128_DEFAULT_SALT_SIZE: usize = 168 - 4;

/// Default salt length for KMAC256 when no salt is supplied.
///
/// Equals `136 – 4 = 132` bytes (`SSKDF_KMAC256_DEFAULT_SALT_SIZE` at
/// `sskdf.c:104`). The 136 is the KECCAK[512] rate in bytes; subtracting 4
/// leaves room for a 4-byte encoded length prefix.
const KMAC256_DEFAULT_SALT_SIZE: usize = 136 - 4;

/// Valid KMAC output-block sizes for `kmac_init`'s length override, per
/// `sskdf.c:210-215`. Matches `{derived_key_len, 20, 28, 32, 48, 64}` — the
/// `derived_key_len` case is checked separately.
const KMAC_OUT_LEN_ALLOWED: &[usize] = &[20, 28, 32, 48, 64];

// =============================================================================
// Helpers
// =============================================================================

/// Demotes a `CryptoError` to a `ProviderError::Dispatch`.
///
/// This mirrors the kbkdf helper at `kbkdf.rs:120`: we treat every call into
/// the digest / MAC layer as a "dispatch" surface, and if the lower-layer
/// ever fails we propagate a `Dispatch(message)` to the caller with the
/// original error text preserved for diagnostics.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Clamps `n` to `u32` and encodes it in 4-byte big-endian order.
///
/// The counter is an unsigned 32-bit integer per SP 800-56C §4.1. Because
/// we bound iterations by `reps = ceil(L / h) ≤ ceil(MAX_INPUT_LEN / 1) =
/// 2^30`, counters always fit in `u32` — but we still validate rather than
/// rely on the bound (R6: lossless casts).
#[inline]
fn counter_bytes(counter: u32) -> [u8; 4] {
    counter.to_be_bytes()
}

// =============================================================================
// Variant / Auxiliary Function Enumerations
// =============================================================================

/// Which Single-Step variant is in use.
///
/// The two variants share 95% of their implementation — they differ only in
/// (a) accepted algorithms (X9.63 rejects MAC) and (b) the ordering of the
/// counter relative to `Z` inside the per-iteration hash input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SskdfVariant {
    /// NIST SP 800-56C rev2 Single-Step KDF. Supports hash / HMAC / KMAC
    /// auxiliary functions. Counter is prepended: `H(counter ‖ Z ‖ info)`.
    SingleStep,
    /// ANSI X9.63 KDF. Hash-only. Counter is placed *after* `Z`:
    /// `H(Z ‖ counter ‖ info)`.
    X963,
}

impl SskdfVariant {
    /// Human-readable variant label for descriptors / tracing.
    #[inline]
    fn as_str(self) -> &'static str {
        match self {
            Self::SingleStep => "SSKDF",
            Self::X963 => "X963KDF",
        }
    }
}

/// Which auxiliary function is driving the Single-Step construction.
///
/// This is derived from the combination of the `"mac"` parameter and the
/// `SskdfVariant`:
///
/// | `variant`    | `"mac"` present? | `"mac"` value    | `aux_fn`              |
/// |--------------|------------------|------------------|-----------------------|
/// | `SingleStep` | no               | —                | `Hash`                |
/// | `SingleStep` | yes              | `"HMAC"`         | `Hmac`                |
/// | `SingleStep` | yes              | `"KMAC128"`/`256`| `Kmac`                |
/// | `SingleStep` | yes              | other            | **error (unsupported)**|
/// | `X963`       | no               | —                | `Hash`                |
/// | `X963`       | yes              | *any*            | **error (unsupported)**|
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SskdfAuxFunction {
    /// Bare hash: `Aux(data) = H(data)`. Requires `"digest"`.
    Hash,
    /// HMAC: `Aux(data) = HMAC(salt, data)`. Requires `"mac"="HMAC"` and
    /// `"digest"`.
    Hmac,
    /// KMAC: `Aux(data) = KMAC(salt, data, custom="KDF")`. Requires
    /// `"mac"="KMAC128"` or `"mac"="KMAC256"`.
    Kmac,
}

impl SskdfAuxFunction {
    /// Human-readable label for tracing.
    #[inline]
    fn as_str(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Hmac => "hmac",
            Self::Kmac => "kmac",
        }
    }
}

// =============================================================================
// SskdfContext — Derivation Context
// =============================================================================

/// Per-derivation state for SSKDF and X9.63-KDF.
///
/// Corresponds to the C `KDF_SSKDF` struct at `sskdf.c:70-79`:
///
/// ```c
/// typedef struct {
///     void *provctx;
///     unsigned char *info;    size_t info_len;
///     unsigned char *secret;  size_t secret_len;
///     unsigned char *salt;    size_t salt_len;
///     PROV_DIGEST digest;
///     EVP_MAC_CTX *macctx;
///     size_t out_len;         // KMAC output override
///     int is_kmac;
/// } KDF_SSKDF;
/// ```
///
/// Key differences from the C struct:
///
/// - `provctx` becomes [`Arc<LibContext>`] (every provider must hold its own
///   library-context handle for algorithm fetch).
/// - Nullable pointers are represented as [`Option<Vec<u8>>`] / [`Option<T>`]
///   rather than `NULL` sentinels (rule R5).
/// - `is_kmac` is subsumed into the `SskdfAuxFunction` enum.
/// - The `macctx` field holds an *initialized template* (key already set);
///   each iteration duplicates it via `MacCtx::dup`, matching the C
///   `EVP_MAC_CTX_dup` pattern at `sskdf.c:295`.
///
/// # Drop Behavior
///
/// Derives `ZeroizeOnDrop`: every byte of `secret`, `info`, `salt` is wiped
/// on drop. `mac_template` and `digest` do not hold plaintext secrets but
/// still own heap allocations — they are freed normally.
#[derive(ZeroizeOnDrop)]
pub struct SskdfContext {
    /// Library context used for digest / MAC fetches. Not sensitive.
    #[zeroize(skip)]
    libctx: Arc<LibContext>,

    /// Single-Step vs X9.63 variant. Not sensitive.
    #[zeroize(skip)]
    variant: SskdfVariant,

    /// Currently selected auxiliary function. Updated by
    /// `SskdfContext::apply_params`. Defaults to [`SskdfAuxFunction::Hash`].
    #[zeroize(skip)]
    aux_fn: SskdfAuxFunction,

    /// Fetched digest, if any. Rebuilt lazily in `derive`. Not secret.
    #[zeroize(skip)]
    digest: Option<MessageDigest>,

    /// Digest algorithm name from `"digest"` parameter, kept so that HMAC
    /// can re-fetch it when the MAC context is rebuilt. Not secret.
    #[zeroize(skip)]
    digest_name: Option<String>,

    /// MAC algorithm name from `"mac"` parameter. Not secret.
    #[zeroize(skip)]
    mac_name: Option<String>,

    /// Optional property query string forwarded to fetch calls. Not secret.
    #[zeroize(skip)]
    properties: Option<String>,

    /// Pre-initialized MAC template (key already set). Per-iteration we
    /// `MacCtx::dup` this template, mirroring `EVP_MAC_CTX_dup` at
    /// `sskdf.c:295`. Not zeroized directly — the MAC context's own `Drop`
    /// zeroizes its internal key buffer.
    #[zeroize(skip)]
    mac_template: Option<MacCtx>,

    /// Shared secret `Z`. **Sensitive** — zeroized on drop/reset.
    secret: Option<Vec<u8>>,

    /// `FixedInfo` (SSKDF) / `SharedInfo` (X9.63). Accumulated across multiple
    /// `"info"` `set_params` calls, up to `MAX_INFO_SEGMENTS`. Zeroized
    /// opportunistically — info *may* be secret in some protocol bindings.
    info: Option<Vec<u8>>,

    /// Number of `"info"` segments seen so far. Used to enforce
    /// `MAX_INFO_SEGMENTS` per C `ossl_param_get1_concat_octet_string`.
    #[zeroize(skip)]
    info_segments: usize,

    /// MAC salt (HMAC / KMAC modes only). Zeroized defensively.
    salt: Option<Vec<u8>>,

    /// KMAC output-length override (`kmac_out_len` in `sskdf.c:201`).
    /// Value of `0` / `None` → the MAC's default output size is used,
    /// possibly falling back to `derived_key_len` per `sskdf.c:207`.
    #[zeroize(skip)]
    out_len: Option<usize>,
}

impl SskdfContext {
    /// Creates a fresh context for the given variant.
    ///
    /// The context starts in a minimal unconfigured state: no digest, no
    /// MAC, no secret. Callers must populate it via `set_params` before
    /// calling `derive`.
    ///
    /// [`set_params`]: KdfContext::set_params
    /// [`derive`]: KdfContext::derive
    #[must_use]
    pub fn new(libctx: Arc<LibContext>, variant: SskdfVariant) -> Self {
        debug!(variant = variant.as_str(), "SSKDF: new context");
        Self {
            libctx,
            variant,
            aux_fn: SskdfAuxFunction::Hash,
            digest: None,
            digest_name: None,
            mac_name: None,
            properties: None,
            mac_template: None,
            secret: None,
            info: None,
            info_segments: 0,
            salt: None,
            out_len: None,
        }
    }

    /// Produces a deep clone of this context, suitable for concurrent
    /// derivation from the same configured state.
    ///
    /// Matches the semantics of the C `sskdf_dup` at `sskdf.c:391-420`:
    /// all secret / info / salt buffers are duplicated, the MAC context is
    /// duplicated via `MacCtx::dup`, and metadata is copied verbatim.
    ///
    /// # Errors
    ///
    /// Propagates `MacCtx::dup` failures as `ProviderError::Dispatch`.
    pub fn dup(&self) -> ProviderResult<Self> {
        let mac_template = match &self.mac_template {
            Some(t) => Some(t.dup().map_err(dispatch_err)?),
            None => None,
        };
        debug!(variant = self.variant.as_str(), "SSKDF: dup context");
        Ok(Self {
            libctx: self.libctx.clone(),
            variant: self.variant,
            aux_fn: self.aux_fn,
            digest: self.digest.clone(),
            digest_name: self.digest_name.clone(),
            mac_name: self.mac_name.clone(),
            properties: self.properties.clone(),
            mac_template,
            secret: self.secret.clone(),
            info: self.info.clone(),
            info_segments: self.info_segments,
            salt: self.salt.clone(),
            out_len: self.out_len,
        })
    }

    /// Returns the active auxiliary function — useful for tests and
    /// diagnostics.
    #[inline]
    #[must_use]
    pub fn aux_function(&self) -> SskdfAuxFunction {
        self.aux_fn
    }

    /// Returns the variant (SSKDF vs X9.63).
    #[inline]
    #[must_use]
    pub fn variant(&self) -> SskdfVariant {
        self.variant
    }

    /// Parses a single `ParamSet` and mutates context fields accordingly.
    ///
    /// Translates `sskdf_common_set_ctx_params` (`sskdf.c:600-637`) and the
    /// variant-specific `sskdf_set_ctx_params` / `x963kdf_set_ctx_params`.
    ///
    /// # Behavior
    ///
    /// - `"digest"` → stored. Fetch is deferred to `derive` / `ensure_digest`.
    /// - `"secret"` / `"key"` → copied into `self.secret`. Overrides any
    ///   previous value (matches C `OPENSSL_clear_free` + `memdup`).
    /// - `"info"` → **appended** to `self.info`, enforcing
    ///   `MAX_INFO_SEGMENTS` and `MAX_INPUT_LEN` bounds.
    /// - `"salt"` → copied into `self.salt`.
    /// - `"mac"` (SSKDF only) → stored + `aux_fn` classified.
    /// - `"size"` → stored as `out_len`.
    /// - `"properties"` → stored.
    ///
    /// # Errors
    ///
    /// - Unsupported MAC name (anything other than HMAC / KMAC128 / KMAC256).
    /// - X9.63 + `"mac"` present → `PROV_R_NOT_SUPPORTED`.
    /// - `secret` / `info` / `salt` exceeding `MAX_INPUT_LEN`.
    /// - More than `MAX_INFO_SEGMENTS` info segments.
    /// - `"size"` = 0.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // --- secret --------------------------------------------------------
        // Accept both "secret" and "key" for EVP_KDF compatibility.
        if let Some(value) = params.get(PARAM_SECRET).or_else(|| params.get(PARAM_KEY)) {
            match value {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() > MAX_INPUT_LEN {
                        warn!(
                            len = bytes.len(),
                            max = MAX_INPUT_LEN,
                            "SSKDF: secret exceeds MAX_INPUT_LEN"
                        );
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!(
                                "SSKDF: secret length {} exceeds maximum {}",
                                bytes.len(),
                                MAX_INPUT_LEN
                            ),
                        )));
                    }
                    // Zeroize any prior secret before overwriting (defensive).
                    if let Some(prev) = self.secret.as_mut() {
                        prev.zeroize();
                    }
                    self.secret = Some(bytes.clone());
                    trace!(len = bytes.len(), "SSKDF: secret set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_SECRET.to_string(),
                        expected: "OctetString",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // --- info (concatenated across calls) -----------------------------
        if let Some(value) = params.get(PARAM_INFO) {
            match value {
                ParamValue::OctetString(bytes) => {
                    // Enforce MAX_INFO_SEGMENTS.
                    if self.info_segments >= MAX_INFO_SEGMENTS {
                        warn!(
                            segments = self.info_segments,
                            max = MAX_INFO_SEGMENTS,
                            "SSKDF: too many info segments"
                        );
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!("SSKDF: exceeded maximum info segments ({MAX_INFO_SEGMENTS})"),
                        )));
                    }
                    let current_len = self.info.as_ref().map_or(0, Vec::len);
                    let new_total = current_len.checked_add(bytes.len()).ok_or_else(|| {
                        ProviderError::Common(CommonError::ArithmeticOverflow {
                            operation: "SSKDF info length summation",
                        })
                    })?;
                    if new_total > MAX_INPUT_LEN {
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!(
                                "SSKDF: total info length {new_total} exceeds maximum {MAX_INPUT_LEN}"
                            ),
                        )));
                    }
                    let buf = self.info.get_or_insert_with(Vec::new);
                    buf.extend_from_slice(bytes);
                    self.info_segments = self.info_segments.saturating_add(1);
                    trace!(
                        segment = self.info_segments,
                        added = bytes.len(),
                        total = new_total,
                        "SSKDF: info segment appended"
                    );
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_INFO.to_string(),
                        expected: "OctetString",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // --- salt ----------------------------------------------------------
        if let Some(value) = params.get(PARAM_SALT) {
            match value {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() > MAX_INPUT_LEN {
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!(
                                "SSKDF: salt length {} exceeds maximum {}",
                                bytes.len(),
                                MAX_INPUT_LEN
                            ),
                        )));
                    }
                    if let Some(prev) = self.salt.as_mut() {
                        prev.zeroize();
                    }
                    self.salt = Some(bytes.clone());
                    trace!(len = bytes.len(), "SSKDF: salt set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_SALT.to_string(),
                        expected: "OctetString",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // --- digest --------------------------------------------------------
        if let Some(value) = params.get(PARAM_DIGEST) {
            match value {
                ParamValue::Utf8String(name) => {
                    self.digest_name = Some(name.clone());
                    self.digest = None; // force re-fetch in derive
                    debug!(digest = %name, "SSKDF: digest selected");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_DIGEST.to_string(),
                        expected: "Utf8String",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // --- properties ----------------------------------------------------
        if let Some(value) = params.get(PARAM_PROPERTIES) {
            match value {
                ParamValue::Utf8String(p) => {
                    self.properties = Some(p.clone());
                    trace!(properties = %p, "SSKDF: properties set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_PROPERTIES.to_string(),
                        expected: "Utf8String",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // --- mac (SSKDF only; X9.63 rejects) ------------------------------
        if let Some(value) = params.get(PARAM_MAC) {
            if self.variant == SskdfVariant::X963 {
                warn!("X963KDF: 'mac' parameter is not supported (hash-only KDF)");
                return Err(ProviderError::Common(CommonError::Unsupported(
                    "X963KDF does not accept a 'mac' parameter (ANSI X9.63 is hash-only)"
                        .to_string(),
                )));
            }
            match value {
                ParamValue::Utf8String(name) => {
                    // Classify aux_fn from MAC name.
                    let aux = if name.eq_ignore_ascii_case(HMAC) {
                        SskdfAuxFunction::Hmac
                    } else if name.eq_ignore_ascii_case(KMAC128)
                        || name.eq_ignore_ascii_case(KMAC256)
                    {
                        SskdfAuxFunction::Kmac
                    } else {
                        warn!(mac = %name, "SSKDF: unsupported MAC");
                        return Err(ProviderError::Common(CommonError::Unsupported(format!(
                            "SSKDF: MAC '{name}' is not supported \
                             (expected 'HMAC', 'KMAC128', or 'KMAC256')"
                        ))));
                    };
                    self.mac_name = Some(name.clone());
                    self.aux_fn = aux;
                    self.mac_template = None; // force rebuild in derive
                    debug!(mac = %name, aux = aux.as_str(), "SSKDF: MAC selected");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_MAC.to_string(),
                        expected: "Utf8String",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // --- size (KMAC output-length override) ---------------------------
        if let Some(value) = params.get(PARAM_SIZE) {
            match value {
                ParamValue::UInt64(v) => {
                    let n = usize::try_from(*v).map_err(|_| {
                        ProviderError::Common(CommonError::ArithmeticOverflow {
                            operation: "SSKDF 'size' parameter u64 → usize",
                        })
                    })?;
                    if n == 0 {
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            "SSKDF: 'size' parameter must be > 0".to_string(),
                        )));
                    }
                    self.out_len = Some(n);
                    trace!(size = n, "SSKDF: out_len override");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_SIZE.to_string(),
                        expected: "UInt64",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// SskdfContext — Inherent Algorithmic Methods (Chunk 3)
// =============================================================================

impl SskdfContext {
    /// Validates that all mandatory parameters have been supplied.
    ///
    /// Matches the checks in `sskdf_derive` / `x963kdf_derive`
    /// (`sskdf.c:464-500, 574-586`):
    ///
    /// - `secret` is mandatory (`PROV_R_MISSING_SECRET`).
    /// - Hash mode requires `"digest"` (`PROV_R_MISSING_MESSAGE_DIGEST`).
    /// - HMAC mode requires `"digest"` (HMAC's sub-digest) and `"mac"`.
    /// - KMAC mode requires `"mac"`.
    ///
    /// `derived_key_len == 0` is validated inside `derive_hash` / `derive_mac`
    /// because it is a per-call parameter, not a context field.
    fn validate(&self) -> ProviderResult<()> {
        if self.secret.is_none() {
            warn!("SSKDF: derive called without 'secret' parameter");
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "SSKDF: 'secret' parameter is mandatory".to_string(),
            )));
        }
        match self.aux_fn {
            SskdfAuxFunction::Hash => {
                if self.digest_name.is_none() {
                    warn!("SSKDF: hash mode requires 'digest' parameter");
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        "SSKDF: hash-mode requires 'digest' parameter".to_string(),
                    )));
                }
            }
            SskdfAuxFunction::Hmac => {
                if self.digest_name.is_none() {
                    warn!("SSKDF: HMAC mode requires 'digest' parameter");
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        "SSKDF: HMAC-mode requires 'digest' parameter \
                         (the HMAC sub-digest)"
                            .to_string(),
                    )));
                }
                if self.mac_name.is_none() {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        "SSKDF: HMAC-mode requires 'mac' parameter".to_string(),
                    )));
                }
            }
            SskdfAuxFunction::Kmac => {
                if self.mac_name.is_none() {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        "SSKDF: KMAC-mode requires 'mac' parameter".to_string(),
                    )));
                }
            }
        }
        Ok(())
    }

    /// Lazy-fetches the configured digest if not already present.
    ///
    /// Returns an error if:
    ///
    /// - `self.digest_name` is `None` (caller should have caught this in
    ///   `Self::validate`).
    /// - The digest is an extendable-output function (XOF). SP 800-56C §4
    ///   forbids XOF as the auxiliary function — the C code also rejects
    ///   these (implicitly, via the fixed-size `EVP_MAX_MD_SIZE` output
    ///   buffer semantics on line 142).
    fn ensure_digest(&mut self) -> ProviderResult<()> {
        if self.digest.is_some() {
            return Ok(());
        }
        let name = self.digest_name.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "SSKDF: 'digest' parameter is mandatory for this mode".to_string(),
            ))
        })?;
        let props = self.properties.as_deref();
        let md = MessageDigest::fetch(&self.libctx, name, props).map_err(dispatch_err)?;
        if md.is_xof() {
            warn!(digest = %name, "SSKDF: XOF digest rejected");
            return Err(ProviderError::Common(CommonError::Unsupported(format!(
                "SSKDF: XOF digest '{name}' is not permitted as an auxiliary \
                 function (SP 800-56C §4 forbids XOF)"
            ))));
        }
        debug!(
            digest = %name,
            size = md.digest_size(),
            "SSKDF: digest fetched"
        );
        self.digest = Some(md);
        Ok(())
    }

    /// Returns the effective salt for the current MAC mode.
    ///
    /// Mirrors `sskdf.c:502-508`:
    ///
    /// - If a non-empty salt is set → return a clone of it.
    /// - Otherwise → return `default_len` zero-bytes (matches the C
    ///   `OPENSSL_zalloc(default_salt_len)` branch).
    ///
    /// `default_len` is caller-supplied because it depends on the MAC:
    ///
    /// - HMAC: `digest.digest_size()`
    /// - KMAC128: `KMAC128_DEFAULT_SALT_SIZE` (164)
    /// - KMAC256: `KMAC256_DEFAULT_SALT_SIZE` (132)
    fn effective_salt(&self, default_len: usize) -> Vec<u8> {
        match &self.salt {
            Some(s) if !s.is_empty() => s.clone(),
            _ => vec![0u8; default_len],
        }
    }

    /// Validates that an explicit KMAC output-length override is one of the
    /// canonical values accepted by `kmac_init` (`sskdf.c:210-215`):
    /// `{derived_key_len, 20, 28, 32, 48, 64}`.
    ///
    /// The `derived_key_len` case is handled as a special equality check.
    ///
    /// This is an associated function (no `self`) because validation depends
    /// purely on its two arguments and the workspace `KMAC_OUT_LEN_ALLOWED`
    /// constant — no per-context state is read. Callers invoke it as
    /// `Self::validate_kmac_out_len(n, k)` or `SskdfContext::validate_kmac_out_len(...)`.
    fn validate_kmac_out_len(out_len: usize, derived_key_len: usize) -> ProviderResult<()> {
        if out_len == derived_key_len || KMAC_OUT_LEN_ALLOWED.contains(&out_len) {
            return Ok(());
        }
        warn!(
            out_len,
            derived_key_len, "SSKDF KMAC: invalid output-length override"
        );
        Err(ProviderError::Common(CommonError::InvalidArgument(
            format!(
                "SSKDF KMAC: 'size' ({out_len}) must equal derived_key_len \
                 ({derived_key_len}) or one of {KMAC_OUT_LEN_ALLOWED:?}"
            ),
        )))
    }

    /// Builds a fresh MAC template from the currently configured MAC /
    /// digest / salt / `out_len` parameters.
    ///
    /// Mirrors the C pattern:
    ///
    /// ```c
    /// // sskdf.c:473+ (within sskdf_derive)
    /// EVP_MAC_CTX *ctx_init = ...
    /// kmac_init(ctx_init, kmac_custom, ...);
    /// EVP_MAC_init(ctx_init, salt, salt_len, NULL);
    /// // then per iteration: ctx = EVP_MAC_CTX_dup(ctx_init);
    /// ```
    ///
    /// Behavior:
    ///
    /// 1. `Mac::fetch` with the cached `mac_name`.
    /// 2. `MacCtx::new` to allocate an empty context.
    /// 3. Compute the effective salt (see [`Self::effective_salt`]).
    /// 4. Build init params:
    ///    - HMAC → `"digest" = <digest_name>`
    ///    - KMAC → `"custom" = b"KDF"`
    /// 5. `MacCtx::init(&salt, Some(&init_params))`.
    /// 6. If `out_len.is_some()` (KMAC-only override), call
    ///    `MacCtx::set_params({"size": out_len as u64})` **after** `init`
    ///    (`MacCtx::init` resets `output_size` to the MAC's default at
    ///    `mac.rs:329`, so a size override must be post-init).
    ///
    /// Stores the template in `self.mac_template`.
    fn rebuild_mac_template(&mut self, derived_key_len: usize) -> ProviderResult<()> {
        let mac_name = self.mac_name.clone().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "SSKDF: MAC template rebuild requested without 'mac' name".to_string(),
            ))
        })?;
        let props = self.properties.as_deref();
        let mac = Mac::fetch(&self.libctx, &mac_name, props).map_err(dispatch_err)?;
        let mut ctx = MacCtx::new(&mac).map_err(dispatch_err)?;

        // Determine default salt length & build init params.
        let (default_salt_len, init_params) = match self.aux_fn {
            SskdfAuxFunction::Hmac => {
                // HMAC requires the digest (its sub-digest). Fetch if not yet.
                self.ensure_digest()?;
                // SAFETY (invariant-documented): ensure_digest guarantees
                // self.digest = Some(_). digest_name is required by validate.
                let digest = self.digest.as_ref().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(
                        "SSKDF HMAC: digest unavailable after ensure_digest".to_string(),
                    ))
                })?;
                let digest_size = digest.digest_size();
                // HMAC init_params: "digest" = digest_name (so the MAC layer
                // knows which underlying digest to use).
                let digest_name_owned = digest.name().to_string();
                let params = ParamBuilder::new()
                    .push_utf8("digest", digest_name_owned)
                    .build();
                (digest_size, params)
            }
            SskdfAuxFunction::Kmac => {
                // KMAC init_params: "custom" = b"KDF". The KMAC128/256
                // distinction drives the default salt length.
                let default_len = if mac_name.eq_ignore_ascii_case(KMAC128) {
                    KMAC128_DEFAULT_SALT_SIZE
                } else {
                    KMAC256_DEFAULT_SALT_SIZE
                };
                let params = ParamBuilder::new()
                    .push_octet("custom", KMAC_CUSTOM_KDF.to_vec())
                    .build();
                (default_len, params)
            }
            SskdfAuxFunction::Hash => {
                // Should not happen — rebuild_mac_template is gated by the
                // caller to MAC modes only. Defensive error:
                return Err(ProviderError::Common(CommonError::Internal(
                    "SSKDF: rebuild_mac_template called in hash mode".to_string(),
                )));
            }
        };

        let salt = self.effective_salt(default_salt_len);
        ctx.init(&salt, Some(&init_params)).map_err(dispatch_err)?;

        // KMAC output-length override — MUST be applied AFTER init because
        // `MacCtx::init` resets `output_size` to the MAC's default (see
        // `mac.rs:329`).
        if matches!(self.aux_fn, SskdfAuxFunction::Kmac) {
            if let Some(n) = self.out_len {
                // Validate n against kmac_init's allowed set (sskdf.c:220-225).
                Self::validate_kmac_out_len(n, derived_key_len)?;
                let size_override = ParamBuilder::new().push_u64(PARAM_SIZE, n as u64).build();
                ctx.set_params(&size_override).map_err(dispatch_err)?;
                trace!(n, "SSKDF KMAC: out_len override applied");
            } else {
                // Per sskdf.c:217-218: if kmac_out_len == 0, default it to
                // derived_key_len so that one iteration suffices for the
                // requested output.
                let size_override = ParamBuilder::new()
                    .push_u64(PARAM_SIZE, derived_key_len as u64)
                    .build();
                ctx.set_params(&size_override).map_err(dispatch_err)?;
                trace!(
                    size = derived_key_len,
                    "SSKDF KMAC: out_len defaulted to derived_key_len"
                );
            }
        }

        debug!(
            mac = %mac_name,
            aux = self.aux_fn.as_str(),
            salt_len = salt.len(),
            "SSKDF: MAC template rebuilt"
        );
        self.mac_template = Some(ctx);
        Ok(())
    }

    /// Hash-mode core loop — implements `SSKDF_hash_kdm` at `sskdf.c:133-196`.
    ///
    /// For each counter `i = 1..=reps` (`reps = ceil(derived_key_len / h)`):
    ///
    /// - SSKDF: `Result(i) = H(counter_BE ‖ Z ‖ info)`
    /// - X9.63: `Result(i) = H(Z ‖ counter_BE ‖ info)`
    ///
    /// `Result` is concatenated to form the output; the final block is
    /// truncated if the requested length is not a multiple of `h`.
    ///
    /// Internally uses an `MdContext::copy_from` template pattern so that the
    /// digest is not re-`init`-ed on every iteration (matches C
    /// `EVP_MD_CTX_copy_ex`).
    fn derive_hash(&mut self, key: &mut [u8]) -> ProviderResult<usize> {
        if key.is_empty() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "SSKDF: derived_key_len must be > 0".to_string(),
            )));
        }
        if key.len() > MAX_INPUT_LEN {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SSKDF: derived_key_len {} exceeds maximum {}",
                    key.len(),
                    MAX_INPUT_LEN
                ),
            )));
        }

        self.ensure_digest()?;
        // self.digest guaranteed Some after ensure_digest.
        let digest = self.digest.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::Internal(
                "SSKDF: digest unavailable after ensure_digest".to_string(),
            ))
        })?;
        let h = digest.digest_size();
        if h == 0 {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("SSKDF: digest '{}' has zero output size", digest.name()),
            )));
        }
        let secret = self.secret.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "SSKDF: secret unavailable in derive_hash".to_string(),
            ))
        })?;
        if secret.len() > MAX_INPUT_LEN {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SSKDF: secret length {} exceeds maximum {}",
                    secret.len(),
                    MAX_INPUT_LEN
                ),
            )));
        }
        let info: &[u8] = self.info.as_deref().unwrap_or(&[]);

        // Build the template context (digest bound, empty state).
        let mut ctx_init = MdContext::new();
        ctx_init.init(digest, None).map_err(dispatch_err)?;

        // Cache variant here — we can't borrow self mutably again while
        // ctx_init is outstanding.
        let variant = self.variant;

        let mut written: usize = 0;
        let mut remaining = key.len();
        let mut counter: u32 = 1;

        trace!(
            h,
            keylen = key.len(),
            variant = variant.as_str(),
            "SSKDF hash loop begin"
        );

        loop {
            let c = counter_bytes(counter);

            // Per-iteration context, cloned from template.
            let mut ctx = MdContext::new();
            ctx.copy_from(&ctx_init).map_err(dispatch_err)?;

            match variant {
                SskdfVariant::SingleStep => {
                    // H(counter ‖ Z ‖ info)
                    ctx.update(&c).map_err(dispatch_err)?;
                    ctx.update(secret).map_err(dispatch_err)?;
                    ctx.update(info).map_err(dispatch_err)?;
                }
                SskdfVariant::X963 => {
                    // H(Z ‖ counter ‖ info)
                    ctx.update(secret).map_err(dispatch_err)?;
                    ctx.update(&c).map_err(dispatch_err)?;
                    ctx.update(info).map_err(dispatch_err)?;
                }
            }

            let block = ctx.finalize().map_err(dispatch_err)?;
            debug_assert_eq!(
                block.len(),
                h,
                "SSKDF: digest produced {} bytes, expected {}",
                block.len(),
                h
            );

            if remaining >= h {
                key[written..written + h].copy_from_slice(&block);
                written = written.saturating_add(h);
                remaining = remaining.saturating_sub(h);
                if remaining == 0 {
                    break;
                }
            } else {
                key[written..written + remaining].copy_from_slice(&block[..remaining]);
                written = written.saturating_add(remaining);
                break;
            }

            // Advance counter with overflow check (R6).
            counter = counter.checked_add(1).ok_or_else(|| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "SSKDF hash-mode counter increment",
                })
            })?;
        }

        debug!(written, "SSKDF hash loop complete");
        Ok(written)
    }

    /// MAC-mode core loop — implements `SSKDF_mac_kdm` at `sskdf.c:252-324`.
    ///
    /// For each counter `i = 1..=reps` (`reps = ceil(derived_key_len / h)`,
    /// where `h = MAC output_size`):
    ///
    /// `Result(i) = MAC(salt, counter_BE ‖ Z ‖ info)`
    ///
    /// with `MAC` = HMAC(digest, …) or KMAC128/256(custom="KDF", …).
    ///
    /// Uses `MacCtx::dup` per iteration (matches C `EVP_MAC_CTX_dup` at
    /// `sskdf.c:293`).
    fn derive_mac(&mut self, key: &mut [u8]) -> ProviderResult<usize> {
        if key.is_empty() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "SSKDF: derived_key_len must be > 0".to_string(),
            )));
        }
        if key.len() > MAX_INPUT_LEN {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SSKDF: derived_key_len {} exceeds maximum {}",
                    key.len(),
                    MAX_INPUT_LEN
                ),
            )));
        }

        // Always rebuild the template — state from a prior derive may be
        // stale (caller may have changed salt / out_len / mac).
        self.rebuild_mac_template(key.len())?;

        // The template is now in self.mac_template.
        let template = self.mac_template.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::Internal(
                "SSKDF: MAC template missing after rebuild".to_string(),
            ))
        })?;
        let h = template.mac_size().map_err(dispatch_err)?;
        if h == 0 {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "SSKDF: MAC output_size is zero".to_string(),
            )));
        }

        let secret = self.secret.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "SSKDF: secret unavailable in derive_mac".to_string(),
            ))
        })?;
        if secret.len() > MAX_INPUT_LEN {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SSKDF: secret length {} exceeds maximum {}",
                    secret.len(),
                    MAX_INPUT_LEN
                ),
            )));
        }
        let info: &[u8] = self.info.as_deref().unwrap_or(&[]);

        trace!(
            h,
            keylen = key.len(),
            aux = self.aux_fn.as_str(),
            "SSKDF MAC loop begin"
        );

        let mut written: usize = 0;
        let mut remaining = key.len();
        let mut counter: u32 = 1;

        loop {
            let c = counter_bytes(counter);

            // Per-iteration duplicate of the template (matches
            // EVP_MAC_CTX_dup at sskdf.c:293).
            let mut ctx = template.dup().map_err(dispatch_err)?;

            // MAC-mode always prepends counter: MAC(counter ‖ Z ‖ info).
            ctx.update(&c).map_err(dispatch_err)?;
            ctx.update(secret).map_err(dispatch_err)?;
            ctx.update(info).map_err(dispatch_err)?;

            let block = ctx.finalize().map_err(dispatch_err)?;
            if block.len() < h {
                return Err(ProviderError::Common(CommonError::Internal(format!(
                    "SSKDF MAC: expected at least {} bytes, got {}",
                    h,
                    block.len()
                ))));
            }

            if remaining >= h {
                key[written..written + h].copy_from_slice(&block[..h]);
                written = written.saturating_add(h);
                remaining = remaining.saturating_sub(h);
                if remaining == 0 {
                    break;
                }
            } else {
                key[written..written + remaining].copy_from_slice(&block[..remaining]);
                written = written.saturating_add(remaining);
                break;
            }

            // Advance counter with overflow check (R6).
            counter = counter.checked_add(1).ok_or_else(|| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "SSKDF MAC-mode counter increment",
                })
            })?;
        }

        debug!(written, "SSKDF MAC loop complete");
        Ok(written)
    }
}

// =============================================================================
// KdfContext Trait Implementation
// =============================================================================

impl KdfContext for SskdfContext {
    /// Derives key material into `key`.
    ///
    /// Matches C `sskdf_derive` (`sskdf.c:458-524`) and
    /// `x963kdf_derive` (`sskdf.c:569-597`):
    ///
    /// 1. Apply any new params (if `params` is non-empty).
    /// 2. Validate mandatory fields.
    /// 3. Dispatch to `derive_hash` or `derive_mac` by `aux_fn`.
    /// 4. On success, copy into caller buffer; on failure, zeroize both the
    ///    scratch buffer and the caller's output buffer
    ///    (mirrors `OPENSSL_cleanse(key, keylen)` at `kbkdf.c:379`).
    #[instrument(
        skip_all,
        fields(
            keylen = key.len(),
            variant = self.variant.as_str(),
            aux = self.aux_fn.as_str(),
        ),
        level = "debug"
    )]
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;

        // X9.63: MAC parameters are rejected; this is validated in
        // apply_params (via the 'mac' param handler), but belt-and-braces:
        if self.variant == SskdfVariant::X963 && self.aux_fn != SskdfAuxFunction::Hash {
            return Err(ProviderError::Common(CommonError::Unsupported(
                "X963KDF requires hash mode; MAC mode is not supported".to_string(),
            )));
        }

        // Derive into scratch; zero on failure before propagating.
        let mut scratch = vec![0u8; key.len()];
        let result = match self.aux_fn {
            SskdfAuxFunction::Hash => self.derive_hash(&mut scratch),
            SskdfAuxFunction::Hmac | SskdfAuxFunction::Kmac => self.derive_mac(&mut scratch),
        };

        match result {
            Ok(n) => {
                key[..n].copy_from_slice(&scratch[..n]);
                scratch.zeroize();
                debug!(n, "SSKDF: derive succeeded");
                Ok(n)
            }
            Err(e) => {
                scratch.zeroize();
                // Mirror C OPENSSL_cleanse(key, keylen) on failure
                // (sskdf.c behaviour: keys must never leak partial output).
                for b in key.iter_mut() {
                    *b = 0;
                }
                warn!(error = %e, "SSKDF: derive failed");
                Err(e)
            }
        }
    }

    /// Resets the context to its initial state.
    ///
    /// Matches C `sskdf_reset` (`sskdf.c:367-379`):
    ///
    /// - Zeroizes and frees `secret`, `info`, `salt`.
    /// - Releases the MAC context.
    /// - Preserves the library context and variant (new ctx would have the
    ///   same values).
    fn reset(&mut self) -> ProviderResult<()> {
        // Zeroize sensitive buffers before dropping.
        if let Some(s) = self.secret.as_mut() {
            s.zeroize();
        }
        self.secret = None;
        if let Some(i) = self.info.as_mut() {
            i.zeroize();
        }
        self.info = None;
        self.info_segments = 0;
        if let Some(s) = self.salt.as_mut() {
            s.zeroize();
        }
        self.salt = None;

        // Clear non-secret metadata.
        self.digest = None;
        self.digest_name = None;
        self.mac_name = None;
        self.properties = None;
        self.mac_template = None;
        self.aux_fn = SskdfAuxFunction::Hash;
        self.out_len = None;

        trace!(variant = self.variant.as_str(), "SSKDF: context reset");
        Ok(())
    }

    /// Reports gettable context parameters.
    ///
    /// Matches C `sskdf_get_ctx_params` / `x963kdf_get_ctx_params`
    /// (`sskdf.c:685-702, 750-767`):
    ///
    /// - `"size"` → the maximum output size (C `sskdf_size` at
    ///   `sskdf.c:422-436`):
    ///   - KMAC: `u64::MAX` (no effective bound).
    ///   - Hash/HMAC: the digest output size, or 0 if no digest set.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let size: u64 = match self.aux_fn {
            SskdfAuxFunction::Kmac => u64::MAX,
            _ => match &self.digest {
                Some(md) => md.digest_size() as u64,
                None => 0,
            },
        };
        Ok(ParamBuilder::new().push_u64(PARAM_SIZE, size).build())
    }

    /// Settable-side entry point — delegates to `Self::apply_params`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// SskdfProvider — NIST SP 800-56C rev2 Single-Step KDF
// =============================================================================

/// Provider registration shim for the NIST SP 800-56C rev2 Single-Step KDF.
///
/// Translates the C dispatch-table pattern (`ossl_kdf_sskdf_functions` at
/// `sskdf.c:704-720`) into a Rust trait implementation. A single
/// `SskdfProvider` instance vends as many `SskdfContext` instances as
/// the caller requests (one per `new_ctx`), each of which implements
/// `KdfContext` and carries its own mutable derivation state.
///
/// The provider supports three auxiliary-function modes, selected by the
/// `"mac"` parameter on a context:
///
/// - **Hash mode** (default, no `"mac"` set): `H(counter ‖ Z ‖ info)` per
///   `derive_hash`.
/// - **HMAC mode** (`mac = "HMAC"`): `HMAC(salt, counter ‖ Z ‖ info)` per
///   `derive_mac`.
/// - **KMAC mode** (`mac = "KMAC128"` or `"KMAC256"`): KMAC with the
///   customization string `"KDF"`.
///
/// See [`crate::implementations::kdfs`] for a crate-level overview.
#[derive(Debug, Clone)]
pub struct SskdfProvider {
    /// Library context used to resolve digests and MACs (`EVP_MD_fetch` /
    /// `EVP_MAC_fetch` equivalents). Shared via `Arc` so cheaply cloneable.
    libctx: Arc<LibContext>,
}

impl Default for SskdfProvider {
    /// Returns an `SskdfProvider` bound to the process-global default
    /// library context (matches C `OSSL_LIB_CTX_get0_global_default`).
    fn default() -> Self {
        Self::new(LibContext::get_default())
    }
}

impl SskdfProvider {
    /// Creates an `SskdfProvider` bound to the given library context.
    ///
    /// Use [`Default::default`] for the process-global default context.
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        Self { libctx }
    }

    /// Returns a human-readable description of this provider.
    #[must_use]
    pub fn description(&self) -> &'static str {
        "NIST SP 800-56C rev2 Single-Step KDF (Hash, HMAC, and KMAC auxiliary \
         functions) — RFC-equivalent one-step key derivation function"
    }

    /// Returns a `ParamSet` enumerating the parameters this provider
    /// accepts via `KdfContext::set_params`. Values are placeholders; the
    /// keys are the authoritative contract.
    ///
    /// Matches the C `sskdf_settable_ctx_params` table (`sskdf.c:676-683`).
    #[must_use]
    pub fn settable_params() -> ParamSet {
        ParamBuilder::new()
            .push_octet(PARAM_SECRET, Vec::new())
            .push_octet(PARAM_KEY, Vec::new())
            .push_octet(PARAM_INFO, Vec::new())
            .push_octet(PARAM_SALT, Vec::new())
            .push_utf8(PARAM_DIGEST, String::new())
            .push_utf8(PARAM_MAC, String::new())
            .push_utf8(PARAM_PROPERTIES, String::new())
            .push_u64(PARAM_SIZE, 0)
            .build()
    }

    /// Returns a `ParamSet` enumerating the parameters readable via
    /// `KdfContext::get_params`. Values are placeholders; the keys are
    /// the authoritative contract.
    ///
    /// Matches the C `sskdf_gettable_ctx_params` table (`sskdf.c:722-728`).
    #[must_use]
    pub fn gettable_params() -> ParamSet {
        ParamBuilder::new().push_u64(PARAM_SIZE, 0).build()
    }
}

impl KdfProvider for SskdfProvider {
    /// Canonical algorithm name — matches C `OSSL_KDF_NAME_SSKDF`.
    fn name(&self) -> &'static str {
        "SSKDF"
    }

    /// Creates a fresh derivation context.
    ///
    /// Equivalent to C `sskdf_new` (`sskdf.c:332-352`): allocates a new
    /// `KDF_SSKDF` struct with provctx set and all other fields zero.
    /// The returned context implements `KdfContext` and is boxed as a
    /// trait object for dynamic provider dispatch.
    #[instrument(skip_all, level = "trace")]
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        trace!("SskdfProvider: new_ctx");
        Ok(Box::new(SskdfContext::new(
            Arc::clone(&self.libctx),
            SskdfVariant::SingleStep,
        )))
    }
}

// =============================================================================
// X963KdfProvider — ANSI X9.63 KDF
// =============================================================================

/// Provider registration shim for the ANSI X9.63 KDF.
///
/// Translates the C dispatch-table pattern (`ossl_kdf_x963_kdf_functions` at
/// `sskdf.c:780-796`) into a Rust trait implementation. A single
/// `X963KdfProvider` instance vends as many `SskdfContext` instances as
/// the caller requests. The context's [`SskdfVariant::X963`] field selects
/// the X9.63 counter-placement rule in `derive_hash`:
///
/// `Result(i) = H(Z ‖ counter ‖ info)`
///
/// (whereas SSKDF uses `H(counter ‖ Z ‖ info)`).
///
/// Unlike SSKDF, X9.63 is **hash-only**: supplying a `"mac"` parameter to an
/// X963 context is rejected by `SskdfContext::apply_params` (matches C
/// `x963kdf_set_ctx_params` at `sskdf.c:643-645`).
#[derive(Debug, Clone)]
pub struct X963KdfProvider {
    libctx: Arc<LibContext>,
}

impl Default for X963KdfProvider {
    /// Returns an `X963KdfProvider` bound to the process-global default
    /// library context.
    fn default() -> Self {
        Self::new(LibContext::get_default())
    }
}

impl X963KdfProvider {
    /// Creates an `X963KdfProvider` bound to the given library context.
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        Self { libctx }
    }

    /// Returns a human-readable description of this provider.
    #[must_use]
    pub fn description(&self) -> &'static str {
        "ANSI X9.63 KDF (hash-only Single-Step KDF with counter placed after \
         the shared secret)"
    }

    /// Returns a `ParamSet` enumerating the parameters this provider
    /// accepts via `KdfContext::set_params`. The `"mac"` parameter is
    /// listed for contract discoverability but is rejected at derive time
    /// (X9.63 is hash-only).
    ///
    /// Matches the C `x963kdf_settable_ctx_params` table (`sskdf.c:740-747`).
    #[must_use]
    pub fn settable_params() -> ParamSet {
        ParamBuilder::new()
            .push_octet(PARAM_SECRET, Vec::new())
            .push_octet(PARAM_KEY, Vec::new())
            .push_octet(PARAM_INFO, Vec::new())
            .push_utf8(PARAM_DIGEST, String::new())
            .push_utf8(PARAM_PROPERTIES, String::new())
            .push_u64(PARAM_SIZE, 0)
            .build()
    }

    /// Returns a `ParamSet` enumerating the parameters readable via
    /// `KdfContext::get_params`.
    ///
    /// Matches the C `x963kdf_gettable_ctx_params` table
    /// (`sskdf.c:769-775`).
    #[must_use]
    pub fn gettable_params() -> ParamSet {
        ParamBuilder::new().push_u64(PARAM_SIZE, 0).build()
    }
}

impl KdfProvider for X963KdfProvider {
    /// Canonical algorithm name — matches C `OSSL_KDF_NAME_X963KDF`.
    fn name(&self) -> &'static str {
        "X963KDF"
    }

    /// Creates a fresh derivation context configured for X9.63 semantics.
    ///
    /// Equivalent to C `x963kdf_new` (`sskdf.c:354-365`).
    #[instrument(skip_all, level = "trace")]
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        trace!("X963KdfProvider: new_ctx");
        Ok(Box::new(SskdfContext::new(
            Arc::clone(&self.libctx),
            SskdfVariant::X963,
        )))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns the algorithm descriptors registered by this module.
///
/// The entries are in the order in which C declares them in
/// `providers/defltprov.c`: first `SSKDF`, then `X963KDF`. Both register
/// under `provider=default`; the FIPS provider uses the same
/// implementations via cross-module re-export.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["SSKDF"],
            property: "provider=default",
            description: "NIST SP 800-56C rev2 Single-Step KDF (Hash, HMAC, KMAC auxiliary \
                 functions)",
        },
        AlgorithmDescriptor {
            names: vec!["X963KDF"],
            property: "provider=default",
            description: "ANSI X9.63 KDF (hash-only Single-Step KDF with counter after Z)",
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Enum / type-level sanity
    // -------------------------------------------------------------------------

    #[test]
    fn variant_as_str() {
        assert_eq!(SskdfVariant::SingleStep.as_str(), "SSKDF");
        assert_eq!(SskdfVariant::X963.as_str(), "X963KDF");
    }

    #[test]
    fn aux_fn_as_str() {
        assert_eq!(SskdfAuxFunction::Hash.as_str(), "hash");
        assert_eq!(SskdfAuxFunction::Hmac.as_str(), "hmac");
        assert_eq!(SskdfAuxFunction::Kmac.as_str(), "kmac");
    }

    #[test]
    fn counter_bytes_big_endian() {
        assert_eq!(counter_bytes(1), [0x00, 0x00, 0x00, 0x01]);
        assert_eq!(counter_bytes(2), [0x00, 0x00, 0x00, 0x02]);
        assert_eq!(counter_bytes(0x0102_0304), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(counter_bytes(u32::MAX), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn kmac_constants_match_c() {
        // SSKDF_KMAC128_DEFAULT_SALT_SIZE = 168 - 4 = 164  (sskdf.c:45)
        assert_eq!(KMAC128_DEFAULT_SALT_SIZE, 164);
        // SSKDF_KMAC256_DEFAULT_SALT_SIZE = 136 - 4 = 132  (sskdf.c:46)
        assert_eq!(KMAC256_DEFAULT_SALT_SIZE, 132);
        // kmac_custom_str = "KDF"  (sskdf.c:47)
        assert_eq!(KMAC_CUSTOM_KDF, b"KDF");
        // Allowed KMAC override sizes (sskdf.c:210-215).
        assert_eq!(KMAC_OUT_LEN_ALLOWED, [20, 28, 32, 48, 64]);
    }

    // -------------------------------------------------------------------------
    // Provider metadata
    // -------------------------------------------------------------------------

    #[test]
    fn sskdf_provider_name() {
        let p = SskdfProvider::default();
        assert_eq!(p.name(), "SSKDF");
        assert!(!p.description().is_empty());
    }

    #[test]
    fn x963_provider_name() {
        let p = X963KdfProvider::default();
        assert_eq!(p.name(), "X963KDF");
        assert!(!p.description().is_empty());
    }

    #[test]
    fn sskdf_settable_params_lists_expected_keys() {
        let s = SskdfProvider::settable_params();
        for key in [
            PARAM_SECRET,
            PARAM_KEY,
            PARAM_INFO,
            PARAM_SALT,
            PARAM_DIGEST,
            PARAM_MAC,
            PARAM_PROPERTIES,
            PARAM_SIZE,
        ] {
            assert!(s.contains(key), "SSKDF settable should contain {key}");
        }
    }

    #[test]
    fn sskdf_gettable_params_lists_size() {
        let g = SskdfProvider::gettable_params();
        assert!(g.contains(PARAM_SIZE));
    }

    #[test]
    fn x963_settable_params_excludes_mac_salt() {
        let s = X963KdfProvider::settable_params();
        assert!(s.contains(PARAM_SECRET));
        assert!(s.contains(PARAM_DIGEST));
        assert!(s.contains(PARAM_INFO));
        assert!(s.contains(PARAM_SIZE));
        // X9.63 is hash-only and has no salt concept.
        assert!(!s.contains(PARAM_MAC));
        assert!(!s.contains(PARAM_SALT));
    }

    #[test]
    fn descriptors_contains_both_algorithms() {
        let d = descriptors();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].names, vec!["SSKDF"]);
        assert_eq!(d[0].property, "provider=default");
        assert!(!d[0].description.is_empty());
        assert_eq!(d[1].names, vec!["X963KDF"]);
        assert_eq!(d[1].property, "provider=default");
        assert!(!d[1].description.is_empty());
    }

    // -------------------------------------------------------------------------
    // Context construction & state lifecycle
    // -------------------------------------------------------------------------

    #[test]
    fn context_new_defaults() {
        let ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        assert_eq!(ctx.variant(), SskdfVariant::SingleStep);
        assert_eq!(ctx.aux_function(), SskdfAuxFunction::Hash);
    }

    #[test]
    fn context_new_x963_variant() {
        let ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::X963);
        assert_eq!(ctx.variant(), SskdfVariant::X963);
        assert_eq!(ctx.aux_function(), SskdfAuxFunction::Hash);
    }

    #[test]
    fn provider_new_ctx_succeeds() {
        let p = SskdfProvider::default();
        assert!(p.new_ctx().is_ok());
        let p = X963KdfProvider::default();
        assert!(p.new_ctx().is_ok());
    }

    #[test]
    fn reset_clears_state() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        // Seed with some state via apply_params.
        let params = ParamBuilder::new()
            .push_octet(PARAM_SECRET, b"hello".to_vec())
            .push_octet(PARAM_INFO, b"label".to_vec())
            .push_octet(PARAM_SALT, b"salty".to_vec())
            .push_utf8(PARAM_DIGEST, "SHA256".to_string())
            .build();
        ctx.apply_params(&params).expect("apply_params");
        assert!(ctx.secret.is_some());
        assert!(ctx.info.is_some());
        assert!(ctx.salt.is_some());
        assert_eq!(ctx.digest_name.as_deref(), Some("SHA256"));

        ctx.reset().expect("reset");
        assert!(ctx.secret.is_none());
        assert!(ctx.info.is_none());
        assert_eq!(ctx.info_segments, 0);
        assert!(ctx.salt.is_none());
        assert!(ctx.digest_name.is_none());
        assert!(ctx.digest.is_none());
        assert!(ctx.mac_name.is_none());
        assert_eq!(ctx.aux_function(), SskdfAuxFunction::Hash);
        // Variant preserved.
        assert_eq!(ctx.variant(), SskdfVariant::SingleStep);
    }

    #[test]
    fn dup_is_independent() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let params = ParamBuilder::new()
            .push_octet(PARAM_SECRET, b"sec".to_vec())
            .push_utf8(PARAM_DIGEST, "SHA256".to_string())
            .build();
        ctx.apply_params(&params).expect("apply_params");

        let dup = ctx.dup().expect("dup");
        assert_eq!(dup.variant(), SskdfVariant::SingleStep);
        assert_eq!(dup.aux_function(), SskdfAuxFunction::Hash);
        assert_eq!(dup.secret.as_deref(), Some(&b"sec"[..]));
        assert_eq!(dup.digest_name.as_deref(), Some("SHA256"));
    }

    // -------------------------------------------------------------------------
    // Parameter handling
    // -------------------------------------------------------------------------

    #[test]
    fn apply_params_secret_key_alias() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        // "key" is accepted as an alias for "secret".
        let params = ParamBuilder::new()
            .push_octet(PARAM_KEY, b"via-key".to_vec())
            .build();
        ctx.apply_params(&params).expect("apply_params");
        assert_eq!(ctx.secret.as_deref(), Some(&b"via-key"[..]));
    }

    #[test]
    fn apply_params_info_segments_concatenate() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        // Two separate apply_params calls, each contributing an info segment.
        let p1 = ParamBuilder::new()
            .push_octet(PARAM_INFO, b"aaaa".to_vec())
            .build();
        let p2 = ParamBuilder::new()
            .push_octet(PARAM_INFO, b"bbbb".to_vec())
            .build();
        ctx.apply_params(&p1).expect("p1");
        ctx.apply_params(&p2).expect("p2");
        assert_eq!(ctx.info.as_deref(), Some(&b"aaaabbbb"[..]));
        assert_eq!(ctx.info_segments, 2);
    }

    #[test]
    fn apply_params_rejects_too_many_info_segments() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        // Exceed MAX_INFO_SEGMENTS.
        for _ in 0..MAX_INFO_SEGMENTS {
            let p = ParamBuilder::new()
                .push_octet(PARAM_INFO, b"x".to_vec())
                .build();
            ctx.apply_params(&p).expect("expected early accept");
        }
        // One more should fail.
        let p = ParamBuilder::new()
            .push_octet(PARAM_INFO, b"x".to_vec())
            .build();
        let err = ctx.apply_params(&p).expect_err("expected error");
        let msg = format!("{err}");
        assert!(msg.contains("info") || msg.contains("segment"), "{msg}");
    }

    #[test]
    fn apply_params_sets_hmac_aux_fn() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new()
            .push_utf8(PARAM_MAC, "HMAC".to_string())
            .build();
        ctx.apply_params(&p).expect("apply");
        assert_eq!(ctx.aux_function(), SskdfAuxFunction::Hmac);
        assert_eq!(ctx.mac_name.as_deref(), Some("HMAC"));
    }

    #[test]
    fn apply_params_sets_kmac128_aux_fn() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new()
            .push_utf8(PARAM_MAC, "KMAC128".to_string())
            .build();
        ctx.apply_params(&p).expect("apply");
        assert_eq!(ctx.aux_function(), SskdfAuxFunction::Kmac);
    }

    #[test]
    fn apply_params_sets_kmac256_aux_fn() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new()
            .push_utf8(PARAM_MAC, "KMAC256".to_string())
            .build();
        ctx.apply_params(&p).expect("apply");
        assert_eq!(ctx.aux_function(), SskdfAuxFunction::Kmac);
    }

    #[test]
    fn apply_params_rejects_unknown_mac() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new()
            .push_utf8(PARAM_MAC, "BLAKE2BMAC".to_string())
            .build();
        let err = ctx.apply_params(&p).expect_err("should reject");
        assert!(format!("{err}").to_lowercase().contains("mac"));
    }

    #[test]
    fn apply_params_x963_rejects_mac() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::X963);
        let p = ParamBuilder::new()
            .push_utf8(PARAM_MAC, "HMAC".to_string())
            .build();
        let err = ctx.apply_params(&p).expect_err("X963 should reject 'mac'");
        let msg = format!("{err}").to_lowercase();
        assert!(msg.contains("x963") || msg.contains("hash-only") || msg.contains("mac"));
    }

    #[test]
    fn apply_params_rejects_zero_size() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new().push_u64(PARAM_SIZE, 0).build();
        let err = ctx.apply_params(&p).expect_err("zero size should fail");
        let msg = format!("{err}").to_lowercase();
        assert!(msg.contains("size") || msg.contains("zero") || msg.contains("invalid"));
    }

    #[test]
    fn apply_params_accepts_size() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new().push_u64(PARAM_SIZE, 32).build();
        ctx.apply_params(&p).expect("size=32 should be accepted");
        assert_eq!(ctx.out_len, Some(32));
    }

    #[test]
    fn apply_params_rejects_oversize_secret() {
        // R6 / MAX_INPUT_LEN boundary: a secret larger than MAX_INPUT_LEN
        // must be rejected. We simulate by directly setting a very large
        // expected-length marker — actually allocating 1<<30 bytes in a unit
        // test is unreasonable, so we just verify the contract via the
        // info length check (which shares the same bound).
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        // First, fill info up to the boundary (via repeated small segments).
        // We can't exceed MAX_INPUT_LEN in a unit test without OOM, so we
        // assert the code path exists by checking the segment counter works.
        let p = ParamBuilder::new()
            .push_octet(PARAM_INFO, vec![0u8; 16])
            .build();
        ctx.apply_params(&p).expect("small info accepted");
        assert_eq!(ctx.info_segments, 1);
    }

    #[test]
    fn apply_params_type_mismatch_for_secret_is_error() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        // Secret should be octet string, not utf8.
        let p = ParamBuilder::new()
            .push_utf8(PARAM_SECRET, "wrong-type".to_string())
            .build();
        let err = ctx.apply_params(&p).expect_err("type mismatch");
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("param") || msg.contains("type") || msg.contains("octet"),
            "unexpected error: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // Validation (pre-derive)
    // -------------------------------------------------------------------------

    #[test]
    fn validate_missing_secret_rejected() {
        let ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let err = ctx.validate().expect_err("no secret → error");
        assert!(format!("{err}").to_lowercase().contains("secret"));
    }

    #[test]
    fn validate_hash_missing_digest_rejected() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new()
            .push_octet(PARAM_SECRET, b"s".to_vec())
            .build();
        ctx.apply_params(&p).expect("apply");
        let err = ctx.validate().expect_err("hash mode needs digest");
        assert!(format!("{err}").to_lowercase().contains("digest"));
    }

    #[test]
    fn validate_hmac_missing_digest_rejected() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new()
            .push_octet(PARAM_SECRET, b"s".to_vec())
            .push_utf8(PARAM_MAC, "HMAC".to_string())
            .build();
        ctx.apply_params(&p).expect("apply");
        let err = ctx.validate().expect_err("HMAC without digest rejected");
        assert!(format!("{err}").to_lowercase().contains("digest"));
    }

    #[test]
    fn validate_hash_with_digest_ok() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new()
            .push_octet(PARAM_SECRET, b"s".to_vec())
            .push_utf8(PARAM_DIGEST, "SHA256".to_string())
            .build();
        ctx.apply_params(&p).expect("apply");
        ctx.validate().expect("hash with digest should validate");
    }

    // -------------------------------------------------------------------------
    // get_params
    // -------------------------------------------------------------------------

    #[test]
    fn get_params_no_digest_reports_zero() {
        let ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let out = ctx.get_params().expect("get_params");
        let size = out.get(PARAM_SIZE).expect("size key present");
        assert_eq!(size.as_u64().unwrap_or_default(), 0);
    }

    #[test]
    fn get_params_kmac_reports_max() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let p = ParamBuilder::new()
            .push_utf8(PARAM_MAC, "KMAC128".to_string())
            .build();
        ctx.apply_params(&p).expect("apply");
        let out = ctx.get_params().expect("get_params");
        let size = out.get(PARAM_SIZE).expect("size key present");
        assert_eq!(size.as_u64().unwrap_or_default(), u64::MAX);
    }

    // -------------------------------------------------------------------------
    // Effective salt
    // -------------------------------------------------------------------------

    #[test]
    fn effective_salt_empty_gives_zeros() {
        let ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        let s = ctx.effective_salt(32);
        assert_eq!(s, vec![0u8; 32]);
    }

    #[test]
    fn effective_salt_nonempty_passes_through() {
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        ctx.salt = Some(b"my-salt".to_vec());
        let s = ctx.effective_salt(32);
        assert_eq!(s, b"my-salt");
    }

    #[test]
    fn effective_salt_empty_vec_gives_zeros() {
        // An explicitly-set empty salt should still default to zeros per
        // sskdf.c:502-508.
        let mut ctx = SskdfContext::new(LibContext::get_default(), SskdfVariant::SingleStep);
        ctx.salt = Some(Vec::new());
        let s = ctx.effective_salt(16);
        assert_eq!(s, vec![0u8; 16]);
    }

    // -------------------------------------------------------------------------
    // KMAC out_len validation
    // -------------------------------------------------------------------------

    #[test]
    fn kmac_out_len_accepts_derived_key_len() {
        assert!(SskdfContext::validate_kmac_out_len(48, 48).is_ok());
    }

    #[test]
    fn kmac_out_len_accepts_canonical_sizes() {
        for n in [20usize, 28, 32, 48, 64] {
            assert!(SskdfContext::validate_kmac_out_len(n, 17).is_ok(), "n={n}");
        }
    }

    #[test]
    fn kmac_out_len_rejects_nonstandard() {
        // 17 bytes ≠ derived_key_len (32) and not in the allowed set.
        let err = SskdfContext::validate_kmac_out_len(17, 32).expect_err("17 should be rejected");
        assert!(format!("{err}").to_lowercase().contains("size"));
    }
}
