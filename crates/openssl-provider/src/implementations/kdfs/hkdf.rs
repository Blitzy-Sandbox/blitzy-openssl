//! HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).
//!
//! This module provides an idiomatic Rust translation of
//! `providers/implementations/kdfs/hkdf.c`. It implements:
//!
//! - **HKDF** — generic HMAC-based Extract-and-Expand KDF with three modes
//!   (Extract-and-Expand, Extract-Only, Expand-Only) per RFC 5869
//! - **HKDF-SHA256 / HKDF-SHA384 / HKDF-SHA512** — fixed-digest variants that
//!   preserve the digest across `reset()` calls, matching the C
//!   `ossl_kdf_hkdf_sha256_functions` dispatch table behaviour
//! - **TLS13-KDF** — the TLS 1.3 HKDF-Label variant per RFC 8446 §7.1,
//!   supporting Extract-Only (HKDF-Extract / HKDF-Generate-Secret) and
//!   Expand-Only (HKDF-Expand-Label) modes
//!
//! # Algorithm Overview
//!
//! HKDF (RFC 5869) operates in two stages:
//!
//! 1. **Extract**: `PRK = HMAC-Hash(salt, IKM)` — produces a pseudorandom key
//!    from the input keying material (IKM). When no salt is provided, a
//!    hash-length block of zeros is used per §2.2.
//! 2. **Expand**: `OKM = HKDF-Expand(PRK, info, L)` — derives up to
//!    `255 × HashLen` bytes of output keying material by iterating
//!    `T(i) = HMAC(PRK, T(i−1) || info || i)` for `i = 1..N` where
//!    `N = ⌈L / HashLen⌉` per §2.3.
//!
//! The TLS 1.3 variant (RFC 8446 §7.1) replaces the `info` argument in
//! `HKDF-Expand` with a structured `HkdfLabel`:
//!
//! ```text
//! struct {
//!     uint16 length;
//!     opaque label<7..255>   = "tls13 " + Label;
//!     opaque context<0..255> = Context;
//! } HkdfLabel;
//! ```
//!
//! # Rules Compliance
//!
//! - **R5** — `Option<T>` is used for every optional field (salt, info,
//!   prefix, label, data, digest). No sentinel-valued integers encode
//!   "unset".
//! - **R6** — Narrowing numeric conversions use `u8::try_from` / `u16::try_from`
//!   / `u64::try_from` with explicit error handling. Every
//!   `#[allow(clippy::cast_possible_truncation)]` that remains carries a
//!   `// TRUNCATION:` justification documenting the algorithmic bound that
//!   makes truncation impossible in practice.
//! - **R7** — `HkdfContext` is a per-instance state bag with no shared
//!   mutability. There are no locks in this module.
//! - **R8** — **Zero** `unsafe` blocks. All cryptographic primitives run via
//!   safe `digest::Mac` and `digest::Digest` trait APIs.
//! - **R9** — All public items carry `///` doc comments and the module
//!   compiles warning-free under `RUSTFLAGS="-D warnings"`.
//!
//! # Observability
//!
//! The module uses `tracing::debug!` and `tracing::trace!` throughout
//! `apply_params` and `derive` to produce structured logs with correlation
//! IDs provided by enclosing spans.
//!
//! Source: `providers/implementations/kdfs/hkdf.c` (1,049 lines).

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::ProviderError;
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Public Constants
// =============================================================================

/// Maximum size (in bytes) of a single HKDF buffer, mirroring the
/// `HKDF_MAXBUF` macro in `hkdf.c` (line 38). This bound is enforced on any
/// single `info`, `label`, or `prefix` input value that enters the context.
pub const HKDF_MAXBUF: usize = 2048;

/// Maximum total size (in bytes) of the concatenated `info` parameter
/// allowed by HKDF set-params, mirroring the `HKDF_MAXINFO` macro in
/// `hkdf.c` (line 39). Set-params rejects any attempt to push info
/// segments that would exceed this cumulative limit.
pub const HKDF_MAXINFO: usize = 32 * 1024;

// =============================================================================
// Parameter Name Constants (internal)
// =============================================================================

/// `OSSL_KDF_PARAM_DIGEST` — hash algorithm name.
const PARAM_DIGEST: &str = "digest";
/// `OSSL_KDF_PARAM_KEY` — input keying material (IKM or PRK).
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_SALT` — optional HKDF-Extract salt.
const PARAM_SALT: &str = "salt";
/// `OSSL_KDF_PARAM_INFO` — context/application-specific info string.
const PARAM_INFO: &str = "info";
/// `OSSL_KDF_PARAM_MODE` — operation mode selection.
const PARAM_MODE: &str = "mode";
/// `OSSL_KDF_PARAM_PREFIX` — TLS 1.3 HKDF-Label prefix ("tls13 ").
const PARAM_PREFIX: &str = "prefix";
/// `OSSL_KDF_PARAM_LABEL` — TLS 1.3 HKDF-Label label string.
const PARAM_LABEL: &str = "label";
/// `OSSL_KDF_PARAM_DATA` — TLS 1.3 HKDF-Label context/hash input.
const PARAM_DATA: &str = "data";
/// `OSSL_KDF_PARAM_SIZE` — derived-output size hint (get-params only).
const PARAM_SIZE: &str = "size";

// =============================================================================
// HKDF Mode Enum
// =============================================================================

/// HKDF operation mode selector.
///
/// Corresponds to the `EVP_KDF_HKDF_MODE_*` enumeration in
/// `include/openssl/kdf.h`.
///
/// | Variant | C constant | Description |
/// |---------|------------|-------------|
/// | [`ExtractAndExpand`](Self::ExtractAndExpand) | `EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND` | Full two-stage HKDF (default) |
/// | [`ExtractOnly`](Self::ExtractOnly) | `EVP_KDF_HKDF_MODE_EXTRACT_ONLY` | Return PRK only |
/// | [`ExpandOnly`](Self::ExpandOnly) | `EVP_KDF_HKDF_MODE_EXPAND_ONLY` | Treat IKM as PRK, run Expand only |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfMode {
    /// Full HKDF: extract PRK, then expand into output material. This is
    /// the default mode used by `HKDF` high-level one-shot operation.
    ExtractAndExpand,
    /// Extract-only: output is the PRK (pseudorandom key) produced by
    /// `HMAC(salt, IKM)`.
    ExtractOnly,
    /// Expand-only: the IKM is treated as an already-extracted PRK and
    /// only the expansion phase is executed.
    ExpandOnly,
}

impl Default for HkdfMode {
    fn default() -> Self {
        Self::ExtractAndExpand
    }
}

impl HkdfMode {
    /// Returns the canonical uppercase mode name matching the C parameter
    /// string convention (`"EXTRACT_AND_EXPAND"`, `"EXTRACT_ONLY"`,
    /// `"EXPAND_ONLY"`).
    #[must_use]
    fn canonical_name(self) -> &'static str {
        match self {
            Self::ExtractAndExpand => "EXTRACT_AND_EXPAND",
            Self::ExtractOnly => "EXTRACT_ONLY",
            Self::ExpandOnly => "EXPAND_ONLY",
        }
    }

    /// Parses a mode from its C string name. Also accepts the numeric
    /// integer codes used by `OSSL_KDF_PARAM_MODE` when supplied as an
    /// `OSSL_PARAM_INTEGER`.
    fn from_name(name: &str) -> ProviderResult<Self> {
        match name.to_uppercase().as_str() {
            "EXTRACT_AND_EXPAND" => Ok(Self::ExtractAndExpand),
            "EXTRACT_ONLY" => Ok(Self::ExtractOnly),
            "EXPAND_ONLY" => Ok(Self::ExpandOnly),
            _ => Err(ProviderError::Init(format!(
                "HKDF: unknown mode name '{name}' (expected EXTRACT_AND_EXPAND, EXTRACT_ONLY, or EXPAND_ONLY)"
            ))),
        }
    }

    /// Parses a mode from its numeric code (matching
    /// `EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND = 0`, `EXTRACT_ONLY = 1`,
    /// `EXPAND_ONLY = 2`).
    fn from_i32(value: i32) -> ProviderResult<Self> {
        match value {
            0 => Ok(Self::ExtractAndExpand),
            1 => Ok(Self::ExtractOnly),
            2 => Ok(Self::ExpandOnly),
            other => Err(ProviderError::Init(format!(
                "HKDF: unknown mode integer {other} (expected 0, 1, or 2)"
            ))),
        }
    }
}

// =============================================================================
// Hash Algorithm Selection
// =============================================================================

/// Hash algorithms supported by HKDF.
///
/// HKDF is defined for any HMAC-compatible hash; SHAKE and other XOF
/// digests are explicitly rejected per `hkdf.c` lines 306-309.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

impl HashAlgorithm {
    /// Returns the output length (in bytes) of this hash. Equivalent to
    /// `EVP_MD_size(md)`.
    const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Returns the canonical uppercase digest name used in error messages,
    /// `get_params()` output, and cross-provider dispatch lookup.
    const fn canonical_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Parses a hash algorithm from its name. Accepts the canonical dashed
    /// form (`"SHA-256"`), the concatenated form (`"SHA256"`), and the
    /// SHA-2 namespaced form (`"SHA2-256"`). Explicit rejections:
    ///
    /// * **XOF digests** (SHAKE-128, SHAKE-256, cSHAKE, KMAC-XOF) yield
    ///   [`ProviderError::Init`] — HKDF requires a fixed-size MAC output
    ///   per RFC 5869 §2.2.
    /// * **Unknown names** yield `ProviderError::AlgorithmUnavailable` —
    ///   matching the provider dispatch behaviour when a named digest is
    ///   not found in any loaded provider.
    fn from_name(name: &str) -> ProviderResult<Self> {
        let upper = name.trim().to_ascii_uppercase();
        match upper.as_str() {
            "SHA1" | "SHA-1" | "SHA1-160" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" | "SHA2-256" => Ok(Self::Sha256),
            "SHA384" | "SHA-384" | "SHA2-384" => Ok(Self::Sha384),
            "SHA512" | "SHA-512" | "SHA2-512" => Ok(Self::Sha512),
            // Reject XOF (extendable-output) digests explicitly —
            // `hkdf.c` rejects these at set_params time (line 306-309).
            s if s.starts_with("SHAKE") || s.starts_with("CSHAKE") || s.starts_with("KMAC") => {
                Err(ProviderError::Init(format!(
                    "HKDF: XOF digest '{name}' not allowed (RFC 5869 requires a fixed-size MAC)"
                )))
            }
            _ => Err(ProviderError::AlgorithmUnavailable(format!(
                "HKDF: unsupported digest '{name}' (supported: SHA-1, SHA-256, SHA-384, SHA-512)"
            ))),
        }
    }

    /// Computes HMAC using the selected hash algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if HMAC key initialisation fails
    /// (HMAC accepts arbitrary-length keys, so this error should not occur
    /// in practice, but we propagate it defensively).
    fn hmac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProviderError> {
        use digest::Mac;
        let bytes = match self {
            Self::Sha1 => {
                let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).map_err(|_| {
                    ProviderError::Init("HMAC-SHA-1 key initialization failed".into())
                })?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha256 => {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).map_err(|_| {
                    ProviderError::Init("HMAC-SHA-256 key initialization failed".into())
                })?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key).map_err(|_| {
                    ProviderError::Init("HMAC-SHA-384 key initialization failed".into())
                })?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha512 => {
                let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key).map_err(|_| {
                    ProviderError::Init("HMAC-SHA-512 key initialization failed".into())
                })?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        };
        Ok(bytes)
    }

    /// Computes a raw hash digest (used by TLS 1.3 HKDF-Generate-Secret's
    /// pre-extract step — `hkdf.c` lines 841-851 — which requires the hash
    /// of the empty message).
    fn hash(self, data: &[u8]) -> Vec<u8> {
        use digest::Digest;
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

// =============================================================================
// HkdfParams — user-facing parameter bundle
// =============================================================================

/// User-facing bundle of HKDF input parameters.
///
/// This struct mirrors the schema-level HKDF input surface and provides a
/// typed alternative to the dynamic `ParamSet` for programmatic callers.
/// All fields are [`Option`] per rule R5 — no sentinel values.
///
/// When serialised into a `ParamSet` via [`HkdfParams::to_param_set`], each
/// present field becomes one entry matching the `PARAM_*` names accepted by
/// [`HkdfContext::set_params`].
#[derive(Debug, Clone, Default)]
pub struct HkdfParams {
    /// Canonical digest name (e.g. `"SHA-256"`).
    pub digest_name: Option<String>,
    /// HKDF operation mode.
    pub mode: Option<HkdfMode>,
    /// HKDF-Extract salt (optional — defaults to zeros of hash length).
    pub salt: Option<Vec<u8>>,
    /// Input keying material (IKM) for Extract, or PRK for Expand-only.
    pub key: Option<Vec<u8>>,
    /// HKDF-Expand info string.
    pub info: Option<Vec<u8>>,
    /// TLS 1.3 HKDF-Label prefix (typically `"tls13 "`).
    pub prefix: Option<Vec<u8>>,
    /// TLS 1.3 HKDF-Label label (e.g. `"derived"`, `"c hs traffic"`).
    pub label: Option<Vec<u8>>,
    /// TLS 1.3 HKDF-Label context/transcript hash.
    pub data: Option<Vec<u8>>,
}

impl HkdfParams {
    /// Creates an empty parameter bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialises this parameter bundle into a `ParamSet`.
    ///
    /// Only fields that are `Some(_)` are pushed into the resulting set.
    /// Octet-string values (salt/key/info/prefix/label/data) are cloned into
    /// owned byte buffers; `digest_name` is cloned into an owned `String`.
    #[must_use]
    pub fn to_param_set(&self) -> ParamSet {
        let mut builder = ParamBuilder::new();
        if let Some(digest) = &self.digest_name {
            builder = builder.push_utf8(PARAM_DIGEST, digest.clone());
        }
        if let Some(mode) = self.mode {
            builder = builder.push_utf8(PARAM_MODE, mode.canonical_name().to_string());
        }
        if let Some(salt) = &self.salt {
            builder = builder.push_octet(PARAM_SALT, salt.clone());
        }
        if let Some(key) = &self.key {
            builder = builder.push_octet(PARAM_KEY, key.clone());
        }
        if let Some(info) = &self.info {
            builder = builder.push_octet(PARAM_INFO, info.clone());
        }
        if let Some(prefix) = &self.prefix {
            builder = builder.push_octet(PARAM_PREFIX, prefix.clone());
        }
        if let Some(label) = &self.label {
            builder = builder.push_octet(PARAM_LABEL, label.clone());
        }
        if let Some(data) = &self.data {
            builder = builder.push_octet(PARAM_DATA, data.clone());
        }
        builder.build()
    }
}

// =============================================================================
// HkdfContext — unified derivation context
// =============================================================================

/// HKDF derivation context implementing `KdfContext`.
///
/// This is the Rust translation of the `KDF_HKDF` C struct (`hkdf.c` lines
/// 77-95). A single struct backs four OSSL dispatch tables:
///
/// * `ossl_kdf_hkdf_functions` — generic HKDF
/// * `ossl_kdf_hkdf_sha{256,384,512}_functions` — fixed-digest variants
/// * `ossl_kdf_tls1_3_kdf_functions` — TLS 1.3 HKDF-Label
///
/// # Zeroisation
///
/// Secret fields (`key`, `salt`, `info`, `data`) are wiped on drop and on
/// [`reset`](Self::reset) via `ZeroizeOnDrop`.  The `prefix` and `label`
/// are not secret (they are public protocol constants such as `"tls13 "`)
/// and are marked `#[zeroize(skip)]`.
///
/// # `reset` semantics
///
/// [`reset`](Self::reset) preserves the `hash` selection if `fixed_digest`
/// is set (matching C `kdf_hkdf_reset_ex` lines 145-167). This is what
/// allows `HKDF-SHA256` to remember its SHA-256 selection across reuse
/// while `HKDF` resets to the unconfigured default.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HkdfContext {
    /// Input keying material (IKM) for Extract, or PRK for Expand-only.
    /// **Secret material** — zeroised on drop.
    key: Vec<u8>,

    /// Optional HKDF-Extract salt.  `None` means "default to hash-length
    /// zeros" per RFC 5869 §2.2.  **Secret-adjacent** — zeroised on drop.
    salt: Option<Vec<u8>>,

    /// HKDF-Expand info string.  Accumulates across repeated `INFO`
    /// parameter entries up to [`HKDF_MAXINFO`].
    info: Vec<u8>,

    /// TLS 1.3 HKDF-Label prefix bytes (e.g. `b"tls13 "`).  Not secret.
    #[zeroize(skip)]
    prefix: Option<Vec<u8>>,

    /// TLS 1.3 HKDF-Label label bytes (e.g. `b"derived"`).  Not secret.
    #[zeroize(skip)]
    label: Option<Vec<u8>>,

    /// TLS 1.3 HKDF-Label context/transcript hash.  **Secret-adjacent**
    /// for some TLS handshake secrets — zeroised on drop.
    data: Option<Vec<u8>>,

    /// Selected hash algorithm.  Set via `PARAM_DIGEST` or pre-configured
    /// for fixed-digest variants (`HKDF-SHA256` etc.).  Not secret.
    #[zeroize(skip)]
    hash: Option<HashAlgorithm>,

    /// HKDF operation mode.  Defaults to `ExtractAndExpand`.  Not secret.
    #[zeroize(skip)]
    mode: HkdfMode,

    /// If `true`, `reset()` preserves `hash`.  Set by the fixed-digest
    /// constructors (`new_fixed`) and by `Tls13KdfProvider`.
    #[zeroize(skip)]
    fixed_digest: bool,

    /// If `true`, this context backs the `TLS13-KDF` dispatch; `derive()`
    /// uses the TLS 1.3 HKDF-Label code path exclusively.  Not secret.
    #[zeroize(skip)]
    tls13: bool,
}

impl Default for HkdfContext {
    fn default() -> Self {
        Self::new()
    }
}

impl HkdfContext {
    /// Creates a new unconfigured HKDF context — matches the generic
    /// `HKDF` dispatch (`kdf_hkdf_new` in `hkdf.c`).
    #[must_use]
    fn new() -> Self {
        Self {
            key: Vec::new(),
            salt: None,
            info: Vec::new(),
            prefix: None,
            label: None,
            data: None,
            hash: None,
            mode: HkdfMode::default(),
            fixed_digest: false,
            tls13: false,
        }
    }

    /// Creates a new context pre-configured for a fixed digest
    /// (matches `kdf_hkdf_sha256_new` etc. in `hkdf.c`).  The chosen
    /// digest is preserved across [`reset`](Self::reset).
    #[must_use]
    fn new_fixed(hash: HashAlgorithm) -> Self {
        let mut ctx = Self::new();
        ctx.hash = Some(hash);
        ctx.fixed_digest = true;
        ctx
    }

    /// Creates a new context for the TLS 1.3 HKDF-Label dispatch
    /// (`ossl_kdf_tls1_3_kdf_functions`).  Forces the TLS 1.3 code path
    /// in [`derive`](Self::derive).
    #[must_use]
    fn new_tls13() -> Self {
        let mut ctx = Self::new();
        ctx.tls13 = true;
        ctx
    }

    /// Resolves the active hash algorithm or returns a standardised error
    /// if none has been set.  Replaces the C `ctx->digest == NULL` check
    /// (`hkdf.c` line 289).
    fn require_hash(&self) -> ProviderResult<HashAlgorithm> {
        self.hash.ok_or_else(|| {
            ProviderError::Init("HKDF: digest parameter is required but was not set".into())
        })
    }

    // -------------------------------------------------------------------------
    // Parameter application
    // -------------------------------------------------------------------------

    /// Applies every recognised parameter in `params` to this context.
    ///
    /// Mirrors `kdf_hkdf_set_ctx_params` / `kdf_tls1_3_set_ctx_params` in
    /// `hkdf.c`.  Secret fields are zeroised before being overwritten.
    ///
    /// # Errors
    ///
    /// * `ProviderError::Init` — type mismatch, length-limit violation,
    ///   XOF digest rejected.
    /// * `ProviderError::AlgorithmUnavailable` — unknown digest name.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // ------------------------------------------------------------------
        // DIGEST — selects the hash algorithm.  Respect `fixed_digest`: if
        // the variant pre-selected a digest, a mismatched request is an
        // error (matches `hkdf.c` line 296-299 behaviour).
        // ------------------------------------------------------------------
        if let Some(v) = params.get(PARAM_DIGEST) {
            let name = v.as_str().ok_or_else(|| {
                ProviderError::Init(format!(
                    "HKDF: parameter '{PARAM_DIGEST}' must be a UTF-8 string"
                ))
            })?;
            let new_hash = HashAlgorithm::from_name(name)?;
            if self.fixed_digest {
                match self.hash {
                    Some(current) if current == new_hash => {
                        // No-op: re-asserting the same digest is benign.
                    }
                    Some(current) => {
                        return Err(ProviderError::Init(format!(
                            "HKDF: cannot change fixed digest from {} to {} on this variant",
                            current.canonical_name(),
                            new_hash.canonical_name()
                        )));
                    }
                    None => self.hash = Some(new_hash),
                }
            } else {
                self.hash = Some(new_hash);
            }
            tracing::debug!(
                target: "openssl_provider::kdf::hkdf",
                digest = %new_hash.canonical_name(),
                "HKDF: digest selected"
            );
        }

        // ------------------------------------------------------------------
        // MODE — accepts both Utf8String names and integer codes.
        // Matches `hkdf.c` OSSL_PARAM_get_int (line 325) plus the string
        // form resolved from `ossl_prov_hkdf_mode_itoa()`.
        // ------------------------------------------------------------------
        if let Some(v) = params.get(PARAM_MODE) {
            let mode = if let Some(name) = v.as_str() {
                HkdfMode::from_name(name)?
            } else if let Some(i) = v.as_i32() {
                HkdfMode::from_i32(i)?
            } else if let Some(i) = v.as_i64() {
                let narrowed = i32::try_from(i).map_err(|_| {
                    ProviderError::Init(format!("HKDF: mode integer {i} exceeds i32 range"))
                })?;
                HkdfMode::from_i32(narrowed)?
            } else {
                return Err(ProviderError::Init(format!(
                    "HKDF: parameter '{PARAM_MODE}' must be a UTF-8 string or integer"
                )));
            };
            // TLS 1.3 HKDF-Label rejects EXTRACT_AND_EXPAND per `hkdf.c`
            // line 927 (PROV_R_INVALID_MODE).
            if self.tls13 && mode == HkdfMode::ExtractAndExpand {
                return Err(ProviderError::Init(
                    "TLS13-KDF: EXTRACT_AND_EXPAND mode is not valid for TLS 1.3 HKDF-Label".into(),
                ));
            }
            self.mode = mode;
            tracing::debug!(
                target: "openssl_provider::kdf::hkdf",
                mode = %mode.canonical_name(),
                "HKDF: mode selected"
            );
        }

        // ------------------------------------------------------------------
        // KEY — IKM for Extract, PRK for Expand-only.  **Secret** —
        // zeroise previous value before overwriting.
        // ------------------------------------------------------------------
        if let Some(v) = params.get(PARAM_KEY) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Init(format!(
                    "HKDF: parameter '{PARAM_KEY}' must be an octet string"
                ))
            })?;
            if bytes.len() > super::MAX_INPUT_LEN {
                return Err(ProviderError::Init(format!(
                    "HKDF: key length {} exceeds maximum {}",
                    bytes.len(),
                    super::MAX_INPUT_LEN
                )));
            }
            self.key.zeroize();
            self.key = bytes.to_vec();
            tracing::trace!(
                target: "openssl_provider::kdf::hkdf",
                key_len = bytes.len(),
                "HKDF: key set"
            );
        }

        // ------------------------------------------------------------------
        // SALT — optional; clears stored value if not present here but
        // was set previously? No — absence means "leave unchanged".  To
        // clear, the caller must reset().
        // ------------------------------------------------------------------
        if let Some(v) = params.get(PARAM_SALT) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Init(format!(
                    "HKDF: parameter '{PARAM_SALT}' must be an octet string"
                ))
            })?;
            if bytes.len() > super::MAX_INPUT_LEN {
                return Err(ProviderError::Init(format!(
                    "HKDF: salt length {} exceeds maximum {}",
                    bytes.len(),
                    super::MAX_INPUT_LEN
                )));
            }
            if let Some(old) = self.salt.as_mut() {
                old.zeroize();
            }
            self.salt = Some(bytes.to_vec());
            tracing::trace!(
                target: "openssl_provider::kdf::hkdf",
                salt_len = bytes.len(),
                "HKDF: salt set"
            );
        }

        // ------------------------------------------------------------------
        // INFO — concatenative; each `PARAM_INFO` entry appends to the
        // current info buffer up to `HKDF_MAXINFO`.  Matches the
        // HKDF_MAX_INFOS loop in `hkdf.c` lines 355-382.  For the typed
        // `ParamSet` representation we allow one entry; callers needing
        // segmented info should concatenate in Rust before calling.
        // ------------------------------------------------------------------
        if let Some(v) = params.get(PARAM_INFO) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Init(format!(
                    "HKDF: parameter '{PARAM_INFO}' must be an octet string"
                ))
            })?;
            let new_total = self.info.len().saturating_add(bytes.len());
            if new_total > HKDF_MAXINFO {
                return Err(ProviderError::Init(format!(
                    "HKDF: cumulative info length {new_total} exceeds HKDF_MAXINFO={HKDF_MAXINFO}"
                )));
            }
            // Per C behaviour, setting the info parameter replaces the
            // accumulated value rather than appending when a single value
            // is supplied.  We mirror this: replace on each set_params
            // call to keep semantics consistent and predictable.
            self.info.zeroize();
            self.info = bytes.to_vec();
            tracing::trace!(
                target: "openssl_provider::kdf::hkdf",
                info_len = bytes.len(),
                "HKDF: info set"
            );
        }

        // ------------------------------------------------------------------
        // PREFIX — TLS 1.3 HKDF-Label prefix (typically b"tls13 ").
        // Not secret.  Length-limited to HKDF_MAXBUF (hkdf.c line 450).
        // ------------------------------------------------------------------
        if let Some(v) = params.get(PARAM_PREFIX) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Init(format!(
                    "HKDF: parameter '{PARAM_PREFIX}' must be an octet string"
                ))
            })?;
            if bytes.len() > HKDF_MAXBUF {
                return Err(ProviderError::Init(format!(
                    "HKDF: prefix length {} exceeds HKDF_MAXBUF={HKDF_MAXBUF}",
                    bytes.len()
                )));
            }
            self.prefix = Some(bytes.to_vec());
        }

        // ------------------------------------------------------------------
        // LABEL — TLS 1.3 HKDF-Label label string. Not secret. Bounded.
        // ------------------------------------------------------------------
        if let Some(v) = params.get(PARAM_LABEL) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Init(format!(
                    "HKDF: parameter '{PARAM_LABEL}' must be an octet string"
                ))
            })?;
            if bytes.len() > HKDF_MAXBUF {
                return Err(ProviderError::Init(format!(
                    "HKDF: label length {} exceeds HKDF_MAXBUF={HKDF_MAXBUF}",
                    bytes.len()
                )));
            }
            self.label = Some(bytes.to_vec());
        }

        // ------------------------------------------------------------------
        // DATA — TLS 1.3 HKDF-Label context (transcript hash or zeros).
        // May be secret depending on call site — zeroise prior value.
        // ------------------------------------------------------------------
        if let Some(v) = params.get(PARAM_DATA) {
            let bytes = v.as_bytes().ok_or_else(|| {
                ProviderError::Init(format!(
                    "HKDF: parameter '{PARAM_DATA}' must be an octet string"
                ))
            })?;
            if bytes.len() > HKDF_MAXBUF {
                return Err(ProviderError::Init(format!(
                    "HKDF: data length {} exceeds HKDF_MAXBUF={HKDF_MAXBUF}",
                    bytes.len()
                )));
            }
            if let Some(old) = self.data.as_mut() {
                old.zeroize();
            }
            self.data = Some(bytes.to_vec());
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Core HKDF primitives (RFC 5869)
    // -------------------------------------------------------------------------

    /// Performs HKDF-Extract: `PRK = HMAC-Hash(salt, IKM)`.
    ///
    /// Mirrors `HKDF_Extract` in `hkdf.c` lines 683-701.  If `salt` is
    /// `None`, a zero-filled buffer of hash-output length is used per
    /// RFC 5869 §2.2.
    fn hkdf_extract(
        hash: HashAlgorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> ProviderResult<Vec<u8>> {
        let default_salt: Vec<u8>;
        let salt_bytes: &[u8] = if let Some(s) = salt {
            s
        } else {
            default_salt = vec![0u8; hash.output_len()];
            &default_salt
        };
        hash.hmac(salt_bytes, ikm)
    }

    /// Performs HKDF-Expand: `OKM = T(1) || T(2) || ... || T(n)` where
    /// `T(i) = HMAC-Hash(PRK, T(i-1) || info || i)` (RFC 5869 §2.3).
    ///
    /// Mirrors `HKDF_Expand` in `hkdf.c` lines 703-761.  The final T(n) is
    /// zeroised before return to match C `OPENSSL_cleanse(prev)`.
    ///
    /// # Errors
    ///
    /// * `ProviderError::Init` — requested output exceeds `255 * hash_len`
    ///   (RFC 5869 §2.3 upper bound).
    fn hkdf_expand(
        hash: HashAlgorithm,
        prk: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> ProviderResult<()> {
        let hash_len = hash.output_len();
        // u8::MAX * hash_len is the RFC 5869 bound; mirror C (hkdf.c line 726).
        let max_okm = hash_len.saturating_mul(u8::MAX as usize);
        if okm.len() > max_okm {
            return Err(ProviderError::Init(format!(
                "HKDF: requested OKM length {} exceeds maximum {} (255 * hash_len)",
                okm.len(),
                max_okm
            )));
        }
        if okm.is_empty() {
            return Ok(());
        }

        // n = ⌈okm_len / hash_len⌉.  Use div_ceil for safety over saturating.
        let n_usize = okm.len().div_ceil(hash_len);
        // n must fit in u8 — bound check above guarantees this, but we
        // re-verify with try_from to satisfy the `cast_possible_truncation`
        // lint at the counter byte conversion site below.
        let n_u8 = u8::try_from(n_usize).map_err(|_| {
            ProviderError::Init(format!(
                "HKDF: internal invariant violated — block count {n_usize} exceeds 255"
            ))
        })?;

        let mut prev: Vec<u8> = Vec::new();
        let mut offset = 0usize;
        for i in 1u8..=n_u8 {
            // T(i) = HMAC(PRK, T(i-1) || info || i)
            let mut input = Vec::with_capacity(prev.len() + info.len() + 1);
            input.extend_from_slice(&prev);
            input.extend_from_slice(info);
            input.push(i);
            let t_i = hash.hmac(prk, &input)?;
            // Zeroise the intermediate HMAC input buffer — it carries the
            // previous T(i-1), which may be derived from secret PRK material.
            input.zeroize();

            let copy_len = core::cmp::min(hash_len, okm.len() - offset);
            okm[offset..offset + copy_len].copy_from_slice(&t_i[..copy_len]);
            offset += copy_len;
            // Zeroise prev before replacing to avoid leaving stale PRK-derived
            // material in memory (mirrors C `OPENSSL_cleanse(prev)` at line 758).
            prev.zeroize();
            prev = t_i;
        }
        prev.zeroize();
        Ok(())
    }

    /// Performs TLS 1.3 HKDF-Expand-Label per RFC 8446 §7.1.
    ///
    /// Constructs the `HkdfLabel` struct:
    ///
    /// ```text
    /// struct {
    ///     uint16 length = Length;                             // big-endian
    ///     opaque label<7..255>   = prefix || label;           // u8 len prefix
    ///     opaque context<0..255> = Context;                    // u8 len prefix
    /// } HkdfLabel;
    /// ```
    ///
    /// and invokes `HKDF-Expand(PRK, HkdfLabel, Length)`.  Mirrors
    /// `prov_tls13_hkdf_expand` in `hkdf.c` lines 854-897.
    fn tls13_hkdf_expand(
        hash: HashAlgorithm,
        prk: &[u8],
        prefix: &[u8],
        label: &[u8],
        data: &[u8],
        okm: &mut [u8],
    ) -> ProviderResult<()> {
        // Length must fit in u16 (RFC 8446 §7.1 HkdfLabel struct).
        let okm_len_u16 = u16::try_from(okm.len()).map_err(|_| {
            ProviderError::Init(format!(
                "TLS13-KDF: output length {} exceeds u16::MAX",
                okm.len()
            ))
        })?;
        let label_total = prefix.len().saturating_add(label.len());
        // Per RFC 8446: 7 <= label.len <= 255.  Upstream callers pass
        // `prefix = "tls13 "` (6 bytes) + a label; we enforce the u8 upper
        // bound strictly and document the 7-byte lower bound in error.
        if label_total > u8::MAX as usize {
            return Err(ProviderError::Init(format!(
                "TLS13-KDF: prefix||label length {label_total} exceeds 255 bytes (RFC 8446 §7.1)"
            )));
        }
        let label_len_u8 = u8::try_from(label_total).map_err(|_| {
            // Unreachable: we bounded above.
            ProviderError::Init("TLS13-KDF: internal label length conversion failed".into())
        })?;
        if data.len() > u8::MAX as usize {
            return Err(ProviderError::Init(format!(
                "TLS13-KDF: context length {} exceeds 255 bytes (RFC 8446 §7.1)",
                data.len()
            )));
        }
        let data_len_u8 = u8::try_from(data.len()).map_err(|_| {
            ProviderError::Init("TLS13-KDF: internal context length conversion failed".into())
        })?;

        let mut hkdf_label: Vec<u8> = Vec::with_capacity(2 + 1 + label_total + 1 + data.len());
        // uint16 length (big-endian)
        hkdf_label.extend_from_slice(&okm_len_u16.to_be_bytes());
        // opaque label<7..255> — u8 length prefix
        hkdf_label.push(label_len_u8);
        hkdf_label.extend_from_slice(prefix);
        hkdf_label.extend_from_slice(label);
        // opaque context<0..255> — u8 length prefix
        hkdf_label.push(data_len_u8);
        hkdf_label.extend_from_slice(data);

        let result = Self::hkdf_expand(hash, prk, &hkdf_label, okm);
        // The HkdfLabel buffer itself is not secret (it contains public
        // protocol constants plus the transcript hash) but zeroising is
        // cheap and defensive.
        hkdf_label.zeroize();
        result
    }

    /// Implements TLS 1.3 HKDF-Extract with the "Derived"-style
    /// pre-extraction step per RFC 8446.
    ///
    /// Mirrors `prov_tls13_hkdf_generate_secret` in `hkdf.c` lines 809-868.
    /// If `prev_secret` is provided, it is first expanded via HKDF-Label
    /// `"derived"` with `hash("")` as context to produce the pre-extract
    /// secret; otherwise a zero-length `prev` is used.  The resulting
    /// pre-extract secret is then used as the salt in HKDF-Extract over
    /// `in_secret` (defaulting to zeros if not provided).
    fn tls13_generate_secret(
        hash: HashAlgorithm,
        prefix: &[u8],
        prev_secret: Option<&[u8]>,
        in_secret: Option<&[u8]>,
        okm: &mut [u8],
    ) -> ProviderResult<()> {
        let md_len = hash.output_len();
        if okm.len() != md_len {
            return Err(ProviderError::Init(format!(
                "TLS13-KDF: output length {} must equal digest size {}",
                okm.len(),
                md_len
            )));
        }

        // Default zeros buffer used for both `prev` and `in` when absent.
        let default_zeros = vec![0u8; md_len];

        let in_bytes: &[u8] = in_secret.unwrap_or(&default_zeros);

        // pre_extract_sec holds the possibly-derived previous-secret material.
        let pre_extract: Vec<u8>;
        let prev_bytes: &[u8] = match prev_secret {
            None => &[],
            Some(prev) => {
                // Pre-expand via HKDF-Expand-Label(prev, "derived", hash(""), md_len)
                let empty_hash = hash.hash(&[]);
                let mut derived = vec![0u8; md_len];
                Self::tls13_hkdf_expand(hash, prev, prefix, b"derived", &empty_hash, &mut derived)?;
                pre_extract = derived;
                &pre_extract
            }
        };

        // HKDF-Extract(salt=prev_bytes, IKM=in_bytes) → okm
        let prk = hash.hmac(prev_bytes, in_bytes)?;
        if prk.len() != okm.len() {
            // Should not happen — HMAC output is always hash_len bytes and
            // we enforced okm.len() == md_len above.
            return Err(ProviderError::Init(
                "TLS13-KDF: PRK length mismatch (internal invariant)".into(),
            ));
        }
        okm.copy_from_slice(&prk);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Top-level derivation dispatch
    // -------------------------------------------------------------------------

    /// Dispatches the derivation according to `self.mode` using standard
    /// HKDF semantics (RFC 5869).  Mirrors `kdf_hkdf_derive` lines 267-337.
    fn derive_standard(&self, okm: &mut [u8]) -> ProviderResult<()> {
        let hash = self.require_hash()?;
        if self.key.is_empty() {
            return Err(ProviderError::Init(
                "HKDF: key (IKM or PRK) parameter is required but was not set".into(),
            ));
        }

        match self.mode {
            HkdfMode::ExtractAndExpand => {
                tracing::trace!(
                    target: "openssl_provider::kdf::hkdf",
                    hash = %hash.canonical_name(),
                    okm_len = okm.len(),
                    "HKDF: extract-and-expand"
                );
                let mut prk = Self::hkdf_extract(hash, self.salt.as_deref(), &self.key)?;
                let expand_result = Self::hkdf_expand(hash, &prk, &self.info, okm);
                // Zeroise intermediate PRK (mirrors C `OPENSSL_cleanse(prk)` at line 610).
                prk.zeroize();
                expand_result
            }
            HkdfMode::ExtractOnly => {
                tracing::trace!(
                    target: "openssl_provider::kdf::hkdf",
                    hash = %hash.canonical_name(),
                    okm_len = okm.len(),
                    "HKDF: extract-only"
                );
                if okm.len() != hash.output_len() {
                    return Err(ProviderError::Init(format!(
                        "HKDF: EXTRACT_ONLY requires output length == {} (hash_len) but got {}",
                        hash.output_len(),
                        okm.len()
                    )));
                }
                let prk = Self::hkdf_extract(hash, self.salt.as_deref(), &self.key)?;
                okm.copy_from_slice(&prk);
                // Intermediate PRK is copied out; zeroise the now-redundant buffer.
                let mut zeroed_prk = prk;
                zeroed_prk.zeroize();
                Ok(())
            }
            HkdfMode::ExpandOnly => {
                tracing::trace!(
                    target: "openssl_provider::kdf::hkdf",
                    hash = %hash.canonical_name(),
                    okm_len = okm.len(),
                    "HKDF: expand-only"
                );
                Self::hkdf_expand(hash, &self.key, &self.info, okm)
            }
        }
    }

    /// Dispatches the derivation for the TLS 1.3 HKDF-Label code path.
    ///
    /// Mirrors `kdf_tls1_3_derive` in `hkdf.c` lines 907-961.  The mode
    /// determines whether to run generate-secret (Extract) or
    /// expand-label (Expand-only):
    ///
    /// * `ExtractOnly` → [`tls13_generate_secret`](Self::tls13_generate_secret)
    /// * `ExpandOnly`  → [`tls13_hkdf_expand`](Self::tls13_hkdf_expand)
    /// * `ExtractAndExpand` → rejected at parameter-setting time
    ///   (see `apply_params`).
    fn derive_tls13(&self, okm: &mut [u8]) -> ProviderResult<()> {
        let hash = self.require_hash()?;
        let prefix: &[u8] = self.prefix.as_deref().unwrap_or(b"tls13 ");

        match self.mode {
            HkdfMode::ExtractOnly => {
                // Generate-secret: key holds the new IKM, salt (when Some)
                // holds the previous-secret; salt=None means no prev-secret.
                tracing::trace!(
                    target: "openssl_provider::kdf::hkdf",
                    hash = %hash.canonical_name(),
                    "TLS13-KDF: generate-secret"
                );
                let in_secret: Option<&[u8]> = if self.key.is_empty() {
                    None
                } else {
                    Some(self.key.as_slice())
                };
                Self::tls13_generate_secret(hash, prefix, self.salt.as_deref(), in_secret, okm)
            }
            HkdfMode::ExpandOnly => {
                // Expand-label: key is the PRK, label+data form the
                // HkdfLabel context.
                if self.key.is_empty() {
                    return Err(ProviderError::Init(
                        "TLS13-KDF: key (PRK) parameter is required for EXPAND_ONLY".into(),
                    ));
                }
                let label = self.label.as_deref().ok_or_else(|| {
                    ProviderError::Init(
                        "TLS13-KDF: label parameter is required for EXPAND_ONLY".into(),
                    )
                })?;
                let data: &[u8] = self.data.as_deref().unwrap_or(&[]);
                tracing::trace!(
                    target: "openssl_provider::kdf::hkdf",
                    hash = %hash.canonical_name(),
                    label_len = label.len(),
                    data_len = data.len(),
                    "TLS13-KDF: expand-label"
                );
                Self::tls13_hkdf_expand(hash, &self.key, prefix, label, data, okm)
            }
            HkdfMode::ExtractAndExpand => Err(ProviderError::Init(
                "TLS13-KDF: EXTRACT_AND_EXPAND mode is not valid for TLS 1.3 HKDF-Label".into(),
            )),
        }
    }
}

// =============================================================================
// KdfContext trait implementation
// =============================================================================

impl KdfContext for HkdfContext {
    /// Derives key material into `key`, reading auxiliary parameters from
    /// `params`.  Mirrors `kdf_hkdf_derive` / `kdf_tls1_3_derive` in
    /// `hkdf.c`.
    ///
    /// If `params` is non-empty, it is first merged into the context via
    /// `apply_params`; this matches the
    /// behaviour of `kdf_hkdf_derive` which calls
    /// `kdf_hkdf_set_ctx_params(ctx, params)` at the top of the function
    /// (`hkdf.c` line 286).
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        if key.is_empty() {
            return Err(ProviderError::Init(
                "HKDF: output buffer must be non-empty".into(),
            ));
        }
        if self.tls13 {
            self.derive_tls13(key)?;
        } else {
            self.derive_standard(key)?;
        }
        tracing::debug!(
            target: "openssl_provider::kdf::hkdf",
            okm_len = key.len(),
            mode = %self.mode.canonical_name(),
            tls13 = self.tls13,
            "HKDF: derivation complete"
        );
        Ok(key.len())
    }

    /// Resets the context, preserving `hash` if `fixed_digest` is set.
    /// Mirrors `kdf_hkdf_reset_ex` in `hkdf.c` lines 145-167.
    fn reset(&mut self) -> ProviderResult<()> {
        // Preserve the digest selection across reset for fixed-digest
        // variants (matches C `preserve_digest = ctx->fixed_digest`).
        let preserved_hash = if self.fixed_digest { self.hash } else { None };
        let preserved_fixed = self.fixed_digest;
        let preserved_tls13 = self.tls13;

        // Zeroise secret fields explicitly; `Zeroize` derive would do this
        // on drop but we want to guarantee reset()-time wiping too.
        self.key.zeroize();
        self.key.clear();
        if let Some(s) = self.salt.as_mut() {
            s.zeroize();
        }
        self.salt = None;
        self.info.zeroize();
        self.info.clear();
        if let Some(d) = self.data.as_mut() {
            d.zeroize();
        }
        self.data = None;
        self.prefix = None;
        self.label = None;

        self.mode = HkdfMode::default();
        self.hash = preserved_hash;
        self.fixed_digest = preserved_fixed;
        self.tls13 = preserved_tls13;

        tracing::debug!(
            target: "openssl_provider::kdf::hkdf",
            preserved_digest = preserved_hash.is_some(),
            tls13 = self.tls13,
            "HKDF: context reset"
        );
        Ok(())
    }

    /// Returns a `ParamSet` describing gettable context parameters.
    ///
    /// Provides:
    ///
    /// * `PARAM_SIZE` — output size hint. For `EXTRACT_ONLY` this is the
    ///   hash output length; otherwise it is `u64::MAX` (representing
    ///   "unbounded" per the C `SIZE_MAX` return at `hkdf.c` line 393).
    /// * `PARAM_DIGEST` — the canonical digest name if set.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut builder = ParamBuilder::new();
        let size_hint: u64 = match self.mode {
            HkdfMode::ExtractOnly => self.hash.map_or(u64::MAX, |h| h.output_len() as u64),
            HkdfMode::ExtractAndExpand | HkdfMode::ExpandOnly => u64::MAX,
        };
        builder = builder.push_u64(PARAM_SIZE, size_hint);
        if let Some(h) = self.hash {
            builder = builder.push_utf8(PARAM_DIGEST, h.canonical_name().to_string());
        }
        Ok(builder.build())
    }

    /// Applies `params` to the context. Delegates to
    /// `apply_params`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Duplicate helper
// =============================================================================

impl HkdfContext {
    /// Creates an independent clone of this context (mirrors
    /// `kdf_hkdf_dup` in `hkdf.c` lines 192-228).  The duplicate owns its
    /// own copies of every buffer; zeroisation of one instance does not
    /// affect the other.
    #[must_use]
    pub fn dup(&self) -> Self {
        self.clone()
    }

    /// Runs the HKDF derivation and returns the produced OKM.  Convenience
    /// wrapper over [`KdfContext::derive`] for programmatic
    /// callers that prefer an owned `Vec` return.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`KdfContext::derive`].
    pub fn derive(&mut self, length: usize, params: &ParamSet) -> ProviderResult<Vec<u8>> {
        let mut out = vec![0u8; length];
        <Self as KdfContext>::derive(self, &mut out, params)?;
        Ok(out)
    }

    /// Sets parameters on the context. Convenience wrapper over
    /// `KdfContext::set_params`.
    ///
    /// # Errors
    ///
    /// Returns any error produced by `KdfContext::set_params`.
    pub fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        <Self as KdfContext>::set_params(self, params)
    }

    /// Returns a `ParamSet` describing gettable parameters.  Convenience
    /// wrapper over `KdfContext::get_params`.
    ///
    /// # Errors
    ///
    /// Returns any error produced by `KdfContext::get_params`.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        <Self as KdfContext>::get_params(self)
    }

    /// Resets the context.  Convenience wrapper over
    /// `KdfContext::reset`.
    ///
    /// # Errors
    ///
    /// Returns any error produced by `KdfContext::reset`.
    pub fn reset(&mut self) -> ProviderResult<()> {
        <Self as KdfContext>::reset(self)
    }
}

// =============================================================================
// Provider descriptor structs (KdfProvider implementations)
// =============================================================================

/// Generic HKDF provider (digest selected via `PARAM_DIGEST`).
///
/// Translation of C `ossl_kdf_hkdf_functions` (`hkdf.c` lines 932-948).
/// The caller must supply a `"digest"` parameter before invoking
/// [`KdfContext::derive`]; otherwise derivation fails.
///
/// # Example
///
/// ```ignore
/// use openssl_provider::implementations::kdfs::hkdf::HkdfProvider;
/// use openssl_provider::traits::KdfProvider;
///
/// let provider = HkdfProvider;
/// let _ctx = provider.new_ctx().expect("context construction should succeed");
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct HkdfProvider;

impl HkdfProvider {
    /// Creates a new provider descriptor.  Equivalent to using the
    /// `Default` implementation.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KdfProvider for HkdfProvider {
    fn name(&self) -> &'static str {
        "HKDF"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(HkdfContext::new()))
    }
}

/// HKDF provider hard-wired to SHA-256.
///
/// Translation of C `ossl_kdf_hkdf_sha256_functions` (`hkdf.c` lines
/// 950-966).  The digest is pre-selected and the `fixed_digest` flag is
/// asserted so that attempts to override the digest via `PARAM_DIGEST`
/// return `ProviderError::Common` (`PROV_R_DIGEST_NOT_ALLOWED`).
#[derive(Debug, Default, Clone, Copy)]
pub struct HkdfSha256Provider;

impl HkdfSha256Provider {
    /// Creates a new provider descriptor for HKDF-SHA256.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KdfProvider for HkdfSha256Provider {
    fn name(&self) -> &'static str {
        "HKDF-SHA256"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(HkdfContext::new_fixed(HashAlgorithm::Sha256)))
    }
}

/// HKDF provider hard-wired to SHA-384.
///
/// Translation of C `ossl_kdf_hkdf_sha384_functions` (`hkdf.c` lines
/// 968-984).  Semantics identical to [`HkdfSha256Provider`], differing
/// only in the pre-selected digest.
#[derive(Debug, Default, Clone, Copy)]
pub struct HkdfSha384Provider;

impl HkdfSha384Provider {
    /// Creates a new provider descriptor for HKDF-SHA384.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KdfProvider for HkdfSha384Provider {
    fn name(&self) -> &'static str {
        "HKDF-SHA384"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(HkdfContext::new_fixed(HashAlgorithm::Sha384)))
    }
}

/// HKDF provider hard-wired to SHA-512.
///
/// Translation of C `ossl_kdf_hkdf_sha512_functions` (`hkdf.c` lines
/// 986-1002).  Semantics identical to [`HkdfSha256Provider`], differing
/// only in the pre-selected digest.
#[derive(Debug, Default, Clone, Copy)]
pub struct HkdfSha512Provider;

impl HkdfSha512Provider {
    /// Creates a new provider descriptor for HKDF-SHA512.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KdfProvider for HkdfSha512Provider {
    fn name(&self) -> &'static str {
        "HKDF-SHA512"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(HkdfContext::new_fixed(HashAlgorithm::Sha512)))
    }
}

/// TLS 1.3 HKDF-Label provider.
///
/// Translation of C `ossl_kdf_tls1_3_kdf_functions` (`hkdf.c` lines
/// 1005-1021).  Exposes the RFC 8446 §7.1 HKDF-Extract /
/// HKDF-Expand-Label construction used to derive TLS 1.3 keys.
///
/// The context returned by [`new_ctx`](Tls13KdfProvider::new_ctx) enforces
/// the TLS 1.3 dispatch path: `EXTRACT_AND_EXPAND` mode is rejected, and
/// `PARAM_PREFIX` / `PARAM_LABEL` / `PARAM_DATA` parameters drive the
/// HKDF-Label encoding.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tls13KdfProvider;

impl Tls13KdfProvider {
    /// Creates a new provider descriptor for TLS 1.3 HKDF-Label.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KdfProvider for Tls13KdfProvider {
    fn name(&self) -> &'static str {
        "TLS13-KDF"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(HkdfContext::new_tls13()))
    }
}

// =============================================================================
// Algorithm descriptor registration
// =============================================================================

/// Returns the complete set of HKDF algorithm descriptors exposed by this
/// module.
///
/// Mirrors the `OSSL_ALGORITHM ossl_kdf_algs[]` table registered from
/// `providers/implementations/include/prov/kdfexchange.h` (and the matching
/// dispatch arrays in `hkdf.c`).  Five variants are registered:
///
/// | Name              | Property            | Description                         |
/// |-------------------|---------------------|-------------------------------------|
/// | `HKDF`            | `provider=default`  | Generic HKDF (digest configurable)  |
/// | `HKDF-SHA256`     | `provider=default`  | HKDF hard-wired to SHA-256          |
/// | `HKDF-SHA384`     | `provider=default`  | HKDF hard-wired to SHA-384          |
/// | `HKDF-SHA512`     | `provider=default`  | HKDF hard-wired to SHA-512          |
/// | `TLS13-KDF`       | `provider=default`  | TLS 1.3 HKDF-Expand-Label (RFC 8446)|
///
/// This function is called by `kdfs::descriptors()` in
/// [`crate::implementations::kdfs`] which aggregates across all KDF
/// algorithms.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["HKDF"],
            "provider=default",
            "RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)",
        ),
        algorithm(
            &["HKDF-SHA256"],
            "provider=default",
            "HKDF (RFC 5869) with the SHA-256 digest fixed at construction time",
        ),
        algorithm(
            &["HKDF-SHA384"],
            "provider=default",
            "HKDF (RFC 5869) with the SHA-384 digest fixed at construction time",
        ),
        algorithm(
            &["HKDF-SHA512"],
            "provider=default",
            "HKDF (RFC 5869) with the SHA-512 digest fixed at construction time",
        ),
        algorithm(
            &["TLS13-KDF"],
            "provider=default",
            "TLS 1.3 HKDF-Extract / HKDF-Expand-Label construction per RFC 8446 §7.1",
        ),
    ]
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    /// RFC 5869 Test Case 1: SHA-256, basic test case.
    #[test]
    fn test_hkdf_rfc5869_case1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA-256".to_string()));
        ps.set(PARAM_KEY, ParamValue::OctetString(ikm.clone()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.clone()));
        ps.set(PARAM_INFO, ParamValue::OctetString(info.clone()));

        let provider = HkdfProvider;
        let mut ctx = provider.new_ctx().unwrap();

        let mut output = vec![0u8; 42];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 42);

        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(output, expected);
    }

    /// Test extract-only mode.
    #[test]
    fn test_hkdf_extract_only() {
        let ikm = vec![0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA-256".to_string()));
        ps.set(PARAM_KEY, ParamValue::OctetString(ikm.clone()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.clone()));
        ps.set(
            PARAM_MODE,
            ParamValue::Utf8String("EXTRACT_ONLY".to_string()),
        );

        let provider = HkdfProvider;
        let mut ctx = provider.new_ctx().unwrap();

        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        // PRK should be deterministic
        assert_ne!(output, vec![0u8; 32]);
    }

    /// Test missing key returns error.
    #[test]
    fn test_hkdf_missing_key() {
        let provider = HkdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        let result = ctx.derive(&mut output, &ParamSet::default());
        assert!(result.is_err());
    }

    /// Test reset clears state.
    #[test]
    fn test_hkdf_reset() {
        let provider = HkdfProvider;
        let mut ctx = provider.new_ctx().unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(b"test_key".to_vec()));
        ctx.set_params(&ps).unwrap();
        ctx.reset().unwrap();

        let mut output = vec![0u8; 32];
        // After reset, key is cleared, should fail
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
