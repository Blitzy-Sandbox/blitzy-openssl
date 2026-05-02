//! ML-DSA (FIPS 204) signature provider implementation.
//!
//! This module is the Rust translation of
//! `providers/implementations/signature/ml_dsa_sig.c` (~510 lines) and
//! exposes Module-Lattice-Based Digital Signature Algorithm signing and
//! verification at three NIST security categories.  The cryptographic
//! work is delegated to [`openssl_crypto::pqc::ml_dsa`]; this provider
//! crate is the dispatch surface that adapts that low-level engine to
//! the [`SignatureProvider`] / [`SignatureContext`] traits used by
//! `openssl-cli`, the FIPS provider, and any future foreign-function
//! consumer through the `openssl-ffi` crate.
//!
//! # Algorithm Coverage
//!
//! | Variant     | NIST Security Category | OID                              | EVP type |
//! |-------------|------------------------|----------------------------------|----------|
//! | ML-DSA-44   | 2 (≈128-bit)           | 2.16.840.1.101.3.4.3.17          | 0        |
//! | ML-DSA-65   | 3 (≈192-bit)           | 2.16.840.1.101.3.4.3.18          | 1        |
//! | ML-DSA-87   | 5 (≈256-bit)           | 2.16.840.1.101.3.4.3.19          | 2        |
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_signature_descriptors` →
//! `crate::implementations::signatures::descriptors` →
//! `crate::implementations::signatures::ml_dsa::descriptors` (this module).
//!
//! Run-time signing/verification reaches this module via
//! [`MlDsaSignatureProvider::new_ctx`] → [`MlDsaSignatureContext`] →
//! [`openssl_crypto::pqc::ml_dsa::ml_dsa_sign`] /
//! [`openssl_crypto::pqc::ml_dsa::ml_dsa_verify`].
//!
//! # FIPS 204 Specifics
//!
//! * **External digest selection is rejected** — ML-DSA defines its own
//!   internal `µ = SHAKE-256(tr || M')` construction.  Any non-empty digest
//!   name passed through [`SignatureContext::digest_sign_init`] /
//!   [`SignatureContext::digest_verify_init`] returns
//!   [`ProviderError::Dispatch`].  This mirrors the C source check at
//!   `ml_dsa_sig.c` lines 410–420.
//! * **Context string** — limited to [`ML_DSA_MAX_CONTEXT_STRING_LEN`] = 255
//!   bytes per FIPS 204 §5.4.
//! * **Message encoding** — *raw* (no domain prefix) and *pure*
//!   (`0x01 || |ctx| || ctx || msg` per FIPS 204 §5.4) modes are both
//!   represented by [`MlDsaMessageEncode`].
//! * **Deterministic / hedged signing** — toggled via the
//!   `deterministic` parameter; *test-entropy* is honoured exclusively
//!   when `deterministic` is set, matching `ml_dsa_sig.c` line 263.
//! * **µ-only mode** — accepted at the parameter API to mirror the C
//!   surface, but rejected at sign/verify time because the underlying
//!   crypto-layer engine does not yet expose a µ-injection entry point.
//!   The check is intentionally placed at the operation site so that
//!   parameter discovery and reset semantics still match the C source.
//!
//! # Rule Compliance
//!
//! * **R5 (nullability)** — all "unset" states are `Option<T>`; the
//!   message-encoding mode is an enum, never an integer sentinel.
//! * **R6 (lossless casts)** — no bare `as` narrowing; all integer
//!   conversions use `try_into` / `usize::from` / explicit length checks.
//! * **R7 (lock granularity)** — this context owns no shared state; the
//!   `Arc<LibContext>` and `Arc<MlDsaKey>` handles are reference-counted
//!   read-only resources requiring no locks.
//! * **R8 (no `unsafe`)** — this file contains zero `unsafe` blocks.
//! * **R9 (warning-free)** — every public item carries `///` docs; every
//!   `#[allow]` is justified.
//!
//! # C Source Mapping
//!
//! | C Source                                                   | Rust Equivalent                                             |
//! |------------------------------------------------------------|-------------------------------------------------------------|
//! | `providers/defltprov.c` lines 506–514 (`deflt_signature`)  | [`descriptors`] in this module                              |
//! | `providers/implementations/signature/ml_dsa_sig.c`         | [`MlDsaSignatureContext`] / [`MlDsaSignatureProvider`]      |
//! | `PROV_ML_DSA_CTX` (lines 54–73)                            | [`MlDsaSignatureContext`] field set                         |
//! | `ML_DSA_MESSAGE_ENCODE_RAW` / `_PURE` (lines 36–37)        | [`MlDsaMessageEncode::Raw`] / [`MlDsaMessageEncode::Pure`]  |
//! | `ml_dsa_44_sign_init` and friends (lines 130–160)          | [`MlDsaSignatureContext::sign_init`]                        |
//! | `ml_dsa_freectx` (lines 75–95)                             | `Drop` / `Zeroize` impls for [`MlDsaSignatureContext`]      |
//! | `MAKE_SIGNATURE_FUNCTIONS(44)` etc. (lines 470–510)        | [`MlDsaSignatureProvider`] parameterised by [`MlDsaVariant`]|

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{
    CommonError, CryptoError, ParamSet, ParamValue, ProviderError, ProviderResult,
};
use openssl_crypto::context::LibContext;
use openssl_crypto::pqc::ml_dsa::{
    ml_dsa_params_get, ml_dsa_sign, ml_dsa_verify, MlDsaKey, MlDsaParams,
    MlDsaVariant as CryptoMlDsaVariant, MAX_CONTEXT_STRING_LEN, MU_BYTES,
};

use super::algorithm;
use super::OperationMode;
use crate::traits::{AlgorithmDescriptor, SignatureContext, SignatureProvider};

// =============================================================================
// Constants
// =============================================================================

/// Maximum permitted byte-length of an ML-DSA context string.
///
/// Mirrors `ML_DSA_MAX_CONTEXT_STRING_LEN` in
/// `crypto/ml_dsa/ml_dsa_sign.c` and the `MAX_CONTEXT_STRING_LEN`
/// constant exposed by [`openssl_crypto::pqc::ml_dsa`].  Per FIPS 204
/// §5.4 a context string longer than 255 bytes is rejected.
pub const ML_DSA_MAX_CONTEXT_STRING_LEN: usize = MAX_CONTEXT_STRING_LEN;

/// Byte-length of the ML-DSA message representative `µ`.
///
/// FIPS 204 fixes `µ` at 64 bytes (the SHAKE-256 XOF output for the
/// digest of the public-key digest `tr` concatenated with the message
/// envelope).  Exposed for the µ-mode parameter and the streaming path
/// even though the local crypto engine does not yet accept a
/// pre-computed µ.
pub const ML_DSA_MU_OUTPUT_LEN: usize = MU_BYTES;

/// Byte-length of the optional per-signature random nonce `rnd`
/// supplied through the `test-entropy` parameter.
///
/// Mirrors `ENTROPY_LEN` in `crypto/ml_dsa/ml_dsa_sign.c` (private in
/// the crypto crate; the value is fixed by FIPS 204).
pub const ML_DSA_ENTROPY_LEN: usize = 32;

/// Property string registered by every default-provider ML-DSA descriptor.
const DEFAULT_PROPERTY: &str = "provider=default";

// =============================================================================
// Helper: dispatch errors from the crypto crate to provider errors.
// =============================================================================

/// Converts a [`CryptoError`] returned by the crypto crate into a
/// [`ProviderError::Dispatch`] suitable for surfacing through the
/// provider trait API.
///
/// The `Display` impl on [`CryptoError`] already produces a stable,
/// human-readable representation; we wrap it untouched.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

// =============================================================================
// MlDsaVariant — provider-level enum exposed via the schema
// =============================================================================

/// The three FIPS 204 ML-DSA parameter sets.
///
/// This is the provider-level enum surfaced through the file's public
/// API.  It mirrors [`openssl_crypto::pqc::ml_dsa::MlDsaVariant`] but
/// adds the [`MlDsaVariant::name`] / [`MlDsaVariant::security_bits`] /
/// [`MlDsaVariant::evp_type`] accessors that the schema demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaVariant {
    /// ML-DSA-44 — NIST security category 2 (≈128-bit).
    MlDsa44,
    /// ML-DSA-65 — NIST security category 3 (≈192-bit).
    MlDsa65,
    /// ML-DSA-87 — NIST security category 5 (≈256-bit).
    MlDsa87,
}

impl MlDsaVariant {
    /// Returns the canonical algorithm name string used by the OpenSSL
    /// algorithm registry: `"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Returns the bit-strength (`λ` in FIPS 204) for this variant.
    ///
    /// This is the symmetric-equivalent security level — 128, 192, or
    /// 256 — used as the `lambda` parameter when constructing the
    /// challenge polynomial.  Equivalent to the C macro
    /// `ML_DSA_*_SECURITY_BITS`.
    ///
    /// The return type is [`i32`] to match the canonical signature-parameter
    /// integer width (`OSSL_SIGNATURE_PARAM_BITS` is constructed via
    /// `OSSL_PARAM_construct_int`, a 32-bit signed integer); using `i32`
    /// directly avoids a narrowing conversion (Rule R6) at every consumer
    /// while remaining wide enough for all currently defined NIST security
    /// categories (`128`, `192`, `256`).
    #[must_use]
    pub fn security_bits(self) -> i32 {
        match self {
            Self::MlDsa44 => 128,
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
        }
    }

    /// Returns the EVP type identifier (`EVP_PKEY_ML_DSA_44/65/87`).
    ///
    /// Matches the numeric ordinal expected by the C side dispatch
    /// macros and the values published in `include/openssl/evp.h`.
    #[must_use]
    pub fn evp_type(self) -> u32 {
        match self {
            Self::MlDsa44 => 0,
            Self::MlDsa65 => 1,
            Self::MlDsa87 => 2,
        }
    }

    /// Returns the security category integer (2, 3, or 5).
    #[must_use]
    pub fn security_category(self) -> u32 {
        match self {
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
        }
    }

    /// Returns the `AlgorithmIdentifier` OID dotted-decimal string.
    #[must_use]
    pub fn oid(self) -> &'static str {
        match self {
            Self::MlDsa44 => "2.16.840.1.101.3.4.3.17",
            Self::MlDsa65 => "2.16.840.1.101.3.4.3.18",
            Self::MlDsa87 => "2.16.840.1.101.3.4.3.19",
        }
    }

    /// Maps to the corresponding crypto-layer variant.
    #[must_use]
    pub fn to_crypto(self) -> CryptoMlDsaVariant {
        match self {
            Self::MlDsa44 => CryptoMlDsaVariant::MlDsa44,
            Self::MlDsa65 => CryptoMlDsaVariant::MlDsa65,
            Self::MlDsa87 => CryptoMlDsaVariant::MlDsa87,
        }
    }

    /// Returns the static parameter table for this variant.
    #[must_use]
    pub fn params(self) -> &'static MlDsaParams {
        ml_dsa_params_get(self.to_crypto())
    }

    /// Returns the serialised public-key length in bytes.
    #[must_use]
    pub fn public_key_len(self) -> usize {
        self.params().pk_len
    }

    /// Returns the serialised private-key length in bytes.
    #[must_use]
    pub fn private_key_len(self) -> usize {
        self.params().sk_len
    }

    /// Returns the serialised signature length in bytes.
    #[must_use]
    pub fn signature_len(self) -> usize {
        self.params().sig_len
    }
}

impl fmt::Display for MlDsaVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl From<MlDsaVariant> for CryptoMlDsaVariant {
    fn from(v: MlDsaVariant) -> Self {
        v.to_crypto()
    }
}

impl From<CryptoMlDsaVariant> for MlDsaVariant {
    fn from(v: CryptoMlDsaVariant) -> Self {
        match v {
            CryptoMlDsaVariant::MlDsa44 => Self::MlDsa44,
            CryptoMlDsaVariant::MlDsa65 => Self::MlDsa65,
            CryptoMlDsaVariant::MlDsa87 => Self::MlDsa87,
        }
    }
}

// =============================================================================
// MlDsaMessageEncode
// =============================================================================

/// Message-encoding mode that drives the ML-DSA µ construction.
///
/// Mirrors the two-valued integer flag stored in `PROV_ML_DSA_CTX.msg_encode`
/// at `ml_dsa_sig.c` line 65.  The discriminant values are kept stable so
/// that callers integrating through [`set_ctx_params`] using the integer
/// `message-encoding` parameter retain their existing wire compatibility:
/// 0 → [`MlDsaMessageEncode::Raw`], 1 → [`MlDsaMessageEncode::Pure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaMessageEncode {
    /// Raw mode: `µ = SHAKE-256(tr || msg)` — no domain separator.
    ///
    /// Matches `ML_DSA_MESSAGE_ENCODE_RAW` (`= 0`) at `ml_dsa_sig.c` line 36.
    Raw = 0,
    /// Pure mode: `µ = SHAKE-256(tr || 0x00 || ctx_len || ctx || msg)` per
    /// FIPS 204 §5.4.
    ///
    /// Matches `ML_DSA_MESSAGE_ENCODE_PURE` (`= 1`) at `ml_dsa_sig.c` line 37.
    Pure = 1,
}

impl MlDsaMessageEncode {
    /// Returns the integer encoding used by the C `message-encoding` parameter.
    #[must_use]
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Raw => 0,
            Self::Pure => 1,
        }
    }

    /// Parses an integer parameter into a [`MlDsaMessageEncode`] value.
    pub fn from_i32(value: i32) -> ProviderResult<Self> {
        match value {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Pure),
            other => Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("unsupported ML-DSA message-encoding: {other}"),
            ))),
        }
    }

    /// Returns the boolean flag accepted by
    /// [`openssl_crypto::pqc::ml_dsa::ml_dsa_sign`] / `ml_dsa_verify`:
    /// `true` for [`MlDsaMessageEncode::Pure`], `false` for
    /// [`MlDsaMessageEncode::Raw`].
    #[must_use]
    pub fn is_pure(self) -> bool {
        matches!(self, Self::Pure)
    }
}

impl Default for MlDsaMessageEncode {
    fn default() -> Self {
        // The C source defaults `msg_encode` to PURE
        // (`ml_dsa_sig.c` line 116).
        Self::Pure
    }
}

// =============================================================================
// MlDsaSignatureProvider
// =============================================================================

/// Signature provider implementation for one ML-DSA parameter set.
///
/// Each instance dispatches to a single [`MlDsaVariant`].  Three live
/// in the default provider, one per variant; each yields a fresh
/// [`MlDsaSignatureContext`] from [`SignatureProvider::new_ctx`].
///
/// The struct itself is `Clone` and cheap to copy (the
/// [`Arc<LibContext>`] handle is reference-counted).
#[derive(Debug, Clone)]
pub struct MlDsaSignatureProvider {
    variant: MlDsaVariant,
    libctx: Arc<LibContext>,
    propq: Option<String>,
}

impl MlDsaSignatureProvider {
    /// Creates a provider bound to the default library context.
    ///
    /// Used by the default provider when registering the variant via
    /// `OSSL_DISPATCH ossl_ml_dsa_<n>_signature_functions[]` — see the
    /// `MAKE_SIGNATURE_FUNCTIONS` macro at `ml_dsa_sig.c` lines 470–510.
    #[must_use]
    pub fn new(variant: MlDsaVariant) -> Self {
        Self {
            variant,
            libctx: LibContext::get_default(),
            propq: None,
        }
    }

    /// Creates a provider bound to a caller-supplied library context
    /// and optional property query.
    #[must_use]
    pub fn new_with_context(
        variant: MlDsaVariant,
        libctx: Arc<LibContext>,
        propq: Option<String>,
    ) -> Self {
        Self {
            variant,
            libctx,
            propq,
        }
    }

    /// Returns the variant this provider serves.
    #[must_use]
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }
}

impl SignatureProvider for MlDsaSignatureProvider {
    fn name(&self) -> &'static str {
        self.variant.name()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>> {
        debug!(
            algorithm = self.variant.name(),
            "ml-dsa: creating new signature context"
        );
        Ok(Box::new(MlDsaSignatureContext::new(
            self.variant,
            Arc::clone(&self.libctx),
            self.propq.clone(),
        )))
    }
}

// =============================================================================
// MlDsaSignatureContext
// =============================================================================

/// Per-operation signing/verification context for ML-DSA.
///
/// Field layout mirrors `PROV_ML_DSA_CTX` at `ml_dsa_sig.c` lines 54–73,
/// but with idiomatic Rust ownership semantics:
/// * The `EVP_MD_CTX *md_ctx` field is replaced by an in-memory
///   `streaming_buffer: Vec<u8>` because the local crypto engine
///   computes µ internally rather than exposing a SHAKE-256 streaming
///   API to providers.
/// * The `unsigned char test_entropy[ENTROPY_LEN]` buffer is a sized
///   `[u8; ML_DSA_ENTROPY_LEN]` zeroised on context drop.
/// * The `unsigned char *sig` cache for verification is an
///   `Option<Vec<u8>>` zeroised on overwrite/drop.
///
/// All sensitive material implements [`Zeroize`] /
/// [`ZeroizeOnDrop`] so context teardown leaves no residue, mirroring
/// the `OPENSSL_cleanse(...)` calls at `ml_dsa_sig.c` lines 80–84.
pub struct MlDsaSignatureContext {
    /// Library context (Rust equivalent of `OSSL_LIB_CTX *libctx`).
    lib_ctx: Arc<LibContext>,
    /// Optional property query string used when fetching dependencies.
    propq: Option<String>,
    /// Active variant — fixed at construction, not mutated thereafter.
    variant: MlDsaVariant,
    /// Loaded ML-DSA key (private for signing, public or private for verify).
    key: Option<Arc<MlDsaKey>>,
    /// Caller-supplied context string (max [`ML_DSA_MAX_CONTEXT_STRING_LEN`]).
    context_string: Option<Vec<u8>>,
    /// Optional test entropy used when `deterministic` is set; honours the C
    /// `ENTROPY_LEN`-byte expectation.
    test_entropy: Option<[u8; ML_DSA_ENTROPY_LEN]>,
    /// Whether test-entropy / zero-entropy hedged signing is in effect.
    deterministic: bool,
    /// Message-encoding mode (PURE by default).
    msg_encode: MlDsaMessageEncode,
    /// Cached `AlgorithmIdentifier` DER encoding.
    aid_cache: Option<Vec<u8>>,
    /// µ-only mode flag — accepted for API parity with C; rejected at sign/
    /// verify time because the crypto crate does not yet expose µ injection.
    mu_mode: bool,
    /// Active operation (Sign / Verify) — `None` between init and finalize.
    operation: Option<OperationMode>,
    /// Streaming buffer for `digest_sign_update` / `digest_verify_update`.
    streaming_buffer: Vec<u8>,
    /// Cached verification signature populated via `set_ctx_params`
    /// (mirrors `PROV_ML_DSA_CTX.sig` at `ml_dsa_sig.c` line 71).
    cached_signature: Option<Vec<u8>>,
}

// -----------------------------------------------------------------------------
// Zeroize / Drop / ZeroizeOnDrop — explicit secure teardown.
// -----------------------------------------------------------------------------

impl Zeroize for MlDsaSignatureContext {
    fn zeroize(&mut self) {
        if let Some(ctx) = self.context_string.as_mut() {
            ctx.zeroize();
        }
        self.context_string = None;

        if let Some(entropy) = self.test_entropy.as_mut() {
            entropy.zeroize();
        }
        self.test_entropy = None;

        if let Some(aid) = self.aid_cache.as_mut() {
            aid.zeroize();
        }
        self.aid_cache = None;

        if let Some(sig) = self.cached_signature.as_mut() {
            sig.zeroize();
        }
        self.cached_signature = None;

        self.streaming_buffer.zeroize();
        self.deterministic = false;
        self.mu_mode = false;
        self.operation = None;
    }
}

impl Drop for MlDsaSignatureContext {
    fn drop(&mut self) {
        // Mirrors `ml_dsa_freectx` at `ml_dsa_sig.c` line 80, which runs
        // `OPENSSL_cleanse(ctx->test_entropy, sizeof(ctx->test_entropy))`.
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MlDsaSignatureContext {}

// -----------------------------------------------------------------------------
// Inherent methods — construction, parameter handling, sign/verify primitives.
// -----------------------------------------------------------------------------

impl MlDsaSignatureContext {
    /// Creates a fresh context.  All operational state is empty; callers
    /// must invoke [`SignatureContext::sign_init`] or
    /// [`SignatureContext::verify_init`] before signing/verifying.
    pub(crate) fn new(
        variant: MlDsaVariant,
        lib_ctx: Arc<LibContext>,
        propq: Option<String>,
    ) -> Self {
        Self {
            lib_ctx,
            propq,
            variant,
            key: None,
            context_string: None,
            test_entropy: None,
            deterministic: false,
            msg_encode: MlDsaMessageEncode::default(),
            aid_cache: None,
            mu_mode: false,
            operation: None,
            streaming_buffer: Vec::new(),
            cached_signature: None,
        }
    }

    /// Returns the variant served by this context.
    #[must_use]
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// Sets the context string with full validation.
    ///
    /// Length must not exceed [`ML_DSA_MAX_CONTEXT_STRING_LEN`].  Any
    /// previous context string is securely zeroised before being
    /// replaced, mirroring the C `OPENSSL_clear_free` pattern at
    /// `ml_dsa_sig.c` line 380.
    fn set_context_string(&mut self, new_ctx: Option<Vec<u8>>) -> ProviderResult<()> {
        if let Some(ref bytes) = new_ctx {
            if bytes.len() > ML_DSA_MAX_CONTEXT_STRING_LEN {
                warn!(
                    algorithm = self.variant.name(),
                    supplied_len = bytes.len(),
                    max_len = ML_DSA_MAX_CONTEXT_STRING_LEN,
                    "ml-dsa: context string exceeds 255 bytes — rejected"
                );
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-DSA context string length {} exceeds maximum {}",
                        bytes.len(),
                        ML_DSA_MAX_CONTEXT_STRING_LEN
                    ),
                )));
            }
        }

        if let Some(prev) = self.context_string.as_mut() {
            prev.zeroize();
        }
        self.context_string = new_ctx;
        Ok(())
    }

    /// Loads the context's signing key from a serialised byte slice.
    ///
    /// ML-DSA keys are length-encoded — see FIPS 204 Table 2 — so we
    /// accept either the canonical private encoding (`sk_len`) or the
    /// canonical public encoding (`pk_len`) and forward to the
    /// appropriate constructor.  Supplying a public key here is
    /// permitted only when verifying; the trait method [`SignatureContext::sign_init`]
    /// rejects public-only loads through a separate length check.
    fn parse_key_for_signing(&self, key: &[u8]) -> ProviderResult<Arc<MlDsaKey>> {
        let params = self.variant.params();
        if key.len() == params.sk_len {
            let parsed = MlDsaKey::from_private(key, params, Arc::clone(&self.lib_ctx))
                .map_err(dispatch_err)?;
            Ok(Arc::new(parsed))
        } else {
            warn!(
                algorithm = self.variant.name(),
                supplied_len = key.len(),
                expected_priv_len = params.sk_len,
                "ml-dsa: signing requires the private encoding"
            );
            Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "ML-DSA {} signing requires a {}-byte private key (got {} bytes)",
                    self.variant.name(),
                    params.sk_len,
                    key.len()
                ),
            )))
        }
    }

    /// Loads a key for verification — accepts either private (rare) or
    /// public encoding lengths.
    fn parse_key_for_verify(&self, key: &[u8]) -> ProviderResult<Arc<MlDsaKey>> {
        let params = self.variant.params();
        if key.len() == params.pk_len {
            let parsed = MlDsaKey::from_public(key, params, Arc::clone(&self.lib_ctx))
                .map_err(dispatch_err)?;
            Ok(Arc::new(parsed))
        } else if key.len() == params.sk_len {
            let parsed = MlDsaKey::from_private(key, params, Arc::clone(&self.lib_ctx))
                .map_err(dispatch_err)?;
            Ok(Arc::new(parsed))
        } else {
            warn!(
                algorithm = self.variant.name(),
                supplied_len = key.len(),
                expected_pub_len = params.pk_len,
                expected_priv_len = params.sk_len,
                "ml-dsa: verify key length unrecognised"
            );
            Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                "ML-DSA {} verify requires {}-byte public or {}-byte private key (got {} bytes)",
                self.variant.name(),
                params.pk_len,
                params.sk_len,
                key.len()
            ),
            )))
        }
    }

    /// Returns a deep clone of the context that is safe to use independently.
    ///
    /// This is the Rust analogue of `ml_dsa_dupctx` at `ml_dsa_sig.c`
    /// line 100.  Heavyweight resources ([`LibContext`], [`MlDsaKey`])
    /// are shared via [`Arc::clone`]; sensitive byte buffers are
    /// duplicated rather than aliased so the duplicate can be modified
    /// without corrupting the source.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            lib_ctx: Arc::clone(&self.lib_ctx),
            propq: self.propq.clone(),
            variant: self.variant,
            key: self.key.as_ref().map(Arc::clone),
            context_string: self.context_string.clone(),
            test_entropy: self.test_entropy,
            deterministic: self.deterministic,
            msg_encode: self.msg_encode,
            aid_cache: self.aid_cache.clone(),
            mu_mode: self.mu_mode,
            operation: self.operation,
            streaming_buffer: self.streaming_buffer.clone(),
            cached_signature: self.cached_signature.clone(),
        }
    }

    // -------------------------------------------------------------------------
    // sign / verify internals
    // -------------------------------------------------------------------------

    /// One-shot sign primitive.  Caller is responsible for ensuring
    /// `self.operation == Some(OperationMode::Sign)` before invocation.
    fn sign_internal(&mut self, message: &[u8]) -> ProviderResult<Vec<u8>> {
        if self.mu_mode {
            warn!(
                algorithm = self.variant.name(),
                "ml-dsa: µ-mode signing is not supported by this provider build"
            );
            return Err(ProviderError::Common(CommonError::Unsupported(
                "ML-DSA µ-mode signing is not yet wired through the crypto crate".to_string(),
            )));
        }

        let key = self.key.clone().ok_or_else(|| {
            ProviderError::Init("ml-dsa: sign called before sign_init loaded a key".to_string())
        })?;

        // Build the entropy reference passed to the crypto crate.
        // Precedence (matches `ml_dsa_sig.c` lines 256–270):
        //   1. caller-supplied test entropy
        //   2. deterministic flag → all-zero nonce
        //   3. neither → None, crypto crate draws from the library RNG.
        let zero_entropy: [u8; ML_DSA_ENTROPY_LEN];
        let add_random: Option<&[u8; ML_DSA_ENTROPY_LEN]> = if let Some(ref te) = self.test_entropy
        {
            Some(te)
        } else if self.deterministic {
            zero_entropy = [0u8; ML_DSA_ENTROPY_LEN];
            Some(&zero_entropy)
        } else {
            None
        };

        let context = self.context_string.as_deref().unwrap_or(&[]);
        let signature = ml_dsa_sign(
            key.as_ref(),
            message,
            context,
            self.msg_encode.is_pure(),
            add_random,
        )
        .map_err(dispatch_err)?;

        let expected_len = self.variant.signature_len();
        if signature.len() != expected_len {
            warn!(
                algorithm = self.variant.name(),
                produced_len = signature.len(),
                expected_len,
                "ml-dsa: crypto layer returned an unexpected signature length"
            );
            return Err(ProviderError::Dispatch(format!(
                "ML-DSA {} signature length mismatch: expected {}, got {}",
                self.variant.name(),
                expected_len,
                signature.len()
            )));
        }

        // Cache the latest signature alongside any prior value, scrubbing
        // the predecessor first.
        if let Some(prev) = self.cached_signature.as_mut() {
            prev.zeroize();
        }
        self.cached_signature = Some(signature.clone());
        Ok(signature)
    }

    /// One-shot verify primitive.
    fn verify_internal(&self, message: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.mu_mode {
            warn!(
                algorithm = self.variant.name(),
                "ml-dsa: µ-mode verification is not supported by this provider build"
            );
            return Err(ProviderError::Common(CommonError::Unsupported(
                "ML-DSA µ-mode verification is not yet wired through the crypto crate".to_string(),
            )));
        }

        // Length pre-check returns Ok(false) (a verification failure)
        // rather than a hard error to mirror EdDSA / RSA semantics.
        let expected_len = self.variant.signature_len();
        if signature.len() != expected_len {
            trace!(
                algorithm = self.variant.name(),
                supplied_len = signature.len(),
                expected_len,
                "ml-dsa: signature length mismatch — verification fails"
            );
            return Ok(false);
        }

        let key = self.key.clone().ok_or_else(|| {
            ProviderError::Init("ml-dsa: verify called before verify_init loaded a key".to_string())
        })?;

        let context = self.context_string.as_deref().unwrap_or(&[]);
        ml_dsa_verify(
            key.as_ref(),
            message,
            context,
            self.msg_encode.is_pure(),
            signature,
        )
        .map_err(dispatch_err)
    }

    // -------------------------------------------------------------------------
    // Parameter handling — set / get
    // -------------------------------------------------------------------------

    /// Inherent `set_ctx_params` mirroring `ml_dsa_set_ctx_params` at
    /// `ml_dsa_sig.c` lines 360–460.
    pub fn set_ctx_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if params.is_empty() {
            return Ok(());
        }
        trace!(
            algorithm = self.variant.name(),
            param_count = params.len(),
            "ml-dsa: set_ctx_params"
        );

        // context-string (octet string, max 255 bytes)
        if let Some(val) = params.get("context-string") {
            let bytes = val.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "context-string".to_string(),
                    expected: "OctetString",
                    actual: val.param_type_name(),
                })
            })?;
            self.set_context_string(Some(bytes.to_vec()))?;
        }

        // deterministic (integer flag, 0 or 1)
        if let Some(val) = params.get("deterministic") {
            let flag = val.as_i32().ok_or_else(|| {
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "deterministic".to_string(),
                    expected: "Integer",
                    actual: val.param_type_name(),
                })
            })?;
            self.deterministic = flag != 0;
        }

        // test-entropy (octet string, exactly ML_DSA_ENTROPY_LEN bytes)
        if let Some(val) = params.get("test-entropy") {
            let bytes = val.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "test-entropy".to_string(),
                    expected: "OctetString",
                    actual: val.param_type_name(),
                })
            })?;
            if bytes.len() != ML_DSA_ENTROPY_LEN {
                warn!(
                    algorithm = self.variant.name(),
                    supplied_len = bytes.len(),
                    expected_len = ML_DSA_ENTROPY_LEN,
                    "ml-dsa: test-entropy must be exactly 32 bytes"
                );
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-DSA test-entropy must be exactly {} bytes (got {})",
                        ML_DSA_ENTROPY_LEN,
                        bytes.len()
                    ),
                )));
            }
            // Take a fixed-size copy to avoid retaining the caller's buffer.
            let mut buf = [0u8; ML_DSA_ENTROPY_LEN];
            buf.copy_from_slice(bytes);
            // Securely overwrite any previous nonce.
            if let Some(prev) = self.test_entropy.as_mut() {
                prev.zeroize();
            }
            self.test_entropy = Some(buf);
        }

        // message-encoding (integer, 0=Raw / 1=Pure)
        if let Some(val) = params.get("message-encoding") {
            let raw = val.as_i32().ok_or_else(|| {
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "message-encoding".to_string(),
                    expected: "Integer",
                    actual: val.param_type_name(),
                })
            })?;
            let mode = MlDsaMessageEncode::from_i32(raw)?;
            self.msg_encode = mode;
        }

        // mu (integer flag) — stored, but rejected at sign/verify time.
        if let Some(val) = params.get("mu") {
            let flag = val.as_i32().ok_or_else(|| {
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "mu".to_string(),
                    expected: "Integer",
                    actual: val.param_type_name(),
                })
            })?;
            self.mu_mode = flag != 0;
            if self.mu_mode {
                debug!(
                    algorithm = self.variant.name(),
                    "ml-dsa: µ-mode flag set (operation will fail at sign/verify time)"
                );
            }
        }

        // signature (octet string) — used by the verify-recover-style API
        // mirroring `ml_dsa_sig.c` lines 425–445.
        if let Some(val) = params.get("signature") {
            let bytes = val.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "signature".to_string(),
                    expected: "OctetString",
                    actual: val.param_type_name(),
                })
            })?;
            if let Some(prev) = self.cached_signature.as_mut() {
                prev.zeroize();
            }
            self.cached_signature = Some(bytes.to_vec());
        }

        Ok(())
    }

    /// Inherent `get_ctx_params` mirroring `ml_dsa_get_ctx_params` at
    /// `ml_dsa_sig.c` lines 462–502.
    pub fn get_ctx_params(&mut self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();

        if self.aid_cache.is_none() {
            self.aid_cache = Some(algorithm_identifier_der(self.variant));
        }
        if let Some(ref aid) = self.aid_cache {
            out.set("algorithm-id", ParamValue::OctetString(aid.clone()));
        }

        out.set(
            "instance",
            ParamValue::Utf8String(self.variant.name().to_string()),
        );
        out.set(
            "deterministic",
            ParamValue::Int32(i32::from(u8::from(self.deterministic))),
        );
        out.set(
            "message-encoding",
            ParamValue::Int32(self.msg_encode.as_i32()),
        );
        out.set("mu", ParamValue::Int32(i32::from(u8::from(self.mu_mode))));
        out.set(
            "security-bits",
            ParamValue::Int32(self.variant.security_bits()),
        );

        Ok(out)
    }

    // -------------------------------------------------------------------------
    // One-shot digest_sign / digest_verify
    // -------------------------------------------------------------------------

    /// One-shot ML-DSA digest-signing entry point.
    ///
    /// Mirrors the C macro-generated `ml_dsa_digest_sign` one-shot path
    /// in `ml_dsa_sig.c` (lines 470–510, `MAKE_SIGNATURE_FUNCTIONS`).
    /// The caller is expected to have invoked
    /// [`MlDsaSignatureContext::digest_sign_init`] (or the trait method
    /// of the same name) beforehand: that sets `operation =
    /// OperationMode::Sign`, loads the private key, and rejects any
    /// externally supplied digest name (FIPS 204 mandates ML-DSA's own
    /// SHAKE-256 µ construction — see `sign_internal` for the actual
    /// `ml_dsa_sign()` invocation).
    ///
    /// Returning [`ProviderError::Init`] when called out of sequence
    /// matches the C-side EVP contract whereby
    /// `EVP_PKEY_OP_SIGN`/`EVP_PKEY_OP_DIGEST_SIGN` operations error out
    /// when invoked without a prior `*_init`.
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Init`] — `digest_sign_init` (or `sign_init`)
    ///   was not called first; the context has no signing key loaded.
    /// * [`ProviderError::Common`] — message is malformed or the
    ///   configured µ-only mode (set via the `mu` ctx parameter) is
    ///   incompatible with one-shot signing because the crypto crate
    ///   does not yet expose direct µ injection.
    /// * [`ProviderError::Dispatch`] — the underlying
    ///   [`crate::pqc::ml_dsa::ml_dsa_sign`] primitive failed (e.g.
    ///   entropy too short, key inconsistency, FIPS self-test
    ///   deferral failure).
    ///
    /// [`crate::pqc::ml_dsa::ml_dsa_sign`]: openssl_crypto::pqc::ml_dsa::ml_dsa_sign
    pub fn digest_sign(&mut self, message: &[u8]) -> ProviderResult<Vec<u8>> {
        if self.operation != Some(OperationMode::Sign) {
            warn!(
                algorithm = self.variant.name(),
                "ml-dsa: digest_sign called without digest_sign_init"
            );
            return Err(ProviderError::Init(
                "ml-dsa: digest_sign called without digest_sign_init".to_string(),
            ));
        }
        debug!(
            algorithm = self.variant.name(),
            message_len = message.len(),
            "ml-dsa: digest_sign one-shot"
        );
        self.sign_internal(message)
    }

    /// One-shot ML-DSA digest-verification entry point.
    ///
    /// Mirrors the C macro-generated `ml_dsa_digest_verify` one-shot
    /// path in `ml_dsa_sig.c`.  The caller must have invoked
    /// [`MlDsaSignatureContext::digest_verify_init`] beforehand to load
    /// the public key and set the operation mode.  Like
    /// [`Self::digest_sign`], any externally supplied digest name is
    /// rejected at `digest_verify_init` time because ML-DSA defines its
    /// own SHAKE-256-based µ construction; this entry point therefore
    /// simply delegates to the internal verification primitive once the
    /// state has been validated.
    ///
    /// Returns `Ok(true)` on a valid signature, `Ok(false)` on a
    /// well-formed but invalid signature, and an `Err` for state or
    /// dispatch failures.
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Init`] — `digest_verify_init` (or
    ///   `verify_init`) was not called first.
    /// * [`ProviderError::Common`] — `signature` length does not match
    ///   the variant's expected signature size, or the µ-only mode
    ///   parameter is incompatible with one-shot verification.
    /// * [`ProviderError::Dispatch`] — the underlying
    ///   [`crate::pqc::ml_dsa::ml_dsa_verify`] primitive failed (FIPS
    ///   self-test deferral failure, key inconsistency).
    ///
    /// [`crate::pqc::ml_dsa::ml_dsa_verify`]: openssl_crypto::pqc::ml_dsa::ml_dsa_verify
    pub fn digest_verify(&mut self, message: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.operation != Some(OperationMode::Verify) {
            warn!(
                algorithm = self.variant.name(),
                "ml-dsa: digest_verify called without digest_verify_init"
            );
            return Err(ProviderError::Init(
                "ml-dsa: digest_verify called without digest_verify_init".to_string(),
            ));
        }
        debug!(
            algorithm = self.variant.name(),
            message_len = message.len(),
            signature_len = signature.len(),
            "ml-dsa: digest_verify one-shot"
        );
        self.verify_internal(message, signature)
    }
}

// -----------------------------------------------------------------------------
// Manual Debug impl — keep sensitive material out of `Debug` output.
// -----------------------------------------------------------------------------

impl fmt::Debug for MlDsaSignatureContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSignatureContext")
            .field("variant", &self.variant)
            .field("operation", &self.operation)
            .field("has_key", &self.key.is_some())
            .field("has_context_string", &self.context_string.is_some())
            .field("has_test_entropy", &self.test_entropy.is_some())
            .field("deterministic", &self.deterministic)
            .field("msg_encode", &self.msg_encode)
            .field("mu_mode", &self.mu_mode)
            .field(
                "cached_signature_len",
                &self.cached_signature.as_ref().map(Vec::len),
            )
            .field("propq", &self.propq)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Helpers — algorithm-identifier DER and digest-name validation.
// =============================================================================

/// Returns the DER-encoded `AlgorithmIdentifier` SEQUENCE for an
/// ML-DSA variant.  Parameters are absent (per FIPS 204 §6.2 and the
/// X.509 hybrid PKI profile in IETF `draft-ietf-lamps-dilithium-certificates`).
///
/// Encoding layout:
///
/// ```text
/// SEQUENCE (length 11) {
///     OID (length 9) 2.16.840.1.101.3.4.3.<NN>
/// }
/// ```
///
/// The leading 0x60 byte encodes joint-iso-itu-t(2)·country(16) per
/// ITU-T X.690 §8.19.4 (40 × 2 + 16 = 96 = 0x60); the rest of the OID
/// follows base-128 encoding.
#[must_use]
fn algorithm_identifier_der(variant: MlDsaVariant) -> Vec<u8> {
    let trailer: u8 = match variant {
        MlDsaVariant::MlDsa44 => 0x11,
        MlDsaVariant::MlDsa65 => 0x12,
        MlDsaVariant::MlDsa87 => 0x13,
    };
    vec![
        0x30, 0x0B, // SEQUENCE, length 11
        0x06, 0x09, // OID, length 9
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, trailer,
    ]
}

/// Parses an ML-DSA variant identifier as supplied through the `instance`
/// parameter or the OID alias.  The full set of recognised names mirrors
/// the array used by the descriptor table at the bottom of this file.
///
/// This helper is currently exercised exclusively from the unit-test module
/// — at runtime the variant is selected by the provider entry point (via
/// [`MlDsaSignatureProvider::variant`]) before the context is constructed,
/// so no parsing is needed on the hot path.  The function is retained
/// because it encodes the canonical alias/OID table used to validate the
/// descriptor entries and to preserve a single source of truth for variant
/// resolution that future callers (e.g. a trait impl that accepts a
/// runtime-supplied algorithm name) can consume without rewriting the
/// alias mapping.  Gating it with `#[cfg(test)]` avoids a `dead_code`
/// warning under `-D warnings` while keeping the canonical mapping in one
/// place.
#[cfg(test)]
fn parse_variant_name(name: &str) -> ProviderResult<MlDsaVariant> {
    let normalised = name.trim();
    let upper = normalised.to_ascii_uppercase();
    let variant = match upper.as_str() {
        "ML-DSA-44" | "MLDSA44" | "ID-ML-DSA-44" | "2.16.840.1.101.3.4.3.17" => {
            MlDsaVariant::MlDsa44
        }
        "ML-DSA-65" | "MLDSA65" | "ID-ML-DSA-65" | "2.16.840.1.101.3.4.3.18" => {
            MlDsaVariant::MlDsa65
        }
        "ML-DSA-87" | "MLDSA87" | "ID-ML-DSA-87" | "2.16.840.1.101.3.4.3.19" => {
            MlDsaVariant::MlDsa87
        }
        _ => {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("unknown ML-DSA variant name: {name}"),
            )));
        }
    };
    Ok(variant)
}

/// Rejects any caller-supplied digest name.
///
/// FIPS 204 fixes the µ construction inside the algorithm itself, so an
/// external digest selection is meaningless for ML-DSA.  The C source
/// returns `ERR_R_DISABLED_FOR_FIPS` from
/// `ml_dsa_digest_signverify_init` (line 414); we translate that to
/// [`ProviderError::Dispatch`] which carries a structured explanation.
fn enforce_digest_match(variant: MlDsaVariant, digest: &str) -> ProviderResult<()> {
    if digest.is_empty() {
        return Ok(());
    }
    warn!(
        algorithm = variant.name(),
        rejected_digest = digest,
        "ml-dsa: external digest selection is forbidden by FIPS 204"
    );
    Err(ProviderError::Dispatch(format!(
        "ML-DSA defines its own µ construction; external digest '{digest}' is rejected for {}",
        variant.name()
    )))
}

// =============================================================================
// SignatureContext trait implementation
// =============================================================================

impl SignatureContext for MlDsaSignatureContext {
    fn sign_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = self.variant.name(),
            key_len = key.len(),
            "ml-dsa: sign_init"
        );
        let parsed = self.parse_key_for_signing(key)?;
        self.key = Some(parsed);
        self.operation = Some(OperationMode::Sign);
        self.streaming_buffer.clear();
        if let Some(prev) = self.cached_signature.as_mut() {
            prev.zeroize();
        }
        self.cached_signature = None;

        if let Some(p) = params {
            self.set_ctx_params(p)?;
        }
        Ok(())
    }

    fn sign(&mut self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        if self.operation != Some(OperationMode::Sign) {
            return Err(ProviderError::Init(
                "ml-dsa: sign called without sign_init".to_string(),
            ));
        }
        self.sign_internal(data)
    }

    fn verify_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = self.variant.name(),
            key_len = key.len(),
            "ml-dsa: verify_init"
        );
        let parsed = self.parse_key_for_verify(key)?;
        self.key = Some(parsed);
        self.operation = Some(OperationMode::Verify);
        self.streaming_buffer.clear();

        if let Some(p) = params {
            self.set_ctx_params(p)?;
        }
        Ok(())
    }

    fn verify(&mut self, data: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "ml-dsa: verify called without verify_init".to_string(),
            ));
        }
        self.verify_internal(data, signature)
    }

    // -------------------------------------------------------------------------
    // digest_sign / digest_verify — delegate to one-shot sign/verify after
    // rejecting any externally-supplied digest name.  ML-DSA uses its
    // own internal µ construction; allowing a digest selection is a
    // FIPS 204 violation.
    // -------------------------------------------------------------------------

    fn digest_sign_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = self.variant.name(),
            digest = digest,
            key_len = key.len(),
            "ml-dsa: digest_sign_init"
        );
        enforce_digest_match(self.variant, digest)?;
        SignatureContext::sign_init(self, key, params)
    }

    fn digest_sign_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(
            algorithm = self.variant.name(),
            chunk_len = data.len(),
            "ml-dsa: digest_sign_update (buffering)"
        );
        if self.operation != Some(OperationMode::Sign) {
            return Err(ProviderError::Init(
                "ml-dsa: digest_sign_update called without digest_sign_init".to_string(),
            ));
        }
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>> {
        debug!(
            algorithm = self.variant.name(),
            buffered_len = self.streaming_buffer.len(),
            "ml-dsa: digest_sign_final"
        );
        if self.operation != Some(OperationMode::Sign) {
            return Err(ProviderError::Init(
                "ml-dsa: digest_sign_final called without digest_sign_init".to_string(),
            ));
        }
        let message = std::mem::take(&mut self.streaming_buffer);
        let sig = self.sign_internal(&message)?;
        // Scrub the message buffer — it may carry secrets.
        let mut spent = message;
        spent.zeroize();
        Ok(sig)
    }

    fn digest_verify_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = self.variant.name(),
            digest = digest,
            key_len = key.len(),
            "ml-dsa: digest_verify_init"
        );
        enforce_digest_match(self.variant, digest)?;
        SignatureContext::verify_init(self, key, params)
    }

    fn digest_verify_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(
            algorithm = self.variant.name(),
            chunk_len = data.len(),
            "ml-dsa: digest_verify_update (buffering)"
        );
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "ml-dsa: digest_verify_update called without digest_verify_init".to_string(),
            ));
        }
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_verify_final(&mut self, signature: &[u8]) -> ProviderResult<bool> {
        debug!(
            algorithm = self.variant.name(),
            buffered_len = self.streaming_buffer.len(),
            signature_len = signature.len(),
            "ml-dsa: digest_verify_final"
        );
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "ml-dsa: digest_verify_final called without digest_verify_init".to_string(),
            ));
        }
        let message = std::mem::take(&mut self.streaming_buffer);
        let ok = self.verify_internal(&message, signature)?;
        let mut spent = message;
        spent.zeroize();
        Ok(ok)
    }

    // -------------------------------------------------------------------------
    // Trait-level parameter access.
    // -------------------------------------------------------------------------

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // The trait method is `&self` so we can't lazily populate the
        // AID cache; build the AID locally and return it.  The local
        // bytes are cheap to recompute (≤13 bytes per call).
        let aid = self
            .aid_cache
            .clone()
            .unwrap_or_else(|| algorithm_identifier_der(self.variant));
        let mut out = ParamSet::new();
        out.set("algorithm-id", ParamValue::OctetString(aid));
        out.set(
            "instance",
            ParamValue::Utf8String(self.variant.name().to_string()),
        );
        out.set(
            "deterministic",
            ParamValue::Int32(i32::from(u8::from(self.deterministic))),
        );
        out.set(
            "message-encoding",
            ParamValue::Int32(self.msg_encode.as_i32()),
        );
        out.set("mu", ParamValue::Int32(i32::from(u8::from(self.mu_mode))));
        out.set(
            "security-bits",
            ParamValue::Int32(self.variant.security_bits()),
        );
        Ok(out)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.set_ctx_params(params)
    }
}

// =============================================================================
// Algorithm descriptors — exact preservation of the prior stub's surface.
// =============================================================================

/// Returns ML-DSA signature algorithm descriptors for provider registration.
///
/// Emits one descriptor per parameter set
/// (`OSSL_DISPATCH ossl_ml_dsa_{44,65,87}_signature_functions[]`).
/// The order mirrors the C array so consumers iterating the results observe
/// the same precedence as the C build, satisfying the deterministic
/// fingerprint requirement called out in the architecture doc.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &[
                "ML-DSA-44",
                "MLDSA44",
                "2.16.840.1.101.3.4.3.17",
                "id-ml-dsa-44",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-44 implementation (FIPS 204, security category 2)",
        ),
        algorithm(
            &[
                "ML-DSA-65",
                "MLDSA65",
                "2.16.840.1.101.3.4.3.18",
                "id-ml-dsa-65",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-65 implementation (FIPS 204, security category 3)",
        ),
        algorithm(
            &[
                "ML-DSA-87",
                "MLDSA87",
                "2.16.840.1.101.3.4.3.19",
                "id-ml-dsa-87",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-87 implementation (FIPS 204, security category 5)",
        ),
    ]
}

// =============================================================================
// Tests
// =============================================================================

// Rationale: Tests intentionally use unwrap/expect/panic to fail fast on
// unexpected errors. The workspace-wide `unwrap_used` and `expect_used` lints
// are documented in the root `Cargo.toml` as applying to library code only —
// "Tests and CLI main() may #[allow] with justification." Panics trigger
// automatic test failure with a clear backtrace, which is exactly the desired
// diagnostic behaviour in unit tests.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // descriptors() — preserved verbatim from the prior stub.
    // -------------------------------------------------------------------------

    #[test]
    fn descriptors_returns_three_entries() {
        let descs = descriptors();
        assert_eq!(descs.len(), 3, "expected three ML-DSA parameter sets");
    }

    #[test]
    fn descriptors_cover_all_security_levels() {
        let descs = descriptors();
        for canonical in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing ML-DSA descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn descriptors_include_alias_and_oid() {
        let descs = descriptors();
        for d in &descs {
            // every descriptor carries at least canonical + compact + OID + id-ml-dsa-*
            assert!(d.names.len() >= 4, "expected canonical + 3 aliases");
        }
    }

    #[test]
    fn descriptors_have_default_property() {
        let descs = descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }

    // -------------------------------------------------------------------------
    // MlDsaVariant API
    // -------------------------------------------------------------------------

    #[test]
    fn variant_name_round_trip() {
        for v in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let parsed = parse_variant_name(v.name()).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn variant_compact_alias_round_trip() {
        assert_eq!(
            parse_variant_name("MLDSA44").unwrap(),
            MlDsaVariant::MlDsa44
        );
        assert_eq!(
            parse_variant_name("MLDSA65").unwrap(),
            MlDsaVariant::MlDsa65
        );
        assert_eq!(
            parse_variant_name("MLDSA87").unwrap(),
            MlDsaVariant::MlDsa87
        );
    }

    #[test]
    fn variant_oid_round_trip() {
        assert_eq!(
            parse_variant_name("2.16.840.1.101.3.4.3.17").unwrap(),
            MlDsaVariant::MlDsa44
        );
        assert_eq!(
            parse_variant_name("2.16.840.1.101.3.4.3.18").unwrap(),
            MlDsaVariant::MlDsa65
        );
        assert_eq!(
            parse_variant_name("2.16.840.1.101.3.4.3.19").unwrap(),
            MlDsaVariant::MlDsa87
        );
    }

    #[test]
    fn variant_unknown_name_rejected() {
        let err = parse_variant_name("SHA-512").unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn variant_security_bits_match_categories() {
        assert_eq!(MlDsaVariant::MlDsa44.security_bits(), 128);
        assert_eq!(MlDsaVariant::MlDsa65.security_bits(), 192);
        assert_eq!(MlDsaVariant::MlDsa87.security_bits(), 256);
    }

    #[test]
    fn variant_security_categories_match_spec() {
        assert_eq!(MlDsaVariant::MlDsa44.security_category(), 2);
        assert_eq!(MlDsaVariant::MlDsa65.security_category(), 3);
        assert_eq!(MlDsaVariant::MlDsa87.security_category(), 5);
    }

    #[test]
    fn variant_evp_type_distinct() {
        assert_eq!(MlDsaVariant::MlDsa44.evp_type(), 0);
        assert_eq!(MlDsaVariant::MlDsa65.evp_type(), 1);
        assert_eq!(MlDsaVariant::MlDsa87.evp_type(), 2);
    }

    #[test]
    fn variant_oid_strings_distinct() {
        let oids: Vec<&str> = [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ]
        .into_iter()
        .map(MlDsaVariant::oid)
        .collect();
        assert!(oids.iter().all(|s| s.starts_with("2.16.840.1.101.3.4.3.")));
        assert_eq!(oids.len(), 3);
        let mut sorted = oids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 3, "OID strings must be distinct");
    }

    #[test]
    fn variant_lengths_match_fips204_table2() {
        assert_eq!(MlDsaVariant::MlDsa44.public_key_len(), 1312);
        assert_eq!(MlDsaVariant::MlDsa44.private_key_len(), 2560);
        assert_eq!(MlDsaVariant::MlDsa44.signature_len(), 2420);

        assert_eq!(MlDsaVariant::MlDsa65.public_key_len(), 1952);
        assert_eq!(MlDsaVariant::MlDsa65.private_key_len(), 4032);
        assert_eq!(MlDsaVariant::MlDsa65.signature_len(), 3309);

        assert_eq!(MlDsaVariant::MlDsa87.public_key_len(), 2592);
        assert_eq!(MlDsaVariant::MlDsa87.private_key_len(), 4896);
        assert_eq!(MlDsaVariant::MlDsa87.signature_len(), 4627);
    }

    #[test]
    fn variant_display_matches_name() {
        assert_eq!(
            format!("{}", MlDsaVariant::MlDsa65),
            "ML-DSA-65".to_string()
        );
    }

    #[test]
    fn variant_crypto_round_trip() {
        for v in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let crypto: CryptoMlDsaVariant = v.into();
            let back: MlDsaVariant = crypto.into();
            assert_eq!(back, v);
        }
    }

    // -------------------------------------------------------------------------
    // MlDsaMessageEncode
    // -------------------------------------------------------------------------

    #[test]
    fn message_encode_round_trip() {
        for mode in [MlDsaMessageEncode::Raw, MlDsaMessageEncode::Pure] {
            let parsed = MlDsaMessageEncode::from_i32(mode.as_i32()).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn message_encode_unknown_rejected() {
        let err = MlDsaMessageEncode::from_i32(7).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn message_encode_default_is_pure() {
        assert_eq!(MlDsaMessageEncode::default(), MlDsaMessageEncode::Pure);
    }

    #[test]
    fn message_encode_is_pure_helper() {
        assert!(MlDsaMessageEncode::Pure.is_pure());
        assert!(!MlDsaMessageEncode::Raw.is_pure());
    }

    // -------------------------------------------------------------------------
    // MlDsaSignatureProvider
    // -------------------------------------------------------------------------

    #[test]
    fn provider_name_matches_variant() {
        for v in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let p = MlDsaSignatureProvider::new(v);
            assert_eq!(p.name(), v.name());
            assert_eq!(p.variant(), v);
        }
    }

    #[test]
    fn provider_with_context_preserves_handle() {
        let ctx = LibContext::get_default();
        let p = MlDsaSignatureProvider::new_with_context(
            MlDsaVariant::MlDsa65,
            Arc::clone(&ctx),
            Some("provider=default".to_string()),
        );
        assert_eq!(p.variant(), MlDsaVariant::MlDsa65);
        assert_eq!(p.name(), "ML-DSA-65");
    }

    #[test]
    fn provider_new_ctx_returns_box() {
        let p = MlDsaSignatureProvider::new(MlDsaVariant::MlDsa44);
        let _ctx: Box<dyn SignatureContext> = p.new_ctx().unwrap();
    }

    // -------------------------------------------------------------------------
    // MlDsaSignatureContext — direct (non-trait) API
    // -------------------------------------------------------------------------

    fn make_ctx(v: MlDsaVariant) -> MlDsaSignatureContext {
        MlDsaSignatureContext::new(v, LibContext::get_default(), None)
    }

    #[test]
    fn context_default_state_is_empty() {
        let ctx = make_ctx(MlDsaVariant::MlDsa44);
        assert_eq!(ctx.variant(), MlDsaVariant::MlDsa44);
        assert!(ctx.key.is_none());
        assert!(ctx.context_string.is_none());
        assert!(ctx.test_entropy.is_none());
        assert!(!ctx.deterministic);
        assert_eq!(ctx.msg_encode, MlDsaMessageEncode::Pure);
        assert!(!ctx.mu_mode);
        assert!(ctx.operation.is_none());
        assert!(ctx.streaming_buffer.is_empty());
        assert!(ctx.cached_signature.is_none());
    }

    #[test]
    fn context_duplicate_clones_state() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa65);
        ctx.context_string = Some(b"session-1".to_vec());
        ctx.deterministic = true;
        ctx.msg_encode = MlDsaMessageEncode::Raw;
        ctx.streaming_buffer = vec![1, 2, 3];
        let dup = ctx.duplicate();
        assert_eq!(dup.variant(), ctx.variant());
        assert_eq!(dup.context_string, ctx.context_string);
        assert_eq!(dup.deterministic, ctx.deterministic);
        assert_eq!(dup.msg_encode, ctx.msg_encode);
        assert_eq!(dup.streaming_buffer, ctx.streaming_buffer);
    }

    #[test]
    fn context_set_context_string_accepts_max_len() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let bytes = vec![0xAA; ML_DSA_MAX_CONTEXT_STRING_LEN];
        ctx.set_context_string(Some(bytes.clone())).unwrap();
        assert_eq!(ctx.context_string.as_deref(), Some(bytes.as_slice()));
    }

    #[test]
    fn context_set_context_string_rejects_overlong() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let bytes = vec![0u8; ML_DSA_MAX_CONTEXT_STRING_LEN + 1];
        let err = ctx.set_context_string(Some(bytes)).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn context_set_context_string_clears_previous() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        ctx.set_context_string(Some(b"first".to_vec())).unwrap();
        ctx.set_context_string(Some(b"second".to_vec())).unwrap();
        assert_eq!(ctx.context_string.as_deref(), Some(b"second".as_slice()));
        ctx.set_context_string(None).unwrap();
        assert!(ctx.context_string.is_none());
    }

    #[test]
    fn context_parse_key_for_signing_rejects_short_buffer() {
        let ctx = make_ctx(MlDsaVariant::MlDsa44);
        let result = ctx.parse_key_for_signing(&[0u8; 10]);
        match result {
            Err(ProviderError::Common(CommonError::InvalidArgument(_))) => {}
            other => panic!("expected InvalidArgument; got {:?}", other.err()),
        }
    }

    #[test]
    fn context_parse_key_for_signing_rejects_public_only() {
        let ctx = make_ctx(MlDsaVariant::MlDsa44);
        let pk_len = MlDsaVariant::MlDsa44.public_key_len();
        let result = ctx.parse_key_for_signing(&vec![0u8; pk_len]);
        match result {
            Err(ProviderError::Common(CommonError::InvalidArgument(_))) => {}
            other => panic!("expected InvalidArgument; got {:?}", other.err()),
        }
    }

    #[test]
    fn context_parse_key_for_verify_rejects_garbage_length() {
        let ctx = make_ctx(MlDsaVariant::MlDsa65);
        let result = ctx.parse_key_for_verify(&[0u8; 7]);
        match result {
            Err(ProviderError::Common(CommonError::InvalidArgument(_))) => {}
            other => panic!("expected InvalidArgument; got {:?}", other.err()),
        }
    }

    // -------------------------------------------------------------------------
    // set_ctx_params / get_ctx_params
    // -------------------------------------------------------------------------

    #[test]
    fn set_ctx_params_accepts_context_string() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set("context-string", ParamValue::OctetString(b"hello".to_vec()));
        ctx.set_ctx_params(&p).unwrap();
        assert_eq!(ctx.context_string.as_deref(), Some(b"hello".as_slice()));
    }

    #[test]
    fn set_ctx_params_rejects_long_context_string() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set(
            "context-string",
            ParamValue::OctetString(vec![0u8; ML_DSA_MAX_CONTEXT_STRING_LEN + 1]),
        );
        let err = ctx.set_ctx_params(&p).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn set_ctx_params_accepts_deterministic_flag() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set("deterministic", ParamValue::Int32(1));
        ctx.set_ctx_params(&p).unwrap();
        assert!(ctx.deterministic);

        let mut p = ParamSet::new();
        p.set("deterministic", ParamValue::Int32(0));
        ctx.set_ctx_params(&p).unwrap();
        assert!(!ctx.deterministic);
    }

    #[test]
    fn set_ctx_params_accepts_test_entropy() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set(
            "test-entropy",
            ParamValue::OctetString(vec![0xAB; ML_DSA_ENTROPY_LEN]),
        );
        ctx.set_ctx_params(&p).unwrap();
        assert_eq!(ctx.test_entropy, Some([0xAB; ML_DSA_ENTROPY_LEN]));
    }

    #[test]
    fn set_ctx_params_rejects_wrong_entropy_length() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set(
            "test-entropy",
            ParamValue::OctetString(vec![0u8; ML_DSA_ENTROPY_LEN - 1]),
        );
        let err = ctx.set_ctx_params(&p).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn set_ctx_params_accepts_message_encoding() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set("message-encoding", ParamValue::Int32(0));
        ctx.set_ctx_params(&p).unwrap();
        assert_eq!(ctx.msg_encode, MlDsaMessageEncode::Raw);

        let mut p = ParamSet::new();
        p.set("message-encoding", ParamValue::Int32(1));
        ctx.set_ctx_params(&p).unwrap();
        assert_eq!(ctx.msg_encode, MlDsaMessageEncode::Pure);
    }

    #[test]
    fn set_ctx_params_rejects_unknown_message_encoding() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set("message-encoding", ParamValue::Int32(99));
        let err = ctx.set_ctx_params(&p).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn set_ctx_params_accepts_mu_flag() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set("mu", ParamValue::Int32(1));
        ctx.set_ctx_params(&p).unwrap();
        assert!(ctx.mu_mode);
    }

    #[test]
    fn set_ctx_params_accepts_signature_cache() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set("signature", ParamValue::OctetString(vec![0xEE; 64]));
        ctx.set_ctx_params(&p).unwrap();
        assert_eq!(
            ctx.cached_signature.as_deref(),
            Some(vec![0xEE; 64].as_slice())
        );
    }

    #[test]
    fn set_ctx_params_empty_is_noop() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        ctx.set_ctx_params(&ParamSet::new()).unwrap();
    }

    #[test]
    fn set_ctx_params_rejects_type_mismatch() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set("deterministic", ParamValue::Utf8String("yes".to_string()));
        let err = ctx.set_ctx_params(&p).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::ParamTypeMismatch { .. })
        ));
    }

    #[test]
    fn get_ctx_params_includes_algorithm_id() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let p = ctx.get_ctx_params().unwrap();
        let v = p.get("algorithm-id").unwrap();
        let bytes = v.as_bytes().unwrap();
        let expected = algorithm_identifier_der(MlDsaVariant::MlDsa44);
        assert_eq!(bytes, expected.as_slice());
    }

    #[test]
    fn get_ctx_params_includes_instance_name() {
        for v in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let mut ctx = make_ctx(v);
            let p = ctx.get_ctx_params().unwrap();
            let val = p.get("instance").unwrap();
            assert_eq!(val.as_str().unwrap(), v.name());
        }
    }

    #[test]
    fn get_ctx_params_includes_security_bits() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa87);
        let p = ctx.get_ctx_params().unwrap();
        let val = p.get("security-bits").unwrap();
        assert_eq!(val.as_i32().unwrap(), 256);
    }

    // -------------------------------------------------------------------------
    // SignatureContext trait method validation
    // -------------------------------------------------------------------------

    #[test]
    fn sign_init_rejects_invalid_key_length() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::sign_init(&mut ctx, &[0u8; 10], None).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn verify_init_rejects_invalid_key_length() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::verify_init(&mut ctx, &[0u8; 10], None).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn sign_without_init_returns_init_error() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::sign(&mut ctx, b"msg").unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn verify_without_init_returns_init_error() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::verify(&mut ctx, b"msg", &vec![0u8; 2420]).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_sign_init_rejects_external_digest() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err =
            SignatureContext::digest_sign_init(&mut ctx, "SHA-512", &[0u8; 10], None).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn digest_verify_init_rejects_external_digest() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::digest_verify_init(&mut ctx, "SHAKE256", &[0u8; 10], None)
            .unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn digest_sign_init_accepts_empty_digest() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        // Empty digest is allowed; key validation then fails with the
        // length-mismatch error path.
        let err = SignatureContext::digest_sign_init(&mut ctx, "", &[0u8; 10], None).unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn digest_sign_update_without_init_errors() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::digest_sign_update(&mut ctx, b"chunk").unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_sign_final_without_init_errors() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::digest_sign_final(&mut ctx).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_verify_update_without_init_errors() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::digest_verify_update(&mut ctx, b"chunk").unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_verify_final_without_init_errors() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = SignatureContext::digest_verify_final(&mut ctx, &vec![0u8; 2420]).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn trait_get_params_returns_algorithm_id() {
        let ctx = make_ctx(MlDsaVariant::MlDsa65);
        let p = SignatureContext::get_params(&ctx).unwrap();
        let v = p.get("algorithm-id").unwrap();
        let bytes = v.as_bytes().unwrap();
        let expected = algorithm_identifier_der(MlDsaVariant::MlDsa65);
        assert_eq!(bytes, expected.as_slice());
    }

    #[test]
    fn trait_set_params_delegates_to_inherent() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let mut p = ParamSet::new();
        p.set("deterministic", ParamValue::Int32(1));
        SignatureContext::set_params(&mut ctx, &p).unwrap();
        assert!(ctx.deterministic);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    #[test]
    fn algorithm_identifier_der_matches_known_oids() {
        let aid44 = algorithm_identifier_der(MlDsaVariant::MlDsa44);
        let aid65 = algorithm_identifier_der(MlDsaVariant::MlDsa65);
        let aid87 = algorithm_identifier_der(MlDsaVariant::MlDsa87);
        assert_eq!(aid44.len(), 13);
        assert_eq!(aid65.len(), 13);
        assert_eq!(aid87.len(), 13);
        // SEQUENCE outer-tag and length
        for b in [&aid44, &aid65, &aid87] {
            assert_eq!(b[0], 0x30);
            assert_eq!(b[1], 0x0B);
            assert_eq!(b[2], 0x06); // OID tag
            assert_eq!(b[3], 0x09); // OID length
            assert_eq!(&b[4..12], &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03]);
        }
        // Final byte is the algorithm-specific suffix byte
        assert_eq!(aid44[12], 0x11);
        assert_eq!(aid65[12], 0x12);
        assert_eq!(aid87[12], 0x13);
    }

    #[test]
    fn enforce_digest_match_accepts_empty() {
        enforce_digest_match(MlDsaVariant::MlDsa44, "").unwrap();
    }

    #[test]
    fn enforce_digest_match_rejects_named_digest() {
        let err = enforce_digest_match(MlDsaVariant::MlDsa65, "SHA-512").unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // -------------------------------------------------------------------------
    // One-shot digest_sign / digest_verify inherent methods
    // -------------------------------------------------------------------------

    #[test]
    fn digest_sign_without_init_errors() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        let err = ctx.digest_sign(b"message").unwrap_err();
        assert!(
            matches!(err, ProviderError::Init(_)),
            "expected Init error; got {err:?}"
        );
    }

    #[test]
    fn digest_verify_without_init_errors() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        // Use the variant's signature length so the length-validation
        // path is not the one rejecting the call.
        let dummy_sig = vec![0u8; ctx.variant.signature_len()];
        let err = ctx.digest_verify(b"message", &dummy_sig).unwrap_err();
        assert!(
            matches!(err, ProviderError::Init(_)),
            "expected Init error; got {err:?}"
        );
    }

    #[test]
    fn digest_sign_after_verify_init_returns_init_error() {
        // Setting `operation = Some(Verify)` then calling digest_sign
        // must error — the modes are mutually exclusive.  We force the
        // state without going through the real key-loading path because
        // load operations exercise the crypto-layer parser which is not
        // the surface under test here.
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        ctx.operation = Some(OperationMode::Verify);
        let err = ctx.digest_sign(b"msg").unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_verify_after_sign_init_returns_init_error() {
        let mut ctx = make_ctx(MlDsaVariant::MlDsa44);
        ctx.operation = Some(OperationMode::Sign);
        let dummy_sig = vec![0u8; ctx.variant.signature_len()];
        let err = ctx.digest_verify(b"msg", &dummy_sig).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // -------------------------------------------------------------------------
    // Public constants
    // -------------------------------------------------------------------------

    #[test]
    fn public_constants_match_fips204() {
        assert_eq!(ML_DSA_MAX_CONTEXT_STRING_LEN, 255);
        assert_eq!(ML_DSA_MU_OUTPUT_LEN, 64);
        assert_eq!(ML_DSA_ENTROPY_LEN, 32);
    }
}
