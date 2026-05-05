//! LMS (Leighton-Micali Hash-Based Signatures) provider implementation.
//!
//! Translates the LMS signature dispatch entry from
//! `providers/defltprov.c` (line 540, `ALG(PROV_NAMES_LMS,
//! ossl_lms_signature_functions)`) into a Rust descriptor consumed by
//! [`crate::implementations::signatures::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/signatures/lms_signature.c` (~290 lines)
//! and provides verify-only support for LMS as defined in
//! NIST SP 800-208 / RFC 8554. LMS is a stateful hash-based signature
//! scheme: only verification is exposed by the default provider.
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_signature_descriptors` →
//! `crate::implementations::signatures::descriptors` →
//! `crate::implementations::signatures::lms::descriptors` (this module).
//!
//! Provider-trait wiring: `LmsSignatureProvider::new` is constructed by the
//! default provider when registering the LMS algorithm. Each call to
//! [`SignatureProvider::new_ctx`] yields a fresh [`LmsSignatureContext`] which
//! implements the full [`SignatureContext`] trait surface — sign-side methods
//! deliberately return [`ProviderError::Dispatch`] errors because LMS is a
//! *stateful* scheme: the C provider exposes verification only, and the Rust
//! provider preserves that semantic boundary. Specifically, the C dispatch
//! table at `lms_signature.c` lines 157–168 lists exactly six entries —
//! verify-only — so the corresponding sign-side Rust trait methods all
//! surface [`ProviderError::Dispatch`] errors.
//!
//! # C Source Mapping
//!
//! | C Source                                                     | Rust Equivalent                                            |
//! |--------------------------------------------------------------|-------------------------------------------------------------|
//! | `providers/defltprov.c` line 540                             | [`descriptors`] in this module                             |
//! | `providers/implementations/signature/lms_signature.c` lines 30–35  | [`LmsSignatureContext`] (`PROV_LMS_CTX` field layout) |
//! | `providers/implementations/signature/lms_signature.c` lines 37–61  | [`LmsSignatureProvider::new_ctx`] (newctx)            |
//! | `providers/implementations/signature/lms_signature.c` lines 63–72  | [`LmsSignatureContext::drop`] (freectx via [`Drop`])  |
//! | `providers/implementations/signature/lms_signature.c` lines 74–95  | [`LmsSignatureContext::set_digest`] (setdigest)       |
//! | `providers/implementations/signature/lms_signature.c` lines 97–112 | [`SignatureContext::verify_init`] (lms_verify_msg_init) |
//! | `providers/implementations/signature/lms_signature.c` lines 114–133| [`SignatureContext::verify`] (lms_verify)              |
//! | `providers/implementations/signature/lms_signature.c` lines 135–149| [`SignatureContext::digest_verify_init`]               |
//! | `providers/implementations/signature/lms_signature.c` lines 151–155| [`SignatureContext::digest_verify_final`]              |
//! | `PROV_NAMES_LMS` in `prov/names.h`                           | `"LMS"` and `id-alg-hss-lms-hashsig` aliases              |
//! | `crypto/lms/lms_sig.c::ossl_lms_sig_decode` + `ossl_lms_sig_verify` | [`openssl_crypto::pqc::lms::lms_verify`]            |
//! | `crypto/lms/lms_key.c::ossl_lms_key_new` (decode of pubkey)  | [`openssl_crypto::pqc::lms::LmsPubKey::decode`]            |
//!
//! # Rule Compliance
//!
//! | Rule | Compliance |
//! |------|------------|
//! | R5 (no sentinels)            | All operations return [`ProviderResult`]; the [`SignatureContext::verify`] outcome is `bool`, never an integer status code. |
//! | R6 (lossless casts)          | No narrowing casts in this module; all cryptographic arithmetic lives in [`openssl_crypto::pqc::lms`]. |
//! | R8 (no unsafe outside FFI)   | This module contains zero `unsafe` blocks. |
//! | R9 (warning-free)            | Builds cleanly under `RUSTFLAGS="-D warnings"`. |
//! | R10 (wiring before done)     | Reachable from `openssl-cli` via the default-provider descriptor pipeline; exercised by inline unit tests. |

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{CryptoError, ParamSet, ParamValue, ProviderError, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::md::MessageDigest;
use openssl_crypto::pqc::lms::{lms_verify, LmsPubKey};

use super::algorithm;
use super::OperationMode;
use crate::traits::{AlgorithmDescriptor, SignatureContext, SignatureProvider};

// =============================================================================
// Constants
// =============================================================================

/// Property string registered by every default-provider LMS descriptor.
const DEFAULT_PROPERTY: &str = "provider=default";

/// Canonical algorithm name returned by [`SignatureProvider::name`].
///
/// Must remain a single-word identifier so the algorithm-fetch machinery can
/// match it against [`AlgorithmDescriptor::names`] entries from
/// [`descriptors`].
const ALGORITHM_NAME: &str = "LMS";

// =============================================================================
// Helpers
// =============================================================================

/// Converts a [`CryptoError`] returned by the crypto crate into a
/// [`ProviderError::Dispatch`] suitable for surfacing through the
/// provider trait API.
///
/// Mirrors the pattern established by the ML-DSA and SLH-DSA signature
/// providers — all crypto-layer failures appear as `Dispatch` errors at
/// the provider boundary so that callers do not have to import
/// `openssl-crypto` types directly.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

// =============================================================================
// LmsSignatureProvider
// =============================================================================

/// Signature provider implementation for LMS (verification only).
///
/// One static instance per default-provider registration. Calls to
/// [`SignatureProvider::new_ctx`] yield a fresh [`LmsSignatureContext`].
/// LMS is a stateful hash-based signature scheme; the C
/// `providers/implementations/signature/lms_signature.c` file exposes only
/// verify-side dispatch entries (`NEWCTX`, `FREECTX`, `VERIFY_MESSAGE_INIT`,
/// `VERIFY`, `DIGEST_VERIFY_INIT`, `DIGEST_VERIFY`), and this implementation
/// preserves that semantic.
///
/// The struct itself is `Clone` and cheap to copy (the
/// [`Arc<LibContext>`] handle is reference-counted).
#[derive(Debug, Clone)]
pub struct LmsSignatureProvider {
    /// Library context shared with all contexts produced by this provider.
    libctx: Arc<LibContext>,
    /// Optional property query passed through to digest fetches.
    propq: Option<String>,
}

impl LmsSignatureProvider {
    /// Creates a provider bound to the default library context.
    ///
    /// Used by the default provider during signature-algorithm registration.
    /// Mirrors the C `lms_newctx` constructor at
    /// `lms_signature.c` lines 37–61: the C side stores a `libctx` and an
    /// optional `propq`; the Rust side does the same with `Arc<LibContext>`
    /// and `Option<String>`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            libctx: LibContext::get_default(),
            propq: None,
        }
    }

    /// Creates a provider bound to a caller-supplied library context and
    /// optional property query.
    ///
    /// Provided for testing and for callers that need to drive multiple
    /// independent library contexts (e.g. FIPS isolation).
    #[must_use]
    pub fn new_with_context(libctx: Arc<LibContext>, propq: Option<String>) -> Self {
        Self { libctx, propq }
    }
}

impl Default for LmsSignatureProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureProvider for LmsSignatureProvider {
    fn name(&self) -> &'static str {
        ALGORITHM_NAME
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>> {
        debug!(
            algorithm = ALGORITHM_NAME,
            propq = self.propq.as_deref().unwrap_or(""),
            "lms: creating new signature context"
        );
        Ok(Box::new(LmsSignatureContext::new(
            Arc::clone(&self.libctx),
            self.propq.clone(),
        )))
    }
}

// =============================================================================
// LmsSignatureContext
// =============================================================================

/// Per-operation verification context for LMS.
///
/// Field layout mirrors `PROV_LMS_CTX` at `lms_signature.c` lines 30–35:
///
/// ```c
/// typedef struct {
///     OSSL_LIB_CTX *libctx;
///     char         *propq;
///     LMS_KEY      *key;       // public-key only
///     EVP_MD       *md;        // mandated by key params
/// } PROV_LMS_CTX;
/// ```
///
/// Translation choices:
/// * `OSSL_LIB_CTX *libctx` → [`Arc<LibContext>`] shared with the provider.
/// * `char *propq`          → [`Option<String>`] (no NUL-termination concerns).
/// * `LMS_KEY *key`         → [`Option<Arc<LmsPubKey>>`] — public key only,
///                              decoded once during [`SignatureContext::verify_init`]
///                              so that subsequent calls to [`SignatureContext::verify`]
///                              do not have to re-parse the wire encoding.
/// * `EVP_MD *md`           → [`Option<MessageDigest>`] — fetched lazily by
///                              [`Self::set_digest`] using the digest name
///                              mandated by the key's OTS parameters.
///
/// Two extra fields exist relative to C:
/// * `operation: Option<OperationMode>` — guards every method against
///   "called before init" sequencing errors (Rule R5: no integer sentinels).
/// * `streaming_buffer: Vec<u8>`        — backing storage for the
///   `digest_verify_update` / `digest_verify_final` flow, since LMS
///   signs/verifies the full message rather than its digest.
///
/// All sensitive material implements [`Zeroize`] / [`ZeroizeOnDrop`] so
/// context teardown leaves no residue, mirroring the
/// `OPENSSL_clear_free(ctx->propq, ...)` and `EVP_MD_free(ctx->md)` cleanup
/// at `lms_signature.c` lines 65–71.
pub struct LmsSignatureContext {
    /// Library context (Rust equivalent of `OSSL_LIB_CTX *libctx`).
    lib_ctx: Arc<LibContext>,
    /// Optional property query string used when fetching digest dependencies.
    propq: Option<String>,
    /// Loaded LMS public key (decoded from the caller's wire encoding).
    key: Option<Arc<LmsPubKey>>,
    /// Digest mandated by the key's OTS parameters (not user-selectable).
    /// `None` until [`Self::set_digest`] has fetched the algorithm.
    digest: Option<MessageDigest>,
    /// Active operation tag — only [`OperationMode::Verify`] is ever stored
    /// because LMS is verify-only; sign-side trait methods refuse to mutate
    /// this field.
    operation: Option<OperationMode>,
    /// Streaming buffer used by [`SignatureContext::digest_verify_update`] /
    /// [`SignatureContext::digest_verify_final`].
    streaming_buffer: Vec<u8>,
}

// -----------------------------------------------------------------------------
// fmt::Debug — manual implementation: MessageDigest holds a function pointer
// so we surface only its name, and the LmsPubKey is reduced to its parameter
// labels to avoid printing the (large) root hash `K`.
// -----------------------------------------------------------------------------

impl fmt::Debug for LmsSignatureContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LmsSignatureContext")
            .field("lib_ctx", &"Arc<LibContext>")
            .field("propq", &self.propq)
            .field(
                "key",
                &self.key.as_ref().map(|k| {
                    format!(
                        "LmsPubKey(lms={:?}, ots={:?})",
                        k.lms_params().lms_type,
                        k.ots_params().lm_ots_type,
                    )
                }),
            )
            .field("digest", &self.digest.as_ref().map(MessageDigest::name))
            .field("operation", &self.operation)
            .field("streaming_buffer_len", &self.streaming_buffer.len())
            .finish()
    }
}

// -----------------------------------------------------------------------------
// Zeroize / Drop / ZeroizeOnDrop — explicit secure teardown.
// -----------------------------------------------------------------------------

impl Zeroize for LmsSignatureContext {
    fn zeroize(&mut self) {
        // Drop the key Arc; if this is the last reference, the underlying
        // LmsPubKey's `k` Vec is dropped (its bytes are public verification
        // material, but we drop them eagerly anyway for hygiene).
        self.key = None;
        // Digest does not own secret state, but null it out so a stale
        // reference cannot leak across operation resets.
        self.digest = None;
        // Streaming buffer may transiently contain caller-supplied
        // plaintext that callers consider sensitive — wipe it.
        self.streaming_buffer.zeroize();
        self.operation = None;
    }
}

impl Drop for LmsSignatureContext {
    fn drop(&mut self) {
        // Mirrors `lms_freectx` at `lms_signature.c` line 63–72, which runs
        // `OPENSSL_free(ctx->propq); EVP_MD_free(ctx->md); OPENSSL_free(ctx);`.
        self.zeroize();
    }
}

impl ZeroizeOnDrop for LmsSignatureContext {}

// -----------------------------------------------------------------------------
// Inherent methods — construction, digest mandation, verify primitive.
// -----------------------------------------------------------------------------

impl LmsSignatureContext {
    /// Creates a fresh context.  All operational state is empty; callers
    /// must invoke [`SignatureContext::verify_init`] before verifying.
    ///
    /// Mirrors `lms_newctx` at `lms_signature.c` lines 37–61: the C body
    /// `OPENSSL_zalloc`-allocates the struct and stores `libctx` + `propq`.
    pub(crate) fn new(lib_ctx: Arc<LibContext>, propq: Option<String>) -> Self {
        Self {
            lib_ctx,
            propq,
            key: None,
            digest: None,
            operation: None,
            streaming_buffer: Vec::new(),
        }
    }

    /// Resolves the digest mandated by the loaded key's OTS parameters and
    /// optionally validates a caller-supplied digest name against it.
    ///
    /// Direct translation of `setdigest` at `lms_signature.c` lines 74–95:
    ///
    /// > "Assume that only one digest can be used by LMS. Set the digest to
    /// > the one contained in the public key. If the optional digestname
    /// > passed in by the user is different then return an error."
    ///
    /// Behaviour matrix:
    ///
    /// | requested  | cached `self.digest`         | action                                           |
    /// |------------|------------------------------|--------------------------------------------------|
    /// | `None`     | `None`                       | fetch mandated digest, store it                  |
    /// | `None`     | `Some(md)` matching mandated | reuse cached `md`                                |
    /// | `None`     | `Some(md)` differing         | refetch mandated digest                          |
    /// | `Some(n)`  | resulting `md.name() == n`   | `Ok(())`                                         |
    /// | `Some(n)`  | resulting `md.name() != n`   | `Err(ProviderError::Dispatch)`                   |
    ///
    /// # Errors
    /// Returns [`ProviderError::Dispatch`] if no key has been loaded, if the
    /// digest fetch fails, or if a caller-supplied digest name differs from
    /// the mandated one.
    pub fn set_digest(&mut self, requested: Option<&str>) -> ProviderResult<()> {
        let key = self.key.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("LMS set_digest called before key was set".to_string())
        })?;
        let pub_digestname = key.ots_params().digest_name;

        // Step 1: ensure self.digest is populated with the mandated digest.
        let need_refetch = !matches!(self.digest.as_ref(), Some(md) if md.name() == pub_digestname);
        if need_refetch {
            trace!(
                algorithm = ALGORITHM_NAME,
                mandated_digest = pub_digestname,
                "lms: fetching mandated digest"
            );
            let md = MessageDigest::fetch(&self.lib_ctx, pub_digestname, self.propq.as_deref())
                .map_err(dispatch_err)?;
            self.digest = Some(md);
        }

        // Step 2: if the caller specified a name, ensure it matches.
        if let Some(name) = requested {
            // SAFETY of unwrap-equivalent: `self.digest` is `Some` after
            // the refetch logic above.  Use a guard rather than `unwrap`
            // to satisfy clippy::unwrap_used.
            let md_name = self
                .digest
                .as_ref()
                .map(MessageDigest::name)
                .unwrap_or_default();
            if md_name != name {
                debug!(
                    algorithm = ALGORITHM_NAME,
                    mandated = pub_digestname,
                    requested = name,
                    "lms: requested digest does not match key-mandated digest"
                );
                return Err(ProviderError::Dispatch(format!(
                    "LMS digest mismatch: key mandates {pub_digestname}, caller requested {name}"
                )));
            }
        }
        Ok(())
    }

    /// Convenience accessor used in tests.
    #[must_use]
    pub fn digest_name(&self) -> Option<&str> {
        self.digest.as_ref().map(MessageDigest::name)
    }

    /// Convenience accessor used in tests.
    #[must_use]
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Internal helper: decode the caller-supplied wire-format public key.
    ///
    /// `LmsPubKey::decode` returns `Ok(None)` for *structural* failures
    /// (length mismatch, unknown LMS/OTS tag) and `Err` only for internal
    /// invariant violations.  At the provider boundary both flavours are
    /// surfaced as [`ProviderError::Dispatch`] so callers see a single
    /// error category for "this is not a valid LMS public key".
    fn decode_pub_key(key: &[u8]) -> ProviderResult<Arc<LmsPubKey>> {
        let parsed = LmsPubKey::decode(key).map_err(dispatch_err)?;
        let pk = parsed.ok_or_else(|| {
            ProviderError::Dispatch(format!(
                "LMS public key decode failed: encoded length {} is not a well-formed LMS public key",
                key.len(),
            ))
        })?;
        Ok(Arc::new(pk))
    }

    /// Verification primitive shared by [`SignatureContext::verify`] and
    /// [`SignatureContext::digest_verify_final`].
    ///
    /// Equivalent of the C `lms_verify` body at lines 114–133:
    ///
    /// ```c
    /// LMS_KEY *pub = ctx->key;
    /// if (pub == NULL) return 0;
    /// if (!ossl_lms_sig_decode(&sig, pub, sigbuf, sigbuf_len)) return 0;
    /// ret = ossl_lms_sig_verify(sig, pub, ctx->md, msg, msglen);
    /// ossl_lms_sig_free(sig);
    /// return ret;
    /// ```
    ///
    /// In Rust, [`lms_verify`] performs the decode-then-verify in one call,
    /// returning `Ok(false)` for any structural failure.
    fn verify_internal(&self, msg: &[u8], sig: &[u8]) -> ProviderResult<bool> {
        let key = self.key.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("LMS verify called without verify_init".to_string())
        })?;
        // The mandated digest is required by the C source's contract; we
        // require it as well so that `set_digest` is always exercised
        // before verify reaches this point.
        if self.digest.is_none() {
            return Err(ProviderError::Dispatch(
                "LMS verify called before mandated digest was resolved".to_string(),
            ));
        }
        lms_verify(key, msg, sig).map_err(dispatch_err)
    }
}

// =============================================================================
// SignatureContext trait implementation
// =============================================================================

impl SignatureContext for LmsSignatureContext {
    // -------------------------------------------------------------------------
    // Sign-side methods — LMS is verify-only at the provider layer.
    //
    // The C dispatch table (`lms_signature.c` lines 157–168) lists exactly
    // six entries: NEWCTX, FREECTX, VERIFY_MESSAGE_INIT, VERIFY,
    // DIGEST_VERIFY_INIT, DIGEST_VERIFY.  No SIGN_*, MESSAGE_INIT (sign
    // side), or DIGEST_SIGN_* entries appear, so we surface uniform
    // dispatch errors for the corresponding Rust trait methods.
    // -------------------------------------------------------------------------

    fn sign_init(&mut self, _key: &[u8], _params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = ALGORITHM_NAME,
            "lms: sign_init called — LMS is verify-only at the provider layer"
        );
        Err(ProviderError::Dispatch(
            "LMS does not support signing through the provider interface".to_string(),
        ))
    }

    fn sign(&mut self, _data: &[u8]) -> ProviderResult<Vec<u8>> {
        debug!(
            algorithm = ALGORITHM_NAME,
            "lms: sign called — LMS is verify-only at the provider layer"
        );
        Err(ProviderError::Dispatch(
            "LMS does not support signing through the provider interface".to_string(),
        ))
    }

    fn digest_sign_init(
        &mut self,
        _digest: &str,
        _key: &[u8],
        _params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = ALGORITHM_NAME,
            "lms: digest_sign_init called — LMS is verify-only at the provider layer"
        );
        Err(ProviderError::Dispatch(
            "LMS does not support signing through the provider interface".to_string(),
        ))
    }

    fn digest_sign_update(&mut self, _data: &[u8]) -> ProviderResult<()> {
        Err(ProviderError::Dispatch(
            "LMS does not support signing through the provider interface".to_string(),
        ))
    }

    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>> {
        Err(ProviderError::Dispatch(
            "LMS does not support signing through the provider interface".to_string(),
        ))
    }

    // -------------------------------------------------------------------------
    // Verify-side methods — direct translations of the C dispatch entries.
    // -------------------------------------------------------------------------

    /// Direct translation of `lms_verify_msg_init` at lines 97–112.
    ///
    /// 1. Decode the caller's wire-format public key into an [`LmsPubKey`].
    /// 2. Store it for use by subsequent calls to [`Self::verify`].
    /// 3. Call [`Self::set_digest`] to fetch the digest mandated by the
    ///    key's OTS parameters (`setdigest(ctx, NULL)` in C).
    /// 4. Apply any caller-supplied parameters (currently a no-op for LMS
    ///    since the context has no settable verify-side state).
    fn verify_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = ALGORITHM_NAME,
            key_len = key.len(),
            "lms: verify_init"
        );
        let parsed = Self::decode_pub_key(key)?;
        self.key = Some(parsed);
        self.set_digest(None)?;
        self.operation = Some(OperationMode::Verify);
        self.streaming_buffer.clear();
        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }

    /// Direct translation of `lms_verify` at lines 114–133.
    ///
    /// Returns `Ok(true)` iff the signature is valid for the message under
    /// the public key supplied to [`Self::verify_init`]. Returns
    /// `Ok(false)` for *any* structural failure (bad signature length,
    /// unknown algorithm tags, mismatched root hash, …) so that callers can
    /// distinguish between "well-formed but invalid" and "internal error".
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "lms: verify called without verify_init".to_string(),
            ));
        }
        debug!(
            algorithm = ALGORITHM_NAME,
            msg_len = data.len(),
            sig_len = signature.len(),
            "lms: verify"
        );
        let result = self.verify_internal(data, signature)?;
        debug!(algorithm = ALGORITHM_NAME, result, "lms: verify result");
        Ok(result)
    }

    /// Direct translation of `lms_digest_verify_init` at lines 135–149.
    ///
    /// The C source rejects any non-empty `mdname` with `PROV_R_INVALID_DIGEST`
    /// because LMS mandates the digest via the key's OTS parameters. The
    /// Rust translation surfaces the same rejection as a
    /// [`ProviderError::Dispatch`] containing the same human-readable error
    /// text ("Explicit digest not supported for LMS operations") used by the
    /// C `ERR_raise_data` call at line 142.
    fn digest_verify_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = ALGORITHM_NAME,
            digest = digest,
            key_len = key.len(),
            "lms: digest_verify_init"
        );
        if !digest.is_empty() {
            warn!(
                algorithm = ALGORITHM_NAME,
                requested = digest,
                "lms: explicit digest rejected — LMS mandates digest via key parameters"
            );
            return Err(ProviderError::Dispatch(
                "Explicit digest not supported for LMS operations".to_string(),
            ));
        }
        SignatureContext::verify_init(self, key, params)
    }

    /// Buffers caller data for later one-shot verification at
    /// [`Self::digest_verify_final`]. LMS verifies the *full message* (it
    /// is not a digest-then-verify scheme), so we accumulate the message
    /// rather than feeding it through an `EVP_MD_CTX`.
    fn digest_verify_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(
            algorithm = ALGORITHM_NAME,
            chunk_len = data.len(),
            "lms: digest_verify_update (buffering)"
        );
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "lms: digest_verify_update called without digest_verify_init".to_string(),
            ));
        }
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Direct translation of `lms_digest_verify` at lines 151–155: takes the
    /// buffered message and forwards to the same verify primitive used by
    /// [`Self::verify`].
    fn digest_verify_final(&mut self, signature: &[u8]) -> ProviderResult<bool> {
        debug!(
            algorithm = ALGORITHM_NAME,
            buffered_len = self.streaming_buffer.len(),
            signature_len = signature.len(),
            "lms: digest_verify_final"
        );
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "lms: digest_verify_final called without digest_verify_init".to_string(),
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

    /// Returns the static, key-derived parameters reportable through
    /// `OSSL_FUNC_signature_get_ctx_params` in the C dispatch table.
    ///
    /// The C source does not expose dedicated `get_ctx_params` /
    /// `set_ctx_params` entries (the dispatch table at lines 157–168 lists
    /// only the six verify entries), so the Rust implementation surfaces
    /// what the public API contract requires:
    /// * `algorithm-id`  — the algorithm name string.
    /// * `instance`      — `"LMS"`.
    /// * `security-bits` — `bit_strength` field of the loaded key's LMS
    ///                     parameters (or 0 if no key has been loaded).
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();
        out.set(
            "algorithm-id",
            ParamValue::Utf8String(ALGORITHM_NAME.to_string()),
        );
        out.set(
            "instance",
            ParamValue::Utf8String(ALGORITHM_NAME.to_string()),
        );

        // security-bits is only meaningful once a key has been loaded.
        // `bit_strength` is a `usize` from the static parameter table; it is
        // bounded by 256 in practice (LMS_SHA256_M32_H25 is the maximum
        // entry), so the i64 conversion is provably lossless and uses
        // `i64::try_from` to satisfy Rule R6 (no narrowing `as` casts).
        let security_bits: i64 = self.key.as_ref().map_or(0, |k| {
            i64::try_from(k.lms_params().bit_strength).unwrap_or(i64::MAX)
        });
        out.set("security-bits", ParamValue::Int64(security_bits));

        // digest is mandated by the key — surface it for diagnostics.
        if let Some(name) = self.digest.as_ref().map(MessageDigest::name) {
            out.set("digest", ParamValue::Utf8String(name.to_string()));
        }
        Ok(out)
    }

    /// LMS has no settable verify-side parameters in the C dispatch table —
    /// the `set_ctx_params` entry is absent from
    /// `ossl_lms_signature_functions[]`. We accept an empty [`ParamSet`]
    /// for forward compatibility but do not honour any parameter.
    ///
    /// The implementation is intentionally permissive: unknown parameters
    /// are silently ignored rather than rejected, matching the behaviour
    /// of providers that do not register a `set_ctx_params` callback —
    /// the OpenSSL core treats parameter setting as a no-op in that case.
    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// Algorithm descriptor — preserved verbatim from the prior stub.
// =============================================================================

/// Returns LMS signature algorithm descriptors for provider registration.
///
/// LMS exposes a single `OSSL_DISPATCH ossl_lms_signature_functions[]`
/// table in the C provider (verify-only).  The canonical name is `LMS`,
/// with the IETF `id-alg-hss-lms-hashsig` alias and the corresponding
/// PKIX OID `1.2.840.113549.1.9.16.3.17`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &[
            "LMS",
            "id-alg-hss-lms-hashsig",
            "1.2.840.113549.1.9.16.3.17",
        ],
        DEFAULT_PROPERTY,
        "OpenSSL LMS implementation (NIST SP 800-208 verify-only)",
    )]
}

// =============================================================================
// Tests
// =============================================================================

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
    // descriptor tests — preserved verbatim from the prior stub.
    // -------------------------------------------------------------------------

    #[test]
    fn descriptors_returns_one_entry() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
    }

    #[test]
    fn descriptors_canonical_name_is_lms() {
        let descs = descriptors();
        assert_eq!(descs[0].names[0], "LMS");
    }

    #[test]
    fn descriptors_carry_oid_and_textual_alias() {
        let descs = descriptors();
        let names = &descs[0].names;
        assert!(names.contains(&"id-alg-hss-lms-hashsig"));
        assert!(names.contains(&"1.2.840.113549.1.9.16.3.17"));
    }

    #[test]
    fn descriptors_have_default_property() {
        let descs = descriptors();
        assert_eq!(descs[0].property, DEFAULT_PROPERTY);
        assert!(!descs[0].description.is_empty());
    }

    // -------------------------------------------------------------------------
    // Provider construction tests.
    // -------------------------------------------------------------------------

    #[test]
    fn provider_name_is_lms() {
        let p = LmsSignatureProvider::new();
        assert_eq!(p.name(), "LMS");
    }

    #[test]
    fn provider_default_constructor_yields_named_provider() {
        let p = LmsSignatureProvider::default();
        assert_eq!(p.name(), "LMS");
    }

    #[test]
    fn provider_creates_fresh_context() {
        let p = LmsSignatureProvider::new();
        let ctx = p.new_ctx();
        assert!(ctx.is_ok());
    }

    #[test]
    fn provider_with_custom_libctx_creates_context() {
        let libctx = LibContext::get_default();
        let p = LmsSignatureProvider::new_with_context(libctx, Some("provider=foo".to_string()));
        let ctx = p.new_ctx();
        assert!(ctx.is_ok());
    }

    // -------------------------------------------------------------------------
    // Sign-side rejection tests — Rule R5 / contract: LMS is verify-only.
    // -------------------------------------------------------------------------

    #[test]
    fn sign_init_returns_dispatch_error() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let result = ctx.sign_init(&[], None);
        match result {
            Err(ProviderError::Dispatch(msg)) => assert!(msg.contains("LMS")),
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    #[test]
    fn sign_returns_dispatch_error() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let result = ctx.sign(&[]);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn digest_sign_init_returns_dispatch_error() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let result = ctx.digest_sign_init("SHA256", &[], None);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn digest_sign_update_returns_dispatch_error() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let result = ctx.digest_sign_update(&[1, 2, 3]);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn digest_sign_final_returns_dispatch_error() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let result = ctx.digest_sign_final();
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    // -------------------------------------------------------------------------
    // Verify-side state-machine tests.
    // -------------------------------------------------------------------------

    #[test]
    fn verify_without_init_fails() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let result = ctx.verify(b"msg", b"sig");
        assert!(matches!(result, Err(ProviderError::Init(_))));
    }

    #[test]
    fn digest_verify_update_without_init_fails() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let result = ctx.digest_verify_update(b"data");
        assert!(matches!(result, Err(ProviderError::Init(_))));
    }

    #[test]
    fn digest_verify_final_without_init_fails() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let result = ctx.digest_verify_final(b"sig");
        assert!(matches!(result, Err(ProviderError::Init(_))));
    }

    #[test]
    fn verify_init_rejects_malformed_key() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        // Too short to be a valid LMS public key (minimum is
        // 4 + 4 + 16 + 24 = 48 bytes).
        let result = ctx.verify_init(&[0u8; 4], None);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn digest_verify_init_rejects_explicit_digest() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        // A non-empty digest name must be rejected even before key
        // decoding is attempted (matches the C ordering at lines 140–144).
        let result = ctx.digest_verify_init("SHA256", &[0u8; 100], None);
        match result {
            Err(ProviderError::Dispatch(msg)) => {
                assert!(msg.contains("Explicit digest"), "unexpected message: {msg}");
            }
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    #[test]
    fn digest_verify_init_accepts_empty_digest_then_validates_key() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        // An empty mdname is permitted (matches C `mdname[0] != '\0'` check)
        // but a malformed key must still cause failure during the delegated
        // verify_init call.
        let result = ctx.digest_verify_init("", &[0u8; 4], None);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    // -------------------------------------------------------------------------
    // Parameter access tests.
    // -------------------------------------------------------------------------

    #[test]
    fn get_params_emits_algorithm_id_and_instance() {
        let p = LmsSignatureProvider::new();
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        // Algorithm name surfaced under both keys for compatibility.
        match params.get("algorithm-id") {
            Some(ParamValue::Utf8String(s)) => assert_eq!(s, "LMS"),
            other => panic!("expected algorithm-id Utf8String, got {other:?}"),
        }
        match params.get("instance") {
            Some(ParamValue::Utf8String(s)) => assert_eq!(s, "LMS"),
            other => panic!("expected instance Utf8String, got {other:?}"),
        }
    }

    #[test]
    fn get_params_security_bits_zero_without_key() {
        let p = LmsSignatureProvider::new();
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        match params.get("security-bits") {
            Some(ParamValue::Int64(v)) => assert_eq!(*v, 0),
            other => panic!("expected security-bits Int64, got {other:?}"),
        }
    }

    #[test]
    fn set_params_is_noop() {
        let p = LmsSignatureProvider::new();
        let mut ctx = p.new_ctx().unwrap();
        let mut empty = ParamSet::new();
        // Even setting a random property is silently ignored — LMS has
        // no settable verify-side state.
        empty.set("digest", ParamValue::Utf8String("SHA256".to_string()));
        let result = ctx.set_params(&empty);
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------------
    // Inherent method tests.
    // -------------------------------------------------------------------------

    #[test]
    fn fresh_context_has_no_key_or_digest() {
        let lib = LibContext::get_default();
        let ctx = LmsSignatureContext::new(lib, None);
        assert!(!ctx.has_key());
        assert!(ctx.digest_name().is_none());
    }

    #[test]
    fn set_digest_without_key_returns_error() {
        let lib = LibContext::get_default();
        let mut ctx = LmsSignatureContext::new(lib, None);
        let result = ctx.set_digest(None);
        match result {
            Err(ProviderError::Dispatch(msg)) => {
                assert!(msg.contains("LMS set_digest"), "unexpected message: {msg}");
            }
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    #[test]
    fn debug_impl_does_not_panic() {
        let p = LmsSignatureProvider::new();
        let ctx = p.new_ctx().unwrap();
        // Round-trip via Debug to exercise the manual fmt::Debug impl on
        // LmsSignatureContext (the boxed trait object hides the concrete
        // type, so call format! on the provider too).
        let _ = format!("{p:?}");
        // The trait object itself does not derive Debug, but the inherent
        // type does — verify by constructing one directly.
        let lib = LibContext::get_default();
        let direct = LmsSignatureContext::new(lib, Some("p=q".to_string()));
        let dbg = format!("{direct:?}");
        assert!(dbg.contains("LmsSignatureContext"));
        // _ctx is intentionally not printed: it's a Box<dyn> with no Debug
        // bound; the test merely ensures the manual impl above compiles
        // and runs.
        let _ = ctx;
    }
}
