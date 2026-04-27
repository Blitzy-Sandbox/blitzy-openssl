//! # MAC-as-Signature Legacy Adapter
//!
//! Rust translation of
//! `providers/implementations/signature/mac_legacy_sig.c` (253 lines).
//!
//! Exposes the Message Authentication Code (MAC) algorithms HMAC, SipHash,
//! Poly1305, and CMAC through the `SignatureProvider` / [`SignatureContext`]
//! interface so they can be invoked via the EVP `digest_sign_*` family of
//! operations.
//!
//! ## Scope of Support
//!
//! This is a **legacy** adapter: MACs are not digital signatures, but some
//! protocols (notably TLS 1.0–1.2 handshake MACs and PRF-bound constructs)
//! use MACs in a signature-shaped API.  The C dispatch tables in
//! `mac_legacy_sig.c` (lines 232–248) register **only** the composite
//! digest-sign flow along with `newctx`, `freectx`, `dupctx`,
//! `set_ctx_params`, and `settable_ctx_params`:
//!
//! ```text
//!     OSSL_FUNC_SIGNATURE_NEWCTX                  → new_ctx
//!     OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT        → digest_sign_init
//!     OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE      → digest_sign_update
//!     OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL       → digest_sign_final
//!     OSSL_FUNC_SIGNATURE_FREECTX                 → Drop (RAII)
//!     OSSL_FUNC_SIGNATURE_DUPCTX                  → duplicate()
//!     OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS          → set_ctx_params / set_params
//!     OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS     → settable_ctx_params
//! ```
//!
//! Raw `sign` / `verify` and the `digest_verify_*` family are **not**
//! registered in C and therefore MUST surface a dispatch error in the Rust
//! port.  This preserves behavioural parity with the upstream adapter.
//!
//! ## Registered Algorithms
//!
//! Mapped from `providers/defltprov.c`:
//!
//! | Provider name       | C dispatch table                                      | MAC algorithm |
//! |---------------------|-------------------------------------------------------|---------------|
//! | `PROV_NAMES_HMAC`   | `ossl_mac_legacy_hmac_signature_functions`            | `HMAC`        |
//! | `PROV_NAMES_SIPHASH`| `ossl_mac_legacy_siphash_signature_functions`         | `SIPHASH`     |
//! | `PROV_NAMES_POLY1305`| `ossl_mac_legacy_poly1305_signature_functions`       | `Poly1305`    |
//! | `PROV_NAMES_CMAC`   | `ossl_mac_legacy_cmac_signature_functions`            | `CMAC`        |
//!
//! ## Architecture
//!
//! The adapter delegates every cryptographic operation to the underlying
//! `MacCtx` from `openssl_crypto::evp::mac`.  `digest_sign_init` fetches
//! the named MAC via `Mac::fetch`, creates a `MacCtx`, forwards any
//! caller-supplied parameters (digest, cipher, properties, size) through
//! `MacCtx::set_params`, and seeds the context with the raw key via
//! `MacCtx::init`.  The subsequent `digest_sign_update` /
//! `digest_sign_final` calls are thin wrappers over `MacCtx::update` and
//! `MacCtx::finalize`.
//!
//! The adapter is always available (no feature gate) because it delegates
//! to MAC providers which are independently feature-gated upstream.
//!
//! ## Rule Compliance
//!
//! - **R5 (Nullability over sentinels)** — every absent value is `Option<T>`
//!   or a dedicated `Err` variant; no `0` / `-1` / `""` sentinel return
//!   values.
//! - **R8 (Zero unsafe outside FFI)** — no `unsafe` blocks appear in this
//!   file.  The workspace-level `#![forbid(unsafe_code)]` attribute on
//!   `openssl-provider::lib.rs` enforces this at crate scope.
//! - **R9 (Warning-free build)** — every public item carries a `///` doc
//!   comment; no `#[allow(warnings)]` escape hatches appear.
//! - **R10 (Wiring before done)** — this module is exported by
//!   `crate::implementations::signatures::mod.rs` which itself feeds
//!   `DefaultProvider::query_operation(OperationType::Signature)`, making
//!   each `MacLegacySignatureProvider` reachable from the provider entry
//!   point.

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};

use openssl_common::{CryptoError, ParamSet, ParamValue, ProviderError, ProviderResult};

use openssl_crypto::context::LibContext;
use openssl_crypto::evp::mac::{Mac, MacCtx, CMAC, HMAC, POLY1305, SIPHASH};

use crate::traits::{AlgorithmDescriptor, SignatureContext, SignatureProvider};

use super::algorithm;

// =============================================================================
// CryptoError → ProviderError mapping helpers
// =============================================================================

/// Converts a [`CryptoError`] raised by the crypto layer into a
/// `ProviderError::Dispatch` suitable for the signature-provider API
/// surface.
///
/// Mirrors the canonical pattern used elsewhere in this crate (see
/// `kem/ecx.rs::dispatch_err`).  The pass-by-value signature is deliberate
/// so the helper can be used directly as a `map_err` argument:
///
/// ```text
///     mac_ctx.update(data).map_err(dispatch_err)?;
/// ```
///
/// The conversion preserves the underlying error message via `Display`,
/// ensuring crypto-layer diagnostics surface through the provider boundary.
#[inline]
#[allow(clippy::needless_pass_by_value)] // ergonomic `map_err` consumer
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Returns a pre-canned "operation not supported" dispatch error used by
/// every non-`digest_sign` entry point.
///
/// The C dispatch tables in `mac_legacy_sig.c` register only the composite
/// digest-sign flow; attempting raw `sign` / `verify` or the digest-verify
/// family on the adapter is a programmer error that must surface as a
/// dispatch failure — Rule R5 requires an explicit `Err` over a sentinel.
#[inline]
fn unsupported(op: &'static str) -> ProviderError {
    warn!(
        operation = op,
        "mac_legacy: unsupported signature operation requested"
    );
    ProviderError::Dispatch(format!(
        "{op}: operation not supported by the MAC-as-signature adapter"
    ))
}

// =============================================================================
// MacSignatureAlgorithm
// =============================================================================

/// Identifies the underlying MAC algorithm used by the legacy signature
/// adapter.
///
/// Each variant corresponds to one `ossl_mac_legacy_*_signature_functions`
/// dispatch table in `providers/defltprov.c` and one `MAC_NEWCTX` macro
/// expansion in `mac_legacy_sig.c` (lines 85–88).
///
/// Variant names follow standard Rust casing conventions (`Siphash`, not
/// `SipHash`) so downstream generic code can match by simple `PartialEq`
/// comparison without relying on display formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacSignatureAlgorithm {
    /// HMAC — Hash-based Message Authentication Code (RFC 2104).
    Hmac,
    /// `SipHash` — short-input optimised pseudo-random function.
    Siphash,
    /// Poly1305 — one-time authenticator (RFC 8439).
    Poly1305,
    /// CMAC — Cipher-based Message Authentication Code (NIST SP 800-38B).
    Cmac,
}

impl MacSignatureAlgorithm {
    /// Returns the canonical MAC algorithm name suitable for
    /// `Mac::fetch`.
    ///
    /// The returned values match the constants exported from
    /// `openssl_crypto::evp::mac`.  Notably the Rust port uses the
    /// camel-cased spelling `"Poly1305"` rather than the C spelling
    /// `"POLY1305"`, so callers must forward whatever this method returns
    /// unchanged to the EVP MAC layer.
    #[must_use]
    pub fn mac_name(self) -> &'static str {
        match self {
            Self::Hmac => HMAC,
            Self::Siphash => SIPHASH,
            Self::Poly1305 => POLY1305,
            Self::Cmac => CMAC,
        }
    }

    /// Returns the canonical signature-algorithm name registered with the
    /// provider.
    ///
    /// These names come directly from `PROV_NAMES_HMAC`,
    /// `PROV_NAMES_SIPHASH`, `PROV_NAMES_POLY1305`, and `PROV_NAMES_CMAC`
    /// in `providers/implementations/include/prov/names.h`.  They are
    /// spelled in upper case regardless of the underlying MAC layer's
    /// preferred casing.
    #[must_use]
    pub fn signature_name(self) -> &'static str {
        match self {
            Self::Hmac => "HMAC",
            Self::Siphash => "SIPHASH",
            Self::Poly1305 => "POLY1305",
            Self::Cmac => "CMAC",
        }
    }
}

// =============================================================================
// MacLegacySignatureProvider
// =============================================================================

/// MAC-as-signature provider that wraps a MAC implementation in the
/// `SignatureProvider` interface.
///
/// Each instance is bound to a specific [`MacSignatureAlgorithm`] variant.
/// Creating a context via
/// [`new_ctx`](SignatureProvider::new_ctx) returns a
/// [`MacSignatureContext`] pre-configured for the selected MAC algorithm
/// and attached to the library context supplied at construction time.
///
/// ## Construction
///
/// - [`Self::new`] — binds to the default library context with no property
///   query, matching the dominant usage pattern.
/// - [`Self::new_with_context`] — binds to an explicit library context and
///   optional property query, matching the `provctx` / `propq` arguments
///   passed into `mac_hmac_newctx`, `mac_siphash_newctx`, etc. in the C
///   source (`mac_legacy_sig.c` lines 79–83).
#[derive(Debug, Clone)]
pub struct MacLegacySignatureProvider {
    /// The underlying MAC algorithm this provider adapts.
    algorithm: MacSignatureAlgorithm,
    /// Library context passed to `Mac::fetch` when creating contexts.
    libctx: Arc<LibContext>,
    /// Optional property query forwarded to `Mac::fetch` (e.g.
    /// `"fips=yes"`).  Rule R5: `Option` rather than an empty-string
    /// sentinel.
    propq: Option<String>,
}

impl MacLegacySignatureProvider {
    /// Creates a new MAC-as-signature provider for the given algorithm,
    /// attached to the default library context with no property query.
    ///
    /// This is the convenient constructor for the dominant case where the
    /// caller does not need to supply a custom library context.
    #[must_use]
    pub fn new(algorithm: MacSignatureAlgorithm) -> Self {
        Self {
            algorithm,
            libctx: LibContext::get_default(),
            propq: None,
        }
    }

    /// Creates a new MAC-as-signature provider attached to a specific
    /// library context, optionally with a property query.
    ///
    /// Mirrors the C `provctx` + `propq` arguments passed into
    /// `mac_hmac_newctx` / `mac_siphash_newctx` / `mac_poly1305_newctx` /
    /// `mac_cmac_newctx` (`mac_legacy_sig.c` lines 79–88).
    #[must_use]
    pub fn new_with_context(
        algorithm: MacSignatureAlgorithm,
        libctx: Arc<LibContext>,
        propq: Option<String>,
    ) -> Self {
        Self {
            algorithm,
            libctx,
            propq,
        }
    }

    /// Returns the MAC algorithm this provider adapts.
    #[must_use]
    pub fn algorithm(&self) -> MacSignatureAlgorithm {
        self.algorithm
    }
}

impl SignatureProvider for MacLegacySignatureProvider {
    fn name(&self) -> &'static str {
        self.algorithm.signature_name()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>> {
        debug!(
            algorithm = self.algorithm.signature_name(),
            has_propq = self.propq.is_some(),
            "mac_legacy: creating new signature context"
        );
        Ok(Box::new(MacSignatureContext::new(
            self.algorithm,
            Arc::clone(&self.libctx),
            self.propq.clone(),
        )))
    }
}

// =============================================================================
// MacSignatureContext
// =============================================================================

/// Per-operation context for the MAC-as-signature adapter.
///
/// Holds the selected MAC algorithm, the library context used for provider
/// fetch, an optional property query, and — after `digest_sign_init` has
/// succeeded — the live `MacCtx` performing the actual MAC computation.
///
/// Replaces the C `PROV_MAC_CTX` struct from `mac_legacy_sig.c` (lines
/// 37–42):
///
/// ```text
/// typedef struct {
///     OSSL_LIB_CTX  *libctx;  // → Arc<LibContext>
///     char          *propq;   // → Option<String>
///     MAC_KEY       *key;     // → key bytes live inside mac_ctx.key
///     EVP_MAC_CTX   *macctx;  // → Option<MacCtx>
/// } PROV_MAC_CTX;
/// ```
///
/// The separate `MAC_KEY` reference from the C struct is not mirrored: the
/// `SignatureContext` trait passes the raw key bytes directly into
/// `digest_sign_init`, and `MacCtx::init` stores them internally with
/// zeroising drop — obviating the need for a free-standing, ref-counted
/// key object.
///
/// Note: this struct cannot derive [`std::fmt::Debug`] automatically
/// because `MacCtx` intentionally omits a `Debug` implementation to
/// avoid accidentally leaking key material through log output.  A manual
/// [`Debug`] impl below reports only whether a MAC context has been
/// initialised.
pub struct MacSignatureContext {
    /// The underlying MAC algorithm (constant for the lifetime of the
    /// context).
    algorithm: MacSignatureAlgorithm,
    /// Library context used when fetching the MAC algorithm.
    libctx: Arc<LibContext>,
    /// Optional property query forwarded to `Mac::fetch`.
    propq: Option<String>,
    /// Active MAC computation context — `None` until `digest_sign_init`
    /// runs successfully.  Rule R5: `Option` rather than a "zero ctx"
    /// sentinel.
    mac_ctx: Option<MacCtx>,
}

impl MacSignatureContext {
    /// Creates a new, uninitialised MAC signature context.
    ///
    /// Constructed exclusively by [`MacLegacySignatureProvider::new_ctx`];
    /// not part of the public API because callers should always route
    /// through the provider for correct library-context wiring.
    fn new(
        algorithm: MacSignatureAlgorithm,
        libctx: Arc<LibContext>,
        propq: Option<String>,
    ) -> Self {
        Self {
            algorithm,
            libctx,
            propq,
            mac_ctx: None,
        }
    }

    /// Returns the list of parameter names that may be supplied to
    /// [`Self::set_ctx_params`] for the current algorithm.
    ///
    /// C source: `mac_settable_ctx_params` (lines 203–218) fetches a
    /// fresh `EVP_MAC` by name and forwards the call to
    /// `EVP_MAC_settable_ctx_params`.  In the Rust port we surface the
    /// same per-algorithm envelope via a static list — the crypto-layer
    /// `MacCtx::set_params` accepts `"size"` for all MACs and
    /// additional per-algorithm entries as listed below.  The lists
    /// mirror the parameter surface expected by the upstream test suite
    /// (`test/evp_extra_test.c` MAC signature cases).
    #[must_use]
    pub fn settable_ctx_params(&self) -> Vec<&'static str> {
        match self.algorithm {
            MacSignatureAlgorithm::Hmac => vec!["digest", "properties", "size"],
            MacSignatureAlgorithm::Cmac => vec!["cipher", "properties", "size"],
            MacSignatureAlgorithm::Siphash => vec!["size"],
            MacSignatureAlgorithm::Poly1305 => vec![],
        }
    }

    /// Forwards caller-supplied parameters to the active `MacCtx`.
    ///
    /// Translates `mac_set_ctx_params` (`mac_legacy_sig.c` lines
    /// 196–201):
    ///
    /// ```c
    /// static int mac_set_ctx_params(void *vpmacctx, const OSSL_PARAM params[])
    /// {
    ///     PROV_MAC_CTX *ctx = (PROV_MAC_CTX *)vpmacctx;
    ///     return EVP_MAC_CTX_set_params(ctx->macctx, params);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Init`] if no MAC context has been initialised
    ///   yet (the C code also requires `ctx->macctx != NULL`, returning
    ///   `0` otherwise).
    /// - `ProviderError::Dispatch` wrapping any [`CryptoError`] raised
    ///   by the underlying `MacCtx::set_params`.
    pub fn set_ctx_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        trace!(
            algorithm = self.algorithm.signature_name(),
            param_count = params.len(),
            "mac_legacy: forwarding caller parameters to MAC context"
        );

        let mac_ctx = self.mac_ctx.as_mut().ok_or_else(|| {
            ProviderError::Init(
                "MAC context not initialised (call digest_sign_init first)".to_string(),
            )
        })?;
        mac_ctx.set_params(params).map_err(dispatch_err)
    }

    /// Returns a deep clone of this signature context, including the
    /// embedded `MacCtx` state.
    ///
    /// Translates `mac_dupctx` (`mac_legacy_sig.c` lines 160–194):
    ///
    /// ```c
    ///     dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    ///     dstctx->propq = OPENSSL_strdup(srcctx->propq);
    ///     ossl_mac_key_up_ref(srcctx->key);
    ///     dstctx->key = srcctx->key;
    ///     dstctx->macctx = EVP_MAC_CTX_dup(srcctx->macctx);
    /// ```
    ///
    /// In Rust the [`Arc<LibContext>`] is clone-refcounted, the
    /// [`Option<String>`] is `Clone`, and the live `MacCtx` is
    /// duplicated via its own `dup()` which deep-copies key material
    /// and accumulated buffered data.
    ///
    /// # Errors
    ///
    /// `ProviderError::Dispatch` wrapping any [`CryptoError`] raised
    /// by `MacCtx::dup`.
    pub fn duplicate(&self) -> ProviderResult<Self> {
        trace!(
            algorithm = self.algorithm.signature_name(),
            has_mac_ctx = self.mac_ctx.is_some(),
            "mac_legacy: duplicating signature context"
        );

        let mac_ctx = match self.mac_ctx.as_ref() {
            Some(ctx) => Some(ctx.dup().map_err(dispatch_err)?),
            None => None,
        };

        Ok(Self {
            algorithm: self.algorithm,
            libctx: Arc::clone(&self.libctx),
            propq: self.propq.clone(),
            mac_ctx,
        })
    }

    /// Fetches the MAC algorithm, constructs a fresh `MacCtx`, merges
    /// parameters, and seeds the context with the supplied key.
    ///
    /// This is the Rust port of the combination of `ossl_prov_set_macctx`
    /// (from `provider_util.c` lines 124–169) and the `EVP_MAC_init` call
    /// at the end of `mac_digest_sign_init` (`mac_legacy_sig.c` lines
    /// 90–126).
    ///
    /// The C implementation builds up to three fixed params
    /// (digest / cipher / properties) from its explicit arguments and
    /// merges them with the caller-supplied `OSSL_PARAM[]`, then forwards
    /// the union to `EVP_MAC_CTX_set_params` before `EVP_MAC_init`.  This
    /// function reproduces that exact ordering so caller-supplied values
    /// win over adapter-provided defaults — matching the behaviour of
    /// `OSSL_PARAM_merge(mac_params, param)` which places the second
    /// argument's entries last.
    fn init_with_params(
        &mut self,
        digest: Option<&str>,
        key: &[u8],
        caller_params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // Fetch the MAC algorithm.  Rust equivalent of `EVP_MAC_fetch`
        // invoked from each `MAC_NEWCTX` macro expansion.  The fetch is
        // repeated per init so the adapter remains stateless between
        // digest_sign_init calls, matching the C design where a newctx
        // followed by digest_sign_init produces a fresh EVP_MAC_CTX.
        let mac = Mac::fetch(
            &self.libctx,
            self.algorithm.mac_name(),
            self.propq.as_deref(),
        )
        .map_err(dispatch_err)?;

        // Build the merged parameter set the way `ossl_prov_set_macctx`
        // does.  Three adapter-supplied keys are candidates: `digest`
        // (meaningful for HMAC), `cipher` (meaningful for CMAC), and
        // `properties` (the provider-level property query).  Caller
        // params are layered on last so they override adapter defaults.
        let mut merged = ParamSet::new();

        // `digest` — HMAC digest name, supplied either via the explicit
        // `digest` argument of `digest_sign_init` or via a caller param.
        // The explicit argument wins only if the caller did not set one.
        if let Some(dname) = digest {
            if !dname.is_empty() {
                merged.set("digest", ParamValue::Utf8String(dname.to_string()));
            }
        }

        // `properties` — propagate the provider-level property query so
        // nested algorithm fetches (e.g. HMAC's inner hash) inherit the
        // same property filter.  Caller override, if any, is applied in
        // the `merge()` call below.
        if let Some(props) = self.propq.as_deref() {
            if !props.is_empty() {
                merged.set("properties", ParamValue::Utf8String(props.to_string()));
            }
        }

        // Layer caller params on top — caller explicitly provided values
        // (digest / cipher / properties / size / …) override the adapter
        // defaults above.  Matches `OSSL_PARAM_merge(mac_params, param)`
        // semantics in C (second arg wins on key collision).
        if let Some(caller) = caller_params {
            merged.merge(caller);
        }

        // Construct the MAC context and forward the merged params, then
        // initialise with key material.  We forward params *before*
        // init() so algorithm-specific context setup (e.g. HMAC digest
        // selection) completes before the HMAC ipad/opad pre-computation
        // inside `init()`.
        let mut ctx = MacCtx::new(&mac).map_err(dispatch_err)?;
        if !merged.is_empty() {
            ctx.set_params(&merged).map_err(dispatch_err)?;
        }

        // Rule R5: init takes `Option<&ParamSet>`, not a zero-length
        // sentinel.  We pass the merged set so `apply_init_params` can
        // interpret algorithm-specific keys (e.g. `size`).
        let init_params = if merged.is_empty() {
            None
        } else {
            Some(&merged)
        };
        ctx.init(key, init_params).map_err(dispatch_err)?;

        debug!(
            algorithm = self.algorithm.signature_name(),
            mac_name = self.algorithm.mac_name(),
            key_len = key.len(),
            param_count = merged.len(),
            "mac_legacy: MAC context initialised for digest_sign"
        );

        self.mac_ctx = Some(ctx);
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Debug — manual implementation because `MacCtx` does not derive `Debug`.
// -----------------------------------------------------------------------------
//
// The crypto-layer `MacCtx` omits `Debug` to avoid leaking key material
// through log output.  Our wrapper reports only whether a context is
// present (a benign boolean), never its internal state.
impl fmt::Debug for MacSignatureContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The `libctx` field is an internal dependency handle and is
        // intentionally omitted from the Debug representation (it holds
        // no interesting per-context state and would be noisy).  The
        // `mac_ctx` field is redacted because `MacCtx` holds key
        // material.  `finish_non_exhaustive()` makes both omissions
        // explicit in the formatted output.
        f.debug_struct("MacSignatureContext")
            .field("algorithm", &self.algorithm)
            .field("propq", &self.propq)
            .field("initialized", &self.mac_ctx.is_some())
            .finish_non_exhaustive()
    }
}

// =============================================================================
// SignatureContext implementation
// =============================================================================

impl SignatureContext for MacSignatureContext {
    // -------------------------------------------------------------------------
    // Unsupported operations — the C dispatch tables in `mac_legacy_sig.c`
    // (lines 232–248) register ONLY the composite digest-sign flow.  Every
    // other entry point MUST surface a dispatch error per Rule R5 so a
    // misuse is explicit rather than returning bogus data.
    // -------------------------------------------------------------------------

    fn sign_init(&mut self, _key: &[u8], _params: Option<&ParamSet>) -> ProviderResult<()> {
        Err(unsupported("sign_init"))
    }

    fn sign(&mut self, _data: &[u8]) -> ProviderResult<Vec<u8>> {
        Err(unsupported("sign"))
    }

    fn verify_init(&mut self, _key: &[u8], _params: Option<&ParamSet>) -> ProviderResult<()> {
        Err(unsupported("verify_init"))
    }

    fn verify(&mut self, _data: &[u8], _signature: &[u8]) -> ProviderResult<bool> {
        Err(unsupported("verify"))
    }

    // -------------------------------------------------------------------------
    // Supported operations — the composite digest-sign flow.
    // -------------------------------------------------------------------------

    fn digest_sign_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = self.algorithm.signature_name(),
            digest = digest,
            key_len = key.len(),
            has_params = params.is_some(),
            "mac_legacy: digest_sign_init"
        );

        // Delegate to the shared init helper.  The helper handles
        // merging of the adapter-supplied digest / cipher / properties
        // keys with caller-supplied params per `ossl_prov_set_macctx`
        // semantics, then seeds the MAC context with the supplied key.
        let digest_arg = if digest.is_empty() {
            None
        } else {
            Some(digest)
        };
        self.init_with_params(digest_arg, key, params)
    }

    fn digest_sign_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(
            algorithm = self.algorithm.signature_name(),
            data_len = data.len(),
            "mac_legacy: digest_sign_update"
        );

        let mac_ctx = self.mac_ctx.as_mut().ok_or_else(|| {
            ProviderError::Init(
                "digest_sign_init must be called before digest_sign_update".to_string(),
            )
        })?;
        mac_ctx.update(data).map_err(dispatch_err)
    }

    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>> {
        let mac_ctx = self.mac_ctx.as_mut().ok_or_else(|| {
            ProviderError::Init(
                "digest_sign_init must be called before digest_sign_final".to_string(),
            )
        })?;
        let tag = mac_ctx.finalize().map_err(dispatch_err)?;
        debug!(
            algorithm = self.algorithm.signature_name(),
            tag_len = tag.len(),
            "mac_legacy: digest_sign_final"
        );
        Ok(tag)
    }

    // -------------------------------------------------------------------------
    // digest_verify_* — not registered in the C dispatch table.
    //
    // MACs are symmetric primitives; "verification" would mean recomputing
    // the tag and comparing in constant time, but the C adapter does not
    // expose this path.  We keep parity by returning dispatch errors here.
    // -------------------------------------------------------------------------

    fn digest_verify_init(
        &mut self,
        _digest: &str,
        _key: &[u8],
        _params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        Err(unsupported("digest_verify_init"))
    }

    fn digest_verify_update(&mut self, _data: &[u8]) -> ProviderResult<()> {
        Err(unsupported("digest_verify_update"))
    }

    fn digest_verify_final(&mut self, _signature: &[u8]) -> ProviderResult<bool> {
        Err(unsupported("digest_verify_final"))
    }

    // -------------------------------------------------------------------------
    // Parameter queries — forwarded to the embedded MAC context when
    // available.  Before digest_sign_init the only observable param is the
    // algorithm name, which mirrors the behaviour of C providers that
    // return an empty OSSL_PARAM array before context initialisation.
    // -------------------------------------------------------------------------

    fn get_params(&self) -> ProviderResult<ParamSet> {
        if let Some(ctx) = self.mac_ctx.as_ref() {
            return ctx.get_params().map_err(dispatch_err);
        }
        // No active MAC context — return a single "algorithm" param so
        // callers can still introspect which adapter they're holding.
        let mut params = ParamSet::new();
        params.set(
            "algorithm",
            ParamValue::Utf8String(self.algorithm.signature_name().to_string()),
        );
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Before digest_sign_init we silently accept incoming params;
        // some callers stage parameters ahead of init.  The real merge
        // happens in `init_with_params`.  After init we forward to the
        // live context, matching the C `mac_set_ctx_params` dispatch in
        // `mac_legacy_sig.c` lines 196–201.
        if let Some(ctx) = self.mac_ctx.as_mut() {
            return ctx.set_params(params).map_err(dispatch_err);
        }
        trace!(
            algorithm = self.algorithm.signature_name(),
            param_count = params.len(),
            "mac_legacy: set_params staged (no active MAC context yet)"
        );
        Ok(())
    }
}

// =============================================================================
// Per-MAC algorithm descriptors
// =============================================================================
//
// Each of the four descriptor functions below corresponds to one of the
// `MAC_SIGNATURE_FUNCTIONS(...)` macro expansions at the tail of
// `mac_legacy_sig.c` (lines 250–253) and one `PROV_NAMES_*` entry in
// `providers/implementations/include/prov/names.h`.

/// Returns the algorithm descriptor used to register HMAC as a signature
/// provider.
///
/// Source: `MAC_SIGNATURE_FUNCTIONS(hmac)` expansion at
/// `mac_legacy_sig.c` line 250.
#[must_use]
pub fn hmac_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["HMAC"],
        "provider=default",
        "HMAC used as a signature (MAC-as-signature legacy adapter, RFC 2104)",
    )
}

/// Returns the algorithm descriptor used to register `SipHash` as a
/// signature provider.
///
/// Source: `MAC_SIGNATURE_FUNCTIONS(siphash)` expansion at
/// `mac_legacy_sig.c` line 251.
#[must_use]
pub fn siphash_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["SIPHASH"],
        "provider=default",
        "SipHash used as a signature (MAC-as-signature legacy adapter)",
    )
}

/// Returns the algorithm descriptor used to register Poly1305 as a
/// signature provider.
///
/// Source: `MAC_SIGNATURE_FUNCTIONS(poly1305)` expansion at
/// `mac_legacy_sig.c` line 252.
#[must_use]
pub fn poly1305_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["POLY1305"],
        "provider=default",
        "Poly1305 used as a signature (MAC-as-signature legacy adapter, RFC 8439)",
    )
}

/// Returns the algorithm descriptor used to register CMAC as a signature
/// provider.
///
/// Source: `MAC_SIGNATURE_FUNCTIONS(cmac)` expansion at
/// `mac_legacy_sig.c` line 253.
#[must_use]
pub fn cmac_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["CMAC"],
        "provider=default",
        "CMAC used as a signature (MAC-as-signature legacy adapter, NIST SP 800-38B)",
    )
}

/// Aggregates every MAC-as-signature descriptor registered by this
/// module.
///
/// Invoked unconditionally by the parent
/// [`super::descriptors`](crate::implementations::signatures::descriptors)
/// aggregator — the adapter is always present in the default provider
/// because the underlying MAC implementations are independently
/// feature-gated upstream.
///
/// Order of returned descriptors matches the order of
/// `MAC_SIGNATURE_FUNCTIONS(...)` invocations at the tail of
/// `mac_legacy_sig.c` (lines 250–253), which is the order in which
/// `defltprov.c` walks them.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        hmac_signature_descriptor(),
        siphash_signature_descriptor(),
        poly1305_signature_descriptor(),
        cmac_signature_descriptor(),
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::redundant_closure_for_method_calls
)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Algorithm enum round-trip tests
    // -------------------------------------------------------------------------

    #[test]
    fn algorithm_mac_name_matches_evp_constants() {
        // The `mac_name()` return values must match the constants from
        // `openssl_crypto::evp::mac` so they can be forwarded to
        // `Mac::fetch` without transformation.
        assert_eq!(MacSignatureAlgorithm::Hmac.mac_name(), HMAC);
        assert_eq!(MacSignatureAlgorithm::Siphash.mac_name(), SIPHASH);
        assert_eq!(MacSignatureAlgorithm::Poly1305.mac_name(), POLY1305);
        assert_eq!(MacSignatureAlgorithm::Cmac.mac_name(), CMAC);
    }

    #[test]
    fn algorithm_signature_name_is_upper_case() {
        // Provider registration names are upper case regardless of the
        // underlying MAC layer's casing.  See `PROV_NAMES_*` in
        // `providers/implementations/include/prov/names.h`.
        assert_eq!(MacSignatureAlgorithm::Hmac.signature_name(), "HMAC");
        assert_eq!(MacSignatureAlgorithm::Siphash.signature_name(), "SIPHASH");
        assert_eq!(MacSignatureAlgorithm::Poly1305.signature_name(), "POLY1305");
        assert_eq!(MacSignatureAlgorithm::Cmac.signature_name(), "CMAC");
    }

    // -------------------------------------------------------------------------
    // Descriptor registration tests
    // -------------------------------------------------------------------------

    #[test]
    fn descriptors_returns_all_four_macs() {
        let descs = descriptors();
        assert_eq!(
            descs.len(),
            4,
            "expected descriptors for HMAC/SIPHASH/POLY1305/CMAC"
        );

        let names: Vec<&&str> = descs.iter().flat_map(|d| d.names.iter()).collect();
        assert!(names.iter().any(|n| **n == "HMAC"));
        assert!(names.iter().any(|n| **n == "SIPHASH"));
        assert!(names.iter().any(|n| **n == "POLY1305"));
        assert!(names.iter().any(|n| **n == "CMAC"));
    }

    #[test]
    fn individual_descriptor_functions_return_single_algorithm() {
        assert_eq!(hmac_signature_descriptor().names, vec!["HMAC"]);
        assert_eq!(siphash_signature_descriptor().names, vec!["SIPHASH"]);
        assert_eq!(poly1305_signature_descriptor().names, vec!["POLY1305"]);
        assert_eq!(cmac_signature_descriptor().names, vec!["CMAC"]);

        // All MAC descriptors register under the default provider.
        assert_eq!(hmac_signature_descriptor().property, "provider=default");
        assert_eq!(siphash_signature_descriptor().property, "provider=default");
        assert_eq!(poly1305_signature_descriptor().property, "provider=default");
        assert_eq!(cmac_signature_descriptor().property, "provider=default");
    }

    // -------------------------------------------------------------------------
    // Provider construction tests
    // -------------------------------------------------------------------------

    #[test]
    fn provider_name_matches_algorithm() {
        let hmac = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Hmac);
        let siphash = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Siphash);
        let poly1305 = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Poly1305);
        let cmac = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Cmac);

        assert_eq!(hmac.name(), "HMAC");
        assert_eq!(siphash.name(), "SIPHASH");
        assert_eq!(poly1305.name(), "POLY1305");
        assert_eq!(cmac.name(), "CMAC");
    }

    #[test]
    fn provider_with_context_preserves_fields() {
        let ctx = LibContext::get_default();
        let provider = MacLegacySignatureProvider::new_with_context(
            MacSignatureAlgorithm::Hmac,
            Arc::clone(&ctx),
            Some("fips=yes".to_string()),
        );
        assert_eq!(provider.algorithm(), MacSignatureAlgorithm::Hmac);
        // new_ctx should succeed and produce a boxed trait object.
        let _sig_ctx = provider
            .new_ctx()
            .expect("new_ctx should succeed for HMAC with default library context");
    }

    // -------------------------------------------------------------------------
    // settable_ctx_params matrix
    // -------------------------------------------------------------------------

    #[test]
    fn settable_params_vary_by_algorithm() {
        let ctx = LibContext::get_default();

        for (alg, expected) in &[
            (
                MacSignatureAlgorithm::Hmac,
                &["digest", "properties", "size"][..],
            ),
            (
                MacSignatureAlgorithm::Cmac,
                &["cipher", "properties", "size"][..],
            ),
            (MacSignatureAlgorithm::Siphash, &["size"][..]),
            (MacSignatureAlgorithm::Poly1305, &[][..]),
        ] {
            let sig_ctx = MacSignatureContext::new(*alg, Arc::clone(&ctx), None);
            let names = sig_ctx.settable_ctx_params();
            assert_eq!(
                names.len(),
                expected.len(),
                "settable_ctx_params count mismatch for {alg:?}"
            );
            for exp in *expected {
                assert!(
                    names.contains(exp),
                    "expected {exp} in settable params for {alg:?}"
                );
            }
            // Make sure no active MAC context yet.
            assert!(!format!("{sig_ctx:?}").contains("initialized: true"));
        }
    }

    // -------------------------------------------------------------------------
    // Unsupported operations — each must surface ProviderError::Dispatch
    // -------------------------------------------------------------------------

    #[test]
    fn raw_sign_returns_dispatch_error() {
        let provider = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Hmac);
        let mut ctx = provider.new_ctx().expect("new_ctx for HMAC");

        let err = ctx
            .sign_init(b"secret-key", None)
            .expect_err("sign_init must be unsupported");
        assert!(
            matches!(err, ProviderError::Dispatch(_)),
            "expected Dispatch variant, got {err:?}"
        );

        let err = ctx.sign(b"data").expect_err("sign must be unsupported");
        assert!(
            matches!(err, ProviderError::Dispatch(_)),
            "expected Dispatch variant, got {err:?}"
        );
    }

    #[test]
    fn raw_verify_returns_dispatch_error() {
        let provider = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Cmac);
        let mut ctx = provider.new_ctx().expect("new_ctx for CMAC");

        let err = ctx
            .verify_init(b"secret-key", None)
            .expect_err("verify_init must be unsupported");
        assert!(matches!(err, ProviderError::Dispatch(_)));

        let err = ctx
            .verify(b"data", b"bogus-tag")
            .expect_err("verify must be unsupported");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn digest_verify_returns_dispatch_error() {
        let provider = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Poly1305);
        let mut ctx = provider.new_ctx().expect("new_ctx for Poly1305");

        let err = ctx
            .digest_verify_init("SHA256", b"key-material", None)
            .expect_err("digest_verify_init must be unsupported");
        assert!(matches!(err, ProviderError::Dispatch(_)));

        let err = ctx
            .digest_verify_update(b"data")
            .expect_err("digest_verify_update must be unsupported");
        assert!(matches!(err, ProviderError::Dispatch(_)));

        let err = ctx
            .digest_verify_final(b"tag")
            .expect_err("digest_verify_final must be unsupported");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // -------------------------------------------------------------------------
    // Digest-sign happy path (exercises real MacCtx)
    // -------------------------------------------------------------------------

    #[test]
    fn digest_sign_full_cycle_hmac() {
        let provider = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Hmac);
        let mut ctx = provider.new_ctx().expect("new_ctx for HMAC");

        // Initialise with a digest name and key bytes.
        ctx.digest_sign_init("SHA256", b"hmac-key-material", None)
            .expect("digest_sign_init must succeed for HMAC");

        // Feed some data.
        ctx.digest_sign_update(b"authenticated message")
            .expect("digest_sign_update must succeed after init");

        // Produce a tag.
        let tag = ctx
            .digest_sign_final()
            .expect("digest_sign_final must succeed after update");
        assert!(!tag.is_empty(), "MAC tag must be non-empty");
    }

    #[test]
    fn digest_sign_full_cycle_poly1305() {
        let provider = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Poly1305);
        let mut ctx = provider.new_ctx().expect("new_ctx for Poly1305");

        // Poly1305 requires exactly 32 bytes of key material per RFC 8439.
        let key = vec![0x42u8; 32];
        ctx.digest_sign_init("", &key, None)
            .expect("digest_sign_init must succeed for Poly1305");
        ctx.digest_sign_update(b"chunk one")
            .expect("digest_sign_update 1 must succeed");
        ctx.digest_sign_update(b"chunk two")
            .expect("digest_sign_update 2 must succeed");
        let tag = ctx
            .digest_sign_final()
            .expect("digest_sign_final must succeed");
        assert!(!tag.is_empty());
    }

    #[test]
    fn digest_sign_update_without_init_fails() {
        let provider = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Hmac);
        let mut ctx = provider.new_ctx().expect("new_ctx for HMAC");

        let err = ctx
            .digest_sign_update(b"nope")
            .expect_err("digest_sign_update before init must fail");
        assert!(
            matches!(err, ProviderError::Init(_)),
            "expected Init variant, got {err:?}"
        );
    }

    #[test]
    fn digest_sign_final_without_init_fails() {
        let provider = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Hmac);
        let mut ctx = provider.new_ctx().expect("new_ctx for HMAC");

        let err = ctx
            .digest_sign_final()
            .expect_err("digest_sign_final before init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_sign_empty_key_fails() {
        let provider = MacLegacySignatureProvider::new(MacSignatureAlgorithm::Hmac);
        let mut ctx = provider.new_ctx().expect("new_ctx for HMAC");

        let err = ctx
            .digest_sign_init("SHA256", &[], None)
            .expect_err("empty key must be rejected by MacCtx::init");
        assert!(
            matches!(err, ProviderError::Dispatch(_)),
            "expected Dispatch variant wrapping CryptoError::Key, got {err:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Duplicate() preserves state
    // -------------------------------------------------------------------------

    #[test]
    fn duplicate_before_init_produces_fresh_context() {
        let sig_ctx = MacSignatureContext::new(
            MacSignatureAlgorithm::Hmac,
            LibContext::get_default(),
            Some("fips=yes".to_string()),
        );
        let dup = sig_ctx
            .duplicate()
            .expect("duplicate before init must succeed");
        assert_eq!(dup.algorithm, sig_ctx.algorithm);
        assert_eq!(dup.propq, sig_ctx.propq);
        assert!(dup.mac_ctx.is_none());
    }

    #[test]
    fn duplicate_after_init_deep_copies_mac_ctx() {
        let mut sig_ctx =
            MacSignatureContext::new(MacSignatureAlgorithm::Hmac, LibContext::get_default(), None);
        sig_ctx
            .init_with_params(Some("SHA256"), b"hmac-key", None)
            .expect("init must succeed");
        assert!(sig_ctx.mac_ctx.is_some());

        let dup = sig_ctx
            .duplicate()
            .expect("duplicate after init must succeed");
        assert!(dup.mac_ctx.is_some());
        assert_eq!(dup.algorithm, sig_ctx.algorithm);

        // Dropping `dup` must not interfere with the original.
        drop(dup);
        // Original should still finalise successfully.
        let tag = sig_ctx
            .digest_sign_final()
            .expect("original digest_sign_final must still succeed");
        assert!(!tag.is_empty());
    }

    // -------------------------------------------------------------------------
    // set_ctx_params / get_params
    // -------------------------------------------------------------------------

    #[test]
    fn set_ctx_params_before_init_returns_init_error() {
        let mut sig_ctx =
            MacSignatureContext::new(MacSignatureAlgorithm::Hmac, LibContext::get_default(), None);
        let params = ParamSet::new();
        let err = sig_ctx
            .set_ctx_params(&params)
            .expect_err("set_ctx_params before init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn set_params_before_init_is_no_op() {
        let mut sig_ctx =
            MacSignatureContext::new(MacSignatureAlgorithm::Hmac, LibContext::get_default(), None);
        let params = ParamSet::new();
        // The trait method tolerates pre-init calls (staging) and must
        // not surface an error.
        sig_ctx
            .set_params(&params)
            .expect("staged set_params before init must be accepted");
    }

    #[test]
    fn get_params_before_init_returns_algorithm_only() {
        let sig_ctx = MacSignatureContext::new(
            MacSignatureAlgorithm::Siphash,
            LibContext::get_default(),
            None,
        );
        let params = sig_ctx
            .get_params()
            .expect("get_params before init must succeed");
        let alg = params
            .get("algorithm")
            .expect("algorithm key must be present");
        match alg {
            ParamValue::Utf8String(name) => assert_eq!(name, "SIPHASH"),
            other => panic!("expected Utf8String, got {other:?}"),
        }
    }

    #[test]
    fn get_params_after_init_forwards_to_mac_ctx() {
        let mut sig_ctx =
            MacSignatureContext::new(MacSignatureAlgorithm::Hmac, LibContext::get_default(), None);
        sig_ctx
            .init_with_params(Some("SHA256"), b"hmac-key-material", None)
            .expect("init must succeed");

        let params = sig_ctx
            .get_params()
            .expect("get_params after init must succeed");
        // The crypto layer's MacCtx::get_params returns both "size" and
        // "algorithm" keys.  Check that forwarding happened by asserting
        // the size key appears.
        assert!(
            params.contains("size"),
            "expected 'size' key from forwarded MacCtx::get_params"
        );
    }

    // -------------------------------------------------------------------------
    // Debug impl does not leak key material
    // -------------------------------------------------------------------------

    #[test]
    fn debug_representation_omits_sensitive_state() {
        let mut sig_ctx = MacSignatureContext::new(
            MacSignatureAlgorithm::Hmac,
            LibContext::get_default(),
            Some("fips=yes".to_string()),
        );
        sig_ctx
            .init_with_params(Some("SHA256"), b"super-secret-hmac-key", None)
            .expect("init must succeed");
        let dbg = format!("{sig_ctx:?}");
        assert!(dbg.contains("MacSignatureContext"));
        assert!(dbg.contains("algorithm: Hmac"));
        assert!(
            !dbg.contains("super-secret-hmac-key"),
            "Debug output must not leak key material: {dbg}"
        );
    }

    // -------------------------------------------------------------------------
    // unsupported() helper round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn unsupported_error_contains_operation_name() {
        let err = unsupported("custom_op");
        let msg = format!("{err}");
        assert!(
            msg.contains("custom_op"),
            "error message should mention the operation"
        );
    }

    #[test]
    fn dispatch_err_preserves_crypto_error_message() {
        let crypto_err = CryptoError::AlgorithmNotFound("BOGUS".to_string());
        let provider_err = dispatch_err(crypto_err);
        match provider_err {
            ProviderError::Dispatch(msg) => {
                assert!(
                    msg.contains("BOGUS"),
                    "error message should be preserved: {msg}"
                );
            }
            other => panic!("expected Dispatch variant, got {other:?}"),
        }
    }
}
