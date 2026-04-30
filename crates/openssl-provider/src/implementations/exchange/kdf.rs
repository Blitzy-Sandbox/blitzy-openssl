//! KDF-backed key exchange adapter implementations.
//!
//! Wraps Key Derivation Function (KDF) operations in the `KEYEXCH` provider
//! interface for backward compatibility with the TLS stack and legacy EVP key
//! derivation API. These are **not** true asymmetric key agreement primitives
//! — they adapt KDF derivation into the key-exchange lifecycle pattern:
//!
//! ```text
//! new_ctx() → init(kdf_data) → set_params(...) → derive(secret) → Drop
//! ```
//!
//! Three KDF algorithms are wrapped:
//!
//! | Algorithm  | Standard          | Use case                                 |
//! |------------|-------------------|------------------------------------------|
//! | `TLS1-PRF` | RFC 5246 §5       | TLS 1.0 / 1.1 / 1.2 master-secret PRF    |
//! | `HKDF`     | RFC 5869          | TLS 1.3 / `IKEv2` expand-and-extract     |
//! | `SCRYPT`   | RFC 7914          | Password-based key derivation            |
//!
//! # Architecture
//!
//! Each adapter is a **thin wrapper** around the [`openssl_crypto::evp::kdf`]
//! module. The provider layer adds:
//!
//! - Lifecycle management (`new_ctx` → `init` → `derive` → `Drop`).
//! - The KEYEXCH dispatch surface (`init`, `set_peer`, `derive`, …) so the
//!   legacy `EVP_PKEY_derive` API can drive a KDF as if it were a key
//!   exchange. The C TLS stack uses this path to derive the TLS 1.0/1.1/1.2
//!   master secret via `EVP_PKEY_derive` over a `TLS1-PRF` KEYEXCH context.
//! - Parameter delegation: every `set_params` / `get_params` call simply
//!   forwards to the wrapped KDF context — the adapter introduces no new
//!   parameter semantics.
//! - `set_peer` is **not applicable** to KDF exchanges (there is no peer); it
//!   returns [`ProviderError::Common`]`(`[`CommonError::Unsupported`]`)`,
//!   mirroring the C dispatch table which simply omits `OSSL_FUNC_KEYEXCH_SET_PEER`.
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KeyExchange)
//!         → implementations::all_exchange_descriptors()
//!           → exchange::kdf::descriptors()
//!             → Tls1PrfExchange / HkdfExchange / ScryptExchange
//!               → KdfExchangeContext::{init, derive, get_params, set_params}
//! ```
//!
//! # Security Properties
//!
//! - All key material flows through `KdfData`, which derives `ZeroizeOnDrop`
//!   (provided by [`openssl_crypto::evp::kdf::KdfData`]).
//! - `KdfCtx::derive` returns a [`zeroize::Zeroizing`]`<Vec<u8>>`, ensuring
//!   intermediate buffers are scrubbed on drop.
//! - Zero `unsafe` blocks (Rule R8 — `#![deny(unsafe_code)]` applies crate-wide).
//!
//! # C Source Mapping
//!
//! | Rust construct                                  | C construct                          | `kdf_exch.c` lines |
//! |-------------------------------------------------|--------------------------------------|--------------------|
//! | [`KdfAlgorithm`]                                | macro-generated dispatch tables      | 80-82, 239-257     |
//! | [`KdfExchangeContext`]                          | `PROV_KDF_CTX` struct                | 39-43              |
//! | [`Tls1PrfExchange`] / [`HkdfExchange`] / [`ScryptExchange`] | three `OSSL_DISPATCH` arrays | 255-257            |
//! | [`Tls1PrfExchange::new_ctx`] et al.             | `kdf_*_newctx()` (via macro)         | 45-82              |
//! | [`KdfExchangeContext::init`]                    | `kdf_init()`                         | 84-96              |
//! | [`KdfExchangeContext::set_peer`]                | (not in C dispatch — error in Rust)  | n/a                |
//! | [`KdfExchangeContext::derive`]                  | `kdf_derive()`                       | 98-129             |
//! | [`Drop`] for [`KdfExchangeContext`]             | `kdf_freectx()`                      | 131-139            |
//! | [`Clone`] for [`KdfExchangeContext`]            | `kdf_dupctx()`                       | 141-167            |
//! | [`KdfExchangeContext::set_params`]              | `kdf_set_ctx_params()`               | 169-174            |
//! | [`KdfExchangeContext::get_params`]              | `kdf_get_ctx_params()`               | 176-181            |
//! | [`KdfExchangeContext::settable_params`]         | `kdf_*_settable_ctx_params()`        | 183-209            |
//! | [`KdfExchangeContext::gettable_params`]         | `kdf_*_gettable_ctx_params()`        | 211-237            |
//! | [`descriptors`]                                 | three `KDF_KEYEXCH_FUNCTIONS` tables | 239-257            |
//!
//! Replaces `providers/implementations/exchange/kdf_exch.c` (~258 lines).

use tracing::{debug, trace};

use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::ParamSet;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::kdf::{Kdf, KdfCtx, KdfData};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyExchangeContext, KeyExchangeProvider};

// =============================================================================
// Parameter Name Constants
// =============================================================================
//
// String constants mirror OpenSSL's `OSSL_KDF_PARAM_*` identifiers from
// `include/openssl/core_names.h`. They are the same keys recognised by the
// underlying [`KdfCtx`] in `openssl_crypto::evp::kdf`. Using `const &str`
// gives compile-time deduplication and a single source of truth.

/// HKDF / TLS1-PRF key (input keying material). Maps to `OSSL_KDF_PARAM_KEY`.
const PARAM_KEY: &str = "key";
/// Optional salt for HKDF / TLS1-PRF / SCRYPT. Maps to `OSSL_KDF_PARAM_SALT`.
const PARAM_SALT: &str = "salt";
/// Context info for HKDF (also accepted as a TLS1-PRF seed alias). Maps to
/// `OSSL_KDF_PARAM_INFO`.
const PARAM_INFO: &str = "info";
/// TLS1-PRF seed bytes. Maps to `OSSL_KDF_PARAM_SEED`.
const PARAM_SEED: &str = "seed";
/// Underlying digest algorithm name. Maps to `OSSL_KDF_PARAM_DIGEST`.
const PARAM_DIGEST: &str = "digest";
/// Provider property string for the digest fetch. Maps to
/// `OSSL_KDF_PARAM_PROPERTIES`.
const PARAM_PROPERTIES: &str = "properties";
/// SCRYPT password (preferred key). Maps to `OSSL_KDF_PARAM_PASSWORD`.
const PARAM_PASSWORD: &str = "pass";
/// SCRYPT password alias. Maps to `OSSL_KDF_PARAM_PASSWORD` too.
const PARAM_PASSWORD_ALIAS: &str = "password";
/// SCRYPT cost parameter `N`. Maps to `OSSL_KDF_PARAM_SCRYPT_N`.
const PARAM_SCRYPT_N: &str = "n";
/// SCRYPT block-size parameter `r`. Maps to `OSSL_KDF_PARAM_SCRYPT_R`.
const PARAM_SCRYPT_R: &str = "r";
/// SCRYPT parallelism parameter `p`. Maps to `OSSL_KDF_PARAM_SCRYPT_P`.
const PARAM_SCRYPT_P: &str = "p";
/// SCRYPT memory cap. Maps to `OSSL_KDF_PARAM_SCRYPT_MAXMEM`.
const PARAM_SCRYPT_MAXMEM: &str = "maxmem_bytes";

// =============================================================================
// KdfAlgorithm
// =============================================================================

/// Selects which KDF algorithm a [`KdfExchangeContext`] wraps.
///
/// The C source uses preprocessor macros (`KDF_NEWCTX`, `KDF_KEYEXCH_FUNCTIONS`)
/// to generate three nearly-identical dispatch tables — one per KDF name.
/// In Rust we enumerate the variants explicitly and use a single shared
/// implementation that branches on this enum.
///
/// # Variants
///
/// | Variant       | KDF name    | Standard      |
/// |---------------|-------------|---------------|
/// | [`Tls1Prf`]   | `TLS1-PRF`  | RFC 5246 §5   |
/// | [`Hkdf`]      | `HKDF`      | RFC 5869      |
/// | [`Scrypt`]    | `SCRYPT`    | RFC 7914      |
///
/// [`Tls1Prf`]: KdfAlgorithm::Tls1Prf
/// [`Hkdf`]: KdfAlgorithm::Hkdf
/// [`Scrypt`]: KdfAlgorithm::Scrypt
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfAlgorithm {
    /// TLS 1.0 / 1.1 / 1.2 pseudo-random function (RFC 5246 §5).
    Tls1Prf,
    /// HMAC-based key derivation function (RFC 5869) — used by TLS 1.3.
    Hkdf,
    /// Memory-hard password-based key derivation function (RFC 7914).
    Scrypt,
}

impl KdfAlgorithm {
    /// Returns the algorithm name as registered in the EVP KDF fetch API.
    ///
    /// These names match the canonical spellings in
    /// [`openssl_crypto::evp::kdf`] — `"TLS1-PRF"`, `"HKDF"`, `"SCRYPT"` — and
    /// mirror the macro literals used in `kdf_exch.c` lines 80-82.
    #[must_use]
    pub fn kdf_name(self) -> &'static str {
        match self {
            Self::Tls1Prf => "TLS1-PRF",
            Self::Hkdf => "HKDF",
            Self::Scrypt => "SCRYPT",
        }
    }

    /// Returns the exchange algorithm name for provider registration.
    ///
    /// The exchange name mirrors the KDF name verbatim — the C macro
    /// `KDF_KEYEXCH_FUNCTIONS(funcname)` declares
    /// `ossl_kdf_<funcname>_keyexch_functions[]` for each KDF and uses the
    /// same string as the algorithm key in `defltprov.c`. Registering both
    /// names from the same source guarantees they cannot drift.
    #[must_use]
    pub fn exchange_name(self) -> &'static str {
        // KDF and exchange names are intentionally the same — see C
        // `defltprov.c` which registers `OSSL_ALGORITHM` entries keyed by the
        // KDF name itself for these adapters.
        self.kdf_name()
    }

    /// Returns a human-readable algorithm description used in
    /// [`AlgorithmDescriptor::description`].
    #[must_use]
    pub fn exchange_description(self) -> &'static str {
        match self {
            Self::Tls1Prf => "TLS1-PRF Key Exchange Adapter (RFC 5246)",
            Self::Hkdf => "HKDF Key Exchange Adapter (RFC 5869)",
            Self::Scrypt => "SCRYPT Key Exchange Adapter (RFC 7914)",
        }
    }

    /// Returns the canonical parameter keys this KDF accepts via
    /// [`KdfExchangeContext::set_params`].
    ///
    /// Mirrors `EVP_KDF_settable_ctx_params` for each KDF in the C source.
    /// The static slice ordering matches the param tables in
    /// `providers/implementations/kdfs/{tls1_prf,hkdf,scrypt}.c`.
    #[must_use]
    fn settable_param_keys(self) -> &'static [&'static str] {
        match self {
            Self::Tls1Prf => &[
                PARAM_KEY,
                PARAM_SALT,
                PARAM_INFO,
                PARAM_SEED,
                PARAM_DIGEST,
                PARAM_PROPERTIES,
            ],
            Self::Hkdf => &[
                PARAM_KEY,
                PARAM_SALT,
                PARAM_INFO,
                PARAM_DIGEST,
                PARAM_PROPERTIES,
            ],
            Self::Scrypt => &[
                PARAM_PASSWORD,
                PARAM_PASSWORD_ALIAS,
                PARAM_SALT,
                PARAM_SCRYPT_N,
                PARAM_SCRYPT_R,
                PARAM_SCRYPT_P,
                PARAM_SCRYPT_MAXMEM,
            ],
        }
    }

    /// Returns the canonical parameter keys observable via
    /// [`KdfExchangeContext::get_params`].
    ///
    /// In the C implementation `EVP_KDF_gettable_ctx_params` returns the same
    /// table that callers write to via `EVP_KDF_CTX_get_params`. Rust mirrors
    /// that semantic: the gettable surface equals the settable surface, since
    /// the underlying [`KdfCtx::get_params`] returns the live parameter set.
    #[must_use]
    fn gettable_param_keys(self) -> &'static [&'static str] {
        // C semantic: `EVP_KDF_gettable_ctx_params(kdf)` returns the same
        // OSSL_PARAM table used for set; we mirror that.
        self.settable_param_keys()
    }
}

impl std::fmt::Display for KdfAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kdf_name())
    }
}

// =============================================================================
// KdfExchangeContext
// =============================================================================

/// Per-operation context for KDF-backed key exchange.
///
/// Wraps an inner [`KdfCtx`] (`EVP_KDF_CTX` equivalent) and an optional
/// [`KdfData`] (`KDF_DATA` equivalent — the key material handed to `init`).
/// All cryptographic logic lives in the wrapped [`KdfCtx`]; this struct is a
/// thin lifecycle adapter.
///
/// # Lifecycle
///
/// 1. `new_ctx()` (via one of the provider structs) constructs an empty
///    context with a freshly-fetched KDF.
/// 2. `init(key_material, params)` stores the [`KdfData`] and applies any
///    initial parameters.
/// 3. Optional further `set_params(...)` calls refine parameters.
/// 4. `derive(secret)` produces output and consumes the context.
/// 5. `Drop` zeros the wrapped [`KdfData`] and tears down the [`KdfCtx`].
///
/// Replaces C `PROV_KDF_CTX` from `kdf_exch.c:39-43`.
pub struct KdfExchangeContext {
    /// Which KDF algorithm this adapter wraps.
    algorithm: KdfAlgorithm,
    /// Inner KDF context. All cryptographic state lives here.
    kdf_ctx: KdfCtx,
    /// Optional KDF data ("key material") supplied at `init` time.
    ///
    /// Rule R5: stored as `Option<KdfData>` rather than a raw pointer or
    /// empty-vector sentinel. Mirrors the C field `kdfdata` (a pointer that
    /// is `NULL` until `kdf_init` populates it).
    kdf_data: Option<KdfData>,
}

impl KdfExchangeContext {
    /// Creates a fresh KDF exchange context for `algorithm`.
    ///
    /// Internally fetches the named KDF from the process-wide library context
    /// and wraps it in a new [`KdfCtx`]. The context starts with no key
    /// material and no parameters — callers must invoke
    /// [`KdfExchangeContext::init`] before [`KdfExchangeContext::derive`].
    ///
    /// Translates the body of C `kdf_newctx()` (`kdf_exch.c:45-72`):
    ///
    /// ```c
    /// kdf = EVP_KDF_fetch(PROV_LIBCTX_OF(provctx), kdfname, NULL);
    /// kdfctx->kdfctx = EVP_KDF_CTX_new(kdf);
    /// EVP_KDF_free(kdf);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::AlgorithmUnavailable`] if the named KDF is
    /// not registered in the library context (mirrors `EVP_KDF_fetch`
    /// returning `NULL`).
    pub fn new(algorithm: KdfAlgorithm) -> ProviderResult<Self> {
        debug!(
            algorithm = %algorithm,
            "kdf-exchange: creating new context"
        );

        // PROV_LIBCTX_OF(provctx) → process-wide default LibContext.
        // The provider context (`provctx`) in C carries a back-pointer to
        // the `OSSL_LIB_CTX`. Our Rust provider system does not yet thread a
        // per-provider context here, so we use the default global context.
        let lib_ctx = LibContext::default();

        let kdf = Kdf::fetch(&lib_ctx, algorithm.kdf_name(), None).map_err(|e| {
            ProviderError::AlgorithmUnavailable(format!(
                "KDF `{}` not available: {e}",
                algorithm.kdf_name()
            ))
        })?;

        let kdf_ctx = KdfCtx::new(&kdf);

        Ok(Self {
            algorithm,
            kdf_ctx,
            kdf_data: None,
        })
    }

    /// Returns the algorithm wrapped by this context.
    #[must_use]
    pub fn algorithm(&self) -> KdfAlgorithm {
        self.algorithm
    }

    /// Returns the static, KDF-specific list of settable parameter keys.
    ///
    /// Translates the C function family `kdf_*_settable_ctx_params()`
    /// (`kdf_exch.c:183-209`). Where the C code fetches the KDF, queries
    /// `EVP_KDF_settable_ctx_params(kdf)`, then `EVP_KDF_free(kdf)`, the Rust
    /// adapter consults the static list embedded in [`KdfAlgorithm`]. This
    /// avoids re-allocating a fresh `Kdf` on every query while preserving the
    /// per-KDF parameter surface.
    #[must_use]
    pub fn settable_params(&self) -> Vec<&'static str> {
        trace!(
            algorithm = %self.algorithm,
            "kdf-exchange: settable_params query"
        );
        self.algorithm.settable_param_keys().to_vec()
    }

    /// Returns the static, KDF-specific list of gettable parameter keys.
    ///
    /// Mirrors C `kdf_*_gettable_ctx_params()` (`kdf_exch.c:211-237`).
    /// Symmetric with [`KdfExchangeContext::settable_params`] — the underlying
    /// [`KdfCtx`] reflects writes back via `get_params`, so the gettable surface
    /// equals the settable surface.
    #[must_use]
    pub fn gettable_params(&self) -> Vec<&'static str> {
        trace!(
            algorithm = %self.algorithm,
            "kdf-exchange: gettable_params query"
        );
        self.algorithm.gettable_param_keys().to_vec()
    }

    /// Returns the natural output length of the wrapped KDF, or `None` for
    /// variable-length KDFs.
    ///
    /// Mirrors C `EVP_KDF_CTX_get_kdf_size()`. The C function returns
    /// `SIZE_MAX` for variable-length output; the Rust [`KdfCtx::kdf_size`]
    /// returns `0`. In this adapter we surface that as [`None`] (Rule R5 —
    /// no sentinel values).
    fn fixed_output_size(&self) -> ProviderResult<Option<usize>> {
        let size = self
            .kdf_ctx
            .kdf_size()
            .map_err(|e| ProviderError::Dispatch(format!("kdf_size query failed: {e}")))?;
        // 0 is the "variable-length" sentinel returned by `KdfCtx::kdf_size`.
        if size == 0 {
            Ok(None)
        } else {
            Ok(Some(size))
        }
    }
}

impl KeyExchangeContext for KdfExchangeContext {
    /// Initialises the exchange with the KDF key material plus optional
    /// initial parameters.
    ///
    /// The `key` slice is taken to be the opaque KDF data. In the C code the
    /// `vkdf` argument is a pointer to a `KDF_DATA` reference-counted handle
    /// produced upstream by the keymgmt layer; here we accept the raw bytes
    /// and wrap them in [`KdfData`] (which derives `ZeroizeOnDrop`).
    ///
    /// Initial parameters, if supplied, are forwarded to
    /// [`KdfCtx::set_params`].
    ///
    /// C equivalent: `kdf_init()` (`kdf_exch.c:84-96`).
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Init`] when `key` is empty (cannot initialise a
    ///   KDF with no key material — mirrors C `vkdf == NULL` rejection).
    /// - [`ProviderError::Common`] propagated from
    ///   [`KdfCtx::set_params`] when the supplied `params` cannot be applied
    ///   (e.g. the context has already been consumed).
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = %self.algorithm,
            key_len = key.len(),
            params_present = params.is_some(),
            "kdf-exchange: init"
        );

        if key.is_empty() {
            return Err(ProviderError::Init(format!(
                "KDF exchange `{}` init: key material is empty",
                self.algorithm
            )));
        }

        // Wrap the key material in `KdfData`. The container derives
        // `ZeroizeOnDrop`, so the bytes will be scrubbed when this context
        // is dropped or replaced.
        self.kdf_data = Some(KdfData::new(key.to_vec()));

        if let Some(ps) = params {
            trace!(
                algorithm = %self.algorithm,
                count = ps.len(),
                "kdf-exchange: init applying initial params"
            );
            self.kdf_ctx.set_params(ps).map_err(|e| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "KDF exchange `{}` init: parameter application failed: {e}",
                    self.algorithm
                )))
            })?;
        }

        Ok(())
    }

    /// Sets the peer public key — **not applicable** to KDF exchanges.
    ///
    /// KDF-backed key exchanges have no peer: the "exchange" is purely a
    /// derivation from local key material. The C dispatch table in
    /// `kdf_exch.c` simply omits `OSSL_FUNC_KEYEXCH_SET_PEER`, so calling
    /// `EVP_PKEY_derive_set_peer()` against a KDF-based KEYEXCH context
    /// returns an error in the C implementation as well.
    ///
    /// # Errors
    ///
    /// Always returns [`ProviderError::Common`]`(`[`CommonError::Unsupported`]`)`.
    fn set_peer(&mut self, _peer_key: &[u8]) -> ProviderResult<()> {
        debug!(
            algorithm = %self.algorithm,
            "kdf-exchange: set_peer rejected (not applicable for KDF adapters)"
        );
        Err(ProviderError::Common(CommonError::Unsupported(format!(
            "set_peer is not applicable to KDF-backed key exchange `{}`",
            self.algorithm
        ))))
    }

    /// Derives output bytes from the configured KDF.
    ///
    /// Two operating modes mirror the C function precisely:
    ///
    /// 1. **Size-query mode** — when `secret` is empty, the call returns the
    ///    fixed output size of the wrapped KDF (or zero for variable-length
    ///    KDFs) without performing derivation.
    ///    C: `if (secret == NULL) { *secretlen = kdfsize; return 1; }`
    ///    (`kdf_exch.c:110-113`).
    ///
    /// 2. **Derive mode** — when `secret` is non-empty, the call validates
    ///    the buffer is large enough (for fixed-size KDFs), runs
    ///    [`KdfCtx::derive`] for `secret.len()` bytes, copies the result
    ///    into `secret`, and returns the number of bytes written.
    ///    C: `EVP_KDF_derive(pkdfctx->kdfctx, secret, outlen, NULL)`
    ///    (`kdf_exch.c:123`).
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Common`]`(`[`CommonError::InvalidArgument`]`)` when
    ///   the buffer is smaller than the KDF's fixed output size.
    /// - [`ProviderError::Dispatch`] when the underlying derivation fails
    ///   (missing param, invalid digest, etc.).
    fn derive(&mut self, secret: &mut [u8]) -> ProviderResult<usize> {
        let buf_len = secret.len();
        trace!(
            algorithm = %self.algorithm,
            buf_len,
            "kdf-exchange: derive"
        );

        // Mode 1: size-query — empty buffer.
        if buf_len == 0 {
            let size = self.fixed_output_size()?.unwrap_or(0);
            trace!(
                algorithm = %self.algorithm,
                reported_size = size,
                "kdf-exchange: derive size-query"
            );
            return Ok(size);
        }

        // Mode 2: real derivation. Apply length validation against the
        // fixed-size constraint when the KDF reports one.
        let outlen = match self.fixed_output_size()? {
            Some(fixed) => {
                if buf_len < fixed {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "KDF exchange `{}` derive: output buffer too small ({buf_len} < {fixed})",
                            self.algorithm
                        ),
                    )));
                }
                fixed
            }
            None => buf_len,
        };

        debug!(
            algorithm = %self.algorithm,
            outlen,
            "kdf-exchange: deriving key material"
        );

        let derived = self.kdf_ctx.derive(outlen).map_err(|e| {
            ProviderError::Dispatch(format!(
                "KDF exchange `{}` derive failed: {e}",
                self.algorithm
            ))
        })?;

        // `KdfCtx::derive` produces exactly `outlen` bytes. Copy into the
        // caller-supplied buffer; for the variable-length case `outlen ==
        // buf_len`, for the fixed-length case `outlen <= buf_len`.
        let written = derived.len();
        // Defensive: trust but verify the length contract.
        if written > buf_len {
            return Err(ProviderError::Dispatch(format!(
                "KDF exchange `{}` derive returned {written} bytes for a {buf_len}-byte buffer",
                self.algorithm
            )));
        }
        secret[..written].copy_from_slice(&derived[..written]);
        Ok(written)
    }

    /// Returns the wrapped KDF context's current parameters.
    ///
    /// Pure delegation to [`KdfCtx::get_params`].
    /// C equivalent: `kdf_get_ctx_params()` (`kdf_exch.c:176-181`).
    fn get_params(&self) -> ProviderResult<ParamSet> {
        trace!(
            algorithm = %self.algorithm,
            "kdf-exchange: get_params"
        );
        self.kdf_ctx.get_params().map_err(|e| {
            ProviderError::Dispatch(format!(
                "KDF exchange `{}` get_params failed: {e}",
                self.algorithm
            ))
        })
    }

    /// Forwards parameter writes to the wrapped KDF context.
    ///
    /// All parameter handling is delegated — the adapter introduces no new
    /// parameter semantics. C equivalent: `kdf_set_ctx_params()`
    /// (`kdf_exch.c:169-174`).
    ///
    /// Note that, like the C implementation, this rejects writes after the
    /// underlying [`KdfCtx`] has been consumed by a successful
    /// [`KdfExchangeContext::derive`] call until the context is reset.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        trace!(
            algorithm = %self.algorithm,
            count = params.len(),
            "kdf-exchange: set_params"
        );
        self.kdf_ctx.set_params(params).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "KDF exchange `{}` set_params failed: {e}",
                self.algorithm
            )))
        })?;

        // Spot-check that every supplied key is recognised for this KDF.
        // The wrapped `KdfCtx::set_params` performs no key validation, so
        // surfacing unknown keys here aids debugging without changing
        // observable behaviour (the merge has already happened).
        let allowed = self.algorithm.settable_param_keys();
        for (key, value) in params.iter() {
            if !allowed.contains(&key) {
                trace!(
                    algorithm = %self.algorithm,
                    key,
                    value_type = value.param_type_name(),
                    "kdf-exchange: set_params received key outside the algorithm's settable set"
                );
            }
        }

        Ok(())
    }
}

impl Clone for KdfExchangeContext {
    /// Deep-clones the KDF exchange context.
    ///
    /// Replaces `kdf_dupctx()` from `kdf_exch.c:141-167`. The C version
    /// allocates a new `PROV_KDF_CTX`, calls `EVP_KDF_CTX_dup()`, and
    /// reference-counts `kdfdata` via `ossl_kdf_data_up_ref()`. In Rust:
    ///
    /// - [`KdfCtx::try_clone`] is documented to be currently infallible;
    ///   if a future implementation makes it fallible, we fall back to a
    ///   freshly fetched KDF context preserving the algorithm but losing
    ///   parameters. This avoids panicking from `Clone` (Rule R8 — no
    ///   `unwrap()`/`expect()` in library code).
    /// - [`KdfData`] derives `Clone`; cloning copies the bytes (Rust's
    ///   ownership model handles refcounting implicitly).
    fn clone(&self) -> Self {
        let kdf_ctx = self.kdf_ctx.try_clone().unwrap_or_else(|err| {
            // Preserve forward-compatibility: if a future `try_clone`
            // implementation can fail, we fall back to a fresh context for
            // the same KDF method. Parameters are lost, but we never panic.
            tracing::warn!(
                algorithm = %self.algorithm,
                error = %err,
                "kdf-exchange: KdfCtx::try_clone failed; falling back to fresh KdfCtx"
            );
            KdfCtx::new(self.kdf_ctx.kdf())
        });

        Self {
            algorithm: self.algorithm,
            kdf_ctx,
            kdf_data: self.kdf_data.clone(),
        }
    }
}

impl std::fmt::Debug for KdfExchangeContext {
    /// Custom `Debug` that hides key material from logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdfExchangeContext")
            .field("algorithm", &self.algorithm)
            .field(
                "kdf_data_len",
                &self.kdf_data.as_ref().map_or(0, KdfData::len),
            )
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Provider entry-point structs
// =============================================================================

/// TLS1-PRF key exchange adapter.
///
/// Wraps the TLS 1.0/1.1/1.2 pseudo-random function (RFC 5246 §5) in the
/// `KEYEXCH` provider interface. Used by the legacy TLS stack to derive
/// the master secret via `EVP_PKEY_derive`.
///
/// Replaces the C `ossl_kdf_tls1_prf_keyexch_functions` dispatch table
/// generated by `KDF_KEYEXCH_FUNCTIONS(tls1_prf)` at `kdf_exch.c:255`.
#[derive(Debug, Clone, Default)]
pub struct Tls1PrfExchange;

impl Tls1PrfExchange {
    /// Constructs a new provider handle. The struct is zero-sized; this
    /// constructor exists purely for API ergonomics.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl KeyExchangeProvider for Tls1PrfExchange {
    /// Returns the canonical exchange algorithm name `"TLS1-PRF"`.
    fn name(&self) -> &'static str {
        KdfAlgorithm::Tls1Prf.exchange_name()
    }

    /// Creates a fresh, uninitialised TLS1-PRF [`KdfExchangeContext`].
    ///
    /// C equivalent: `kdf_tls1_prf_newctx()` macro expansion of
    /// `KDF_NEWCTX(tls1_prf, "TLS1-PRF")` at `kdf_exch.c:80`.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("kdf-exchange: TLS1-PRF — creating new context");
        Ok(Box::new(KdfExchangeContext::new(KdfAlgorithm::Tls1Prf)?))
    }
}

/// HKDF key exchange adapter.
///
/// Wraps HMAC-based KDF (RFC 5869) in the `KEYEXCH` provider interface.
/// Used by the TLS 1.3 key schedule (HKDF-Extract / HKDF-Expand-Label) and
/// by IKEv2-style key derivation flows.
///
/// Replaces the C `ossl_kdf_hkdf_keyexch_functions` dispatch table
/// generated by `KDF_KEYEXCH_FUNCTIONS(hkdf)` at `kdf_exch.c:256`.
#[derive(Debug, Clone, Default)]
pub struct HkdfExchange;

impl HkdfExchange {
    /// Constructs a new provider handle. The struct is zero-sized; this
    /// constructor exists purely for API ergonomics.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl KeyExchangeProvider for HkdfExchange {
    /// Returns the canonical exchange algorithm name `"HKDF"`.
    fn name(&self) -> &'static str {
        KdfAlgorithm::Hkdf.exchange_name()
    }

    /// Creates a fresh, uninitialised HKDF [`KdfExchangeContext`].
    ///
    /// C equivalent: `kdf_hkdf_newctx()` macro expansion of
    /// `KDF_NEWCTX(hkdf, "HKDF")` at `kdf_exch.c:81`.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("kdf-exchange: HKDF — creating new context");
        Ok(Box::new(KdfExchangeContext::new(KdfAlgorithm::Hkdf)?))
    }
}

/// SCRYPT key exchange adapter.
///
/// Wraps the scrypt password-based KDF (RFC 7914) in the `KEYEXCH` provider
/// interface so that `EVP_PKEY_derive` can drive a scrypt derivation in the
/// same way it drives ECDH or HKDF.
///
/// Replaces the C `ossl_kdf_scrypt_keyexch_functions` dispatch table
/// generated by `KDF_KEYEXCH_FUNCTIONS(scrypt)` at `kdf_exch.c:257`.
#[derive(Debug, Clone, Default)]
pub struct ScryptExchange;

impl ScryptExchange {
    /// Constructs a new provider handle. The struct is zero-sized; this
    /// constructor exists purely for API ergonomics.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl KeyExchangeProvider for ScryptExchange {
    /// Returns the canonical exchange algorithm name `"SCRYPT"`.
    fn name(&self) -> &'static str {
        KdfAlgorithm::Scrypt.exchange_name()
    }

    /// Creates a fresh, uninitialised SCRYPT [`KdfExchangeContext`].
    ///
    /// C equivalent: `kdf_scrypt_newctx()` macro expansion of
    /// `KDF_NEWCTX(scrypt, "SCRYPT")` at `kdf_exch.c:82`.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("kdf-exchange: SCRYPT — creating new context");
        Ok(Box::new(KdfExchangeContext::new(KdfAlgorithm::Scrypt)?))
    }
}

// =============================================================================
// Algorithm Registration
// =============================================================================

/// Returns descriptors for every KDF-backed key-exchange algorithm provided
/// by this module.
///
/// Used by [`super::descriptors`] to register `TLS1-PRF`, `HKDF`, and `SCRYPT`
/// as valid `KEYEXCH` algorithms in the default provider's algorithm
/// directory.
///
/// Replaces the three C dispatch-table arrays
/// (`ossl_kdf_tls1_prf_keyexch_functions`, `ossl_kdf_hkdf_keyexch_functions`,
/// `ossl_kdf_scrypt_keyexch_functions`) generated by `KDF_KEYEXCH_FUNCTIONS`
/// at `kdf_exch.c:255-257`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &[KdfAlgorithm::Tls1Prf.exchange_name()],
            "provider=default",
            KdfAlgorithm::Tls1Prf.exchange_description(),
        ),
        algorithm(
            &[KdfAlgorithm::Hkdf.exchange_name()],
            "provider=default",
            KdfAlgorithm::Hkdf.exchange_description(),
        ),
        algorithm(
            &[KdfAlgorithm::Scrypt.exchange_name()],
            "provider=default",
            KdfAlgorithm::Scrypt.exchange_description(),
        ),
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for the KDF-backed key-exchange adapter.
    //!
    //! These verify:
    //! * `KdfAlgorithm` reports the expected names.
    //! * Each provider struct exposes the right algorithm name and creates
    //!   a context with the matching algorithm.
    //! * `set_peer` is rejected with `Unsupported`.
    //! * Empty-key `init` is rejected.
    //! * `derive` honours size-query semantics on an empty buffer.
    //! * `Clone` preserves the algorithm.
    //! * `descriptors()` lists all three KDF exchanges.
    //! * Property delegation (`set_params` → `get_params`) round-trips.

    use super::*;
    use openssl_common::param::ParamValue;

    fn expect_kdf_ctx(algo: KdfAlgorithm) -> KdfExchangeContext {
        KdfExchangeContext::new(algo)
            .unwrap_or_else(|err| panic!("KDF context creation must succeed for {algo}: {err}"))
    }

    #[test]
    fn algorithm_names_match_kdf_names() {
        assert_eq!(KdfAlgorithm::Tls1Prf.kdf_name(), "TLS1-PRF");
        assert_eq!(KdfAlgorithm::Hkdf.kdf_name(), "HKDF");
        assert_eq!(KdfAlgorithm::Scrypt.kdf_name(), "SCRYPT");

        assert_eq!(
            KdfAlgorithm::Tls1Prf.exchange_name(),
            KdfAlgorithm::Tls1Prf.kdf_name()
        );
        assert_eq!(
            KdfAlgorithm::Hkdf.exchange_name(),
            KdfAlgorithm::Hkdf.kdf_name()
        );
        assert_eq!(
            KdfAlgorithm::Scrypt.exchange_name(),
            KdfAlgorithm::Scrypt.kdf_name()
        );
    }

    #[test]
    fn algorithm_display_uses_kdf_name() {
        assert_eq!(format!("{}", KdfAlgorithm::Hkdf), "HKDF");
    }

    #[test]
    fn settable_param_keys_per_algorithm() {
        let tls = KdfAlgorithm::Tls1Prf.settable_param_keys();
        assert!(tls.contains(&PARAM_KEY));
        assert!(tls.contains(&PARAM_SEED));
        assert!(tls.contains(&PARAM_DIGEST));
        assert!(!tls.contains(&PARAM_SCRYPT_N));

        let hkdf = KdfAlgorithm::Hkdf.settable_param_keys();
        assert!(hkdf.contains(&PARAM_KEY));
        assert!(hkdf.contains(&PARAM_INFO));
        assert!(hkdf.contains(&PARAM_DIGEST));
        assert!(!hkdf.contains(&PARAM_SEED));
        assert!(!hkdf.contains(&PARAM_SCRYPT_N));

        let scrypt = KdfAlgorithm::Scrypt.settable_param_keys();
        assert!(scrypt.contains(&PARAM_PASSWORD));
        assert!(scrypt.contains(&PARAM_PASSWORD_ALIAS));
        assert!(scrypt.contains(&PARAM_SALT));
        assert!(scrypt.contains(&PARAM_SCRYPT_N));
        assert!(scrypt.contains(&PARAM_SCRYPT_R));
        assert!(scrypt.contains(&PARAM_SCRYPT_P));
        assert!(scrypt.contains(&PARAM_SCRYPT_MAXMEM));
    }

    #[test]
    fn provider_struct_names_match_algorithm() {
        assert_eq!(Tls1PrfExchange::new().name(), "TLS1-PRF");
        assert_eq!(HkdfExchange::new().name(), "HKDF");
        assert_eq!(ScryptExchange::new().name(), "SCRYPT");
    }

    #[test]
    fn new_ctx_returns_boxed_context_for_each_provider() {
        for provider in [
            Box::new(Tls1PrfExchange::new()) as Box<dyn KeyExchangeProvider>,
            Box::new(HkdfExchange::new()) as Box<dyn KeyExchangeProvider>,
            Box::new(ScryptExchange::new()) as Box<dyn KeyExchangeProvider>,
        ] {
            let _ctx = provider
                .new_ctx()
                .expect("KDF exchange contexts must be creatable for all three KDFs");
        }
    }

    #[test]
    fn context_reports_algorithm_for_each_kdf() {
        for algo in [
            KdfAlgorithm::Tls1Prf,
            KdfAlgorithm::Hkdf,
            KdfAlgorithm::Scrypt,
        ] {
            let ctx = expect_kdf_ctx(algo);
            assert_eq!(ctx.algorithm(), algo);
        }
    }

    #[test]
    fn settable_and_gettable_params_match_algorithm_keys() {
        for algo in [
            KdfAlgorithm::Tls1Prf,
            KdfAlgorithm::Hkdf,
            KdfAlgorithm::Scrypt,
        ] {
            let ctx = expect_kdf_ctx(algo);
            let settable = ctx.settable_params();
            let gettable = ctx.gettable_params();
            assert_eq!(
                settable, gettable,
                "{algo}: settable and gettable should match"
            );
            // Every entry should be a key from the algorithm's static list.
            for key in &settable {
                assert!(
                    algo.settable_param_keys().contains(key),
                    "settable_params surfaces foreign key for {algo}: {key}"
                );
            }
        }
    }

    #[test]
    fn init_rejects_empty_key() {
        let mut ctx = expect_kdf_ctx(KdfAlgorithm::Hkdf);
        let err = ctx
            .init(&[], None)
            .expect_err("init with empty key must fail");
        match err {
            ProviderError::Init(msg) => assert!(msg.contains("empty"), "msg = {msg}"),
            other => panic!("expected ProviderError::Init, got {other:?}"),
        }
    }

    #[test]
    fn init_accepts_non_empty_key() {
        let mut ctx = expect_kdf_ctx(KdfAlgorithm::Hkdf);
        ctx.init(b"input keying material", None)
            .expect("init with valid key material must succeed");
    }

    #[test]
    fn init_applies_initial_params() {
        let mut ctx = expect_kdf_ctx(KdfAlgorithm::Hkdf);
        let mut params = ParamSet::new();
        params.set(PARAM_DIGEST, ParamValue::Utf8String("SHA256".into()));

        ctx.init(b"ikm", Some(&params))
            .expect("init with params must succeed");

        let observed = ctx.get_params().expect("get_params must succeed");
        assert!(
            observed.contains(PARAM_DIGEST),
            "digest must be observable after init"
        );
    }

    #[test]
    fn set_peer_is_unsupported() {
        let mut ctx = expect_kdf_ctx(KdfAlgorithm::Hkdf);
        let err = ctx
            .set_peer(b"any-peer-bytes")
            .expect_err("set_peer must fail for KDF adapters");
        match err {
            ProviderError::Common(CommonError::Unsupported(msg)) => {
                assert!(msg.contains("set_peer"), "msg = {msg}");
            }
            other => panic!("expected Unsupported error, got {other:?}"),
        }
    }

    #[test]
    fn derive_size_query_returns_zero_for_variable_length_kdf() {
        let mut ctx = expect_kdf_ctx(KdfAlgorithm::Hkdf);
        // No data needs to be set up — size queries do not exercise the KDF.
        let mut empty: [u8; 0] = [];
        let reported = ctx
            .derive(&mut empty)
            .expect("size-query derive must succeed");
        assert_eq!(
            reported, 0,
            "HKDF is variable-length; size-query must report 0"
        );
    }

    #[test]
    fn set_params_round_trip() {
        let mut ctx = expect_kdf_ctx(KdfAlgorithm::Hkdf);
        let mut params = ParamSet::new();
        params.set(PARAM_DIGEST, ParamValue::Utf8String("SHA256".into()));
        params.set(PARAM_KEY, ParamValue::OctetString(b"k".to_vec()));

        ctx.set_params(&params).expect("set_params must succeed");
        let observed = ctx.get_params().expect("get_params must succeed");

        assert!(observed.contains(PARAM_DIGEST));
        assert!(observed.contains(PARAM_KEY));
    }

    #[test]
    fn clone_preserves_algorithm() {
        let original = expect_kdf_ctx(KdfAlgorithm::Scrypt);
        let cloned = original.clone();
        assert_eq!(original.algorithm(), cloned.algorithm());
    }

    #[test]
    fn descriptors_lists_all_three_kdfs() {
        let descs = descriptors();
        assert_eq!(
            descs.len(),
            3,
            "must register exactly TLS1-PRF, HKDF, SCRYPT"
        );

        let mut names: Vec<&str> = descs.iter().flat_map(|d| d.names.iter().copied()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["HKDF", "SCRYPT", "TLS1-PRF"]);

        for desc in &descs {
            assert_eq!(
                desc.property, "provider=default",
                "all three KDF exchanges live in the default provider"
            );
            assert!(
                !desc.description.is_empty(),
                "every algorithm must have a description"
            );
        }
    }

    #[test]
    fn debug_impl_does_not_leak_key_material() {
        let mut ctx = expect_kdf_ctx(KdfAlgorithm::Hkdf);
        ctx.init(b"super-secret-ikm-do-not-leak", None)
            .expect("init must succeed");
        let dbg = format!("{ctx:?}");
        assert!(
            !dbg.contains("super-secret-ikm-do-not-leak"),
            "Debug output must not include raw key bytes; got: {dbg}"
        );
        assert!(
            dbg.contains("kdf_data_len"),
            "Debug output must include kdf_data_len summary; got: {dbg}"
        );
    }
}
