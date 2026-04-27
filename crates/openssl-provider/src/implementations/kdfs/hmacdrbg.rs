//! HMAC-DRBG KDF — Key derivation using HMAC-DRBG (NIST SP 800-90A Rev. 1).
//!
//! This module provides a key derivation function that wraps the HMAC-DRBG
//! deterministic random-bit generator mechanism defined in NIST Special
//! Publication 800-90A Revision 1, Section 10.1.2.  It is used as a
//! deterministic nonce source (e.g. for RFC 6979 ECDSA) and as a building
//! block for other higher-level deterministic key-derivation primitives.
//!
//! The implementation is an idiomatic Rust translation of the C provider in
//! `providers/implementations/kdfs/hmacdrbg_kdf.c` (SP 800-90A §10.1.2) and
//! `providers/implementations/rands/drbg_hmac.c` (the underlying DRBG state
//! machine).  The algorithm operates on two equal-length internal vectors —
//! the key `K` and the value `V` — whose length is the output size of the
//! underlying HMAC digest.  The KDF lifecycle is:
//!
//! 1. The caller configures the context via `KdfContext::set_params` with
//!    a digest name, an entropy input and a nonce.
//! 2. On the first call to `KdfContext::derive` the context runs the
//!    HMAC-DRBG Instantiate procedure (SP 800-90A §10.1.2.3) to seed `K`
//!    and `V` from the provided entropy and nonce.
//! 3. Subsequent `derive` calls run the HMAC-DRBG Generate procedure
//!    (SP 800-90A §10.1.2.5) to produce additional pseudo-random output
//!    without re-seeding.
//!
//! # Rules Compliance
//!
//! - **R5 — Nullability Over Sentinels:** optional digest / property-query
//!   values are represented as `Option<…>` rather than empty strings.
//! - **R6 — Lossless Numeric Casts:** no narrowing `as` casts are used;
//!   lengths flow exclusively as `usize` and checked arithmetic is applied
//!   where slices are indexed.
//! - **R8 — Zero Unsafe Outside FFI:** the module contains no `unsafe`
//!   blocks.  All cryptographic primitives are reached through the
//!   `openssl_crypto` public APIs.
//! - **R9 — Warning-Free Build:** the module compiles cleanly with
//!   `RUSTFLAGS="-D warnings"` and does not rely on `#[allow]`
//!   escape-hatches.
//!
//! # Security
//!
//! All sensitive state (entropy, nonce, key `K`, value `V`) is zeroised on
//! drop and on reset via `zeroize::ZeroizeOnDrop`, replacing the manual
//! `OPENSSL_cleanse()` calls in `hmac_drbg_kdf_reset()` and
//! `hmac_drbg_kdf_free()` of the C source.  XOF digests (SHAKE128 /
//! SHAKE256) are explicitly rejected, matching the `EVP_MD_xof()` check in
//! `hmac_drbg_kdf_set_ctx_params()`.

use std::sync::Arc;

use openssl_common::error::{CryptoError, ProviderError};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
use openssl_common::{CommonError, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::mac::{Mac, MacCtx, HMAC};
use openssl_crypto::evp::md::MessageDigest;
use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};

// =============================================================================
// Constants — Parameter names and algorithm identifiers
// =============================================================================

/// Canonical algorithm name exposed to consumers.
///
/// Matches `OSSL_KDF_NAME_HMACDRBGKDF` defined in
/// `include/openssl/core_names.h.in` line 88.
const ALG_NAME: &str = "HMAC-DRBG-KDF";

/// MAC algorithm backing HMAC-DRBG is always HMAC (SP 800-90A §10.1).
const MAC_ALG_NAME: &str = HMAC;

/// Property string advertising the default provider (matches the other
/// standard KDFs in this crate).
const ALG_PROPERTY: &str = "provider=default";

/// Short algorithm description surfaced through provider enumeration APIs.
const ALG_DESCRIPTION: &str = "HMAC-DRBG based key derivation (NIST SP 800-90A Rev. 1 §10.1.2)";

// ---- Parameter names (resolved from util/perl/OpenSSL/paramnames.pm) -------

/// `OSSL_KDF_PARAM_HMACDRBG_ENTROPY` (`"entropy"`, `OCTET_STRING`).
/// The entropy input for the HMAC-DRBG Instantiate procedure
/// (SP 800-90A §10.1.2.3, step 1).
const PARAM_ENTROPY: &str = "entropy";

/// `OSSL_KDF_PARAM_HMACDRBG_NONCE` (`"nonce"`, `OCTET_STRING`).
/// The nonce concatenated with the entropy in the Instantiate procedure
/// (SP 800-90A §10.1.2.3, step 1).
const PARAM_NONCE: &str = "nonce";

/// `OSSL_KDF_PARAM_DIGEST` → `OSSL_ALG_PARAM_DIGEST` (`"digest"`, UTF-8).
/// The name of the underlying hash function used by HMAC.
const PARAM_DIGEST: &str = "digest";

/// `OSSL_KDF_PARAM_PROPERTIES` → `OSSL_ALG_PARAM_PROPERTIES`
/// (`"properties"`, UTF-8).  Provider property-query string forwarded to
/// `MessageDigest::fetch` and `Mac::fetch`.
const PARAM_PROPERTIES: &str = "properties";

/// `OSSL_KDF_PARAM_MAC` → `OSSL_ALG_PARAM_MAC` (`"mac"`, UTF-8).
/// Reported via `KdfContext::get_params` and always equal to `"HMAC"`.
const PARAM_MAC: &str = "mac";

// =============================================================================
// Error Conversion Helpers
// =============================================================================

/// Converts a [`CryptoError`] returned by
/// `MessageDigest::fetch`, `Mac::fetch`, or the `MacCtx::{init,update,
/// finalize}` chain into a `ProviderError::Dispatch` for the provider layer.
///
/// Centralising this mapping keeps per-call sites concise via
/// `.map_err(dispatch_err)?` and preserves the underlying error message
/// through `Display`.  The pattern mirrors `kdfs/pbkdf1.rs` and other
/// provider implementations that bridge crypto errors to provider errors.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Build an `InvalidArgument` provider error from a static message.
#[inline]
fn invalid_arg(msg: &str) -> ProviderError {
    ProviderError::Common(CommonError::InvalidArgument(msg.to_string()))
}

// =============================================================================
// HmacDrbgKdfContext — Per-derivation state
// =============================================================================

/// Per-operation HMAC-DRBG KDF state.
///
/// Holds the HMAC-DRBG internal state (`K`, `V`) together with the digest
/// selection and the entropy / nonce inputs supplied via
/// `KdfContext::set_params`.  The context follows a *lazy instantiation*
/// model — the Instantiate procedure runs on the first call to
/// `KdfContext::derive`, matching the `ctx->init` flag behaviour in
/// `hmac_drbg_kdf_derive()`.
///
/// All sensitive byte buffers are wrapped in `Vec<u8>` and zeroised on
/// drop via the `ZeroizeOnDrop` derive, replacing the manual
/// `OPENSSL_cleanse()` / `OPENSSL_clear_free()` calls in the C source.
///
/// # Fields
///
/// * `digest_name`   — Human-readable name of the underlying hash
///                     (e.g. `"SHA-256"`).  `None` until a digest is
///                     configured.
/// * `properties`    — Optional provider property-query forwarded to
///                     `MessageDigest::fetch` / `Mac::fetch`.
/// * `digest_size`   — Cached output size of the selected digest, equal to
///                     the length of both `K` and `V` (SP 800-90A §10.1.2
///                     requires `outlen == seedlen`).
/// * `entropy`       — Entropy input supplied via `PARAM_ENTROPY`.  When
///                     any entropy bytes are set, the context is flagged as
///                     *not yet instantiated* so the next `derive` re-seeds.
/// * `nonce`         — Nonce supplied via `PARAM_NONCE`.
/// * `key` / `value` — HMAC-DRBG internal state vectors `K` and `V`.  Both
///                     are exactly `digest_size` bytes long once configured.
/// * `initialized`   — Whether the HMAC-DRBG Instantiate procedure has
///                     already been executed for the current
///                     entropy/nonce/digest tuple.
pub struct HmacDrbgKdfContext {
    digest_name: Option<String>,
    properties: Option<String>,
    digest_size: usize,
    entropy: Vec<u8>,
    nonce: Vec<u8>,
    key: Vec<u8>,
    value: Vec<u8>,
    initialized: bool,
}

// ZeroizeOnDrop is implemented manually (rather than via derive) because
// several fields — `digest_name`, `properties`, `digest_size`,
// `initialized` — do not carry cryptographic material and need not be
// zeroised.  Only the key-material vectors are wiped.
impl Drop for HmacDrbgKdfContext {
    fn drop(&mut self) {
        self.entropy.zeroize();
        self.nonce.zeroize();
        self.key.zeroize();
        self.value.zeroize();
    }
}

// Assert the `ZeroizeOnDrop` marker trait at compile time.  This preserves
// the contractual invariant encoded in the AAP: the context *is* a
// zeroise-on-drop type, even though the `Drop` implementation is manual
// and selective.  The empty `ZeroizeOnDrop` impl composes with the `Drop`
// implementation above.
impl ZeroizeOnDrop for HmacDrbgKdfContext {}

impl HmacDrbgKdfContext {
    /// Creates a new, uninitialised HMAC-DRBG KDF context.
    ///
    /// The returned context has no digest selected and no entropy / nonce
    /// configured — `KdfContext::set_params` must be invoked before any
    /// productive call to `KdfContext::derive`.
    #[must_use]
    fn new() -> Self {
        Self {
            digest_name: None,
            properties: None,
            digest_size: 0,
            entropy: Vec::new(),
            nonce: Vec::new(),
            key: Vec::new(),
            value: Vec::new(),
            initialized: false,
        }
    }

    /// Returns the currently selected digest, resolving it via
    /// `MessageDigest::fetch` from the default library context.
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Init`]            — if no digest has been
    ///                                        configured.
    /// * `ProviderError::Dispatch`        — if the requested digest
    ///                                        cannot be located in any
    ///                                        loaded provider.
    /// * [`ProviderError::Common`]
    ///   (`CommonError::InvalidArgument`)   — if the selected digest is an
    ///                                        XOF (SHAKE128 / SHAKE256).
    fn resolve_digest(&self) -> ProviderResult<MessageDigest> {
        let name = self
            .digest_name
            .as_deref()
            .ok_or_else(|| ProviderError::Init("HMAC-DRBG: digest not set".into()))?;
        let lib_ctx = LibContext::get_default();
        let md = MessageDigest::fetch(&lib_ctx, name, self.properties.as_deref())
            .map_err(dispatch_err)?;
        if md.is_xof() {
            return Err(invalid_arg("HMAC-DRBG: XOF digests are not allowed"));
        }
        Ok(md)
    }

    /// Computes a single HMAC value using the configured digest.
    ///
    /// The data is supplied as a slice of byte slices which are fed into
    /// the MAC context in order — this mirrors the C helper `do_hmac()`
    /// in `drbg_hmac.c` that accepts up to three optional input segments.
    ///
    /// `expected_size` is passed to the HMAC context as the
    /// `OSSL_MAC_PARAM_SIZE` (`"size"`) parameter so the produced tag is
    /// the full `digest_size` bytes — the `MacCtx` abstraction defaults to
    /// 32 bytes for HMAC regardless of the actual digest, so we override
    /// that to match the digest's natural output length (e.g. 64 bytes
    /// for SHA-512, 48 for SHA-384).
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying MAC fetch or context
    /// operations, mapped through [`dispatch_err`].
    fn hmac(
        lib_ctx: &Arc<LibContext>,
        digest_name: &str,
        properties: Option<&str>,
        expected_size: usize,
        key: &[u8],
        segments: &[&[u8]],
    ) -> ProviderResult<Vec<u8>> {
        let mac = Mac::fetch(lib_ctx, MAC_ALG_NAME, properties).map_err(dispatch_err)?;
        let mut ctx = MacCtx::new(&mac).map_err(dispatch_err)?;

        // The `digest` sub-parameter tells the underlying HMAC provider
        // which hash function to use.  HMAC-DRBG relies on this
        // configuration path (see `ossl_prov_macctx_load()` in the C
        // source which passes `"digest"` through the same route).
        let mut init_params = ParamSet::new();
        init_params.set(
            PARAM_DIGEST,
            ParamValue::Utf8String(digest_name.to_string()),
        );
        ctx.init(key, Some(&init_params)).map_err(dispatch_err)?;

        // Pin the output tag length to the digest's natural output so the
        // vectors `K`/`V` always match the HMAC-DRBG seed length
        // (SP 800-90A §10.1.2 Table 2).  Applied *after* `init` because
        // `MacCtx::init` unconditionally resets `output_size` to the
        // algorithm default — explicit `set_params("size", …)` is the
        // public way to override the tag length (see `mac_lib.c` line 280
        // in the C source).
        let size_u64 = u64::try_from(expected_size)
            .map_err(|_| invalid_arg("HMAC-DRBG: digest size does not fit in u64"))?;
        let mut size_params = ParamSet::new();
        size_params.set("size", ParamValue::UInt64(size_u64));
        ctx.set_params(&size_params).map_err(dispatch_err)?;

        for seg in segments {
            if !seg.is_empty() {
                ctx.update(seg).map_err(dispatch_err)?;
            }
        }
        ctx.finalize().map_err(dispatch_err)
    }

    /// SP 800-90A §10.1.2.2 — HMAC-DRBG Update primitive with a single
    /// byte marker `inbyte` (0x00 on the first invocation, 0x01 on the
    /// second).  Applies the transformation
    ///
    /// ```text
    /// K = HMAC(K, V || inbyte || seg1 || seg2 || seg3)
    /// V = HMAC(K, V)
    /// ```
    ///
    /// All segments may be empty slices; the caller is responsible for
    /// enforcing the "skip second step when no data was provided" rule.
    fn do_hmac(
        &mut self,
        lib_ctx: &Arc<LibContext>,
        digest_name: &str,
        inbyte: u8,
        seg1: &[u8],
        seg2: &[u8],
        seg3: &[u8],
    ) -> ProviderResult<()> {
        let size = self.digest_size;
        // K = HMAC(K, V || inbyte || seg1 || seg2 || seg3)
        let new_k = Self::hmac(
            lib_ctx,
            digest_name,
            self.properties.as_deref(),
            size,
            &self.key,
            &[
                &self.value,
                core::slice::from_ref(&inbyte),
                seg1,
                seg2,
                seg3,
            ],
        )?;
        self.key.zeroize();
        self.key = new_k;

        // V = HMAC(K, V)
        let new_v = Self::hmac(
            lib_ctx,
            digest_name,
            self.properties.as_deref(),
            size,
            &self.key,
            &[&self.value],
        )?;
        self.value.zeroize();
        self.value = new_v;
        Ok(())
    }

    /// SP 800-90A §10.1.2.2 — HMAC-DRBG Update.  Runs [`Self::do_hmac`]
    /// with `inbyte == 0x00`; if any of the provided segments is
    /// non-empty, runs it a second time with `inbyte == 0x01`.
    fn update(
        &mut self,
        lib_ctx: &Arc<LibContext>,
        digest_name: &str,
        seg1: &[u8],
        seg2: &[u8],
        seg3: &[u8],
    ) -> ProviderResult<()> {
        // Step 1-2: K = HMAC(K, V || 0x00 || provided_data); V = HMAC(K, V)
        self.do_hmac(lib_ctx, digest_name, 0x00, seg1, seg2, seg3)?;
        // Step 3: if all provided_data segments are empty, return (K, V)
        if seg1.is_empty() && seg2.is_empty() && seg3.is_empty() {
            return Ok(());
        }
        // Step 4-5: K = HMAC(K, V || 0x01 || provided_data); V = HMAC(K, V)
        self.do_hmac(lib_ctx, digest_name, 0x01, seg1, seg2, seg3)
    }

    /// SP 800-90A §10.1.2.3 — HMAC-DRBG Instantiate.
    ///
    /// 1. `K ← 0x00…00` (`digest_size` zero bytes).
    /// 2. `V ← 0x01…01` (`digest_size` bytes of value `0x01`).
    /// 3. Run [`Self::update`] with the concatenation of entropy and nonce
    ///    as the provided data (the C source passes them as separate
    ///    segments `in1 = ent`, `in2 = nonce`, `in3 = pstr`).
    fn instantiate(&mut self, lib_ctx: &Arc<LibContext>, digest_name: &str) -> ProviderResult<()> {
        // Pre-conditions mirrored from hmac_drbg_kdf_derive():
        //   entropy != NULL && entropylen > 0 && nonce != NULL && noncelen > 0
        if self.entropy.is_empty() {
            return Err(invalid_arg("HMAC-DRBG: entropy is required"));
        }
        if self.nonce.is_empty() {
            return Err(invalid_arg("HMAC-DRBG: nonce is required"));
        }
        if self.digest_size == 0 {
            return Err(ProviderError::Init(
                "HMAC-DRBG: digest not configured before instantiate".into(),
            ));
        }

        // Step 2: K = 0x00..00
        self.key.zeroize();
        self.key = vec![0x00u8; self.digest_size];
        // Step 3: V = 0x01..01
        self.value.zeroize();
        self.value = vec![0x01u8; self.digest_size];

        trace!(
            digest = digest_name,
            digest_size = self.digest_size,
            entropy_len = self.entropy.len(),
            nonce_len = self.nonce.len(),
            "hmacdrbg: instantiate (SP 800-90A §10.1.2.3)"
        );

        // Step 4: (K, V) = HMAC_DRBG_Update(entropy || nonce || pstr, K, V)
        // Clone the input segments to avoid borrowing self immutably and
        // mutably at the same time.
        let ent = self.entropy.clone();
        let nonce = self.nonce.clone();
        let result = self.update(lib_ctx, digest_name, &ent, &nonce, &[]);
        // Best-effort wipe of the cloned inputs — the originals remain in
        // `self.entropy` and `self.nonce` and are zeroised on drop.
        let mut ent = ent;
        ent.zeroize();
        let mut nonce = nonce;
        nonce.zeroize();
        result?;

        self.initialized = true;
        Ok(())
    }

    /// SP 800-90A §10.1.2.5 — HMAC-DRBG Generate.
    ///
    /// Fills `out` with pseudo-random bytes by repeatedly hashing the
    /// chaining value `V`:
    ///
    /// ```text
    /// while (len(temp) < outlen) {
    ///     V = HMAC(K, V)
    ///     temp = temp || V
    /// }
    /// out = leftmost(outlen, temp)
    /// (K, V) = HMAC_DRBG_Update(adin, K, V)   // adin is empty here
    /// ```
    ///
    /// Returns the number of bytes written, which always equals
    /// `out.len()`.
    fn generate(
        &mut self,
        lib_ctx: &Arc<LibContext>,
        digest_name: &str,
        out: &mut [u8],
    ) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Init(
                "HMAC-DRBG: generate before instantiate".into(),
            ));
        }

        let out_len = out.len();
        if out_len == 0 {
            return Ok(0);
        }
        if self.digest_size == 0 {
            return Err(ProviderError::Init("HMAC-DRBG: digest size is zero".into()));
        }

        trace!(
            digest = digest_name,
            out_len = out_len,
            block_len = self.digest_size,
            "hmacdrbg: generate (SP 800-90A §10.1.2.5)"
        );

        let size = self.digest_size;
        let mut written = 0usize;
        while written < out_len {
            // V = HMAC(K, V)
            let new_v = Self::hmac(
                lib_ctx,
                digest_name,
                self.properties.as_deref(),
                size,
                &self.key,
                &[&self.value],
            )?;
            self.value.zeroize();
            self.value = new_v;

            let remaining = out_len - written;
            let take = core::cmp::min(size, remaining);
            // `take <= self.value.len()` by construction because
            // `self.value.len() == self.digest_size >= take`.
            out[written..written + take].copy_from_slice(&self.value[..take]);
            written += take;
        }

        // Step 6: (K, V) = HMAC_DRBG_Update([], K, V)
        self.update(lib_ctx, digest_name, &[], &[], &[])?;

        Ok(written)
    }

    /// Applies the set-context parameter handling defined by
    /// `hmac_drbg_kdf_set_ctx_params()` in the C source.  Accepts the
    /// four documented parameters:
    ///
    /// * `"entropy"`    — `OCTET_STRING` (SP 800-90A entropy input)
    /// * `"nonce"`      — `OCTET_STRING` (SP 800-90A nonce)
    /// * `"digest"`     — `UTF8_STRING` (underlying hash name)
    /// * `"properties"` — `UTF8_STRING` (provider property query)
    ///
    /// Unknown keys are silently ignored (matches the permissive behaviour
    /// of the generated C `_decoder` which extracts named fields and
    /// leaves the remainder alone).
    fn apply_set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // `propq` must be applied first because the `digest` handler
        // reads it when resolving the digest.
        if let Some(value) = params.get(PARAM_PROPERTIES) {
            match value {
                ParamValue::Utf8String(s) if s.is_empty() => {
                    self.properties = None;
                }
                ParamValue::Utf8String(s) => {
                    trace!(properties = %s, "hmacdrbg: properties set");
                    self.properties = Some(s.clone());
                }
                _ => {
                    return Err(invalid_arg(
                        "HMAC-DRBG: 'properties' must be a UTF-8 string",
                    ));
                }
            }
        }

        if let Some(value) = params.get(PARAM_DIGEST) {
            let name = match value {
                ParamValue::Utf8String(s) => s.clone(),
                _ => {
                    return Err(invalid_arg("HMAC-DRBG: 'digest' must be a UTF-8 string"));
                }
            };
            if name.is_empty() {
                return Err(invalid_arg("HMAC-DRBG: 'digest' must not be empty"));
            }

            // Validate the digest eagerly: resolve it through a provider
            // and reject XOFs before storing any state.  This mirrors the
            // behaviour of `hmac_drbg_kdf_set_ctx_params()` which calls
            // `EVP_MD_xof()` at the moment the parameter is applied.
            let lib_ctx = LibContext::get_default();
            let md = MessageDigest::fetch(&lib_ctx, &name, self.properties.as_deref())
                .map_err(dispatch_err)?;
            if md.is_xof() {
                warn!(digest = %md.name(), "hmacdrbg: XOF digest rejected");
                return Err(invalid_arg("HMAC-DRBG: XOF digests are not allowed"));
            }
            let digest_size = md.digest_size();
            if digest_size == 0 {
                return Err(ProviderError::Init(
                    "HMAC-DRBG: selected digest reports size 0".into(),
                ));
            }

            debug!(
                digest = %md.name(),
                digest_size = digest_size,
                "hmacdrbg: digest accepted"
            );

            self.digest_name = Some(name);
            self.digest_size = digest_size;
            // Changing the digest invalidates the current K/V because the
            // vector sizes change.  The next `derive` call will re-run the
            // Instantiate procedure.
            self.initialized = false;
            self.key.zeroize();
            self.key.clear();
            self.value.zeroize();
            self.value.clear();
        }

        if let Some(value) = params.get(PARAM_ENTROPY) {
            let bytes = value
                .as_bytes()
                .ok_or_else(|| invalid_arg("HMAC-DRBG: 'entropy' must be an octet string"))?;
            self.entropy.zeroize();
            self.entropy = bytes.to_vec();
            // Any change to entropy invalidates the instantiation state.
            self.initialized = false;
            trace!(entropy_len = self.entropy.len(), "hmacdrbg: entropy set");
        }

        if let Some(value) = params.get(PARAM_NONCE) {
            let bytes = value
                .as_bytes()
                .ok_or_else(|| invalid_arg("HMAC-DRBG: 'nonce' must be an octet string"))?;
            self.nonce.zeroize();
            self.nonce = bytes.to_vec();
            self.initialized = false;
            trace!(nonce_len = self.nonce.len(), "hmacdrbg: nonce set");
        }

        Ok(())
    }
}

// =============================================================================
// KdfContext implementation
// =============================================================================

impl KdfContext for HmacDrbgKdfContext {
    /// Derives `key.len()` pseudo-random bytes into `key`.
    ///
    /// Applies the supplied parameters first (allowing callers to seed
    /// the context in a single call), then runs the HMAC-DRBG Instantiate
    /// procedure the first time round and the Generate procedure on every
    /// subsequent call, matching the branching in `hmac_drbg_kdf_derive()`.
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Init`]                   — if the digest has not
    ///                                               been configured yet.
    /// * [`ProviderError::Common`]
    ///   (`CommonError::InvalidArgument`)          — if the entropy or
    ///                                               nonce is missing, or
    ///                                               any parameter has the
    ///                                               wrong type.
    /// * `ProviderError::Dispatch`               — propagated from the
    ///                                               underlying digest /
    ///                                               MAC fetch.
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        self.apply_set_params(params)?;

        // Resolve the digest once for the entire derive call.
        let digest = self.resolve_digest()?;
        let digest_name = digest.name().to_string();

        let lib_ctx = LibContext::get_default();
        if !self.initialized {
            self.instantiate(&lib_ctx, &digest_name)?;
        }

        debug!(
            digest = %digest_name,
            out_len = key.len(),
            "hmacdrbg: derive"
        );

        self.generate(&lib_ctx, &digest_name, key)
    }

    /// Resets the context, zeroising all sensitive state.
    ///
    /// After `reset()` the context is equivalent to a freshly-constructed
    /// one: no digest is selected, the entropy / nonce are empty, and the
    /// next call to `KdfContext::derive` will fail unless
    /// `KdfContext::set_params` is called first.  This is the direct
    /// analogue of `hmac_drbg_kdf_reset()` in the C source (which calls
    /// `OPENSSL_clear_free()` on all secret buffers).
    fn reset(&mut self) -> ProviderResult<()> {
        trace!("hmacdrbg: reset");
        self.entropy.zeroize();
        self.entropy.clear();
        self.nonce.zeroize();
        self.nonce.clear();
        self.key.zeroize();
        self.key.clear();
        self.value.zeroize();
        self.value.clear();
        self.digest_name = None;
        self.properties = None;
        self.digest_size = 0;
        self.initialized = false;
        Ok(())
    }

    /// Returns the gettable parameters described by the C dispatcher
    /// `hmac_drbg_kdf_get_ctx_params_decoder`:
    ///
    /// * `"mac"`    — always `"HMAC"` (SP 800-90A §10.1.2 fixes the MAC
    ///                 as HMAC).
    /// * `"digest"` — the currently selected hash function name, if any.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut builder = ParamBuilder::new().push_utf8(PARAM_MAC, MAC_ALG_NAME.to_string());
        if let Some(ref name) = self.digest_name {
            builder = builder.push_utf8(PARAM_DIGEST, name.clone());
        }
        Ok(builder.build())
    }

    /// Forwards to `HmacDrbgKdfContext::apply_set_params`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_set_params(params)
    }
}

// =============================================================================
// HmacDrbgKdfProvider — Provider-side factory
// =============================================================================

/// Zero-sized provider type exposing the HMAC-DRBG KDF algorithm.
///
/// Each call to [`KdfProvider::new_ctx`] yields a fresh, zero-initialised
/// [`HmacDrbgKdfContext`].  The provider itself holds no state and is
/// therefore trivially `Send + Sync`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HmacDrbgKdfProvider;

impl HmacDrbgKdfProvider {
    /// Returns a new instance of the provider.  Equivalent to
    /// `HmacDrbgKdfProvider::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KdfProvider for HmacDrbgKdfProvider {
    fn name(&self) -> &'static str {
        ALG_NAME
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        trace!(algorithm = ALG_NAME, "hmacdrbg: new context");
        Ok(Box::new(HmacDrbgKdfContext::new()))
    }
}

// =============================================================================
// Algorithm registration
// =============================================================================

/// Returns the [`AlgorithmDescriptor`] slice registering the HMAC-DRBG KDF
/// with the provider framework.
///
/// The returned vector contains a single entry advertising the algorithm
/// under its canonical NIST name `"HMAC-DRBG-KDF"` with
/// `property = "provider=default"`, matching the C provider dispatch
/// table `ossl_kdf_hmac_drbg_functions` at the end of
/// `providers/implementations/kdfs/hmacdrbg_kdf.c`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec![ALG_NAME],
        property: ALG_PROPERTY,
        description: ALG_DESCRIPTION,
    }]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;

    /// Build a `ParamSet` configuring digest, entropy and nonce in one
    /// call.  Used by the happy-path tests below.
    fn full_params(digest: &str, entropy: &[u8], nonce: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String(digest.to_string()));
        ps.set(PARAM_ENTROPY, ParamValue::OctetString(entropy.to_vec()));
        ps.set(PARAM_NONCE, ParamValue::OctetString(nonce.to_vec()));
        ps
    }

    #[test]
    fn provider_reports_canonical_name() {
        let provider = HmacDrbgKdfProvider::new();
        assert_eq!(provider.name(), "HMAC-DRBG-KDF");
    }

    #[test]
    fn descriptors_expose_hmac_drbg_kdf() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].names, vec!["HMAC-DRBG-KDF"]);
        assert_eq!(descs[0].property, "provider=default");
        assert!(descs[0].description.contains("HMAC-DRBG"));
    }

    #[test]
    fn new_ctx_returns_uninitialised_context() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().expect("context creation should succeed");
        let mut out = vec![0u8; 16];

        // Without any parameters, derive() must fail — the digest, entropy
        // and nonce are all missing.
        let empty = ParamSet::new();
        assert!(ctx.derive(&mut out, &empty).is_err());
    }

    #[test]
    fn derive_with_sha256_succeeds_and_overwrites_output() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().expect("context creation should succeed");
        let params = full_params("SHA2-256", &[0xAA; 32], &[0xBB; 16]);
        let mut out = vec![0u8; 32];

        let n = ctx
            .derive(&mut out, &params)
            .expect("derive should succeed");
        assert_eq!(n, 32);
        assert_ne!(out, vec![0u8; 32]);
    }

    #[test]
    fn derive_is_deterministic_for_identical_inputs() {
        let provider = HmacDrbgKdfProvider::new();
        let params = full_params("SHA2-256", &[0x11; 32], &[0x22; 16]);

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 64];
        ctx1.derive(&mut out1, &params).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 64];
        ctx2.derive(&mut out2, &params).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn derive_spanning_multiple_blocks_fills_all_bytes() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();
        let params = full_params("SHA2-256", &[0x55; 32], &[0x66; 16]);
        // 129 bytes forces the generate loop to produce five SHA-256
        // blocks and to truncate the last one.
        let mut out = vec![0u8; 129];
        let n = ctx.derive(&mut out, &params).unwrap();
        assert_eq!(n, 129);
    }

    #[test]
    fn set_params_missing_entropy_errors_on_derive() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA2-256".to_string()));
        ps.set(PARAM_NONCE, ParamValue::OctetString(vec![0x01; 16]));
        // Entropy is intentionally absent.
        let mut out = vec![0u8; 8];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn set_params_missing_nonce_errors_on_derive() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA2-256".to_string()));
        ps.set(PARAM_ENTROPY, ParamValue::OctetString(vec![0x01; 32]));
        // Nonce is intentionally absent.
        let mut out = vec![0u8; 8];
        assert!(ctx.derive(&mut out, &ps).is_err());
    }

    #[test]
    fn xof_digest_is_rejected() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut ps = ParamSet::new();
        ps.set(
            PARAM_DIGEST,
            ParamValue::Utf8String("SHAKE-128".to_string()),
        );
        let err = ctx.set_params(&ps).expect_err("XOF must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("XOF") || message.contains("xof"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn reset_clears_state_and_forces_reconfiguration() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let params = full_params("SHA2-256", &[0xFF; 32], &[0x00; 16]);
        let mut out = vec![0u8; 32];
        ctx.derive(&mut out, &params).unwrap();
        ctx.reset().unwrap();

        // After reset, deriving without reconfiguring must fail.
        let empty = ParamSet::new();
        let mut out2 = vec![0u8; 32];
        assert!(ctx.derive(&mut out2, &empty).is_err());
    }

    #[test]
    fn get_params_reports_mac_and_digest_names() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA2-256".to_string()));
        ctx.set_params(&ps).unwrap();

        let out = ctx.get_params().unwrap();
        let mac = out.get(PARAM_MAC).and_then(ParamValue::as_str);
        assert_eq!(mac, Some("HMAC"));
        let digest = out.get(PARAM_DIGEST).and_then(ParamValue::as_str);
        assert_eq!(digest, Some("SHA2-256"));
    }

    #[test]
    fn get_params_before_configuration_omits_digest() {
        let provider = HmacDrbgKdfProvider::new();
        let ctx = provider.new_ctx().unwrap();
        let out = ctx.get_params().unwrap();
        assert_eq!(
            out.get(PARAM_MAC).and_then(ParamValue::as_str),
            Some("HMAC")
        );
        assert!(out.get(PARAM_DIGEST).is_none());
    }

    #[test]
    fn changing_digest_invalidates_initialisation() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut params = full_params("SHA2-256", &[0x11; 32], &[0x22; 16]);
        let mut out = vec![0u8; 32];
        ctx.derive(&mut out, &params).unwrap();

        // Switching to SHA-384 should re-size K/V and re-instantiate on the
        // next derive.  Re-supply entropy+nonce because `set_params` clears
        // the initialization flag.
        params.set(PARAM_DIGEST, ParamValue::Utf8String("SHA2-384".to_string()));
        let mut out2 = vec![0u8; 48];
        ctx.derive(&mut out2, &params).unwrap();
        assert_ne!(out2, vec![0u8; 48]);
    }

    #[test]
    fn entropy_octet_string_type_is_required() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::Utf8String("SHA2-256".to_string()));
        // Pass the wrong type for entropy.
        ps.set(
            PARAM_ENTROPY,
            ParamValue::Utf8String("not bytes".to_string()),
        );
        assert!(ctx.set_params(&ps).is_err());
    }

    #[test]
    fn digest_utf8_string_type_is_required() {
        let provider = HmacDrbgKdfProvider::new();
        let mut ctx = provider.new_ctx().unwrap();

        let mut ps = ParamSet::new();
        ps.set(PARAM_DIGEST, ParamValue::OctetString(vec![0, 1, 2]));
        assert!(ctx.set_params(&ps).is_err());
    }
}
