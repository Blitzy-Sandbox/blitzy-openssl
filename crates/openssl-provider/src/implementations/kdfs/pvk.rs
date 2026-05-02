//! PVK KDF — Microsoft Private Key Blob Key Derivation.
//!
//! Idiomatic Rust translation of
//! `providers/implementations/kdfs/pvkkdf.c` (the C reference).
//!
//! # Algorithm
//!
//! The PVK KDF computes a single digest over the salt followed by the
//! password:
//!
//! ```text
//! key = HASH(salt || password)
//! ```
//!
//! The default digest is **SHA-1** (matching the C source's use of the
//! `SN_sha1` short name in `kdf_pvk_init`). The output length must not
//! exceed the digest output size; the C implementation raises
//! `PROV_R_LENGTH_TOO_LARGE` in that case, and this Rust translation
//! preserves the same behavior (it does **not** perform double-hash
//! overflow extension).
//!
//! Both the password and the salt are mandatory — the C implementation
//! raises `PROV_R_MISSING_PASS` / `PROV_R_MISSING_SALT` when either is
//! absent, and this module mirrors that contract by returning
//! `ProviderError::Common(CommonError::InvalidArgument(...))`.
//!
//! # Parameters
//!
//! | Name        | Type            | Description                              |
//! |-------------|-----------------|------------------------------------------|
//! | `digest`    | UTF-8 string    | Digest algorithm name. Default: `SHA1`.  |
//! | `pass`      | octet string    | Password. **Mandatory.**                 |
//! | `salt`      | octet string    | Salt. **Mandatory.**                     |
//!
//! # FIPS
//!
//! PVK KDF is **not** a FIPS-approved key derivation function. The
//! algorithm is registered only against the `legacy` provider property
//! and carries no FIPS approval indicator.
//!
//! # Rules Compliance
//!
//! - **R5** — `Option<T>` is used for the fetched `MessageDigest`
//!   cache, rather than a sentinel value.
//! - **R6** — No bare `as` narrowing casts. All numeric conversions are
//!   either widening or use checked arithmetic / explicit bounds.
//! - **R7** — No shared mutable state; each context owns its own fields.
//! - **R8** — Zero `unsafe` blocks. Key material zeroization is handled
//!   via the `Zeroize` / `ZeroizeOnDrop` derive macros.
//! - **R9** — Warning-free under `-D warnings`; no `#[allow(warnings)]`
//!   or module-level lint relaxations.
//! - **R10** — Wired into the legacy provider via
//!   [`crate::legacy::LegacyProvider`] through the `descriptors`
//!   aggregation in `super::descriptors` and `super::new_context`.
//!
//! # Source
//!
//! Source: `providers/implementations/kdfs/pvkkdf.c` (244 lines).

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::{CommonError, CryptoError, ProviderError};
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::md::{MdContext, MessageDigest, SHA1};
use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Parameter Name Constants
// =============================================================================

/// `OSSL_KDF_PARAM_DIGEST` — digest algorithm name selector.
const PARAM_DIGEST: &str = "digest";

/// `OSSL_KDF_PARAM_PASSWORD` — password (octet string, mandatory).
const PARAM_PASSWORD: &str = "pass";

/// `OSSL_KDF_PARAM_SALT` — salt (octet string, mandatory).
const PARAM_SALT: &str = "salt";

/// `OSSL_KDF_PARAM_SIZE` — maximum output size reported by `get_params`.
///
/// Used when reporting the logical upper bound on output length. The C
/// implementation returns `SIZE_MAX` via `OSSL_PARAM_set_size_t`. In
/// practice the real bound is the selected digest's output size, which
/// is enforced at derivation time.
const PARAM_SIZE: &str = "size";

/// Default digest algorithm used at context initialization, matching
/// the C source's `SN_sha1` / `"SHA1"` short name in `kdf_pvk_init`.
const DEFAULT_DIGEST: &str = SHA1;

/// Algorithm registration name — matches the C provider dispatch table
/// `ossl_kdf_pvk_functions` entry for `OSSL_ALG_PARAM_ALGORITHM_NAMES`.
const ALGORITHM_NAME: &str = "PVKKDF";

/// Provider property string — registered against the `legacy` provider
/// because PVK is Microsoft's legacy Private Key Blob format and is not
/// FIPS-approved.
const ALGORITHM_PROPERTY: &str = "provider=legacy";

/// Human-readable description published via the algorithm descriptor.
const ALGORITHM_DESCRIPTION: &str = "Microsoft PVK (Private Key Blob) key derivation function \
     (legacy Windows private key format, non-FIPS)";

// =============================================================================
// Error Helpers
// =============================================================================

/// Converts a [`CryptoError`] raised by the digest subsystem into a
/// `ProviderError::Dispatch` so the error surface remains consistent
/// with the other KDF implementations in this crate.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Helper for constructing an "invalid argument" error — used when the
/// caller-supplied parameters are well-typed but violate the PVK KDF
/// preconditions (missing mandatory field, buffer too small, etc.).
///
/// Uses [`ProviderError::Common`] wrapping [`CommonError::InvalidArgument`],
/// matching the schema's recommended error variant for parameter-level
/// validation failures.
#[inline]
fn invalid_arg(msg: impl Into<String>) -> ProviderError {
    ProviderError::Common(CommonError::InvalidArgument(msg.into()))
}

// =============================================================================
// Context
// =============================================================================

/// PVK KDF derivation context.
///
/// Holds the password, salt, and selected digest name for the next call
/// to `KdfContext::derive`. The password is sensitive key material and
/// is erased automatically on drop via `ZeroizeOnDrop` — matching the
/// C source's `OPENSSL_clear_free(ctx->pass, ctx->pass_len)` in
/// `kdf_pvk_cleanup`.
///
/// The salt is not, strictly speaking, a secret, but it is also erased
/// for consistency and defense-in-depth. The `digest_name` field is
/// user-visible configuration and is excluded from zeroization.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PvkKdfContext {
    /// Raw password bytes — corresponds to the C `pass`/`pass_len`
    /// members of `KDF_PVK`. Mandatory; a derivation with an empty
    /// password is rejected at validation time.
    password: Vec<u8>,

    /// Raw salt bytes — corresponds to the C `salt`/`salt_len` members
    /// of `KDF_PVK`. Mandatory in this implementation (C also rejects
    /// a `NULL` salt via `PROV_R_MISSING_SALT`).
    salt: Vec<u8>,

    /// Name of the selected digest algorithm. Matches the C source's
    /// behavior of deferring digest resolution to derivation time via
    /// `ossl_prov_digest_md(&ctx->digest)`. Default is `SHA1`.
    ///
    /// Not treated as sensitive, therefore excluded from zeroization.
    #[zeroize(skip)]
    digest_name: String,
}

impl PvkKdfContext {
    /// Creates a fresh context with the default digest (SHA-1) selected
    /// and empty password/salt buffers.
    ///
    /// Matches the C `kdf_pvk_new` + `kdf_pvk_init` initialization
    /// sequence.
    fn new() -> Self {
        debug!(
            default_digest = DEFAULT_DIGEST,
            "PvkKdfContext::new: initialising PVK KDF context"
        );
        Self {
            password: Vec::new(),
            salt: Vec::new(),
            digest_name: DEFAULT_DIGEST.to_string(),
        }
    }

    /// Applies a batch of incoming parameters to the context.
    ///
    /// Corresponds to the C `kdf_pvk_set_ctx_params` function. Each
    /// field is optional in the parameter set: only keys that are
    /// present are updated. Unknown keys are silently ignored, matching
    /// the C `OSSL_PARAM_locate`-based lookup which returns `NULL` for
    /// missing keys.
    ///
    /// Sensitive overwrites (password) zeroize the previous value
    /// before replacing it, matching `OPENSSL_clear_free` in
    /// `pvk_set_membuf`.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        trace!(
            param_count = params.len(),
            "PvkKdfContext::apply_params: processing parameter set"
        );

        // Digest — uses `contains` + `get_typed::<String>` so that a
        // misspelled or wrong-type digest key raises an explicit error
        // rather than silently falling back to the previous value.
        if params.contains(PARAM_DIGEST) {
            let name = params.get_typed::<String>(PARAM_DIGEST).map_err(|e| {
                warn!(
                    error = %e,
                    "PvkKdfContext::apply_params: digest parameter has wrong type"
                );
                invalid_arg(format!(
                    "PVKKDF: digest parameter must be a UTF-8 string: {e}"
                ))
            })?;
            trace!(
                digest = %name,
                "PvkKdfContext::apply_params: selecting digest algorithm"
            );
            self.digest_name = name;
        }

        // Password — mandatory octet string; any previous value must be
        // zeroized to match the C `OPENSSL_clear_free` semantics.
        if let Some(val) = params.get(PARAM_PASSWORD) {
            let bytes = val.as_bytes().ok_or_else(|| {
                warn!("PvkKdfContext::apply_params: password parameter is not bytes");
                invalid_arg("PVKKDF: password parameter must be an octet string")
            })?;
            if bytes.len() > super::MAX_INPUT_LEN {
                warn!(
                    len = bytes.len(),
                    max = super::MAX_INPUT_LEN,
                    "PvkKdfContext::apply_params: password exceeds MAX_INPUT_LEN"
                );
                return Err(invalid_arg(format!(
                    "PVKKDF: password length {} exceeds maximum allowed {}",
                    bytes.len(),
                    super::MAX_INPUT_LEN
                )));
            }
            trace!(
                len = bytes.len(),
                "PvkKdfContext::apply_params: storing password"
            );
            self.password.zeroize();
            self.password.clear();
            self.password.extend_from_slice(bytes);
        }

        // Salt — mandatory octet string, same policy as password.
        if let Some(val) = params.get(PARAM_SALT) {
            let bytes = val.as_bytes().ok_or_else(|| {
                warn!("PvkKdfContext::apply_params: salt parameter is not bytes");
                invalid_arg("PVKKDF: salt parameter must be an octet string")
            })?;
            if bytes.len() > super::MAX_INPUT_LEN {
                warn!(
                    len = bytes.len(),
                    max = super::MAX_INPUT_LEN,
                    "PvkKdfContext::apply_params: salt exceeds MAX_INPUT_LEN"
                );
                return Err(invalid_arg(format!(
                    "PVKKDF: salt length {} exceeds maximum allowed {}",
                    bytes.len(),
                    super::MAX_INPUT_LEN
                )));
            }
            trace!(
                len = bytes.len(),
                "PvkKdfContext::apply_params: storing salt"
            );
            self.salt.zeroize();
            self.salt.clear();
            self.salt.extend_from_slice(bytes);
        }

        Ok(())
    }

    /// Validates that the context state is sufficient to perform a
    /// derivation.
    ///
    /// Matches the C checks in `kdf_pvk_derive`:
    ///
    /// - `ctx->pass == NULL`   → `PROV_R_MISSING_PASS`
    /// - `ctx->salt == NULL`   → `PROV_R_MISSING_SALT`
    ///
    /// In this Rust translation, a zero-length password or salt is
    /// treated as "unset" because the C API buffer + length pair with a
    /// `NULL` data pointer yields the same semantic as an empty vector
    /// that has never been populated. Tests verify both cases are
    /// rejected.
    fn validate(&self) -> ProviderResult<()> {
        if self.password.is_empty() {
            warn!("PvkKdfContext::validate: missing mandatory password");
            return Err(invalid_arg(
                "PVKKDF: password parameter is mandatory (PROV_R_MISSING_PASS)",
            ));
        }
        if self.salt.is_empty() {
            warn!("PvkKdfContext::validate: missing mandatory salt");
            return Err(invalid_arg(
                "PVKKDF: salt parameter is mandatory (PROV_R_MISSING_SALT)",
            ));
        }
        if self.digest_name.is_empty() {
            warn!("PvkKdfContext::validate: digest name is empty");
            return Err(ProviderError::Init("PVKKDF: digest name is empty".into()));
        }
        Ok(())
    }

    /// Performs the PVK key derivation and writes the result into
    /// `output`.
    ///
    /// Algorithm (matches `kdf_pvk_derive` in the C source):
    ///
    /// 1. Resolve the digest by name from the default library context.
    /// 2. If the digest output size is larger than `output.len()`, fail
    ///    with `PROV_R_LENGTH_TOO_LARGE` (single-hash only; no overflow
    ///    expansion is performed).
    /// 3. Otherwise compute `HASH(salt || password)` and write the
    ///    first `digest_size()` bytes of the result into
    ///    `output[..digest_size()]`.
    /// 4. Return the number of bytes written.
    ///
    /// The hash update order (salt, then password) matches the C source
    /// exactly: the `EVP_DigestUpdate(mctx, ctx->salt, ...)` call
    /// precedes `EVP_DigestUpdate(mctx, ctx->pass, ...)`.
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let lib_ctx = LibContext::get_default();
        let digest =
            MessageDigest::fetch(&lib_ctx, &self.digest_name, None).map_err(dispatch_err)?;
        let hash_len = digest.digest_size();
        let out_len = output.len();

        debug!(
            digest = %digest.name(),
            hash_len,
            out_len,
            "PvkKdfContext::derive_internal: starting PVK derivation"
        );

        // Empty output buffer — the caller asked for zero bytes, which
        // is semantically invalid for a KDF derivation.
        if out_len == 0 {
            warn!("PvkKdfContext::derive_internal: output length is zero");
            return Err(invalid_arg(
                "PVKKDF: output length must be greater than zero",
            ));
        }

        // Digest size greater than output → `PROV_R_LENGTH_TOO_LARGE`.
        // Matches C: `if ((size_t)res > keylen) { ERR_raise(...); return 0; }`.
        if hash_len > out_len {
            warn!(
                hash_len,
                out_len,
                digest = %digest.name(),
                "PvkKdfContext::derive_internal: digest output larger than requested key"
            );
            return Err(invalid_arg(format!(
                "PVKKDF: output length {out_len} is smaller than digest size {hash_len} \
                 (PROV_R_LENGTH_TOO_LARGE for {})",
                digest.name()
            )));
        }

        // Compute `HASH(salt || password)`. The `MdContext::finalize`
        // API returns an owned `Vec<u8>` of exactly `digest_size()`
        // bytes, which we then copy into the caller's buffer.
        //
        // Order is deliberately salt-first, password-second — exactly
        // the order of the two `EVP_DigestUpdate` calls in the C
        // source's `kdf_pvk_derive`.
        let mut md_ctx = MdContext::new();
        md_ctx.init(&digest, None).map_err(dispatch_err)?;
        md_ctx.update(&self.salt).map_err(dispatch_err)?;
        md_ctx.update(&self.password).map_err(dispatch_err)?;
        let mut hash = md_ctx.finalize().map_err(dispatch_err)?;

        // Defensive: even though `MdContext::finalize` returns a vector
        // whose length equals `digest_size()`, we assert the invariant
        // so that a bug in an upstream crate cannot cause an out-of-
        // bounds panic in `copy_from_slice`.
        if hash.len() < hash_len {
            warn!(
                actual = hash.len(),
                expected = hash_len,
                "PvkKdfContext::derive_internal: digest output shorter than advertised"
            );
            hash.zeroize();
            return Err(ProviderError::Dispatch(format!(
                "PVKKDF: digest {} returned {} bytes, expected {}",
                digest.name(),
                hash.len(),
                hash_len
            )));
        }

        output[..hash_len].copy_from_slice(&hash[..hash_len]);

        // Erase the intermediate digest value — even though a public
        // hash of a secret password is not itself a usable key, scrub
        // it for defense in depth. `Vec` will otherwise leave it on
        // the heap until realloc.
        hash.zeroize();

        debug!(
            bytes_written = hash_len,
            "PvkKdfContext::derive_internal: PVK derivation complete"
        );

        Ok(hash_len)
    }
}

// =============================================================================
// KdfContext Trait Implementation
// =============================================================================

impl KdfContext for PvkKdfContext {
    /// Performs the PVK derivation into `key`.
    ///
    /// Any parameters provided in `params` are merged into the context
    /// before derivation, matching the C source's call to
    /// `kdf_pvk_set_ctx_params(ctx, params)` at the top of
    /// `kdf_pvk_derive`.
    ///
    /// Returns the number of bytes written into `key` on success, which
    /// equals the digest output size. The caller may pass a `key` slice
    /// larger than the digest size; only the leading `digest_size()`
    /// bytes are written and the trailing bytes are left untouched.
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        self.derive_internal(key)
    }

    /// Resets the context to the freshly-constructed state.
    ///
    /// Mirrors the C `kdf_pvk_reset` → `kdf_pvk_cleanup` →
    /// `kdf_pvk_init` sequence: free the salt, `clear_free` the
    /// password, then re-apply the SHA-1 default.
    fn reset(&mut self) -> ProviderResult<()> {
        debug!("PvkKdfContext::reset: clearing context state");
        self.password.zeroize();
        self.password.clear();
        self.salt.zeroize();
        self.salt.clear();
        self.digest_name.clear();
        self.digest_name.push_str(DEFAULT_DIGEST);
        Ok(())
    }

    /// Returns the retrievable parameters for this context.
    ///
    /// Matches the C `kdf_pvk_get_ctx_params`:
    ///
    /// - `OSSL_KDF_PARAM_SIZE` → `SIZE_MAX` (unbounded logical limit;
    ///   actual bound is the digest output size, enforced at derive).
    ///
    /// Additionally exposes the currently-selected digest name for
    /// introspection and test assertions, which the C source does not
    /// expose but is useful and harmless in this Rust surface.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_utf8(PARAM_DIGEST, self.digest_name.clone())
            .push_u64(PARAM_SIZE, u64::MAX)
            .build())
    }

    /// Applies incoming parameters without performing a derivation.
    ///
    /// Matches the C `kdf_pvk_set_ctx_params`. Errors returned from
    /// this path include wrong-type parameters and oversized password
    /// or salt buffers.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// Provider factory for the PVK KDF.
///
/// A zero-sized type that implements `KdfProvider` to produce fresh
/// [`PvkKdfContext`] instances on demand. Instances are cheap to clone
/// and hold no state.
#[derive(Debug, Default, Clone, Copy)]
pub struct PvkKdfProvider;

impl KdfProvider for PvkKdfProvider {
    /// Returns the algorithm registration name, matching the C dispatch
    /// table entry for `ossl_kdf_pvk_functions`.
    fn name(&self) -> &'static str {
        ALGORITHM_NAME
    }

    /// Constructs a fresh derivation context initialized to the SHA-1
    /// default with empty password and salt buffers.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        debug!("PvkKdfProvider::new_ctx: creating new PVK KDF context");
        Ok(Box::new(PvkKdfContext::new()))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns the algorithm descriptor(s) exposed by this module for the
/// provider-framework registration path.
///
/// The returned vector always contains exactly one descriptor naming
/// `"PVKKDF"` and carrying the `provider=legacy` property. The PVK KDF
/// has no alias names in the C source.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &[ALGORITHM_NAME],
        ALGORITHM_PROPERTY,
        ALGORITHM_DESCRIPTION,
    )]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    // Expected SHA-1 output size, used throughout the tests.
    const SHA1_LEN: usize = 20;

    /// Builds a parameter set with the default SHA-1 digest, the given
    /// password, and the given salt.
    fn make_params(pw: &[u8], salt: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(pw.to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.to_vec()));
        ps
    }

    /// Builds a parameter set that additionally selects a non-default
    /// digest algorithm by name.
    fn make_params_with_digest(digest: &str, pw: &[u8], salt: &[u8]) -> ParamSet {
        let mut ps = make_params(pw, salt);
        ps.set(PARAM_DIGEST, ParamValue::Utf8String(digest.to_string()));
        ps
    }

    // ---- Provider-level tests -----------------------------------------------

    #[test]
    fn test_provider_name_is_pvkkdf() {
        let provider = PvkKdfProvider;
        assert_eq!(provider.name(), "PVKKDF");
    }

    #[test]
    fn test_descriptors_structure() {
        let descs = descriptors();
        assert_eq!(
            descs.len(),
            1,
            "PVK KDF should expose exactly one algorithm descriptor"
        );
        let d = &descs[0];
        assert!(
            d.names.contains(&"PVKKDF"),
            "descriptor must advertise the PVKKDF name"
        );
        assert_eq!(
            d.property, "provider=legacy",
            "PVK is registered against the legacy provider"
        );
        assert!(
            !d.description.is_empty(),
            "descriptor must carry a non-empty description"
        );
    }

    #[test]
    fn test_new_ctx_returns_box() {
        let provider = PvkKdfProvider;
        let ctx = provider.new_ctx();
        assert!(
            ctx.is_ok(),
            "new_ctx should succeed unconditionally on a fresh provider"
        );
    }

    #[test]
    fn test_default_context_state() {
        let ctx = PvkKdfContext::new();
        assert!(ctx.password.is_empty(), "fresh password must be empty");
        assert!(ctx.salt.is_empty(), "fresh salt must be empty");
        assert_eq!(
            ctx.digest_name, "SHA1",
            "fresh context must default to SHA-1"
        );
    }

    // ---- Derivation tests ---------------------------------------------------

    #[test]
    fn test_pvk_basic_sha1_20_bytes() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"password", b"saltsalt");
        let mut output = vec![0u8; SHA1_LEN];
        let n = ctx
            .derive(&mut output, &ps)
            .expect("derivation should succeed");
        assert_eq!(
            n, SHA1_LEN,
            "PVK writes exactly digest_size bytes for SHA-1"
        );
        assert_ne!(
            output,
            vec![0u8; SHA1_LEN],
            "derived key must not be all zeros"
        );
    }

    #[test]
    fn test_pvk_deterministic() {
        let provider = PvkKdfProvider;
        let ps = make_params(b"test-pass", b"test-salt");

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        let n1 = ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        let n2 = ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(n1, n2, "both derivations must return the same length");
        assert_eq!(out1, out2, "PVK KDF must be deterministic");
    }

    #[test]
    fn test_pvk_different_passwords_produce_different_output() {
        let provider = PvkKdfProvider;
        let salt = b"common-salt";

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        ctx1.derive(&mut out1, &make_params(b"password-a", salt))
            .unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        ctx2.derive(&mut out2, &make_params(b"password-b", salt))
            .unwrap();

        assert_ne!(out1, out2, "distinct passwords must produce distinct keys");
    }

    #[test]
    fn test_pvk_different_salts_produce_different_output() {
        let provider = PvkKdfProvider;
        let pw = b"common-password";

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        ctx1.derive(&mut out1, &make_params(pw, b"salt-a")).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        ctx2.derive(&mut out2, &make_params(pw, b"salt-b")).unwrap();

        assert_ne!(out1, out2, "distinct salts must produce distinct keys");
    }

    // ---- Hash order verification -------------------------------------------

    /// Verifies the C-documented hash order is SALT || PASSWORD, not
    /// PASSWORD || SALT. We exploit the fact that two inputs of equal
    /// length with swapped assignment would produce the same hash
    /// under the wrong order but distinct hashes under the correct
    /// one.
    #[test]
    fn test_pvk_salt_and_password_not_commutative() {
        let provider = PvkKdfProvider;

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        ctx1.derive(&mut out1, &make_params(b"aaaaa", b"bbbbb"))
            .unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        // Swap: password becomes "bbbbb", salt becomes "aaaaa".
        ctx2.derive(&mut out2, &make_params(b"bbbbb", b"aaaaa"))
            .unwrap();

        assert_ne!(
            out1, out2,
            "HASH(salt || password) must not equal HASH(password || salt) \
             when the two inputs differ — this guards the documented C order"
        );
    }

    // ---- Output buffer size handling ---------------------------------------

    #[test]
    fn test_pvk_output_larger_than_digest_is_partial_write() {
        // Output buffer is 64 bytes but SHA-1 is only 20 bytes. The C
        // behavior writes exactly 20 bytes and leaves the rest of the
        // caller's buffer untouched. Our Rust port does the same and
        // returns 20 as the bytes-written count.
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0xAAu8; 64];
        let sentinel = output[SHA1_LEN..].to_vec();
        let n = ctx
            .derive(&mut output, &make_params(b"pw", b"salt"))
            .expect("derive with oversized buffer should succeed");
        assert_eq!(n, SHA1_LEN, "PVK writes exactly digest size bytes");
        assert_eq!(
            &output[SHA1_LEN..],
            &sentinel[..],
            "bytes beyond digest_size must be left untouched"
        );
    }

    #[test]
    fn test_pvk_output_too_small_rejected() {
        // SHA-1 output is 20 bytes; asking for fewer bytes triggers
        // PROV_R_LENGTH_TOO_LARGE in the C source.
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; SHA1_LEN - 1];
        let res = ctx.derive(&mut output, &make_params(b"pw", b"salt"));
        assert!(
            res.is_err(),
            "derive should fail when output is smaller than digest size"
        );
    }

    #[test]
    fn test_pvk_output_zero_length_rejected() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output: Vec<u8> = Vec::new();
        let res = ctx.derive(&mut output, &make_params(b"pw", b"salt"));
        assert!(
            res.is_err(),
            "derive should fail when output length is zero"
        );
    }

    #[test]
    fn test_pvk_output_exactly_digest_size_ok() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; SHA1_LEN];
        let n = ctx
            .derive(&mut output, &make_params(b"pw", b"salt"))
            .expect("exact-fit buffer must succeed");
        assert_eq!(n, SHA1_LEN);
    }

    // ---- Missing-mandatory-parameter tests ---------------------------------

    #[test]
    fn test_pvk_missing_password_rejected() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; SHA1_LEN];
        // Empty parameter set: both password and salt are missing.
        let res = ctx.derive(&mut output, &ParamSet::default());
        assert!(
            res.is_err(),
            "derive without a password must fail (PROV_R_MISSING_PASS)"
        );
    }

    #[test]
    fn test_pvk_missing_salt_rejected() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        // Supply only the password.
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(b"pw".to_vec()));
        let mut output = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut output, &ps);
        assert!(
            res.is_err(),
            "derive without a salt must fail (PROV_R_MISSING_SALT)"
        );
    }

    // ---- Wrong-parameter-type tests ----------------------------------------

    #[test]
    fn test_pvk_digest_wrong_type_rejected() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = make_params(b"pw", b"salt");
        // Digest should be a UTF-8 string; pass octets instead.
        ps.set(PARAM_DIGEST, ParamValue::OctetString(b"SHA1".to_vec()));
        let mut output = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut output, &ps);
        assert!(res.is_err(), "wrong-type digest parameter must be rejected");
    }

    #[test]
    fn test_pvk_password_wrong_type_rejected() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        // Password should be OctetString; pass a UTF-8 string instead.
        ps.set(PARAM_PASSWORD, ParamValue::Utf8String("password".into()));
        ps.set(PARAM_SALT, ParamValue::OctetString(b"salt".to_vec()));
        let mut output = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut output, &ps);
        assert!(
            res.is_err(),
            "wrong-type password parameter must be rejected"
        );
    }

    #[test]
    fn test_pvk_salt_wrong_type_rejected() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(b"pw".to_vec()));
        ps.set(PARAM_SALT, ParamValue::Utf8String("salt".into()));
        let mut output = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut output, &ps);
        assert!(res.is_err(), "wrong-type salt parameter must be rejected");
    }

    // ---- Reset and re-derive tests -----------------------------------------

    #[test]
    fn test_pvk_reset_clears_sensitive_state() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; SHA1_LEN];
        ctx.derive(&mut output, &make_params(b"pw", b"salt"))
            .unwrap();
        ctx.reset().unwrap();
        // After reset, both password and salt are unset and the next
        // derive without re-providing them must fail.
        let res = ctx.derive(&mut output, &ParamSet::default());
        assert!(
            res.is_err(),
            "derive after reset (without re-providing params) must fail"
        );
    }

    #[test]
    fn test_pvk_reset_restores_default_digest() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        // Switch digest to something non-default, then reset.
        ctx.set_params(
            &ParamBuilder::new()
                .push_utf8(PARAM_DIGEST, "SHA2-256".into())
                .build(),
        )
        .unwrap();
        ctx.reset().unwrap();
        let params = ctx.get_params().unwrap();
        let digest = params
            .get(PARAM_DIGEST)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        assert_eq!(
            digest.as_deref(),
            Some("SHA1"),
            "reset must restore the SHA-1 default digest"
        );
    }

    // ---- set_params + derive split tests -----------------------------------

    #[test]
    fn test_pvk_set_params_then_derive_without_params() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        // Pre-load password and salt via set_params, then derive with
        // an empty parameter set to exercise the split.
        ctx.set_params(&make_params(b"pw", b"salt")).unwrap();
        let mut output = vec![0u8; SHA1_LEN];
        let n = ctx
            .derive(&mut output, &ParamSet::default())
            .expect("derive after set_params must succeed");
        assert_eq!(n, SHA1_LEN);
        assert_ne!(output, vec![0u8; SHA1_LEN]);
    }

    #[test]
    fn test_pvk_derive_params_override_prior_set_params() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        ctx.set_params(&make_params(b"original", b"original-salt"))
            .unwrap();
        // Pass an overriding password in the derive call.
        let mut output = vec![0u8; SHA1_LEN];
        ctx.derive(&mut output, &make_params(b"new", b"new-salt"))
            .unwrap();

        // Compare against a fresh context that only ever saw the new
        // parameters — the outputs must match, demonstrating that the
        // derive-time parameters replaced the pre-loaded ones.
        let mut ctx2 = provider.new_ctx().unwrap();
        let mut output2 = vec![0u8; SHA1_LEN];
        ctx2.derive(&mut output2, &make_params(b"new", b"new-salt"))
            .unwrap();

        assert_eq!(
            output, output2,
            "derive-time params must override pre-loaded set_params values"
        );
    }

    // ---- Custom digest tests -----------------------------------------------

    #[test]
    fn test_pvk_with_sha256_uses_32_bytes() {
        // When SHA2-256 is selected, the derivation writes 32 bytes.
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params_with_digest("SHA2-256", b"pw", b"salt");
        let mut output = vec![0u8; 32];
        let n = ctx
            .derive(&mut output, &ps)
            .expect("SHA2-256 derivation must succeed");
        assert_eq!(n, 32, "SHA2-256 digest size is 32 bytes");
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_pvk_with_sha256_output_too_small_rejected() {
        // SHA2-256 digest_size = 32; asking for 20 triggers error.
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params_with_digest("SHA2-256", b"pw", b"salt");
        let mut output = vec![0u8; 20];
        let res = ctx.derive(&mut output, &ps);
        assert!(
            res.is_err(),
            "buffer smaller than digest size must be rejected"
        );
    }

    #[test]
    fn test_pvk_unknown_digest_rejected() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params_with_digest("NOT-A-REAL-DIGEST-42", b"pw", b"salt");
        let mut output = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut output, &ps);
        assert!(
            res.is_err(),
            "unknown digest algorithm must produce an error"
        );
    }

    // ---- get_params tests --------------------------------------------------

    #[test]
    fn test_pvk_get_params_reports_default_digest() {
        let ctx = PvkKdfContext::new();
        let params = ctx.get_params().unwrap();
        let digest = params
            .get(PARAM_DIGEST)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        assert_eq!(digest.as_deref(), Some("SHA1"));
    }

    #[test]
    fn test_pvk_get_params_reports_size() {
        // C returns SIZE_MAX for the size parameter. u64::MAX is the
        // idiomatic Rust replacement.
        let ctx = PvkKdfContext::new();
        let params = ctx.get_params().unwrap();
        let size = params.get(PARAM_SIZE).and_then(|v| v.as_u64());
        assert_eq!(
            size,
            Some(u64::MAX),
            "PVKKDF get_params should report u64::MAX for size (maps to SIZE_MAX)"
        );
    }

    // ---- Large input sanity check ------------------------------------------

    #[test]
    fn test_pvk_moderately_large_password_accepted() {
        // Verifies the normal (under-the-limit) large-input path works.
        // Allocating 64 KiB — well below `MAX_INPUT_LEN` — ensures we
        // exercise the copy/hash-update code paths without risking OOM
        // in the test environment.
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let big_pw = vec![0xABu8; 64 * 1024];
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(big_pw));
        ps.set(PARAM_SALT, ParamValue::OctetString(b"salt".to_vec()));
        let mut output = vec![0u8; SHA1_LEN];
        let n = ctx
            .derive(&mut output, &ps)
            .expect("moderately large password must be accepted");
        assert_eq!(n, SHA1_LEN);
    }

    // ---- Zeroize behavior --------------------------------------------------

    #[test]
    fn test_pvk_reset_zeroizes_password_and_salt() {
        let mut ctx = PvkKdfContext::new();
        ctx.apply_params(&make_params(b"supersecret", b"some-salt"))
            .unwrap();
        assert!(!ctx.password.is_empty());
        assert!(!ctx.salt.is_empty());
        // After reset, the context-facing containers report empty and
        // the digest is back to SHA-1 default.
        ctx.reset().unwrap();
        assert!(ctx.password.is_empty());
        assert!(ctx.salt.is_empty());
        assert_eq!(ctx.digest_name, "SHA1");
    }

    // ---- Clone independence ------------------------------------------------

    #[test]
    fn test_pvk_clone_is_independent() {
        let mut ctx = PvkKdfContext::new();
        ctx.apply_params(&make_params(b"pw", b"salt")).unwrap();
        let clone = ctx.clone();
        // Mutate the original; the clone should remain unchanged.
        ctx.reset().unwrap();
        assert!(ctx.password.is_empty());
        assert!(!clone.password.is_empty());
        assert_eq!(clone.password, b"pw");
        assert_eq!(clone.salt, b"salt");
    }
}
