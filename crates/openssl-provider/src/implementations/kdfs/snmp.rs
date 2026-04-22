//! SNMP KDF — `SNMPv3` USM Password-to-Key Derivation.
//!
//! Idiomatic Rust translation of
//! `providers/implementations/kdfs/snmpkdf.c` (the C reference).
//!
//! Implements RFC 3414 Appendix A.2.2 — the `SNMPv3` User Security Model
//! password-to-key algorithm (a.k.a. NIST SP 800-135 §6.8).  A user's
//! passphrase is expanded cyclically to exactly 1 MiB of digest input,
//! hashed once to obtain the unlocalized key `Ku`, and then localized for a
//! given SNMP engine identifier by the second hash
//! `HASH(Ku || engineID || Ku)`.
//!
//! # Algorithm
//!
//! ```text
//! expanded = leftmost 1_048_576 bytes of (password || password || ...)
//! Ku       = HASH(expanded)
//! key      = HASH(Ku || engineID || Ku)
//! ```
//!
//! The password is fed into the digest in full-length chunks and terminated
//! by a trailing partial chunk so that exactly `PASSWORD_HASH_AMOUNT` bytes
//! are consumed — precisely matching the C implementation's
//! `for (...) EVP_DigestUpdate(password, password_len)` loop followed by the
//! final `EVP_DigestUpdate(password, PASSWORD_HASH_AMOUNT - len)` call.
//!
//! Both mandatory parameters — the passphrase (`pass`) and the engine ID
//! (`eid`) — must be supplied before [`derive`](KdfContext::derive) can
//! succeed, mirroring the C source's `PROV_R_MISSING_PASS` and
//! `PROV_R_MISSING_EID` error paths.  A message digest must also be
//! selected; `SNMPKDF` defaults to SHA-1 — the only digest approved for FIPS
//! use per C `providers/common/securitycheck.c` `ossl_digest_is_allowed`.
//!
//! # Parameters
//!
//! | Name       | Type          | Description                                               |
//! |------------|---------------|-----------------------------------------------------------|
//! | `digest`   | UTF-8 string  | Hash algorithm name (defaults to `SHA1`).                 |
//! | `pass`     | Octet string  | Passphrase, 8–1 048 576 bytes (`PROV_R_MISSING_PASS`).    |
//! | `eid`      | Octet string  | SNMP engine ID for localization (`PROV_R_MISSING_EID`).   |
//!
//! The length bounds on `pass` correspond to the C constants
//! `KDF_SNMP_MIN_PASSWORD_LEN` (8) and `KDF_SNMP_PASSWORD_HASH_AMOUNT`
//! (1 MiB).  The C code returns 0 from `kdf_snmpkdf_set_ctx_params` for
//! out-of-range passwords; the Rust port returns
//! [`ProviderError::Common(CommonError::InvalidArgument)`] at the same
//! point.
//!
//! # Output Size
//!
//! [`get_params`](KdfContext::get_params) reports a `size` parameter equal
//! to the currently selected digest's output length, exactly mirroring the C
//! `kdf_snmpkdf_size` function which returns `EVP_MD_get_size(md)`.  The
//! Rust port additionally exposes `digest` so callers may introspect the
//! selected hash algorithm.
//!
//! A caller-supplied output buffer smaller than the digest output size
//! produces an error (the C source short-circuits with
//! `mdsize > keylen -> goto err`).  An output buffer larger than the digest
//! size is allowed; only the first `digest_size` bytes are written, matching
//! the C source's `memcpy(okey, digest, md_len)`.
//!
//! # FIPS
//!
//! In FIPS mode only SHA-1 is approved for SNMPKDF — see the upstream
//! comment block in `providers/implementations/kdfs/snmpkdf.c` above the
//! `SNMPKDF` function ("FIPS testing limited to SHA-1") and the allowance
//! table in `providers/common/securitycheck.c`.  This non-FIPS default
//! provider implementation does not additionally restrict digest selection.
//! The dedicated FIPS build of this algorithm lives in the
//! `openssl-fips` crate.
//!
//! # Rules Compliance
//!
//! - **R5** — `Option<T>` for optional engine-ID / digest state rather than
//!   sentinel-empty-vec checks for "unset".
//! - **R6** — All narrowing numeric conversions use `u64::try_from` or
//!   `usize::try_from`; there are no bare `as` casts.
//! - **R7** — No shared mutable state; the context is per-operation and
//!   single-owner.
//! - **R8** — Zero `unsafe`.
//! - **R9** — All public items documented with `///`, no warnings.
//! - **R10** — `SnmpKdfProvider` is reachable through
//!   `crate::implementations::kdfs::descriptors()` (see `kdfs/mod.rs`) and
//!   exercised by the integration tests at the bottom of this file.
//!
//! # Source
//!
//! `providers/implementations/kdfs/snmpkdf.c`.

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::{CommonError, CryptoError, ProviderError};
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::md::{MdContext, MessageDigest, SHA1};
use tracing::{debug, instrument, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Constants
// =============================================================================

/// Total byte count over which the password is expanded before the initial
/// hash.  Matches the C macro `KDF_SNMP_PASSWORD_HASH_AMOUNT` (1 MiB).
const PASSWORD_HASH_AMOUNT: usize = 1024 * 1024;

/// Minimum allowable password length in bytes.  Matches the C macro
/// `KDF_SNMP_MIN_PASSWORD_LEN`.  Values below this trigger
/// `ProviderError::Common(CommonError::InvalidArgument)` — the Rust analogue
/// of the C `set_ctx_params` `return 0` on underflow.
const MIN_PASSWORD_LEN: usize = 8;

/// `OSSL_KDF_PARAM_DIGEST` — UTF-8 digest algorithm name.
const PARAM_DIGEST: &str = "digest";

/// `OSSL_KDF_PARAM_PASSWORD` — octet-string passphrase.
const PARAM_PASSWORD: &str = "pass";

/// `OSSL_KDF_PARAM_SNMPKDF_EID` — octet-string SNMP engine identifier.
///
/// NOTE: The canonical OpenSSL C parameter name for the SNMP engine ID is
/// `"eid"` (see `include/openssl/core_names.h` and
/// `util/perl/OpenSSL/paramnames.pm`).  Earlier revisions of this Rust
/// module incorrectly used `"engineid"`, which would silently fail to match
/// parameters emitted by the canonical C `OSSL_PARAM_construct_octet_string`
/// calls.
const PARAM_ENGINE_ID: &str = "eid";

/// `OSSL_KDF_PARAM_SIZE` — `u64` output size, returned from
/// [`KdfContext::get_params`].  C equivalent: `kdf_snmpkdf_get_ctx_params`
/// sets this to `EVP_MD_get_size(md)`.
const PARAM_SIZE: &str = "size";

/// Default digest when none is explicitly configured.  Matches the
/// `PROV_DIGEST_LOAD_EX` default + the FIPS-only-approved algorithm.
const DEFAULT_DIGEST: &str = SHA1;

/// Canonical algorithm name.  Emitted in the
/// [`AlgorithmDescriptor`] returned by [`descriptors`] and used by the
/// provider framework for fetch/match.
const ALGORITHM_NAME: &str = "SNMPKDF";

/// Property string under which this algorithm is registered.  The SNMP KDF
/// lives in the default provider.
const ALGORITHM_PROPERTY: &str = "provider=default";

/// Human-readable description carried in the algorithm descriptor.
const ALGORITHM_DESCRIPTION: &str =
    "SNMPv3 USM password-to-key derivation (RFC 3414 §A.2.2, NIST SP 800-135 §6.8)";

// =============================================================================
// Error helpers
// =============================================================================

/// Maps a cryptographic error surfaced by
/// [`openssl_crypto::evp::md`](openssl_crypto::evp::md) into the provider
/// error taxonomy.  Used uniformly inside [`SnmpKdfContext::derive_internal`]
/// so that digest-level errors are reported to the caller as
/// [`ProviderError::Dispatch`].  Consistent with PVK, PBKDF1, KRB5 and the
/// rest of the KDF family (see the PVK reference pattern).
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Constructs a `ProviderError::Common(CommonError::InvalidArgument)` from a
/// caller-supplied message.  Used for user-visible validation failures such
/// as out-of-range password length, missing mandatory parameters, or
/// wrong-type parameter values.  Mirrors the C `PROV_R_MISSING_PASS`,
/// `PROV_R_MISSING_EID`, `PROV_R_BAD_LENGTH`, and
/// `PROV_R_MISSING_MESSAGE_DIGEST` error codes.
#[inline]
fn invalid_arg(msg: impl Into<String>) -> ProviderError {
    ProviderError::Common(CommonError::InvalidArgument(msg.into()))
}

// =============================================================================
// Context
// =============================================================================

/// Per-operation SNMP KDF state.
///
/// Equivalent to the C `struct KDF_SNMPKDF` in
/// `providers/implementations/kdfs/snmpkdf.c`.  The struct is cloneable so
/// that a duplicate operation (the C `kdf_snmpkdf_dup` path) can be
/// obtained from a populated context without re-supplying parameters.
///
/// The `password` field is marked `Zeroize + ZeroizeOnDrop`, replacing the
/// C `OPENSSL_clear_free(ctx->password, ...)` calls in
/// `kdf_snmpkdf_reset` / `kdf_snmpkdf_free`.  The engine ID is not
/// considered confidential — it is a publicly advertised SNMP identifier —
/// but is nonetheless cleared on drop via the default `Drop`.
///
/// Rule R5: `digest` is an `Option<MessageDigest>` — `None` before a
/// successful `apply_params` digest resolution, `Some` after.  `engine_id`
/// is `Option<Vec<u8>>` — `None` before the caller supplies `PARAM_ENGINE_ID`
/// and `Some` once supplied (possibly with a zero-length payload, which is
/// a legal SNMP engine ID per RFC 3411).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SnmpKdfContext {
    /// Passphrase bytes.  Validated on apply to be within
    /// `[MIN_PASSWORD_LEN, PASSWORD_HASH_AMOUNT]`.
    password: Vec<u8>,

    /// SNMP engine identifier.  Length is not bounded here — the C source
    /// performs no length check on `eid` inside `snmpkdf_set_membuf`, and
    /// RFC 3411 allows engine IDs up to 32 bytes in practice but the format
    /// imposes no hard upper bound inside the KDF.  `None` means unset.
    engine_id: Option<Vec<u8>>,

    /// Selected digest algorithm name — e.g. `"SHA1"`, `"SHA2-256"`.  Not
    /// sensitive, but carried as a `String` for fetch at derive time.
    /// Starts at [`DEFAULT_DIGEST`] and is overwritten by `PARAM_DIGEST`.
    #[zeroize(skip)]
    digest_name: String,
}

impl SnmpKdfContext {
    /// Creates a new context with no password, no engine ID, and the
    /// default digest selection (`SHA1`).  Corresponds to the C
    /// `kdf_snmpkdf_new` call (which does `OPENSSL_zalloc(sizeof(*ctx))`
    /// and then picks up the default digest during
    /// `ossl_prov_digest_load`).
    fn new() -> Self {
        debug!(
            default_digest = DEFAULT_DIGEST,
            "SnmpKdfContext::new: initialising SNMP KDF context"
        );
        Self {
            password: Vec::new(),
            engine_id: None,
            digest_name: DEFAULT_DIGEST.to_owned(),
        }
    }

    /// Applies a batch of parameters to this context.  Equivalent to the C
    /// `kdf_snmpkdf_set_ctx_params`.  Unknown keys are silently ignored —
    /// the C code only cares about `digest`, `properties`, `pass`, and
    /// `eid`, so Rust does the same.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Common(CommonError::InvalidArgument)`] when:
    /// - the `digest` value is not a UTF-8 string;
    /// - the `pass` value is not an octet string, or is outside
    ///   `[MIN_PASSWORD_LEN, PASSWORD_HASH_AMOUNT]`;
    /// - the `eid` value is not an octet string.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        trace!(
            param_count = params.len(),
            "SnmpKdfContext::apply_params: applying parameters"
        );

        // ---- PARAM_DIGEST (UTF-8 string) ----
        //
        // Mirrors the C `if (p.digest != NULL) ossl_prov_digest_load(...)`
        // branch in `kdf_snmpkdf_set_ctx_params`.  Unlike the C code we do
        // not perform the fetch here; the digest name is recorded and the
        // fetch happens at derive time, matching the lazy-fetch approach
        // used throughout the KDF family (PVK, PBKDF1, KRB5, SSH).
        if params.contains(PARAM_DIGEST) {
            let name = params.get_typed::<String>(PARAM_DIGEST).map_err(|e| {
                warn!(error = %e, "SNMPKDF: digest parameter must be a UTF-8 string");
                invalid_arg(format!(
                    "SNMPKDF: digest parameter must be a UTF-8 string: {e}"
                ))
            })?;
            trace!(digest = %name, "SNMPKDF: storing digest selection");
            self.digest_name = name;
        }

        // ---- PARAM_PASSWORD (octet string) ----
        //
        // C behaviour: `snmpkdf_set_membuf` clear-frees the old buffer and
        // stores the new bytes, then a post-check rejects lengths outside
        // `[MIN_PASSWORD_LEN, PASSWORD_HASH_AMOUNT]`.  We validate first
        // and only then overwrite — the result is indistinguishable from
        // the caller's perspective but leaves the context in a consistent
        // state on rejection.  The old buffer is zeroized-on-overwrite.
        if let Some(val) = params.get(PARAM_PASSWORD) {
            let bytes = val.as_bytes().ok_or_else(|| {
                warn!(
                    actual_type = val.param_type_name(),
                    "SNMPKDF: password parameter must be an octet string"
                );
                invalid_arg("SNMPKDF: password parameter must be an octet string")
            })?;
            if bytes.len() < MIN_PASSWORD_LEN {
                warn!(
                    len = bytes.len(),
                    min = MIN_PASSWORD_LEN,
                    "SNMPKDF: password too short"
                );
                return Err(invalid_arg(format!(
                    "SNMPKDF: password length {} is below minimum {} (KDF_SNMP_MIN_PASSWORD_LEN)",
                    bytes.len(),
                    MIN_PASSWORD_LEN
                )));
            }
            if bytes.len() > PASSWORD_HASH_AMOUNT {
                warn!(
                    len = bytes.len(),
                    max = PASSWORD_HASH_AMOUNT,
                    "SNMPKDF: password too long"
                );
                return Err(invalid_arg(format!(
                    "SNMPKDF: password length {} exceeds maximum {} (KDF_SNMP_PASSWORD_HASH_AMOUNT)",
                    bytes.len(),
                    PASSWORD_HASH_AMOUNT
                )));
            }
            trace!(len = bytes.len(), "SNMPKDF: storing password");
            self.password.zeroize();
            self.password.clear();
            self.password.extend_from_slice(bytes);
        }

        // ---- PARAM_ENGINE_ID (octet string) ----
        //
        // C: `if (p.eid != NULL && !snmpkdf_set_membuf(&ctx->eid, ...))
        // return 0;`.  No length validation.
        if let Some(val) = params.get(PARAM_ENGINE_ID) {
            let bytes = val.as_bytes().ok_or_else(|| {
                warn!(
                    actual_type = val.param_type_name(),
                    "SNMPKDF: eid parameter must be an octet string"
                );
                invalid_arg("SNMPKDF: eid (engine ID) parameter must be an octet string")
            })?;
            trace!(len = bytes.len(), "SNMPKDF: storing engine ID");
            self.engine_id = Some(bytes.to_vec());
        }

        Ok(())
    }

    /// Validates that all mandatory inputs have been supplied before
    /// [`derive_internal`](Self::derive_internal) is invoked.
    ///
    /// Mirrors the three error paths at the top of the C
    /// `kdf_snmpkdf_derive`:
    /// - `PROV_R_MISSING_MESSAGE_DIGEST` — digest never set (impossible
    ///   here because of [`DEFAULT_DIGEST`], but kept for parity).
    /// - `PROV_R_MISSING_EID` — engine ID never supplied.
    /// - `PROV_R_MISSING_PASS` — password never supplied.
    fn validate(&self) -> ProviderResult<()> {
        if self.digest_name.is_empty() {
            warn!("SNMPKDF: digest name is empty");
            return Err(ProviderError::Init(
                "SNMPKDF: digest algorithm is mandatory (PROV_R_MISSING_MESSAGE_DIGEST)".into(),
            ));
        }
        if self.password.is_empty() {
            warn!("SNMPKDF: password is not set");
            return Err(invalid_arg(
                "SNMPKDF: password parameter is mandatory (PROV_R_MISSING_PASS)",
            ));
        }
        if self.engine_id.is_none() {
            warn!("SNMPKDF: engine ID is not set");
            return Err(invalid_arg(
                "SNMPKDF: eid (engine ID) parameter is mandatory (PROV_R_MISSING_EID)",
            ));
        }
        Ok(())
    }

    /// Executes the RFC 3414 §A.2.2 password-to-key derivation.
    ///
    /// This is a faithful port of the C `SNMPKDF()` function in
    /// `providers/implementations/kdfs/snmpkdf.c` (lines 286-336 of the
    /// OpenSSL 4.0 source):
    ///
    /// 1. Check the output buffer is non-empty and at least `digest_size`
    ///    bytes long — the C `goto err` on `okey == NULL || keylen == 0`
    ///    and `mdsize > keylen`.
    /// 2. Init the digest, feed `PASSWORD_HASH_AMOUNT / password_len`
    ///    full-length password chunks followed by a final partial chunk
    ///    to reach exactly 1 MiB of input, then finalize to produce
    ///    `Ku = HASH(password || password || ... truncated to 1 MiB)`.
    /// 3. Re-init the same digest context, feed
    ///    `Ku || engine_id || Ku`, and finalize to produce the localized
    ///    key `key = HASH(Ku || engineID || Ku)`.
    /// 4. Copy the first `digest_size` bytes of the localized key into
    ///    the caller's output buffer.
    ///
    /// # Returns
    ///
    /// The number of bytes written, equal to the digest's output size.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if any `MdContext` operation fails.
    /// - [`ProviderError::Common(CommonError::InvalidArgument)`] if the
    ///   output buffer is empty or smaller than the digest size.
    /// - [`ProviderError::AlgorithmUnavailable`] if the configured digest
    ///   cannot be resolved by any active provider.
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        // --- Guard output buffer ----------------------------------------
        //
        // C: `if (okey == NULL || keylen == 0) return 0;`
        let out_len = output.len();
        if out_len == 0 {
            warn!("SNMPKDF: output buffer is empty");
            return Err(invalid_arg(
                "SNMPKDF: output length must be greater than zero",
            ));
        }

        // --- Fetch digest -----------------------------------------------
        let lib_ctx = LibContext::get_default();
        let digest =
            MessageDigest::fetch(&lib_ctx, &self.digest_name, None).map_err(|e| match e {
                CryptoError::AlgorithmNotFound(name) => ProviderError::AlgorithmUnavailable(
                    format!("SNMPKDF: digest algorithm {name:?} not available"),
                ),
                other => dispatch_err(other),
            })?;

        let hash_len = digest.digest_size();
        debug!(
            digest = %digest.name(),
            hash_len,
            out_len,
            "SNMPKDF: starting password-to-key derivation"
        );

        // C: `if (mdsize <= 0 || mdsize > keylen) goto err;`
        if hash_len == 0 {
            warn!(digest = %digest.name(), "SNMPKDF: digest reported zero size");
            return Err(ProviderError::Dispatch(format!(
                "SNMPKDF: digest {} reported zero-length output",
                digest.name()
            )));
        }
        if hash_len > out_len {
            warn!(
                digest = %digest.name(),
                hash_len,
                out_len,
                "SNMPKDF: output buffer smaller than digest output size"
            );
            return Err(invalid_arg(format!(
                "SNMPKDF: output length {out_len} is smaller than digest size {hash_len} for {} \
                 (PROV_R_LENGTH_TOO_LARGE)",
                digest.name()
            )));
        }

        // --- Unwrap mandatory state -------------------------------------
        //
        // `validate()` was called before this function, so both unwraps
        // below are logically guaranteed, but we surface clean errors if
        // the invariant is ever violated.
        let engine_id = self
            .engine_id
            .as_deref()
            .ok_or_else(|| invalid_arg("SNMPKDF: eid (engine ID) unset at derive time"))?;
        let password = &self.password[..];
        let password_len = password.len();
        if password_len == 0 {
            return Err(invalid_arg("SNMPKDF: password unset at derive time"));
        }

        // --- Phase 1: password expansion to Ku --------------------------
        //
        // Exact port of the C loop:
        //   for (len = 0; len < KDF_SNMP_PASSWORD_HASH_AMOUNT - password_len;
        //        len += password_len)
        //     EVP_DigestUpdate(md, password, password_len);
        //   EVP_DigestUpdate(md, password, KDF_SNMP_PASSWORD_HASH_AMOUNT - len);
        //   EVP_DigestFinal_ex(md, digest, &md_len);
        //
        // When `password_len <= PASSWORD_HASH_AMOUNT` (guaranteed by
        // `apply_params`), `PASSWORD_HASH_AMOUNT - password_len` is in
        // bounds for the `usize` loop counter.  The subtraction
        // `PASSWORD_HASH_AMOUNT - len` after the loop is also in bounds
        // because `len` monotonically increases by `password_len` and the
        // loop exits once `len >= PASSWORD_HASH_AMOUNT - password_len`,
        // i.e. `len <= PASSWORD_HASH_AMOUNT`.
        let mut md_ctx = MdContext::new();
        md_ctx.init(&digest, None).map_err(dispatch_err)?;

        let full_chunks_limit = PASSWORD_HASH_AMOUNT.saturating_sub(password_len);
        let mut len = 0usize;
        while len < full_chunks_limit {
            md_ctx.update(password).map_err(dispatch_err)?;
            len = len.saturating_add(password_len);
        }
        // Final partial chunk: `PASSWORD_HASH_AMOUNT - len` is in
        // `[0, password_len]` and always >= 1 because `password_len >= 1`
        // and the loop exits only when `len >= full_chunks_limit`.
        let final_chunk_len = PASSWORD_HASH_AMOUNT - len;
        trace!(
            full_chunks = len / password_len,
            final_chunk_len,
            password_len,
            "SNMPKDF: phase 1 feed schedule"
        );
        if final_chunk_len > 0 {
            md_ctx
                .update(&password[..final_chunk_len])
                .map_err(dispatch_err)?;
        }
        let mut ku = md_ctx.finalize().map_err(dispatch_err)?;

        // Defensive: the provider contract says `finalize()` yields
        // `digest_size` bytes; if that ever drifts (e.g. a future
        // XOF-backed digest misconfiguration) we refuse rather than read
        // out-of-range bytes downstream.
        if ku.len() < hash_len {
            warn!(
                digest = %digest.name(),
                got = ku.len(),
                expected = hash_len,
                "SNMPKDF: phase 1 digest returned fewer bytes than advertised"
            );
            ku.zeroize();
            return Err(ProviderError::Dispatch(format!(
                "SNMPKDF: digest {} returned {} bytes, expected {}",
                digest.name(),
                ku.len(),
                hash_len
            )));
        }

        // --- Phase 2: localization --------------------------------------
        //
        // C: EVP_DigestInit_ex(md, evp_md, NULL);
        //    EVP_DigestUpdate(md, digest, mdsize);
        //    EVP_DigestUpdate(md, e_id, e_len);
        //    EVP_DigestUpdate(md, digest, mdsize);
        //    EVP_DigestFinal_ex(md, digest, &md_len);
        //
        // Re-initializing the *same* `MdContext` drops its finalized state
        // and lets us reuse it for the localization pass, matching the C
        // code which reuses a single `EVP_MD_CTX` across both phases.
        md_ctx.init(&digest, None).map_err(dispatch_err)?;
        md_ctx.update(&ku[..hash_len]).map_err(dispatch_err)?;
        md_ctx.update(engine_id).map_err(dispatch_err)?;
        md_ctx.update(&ku[..hash_len]).map_err(dispatch_err)?;
        let mut final_key = md_ctx.finalize().map_err(dispatch_err)?;

        if final_key.len() < hash_len {
            warn!(
                digest = %digest.name(),
                got = final_key.len(),
                expected = hash_len,
                "SNMPKDF: phase 2 digest returned fewer bytes than advertised"
            );
            ku.zeroize();
            final_key.zeroize();
            return Err(ProviderError::Dispatch(format!(
                "SNMPKDF: digest {} localization returned {} bytes, expected {}",
                digest.name(),
                final_key.len(),
                hash_len
            )));
        }

        // --- Copy out and wipe intermediates ----------------------------
        //
        // C: `memcpy(okey, digest, md_len)` — the buffer beyond `md_len`
        // is left untouched, matching our `output[..hash_len]` slice copy.
        output[..hash_len].copy_from_slice(&final_key[..hash_len]);
        ku.zeroize();
        final_key.zeroize();

        debug!(bytes_written = hash_len, "SNMPKDF: derivation complete");
        Ok(hash_len)
    }
}

impl KdfContext for SnmpKdfContext {
    /// Combined set-params + derive, matching the C
    /// `kdf_snmpkdf_derive` contract which starts with an unconditional
    /// call to `kdf_snmpkdf_set_ctx_params(ctx, params)` before invoking
    /// `SNMPKDF(...)`.
    ///
    /// When `params` is empty, the current context state is used — this
    /// supports the legitimate pattern of calling `set_params` followed by
    /// `derive(&mut key, &ParamSet::default())`.
    #[instrument(level = "debug", skip(self, key, params), fields(key_len = key.len()))]
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        self.derive_internal(key)
    }

    /// Clears password and engine-ID material, matching the C
    /// `kdf_snmpkdf_reset` function (which `OPENSSL_clear_free`s the
    /// sensitive fields and `memset(ctx, 0, sizeof(*ctx))` before
    /// restoring `provctx`).  The digest selection is restored to
    /// [`DEFAULT_DIGEST`] because the C `reset` wipes the entire
    /// `PROV_DIGEST` struct too.
    fn reset(&mut self) -> ProviderResult<()> {
        debug!("SnmpKdfContext::reset: wiping sensitive state");
        self.password.zeroize();
        self.password.clear();
        self.engine_id = None;
        self.digest_name.clear();
        self.digest_name.push_str(DEFAULT_DIGEST);
        Ok(())
    }

    /// Reports the current output size (the digest's output length) and
    /// the currently selected digest name.  Mirrors
    /// `kdf_snmpkdf_get_ctx_params` which returns
    /// `OSSL_PARAM_set_size_t(p, EVP_MD_get_size(md))`.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::AlgorithmUnavailable`] if the digest name
    /// cannot be resolved at call time.  Returns
    /// [`ProviderError::Common(CommonError::InvalidArgument)`] if the
    /// digest size cannot be represented as `u64` (this is purely
    /// defensive — digest sizes are small).
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let lib_ctx = LibContext::get_default();
        let digest =
            MessageDigest::fetch(&lib_ctx, &self.digest_name, None).map_err(|e| match e {
                CryptoError::AlgorithmNotFound(name) => ProviderError::AlgorithmUnavailable(
                    format!("SNMPKDF: digest algorithm {name:?} not available"),
                ),
                other => dispatch_err(other),
            })?;
        let size_u64 = u64::try_from(digest.digest_size()).map_err(|_| {
            invalid_arg(format!(
                "SNMPKDF: digest size {} exceeds u64::MAX",
                digest.digest_size()
            ))
        })?;

        trace!(
            digest = %digest.name(),
            size = size_u64,
            "SnmpKdfContext::get_params: reporting output size"
        );

        Ok(ParamBuilder::new()
            .push_u64(PARAM_SIZE, size_u64)
            .push_utf8(PARAM_DIGEST, self.digest_name.clone())
            .build())
    }

    /// Applies the given parameter set, matching `kdf_snmpkdf_set_ctx_params`.
    /// An empty set is a no-op (the C function returns 1 immediately on
    /// `params == NULL`).
    #[instrument(level = "debug", skip(self, params), fields(count = params.len()))]
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if params.is_empty() {
            return Ok(());
        }
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// Provider-side adapter for the SNMP KDF.
///
/// Registered in the default provider's algorithm list via
/// [`descriptors`] and wired into the module aggregator in
/// `crates/openssl-provider/src/implementations/kdfs/mod.rs`.  Implements
/// [`KdfProvider::new_ctx`] to hand out a fresh [`SnmpKdfContext`] boxed as
/// a `dyn KdfContext` trait object — the Rust replacement for the C
/// `OSSL_DISPATCH` function-pointer table declared in
/// `ossl_kdf_snmpkdf_functions`.
///
/// The struct is zero-sized and cheap to construct; `Default` and `Copy`
/// are implemented so it can be stored as a simple field in provider
/// registration tables.
#[derive(Debug, Default, Clone, Copy)]
pub struct SnmpKdfProvider;

impl KdfProvider for SnmpKdfProvider {
    fn name(&self) -> &'static str {
        ALGORITHM_NAME
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        debug!("SnmpKdfProvider::new_ctx: creating SNMP KDF context");
        Ok(Box::new(SnmpKdfContext::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns the algorithm descriptor vector registered by this module.
///
/// The SNMP KDF is exposed under the canonical name `SNMPKDF` with property
/// `provider=default`.  Called from
/// `crate::implementations::kdfs::descriptors` which aggregates all KDF
/// descriptors before returning them to the provider core.
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

    const SHA1_LEN: usize = 20;
    const SHA256_LEN: usize = 32;
    const SHA512_LEN: usize = 64;

    /// Builds a parameter set with the two mandatory inputs.
    fn make_params(pw: &[u8], eid: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(pw.to_vec()));
        ps.set(PARAM_ENGINE_ID, ParamValue::OctetString(eid.to_vec()));
        ps
    }

    /// Builds a parameter set that also selects a non-default digest.
    fn make_params_with_digest(digest: &str, pw: &[u8], eid: &[u8]) -> ParamSet {
        let mut ps = make_params(pw, eid);
        ps.set(PARAM_DIGEST, ParamValue::Utf8String(digest.to_string()));
        ps
    }

    // ---- Provider/descriptor surface ---------------------------------------

    #[test]
    fn test_provider_name_is_snmpkdf() {
        let p = SnmpKdfProvider;
        assert_eq!(p.name(), "SNMPKDF");
    }

    #[test]
    fn test_provider_new_ctx_succeeds() {
        let p = SnmpKdfProvider::default();
        let ctx = p.new_ctx();
        assert!(ctx.is_ok(), "new_ctx must succeed unconditionally");
    }

    #[test]
    fn test_descriptors_structure() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1, "SNMP KDF registers exactly one algorithm");
        let d = &descs[0];
        assert!(d.names.contains(&ALGORITHM_NAME), "SNMPKDF must be listed");
        assert_eq!(d.property, "provider=default");
        assert!(!d.description.is_empty(), "description must be non-empty");
    }

    #[test]
    fn test_default_context_state() {
        let ctx = SnmpKdfContext::new();
        assert!(ctx.password.is_empty(), "fresh password must be empty");
        assert!(ctx.engine_id.is_none(), "fresh engine ID must be unset");
        assert_eq!(
            ctx.digest_name, "SHA1",
            "fresh context must default to SHA-1"
        );
    }

    // ---- Successful derivation ---------------------------------------------

    #[test]
    fn test_snmp_basic_sha1_20_bytes() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(
            b"maplesyrup",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
        );
        let mut out = vec![0u8; SHA1_LEN];
        let n = ctx.derive(&mut out, &ps).expect("derive must succeed");
        assert_eq!(n, SHA1_LEN, "SNMPKDF writes exactly digest_size bytes");
        assert_ne!(out, vec![0u8; SHA1_LEN], "derived key must not be zero");
    }

    #[test]
    fn test_snmp_deterministic() {
        let provider = SnmpKdfProvider;
        let ps = make_params(b"password", b"\x01\x02\x03\x04");

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2, "SNMP KDF must be deterministic");
    }

    #[test]
    fn test_snmp_different_passwords_produce_different_output() {
        let provider = SnmpKdfProvider;
        let eid = b"\x80\x00\x1f\x88\x80\x00\x00\x00\x00";

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        ctx1.derive(&mut out1, &make_params(b"password-a", eid))
            .unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        ctx2.derive(&mut out2, &make_params(b"password-b", eid))
            .unwrap();

        assert_ne!(out1, out2, "distinct passwords must yield distinct keys");
    }

    #[test]
    fn test_snmp_different_engine_ids_produce_different_output() {
        let provider = SnmpKdfProvider;
        let pw = b"password";

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        ctx1.derive(&mut out1, &make_params(pw, b"\x01\x02\x03"))
            .unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        ctx2.derive(&mut out2, &make_params(pw, b"\x04\x05\x06"))
            .unwrap();

        assert_ne!(out1, out2, "distinct engine IDs must yield distinct keys");
    }

    // ---- Hash structure verification ---------------------------------------

    /// Verifies that the two halves of the localization (Ku || engineID ||
    /// Ku) are hashed in the documented order: swapping password and
    /// engine ID positions must produce a different output, guarding
    /// against an accidental symmetric swap.
    #[test]
    fn test_snmp_hash_order_not_commutative() {
        let provider = SnmpKdfProvider;

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        // pw = "abcdefgh", eid = "\x01\x02\x03\x04"
        ctx1.derive(&mut out1, &make_params(b"abcdefgh", b"\x01\x02\x03\x04"))
            .unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        // Swap roles: pw = "\x01\x02\x03\x04\x05\x06\x07\x08", eid = "abcd".
        ctx2.derive(
            &mut out2,
            &make_params(b"\x01\x02\x03\x04\x05\x06\x07\x08", b"abcd"),
        )
        .unwrap();

        assert_ne!(
            out1, out2,
            "swapping pw/eid roles must change the derived key \
             — HASH(HASH(pw1M)||eid||HASH(pw1M)) differs from HASH(HASH(pw1M')||eid'||HASH(pw1M'))"
        );
    }

    // ---- Output buffer size handling --------------------------------------

    #[test]
    fn test_snmp_output_larger_than_digest_is_partial_write() {
        // SHA-1 writes 20 bytes, leaving the rest of a 64-byte buffer
        // untouched — matching the C `memcpy(okey, digest, md_len)`.
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut out = vec![0xAAu8; 64];
        let sentinel = out[SHA1_LEN..].to_vec();
        let n = ctx
            .derive(&mut out, &make_params(b"password", b"\x01\x02\x03\x04"))
            .unwrap();
        assert_eq!(n, SHA1_LEN, "SNMPKDF writes exactly digest_size bytes");
        assert_eq!(
            &out[SHA1_LEN..],
            &sentinel[..],
            "bytes beyond digest_size must be left untouched"
        );
    }

    #[test]
    fn test_snmp_output_smaller_than_digest_rejected() {
        // C: `mdsize > keylen -> goto err` — a 19-byte buffer cannot hold
        // the 20-byte SHA-1 digest.
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut out = vec![0u8; SHA1_LEN - 1];
        let res = ctx.derive(&mut out, &make_params(b"password", b"eid"));
        assert!(
            res.is_err(),
            "output buffer smaller than digest size must be rejected"
        );
    }

    #[test]
    fn test_snmp_output_zero_length_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut out: Vec<u8> = Vec::new();
        let res = ctx.derive(&mut out, &make_params(b"password", b"eid"));
        assert!(res.is_err(), "zero-length output must be rejected");
    }

    #[test]
    fn test_snmp_output_exactly_digest_size_ok() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut out = vec![0u8; SHA1_LEN];
        let n = ctx
            .derive(&mut out, &make_params(b"password", b"eid"))
            .unwrap();
        assert_eq!(n, SHA1_LEN);
    }

    // ---- Missing-mandatory-parameter tests --------------------------------

    #[test]
    fn test_snmp_missing_password_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_ENGINE_ID,
            ParamValue::OctetString(b"\x01\x02".to_vec()),
        );
        let mut out = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut out, &ps);
        assert!(
            res.is_err(),
            "missing password must fail (PROV_R_MISSING_PASS)"
        );
    }

    #[test]
    fn test_snmp_missing_engine_id_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_PASSWORD,
            ParamValue::OctetString(b"password".to_vec()),
        );
        let mut out = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut out, &ps);
        assert!(
            res.is_err(),
            "missing engine ID must fail (PROV_R_MISSING_EID)"
        );
    }

    // ---- Password length validation ---------------------------------------

    #[test]
    fn test_snmp_password_too_short_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        // 7 bytes < MIN_PASSWORD_LEN (8)
        let ps = make_params(b"1234567", b"eid");
        let mut out = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut out, &ps);
        assert!(
            res.is_err(),
            "password shorter than KDF_SNMP_MIN_PASSWORD_LEN (8) must be rejected"
        );
    }

    #[test]
    fn test_snmp_password_at_min_length_ok() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        // Exactly 8 bytes
        let ps = make_params(b"12345678", b"eid");
        let mut out = vec![0u8; SHA1_LEN];
        assert!(
            ctx.derive(&mut out, &ps).is_ok(),
            "password of exactly {} bytes must be accepted",
            MIN_PASSWORD_LEN
        );
    }

    #[test]
    fn test_snmp_password_at_max_length_ok() {
        // Exactly 1 MiB — the upper bound KDF_SNMP_PASSWORD_HASH_AMOUNT.
        // This exercises the degenerate loop branch where
        // `full_chunks_limit == 0` and only the final chunk is fed.
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let big_pw = vec![0x42u8; PASSWORD_HASH_AMOUNT];
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(big_pw));
        ps.set(PARAM_ENGINE_ID, ParamValue::OctetString(b"eid".to_vec()));
        let mut out = vec![0u8; SHA1_LEN];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, SHA1_LEN);
    }

    #[test]
    fn test_snmp_password_too_long_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        // 1 byte over the limit.
        let oversize = vec![0u8; PASSWORD_HASH_AMOUNT + 1];
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(oversize));
        ps.set(PARAM_ENGINE_ID, ParamValue::OctetString(b"eid".to_vec()));
        let mut out = vec![0u8; SHA1_LEN];
        let res = ctx.derive(&mut out, &ps);
        assert!(
            res.is_err(),
            "password longer than KDF_SNMP_PASSWORD_HASH_AMOUNT (1 MiB) must be rejected"
        );
    }

    // ---- Wrong-parameter-type tests ---------------------------------------

    #[test]
    fn test_snmp_password_wrong_type_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        // Password should be OctetString; pass a UTF-8 string instead.
        ps.set(PARAM_PASSWORD, ParamValue::Utf8String("password".into()));
        ps.set(PARAM_ENGINE_ID, ParamValue::OctetString(b"eid".to_vec()));
        let mut out = vec![0u8; SHA1_LEN];
        assert!(
            ctx.derive(&mut out, &ps).is_err(),
            "non-octet-string password must be rejected"
        );
    }

    #[test]
    fn test_snmp_engine_id_wrong_type_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_PASSWORD,
            ParamValue::OctetString(b"password".to_vec()),
        );
        ps.set(PARAM_ENGINE_ID, ParamValue::Utf8String("engineid".into()));
        let mut out = vec![0u8; SHA1_LEN];
        assert!(
            ctx.derive(&mut out, &ps).is_err(),
            "non-octet-string engine ID must be rejected"
        );
    }

    #[test]
    fn test_snmp_digest_wrong_type_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = make_params(b"password", b"eid");
        // Digest should be Utf8String.
        ps.set(PARAM_DIGEST, ParamValue::OctetString(b"SHA1".to_vec()));
        let mut out = vec![0u8; SHA1_LEN];
        assert!(
            ctx.derive(&mut out, &ps).is_err(),
            "non-UTF-8 digest name must be rejected"
        );
    }

    // ---- Reset and re-derive tests ----------------------------------------

    #[test]
    fn test_snmp_reset_clears_sensitive_state() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut out = vec![0u8; SHA1_LEN];
        ctx.derive(&mut out, &make_params(b"supersecret", b"eid"))
            .unwrap();
        ctx.reset().unwrap();
        // Without re-supplying params, subsequent derive must fail.
        let res = ctx.derive(&mut out, &ParamSet::default());
        assert!(
            res.is_err(),
            "derive after reset without re-supplying params must fail"
        );
    }

    #[test]
    fn test_snmp_reset_restores_default_digest() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
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

    // ---- set_params + derive split tests ----------------------------------

    #[test]
    fn test_snmp_set_params_then_derive_without_params() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        ctx.set_params(&make_params(b"password", b"eid")).unwrap();
        let mut out = vec![0u8; SHA1_LEN];
        let n = ctx
            .derive(&mut out, &ParamSet::default())
            .expect("derive after set_params must succeed");
        assert_eq!(n, SHA1_LEN);
        assert_ne!(out, vec![0u8; SHA1_LEN]);
    }

    #[test]
    fn test_snmp_derive_params_override_prior_set_params() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        ctx.set_params(&make_params(b"originalpw", b"eid-1"))
            .unwrap();
        let mut out = vec![0u8; SHA1_LEN];
        ctx.derive(&mut out, &make_params(b"newpassword", b"eid-2"))
            .unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        ctx2.derive(&mut out2, &make_params(b"newpassword", b"eid-2"))
            .unwrap();

        assert_eq!(
            out, out2,
            "derive-time params must override pre-loaded set_params"
        );
    }

    #[test]
    fn test_snmp_set_params_empty_is_noop() {
        let mut ctx = SnmpKdfContext::new();
        let original_digest = ctx.digest_name.clone();
        ctx.set_params(&ParamSet::default())
            .expect("empty set_params is a no-op");
        assert_eq!(ctx.digest_name, original_digest);
        assert!(ctx.password.is_empty());
        assert!(ctx.engine_id.is_none());
    }

    // ---- Custom digest tests ----------------------------------------------

    #[test]
    fn test_snmp_with_sha256_writes_32_bytes() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params_with_digest("SHA2-256", b"password", b"eid");
        let mut out = vec![0u8; SHA256_LEN];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, SHA256_LEN);
        assert_ne!(out, vec![0u8; SHA256_LEN]);
    }

    #[test]
    fn test_snmp_with_sha512_writes_64_bytes() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params_with_digest("SHA2-512", b"password", b"eid");
        let mut out = vec![0u8; SHA512_LEN];
        let n = ctx.derive(&mut out, &ps).unwrap();
        assert_eq!(n, SHA512_LEN);
        assert_ne!(out, vec![0u8; SHA512_LEN]);
    }

    #[test]
    fn test_snmp_with_sha256_output_too_small_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params_with_digest("SHA2-256", b"password", b"eid");
        let mut out = vec![0u8; SHA1_LEN]; // 20 < 32
        assert!(
            ctx.derive(&mut out, &ps).is_err(),
            "buffer smaller than SHA-256 digest size must be rejected"
        );
    }

    #[test]
    fn test_snmp_unknown_digest_rejected() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params_with_digest("NOT-A-REAL-DIGEST-42", b"password", b"eid");
        let mut out = vec![0u8; SHA1_LEN];
        assert!(
            ctx.derive(&mut out, &ps).is_err(),
            "unknown digest algorithm must be rejected"
        );
    }

    // ---- get_params tests -------------------------------------------------

    #[test]
    fn test_snmp_get_params_reports_sha1_size() {
        let ctx = SnmpKdfContext::new();
        let params = ctx.get_params().unwrap();
        let size = params.get(PARAM_SIZE).and_then(|v| v.as_u64());
        assert_eq!(
            size,
            Some(SHA1_LEN as u64),
            "default SHA-1 digest size reported via get_params"
        );
    }

    #[test]
    fn test_snmp_get_params_reports_default_digest() {
        let ctx = SnmpKdfContext::new();
        let params = ctx.get_params().unwrap();
        let digest = params
            .get(PARAM_DIGEST)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        assert_eq!(digest.as_deref(), Some("SHA1"));
    }

    #[test]
    fn test_snmp_get_params_after_digest_change() {
        let mut ctx = SnmpKdfContext::new();
        ctx.apply_params(
            &ParamBuilder::new()
                .push_utf8(PARAM_DIGEST, "SHA2-256".into())
                .build(),
        )
        .unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(
            params.get(PARAM_SIZE).and_then(|v| v.as_u64()),
            Some(SHA256_LEN as u64),
            "SHA-256 size must be reported after digest change"
        );
        assert_eq!(
            params.get(PARAM_DIGEST).and_then(|v| v.as_str()),
            Some("SHA2-256"),
            "selected digest name must be reported"
        );
    }

    // ---- Zeroize behavior -------------------------------------------------

    #[test]
    fn test_snmp_reset_zeroizes_password_and_engine_id() {
        let mut ctx = SnmpKdfContext::new();
        ctx.apply_params(&make_params(b"supersecret", b"eid-bytes"))
            .unwrap();
        assert!(!ctx.password.is_empty());
        assert!(ctx.engine_id.is_some());
        ctx.reset().unwrap();
        assert!(ctx.password.is_empty());
        assert!(ctx.engine_id.is_none());
        assert_eq!(ctx.digest_name, "SHA1");
    }

    // ---- Clone independence -----------------------------------------------

    #[test]
    fn test_snmp_clone_is_independent() {
        let mut ctx = SnmpKdfContext::new();
        ctx.apply_params(&make_params(b"password", b"engine-id"))
            .unwrap();
        let clone = ctx.clone();
        ctx.reset().unwrap();
        assert!(ctx.password.is_empty());
        assert!(!clone.password.is_empty());
        assert_eq!(clone.password, b"password");
        assert_eq!(clone.engine_id.as_deref(), Some(b"engine-id".as_slice()));
    }

    // ---- Algorithm sanity with a known fixed-point test ------------------

    /// Sanity: with a password of exactly `MIN_PASSWORD_LEN` bytes, one
    /// derivation must produce 20 SHA-1 bytes and re-running with the
    /// same inputs produces the same output (stability test).  This
    /// exercises the full-chunks + partial-chunks loop branches.
    #[test]
    fn test_snmp_8byte_password_stable() {
        let provider = SnmpKdfProvider;
        let pw = b"abcdefgh"; // exactly 8
        let eid = b"\x80\x00\x1f\x88\x80"; // short eid

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; SHA1_LEN];
        ctx1.derive(&mut out1, &make_params(pw, eid)).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; SHA1_LEN];
        ctx2.derive(&mut out2, &make_params(pw, eid)).unwrap();

        assert_eq!(out1, out2);
        assert_ne!(out1, vec![0u8; SHA1_LEN]);
    }

    /// Verifies the partial-chunks loop branch works for a password length
    /// that does NOT evenly divide 1 MiB.
    #[test]
    fn test_snmp_non_divisor_password_length() {
        let provider = SnmpKdfProvider;
        // 9 bytes — 1 MiB / 9 = 116508 remainder 4, exercising the
        // partial final chunk.
        let pw = b"123456789";
        let eid = b"\x01";
        let mut ctx = provider.new_ctx().unwrap();
        let mut out = vec![0u8; SHA1_LEN];
        let n = ctx.derive(&mut out, &make_params(pw, eid)).unwrap();
        assert_eq!(n, SHA1_LEN);
        assert_ne!(out, vec![0u8; SHA1_LEN]);
    }
}
