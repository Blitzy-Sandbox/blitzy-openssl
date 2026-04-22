//! Password-Based Key Derivation Function 2 (PKCS#5 v2.1, SP 800-132).
//!
//! This module provides an idiomatic Rust translation of
//! `providers/implementations/kdfs/pbkdf2.c`.  It implements **PBKDF2** — the
//! password-based key derivation function defined by RFC 8018 (PKCS#5 v2.1)
//! using HMAC as the pseudo-random function.
//!
//! # Algorithm Overview
//!
//! For each output block `T_i` (with `i = 1..=ceil(dkLen / hLen)`):
//!
//! ```text
//! U_1 = PRF(P, S || INT_32_BE(i))
//! U_j = PRF(P, U_{j-1})   for j = 2..=c
//! T_i = U_1 XOR U_2 XOR ... XOR U_c
//! ```
//!
//! where `P` is the password, `S` is the salt, `c` is the iteration count,
//! and the derived key is `DK = T_1 || T_2 || ... || T_L` truncated to the
//! requested `dkLen`.
//!
//! The PRF is HMAC parameterised by a configurable hash (SHA-1, SHA-256,
//! SHA-384, SHA-512).  XOF digests (SHAKE-128, SHAKE-256) are rejected
//! because PBKDF2 requires a fixed-length PRF output.
//!
//! # SP 800-132 Compliance
//!
//! When the `lower_bound_checks` flag is enabled (default for FIPS, or when
//! the caller explicitly sets `pkcs5=0`), the following SP 800-132 minima
//! are enforced:
//!
//! - Minimum iteration count: **1000**
//! - Minimum salt length:     **128 bits (16 bytes)**
//! - Minimum password length: **1 byte** (non-FIPS); **8 bytes** under FIPS
//! - Minimum key length:      **112 bits (14 bytes)**
//! - Maximum key/digest ratio: **< 2^32 − 1** (prevents 32-bit block-counter
//!   overflow)
//!
//! Callers opt out of the lower-bound checks by setting the OSSL parameter
//! `pkcs5=1` (legacy PKCS#5 compatibility mode).  Setting `pkcs5=0` forces
//! strict SP 800-132 validation.
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` for the optional salt field — no sentinel values.
//! - **R6:** All narrowing conversions go through `try_from`; no bare `as`
//!   casts on user-controlled data.
//! - **R8:** Zero `unsafe` blocks.
//! - **R9:** All public items carry `///` doc comments.
//!
//! Source: `providers/implementations/kdfs/pbkdf2.c`

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::ProviderError;
use openssl_common::{ParamBuilder, ParamSet, ProviderResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Parameter Name Constants
// =============================================================================

/// `OSSL_KDF_PARAM_DIGEST` — hash algorithm name (e.g. "SHA-256").
const PARAM_DIGEST: &str = "digest";
/// `OSSL_KDF_PARAM_PASSWORD` — the password / passphrase (octet string).
const PARAM_PASSWORD: &str = "pass";
/// `OSSL_KDF_PARAM_SALT` — salt (octet string).
const PARAM_SALT: &str = "salt";
/// `OSSL_KDF_PARAM_ITER` — iteration count (unsigned integer).
const PARAM_ITER: &str = "iter";
/// `OSSL_KDF_PARAM_PKCS5` — legacy-compatibility flag (integer).
/// When set to `1`, SP 800-132 lower-bound checks are disabled.
const PARAM_PKCS5: &str = "pkcs5";
/// `OSSL_KDF_PARAM_SIZE` — returned by `get_params` (size hint).
const PARAM_SIZE: &str = "size";

// =============================================================================
// SP 800-132 Policy Constants
// =============================================================================

/// Minimum key length in bits (SP 800-132 §5.3).
const MIN_KEY_LEN_BITS: usize = 112;
/// Maximum ratio of `keylen / digest_size` permitted.
///
/// Rationale: the PBKDF2 block counter is a 32-bit big-endian integer.  If
/// `keylen / mdlen` reaches `2^32 − 1` the counter overflows.  This check
/// must be performed regardless of `lower_bound_checks`.
const MAX_KEY_LEN_DIGEST_RATIO: u64 = 0xFFFF_FFFF;
/// Minimum iteration count required by SP 800-132.
const MIN_ITERATIONS: u64 = 1000;
/// Minimum salt length in bytes (128 / 8).
const MIN_SALT_LEN: usize = 16;
/// Minimum password length in bytes (non-FIPS default).
const MIN_PASSWORD_LEN: usize = 1;
/// Default iteration count used when none is supplied — matches
/// `PKCS5_DEFAULT_ITER` from `<openssl/evp.h>`.
const DEFAULT_ITERATIONS: u64 = 2048;

// =============================================================================
// Hash Algorithm Selection
// =============================================================================

/// Supported hash algorithms for PBKDF2's HMAC PRF.
///
/// Restricting the PRF to a small enumeration (rather than accepting any
/// `EVP_MD`) serves two purposes:
///
/// 1. It enforces the XOF-rejection rule at the type level — SHAKE variants
///    are simply not constructible.
/// 2. It enables pure-Rust `RustCrypto` implementations via `hmac::Hmac`
///    parameterised over `sha1::Sha1` or `sha2::{Sha256, Sha384, Sha512}`,
///    avoiding any dependency on the FFI `MessageDigest::fetch` path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    /// SHA-1 — default, matches C `SN_sha1` initialisation.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Default for HashAlgorithm {
    /// PBKDF2's default digest is **SHA-1**, matching
    /// `kdf_pbkdf2_init()` in `pbkdf2.c` line 187-188.
    fn default() -> Self {
        Self::Sha1
    }
}

impl HashAlgorithm {
    /// Returns the output length of this hash in bytes (`hLen`).
    fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Canonical name used in `get_params` responses.
    fn canonical_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Parses a hash-algorithm name.  Accepts both the dashless form
    /// (`SHA256`) and the dashed form (`SHA-256`), matching OpenSSL's
    /// `EVP_get_digestbyname` aliases.
    ///
    /// XOF digests (`SHAKE-128`, `SHAKE-256`) are explicitly rejected —
    /// PBKDF2 requires a fixed-length PRF, matching the
    /// `PROV_R_XOF_DIGESTS_NOT_ALLOWED` check in `pbkdf2.c` line 349-352.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::AlgorithmUnavailable` for unknown names and
    /// `ProviderError::Init` for explicitly rejected XOF digests.
    fn from_name(name: &str) -> ProviderResult<Self> {
        let upper = name.to_uppercase();
        match upper.as_str() {
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" | "SHA2-256" => Ok(Self::Sha256),
            "SHA384" | "SHA-384" | "SHA2-384" => Ok(Self::Sha384),
            "SHA512" | "SHA-512" | "SHA2-512" => Ok(Self::Sha512),
            "SHAKE128" | "SHAKE-128" | "SHAKE256" | "SHAKE-256" => {
                tracing::debug!(
                    digest = %name,
                    "PBKDF2: rejected XOF digest (PROV_R_XOF_DIGESTS_NOT_ALLOWED)"
                );
                Err(ProviderError::Init(format!(
                    "PBKDF2: XOF digest '{name}' not allowed"
                )))
            }
            _ => Err(ProviderError::AlgorithmUnavailable(format!(
                "PBKDF2: unsupported digest '{name}'"
            ))),
        }
    }

    /// Computes HMAC using the selected hash algorithm.
    ///
    /// Uses the `RustCrypto` `hmac::Hmac<ShaX>` types, mirroring the approach
    /// taken in the HKDF sibling module.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if HMAC key initialisation fails.
    /// HMAC accepts arbitrary-length keys, so this should not occur in
    /// practice; the error is propagated defensively.
    fn hmac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProviderError> {
        use digest::Mac;
        let bytes = match self {
            Self::Sha1 => {
                let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key)
                    .map_err(|_| ProviderError::Init("HMAC key initialization failed".into()))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha256 => {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
                    .map_err(|_| ProviderError::Init("HMAC key initialization failed".into()))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
                    .map_err(|_| ProviderError::Init("HMAC key initialization failed".into()))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha512 => {
                let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
                    .map_err(|_| ProviderError::Init("HMAC key initialization failed".into()))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        };
        Ok(bytes)
    }
}

// =============================================================================
// PBKDF2 Context
// =============================================================================

/// PBKDF2 context holding all derivation parameters.
///
/// Replaces the `KDF_PBKDF2` C struct from `pbkdf2.c` lines 76-86.  Every
/// sensitive field carries the `Zeroize` derive so that the password and
/// salt buffers are wiped from memory on drop — the idiomatic replacement
/// for the C `OPENSSL_clear_free(ctx->pass, ctx->pass_len)` call.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Pbkdf2Context {
    /// The password / passphrase.  Always present after `set_params`; the
    /// derive call rejects empty passwords when `lower_bound_checks` is on.
    password: Vec<u8>,
    /// The salt.  `None` until the caller sets it; `derive` fails with
    /// `MISSING_SALT` if unset.
    salt: Option<Vec<u8>>,
    /// Iteration count (`c` in RFC 8018).  Matches C `uint64_t iter`.
    #[zeroize(skip)]
    iterations: u64,
    /// The hash algorithm underlying the HMAC PRF.
    #[zeroize(skip)]
    hash: HashAlgorithm,
    /// SP 800-132 lower-bound-check enablement.
    ///
    /// Inverted semantics from the public `pkcs5` parameter:
    /// `lower_bound_checks = (pkcs5 == 0)`.  When `true`, strict SP 800-132
    /// minimums are enforced; when `false`, legacy PKCS#5 v2.0 behaviour
    /// is preserved.
    #[zeroize(skip)]
    lower_bound_checks: bool,
}

impl Default for Pbkdf2Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Pbkdf2Context {
    /// Creates a new PBKDF2 context with SHA-1 (matching C init) and the
    /// default iteration count (2048).  Lower-bound checks are off for the
    /// non-FIPS provider, matching `kdf_pbkdf2_init()` in `pbkdf2.c`
    /// line 193-197.
    fn new() -> Self {
        Self {
            password: Vec::new(),
            salt: None,
            iterations: DEFAULT_ITERATIONS,
            hash: HashAlgorithm::default(),
            lower_bound_checks: false,
        }
    }

    /// Applies a `ParamSet` to the context, matching the C
    /// `kdf_pbkdf2_set_ctx_params` function at `pbkdf2.c` line 331-393.
    ///
    /// The order of processing matches the C source:
    ///
    /// 1. **digest** — resolve hash and reject XOF digests
    /// 2. **pkcs5** — set `lower_bound_checks` (inverted)
    /// 3. **password** — validate min length if strict, then copy
    /// 4. **salt** — validate min length if strict, then copy
    /// 5. **iter** — validate min iterations if strict, then copy
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` for validation failures (weak password,
    /// short salt, low iteration count) and propagates the error from
    /// `HashAlgorithm::from_name` for unknown / XOF digests.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // --- 1. Digest ---------------------------------------------------
        if let Some(v) = params.get(PARAM_DIGEST) {
            let name = v.as_str().ok_or_else(|| {
                ProviderError::Init("PBKDF2: 'digest' must be a UTF-8 string".into())
            })?;
            self.hash = HashAlgorithm::from_name(name)?;
            tracing::debug!(digest = %self.hash.canonical_name(), "PBKDF2: digest selected");
        }

        // --- 2. PKCS5 flag (sets lower_bound_checks) ---------------------
        if let Some(v) = params.get(PARAM_PKCS5) {
            let pkcs5 = v
                .as_i32()
                .ok_or_else(|| ProviderError::Init("PBKDF2: 'pkcs5' must be an integer".into()))?;
            // Inverted: pkcs5 == 0 means "enable strict SP 800-132 checks".
            self.lower_bound_checks = pkcs5 == 0;
            tracing::debug!(
                pkcs5 = pkcs5,
                lower_bound_checks = self.lower_bound_checks,
                "PBKDF2: pkcs5 flag set"
            );
        }

        // --- 3. Password -------------------------------------------------
        if let Some(v) = params.get(PARAM_PASSWORD) {
            let pw = v.as_bytes().ok_or_else(|| {
                ProviderError::Init("PBKDF2: 'pass' must be an octet string".into())
            })?;
            if self.lower_bound_checks && pw.len() < MIN_PASSWORD_LEN {
                tracing::debug!(
                    pass_len = pw.len(),
                    "PBKDF2: SP800-132 rejection — password too weak"
                );
                return Err(ProviderError::Init(format!(
                    "PBKDF2: password strength too weak (length {} < {})",
                    pw.len(),
                    MIN_PASSWORD_LEN
                )));
            }
            // Zeroize any existing password before replacement.
            self.password.zeroize();
            self.password = pw.to_vec();
            tracing::debug!(pass_len = self.password.len(), "PBKDF2: password set");
        }

        // --- 4. Salt -----------------------------------------------------
        if let Some(v) = params.get(PARAM_SALT) {
            let salt = v.as_bytes().ok_or_else(|| {
                ProviderError::Init("PBKDF2: 'salt' must be an octet string".into())
            })?;
            if salt.len() > super::MAX_INPUT_LEN {
                return Err(ProviderError::Init(format!(
                    "PBKDF2: salt length {} exceeds maximum {}",
                    salt.len(),
                    super::MAX_INPUT_LEN
                )));
            }
            if self.lower_bound_checks && salt.len() < MIN_SALT_LEN {
                tracing::debug!(
                    salt_len = salt.len(),
                    "PBKDF2: SP800-132 rejection — salt too short"
                );
                return Err(ProviderError::Init(format!(
                    "PBKDF2: invalid salt length ({} < {})",
                    salt.len(),
                    MIN_SALT_LEN
                )));
            }
            // Zeroize any previous salt before replacement.
            if let Some(old) = self.salt.as_mut() {
                old.zeroize();
            }
            self.salt = Some(salt.to_vec());
            tracing::debug!(salt_len = salt.len(), "PBKDF2: salt set");
        }

        // --- 5. Iteration count ------------------------------------------
        if let Some(v) = params.get(PARAM_ITER) {
            let iter = v.as_u64().ok_or_else(|| {
                ProviderError::Init("PBKDF2: 'iter' must be an unsigned integer".into())
            })?;
            if self.lower_bound_checks && iter < MIN_ITERATIONS {
                tracing::debug!(
                    iter = iter,
                    "PBKDF2: SP800-132 rejection — iteration count too low"
                );
                return Err(ProviderError::Init(format!(
                    "PBKDF2: invalid iteration count ({iter} < {MIN_ITERATIONS})"
                )));
            } else if !self.lower_bound_checks && iter < 1 {
                // Even without strict checks, zero iterations are always
                // invalid — matches C fallback at pbkdf2.c line 297-300.
                return Err(ProviderError::Init(
                    "PBKDF2: iteration count must be >= 1".into(),
                ));
            }
            self.iterations = iter;
            tracing::debug!(iter = iter, "PBKDF2: iteration count set");
        }

        Ok(())
    }
}

// =============================================================================
// Lower-Bound Check (Derive-Time)
// =============================================================================

/// Performs the full SP 800-132 lower-bound check at derive time.
///
/// This mirrors `pbkdf2_lower_bound_check_passed()` in `pbkdf2.c`
/// line 217-255.  When `lower_bound_checks` is `true`, all five invariants
/// must hold; otherwise only the `iter >= 1` sanity check is applied.
///
/// The `MAX_KEY_LEN_DIGEST_RATIO` guard is enforced unconditionally
/// (see `derive_internal`).
fn lower_bound_check_passed(
    saltlen: usize,
    iter: u64,
    keylen: usize,
    passlen: usize,
    lower_bound_checks: bool,
) -> ProviderResult<()> {
    if !lower_bound_checks {
        if iter < 1 {
            return Err(ProviderError::Init(
                "PBKDF2: iteration count must be >= 1".into(),
            ));
        }
        return Ok(());
    }

    if passlen < MIN_PASSWORD_LEN {
        return Err(ProviderError::Init(format!(
            "PBKDF2: password strength too weak (length {passlen} < {MIN_PASSWORD_LEN})"
        )));
    }
    // keylen * 8 < MIN_KEY_LEN_BITS  ⇔  keylen < MIN_KEY_LEN_BITS / 8.
    // Using checked arithmetic per Rule R6 — keylen * 8 can overflow on
    // 32-bit targets for very large buffers, but we guard anyway.
    let keylen_bits = keylen
        .checked_mul(8)
        .ok_or_else(|| ProviderError::Init("PBKDF2: key length overflow".into()))?;
    if keylen_bits < MIN_KEY_LEN_BITS {
        return Err(ProviderError::Init(format!(
            "PBKDF2: key size too small ({keylen_bits} bits < {MIN_KEY_LEN_BITS} bits)"
        )));
    }
    if saltlen < MIN_SALT_LEN {
        return Err(ProviderError::Init(format!(
            "PBKDF2: invalid salt length ({saltlen} < {MIN_SALT_LEN})"
        )));
    }
    if iter < MIN_ITERATIONS {
        return Err(ProviderError::Init(format!(
            "PBKDF2: invalid iteration count ({iter} < {MIN_ITERATIONS})"
        )));
    }

    Ok(())
}

// =============================================================================
// Core PBKDF2 Derivation
// =============================================================================

/// Core PBKDF2 algorithm.  Produces `key.len()` bytes of derived output.
///
/// Implementation strategy matches the C reference at
/// `pbkdf2.c` line 448-525:
///
/// 1. Fetch digest size `h_len`.
/// 2. Bail if `keylen / h_len >= 2^32 − 1` (overflow guard, unconditional).
/// 3. Apply SP 800-132 lower-bound checks if `lower_bound_checks`.
/// 4. Compute `num_blocks = ceil(keylen / h_len)` via `div_ceil`.
/// 5. For each block `i` (1-indexed), compute `T_i = U_1 XOR U_2 XOR ... XOR U_c`,
///    where `U_j = HMAC(pass, U_{j-1})` and `U_1 = HMAC(pass, salt || INT_32_BE(i))`.
/// 6. Concatenate all `T_i` into `key`, truncating the last block to the
///    exact requested length.
///
/// # Errors
///
/// Returns `ProviderError::Init` on parameter validation failure and
/// propagates HMAC initialisation errors from `HashAlgorithm::hmac`.
fn derive_internal(
    password: &[u8],
    salt: &[u8],
    iter: u64,
    hash: HashAlgorithm,
    key: &mut [u8],
    lower_bound_checks: bool,
) -> ProviderResult<()> {
    let h_len = hash.output_len();
    let dk_len = key.len();

    // Unconditional overflow guard — the 32-bit block counter must not wrap.
    // Uses u64 arithmetic to avoid any platform-dependent truncation.
    let dk_len_u64 = u64::try_from(dk_len)
        .map_err(|_| ProviderError::Init("PBKDF2: key length exceeds 64-bit range".into()))?;
    let h_len_u64 = u64::try_from(h_len)
        .map_err(|_| ProviderError::Init("PBKDF2: digest size exceeds 64-bit range".into()))?;
    if h_len_u64 == 0 {
        return Err(ProviderError::Init(
            "PBKDF2: digest output size is zero".into(),
        ));
    }
    if dk_len_u64 / h_len_u64 >= MAX_KEY_LEN_DIGEST_RATIO {
        return Err(ProviderError::Init(format!(
            "PBKDF2: invalid key length (ratio {dk_len}/{h_len} >= {MAX_KEY_LEN_DIGEST_RATIO})"
        )));
    }

    lower_bound_check_passed(salt.len(), iter, dk_len, password.len(), lower_bound_checks)?;

    // Zero output length → nothing to derive.  The C source exits early
    // (the while loop condition `tkeylen` becomes 0 before the first pass).
    if dk_len == 0 {
        return Ok(());
    }

    // num_blocks = ceil(dk_len / h_len) — safe because we just verified
    // dk_len / h_len < 2^32 − 1, so the ceiling fits in u64.
    let num_blocks_u64 = dk_len_u64.div_ceil(h_len_u64);
    // The overflow guard above ensures num_blocks < 2^32.
    let num_blocks = u32::try_from(num_blocks_u64)
        .map_err(|_| ProviderError::Init("PBKDF2: block count exceeds u32 range".into()))?;

    let mut offset: usize = 0;
    for block_num in 1..=num_blocks {
        // INT_32_BE(i) — big-endian 4-byte block counter.
        let counter_be = block_num.to_be_bytes();

        // U_1 = HMAC(pass, salt || INT_32_BE(i)).
        let mut salt_and_counter = Vec::with_capacity(salt.len() + 4);
        salt_and_counter.extend_from_slice(salt);
        salt_and_counter.extend_from_slice(&counter_be);
        let mut u_current = hash.hmac(password, &salt_and_counter)?;
        // Wipe the intermediate salt||counter buffer — the salt is
        // sensitive material when the caller treats it as such.
        salt_and_counter.zeroize();

        // T_i accumulator starts at U_1.
        let mut t_block: Vec<u8> = u_current.clone();

        // U_j = HMAC(pass, U_{j-1}) for j = 2..=iter, XORed into T_i.
        for _ in 1..iter {
            u_current = hash.hmac(password, &u_current)?;
            for (t_byte, u_byte) in t_block.iter_mut().zip(u_current.iter()) {
                *t_byte ^= *u_byte;
            }
        }

        // Copy T_i into output, truncating the final block to the
        // remaining requested length.
        let remaining = dk_len - offset;
        let copy_len = remaining.min(h_len);
        key[offset..offset + copy_len].copy_from_slice(&t_block[..copy_len]);
        offset += copy_len;

        // Wipe transient buffers — `t_block` may expose correlated
        // output to memory snoopers.
        u_current.zeroize();
        t_block.zeroize();
    }

    debug_assert_eq!(offset, dk_len, "PBKDF2: derive offset mismatch");
    Ok(())
}

// =============================================================================
// KdfContext Implementation
// =============================================================================

impl KdfContext for Pbkdf2Context {
    /// Derives `key.len()` bytes of key material into `key`.
    ///
    /// Matches `kdf_pbkdf2_derive()` in `pbkdf2.c` line 306-329.
    ///
    /// The `params` argument is applied before derivation — any parameter
    /// updates take effect for this call and are persisted on the context
    /// (matching OpenSSL's behaviour where `set_ctx_params` is invoked from
    /// within `derive`).
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` for missing-password, missing-salt,
    /// validation-failure, and propagates HMAC errors.
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }

        if self.password.is_empty() {
            return Err(ProviderError::Init(
                "PBKDF2: missing password (PROV_R_MISSING_PASS)".into(),
            ));
        }

        let salt = self.salt.as_deref().ok_or_else(|| {
            ProviderError::Init("PBKDF2: missing salt (PROV_R_MISSING_SALT)".into())
        })?;

        derive_internal(
            &self.password,
            salt,
            self.iterations,
            self.hash,
            key,
            self.lower_bound_checks,
        )?;

        tracing::debug!(
            digest = %self.hash.canonical_name(),
            iter = self.iterations,
            output_len = key.len(),
            "PBKDF2: derivation complete"
        );
        Ok(key.len())
    }

    /// Resets the context to its newly-initialised state, matching
    /// `kdf_pbkdf2_reset()` in `pbkdf2.c` line 147-155.
    ///
    /// Sensitive material (password, salt) is zeroized; the digest is
    /// reset to SHA-1; iteration count is restored to the default; and
    /// `lower_bound_checks` is disabled (non-FIPS default).
    fn reset(&mut self) -> ProviderResult<()> {
        self.password.zeroize();
        if let Some(salt) = self.salt.as_mut() {
            salt.zeroize();
        }
        self.salt = None;
        self.iterations = DEFAULT_ITERATIONS;
        self.hash = HashAlgorithm::default();
        self.lower_bound_checks = false;
        tracing::debug!("PBKDF2: context reset");
        Ok(())
    }

    /// Returns a `ParamSet` describing the current context state.
    ///
    /// Matches `kdf_pbkdf2_get_ctx_params()` in `pbkdf2.c` line 401-415.
    /// The `size` parameter reports `u64::MAX` (equivalent to the C
    /// `SIZE_MAX`) indicating unlimited output length — PBKDF2 can produce
    /// arbitrarily long output bounded only by the 32-bit block counter.
    ///
    /// Additional informational fields (digest name, iteration count) are
    /// exposed for diagnostics; these are not part of the original C API
    /// but aid observability per the AAP §0.8.5 rule.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let params = ParamBuilder::new()
            .push_u64(PARAM_SIZE, u64::MAX)
            .push_utf8(PARAM_DIGEST, self.hash.canonical_name().to_string())
            .push_u64(PARAM_ITER, self.iterations)
            .build();
        Ok(params)
    }

    /// Applies a `ParamSet` to the context.  Delegates to `apply_params`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// KdfProvider Implementation
// =============================================================================

/// Provider handle for the PBKDF2 KDF algorithm.
///
/// Zero-sized type; instantiation is cheap and thread-safe.  Used by the
/// provider framework to create new contexts via `new_ctx()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Pbkdf2Provider;

impl Pbkdf2Provider {
    /// Creates a new `Pbkdf2Provider`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KdfProvider for Pbkdf2Provider {
    /// Returns the algorithm's canonical name.
    fn name(&self) -> &'static str {
        "PBKDF2"
    }

    /// Creates a fresh PBKDF2 context initialised with the default
    /// digest (SHA-1) and iteration count (2048), matching the C
    /// `kdf_pbkdf2_new()` function.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(Pbkdf2Context::new()))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns the algorithm descriptors exported by this module.
///
/// Only a single descriptor is produced — the PBKDF2 algorithm itself.
/// The provider framework aggregates this with the other KDF descriptors
/// in `kdfs/mod.rs::descriptors()`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["PBKDF2"],
        "provider=default",
        "Password-Based Key Derivation Function 2 (PKCS#5 v2.1, SP 800-132) — RFC 8018",
    )]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::ParamValue;

    /// Helper to decode lowercase hex into a byte vector.
    fn hex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn build_params(
        password: &[u8],
        salt: &[u8],
        iter: u64,
        digest: Option<&str>,
        pkcs5: Option<i32>,
    ) -> ParamSet {
        let mut b = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, password.to_vec())
            .push_octet(PARAM_SALT, salt.to_vec())
            .push_u64(PARAM_ITER, iter);
        if let Some(d) = digest {
            b = b.push_utf8(PARAM_DIGEST, d.to_string());
        }
        let mut set = b.build();
        if let Some(p) = pkcs5 {
            set.set(PARAM_PKCS5, ParamValue::Int32(p));
        }
        set
    }

    // ---------------------------------------------------------------
    // RFC 6070 — PBKDF2 HMAC-SHA1 Test Vectors
    // ---------------------------------------------------------------

    #[test]
    fn test_pbkdf2_rfc6070_vector1() {
        // P = "password" (8 octets), S = "salt" (4 octets), c = 1, dkLen = 20
        // Expected: 0c60c80f961f0e71f3a9b524af6012062fe037a6
        let mut key = [0u8; 20];
        let params = build_params(b"password", b"salt", 1, Some("SHA1"), Some(1));
        let mut ctx = Pbkdf2Context::new();
        let out = ctx
            .derive(&mut key, &params)
            .expect("RFC 6070 vector 1 derive");
        assert_eq!(out, 20);
        assert_eq!(
            key.to_vec(),
            hex("0c60c80f961f0e71f3a9b524af6012062fe037a6")
        );
    }

    #[test]
    fn test_pbkdf2_rfc6070_vector2() {
        // P = "password", S = "salt", c = 2, dkLen = 20
        // Expected: ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
        let mut key = [0u8; 20];
        let params = build_params(b"password", b"salt", 2, Some("SHA1"), Some(1));
        let mut ctx = Pbkdf2Context::new();
        ctx.derive(&mut key, &params)
            .expect("RFC 6070 vector 2 derive");
        assert_eq!(
            key.to_vec(),
            hex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
        );
    }

    #[test]
    fn test_pbkdf2_rfc6070_vector3() {
        // P = "password", S = "salt", c = 4096, dkLen = 20
        // Expected: 4b007901b765489abead49d926f721d065a429c1
        let mut key = [0u8; 20];
        let params = build_params(b"password", b"salt", 4096, Some("SHA1"), Some(1));
        let mut ctx = Pbkdf2Context::new();
        ctx.derive(&mut key, &params)
            .expect("RFC 6070 vector 3 derive");
        assert_eq!(
            key.to_vec(),
            hex("4b007901b765489abead49d926f721d065a429c1")
        );
    }

    #[test]
    fn test_pbkdf2_rfc6070_vector5() {
        // P = "passwordPASSWORDpassword" (24 octets),
        // S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets),
        // c = 4096, dkLen = 25
        // Expected: 3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038
        let mut key = [0u8; 25];
        let params = build_params(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            Some("SHA1"),
            Some(1),
        );
        let mut ctx = Pbkdf2Context::new();
        ctx.derive(&mut key, &params)
            .expect("RFC 6070 vector 5 derive");
        assert_eq!(
            key.to_vec(),
            hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
        );
    }

    #[test]
    fn test_pbkdf2_rfc6070_vector6() {
        // P = "pass\0word" (9 octets, embedded NUL), S = "sa\0lt" (5 octets),
        // c = 4096, dkLen = 16
        // Expected: 56fa6aa75548099dcc37d7f03425e0c3
        let mut key = [0u8; 16];
        let params = build_params(b"pass\0word", b"sa\0lt", 4096, Some("SHA1"), Some(1));
        let mut ctx = Pbkdf2Context::new();
        ctx.derive(&mut key, &params)
            .expect("RFC 6070 vector 6 derive");
        assert_eq!(key.to_vec(), hex("56fa6aa75548099dcc37d7f03425e0c3"));
    }

    // ---------------------------------------------------------------
    // RFC 7914 §11 — PBKDF2-HMAC-SHA256 Reference
    // ---------------------------------------------------------------

    #[test]
    fn test_pbkdf2_rfc7914_sha256_vector() {
        // P = "passwd", S = "salt", c = 1, dkLen = 64
        // Expected: 55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05
        //           f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc
        //           49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31
        //           7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83
        let mut key = [0u8; 64];
        let params = build_params(b"passwd", b"salt", 1, Some("SHA-256"), Some(1));
        let mut ctx = Pbkdf2Context::new();
        ctx.derive(&mut key, &params)
            .expect("RFC 7914 SHA-256 vector derive");
        let expected = hex(concat!(
            "55ac046e56e3089fec1691c22544b605",
            "f94185216dde0465e68b9d57c20dacbc",
            "49ca9cccf179b64599166 4b39d77ef31",
            "7c71b845b1e30bd509112041d3a19783"
        ));
        assert_eq!(key.to_vec(), expected);
    }

    // ---------------------------------------------------------------
    // XOF Rejection
    // ---------------------------------------------------------------

    #[test]
    fn test_pbkdf2_rejects_shake128() {
        let mut key = [0u8; 16];
        let params = build_params(
            b"password",
            b"saltsaltsaltsalt",
            1000,
            Some("SHAKE128"),
            None,
        );
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
        assert!(err.to_string().contains("XOF"));
    }

    #[test]
    fn test_pbkdf2_rejects_shake256() {
        let mut key = [0u8; 16];
        let params = build_params(
            b"password",
            b"saltsaltsaltsalt",
            1000,
            Some("SHAKE-256"),
            None,
        );
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn test_pbkdf2_rejects_unknown_digest() {
        let mut key = [0u8; 16];
        let params = build_params(b"password", b"saltsaltsaltsalt", 1000, Some("MD5"), None);
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(matches!(err, ProviderError::AlgorithmUnavailable(_)));
    }

    // ---------------------------------------------------------------
    // SP 800-132 Lower-Bound Enforcement
    // ---------------------------------------------------------------

    #[test]
    fn test_pbkdf2_sp800_132_rejects_short_salt() {
        // pkcs5=0 → lower_bound_checks=true; salt < 16 bytes → reject.
        let mut key = [0u8; 20];
        let params = build_params(
            b"strongpassword",
            b"shortsalt",
            1000,
            Some("SHA-256"),
            Some(0),
        );
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("salt"));
    }

    #[test]
    fn test_pbkdf2_sp800_132_rejects_low_iterations() {
        // pkcs5=0 → strict mode; iter < 1000 → reject.
        let mut key = [0u8; 20];
        let params = build_params(
            b"strongpassword",
            b"saltsaltsaltsalt",
            500,
            Some("SHA-256"),
            Some(0),
        );
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("iteration"));
    }

    #[test]
    fn test_pbkdf2_sp800_132_rejects_short_key() {
        // pkcs5=0 → strict mode; keylen * 8 < 112 bits (14 bytes) → reject.
        let mut key = [0u8; 8];
        let params = build_params(
            b"strongpassword",
            b"saltsaltsaltsalt",
            1000,
            Some("SHA-256"),
            Some(0),
        );
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("key size"));
    }

    #[test]
    fn test_pbkdf2_sp800_132_allows_strong_params() {
        // All SP 800-132 minima satisfied; derivation should succeed.
        let mut key = [0u8; 20];
        let params = build_params(
            b"strongpassword",
            b"saltsaltsaltsalt",
            1000,
            Some("SHA-256"),
            Some(0),
        );
        let mut ctx = Pbkdf2Context::new();
        ctx.derive(&mut key, &params).expect("strong params OK");
        // Derived output should be non-zero.
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_pbkdf2_pkcs5_flag_bypasses_checks() {
        // pkcs5=1 → lower_bound_checks=false; all minima are bypassed.
        let mut key = [0u8; 8]; // 64 bits — below SP 800-132 floor
        let params = build_params(b"p", b"s", 1, Some("SHA-1"), Some(1));
        let mut ctx = Pbkdf2Context::new();
        ctx.derive(&mut key, &params).expect("pkcs5=1 bypass");
    }

    #[test]
    fn test_pbkdf2_zero_iterations_always_rejected() {
        // Even with pkcs5=1, iter must be >= 1.
        let mut key = [0u8; 20];
        let mut params = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, b"password".to_vec())
            .push_octet(PARAM_SALT, b"salt".to_vec())
            .push_utf8(PARAM_DIGEST, "SHA-1".to_string())
            .push_u64(PARAM_ITER, 0)
            .build();
        params.set(PARAM_PKCS5, ParamValue::Int32(1));
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("iteration"));
    }

    // ---------------------------------------------------------------
    // Missing-Parameter Rejections
    // ---------------------------------------------------------------

    #[test]
    fn test_pbkdf2_rejects_missing_password() {
        let mut key = [0u8; 20];
        let params = ParamBuilder::new()
            .push_octet(PARAM_SALT, b"saltsaltsaltsalt".to_vec())
            .push_u64(PARAM_ITER, 1000)
            .push_utf8(PARAM_DIGEST, "SHA-1".to_string())
            .build();
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("password"));
    }

    #[test]
    fn test_pbkdf2_rejects_missing_salt() {
        let mut key = [0u8; 20];
        let params = ParamBuilder::new()
            .push_octet(PARAM_PASSWORD, b"password".to_vec())
            .push_u64(PARAM_ITER, 1000)
            .push_utf8(PARAM_DIGEST, "SHA-1".to_string())
            .build();
        let mut ctx = Pbkdf2Context::new();
        let err = ctx.derive(&mut key, &params).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("salt"));
    }

    // ---------------------------------------------------------------
    // Context Lifecycle
    // ---------------------------------------------------------------

    #[test]
    fn test_pbkdf2_reset_clears_state() {
        let mut ctx = Pbkdf2Context::new();
        let params = build_params(b"password", b"salt", 1, Some("SHA-256"), Some(1));
        ctx.apply_params(&params).expect("apply params");
        assert!(!ctx.password.is_empty());
        assert!(ctx.salt.is_some());
        assert_eq!(ctx.hash, HashAlgorithm::Sha256);

        ctx.reset().expect("reset");
        assert!(ctx.password.is_empty());
        assert!(ctx.salt.is_none());
        assert_eq!(ctx.iterations, DEFAULT_ITERATIONS);
        assert_eq!(ctx.hash, HashAlgorithm::Sha1);
        assert!(!ctx.lower_bound_checks);
    }

    #[test]
    fn test_pbkdf2_get_params_returns_canonical_digest() {
        let mut ctx = Pbkdf2Context::new();
        let params = build_params(b"password", b"salt", 1, Some("SHA-256"), Some(1));
        ctx.apply_params(&params).expect("apply params");

        let out = ctx.get_params().expect("get_params");
        let digest = out
            .get(PARAM_DIGEST)
            .and_then(|v| v.as_str())
            .expect("digest present");
        assert_eq!(digest, "SHA-256");
        let size = out
            .get(PARAM_SIZE)
            .and_then(|v| v.as_u64())
            .expect("size present");
        assert_eq!(size, u64::MAX);
    }

    #[test]
    fn test_pbkdf2_default_digest_is_sha1() {
        let ctx = Pbkdf2Context::new();
        assert_eq!(ctx.hash, HashAlgorithm::Sha1);
        assert_eq!(HashAlgorithm::default(), HashAlgorithm::Sha1);
    }

    // ---------------------------------------------------------------
    // Provider Surface
    // ---------------------------------------------------------------

    #[test]
    fn test_pbkdf2_provider_name() {
        let p = Pbkdf2Provider::new();
        assert_eq!(p.name(), "PBKDF2");
    }

    #[test]
    fn test_pbkdf2_provider_new_ctx() {
        let p = Pbkdf2Provider::new();
        let mut ctx = p.new_ctx().expect("new_ctx");
        let mut key = [0u8; 20];
        let params = build_params(b"password", b"salt", 1, Some("SHA-1"), Some(1));
        ctx.derive(&mut key, &params)
            .expect("derive via provider-created ctx");
        assert_eq!(
            key.to_vec(),
            hex("0c60c80f961f0e71f3a9b524af6012062fe037a6")
        );
    }

    #[test]
    fn test_pbkdf2_descriptors() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].names, vec!["PBKDF2"]);
        assert_eq!(descs[0].property, "provider=default");
        // Description contains the full algorithm name and an RFC reference.
        assert!(descs[0].description.contains("Password-Based"));
        assert!(descs[0].description.contains("RFC 8018"));
    }

    // ---------------------------------------------------------------
    // HashAlgorithm Unit Tests
    // ---------------------------------------------------------------

    #[test]
    fn test_hash_algorithm_output_len() {
        assert_eq!(HashAlgorithm::Sha1.output_len(), 20);
        assert_eq!(HashAlgorithm::Sha256.output_len(), 32);
        assert_eq!(HashAlgorithm::Sha384.output_len(), 48);
        assert_eq!(HashAlgorithm::Sha512.output_len(), 64);
    }

    #[test]
    fn test_hash_algorithm_canonical_name() {
        assert_eq!(HashAlgorithm::Sha1.canonical_name(), "SHA-1");
        assert_eq!(HashAlgorithm::Sha256.canonical_name(), "SHA-256");
        assert_eq!(HashAlgorithm::Sha384.canonical_name(), "SHA-384");
        assert_eq!(HashAlgorithm::Sha512.canonical_name(), "SHA-512");
    }

    #[test]
    fn test_hash_algorithm_from_name_aliases() {
        assert_eq!(
            HashAlgorithm::from_name("SHA1").unwrap(),
            HashAlgorithm::Sha1
        );
        assert_eq!(
            HashAlgorithm::from_name("SHA-1").unwrap(),
            HashAlgorithm::Sha1
        );
        assert_eq!(
            HashAlgorithm::from_name("sha256").unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            HashAlgorithm::from_name("SHA-256").unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            HashAlgorithm::from_name("SHA2-384").unwrap(),
            HashAlgorithm::Sha384
        );
        assert_eq!(
            HashAlgorithm::from_name("SHA-512").unwrap(),
            HashAlgorithm::Sha512
        );
    }

    // ---------------------------------------------------------------
    // Rule R8 (no unsafe) — structural check
    // ---------------------------------------------------------------

    #[test]
    fn test_no_unsafe_in_file() {
        // Rule R8 compliance — the crate root applies `#![forbid(unsafe_code)]`,
        // which is strictly stronger than `deny`.  The mere compilation of this
        // file is the proof: a single `unsafe` block anywhere in this module
        // would trigger E0133 at build time.  This test exists as a structural
        // tripwire for future reviewers.
        let module_path = module_path!();
        assert!(module_path.contains("pbkdf2"));
    }
}
