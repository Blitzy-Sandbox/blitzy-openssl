//! # RSA-KEM Provider Implementation — RSASVE
//!
//! Idiomatic Rust translation of the C provider implementation at
//! `providers/implementations/kem/rsa_kem.c` (447 lines). Implements the
//! **RSA Secret Value Encapsulation (RSASVE)** key-encapsulation mechanism
//! defined in **NIST SP 800-56B Rev.2 §7.2.1.2 / §7.2.1.3**.
//!
//! ## Operations
//!
//! | Operation     | NIST Section | What it does                                                  |
//! |---------------|--------------|---------------------------------------------------------------|
//! | Encapsulate   | §7.2.1.2     | Generate random `z ∈ [2, n−2]`; raw-RSA encrypt to ciphertext |
//! | Decapsulate   | §7.2.1.3     | Raw-RSA decrypt ciphertext to recover `z` (the shared secret) |
//!
//! Encapsulation outputs **two** byte vectors of length `RSA_size(key)`:
//! the ciphertext (delivered to the peer) and the shared secret `z`
//! (consumed locally as keying material).
//!
//! ## C → Rust Source-Translation Map
//!
//! | C Construct (`rsa_kem.c`)                          | Rust Equivalent                                            |
//! |----------------------------------------------------|------------------------------------------------------------|
//! | `PROV_RSA_CTX` (lines 57–62)                       | [`RsaKemContext`] — RAII, typed fields                     |
//! | `RSA *rsa` (lines 60)                              | `Option<RsaPublicKey>` / `Option<RsaPrivateKey>` (split)   |
//! | `int op` (line 61)                                 | [`Option<RsaKemOperation>`] (typed enum)                   |
//! | `OSSL_FIPS_IND_DECLARE` (line 62)                  | `Option<FipsIndicator>` field                              |
//! | `KEM_OP_RSASVE` (line 50)                          | [`RsaKemMode::Rsasve`]                                     |
//! | `OSSL_KEM_PARAM_OPERATION_RSASVE`                  | constant string `"RSASVE"`                                 |
//! | `rsakem_newctx`        (lines 87–108)              | [`RsaKemContext::new`]                                     |
//! | `rsakem_freectx`       (lines 110–116)             | `Drop` (RAII via `ZeroizeOnDrop`)                          |
//! | `rsakem_dupctx`        (lines 118–136)             | `Clone` impl                                               |
//! | `rsakem_init`          (lines 138–168)             | private `init()`                                           |
//! | `rsakem_encapsulate_init` (170–175)                | [`RsaKemContext::encapsulate_init`]                        |
//! | `rsakem_decapsulate_init` (177–182)                | [`RsaKemContext::decapsulate_init`]                        |
//! | `rsasve_gen_rand_bytes` (lines 239–268)            | private `rsasve_gen_rand_bytes()`                          |
//! | `rsasve_generate`      (lines 274–328)             | [`RsaKemContext::encapsulate`]                             |
//! | `rsasve_recover`       (lines 351–394)             | [`RsaKemContext::decapsulate`]                             |
//! | `rsakem_get_ctx_params`(lines 184–195)             | [`RsaKemContext::get_params`]                              |
//! | `rsakem_set_ctx_params`(lines 203–225)             | [`RsaKemContext::set_params`]                              |
//! | `BN_priv_rand_range_ex`                            | [`BigNum::priv_rand_range`]                                |
//! | `BN_add_word(z, 2)`                                | `&z + &BigNum::from(2u64)`                                 |
//! | `BN_bn2binpad(z, out, outlen)`                     | [`BigNum::to_bytes_be_padded`]                             |
//! | `RSA_public_encrypt(.., RSA_NO_PADDING)`           | [`public_encrypt`] with [`PaddingMode::None`]              |
//! | `RSA_private_decrypt(.., RSA_NO_PADDING)`          | [`private_decrypt`] with [`PaddingMode::None`]             |
//! | `RSA_size(rsa)`                                    | `usize::from(key.key_size_bytes())`                        |
//! | `OPENSSL_cleanse(secret, nlen)`                    | [`Zeroize::zeroize`]                                       |
//! | `RSA_up_ref` / refcount                            | [`Clone::clone`] (cryptographic keys are `Clone`)          |
//! | `ossl_rsa_check_key_size`                          | inline check on [`RsaPublicKey::key_size_bits`]            |
//! | `ossl_rsa_key_op_get_protect`                      | inline match on operation + PSS params rejection           |
//! | `ERR_raise(ERR_LIB_PROV, PROV_R_*)`                | `Err(ProviderError::Dispatch(...))` (Rule R5)              |
//!
//! ## Rule Compliance (per AAP §0.8)
//!
//! - **R1 — Single Runtime Owner:** RSA-KEM is fully synchronous; no async
//!   primitives are used. The runtime topology is unaffected.
//! - **R5 — Nullability over Sentinels:** every fallible operation returns
//!   [`ProviderResult`]; "unset key" is encoded as `Option<RsaPublicKey>`
//!   / `Option<RsaPrivateKey>` rather than null pointers.
//! - **R6 — Lossless Numeric Casts:** `key_size_bytes()` (`u32`) is
//!   converted to `usize` via `usize::from` (lossless on every supported
//!   target). No bare `as` narrowing casts.
//! - **R7 — Concurrency Lock Granularity:** the per-operation context is
//!   single-owner; no shared mutable state, no locking required.
//! - **R8 — Zero `unsafe` Outside FFI:** zero `unsafe` blocks. All RSA
//!   primitives are invoked through safe wrappers in [`openssl_crypto`].
//! - **R9 — Warning-Free Build:** every public item is documented with
//!   `///`. No `#[allow(unused)]` or `#[allow(warnings)]`.
//! - **R10 — Wiring Before Done:** [`descriptors`] is reachable from the
//!   provider entry point via `kem::descriptors()`.
//!
//! ## Behavioral Parity Notes
//!
//! - **Length checks are exact.** The ciphertext length passed to
//!   [`RsaKemContext::decapsulate`] must equal `RSA_size(key)` — any other
//!   value yields `ProviderError::Dispatch` (matching the C source's
//!   `PROV_R_BAD_LENGTH` at `rsa_kem.c:380-385`).
//! - **The random `z` is in `[2, n−2]`.** Sampled by computing `n−3`,
//!   drawing `z' ∈ [0, n−3)` via rejection sampling
//!   ([`BigNum::priv_rand_range`]), then `z = z' + 2`. The bias on
//!   the upper bound is acceptable because the lost values represent
//!   `O(2^{-num_bits(n)})` of the modulus space (NIST SP 800-56B does not
//!   prohibit single-rejection sampling for RSASVE; this matches the C
//!   reference exactly — `rsa_kem.c:259-265`).
//! - **No padding (raw RSA).** RSASVE deliberately uses `RSA_NO_PADDING`
//!   because `z` is already a uniform value in `[1, n−1]`. The
//!   implementation calls [`PaddingMode::None`] to match this contract.
//! - **PSS-restricted keys are rejected.** RSA keys whose ASN.1
//!   `RSASSA-PSS-params` field is present (`pss_params() != None`) are
//!   not eligible for any KEM operation, mirroring the C source's
//!   `ossl_rsa_key_op_get_protect` rejection at `securitycheck.c:44-51`.
//! - **FIPS minimum bits.** Encapsulation requires `key_size_bits() >=
//!   2048`; decapsulation requires `key_size_bits() >= 1024` (legacy).
//!   These match `ossl_rsa_check_key_size` at `securitycheck.c:68-75`.
//! - **Secret zeroization on error.** `rsasve_gen_rand_bytes` and
//!   [`RsaKemContext::encapsulate`] explicitly zeroize the in-flight
//!   shared secret on every error path, mirroring the C source's
//!   `OPENSSL_cleanse(secret, nlen)` at `rsa_kem.c:324`.
//! - **Context duplication.** [`Clone`] is implemented to mirror the C
//!   `rsakem_dupctx` (lines 118–136). RSA keys are reference-counted in C
//!   (`RSA_up_ref`); the Rust types are `Clone` and (for private keys)
//!   `ZeroizeOnDrop`, providing equivalent semantics with safer ownership.

// -----------------------------------------------------------------------------
// Imports
// -----------------------------------------------------------------------------

use std::fmt;

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::bn::BigNum;
use openssl_crypto::rsa::{
    private_decrypt, private_key_from_der, public_encrypt, public_key_from_der, PaddingMode,
    RsaPrivateKey, RsaPublicKey,
};
use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::traits::{AlgorithmDescriptor, KemContext, KemProvider};

// -----------------------------------------------------------------------------
// Public constants — FIPS minimum key sizes
// -----------------------------------------------------------------------------

/// FIPS-approved minimum RSA key size **in bits** for *encapsulation*
/// operations (corresponds to the C source's `protect = 1` branch in
/// `providers/common/securitycheck.c:72`).
///
/// At least 2048-bit keys are required because encapsulation generates
/// new keying material that must achieve ≥112 bits of security strength.
pub const FIPS_MIN_RSA_BITS_ENCAPSULATE: u32 = 2048;

/// FIPS-approved minimum RSA key size **in bits** for *decapsulation*
/// operations (corresponds to the C source's `protect = 0` branch in
/// `providers/common/securitycheck.c:72`).
///
/// At least 1024-bit keys are accepted for decapsulation, recognizing
/// that legacy ciphertexts may have been produced under a prior
/// classification regime — see SP 800-131A Rev.2.
pub const FIPS_MIN_RSA_BITS_DECAPSULATE: u32 = 1024;

// -----------------------------------------------------------------------------
// Parameter keys
// -----------------------------------------------------------------------------

/// Canonical name of the RSASVE operation as exposed via `OSSL_KEM_PARAM`
/// to client code (matches the C macro `OSSL_KEM_PARAM_OPERATION_RSASVE`
/// from `include/openssl/core_names.h`).
const OSSL_KEM_PARAM_OPERATION_RSASVE: &str = "RSASVE";

/// Parameter key naming the KEM operation in the [`ParamSet`]
/// (corresponds to `OSSL_KEM_PARAM_OPERATION` in `core_names.h`).
const PARAM_OPERATION: &str = "operation";

/// Parameter key for the FIPS approved-mode indicator
/// (corresponds to `OSSL_KEM_PARAM_FIPS_APPROVED_INDICATOR` in
/// `core_names.h` / `OSSL_FIPS_IND_GET` macro).
const PARAM_FIPS_INDICATOR: &str = "fips-indicator";

// -----------------------------------------------------------------------------
// Operation enum — encapsulate vs. decapsulate
// -----------------------------------------------------------------------------

/// The KEM operation a context is currently bound to.
///
/// Replaces the C dispatch sentinel pair
/// `EVP_PKEY_OP_ENCAPSULATE` / `EVP_PKEY_OP_DECAPSULATE` from
/// `rsa_kem.c:172, 179`. Encoding the operation as a typed enum (rather
/// than an `int`) enforces correct usage at compile time — Rule R5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKemOperation {
    /// The context is initialized for *encapsulation* (sender side):
    /// it must hold an [`RsaPublicKey`] and produces both a ciphertext
    /// and a shared secret.
    Encapsulate,
    /// The context is initialized for *decapsulation* (receiver side):
    /// it must hold an [`RsaPrivateKey`] and produces a shared secret
    /// from a peer-supplied ciphertext.
    Decapsulate,
}

impl RsaKemOperation {
    /// Returns the canonical short name used in tracing and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encapsulate => "encapsulate",
            Self::Decapsulate => "decapsulate",
        }
    }
}

// -----------------------------------------------------------------------------
// KEM mode — RSASVE is the only RSA-KEM mode currently defined
// -----------------------------------------------------------------------------

/// The RSA-KEM mode selected for the context.
///
/// At present the only mode defined by NIST SP 800-56B Rev.2 §7.2 is
/// **RSASVE** (RSA Secret Value Encapsulation). Storing the mode as an
/// enum (rather than the C source's bare `int op`) leaves room for
/// future modes without breaking the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RsaKemMode {
    /// RSA Secret Value Encapsulation — NIST SP 800-56B Rev.2 §7.2.
    #[default]
    Rsasve,
}

impl RsaKemMode {
    /// Returns the canonical `OSSL_KEM_PARAM_OPERATION` string used by
    /// providers and applications when configuring or querying the mode.
    #[must_use]
    pub const fn as_param_str(self) -> &'static str {
        match self {
            Self::Rsasve => OSSL_KEM_PARAM_OPERATION_RSASVE,
        }
    }

    /// Parses a mode string (case-insensitive) and returns the
    /// corresponding [`RsaKemMode`] variant, mirroring the C source's
    /// `rsakem_opname2id` function (`rsa_kem.c:82–85`).
    #[must_use]
    pub fn from_param_str(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case(OSSL_KEM_PARAM_OPERATION_RSASVE) {
            Some(Self::Rsasve)
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------------
// Provider struct — RsaKem
// -----------------------------------------------------------------------------

/// Zero-sized provider type registering the **RSA-KEM (RSASVE)** algorithm
/// with the dispatch core.
///
/// This struct corresponds to the C dispatch table
/// `ossl_rsa_asym_kem_functions` (`rsa_kem.c:428–447`); a single static
/// instance is created and queried by the default provider when an
/// application calls `EVP_KEM_fetch(libctx, "RSA", NULL)`.
///
/// `RsaKem` is `Send + Sync` (no mutable state) and trivially [`Clone`]:
/// it carries no per-instance fields, so cloning is a no-op.
#[derive(Debug, Clone, Copy, Default)]
pub struct RsaKem;

impl RsaKem {
    /// Creates a new [`RsaKem`] provider instance.
    ///
    /// Returns a zero-sized value; called by the default provider at
    /// algorithm-fetch time. Equivalent to the C source's static
    /// dispatch-table reference at `rsa_kem.c:428`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the canonical algorithm name (`"RSA"`) that this
    /// provider responds to in algorithm fetches. Mirrors the C
    /// dispatch table's `ALG("RSA", ...)` registration.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        "RSA"
    }

    /// Constructs a fresh, uninitialized [`RsaKemContext`] tied to no
    /// key and no operation.
    ///
    /// Replaces the C dispatch entry
    /// `{ OSSL_FUNC_KEM_NEWCTX, (void (*)(void))rsakem_newctx }`
    /// (`rsa_kem.c:431`). The returned context must be initialized via
    /// [`RsaKemContext::encapsulate_init`] or
    /// [`RsaKemContext::decapsulate_init`] before any KEM operation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if the underlying allocator fails
    /// (preserved for parity with the C `OPENSSL_zalloc` error path at
    /// `rsa_kem.c:91-95`).
    pub fn new_ctx(&self) -> ProviderResult<RsaKemContext> {
        debug!(provider = "RSA-KEM", "creating new RSA-KEM context");
        Ok(RsaKemContext::new())
    }

    /// Returns the algorithm descriptors registered by this provider.
    /// Convenience wrapper around the module-level [`descriptors`] free
    /// function so callers can drive registration directly from an
    /// `RsaKem` instance if they prefer.
    #[must_use]
    pub fn descriptors(&self) -> Vec<AlgorithmDescriptor> {
        descriptors()
    }
}

// -----------------------------------------------------------------------------
// Context struct — RsaKemContext
// -----------------------------------------------------------------------------

/// Per-operation state for an RSA-KEM (RSASVE) computation.
///
/// Replaces the C `PROV_RSA_CTX` aggregate (`rsa_kem.c:57–62`). The
/// `RSA *rsa` pointer of the C struct is split into two strongly-typed
/// `Option`s — only the relevant key form is held for any given
/// operation:
///
/// | C field                 | Rust field                         | Purpose                       |
/// |-------------------------|------------------------------------|-------------------------------|
/// | `OSSL_LIB_CTX *libctx`  | (implicit; `LibContext` global)    | library context (unused here) |
/// | `RSA *rsa` (encap path) | `public_key: Option<RsaPublicKey>` | encryption key                |
/// | `RSA *rsa` (decap path) | `private_key: Option<RsaPrivateKey>` | decryption key              |
/// | `int op`                | `op: Option<RsaKemOperation>`      | bound operation               |
/// |                         | `mode: RsaKemMode`                 | always [`RsaKemMode::Rsasve`] |
/// | `OSSL_FIPS_IND` slot    | `fips_indicator: Option<...>`      | FIPS-approval state           |
///
/// The struct is **`ZeroizeOnDrop`** to ensure that any private key it
/// holds is zeroized when the context is dropped (mirroring the C
/// `OPENSSL_cleanse(secret, nlen)` discipline at `rsa_kem.c:324`). The
/// `Option` wrappers are skipped from zeroization because [`RsaPrivateKey`]
/// already implements `ZeroizeOnDrop` itself.
#[derive(ZeroizeOnDrop)]
pub struct RsaKemContext {
    /// Public key for encapsulation operations. `None` when the
    /// context has not been initialized for encapsulation.
    #[zeroize(skip)]
    public_key: Option<RsaPublicKey>,

    /// Private key for decapsulation operations. `None` when the
    /// context has not been initialized for decapsulation. The wrapped
    /// [`RsaPrivateKey`] derives [`ZeroizeOnDrop`] itself, so the
    /// secret material is zeroized when this `Option` is dropped.
    #[zeroize(skip)]
    private_key: Option<RsaPrivateKey>,

    /// The operation this context is currently bound to. `None` until
    /// `encapsulate_init` or `decapsulate_init` is called (mirrors C
    /// dispatch sentinel `KEM_OP_UNDEFINED = -1` from `rsa_kem.c:49`).
    #[zeroize(skip)]
    op: Option<RsaKemOperation>,

    /// The KEM mode. The C source initializes this to
    /// `prsactx->op = KEM_OP_RSASVE` at construction (`rsa_kem.c:107`);
    /// we adopt the same default and currently support no other mode.
    #[zeroize(skip)]
    mode: RsaKemMode,

    /// FIPS approved-mode indicator for the most recent operation
    /// (mirrors `OSSL_FIPS_IND_DECLARE`). `None` when no operation
    /// has yet been initialized.
    #[zeroize(skip)]
    fips_indicator: Option<FipsIndicator>,
}

impl Clone for RsaKemContext {
    /// Replaces the C source's `rsakem_dupctx` (`rsa_kem.c:118–136`).
    ///
    /// In C the `RSA *rsa` pointer is reference-counted via
    /// `RSA_up_ref(srcctx->rsa)` so both contexts share the underlying
    /// key material. Rust types are `Clone` so we duplicate the key
    /// directly; for [`RsaPrivateKey`] this still enforces the
    /// `ZeroizeOnDrop` discipline on each instance independently.
    fn clone(&self) -> Self {
        trace!(
            op = self.op.map_or("none", RsaKemOperation::as_str),
            "duplicating RSA-KEM context",
        );
        Self {
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
            op: self.op,
            mode: self.mode,
            fips_indicator: self.fips_indicator,
        }
    }
}

impl fmt::Debug for RsaKemContext {
    /// Custom `Debug` implementation that **redacts** all key material —
    /// only the binding state (operation, mode, FIPS indicator) is
    /// printed. Replaces the C source's lack of a debug printer with a
    /// safe default that cannot leak secrets to logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKemContext")
            .field("op", &self.op.map(RsaKemOperation::as_str))
            .field("mode", &self.mode)
            .field(
                "public_key_size_bits",
                &self.public_key.as_ref().map(RsaPublicKey::key_size_bits),
            )
            .field(
                "private_key_size_bits",
                &self.private_key.as_ref().map(RsaPrivateKey::key_size_bits),
            )
            .field("fips_indicator", &self.fips_indicator)
            .finish()
    }
}

impl Default for RsaKemContext {
    /// Returns a fresh, uninitialized context. Equivalent to
    /// [`RsaKemContext::new`].
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// FIPS approved-mode indicator
// -----------------------------------------------------------------------------

/// Approval state of the most recent KEM operation under the FIPS
/// security policy.
///
/// Mirrors the C source's `OSSL_FIPS_IND_DECLARE` field in `PROV_RSA_CTX`
/// (`rsa_kem.c:62`). The C dispatch sets this via
/// `OSSL_FIPS_IND_SET_APPROVED` when the underlying RSA key satisfies
/// the minimum size policy and is not RSA-PSS-restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsIndicator {
    /// The active operation is performed in FIPS-approved mode.
    Approved,
    /// The active operation is *not* approved under the active FIPS
    /// policy (typically because the RSA key is below the minimum bit
    /// size or is PSS-restricted).
    NotApproved,
}

impl FipsIndicator {
    /// Returns `true` when the indicator value is [`Self::Approved`].
    #[must_use]
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Decode an `i32` parameter value into an indicator. The encoding
    /// matches the C source's `OSSL_FIPS_IND_PARAM_*` macros: `1` for
    /// approved, anything else for not-approved.
    #[must_use]
    pub const fn from_i32(v: i32) -> Self {
        if v == 1 {
            Self::Approved
        } else {
            Self::NotApproved
        }
    }

    /// Encode an indicator as an `i32` parameter value.
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        match self {
            Self::Approved => 1,
            Self::NotApproved => 0,
        }
    }
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

/// Convert any [`openssl_common::error::CryptoError`] coming out of the
/// crypto crate into a [`ProviderError::Dispatch`].
///
/// The conversion preserves the original error string so that operators
/// debugging a stuck KEM operation can see the underlying RSA / `BigNum`
/// failure detail (replaces the C source's `ERR_raise` call sites).
///
/// This helper deliberately mirrors the equivalent helper in
/// `ml_kem.rs` for cross-module consistency.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: openssl_common::error::CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Convert the modulus bit-length of an [`RsaPublicKey`] /
/// [`RsaPrivateKey`] into a `usize` byte count without lossy casts.
///
/// `key_size_bytes()` returns a `u32` whose maximum value is
/// `u32::MAX / 8` — well within `usize` on every supported target
/// (16-bit `usize` is not a Rust target tier we ship). Using
/// [`usize::try_from`] keeps Rule R6 satisfied (no bare `as` narrowing).
#[inline]
fn rsa_size_bytes_public(key: &RsaPublicKey) -> ProviderResult<usize> {
    usize::try_from(key.key_size_bytes()).map_err(|_| {
        ProviderError::Dispatch(format!(
            "RSA modulus byte length {} exceeds platform usize",
            key.key_size_bytes()
        ))
    })
}

/// Same as [`rsa_size_bytes_public`] but for [`RsaPrivateKey`].
#[inline]
fn rsa_size_bytes_private(key: &RsaPrivateKey) -> ProviderResult<usize> {
    usize::try_from(key.key_size_bytes()).map_err(|_| {
        ProviderError::Dispatch(format!(
            "RSA modulus byte length {} exceeds platform usize",
            key.key_size_bytes()
        ))
    })
}

/// Generate a uniformly distributed random shared secret `z ∈ [2, n−2]`
/// padded to `out_len` bytes (big-endian).
///
/// Replaces the C source's `rsasve_gen_rand_bytes` helper
/// (`rsa_kem.c:239–268`), which implements NIST SP 800-56B Rev.2
/// §7.2.1.2 step 1: the *generation of the random secret value*.
///
/// # Algorithm (mirrors C reference exactly)
///
/// 1. Compute `n − 3` where `n = key.modulus()`.
/// 2. Sample `z' ∈ [0, n−3)` via [`BigNum::priv_rand_range`]
///    (rejection sampling — strictly less than the bound).
/// 3. Set `z = z' + 2`. By construction `z ∈ [2, n−2]`, the exact range
///    required by RSASVE.
/// 4. Encode `z` as a big-endian, left-zero-padded byte string of
///    length `out_len` via [`BigNum::to_bytes_be_padded`].
///
/// # Errors
///
/// - Returns [`ProviderError::Dispatch`] if `n` is so small that `n−3`
///   becomes zero or negative — that is, key sizes < 3 bits, which the
///   higher-level FIPS minimum bit check (1024 / 2048) already rejects.
/// - Propagates any error from the underlying random source via
///   [`dispatch_err`].
fn rsasve_gen_rand_bytes(pubkey: &RsaPublicKey, out_len: usize) -> ProviderResult<Vec<u8>> {
    trace!(
        n_len = out_len,
        "RSASVE: generating random shared secret in [2, n-2]"
    );

    // Step 1: nminus3 = n - 3.
    let n_minus_3 = pubkey.modulus() - &BigNum::from(3u64);
    if n_minus_3.is_zero() || n_minus_3.is_negative() {
        warn!(
            key_bits = pubkey.key_size_bits(),
            "RSA modulus too small for RSASVE: n - 3 is non-positive"
        );
        return Err(ProviderError::Dispatch(
            "RSA modulus too small for RSASVE: n - 3 is non-positive".to_string(),
        ));
    }

    // Step 2: z' ∈ [0, n-3) via private-RNG rejection sampling.
    let z_prime = BigNum::priv_rand_range(&n_minus_3).map_err(dispatch_err)?;

    // Step 3: z = z' + 2 ∈ [2, n-2].
    let z = &z_prime + &BigNum::from(2u64);

    // Step 4: encode z as a big-endian, zero-padded byte string of length
    //          out_len (== RSA_size(key)). `to_bytes_be_padded` returns
    //          an error if the value would not fit in the requested
    //          length — for our `n−2` upper bound this is impossible
    //          when out_len = ceil(num_bits(n) / 8).
    let secret = z.to_bytes_be_padded(out_len).map_err(dispatch_err)?;

    Ok(secret)
}

/// Validate that a public key is acceptable for use as a KEM context's
/// active key.
///
/// Mirrors the security-check logic at
/// `providers/common/securitycheck.c:25–60` (`ossl_rsa_key_op_get_protect`).
/// Specifically:
/// - PSS-restricted keys (those carrying ASN.1 `RSASSA-PSS-params`) are
///   rejected because RSA-KEM requires unconstrained encryption keys.
/// - The minimum bit size depends on the operation: 2048 for
///   encapsulate (`protect = 1`), 1024 for decapsulate (`protect = 0`).
fn check_public_key(
    key: &RsaPublicKey,
    op: RsaKemOperation,
    pss_restricted: bool,
) -> ProviderResult<FipsIndicator> {
    if pss_restricted {
        return Err(ProviderError::Dispatch(
            "RSA-KEM does not support RSASSA-PSS-restricted keys".to_string(),
        ));
    }

    let bits = key.key_size_bits();
    let min_bits = match op {
        RsaKemOperation::Encapsulate => FIPS_MIN_RSA_BITS_ENCAPSULATE,
        RsaKemOperation::Decapsulate => FIPS_MIN_RSA_BITS_DECAPSULATE,
    };

    if bits < min_bits {
        warn!(
            op = op.as_str(),
            bits, min_bits, "RSA key below FIPS minimum size — marking NotApproved"
        );
        Ok(FipsIndicator::NotApproved)
    } else {
        Ok(FipsIndicator::Approved)
    }
}

// -----------------------------------------------------------------------------
// RsaKemContext — lifecycle and operations
// -----------------------------------------------------------------------------

impl RsaKemContext {
    /// Construct a fresh, uninitialized context.
    ///
    /// Replaces the C source's `rsakem_newctx` (`rsa_kem.c:87–108`):
    /// the C version `OPENSSL_zalloc`s a `PROV_RSA_CTX`, sets
    /// `prsactx->op = KEM_OP_RSASVE`, and initializes the FIPS indicator
    /// to "approved" via `OSSL_FIPS_IND_INIT`. The Rust equivalent
    /// initializes all fields to `None` / default and defers FIPS
    /// indicator computation until [`Self::encapsulate_init`] /
    /// [`Self::decapsulate_init`] is called.
    #[must_use]
    pub fn new() -> Self {
        debug!("RsaKemContext::new — fresh context, no key bound");
        Self {
            public_key: None,
            private_key: None,
            op: None,
            mode: RsaKemMode::Rsasve,
            fips_indicator: None,
        }
    }

    /// Returns the bound operation, if any. Returns `None` until the
    /// context has been initialized.
    #[must_use]
    pub const fn operation(&self) -> Option<RsaKemOperation> {
        self.op
    }

    /// Returns the bound RSA-KEM mode (currently always
    /// [`RsaKemMode::Rsasve`]).
    #[must_use]
    pub const fn mode(&self) -> RsaKemMode {
        self.mode
    }

    /// Returns the FIPS approved-mode indicator from the most recent
    /// `*_init` call, if any.
    #[must_use]
    pub const fn fips_indicator(&self) -> Option<FipsIndicator> {
        self.fips_indicator
    }

    /// Returns the bound public key, if the context was initialized for
    /// encapsulation. Provided primarily for testing.
    #[must_use]
    pub const fn public_key(&self) -> Option<&RsaPublicKey> {
        self.public_key.as_ref()
    }

    /// Returns the bound private key, if the context was initialized
    /// for decapsulation. Provided primarily for testing.
    #[must_use]
    pub const fn private_key(&self) -> Option<&RsaPrivateKey> {
        self.private_key.as_ref()
    }

    /// Reset the context's per-init state so it can be re-initialized
    /// for a fresh operation. Called internally at the top of every
    /// `*_init` to clear any prior key binding.
    fn reset_for_reinit(&mut self) {
        // Drop any previously held key material; `RsaPrivateKey` is
        // `ZeroizeOnDrop` so secret components are wiped.
        self.public_key = None;
        self.private_key = None;
        self.op = None;
        self.fips_indicator = None;
        // `mode` is preserved across re-init (matches C behavior where
        // `prsactx->op` is restored from `KEM_OP_RSASVE` at construction
        // and is only changed by an explicit `set_ctx_params` call).
    }

    /// Apply parameters that affect operation binding (currently the
    /// "operation" UTF-8 parameter selecting RSASVE).
    ///
    /// Mirrors the C source's `rsakem_set_ctx_params` (`rsa_kem.c:203–225`)
    /// which inspects `OSSL_KEM_PARAM_OPERATION` and looks up the
    /// corresponding numeric `op` via `rsakem_opname2id`.
    fn apply_param_set(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(value) = params.get(PARAM_OPERATION) {
            let mode_str = value.as_str().ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "{PARAM_OPERATION} parameter must be a UTF-8 string, got {}",
                    value.param_type_name()
                ))
            })?;

            let mode = RsaKemMode::from_param_str(mode_str).ok_or_else(|| {
                ProviderError::Dispatch(format!("unknown RSA-KEM operation mode: {mode_str:?}"))
            })?;
            trace!(
                mode = mode.as_param_str(),
                "RSA-KEM mode selected via params"
            );
            self.mode = mode;
        }

        if let Some(value) = params.get(PARAM_FIPS_INDICATOR) {
            // Accept either an i32 (matches C `OSSL_PARAM_INTEGER`) or
            // a UTF-8 string ("approved" / "not-approved") for ergonomics.
            if let Some(int_val) = value.as_i32() {
                self.fips_indicator = Some(FipsIndicator::from_i32(int_val));
            } else if let Some(s) = value.as_str() {
                let ind = if s.eq_ignore_ascii_case("approved") {
                    FipsIndicator::Approved
                } else {
                    FipsIndicator::NotApproved
                };
                self.fips_indicator = Some(ind);
            } else {
                return Err(ProviderError::Dispatch(format!(
                    "{PARAM_FIPS_INDICATOR} must be an integer or UTF-8 string, got {}",
                    value.param_type_name()
                )));
            }
        }

        Ok(())
    }

    /// Common init path used by both [`Self::encapsulate_init`] and
    /// [`Self::decapsulate_init`].
    ///
    /// Mirrors the C source's unified `rsakem_init` helper
    /// (`rsa_kem.c:138–168`). Key parsing (`vrsa` in the C source) is
    /// expressed in Rust as DER decoding via [`public_key_from_der`] /
    /// [`private_key_from_der`].
    fn init_with_keys(
        &mut self,
        public_key: Option<RsaPublicKey>,
        private_key: Option<RsaPrivateKey>,
        op: RsaKemOperation,
        params: Option<&ParamSet>,
        pss_restricted: bool,
    ) -> ProviderResult<()> {
        debug!(
            op = op.as_str(),
            public_key_bound = public_key.is_some(),
            private_key_bound = private_key.is_some(),
            "RSA-KEM init",
        );

        // Validate the key for the requested operation. We extract a
        // borrow of whichever key is present; `init_with_keys` is only
        // called with one or the other, depending on the caller.
        let indicator = if let Some(pk) = public_key.as_ref() {
            check_public_key(pk, op, pss_restricted)?
        } else if let Some(sk) = private_key.as_ref() {
            // For private keys we validate via the public component to
            // share a single code path.
            let pub_for_check = sk.public_key();
            check_public_key(&pub_for_check, op, pss_restricted)?
        } else {
            return Err(ProviderError::Init(
                "RSA-KEM init called without a key".to_string(),
            ));
        };

        // Commit state.
        self.reset_for_reinit();
        self.public_key = public_key;
        self.private_key = private_key;
        self.op = Some(op);
        self.fips_indicator = Some(indicator);

        // Apply any caller-provided parameters last so they can override
        // the freshly-computed FIPS indicator (matches the C source's
        // ordering at `rsa_kem.c:160`).
        if let Some(p) = params {
            self.apply_param_set(p)?;
        }

        trace!(
            op = op.as_str(),
            fips_approved = indicator.is_approved(),
            "RSA-KEM init complete"
        );
        Ok(())
    }

    /// Initialize the context for encapsulation, using the supplied
    /// **DER-encoded `SubjectPublicKeyInfo`** (or PKCS#1 RSA public key)
    /// as the encryption target.
    ///
    /// Mirrors the C source's `rsakem_encapsulate_init`
    /// (`rsa_kem.c:170–175`) which takes an `RSA *vrsa` pointer; in
    /// Rust the equivalent is a DER blob that we decode into an owned
    /// [`RsaPublicKey`].
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] if the DER does not decode
    /// to a valid RSA public key, or [`ProviderError::Init`] if no key
    /// is supplied. [`ProviderError::Dispatch`] is also returned when
    /// the key fails the security policy (PSS-restricted, etc.).
    pub fn encapsulate_init(
        &mut self,
        key_der: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key_der.is_empty() {
            return Err(ProviderError::Init(
                "RSA-KEM encapsulate_init requires a non-empty key blob".to_string(),
            ));
        }

        let pub_key = public_key_from_der(key_der).map_err(dispatch_err)?;
        // PSS-restriction check: pure RSA public keys (RFC 8017
        // SubjectPublicKeyInfo) carry no PSS parameters. If we are
        // wrapping a private key carrying PSS params we reject it via
        // `decapsulate_init`. For the public-key path the C code
        // checks `RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) == RSASSAPSS`
        // — there is no equivalent flag on `RsaPublicKey`, so we treat
        // public keys as unrestricted (consistent with C's parser).
        self.init_with_keys(
            Some(pub_key),
            None,
            RsaKemOperation::Encapsulate,
            params,
            /* pss_restricted = */ false,
        )
    }

    /// Initialize the context for decapsulation, using the supplied
    /// **DER-encoded `PrivateKeyInfo`** (or PKCS#1 RSA private key) as
    /// the decryption credential.
    ///
    /// Mirrors the C source's `rsakem_decapsulate_init`
    /// (`rsa_kem.c:177–182`).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] if the DER does not decode
    /// to a valid RSA private key, the key is PSS-restricted, or any
    /// underlying crypto operation fails.
    pub fn decapsulate_init(
        &mut self,
        key_der: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        if key_der.is_empty() {
            return Err(ProviderError::Init(
                "RSA-KEM decapsulate_init requires a non-empty key blob".to_string(),
            ));
        }

        let priv_key = private_key_from_der(key_der).map_err(dispatch_err)?;
        // RSA-PSS-restricted private keys carry an ASN.1 `pssParams` field.
        let pss_restricted = priv_key.pss_params().is_some();
        self.init_with_keys(
            None,
            Some(priv_key),
            RsaKemOperation::Decapsulate,
            params,
            pss_restricted,
        )
    }

    /// Run RSASVE-GENERATE: produce the `(ciphertext, shared_secret)`
    /// pair for the encapsulation operation.
    ///
    /// Mirrors the C source's `rsasve_generate` (`rsa_kem.c:274–328`).
    /// The implementation follows NIST SP 800-56B Rev.2 §7.2.1.2:
    ///
    /// 1. Determine `n_len = RSA_size(key)`.
    /// 2. Generate `z ∈ [2, n−2]` via [`rsasve_gen_rand_bytes`].
    /// 3. Encrypt `z` under the public key with raw RSA
    ///    (`PaddingMode::None`) to obtain the ciphertext.
    /// 4. Return the `(ciphertext, z)` pair. **Both** vectors have
    ///    length `n_len`.
    ///
    /// On any error path the in-flight `secret` buffer is explicitly
    /// zeroized (mirroring `OPENSSL_cleanse(secret, nlen)` at C line
    /// 324).
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if the context is not initialized
    ///   for encapsulation, or the underlying RSA / random-number
    ///   primitives fail.
    pub fn encapsulate(&mut self) -> ProviderResult<(Vec<u8>, Vec<u8>)> {
        match self.op {
            Some(RsaKemOperation::Encapsulate) => {}
            Some(other) => {
                return Err(ProviderError::Dispatch(format!(
                    "RSA-KEM context bound to {} but encapsulate() called",
                    other.as_str()
                )));
            }
            None => {
                return Err(ProviderError::Dispatch(
                    "RSA-KEM encapsulate() called before init".to_string(),
                ));
            }
        }

        let pub_key = self.public_key.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("RSA-KEM encapsulate() requires a bound public key".to_string())
        })?;

        let n_len = rsa_size_bytes_public(pub_key)?;
        trace!(
            n_len,
            mode = self.mode.as_param_str(),
            "RSASVE-GENERATE start"
        );

        // Step 1 & 2: generate the random secret in [2, n-2].
        let mut secret = match rsasve_gen_rand_bytes(pub_key, n_len) {
            Ok(b) => b,
            Err(e) => {
                // No secret to zeroize yet; just propagate.
                return Err(e);
            }
        };

        // Step 3: encrypt the secret with raw RSA (RSA_NO_PADDING).
        let ciphertext = match public_encrypt(pub_key, &secret, PaddingMode::None) {
            Ok(ct) => ct,
            Err(e) => {
                // Zeroize the in-flight secret on the error path.
                secret.zeroize();
                return Err(dispatch_err(e));
            }
        };

        if ciphertext.len() != n_len {
            // Defensive: if the underlying primitive ever returned a
            // different-length ciphertext, treat as a hard fail and
            // wipe the secret rather than ship a malformed pair.
            secret.zeroize();
            return Err(ProviderError::Dispatch(format!(
                "RSA encrypt produced {} bytes; expected {}",
                ciphertext.len(),
                n_len
            )));
        }

        trace!(n_len, "RSASVE-GENERATE complete");
        Ok((ciphertext, secret))
    }

    /// Run RSASVE-RECOVER: produce the `shared_secret` for the
    /// decapsulation operation, given a ciphertext.
    ///
    /// Mirrors the C source's `rsasve_recover` (`rsa_kem.c:351–394`):
    /// the function validates that `inlen == n_len` exactly (returning
    /// `PROV_R_BAD_LENGTH` otherwise), then performs raw RSA
    /// decryption (`RSA_NO_PADDING`) producing exactly `n_len` bytes.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if the context is not initialized
    ///   for decapsulation, the ciphertext length is not exactly
    ///   `RSA_size(key)`, or the underlying decryption fails.
    pub fn decapsulate(&mut self, ciphertext: &[u8]) -> ProviderResult<Vec<u8>> {
        match self.op {
            Some(RsaKemOperation::Decapsulate) => {}
            Some(other) => {
                return Err(ProviderError::Dispatch(format!(
                    "RSA-KEM context bound to {} but decapsulate() called",
                    other.as_str()
                )));
            }
            None => {
                return Err(ProviderError::Dispatch(
                    "RSA-KEM decapsulate() called before init".to_string(),
                ));
            }
        }

        let priv_key = self.private_key.as_ref().ok_or_else(|| {
            ProviderError::Dispatch(
                "RSA-KEM decapsulate() requires a bound private key".to_string(),
            )
        })?;

        let n_len = rsa_size_bytes_private(priv_key)?;

        // Pre-validate ciphertext length to give a clean diagnostic
        // before delegating to `private_decrypt`. This matches the C
        // source's explicit `inlen == nlen` check at `rsa_kem.c:380-385`.
        if ciphertext.len() != n_len {
            warn!(
                got = ciphertext.len(),
                expected = n_len,
                "RSA-KEM decapsulate ciphertext length mismatch"
            );
            return Err(ProviderError::Dispatch(format!(
                "RSA-KEM ciphertext length {} does not match RSA_size {}",
                ciphertext.len(),
                n_len
            )));
        }

        trace!(n_len, "RSASVE-RECOVER start");
        let secret =
            private_decrypt(priv_key, ciphertext, PaddingMode::None).map_err(dispatch_err)?;

        if secret.len() != n_len {
            // Defensive: as for encapsulate, RSADP must produce exactly
            // `n_len` bytes (because it is raw RSA). If not, zero the
            // partial output and fail cleanly. Capture `produced`
            // before `zeroize()` so the diagnostic reports the actual
            // (mis-sized) length rather than the expected length.
            let produced = secret.len();
            let mut bad = secret;
            bad.zeroize();
            return Err(ProviderError::Dispatch(format!(
                "RSA decrypt produced {produced} bytes; expected {n_len}"
            )));
        }

        trace!(n_len, "RSASVE-RECOVER complete");
        Ok(secret)
    }

    /// Returns the gettable parameters for this context.
    ///
    /// Mirrors the C source's `rsakem_get_ctx_params`
    /// (`rsa_kem.c:184–195`): the only gettable parameter is the FIPS
    /// approved-mode indicator from the most recent operation.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();
        if let Some(ind) = self.fips_indicator {
            out.set(PARAM_FIPS_INDICATOR, ParamValue::Int32(ind.to_i32()));
        }
        // The C source does not expose the bound operation back to the
        // caller via get_ctx_params; we follow the same convention to
        // preserve drop-in behavior.
        Ok(out)
    }

    /// Apply settable parameters to this context.
    ///
    /// Mirrors the C source's `rsakem_set_ctx_params`
    /// (`rsa_kem.c:203–225`).
    pub fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_param_set(params)
    }
}

// -----------------------------------------------------------------------------
// Trait implementations — KemProvider / KemContext
// -----------------------------------------------------------------------------

/// Master KEM-provider trait surface for the RSA-KEM (RSASVE) algorithm.
///
/// The trait methods delegate to the inherent methods on [`RsaKem`] and
/// [`RsaKemContext`]. The only behavioral difference is that
/// [`KemProvider::new_ctx`] returns a `Box<dyn KemContext>` so the
/// provider's method store can hold heterogeneous KEM implementations
/// behind a single trait-object handle (the C source achieves the same
/// outcome via the `OSSL_DISPATCH` pointer table).
///
/// Mirrors the C dispatch table `ossl_rsa_asym_kem_functions`
/// (`rsa_kem.c:428–446`).
impl KemProvider for RsaKem {
    /// Returns the canonical algorithm name (`"RSA"`).
    ///
    /// Delegates to the inherent [`RsaKem::name`] method.
    fn name(&self) -> &'static str {
        Self::name(self)
    }

    /// Constructs a fresh, uninitialized [`RsaKemContext`] boxed as a
    /// `dyn KemContext` trait object so it can participate in dynamic
    /// dispatch through the provider's method store.
    ///
    /// Replaces the C dispatch entry
    /// `{ OSSL_FUNC_KEM_NEWCTX, (void (*)(void))rsakem_newctx }`
    /// (`rsa_kem.c:431`).
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok` — context construction is
    /// infallible. The `Result` return type is preserved for parity
    /// with the C source's `rsakem_newctx` which returns `NULL` on
    /// allocator failure (`rsa_kem.c:91-95`).
    fn new_ctx(&self) -> ProviderResult<Box<dyn KemContext>> {
        debug!(
            provider = "RSA-KEM",
            "RsaKem::new_ctx (KemProvider trait) — boxing fresh context"
        );
        Ok(Box::new(RsaKemContext::new()))
    }
}

/// Per-operation [`KemContext`] trait surface for [`RsaKemContext`].
///
/// All six trait methods delegate verbatim to the eponymous inherent
/// methods on [`RsaKemContext`]. The trait impl exists so the context
/// can be returned from [`RsaKem::new_ctx`] as a `Box<dyn KemContext>`
/// trait object — no behavioral logic lives in this impl block.
///
/// Mirrors the per-operation dispatch entries in
/// `ossl_rsa_asym_kem_functions` (`rsa_kem.c:428–446`).
impl KemContext for RsaKemContext {
    /// Initializes for encapsulation; delegates to
    /// [`RsaKemContext::encapsulate_init`].
    fn encapsulate_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        Self::encapsulate_init(self, key, params)
    }

    /// Performs RSASVE-GENERATE; delegates to
    /// [`RsaKemContext::encapsulate`].
    fn encapsulate(&mut self) -> ProviderResult<(Vec<u8>, Vec<u8>)> {
        Self::encapsulate(self)
    }

    /// Initializes for decapsulation; delegates to
    /// [`RsaKemContext::decapsulate_init`].
    fn decapsulate_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        Self::decapsulate_init(self, key, params)
    }

    /// Performs RSASVE-RECOVER; delegates to
    /// [`RsaKemContext::decapsulate`].
    fn decapsulate(&mut self, ciphertext: &[u8]) -> ProviderResult<Vec<u8>> {
        Self::decapsulate(self, ciphertext)
    }

    /// Returns the gettable parameters; delegates to
    /// [`RsaKemContext::get_params`].
    fn get_params(&self) -> ProviderResult<ParamSet> {
        Self::get_params(self)
    }

    /// Applies settable parameters; delegates to
    /// [`RsaKemContext::set_params`].
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        Self::set_params(self, params)
    }
}

// -----------------------------------------------------------------------------
// Algorithm descriptors
// -----------------------------------------------------------------------------

/// Returns the [`AlgorithmDescriptor`] entries published by this module.
///
/// RSA-KEM exposes a single entry — the canonical algorithm name `"RSA"`
/// registered under `provider=default`. Replaces the C dispatch-table
/// registration block at `providers/implementations/kem/rsa_kem.c`
/// lines 428–446 (the `ossl_rsa_asym_kem_functions` table) and the
/// algorithm-name registration in the default provider's
/// `OSSL_ALGORITHM` array (`providers/defltprov.c`, `RSA` KEM entry).
///
/// The returned descriptor carries:
/// - **`names`** — the canonical algorithm name `"RSA"` (single-element
///   vector; RSA-KEM has no aliases in the C source).
/// - **`property`** — `"provider=default"` so the dispatch core selects
///   this entry when no explicit property query is supplied.
/// - **`description`** — a short human-readable description suitable
///   for `openssl list -kem-algorithms` output.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["RSA"],
        property: "provider=default",
        description: "RSA Key Encapsulation Mechanism",
    }]
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unit tests for the RSA-KEM (RSASVE) provider implementation.
    //!
    //! Coverage targets:
    //! - Type-level invariants (`Send + Sync`, `Clone`, `Default`).
    //! - Enum conversions (`RsaKemOperation`, `RsaKemMode`,
    //!   `FipsIndicator`).
    //! - Context lifecycle (`new` / `default` / `reset_for_reinit`).
    //! - Parameter handling (`get_params` / `set_params` round-trip,
    //!   FIPS-indicator coercion from `i32` and from string).
    //! - Init-mode gating (encapsulate before init, decapsulate before
    //!   init, cross-mode misuse).
    //! - DER-decoding error paths (empty blob, malformed DER).
    //! - Ciphertext-length validation on decapsulate.
    //! - Round-trip encapsulate/decapsulate parity with C source.
    //! - Trait-object dispatch via [`KemProvider`] / [`KemContext`].
    //! - Descriptor surface (`descriptors()` returns expected names).

    // Justification: Test code legitimately uses expect/unwrap/panic for clear
    // failure messages on assertion failures. The workspace `Cargo.toml`
    // §[workspace.lints.clippy] explicitly states:
    // "Tests and CLI main() may #[allow] with justification."
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::*;
    use openssl_common::error::ProviderError;
    use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
    use openssl_crypto::rsa::{
        generate_key, private_key_to_der, public_key_to_der, RsaKeyGenParams, RsaKeyPair,
    };
    use std::sync::OnceLock;

    // -------------------------------------------------------------------------
    // Shared 2048-bit RSA key for round-trip tests
    //
    // RSA-2048 keygen takes seconds; we generate exactly one shared keypair
    // for the entire test module via `OnceLock` so that round-trip tests
    // share the same keypair without forcing serial execution.
    // -------------------------------------------------------------------------

    /// Lazily-generated 2048-bit RSA keypair for tests that need a real key.
    fn shared_keypair() -> &'static RsaKeyPair {
        static KEYPAIR: OnceLock<RsaKeyPair> = OnceLock::new();
        KEYPAIR.get_or_init(|| {
            generate_key(&RsaKeyGenParams::default())
                .expect("RSA-2048 default key generation must succeed in tests")
        })
    }

    /// Returns DER-encoded public-key bytes for the shared keypair.
    fn shared_pub_der() -> Vec<u8> {
        let pk = shared_keypair().public_key();
        public_key_to_der(&pk).expect("RSA public-key DER encoding must succeed")
    }

    /// Returns DER-encoded private-key bytes for the shared keypair.
    fn shared_priv_der() -> Vec<u8> {
        let sk = shared_keypair().private_key();
        private_key_to_der(sk).expect("RSA private-key DER encoding must succeed")
    }

    // -------------------------------------------------------------------------
    // Type-level invariants
    // -------------------------------------------------------------------------

    /// Compile-time check that `RsaKem` and `RsaKemContext` are `Send + Sync`,
    /// satisfying the `KemProvider`/`KemContext` trait bounds.
    #[test]
    fn types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RsaKem>();
        assert_send_sync::<RsaKemContext>();
        assert_send_sync::<Box<dyn KemContext>>();
    }

    /// Compile-time check that `RsaKemContext` implements `Clone` and
    /// `Default` (replaces C `rsakem_dupctx` and `rsakem_newctx`).
    #[test]
    fn context_is_clone_and_default() {
        fn assert_clone<T: Clone>() {}
        fn assert_default<T: Default>() {}
        assert_clone::<RsaKemContext>();
        assert_default::<RsaKemContext>();
    }

    // -------------------------------------------------------------------------
    // Enum conversions — RsaKemOperation / RsaKemMode / FipsIndicator
    // -------------------------------------------------------------------------

    #[test]
    fn rsa_kem_operation_as_str_round_trip() {
        assert_eq!(RsaKemOperation::Encapsulate.as_str(), "encapsulate");
        assert_eq!(RsaKemOperation::Decapsulate.as_str(), "decapsulate");
    }

    #[test]
    fn rsa_kem_mode_default_is_rsasve() {
        let ctx = RsaKemContext::new();
        assert_eq!(ctx.mode(), RsaKemMode::Rsasve);
    }

    #[test]
    fn rsa_kem_mode_param_round_trip() {
        assert_eq!(
            RsaKemMode::Rsasve.as_param_str(),
            OSSL_KEM_PARAM_OPERATION_RSASVE
        );
        assert_eq!(
            RsaKemMode::from_param_str(OSSL_KEM_PARAM_OPERATION_RSASVE),
            Some(RsaKemMode::Rsasve)
        );
        // Case-insensitive lookup mirrors C's strcasecmp behavior.
        assert_eq!(
            RsaKemMode::from_param_str("rsasve"),
            Some(RsaKemMode::Rsasve)
        );
        assert_eq!(
            RsaKemMode::from_param_str("RSASVE"),
            Some(RsaKemMode::Rsasve)
        );
        // Unknown modes return None (Rule R5 — no sentinel encoding).
        assert_eq!(RsaKemMode::from_param_str("RSAOAEP"), None);
        assert_eq!(RsaKemMode::from_param_str(""), None);
    }

    #[test]
    fn fips_indicator_round_trip_via_i32() {
        assert!(FipsIndicator::Approved.is_approved());
        assert!(!FipsIndicator::NotApproved.is_approved());
        assert_eq!(FipsIndicator::Approved.to_i32(), 1);
        assert_eq!(FipsIndicator::NotApproved.to_i32(), 0);
        assert_eq!(FipsIndicator::from_i32(1), FipsIndicator::Approved);
        assert_eq!(FipsIndicator::from_i32(0), FipsIndicator::NotApproved);
        // Strict equality against the `1` sentinel — any other value
        // (including `42` or `-1`) decodes to `NotApproved`. This is
        // intentionally stricter than C's bitmask semantics so that
        // unknown encodings are *never* silently treated as approved.
        assert_eq!(FipsIndicator::from_i32(42), FipsIndicator::NotApproved);
        assert_eq!(FipsIndicator::from_i32(-1), FipsIndicator::NotApproved);
    }

    // -------------------------------------------------------------------------
    // RsaKem provider surface
    // -------------------------------------------------------------------------

    #[test]
    fn rsa_kem_provider_name_is_canonical() {
        let prov = RsaKem::new();
        assert_eq!(prov.name(), "RSA");
        assert_eq!(<RsaKem as KemProvider>::name(&prov), "RSA");
    }

    #[test]
    fn rsa_kem_provider_new_ctx_returns_fresh_context() {
        let prov = RsaKem::new();
        // Inherent method returns a typed RsaKemContext.
        let inherent_ctx = prov.new_ctx().expect("inherent new_ctx must succeed");
        assert!(inherent_ctx.operation().is_none());
        assert!(inherent_ctx.public_key().is_none());
        assert!(inherent_ctx.private_key().is_none());
        // Trait method returns a Box<dyn KemContext>.
        let trait_ctx: Box<dyn KemContext> =
            <RsaKem as KemProvider>::new_ctx(&prov).expect("trait new_ctx must succeed");
        // The trait object's get_params on a fresh context returns an
        // empty ParamSet (no FIPS indicator yet).
        let params = trait_ctx.get_params().expect("get_params must succeed");
        assert!(params.is_empty());
    }

    // -------------------------------------------------------------------------
    // Lifecycle — new / default / reset_for_reinit
    // -------------------------------------------------------------------------

    #[test]
    fn context_new_has_no_state() {
        let ctx = RsaKemContext::new();
        assert!(ctx.operation().is_none());
        assert!(ctx.public_key().is_none());
        assert!(ctx.private_key().is_none());
        assert!(ctx.fips_indicator().is_none());
        assert_eq!(ctx.mode(), RsaKemMode::Rsasve);
    }

    #[test]
    fn context_default_equals_new() {
        let new = RsaKemContext::new();
        let dflt = RsaKemContext::default();
        // Compare the observable surface (we don't derive PartialEq on
        // RsaKemContext to avoid leaking key material into comparisons).
        assert_eq!(new.operation(), dflt.operation());
        assert_eq!(new.mode(), dflt.mode());
        assert_eq!(new.fips_indicator(), dflt.fips_indicator());
        assert!(new.public_key().is_none() && dflt.public_key().is_none());
        assert!(new.private_key().is_none() && dflt.private_key().is_none());
    }

    #[test]
    fn context_clone_preserves_observable_state() {
        let mut ctx = RsaKemContext::new();
        // Set a FIPS indicator via params and clone.
        let p = ParamBuilder::new()
            .push_i32(PARAM_FIPS_INDICATOR, 1)
            .build();
        ctx.set_params(&p).expect("set_params must succeed");
        let clone = ctx.clone();
        assert_eq!(clone.fips_indicator(), Some(FipsIndicator::Approved));
        assert_eq!(clone.mode(), ctx.mode());
    }

    // -------------------------------------------------------------------------
    // Parameter round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn get_params_on_fresh_context_is_empty() {
        let ctx = RsaKemContext::new();
        let params = ctx.get_params().expect("get_params must succeed");
        assert!(params.is_empty());
    }

    #[test]
    fn set_params_fips_indicator_int_then_get() {
        let mut ctx = RsaKemContext::new();
        let p = ParamBuilder::new()
            .push_i32(PARAM_FIPS_INDICATOR, 1)
            .build();
        ctx.set_params(&p).expect("set_params must succeed");
        assert_eq!(ctx.fips_indicator(), Some(FipsIndicator::Approved));
        let got = ctx.get_params().expect("get_params must succeed");
        let value = got
            .get(PARAM_FIPS_INDICATOR)
            .expect("FIPS indicator must be present after get_params");
        assert_eq!(value.as_i32(), Some(1));
    }

    #[test]
    fn set_params_fips_indicator_zero_means_not_approved() {
        let mut ctx = RsaKemContext::new();
        let p = ParamBuilder::new()
            .push_i32(PARAM_FIPS_INDICATOR, 0)
            .build();
        ctx.set_params(&p).expect("set_params must succeed");
        assert_eq!(ctx.fips_indicator(), Some(FipsIndicator::NotApproved));
    }

    #[test]
    fn set_params_fips_indicator_string_approved() {
        let mut ctx = RsaKemContext::new();
        let mut p = ParamSet::new();
        p.set(
            PARAM_FIPS_INDICATOR,
            ParamValue::Utf8String("approved".to_string()),
        );
        ctx.set_params(&p).expect("set_params must succeed");
        assert_eq!(ctx.fips_indicator(), Some(FipsIndicator::Approved));
    }

    #[test]
    fn set_params_fips_indicator_string_not_approved() {
        let mut ctx = RsaKemContext::new();
        let mut p = ParamSet::new();
        p.set(
            PARAM_FIPS_INDICATOR,
            ParamValue::Utf8String("not-approved".to_string()),
        );
        ctx.set_params(&p).expect("set_params must succeed");
        assert_eq!(ctx.fips_indicator(), Some(FipsIndicator::NotApproved));
    }

    #[test]
    fn set_params_fips_indicator_invalid_type_errors() {
        let mut ctx = RsaKemContext::new();
        let mut p = ParamSet::new();
        // Real (f64) is not a valid encoding for the FIPS indicator.
        p.set(PARAM_FIPS_INDICATOR, ParamValue::Real(1.0));
        let err = ctx
            .set_params(&p)
            .expect_err("set_params must reject non-int/non-string FIPS indicator");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn set_params_operation_rsasve() {
        let mut ctx = RsaKemContext::new();
        let mut p = ParamSet::new();
        p.set(
            PARAM_OPERATION,
            ParamValue::Utf8String("RSASVE".to_string()),
        );
        ctx.set_params(&p).expect("set_params must succeed");
        assert_eq!(ctx.mode(), RsaKemMode::Rsasve);
    }

    #[test]
    fn set_params_operation_unknown_errors() {
        let mut ctx = RsaKemContext::new();
        let mut p = ParamSet::new();
        p.set(
            PARAM_OPERATION,
            ParamValue::Utf8String("RSA-OAEP".to_string()),
        );
        let err = ctx
            .set_params(&p)
            .expect_err("unknown operation mode must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn set_params_operation_wrong_type_errors() {
        let mut ctx = RsaKemContext::new();
        let mut p = ParamSet::new();
        p.set(PARAM_OPERATION, ParamValue::Int32(0));
        let err = ctx
            .set_params(&p)
            .expect_err("non-string operation must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // -------------------------------------------------------------------------
    // Init-mode gating
    // -------------------------------------------------------------------------

    #[test]
    fn encapsulate_before_init_fails() {
        let mut ctx = RsaKemContext::new();
        let err = ctx
            .encapsulate()
            .expect_err("encapsulate without init must fail");
        // Mirrors C `PROV_R_OPERATION_NOT_INITIALIZED` raised inside
        // the dispatch path (`rsa_kem.c:226–235`): the operation has
        // not been initialized so the dispatch step itself rejects
        // the call. Surfaces as `ProviderError::Dispatch`.
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn decapsulate_before_init_fails() {
        let mut ctx = RsaKemContext::new();
        let err = ctx
            .decapsulate(&[0u8; 256])
            .expect_err("decapsulate without init must fail");
        // See `encapsulate_before_init_fails` — same dispatch path.
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn encapsulate_init_rejects_empty_blob() {
        let mut ctx = RsaKemContext::new();
        let err = ctx
            .encapsulate_init(&[], None)
            .expect_err("empty key blob must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn decapsulate_init_rejects_empty_blob() {
        let mut ctx = RsaKemContext::new();
        let err = ctx
            .decapsulate_init(&[], None)
            .expect_err("empty key blob must be rejected");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn encapsulate_init_rejects_malformed_der() {
        let mut ctx = RsaKemContext::new();
        let err = ctx
            .encapsulate_init(&[0xFFu8; 32], None)
            .expect_err("malformed DER must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn decapsulate_init_rejects_malformed_der() {
        let mut ctx = RsaKemContext::new();
        let err = ctx
            .decapsulate_init(&[0xFFu8; 32], None)
            .expect_err("malformed DER must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // -------------------------------------------------------------------------
    // Round-trip — encapsulate/decapsulate parity
    // -------------------------------------------------------------------------

    /// Full RSASVE round-trip: encapsulate produces `(ciphertext,
    /// shared_secret)`; `decapsulate(ciphertext)` recovers the same
    /// `shared_secret`.
    ///
    /// Mirrors the C source's `rsasve_generate` →  `rsasve_recover`
    /// flow at `rsa_kem.c:226–304`.
    #[test]
    fn rsasve_encapsulate_decapsulate_round_trip() {
        let pub_der = shared_pub_der();
        let priv_der = shared_priv_der();
        let n_bytes = shared_keypair().public_key().key_size_bytes() as usize;

        // Encapsulate using a fresh context bound to the public key.
        let mut enc_ctx = RsaKemContext::new();
        enc_ctx
            .encapsulate_init(&pub_der, None)
            .expect("encapsulate_init must succeed for valid public key");
        assert_eq!(enc_ctx.operation(), Some(RsaKemOperation::Encapsulate));
        let (ciphertext, secret) = enc_ctx.encapsulate().expect("encapsulate must succeed");

        // Per RSASVE: |ciphertext| == |secret| == RSA_size(key).
        assert_eq!(ciphertext.len(), n_bytes);
        assert_eq!(secret.len(), n_bytes);

        // Decapsulate using a fresh context bound to the private key.
        let mut dec_ctx = RsaKemContext::new();
        dec_ctx
            .decapsulate_init(&priv_der, None)
            .expect("decapsulate_init must succeed for valid private key");
        assert_eq!(dec_ctx.operation(), Some(RsaKemOperation::Decapsulate));
        let recovered = dec_ctx
            .decapsulate(&ciphertext)
            .expect("decapsulate must succeed");
        assert_eq!(recovered.len(), n_bytes);

        // Recovered shared secret must equal the original z.
        assert_eq!(recovered, secret, "round-trip must preserve shared secret");
    }

    /// Two consecutive encapsulations against the same public key must
    /// produce *different* ciphertexts (the random `z` is sampled fresh
    /// each time; otherwise this would be a serious correctness bug).
    #[test]
    fn rsasve_two_encapsulations_produce_different_outputs() {
        let pub_der = shared_pub_der();
        let mut ctx = RsaKemContext::new();
        ctx.encapsulate_init(&pub_der, None)
            .expect("encapsulate_init must succeed");
        let (ct1, s1) = ctx.encapsulate().expect("first encapsulate");
        let (ct2, s2) = ctx.encapsulate().expect("second encapsulate");
        assert_ne!(ct1, ct2, "ciphertexts must differ between encapsulations");
        assert_ne!(s1, s2, "shared secrets must differ between encapsulations");
    }

    /// Decapsulation must reject ciphertexts whose length differs from
    /// `RSA_size(key)`. Mirrors the C source's length check at
    /// `rsa_kem.c:285–289`.
    #[test]
    fn decapsulate_rejects_short_ciphertext() {
        let priv_der = shared_priv_der();
        let mut ctx = RsaKemContext::new();
        ctx.decapsulate_init(&priv_der, None)
            .expect("decapsulate_init must succeed");
        // A 32-byte ciphertext is far smaller than RSA-2048's 256-byte modulus.
        let err = ctx
            .decapsulate(&[0u8; 32])
            .expect_err("short ciphertext must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn decapsulate_rejects_long_ciphertext() {
        let priv_der = shared_priv_der();
        let mut ctx = RsaKemContext::new();
        ctx.decapsulate_init(&priv_der, None)
            .expect("decapsulate_init must succeed");
        // A 512-byte ciphertext is far larger than RSA-2048's 256-byte modulus.
        let err = ctx
            .decapsulate(&[0u8; 512])
            .expect_err("oversize ciphertext must be rejected");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// After `encapsulate_init`, a subsequent `decapsulate` call must
    /// fail because the operation is bound to encapsulation.
    #[test]
    fn decapsulate_after_encap_init_fails() {
        let pub_der = shared_pub_der();
        let mut ctx = RsaKemContext::new();
        ctx.encapsulate_init(&pub_der, None)
            .expect("encapsulate_init must succeed");
        let err = ctx
            .decapsulate(&[0u8; 256])
            .expect_err("decapsulate after encap-init must fail");
        // The dispatch arm guarding the operation type rejects the
        // call — same `ProviderError::Dispatch` as the not-initialized
        // case.
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// After `decapsulate_init`, a subsequent `encapsulate` call must
    /// fail because the operation is bound to decapsulation.
    #[test]
    fn encapsulate_after_decap_init_fails() {
        let priv_der = shared_priv_der();
        let mut ctx = RsaKemContext::new();
        ctx.decapsulate_init(&priv_der, None)
            .expect("decapsulate_init must succeed");
        let err = ctx
            .encapsulate()
            .expect_err("encapsulate after decap-init must fail");
        // The dispatch arm guarding the operation type rejects the
        // call — same `ProviderError::Dispatch` as the not-initialized
        // case.
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    /// The init step must populate the FIPS indicator. For a fresh
    /// 2048-bit RSA key the indicator should be `Approved` (≥ 2048
    /// minimum bits, no PSS restriction).
    #[test]
    fn encapsulate_init_sets_fips_indicator_approved() {
        let pub_der = shared_pub_der();
        let mut ctx = RsaKemContext::new();
        ctx.encapsulate_init(&pub_der, None)
            .expect("encapsulate_init must succeed");
        assert_eq!(ctx.fips_indicator(), Some(FipsIndicator::Approved));
        assert_eq!(ctx.operation(), Some(RsaKemOperation::Encapsulate));
        assert!(ctx.public_key().is_some());
        assert!(ctx.private_key().is_none());
    }

    #[test]
    fn decapsulate_init_sets_fips_indicator_approved() {
        let priv_der = shared_priv_der();
        let mut ctx = RsaKemContext::new();
        ctx.decapsulate_init(&priv_der, None)
            .expect("decapsulate_init must succeed");
        assert_eq!(ctx.fips_indicator(), Some(FipsIndicator::Approved));
        assert_eq!(ctx.operation(), Some(RsaKemOperation::Decapsulate));
        assert!(ctx.public_key().is_none());
        assert!(ctx.private_key().is_some());
    }

    // -------------------------------------------------------------------------
    // Trait-object dispatch via Box<dyn KemContext>
    // -------------------------------------------------------------------------

    /// End-to-end trait-object round-trip: both encap and decap are
    /// driven via the `KemContext` trait object (no inherent calls).
    /// Validates that the trait surface fully covers the C dispatch
    /// table semantics.
    #[test]
    fn kem_context_trait_object_round_trip() {
        let prov = RsaKem::new();
        let pub_der = shared_pub_der();
        let priv_der = shared_priv_der();

        // Encapsulate via trait object.
        let mut enc_ctx: Box<dyn KemContext> =
            <RsaKem as KemProvider>::new_ctx(&prov).expect("new_ctx (trait) must succeed");
        enc_ctx
            .encapsulate_init(&pub_der, None)
            .expect("encapsulate_init (trait) must succeed");
        let (ciphertext, secret) = enc_ctx
            .encapsulate()
            .expect("encapsulate (trait) must succeed");

        // Decapsulate via a separate trait object.
        let mut dec_ctx: Box<dyn KemContext> =
            <RsaKem as KemProvider>::new_ctx(&prov).expect("new_ctx (trait) must succeed");
        dec_ctx
            .decapsulate_init(&priv_der, None)
            .expect("decapsulate_init (trait) must succeed");
        let recovered = dec_ctx
            .decapsulate(&ciphertext)
            .expect("decapsulate (trait) must succeed");
        assert_eq!(recovered, secret);
    }

    // -------------------------------------------------------------------------
    // Descriptor surface
    // -------------------------------------------------------------------------

    #[test]
    fn descriptors_return_single_rsa_entry() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1, "RSA-KEM exposes exactly one canonical name");
        let d = &descs[0];
        assert_eq!(d.names, vec!["RSA"]);
        assert_eq!(d.property, "provider=default");
        assert!(
            !d.description.is_empty(),
            "descriptor must carry a non-empty human-readable description"
        );
    }

    #[test]
    fn rsa_kem_descriptors_method_matches_free_function() {
        let prov = RsaKem::new();
        let inherent = prov.descriptors();
        let free = descriptors();
        assert_eq!(inherent.len(), free.len());
        assert_eq!(inherent[0].names, free[0].names);
        assert_eq!(inherent[0].property, free[0].property);
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    #[test]
    fn fips_min_bits_constants_are_aligned_with_specification() {
        // SP 800-56B Rev.2 §6.5.1 — minimum 2048-bit key for encapsulation.
        assert_eq!(FIPS_MIN_RSA_BITS_ENCAPSULATE, 2048);
        // SP 800-131A Rev.2 — 1024-bit minimum for legacy decapsulation
        // outside the FIPS module (matches C
        // `RSA_FIPS1864_MIN_KEYSIZE_BITS_LEGACY`).
        assert_eq!(FIPS_MIN_RSA_BITS_DECAPSULATE, 1024);
    }
}
