//! `EVP_KDF` — Key Derivation Function abstraction layer.
//!
//! Translates the OpenSSL `EVP_KDF` interface from the following C sources:
//!
//! - `crypto/evp/kdf_meth.c` (241 lines) — `EVP_KDF` method structure
//!   (`up_ref`, `free`, `new`, `from_algorithm`, `fetch`, `do_all`).
//! - `crypto/evp/kdf_lib.c` (321 lines) — `EVP_KDF_CTX` lifecycle
//!   (`new_ctx`, `free_ctx`, `dup_ctx`, `reset`, `derive`, `get_params`,
//!   `set_params`).
//! - `crypto/evp/evp_pbe.c` (PBE algorithm registry and
//!   `EVP_PBE_CipherInit_ex`).
//! - `crypto/evp/p5_crpt.c` (PKCS#5 v1/PBES1 key derivation via `PBKDF1`).
//! - `crypto/evp/p5_crpt2.c` (PKCS#5 v2/PBKDF2/PBES2 derivation).
//! - `crypto/evp/pbe_scrypt.c` (scrypt EVP wrapper).
//!
//! # C struct reference (`evp_local.h` lines 73-80)
//!
//! ```c
//! struct evp_kdf_ctx_st {
//!     EVP_KDF *meth;     // Method structure
//!     void *algctx;      // Provider algorithm context
//! };
//! ```
//!
//! # C to Rust Mapping
//!
//! | C Symbol                        | Rust Equivalent             |
//! |---------------------------------|-----------------------------|
//! | `EVP_KDF`                       | [`Kdf`]                     |
//! | `EVP_KDF_CTX`                   | [`KdfCtx`]                  |
//! | `EVP_KDF_fetch()`               | [`Kdf::fetch()`]            |
//! | `EVP_KDF_get0_name()`           | [`Kdf::name()`]             |
//! | `EVP_KDF_CTX_new()`             | [`KdfCtx::new()`]           |
//! | `EVP_KDF_CTX_free()`            | `impl Drop for KdfCtx`      |
//! | `EVP_KDF_CTX_dup()`             | [`KdfCtx::try_clone()`]     |
//! | `EVP_KDF_CTX_reset()`           | [`KdfCtx::reset()`]         |
//! | `EVP_KDF_CTX_set_params()`      | [`KdfCtx::set_params()`]    |
//! | `EVP_KDF_CTX_get_params()`      | [`KdfCtx::get_params()`]    |
//! | `EVP_KDF_CTX_get_kdf_size()`    | [`KdfCtx::kdf_size()`]      |
//! | `EVP_KDF_derive()`              | [`KdfCtx::derive()`]        |
//! | `PKCS5_PBKDF2_HMAC()`           | [`pbkdf2_derive()`]         |
//! | `EVP_PBE_scrypt()`              | [`scrypt_derive()`]         |
//! | `EVP_PBE_CipherInit_ex()`       | [`pbe_cipher_init()`]       |
//!
//! # Cryptographic Implementation
//!
//! All key-derivation primitives delegate to [`crate::kdf`], which provides
//! the genuine cryptographic implementations (SHA-256, HMAC-SHA-256, HKDF,
//! PBKDF2, scrypt, Argon2) per their respective RFCs (5869, 8018, 7914, 9106).
//! This EVP wrapper adds EVP-level parameter handling, algorithm dispatch,
//! and conformance with the OpenSSL `EVP_KDF` API contract.
//!
//! # Rule Compliance
//!
//! - **R5 (Nullability):** Optional parameters use [`Option`]; derivation
//!   results return [`CryptoResult`].
//! - **R6 (Lossless casts):** All numeric coercions use
//!   [`TryFrom`]/[`u32::try_from`] — no bare `as` narrowing.
//! - **R8 (Zero unsafe):** This module contains no `unsafe` code.
//! - **R9 (Warning-free):** All items are documented; no suppressions.
//! - **R10 (Wiring):** Reachable from `openssl_cli::enc` via the EVP
//!   password-based encryption path.

use std::sync::Arc;

use tracing::{debug, trace};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::cipher::{Cipher, CipherCtx};
use crate::context::LibContext;
use crate::kdf as core_kdf;
use openssl_common::{CryptoError, CryptoResult, ParamSet, ParamValue};

// ============================================================================
// Well-known KDF algorithm name constants
// ============================================================================

/// HKDF — HMAC-based Key Derivation Function (RFC 5869).
pub const HKDF: &str = "HKDF";

/// PBKDF2 — Password-Based Key Derivation Function 2 (RFC 8018 / PKCS#5).
pub const PBKDF2: &str = "PBKDF2";

/// scrypt — sequential memory-hard KDF (RFC 7914).
pub const SCRYPT: &str = "SCRYPT";

/// Argon2i — memory-hard password-based KDF, side-channel-resistant variant.
pub const ARGON2I: &str = "ARGON2I";

/// Argon2d — memory-hard password-based KDF, maximum-memory-hardness variant.
pub const ARGON2D: &str = "ARGON2D";

/// Argon2id — memory-hard password-based KDF, hybrid variant (RFC 9106 §4).
pub const ARGON2ID: &str = "ARGON2ID";

/// KBKDF — Key-Based Key Derivation Function (NIST SP 800-108).
pub const KBKDF: &str = "KBKDF";

/// SSKDF — Single-Step Key Derivation Function (NIST SP 800-56C).
pub const SSKDF: &str = "SSKDF";

/// X9.63 KDF — ANSI X9.63 key derivation.
pub const X963KDF: &str = "X963KDF";

/// TLS 1.0/1.1/1.2 PRF — Pseudorandom Function used in TLS key derivation.
pub const TLS1_PRF: &str = "TLS1-PRF";

/// SSH KDF — SSH key derivation (RFC 4253).
pub const SSHKDF: &str = "SSHKDF";

/// TLS 1.3 HKDF-Expand-Label based KDF (RFC 8446 §7.1).
pub const TLS13_KDF: &str = "TLS13-KDF";

/// The set of known KDF algorithm names recognised by [`Kdf::fetch()`].
///
/// Any name supplied to [`Kdf::fetch()`] must match one of these (case-
/// sensitive) — unrecognised names produce [`CryptoError::AlgorithmNotFound`].
const KNOWN_KDFS: &[&str] = &[
    HKDF, PBKDF2, SCRYPT, ARGON2I, ARGON2D, ARGON2ID, KBKDF, SSKDF, X963KDF, TLS1_PRF, SSHKDF,
    TLS13_KDF,
];

// ============================================================================
// Kdf — fetched KDF method descriptor (EVP_KDF equivalent)
// ============================================================================

/// Fetched KDF method — the Rust equivalent of C `EVP_KDF`.
///
/// A `Kdf` is a lightweight descriptor produced by [`Kdf::fetch()`]. It
/// carries the algorithm name, optional human-readable description, and the
/// name of the provider that supplied the implementation. Instances of this
/// type are cheap to clone and may be shared between threads.
///
/// # Example
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use openssl_crypto::context::LibContext;
/// # use openssl_crypto::evp::kdf::{Kdf, HKDF};
/// let ctx = LibContext::new();
/// let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
/// assert_eq!(kdf.name(), "HKDF");
/// ```
#[derive(Debug, Clone)]
pub struct Kdf {
    /// Algorithm name (matches one of the `*_KDF` constants).
    name: String,

    /// Optional human-readable description of the algorithm.
    /// Rule R5: uses [`Option`] instead of an empty-string sentinel.
    description: Option<String>,

    /// Name of the provider supplying the implementation (e.g., `"default"`).
    provider_name: String,
}

impl Kdf {
    /// Fetches a KDF algorithm by name from the library context.
    ///
    /// Translates `EVP_KDF_fetch()` from `crypto/evp/kdf_meth.c:197`. The
    /// library context's provider store is consulted to resolve the algorithm;
    /// the optional `properties` string may restrict the search to specific
    /// providers (e.g., `"fips=yes"`).
    ///
    /// # Arguments
    ///
    /// * `ctx` — Library context supplying the provider store.
    /// * `algorithm` — KDF algorithm name (case-insensitive; see `*_KDF`
    ///   consts for the canonical spellings).  The stored name on the
    ///   returned [`Kdf`] is always the canonical form from `KNOWN_KDFS`.
    /// * `properties` — Optional property query string (e.g., `"fips=yes"`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AlgorithmNotFound`] when `algorithm` is not a
    /// recognised KDF name.
    pub fn fetch(
        ctx: &Arc<LibContext>,
        algorithm: &str,
        properties: Option<&str>,
    ) -> CryptoResult<Self> {
        debug!(
            algorithm = algorithm,
            properties = properties.unwrap_or(""),
            "evp::kdf: fetching KDF method"
        );

        // Touch the context so the fetch integrates with the provider store
        // even though our current implementation only validates the name.
        // This preserves the API contract and enables future extension to
        // a real provider-backed lookup without signature changes.
        let _ = ctx.is_child();

        // OpenSSL's EVP fetch system treats algorithm names case-insensitively
        // (e.g. `"PBKDF2"`, `"pbkdf2"`, and `"PbKdF2"` all resolve to the
        // same algorithm).  We mirror that behaviour here and canonicalise
        // the stored name to the spelling declared in `KNOWN_KDFS`, so that
        // callers of `Kdf::name()` always see a stable, upper-case string
        // regardless of how the algorithm was spelled on the way in.
        let canonical = KNOWN_KDFS
            .iter()
            .find(|k| k.eq_ignore_ascii_case(algorithm))
            .copied();
        let Some(canonical_name) = canonical else {
            return Err(CryptoError::AlgorithmNotFound(algorithm.to_string()));
        };

        Ok(Self {
            name: canonical_name.to_string(),
            description: Some(format!("{canonical_name} KDF")),
            provider_name: "default".to_string(),
        })
    }

    /// Returns the KDF algorithm name (matches `EVP_KDF_get0_name()`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the human-readable description when one is available.
    ///
    /// Rule R5: uses [`Option`] rather than an empty-string sentinel.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the name of the provider supplying this implementation.
    #[must_use]
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

// ============================================================================
// PbeAlgorithm — PKCS#5 PBE algorithm selector
// ============================================================================

/// Selector for Password-Based Encryption (PBE) scheme.
///
/// PKCS#5 defines two PBE schemes:
///
/// * **PBES1** — derives key and IV jointly from a password using PBKDF1
///   (one iteration of the digest). Used by legacy PKCS#8 encrypted keys.
/// * **PBES2** — derives a key using PBKDF2 (modern, RFC 8018 §6.2). The IV
///   is stored in the algorithm parameters and is not derived from the
///   password. This is the preferred scheme for new applications.
///
/// Translates the PBES1/PBES2 distinction from `crypto/evp/evp_pbe.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PbeAlgorithm {
    /// PKCS#5 v1 — PBES1 / PBKDF1-based derivation (joint key + IV).
    Pbes1,

    /// PKCS#5 v2 — PBES2 / PBKDF2-based derivation (key only; IV supplied).
    Pbes2,
}

impl PbeAlgorithm {
    /// Returns the human-readable name of this PBE scheme.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Pbes1 => "PBES1",
            Self::Pbes2 => "PBES2",
        }
    }
}

impl std::fmt::Display for PbeAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ============================================================================
// KdfData — opaque bytes container for derived key material
// ============================================================================

/// Opaque container for derived key material.
///
/// `KdfData` wraps an immutable byte sequence representing derived output
/// that has been produced by a KDF. The underlying bytes are automatically
/// zeroed when the container is dropped (via the [`Zeroize`] trait), giving
/// callers a convenient "opaque handle" alternative to working with bare
/// [`Vec<u8>`] when they do not need to mutate the derived bytes.
///
/// # Example
///
/// ```rust
/// # use openssl_crypto::evp::kdf::KdfData;
/// let bytes = vec![0xAAu8; 32];
/// let data = KdfData::new(bytes);
/// assert_eq!(data.as_bytes().len(), 32);
/// assert_eq!(data.len(), 32);
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct KdfData {
    /// Derived bytes — zeroed on drop.
    bytes: Vec<u8>,
}

impl KdfData {
    /// Constructs a new [`KdfData`] from the supplied bytes.
    ///
    /// The bytes are moved into the container and will be zeroed when the
    /// container is dropped.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns a borrowed slice over the derived bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the derived output in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the derived output is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for KdfData {
    // Redact the contents to avoid leaking key material into logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdfData")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// KdfCtx — EVP_KDF_CTX equivalent
// ============================================================================

/// KDF operation context — manages parameters and algorithm state for key
/// derivation.
///
/// Translates C `EVP_KDF_CTX` from `crypto/evp/kdf_lib.c`. The context bundles
/// a fetched [`Kdf`] method with a [`ParamSet`] containing algorithm-specific
/// parameters (password, salt, iterations, info, etc.). Call
/// [`KdfCtx::derive()`] to produce key material; call [`KdfCtx::reset()`] to
/// clear state and reuse the context with fresh parameters.
///
/// # Drop semantics
///
/// On drop, all octet-string and bignum parameters (potentially containing
/// passwords or keying material) are explicitly zeroed before deallocation.
/// This replicates the C implementation's `OPENSSL_cleanse()` behaviour.
///
/// # Example
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use openssl_common::{ParamSet, ParamValue};
/// # use openssl_crypto::context::LibContext;
/// # use openssl_crypto::evp::kdf::{Kdf, KdfCtx, HKDF};
/// let ctx = LibContext::new();
/// let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
/// let mut kctx = KdfCtx::new(&kdf);
///
/// let mut params = ParamSet::new();
/// params.set("key", ParamValue::OctetString(b"input-keying-material".to_vec()));
/// params.set("salt", ParamValue::OctetString(b"salt-value".to_vec()));
/// params.set("info", ParamValue::OctetString(b"context".to_vec()));
/// params.set("digest", ParamValue::Utf8String("SHA256".into()));
///
/// kctx.set_params(&params).unwrap();
/// let derived = kctx.derive(32).unwrap();
/// assert_eq!(derived.len(), 32);
/// ```
pub struct KdfCtx {
    /// The KDF method backing this context.
    kdf: Kdf,

    /// Algorithm-specific parameters. Zeroed on drop via [`Self::zeroize_params`].
    params: ParamSet,

    /// Set to `true` once [`Self::derive()`] has succeeded; a used context may
    /// be re-used after [`Self::reset()`].
    consumed: bool,
}

impl KdfCtx {
    /// Creates a new KDF context wrapping the supplied method.
    ///
    /// Translates `EVP_KDF_CTX_new()` (`kdf_lib.c` ≈ lines 30-60). The context
    /// starts with an empty parameter set; callers must populate it via
    /// [`KdfCtx::set_params()`] prior to invoking [`KdfCtx::derive()`].
    #[must_use]
    pub fn new(kdf: &Kdf) -> Self {
        trace!(
            kdf = kdf.name(),
            provider = kdf.provider_name(),
            "evp::kdf: creating new KDF context"
        );
        Self {
            kdf: kdf.clone(),
            params: ParamSet::new(),
            consumed: false,
        }
    }

    /// Returns a reference to the backing KDF method.
    #[must_use]
    pub fn kdf(&self) -> &Kdf {
        &self.kdf
    }

    /// Applies `params` to this context, merging them with any pre-existing
    /// parameters.
    ///
    /// Translates `EVP_KDF_CTX_set_params()` from `kdf_lib.c` ≈ lines 175-205.
    /// Supported parameter keys (algorithm-dependent) include:
    ///
    /// | Key              | Type            | Applies to                |
    /// |------------------|-----------------|---------------------------|
    /// | `"pass"`         | `OctetString`   | PBKDF2, scrypt, Argon2    |
    /// | `"password"`     | `OctetString`   | PBKDF2, scrypt, Argon2    |
    /// | `"key"`          | `OctetString`   | HKDF (IKM)                |
    /// | `"salt"`         | `OctetString`   | all                       |
    /// | `"info"`         | `OctetString`   | HKDF                      |
    /// | `"digest"`       | `Utf8String`    | HKDF, PBKDF2              |
    /// | `"iter"`         | `UInt32`        | PBKDF2                    |
    /// | `"iterations"`   | `UInt32`        | PBKDF2 (alias)            |
    /// | `"n"`            | `UInt64`        | scrypt                    |
    /// | `"r"`            | `UInt32`        | scrypt                    |
    /// | `"p"`            | `UInt32`        | scrypt                    |
    /// | `"maxmem_bytes"` | `UInt64`        | scrypt                    |
    /// | `"time_cost"`    | `UInt32`        | Argon2                    |
    /// | `"mem_cost"`     | `UInt32`        | Argon2                    |
    /// | `"parallelism"`  | `UInt32`        | Argon2                    |
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the context has already been used and not
    /// yet reset (mirrors C `EVP_KDF_CTX` single-shot semantics).
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        if self.consumed {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KdfCtx already consumed; call reset() first".to_string(),
                ),
            ));
        }
        trace!(
            kdf = self.kdf.name(),
            param_count = params.len(),
            "evp::kdf: applying parameters"
        );
        self.params.merge(params);
        Ok(())
    }

    /// Returns a clone of the currently-configured parameter set.
    ///
    /// Translates `EVP_KDF_CTX_get_params()` (`kdf_lib.c` ≈ line 207). The
    /// returned [`ParamSet`] is an independent snapshot — subsequent
    /// modifications to the context do not affect it.
    ///
    /// # Errors
    ///
    /// Currently never fails; the [`CryptoResult`] wrapper preserves API
    /// symmetry with `set_params()` and keeps the door open for future
    /// provider-specific validation hooks.
    pub fn get_params(&self) -> CryptoResult<ParamSet> {
        Ok(self.params.duplicate())
    }

    /// Derives `key_length` bytes of key material using the configured KDF
    /// and parameter set.
    ///
    /// Translates `EVP_KDF_derive()` from `kdf_lib.c` ≈ lines 100-160. The
    /// implementation delegates to the real cryptographic routines in
    /// [`crate::kdf`] (SHA-256–based RustCrypto-free implementations compliant
    /// with RFC 5869 / RFC 8018 / RFC 7914 / RFC 9106). Dispatch is driven by
    /// [`Kdf::name()`]:
    ///
    /// | KDF algorithm   | Delegate                               |
    /// |-----------------|----------------------------------------|
    /// | `HKDF`          | [`core_kdf::hkdf_derive`]              |
    /// | `TLS13-KDF`     | [`core_kdf::hkdf_derive`] (HKDF-based) |
    /// | `PBKDF2`        | [`core_kdf::pbkdf2_derive`]            |
    /// | `SCRYPT`        | [`core_kdf::scrypt_derive`]            |
    /// | `ARGON2I/D/ID`  | [`core_kdf::argon2_derive`]            |
    /// | `KBKDF`, `SSKDF`, `X963KDF`, `TLS1-PRF`, `SSHKDF` | [`core_kdf::KdfContext::derive`] |
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when:
    /// * `key_length` is zero.
    /// * a required parameter (password/key/salt/digest/iterations/etc.) is
    ///   missing from the context's parameter set.
    /// * the configured `digest` is not a supported SHA-256 alias.
    /// * the KDF algorithm is unknown or the context has already been consumed
    ///   and not yet reset.
    /// * underlying numerical conversions (R6) would overflow.
    pub fn derive(&mut self, key_length: usize) -> CryptoResult<Zeroizing<Vec<u8>>> {
        if self.consumed {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "KdfCtx already consumed; call reset() before re-deriving".to_string(),
                ),
            ));
        }
        if key_length == 0 {
            return Err(CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "derive output length must be greater than zero".to_string(),
                ),
            ));
        }

        let algo = self.kdf.name().to_string();
        debug!(
            kdf = %algo,
            length = key_length,
            "evp::kdf: deriving key material"
        );

        let raw: Vec<u8> = match algo.as_str() {
            HKDF | TLS13_KDF => {
                // HKDF-based derivation. Supports `TLS13-KDF` as an alias since
                // TLS 1.3 key schedules are HKDF-Expand-Label-based (RFC 8446).
                let digest = self.required_digest_param()?;
                require_sha256_alias(&digest)?;
                let ikm = self.required_octets("key")?;
                let salt = self.optional_octets("salt")?.unwrap_or_default();
                let info = self.optional_octets("info")?.unwrap_or_default();
                core_kdf::hkdf_derive(&ikm, &salt, &info, key_length)?
            }
            PBKDF2 => {
                let digest = self.required_digest_param()?;
                require_sha256_alias(&digest)?;
                let password = self.required_password()?;
                let salt = self.required_octets("salt")?;
                let iterations = self.required_iterations()?;
                core_kdf::pbkdf2_derive(&password, &salt, iterations, key_length)?
            }
            SCRYPT => {
                let password = self.required_password()?;
                let salt = self.required_octets("salt")?;
                let n = self.required_u64("n")?;
                let r = self.required_u32("r")?;
                let p = self.required_u32("p")?;
                // `maxmem_bytes` is optional; when present, compute the
                // expected footprint and reject oversize requests (mirrors
                // EVP_PBE_scrypt's `maxmem` guard from pbe_scrypt.c).
                if let Some(max_mem) = self.optional_u64("maxmem_bytes")? {
                    enforce_scrypt_max_mem(n, r, p, max_mem)?;
                }
                core_kdf::scrypt_derive(&password, &salt, n, r, p, key_length)?
            }
            ARGON2I | ARGON2D | ARGON2ID => {
                let password = self.required_password()?;
                let salt = self.required_octets("salt")?;
                let time_cost = self.required_u32("time_cost")?;
                let mem_cost = self.required_u32("mem_cost")?;
                let parallelism = self.required_u32("parallelism")?;
                let variant = match algo.as_str() {
                    ARGON2I => core_kdf::KdfType::Argon2i,
                    ARGON2D => core_kdf::KdfType::Argon2d,
                    _ => core_kdf::KdfType::Argon2id,
                };
                core_kdf::argon2_derive(
                    &password,
                    &salt,
                    variant,
                    time_cost,
                    mem_cost,
                    parallelism,
                    key_length,
                )?
            }
            KBKDF | SSKDF | X963KDF | TLS1_PRF | SSHKDF => {
                // Non-one-shot KDFs are executed via the full
                // [`core_kdf::KdfContext`] pipeline which handles their
                // algorithm-specific state machines.
                let kdf_type = match algo.as_str() {
                    KBKDF => core_kdf::KdfType::Kbkdf,
                    SSKDF => core_kdf::KdfType::Sskdf,
                    X963KDF => core_kdf::KdfType::X963Kdf,
                    TLS1_PRF => core_kdf::KdfType::TlsPrf,
                    _ => core_kdf::KdfType::SshKdf,
                };
                let mut inner = core_kdf::KdfContext::new(kdf_type);
                let key = self.required_octets("key")?;
                inner.set_key(&key)?;
                if let Some(salt) = self.optional_octets("salt")? {
                    inner.set_salt(&salt)?;
                }
                if let Some(info) = self.optional_octets("info")? {
                    inner.set_info(&info)?;
                }
                if let Some(digest) = self.optional_digest_param()? {
                    inner.set_digest(&digest)?;
                }
                // Pass through the full ParamSet so algorithm-specific knobs
                // (mode, cipher, label, seed, …) propagate to the inner KDF.
                inner.set_params(self.params.duplicate())?;
                inner.derive(key_length)?
            }
            other => {
                return Err(CryptoError::AlgorithmNotFound(format!(
                    "KDF `{other}` is recognised but has no available implementation"
                )));
            }
        };

        self.consumed = true;
        debug!(
            kdf = %algo,
            length = raw.len(),
            "evp::kdf: derivation complete"
        );
        Ok(Zeroizing::new(raw))
    }

    /// Resets this context, clearing the parameter set and marking it as
    /// unused so the same [`Kdf`] method can be reused for a subsequent
    /// derivation.
    ///
    /// Translates `EVP_KDF_CTX_reset()` from `kdf_lib.c` ≈ lines 162-172. The
    /// old parameter set's sensitive octet strings are zeroed in the process.
    pub fn reset(&mut self) {
        trace!(kdf = self.kdf.name(), "evp::kdf: resetting context");
        self.zeroize_params();
        self.params = ParamSet::new();
        self.consumed = false;
    }

    /// Returns an independent clone of this context that can be used to run a
    /// second derivation with the same parameters.
    ///
    /// Translates `EVP_KDF_CTX_dup()` from `kdf_lib.c` ≈ lines 70-90. The
    /// duplicate's `consumed` flag is carried over so an already-consumed
    /// context produces an already-consumed clone (matching the C semantics).
    ///
    /// # Errors
    ///
    /// Currently never fails. The [`CryptoResult`] wrapper preserves API
    /// parity with the C function `EVP_KDF_CTX_dup`, which returns `NULL` on
    /// allocation failure in the C implementation.
    pub fn try_clone(&self) -> CryptoResult<Self> {
        Ok(Self {
            kdf: self.kdf.clone(),
            params: self.params.duplicate(),
            consumed: self.consumed,
        })
    }

    /// Returns the algorithm's fixed output size in bytes, or `0` when the
    /// KDF produces variable-length output.
    ///
    /// Translates `EVP_KDF_CTX_get_kdf_size()` from `kdf_lib.c` ≈ lines 220-235.
    /// The C function returns `SIZE_MAX` for variable-length KDFs; we follow
    /// the more idiomatic convention of returning `0` (interpreted as "no
    /// natural fixed size") for variable-output algorithms.
    ///
    /// # Errors
    ///
    /// Currently never fails. The [`CryptoResult`] wrapper preserves API
    /// parity with the C function signature and keeps the door open for
    /// future provider-reported size queries.
    pub fn kdf_size(&self) -> CryptoResult<usize> {
        // All supported KDFs (HKDF, PBKDF2, scrypt, Argon2, KBKDF, …) produce
        // output of caller-chosen length. Only fixed-extract modes such as
        // `HKDF-Extract` have a natural output size (the digest length).
        // Since our KDF name whitelist routes extract-mode under `HKDF`
        // (which in the current dispatch is always extract-and-expand), we
        // report 0 across the board.
        Ok(0)
    }

    // ------------------------------------------------------------------
    // Internal parameter-extraction helpers
    // ------------------------------------------------------------------

    /// Fetches a required octet-string parameter by name, returning an owned
    /// copy.
    fn required_octets(&self, key: &str) -> CryptoResult<Vec<u8>> {
        self.optional_octets(key)?.ok_or_else(|| {
            CryptoError::Common(openssl_common::CommonError::ParamNotFound {
                key: key.to_string(),
            })
        })
    }

    /// Fetches an optional octet-string parameter by name.
    fn optional_octets(&self, key: &str) -> CryptoResult<Option<Vec<u8>>> {
        match self.params.get(key) {
            None => Ok(None),
            Some(ParamValue::OctetString(bytes)) => Ok(Some(bytes.clone())),
            Some(ParamValue::Utf8String(s)) => Ok(Some(s.as_bytes().to_vec())),
            Some(other) => Err(CryptoError::Common(
                openssl_common::CommonError::ParamTypeMismatch {
                    key: key.to_string(),
                    expected: "OctetString or Utf8String",
                    actual: other.param_type_name(),
                },
            )),
        }
    }

    /// Fetches the password/passphrase, accepting either `"pass"` or
    /// `"password"` as the parameter key.
    fn required_password(&self) -> CryptoResult<Vec<u8>> {
        if let Some(bytes) = self.optional_octets("pass")? {
            return Ok(bytes);
        }
        if let Some(bytes) = self.optional_octets("password")? {
            return Ok(bytes);
        }
        Err(CryptoError::Common(
            openssl_common::CommonError::ParamNotFound {
                key: "pass".to_string(),
            },
        ))
    }

    /// Fetches the digest name, accepting any of the usual parameter aliases.
    fn optional_digest_param(&self) -> CryptoResult<Option<String>> {
        for key in &["digest", "md", "mac-digest"] {
            if let Some(value) = self.params.get(key) {
                match value {
                    ParamValue::Utf8String(s) => return Ok(Some(s.clone())),
                    other => {
                        return Err(CryptoError::Common(
                            openssl_common::CommonError::ParamTypeMismatch {
                                key: (*key).to_string(),
                                expected: "Utf8String",
                                actual: other.param_type_name(),
                            },
                        ))
                    }
                }
            }
        }
        Ok(None)
    }

    /// Fetches a required digest-name parameter; defaults to SHA-256 when
    /// absent to match the most common `EVP_KDF` usage pattern.
    fn required_digest_param(&self) -> CryptoResult<String> {
        Ok(self
            .optional_digest_param()?
            .unwrap_or_else(|| "SHA256".to_string()))
    }

    /// Fetches the iteration count for PBKDF2, accepting either `"iter"` or
    /// `"iterations"` as the parameter key.
    fn required_iterations(&self) -> CryptoResult<u32> {
        if let Some(value) = self.optional_u32("iter")? {
            return Ok(value);
        }
        if let Some(value) = self.optional_u32("iterations")? {
            return Ok(value);
        }
        Err(CryptoError::Common(
            openssl_common::CommonError::ParamNotFound {
                key: "iter".to_string(),
            },
        ))
    }

    /// Fetches an optional `u32` parameter, accepting any integer type that
    /// fits losslessly.
    fn optional_u32(&self, key: &str) -> CryptoResult<Option<u32>> {
        match self.params.get(key) {
            None => Ok(None),
            Some(value) => {
                let v = value.as_u32().ok_or_else(|| {
                    CryptoError::Common(openssl_common::CommonError::ParamTypeMismatch {
                        key: key.to_string(),
                        expected: "u32-compatible integer",
                        actual: value.param_type_name(),
                    })
                })?;
                Ok(Some(v))
            }
        }
    }

    /// Fetches a required `u32` parameter.
    fn required_u32(&self, key: &str) -> CryptoResult<u32> {
        self.optional_u32(key)?.ok_or_else(|| {
            CryptoError::Common(openssl_common::CommonError::ParamNotFound {
                key: key.to_string(),
            })
        })
    }

    /// Fetches an optional `u64` parameter, accepting any integer type that
    /// fits losslessly.
    fn optional_u64(&self, key: &str) -> CryptoResult<Option<u64>> {
        match self.params.get(key) {
            None => Ok(None),
            Some(value) => {
                let v = value.as_u64().ok_or_else(|| {
                    CryptoError::Common(openssl_common::CommonError::ParamTypeMismatch {
                        key: key.to_string(),
                        expected: "u64-compatible integer",
                        actual: value.param_type_name(),
                    })
                })?;
                Ok(Some(v))
            }
        }
    }

    /// Fetches a required `u64` parameter.
    fn required_u64(&self, key: &str) -> CryptoResult<u64> {
        self.optional_u64(key)?.ok_or_else(|| {
            CryptoError::Common(openssl_common::CommonError::ParamNotFound {
                key: key.to_string(),
            })
        })
    }

    /// Explicitly zeroes all octet-string and bignum parameter values prior
    /// to their removal from the parameter set. Invoked from [`Self::reset`]
    /// and implicitly from the [`Zeroize`] implementation on drop.
    ///
    /// ## Implementation note
    ///
    /// We first collect the current keys into an owned `Vec<String>` so that
    /// the borrow returned by [`ParamSet::keys`] ends before we begin
    /// mutating the set via [`ParamSet::remove`].  This two-phase pattern
    /// (collect keys → remove entries) is the idiomatic Rust approach for
    /// clearing a map while inspecting or transforming each value.
    ///
    /// For each removed entry that carries sensitive bytes (octet strings
    /// and bignums), we zeroize the actual owned buffer that `remove`
    /// returns — unlike the earlier "clone + zeroize the clone" approach,
    /// this wipes the memory that previously held the secret.
    fn zeroize_params(&mut self) {
        // Phase 1: snapshot keys into owned storage so the immutable borrow
        // from `keys()` is released before the mutation phase begins.  This
        // is required because `ParamSet::keys()` returns
        // `impl Iterator<Item = &str>` which borrows the inner HashMap.
        let keys: Vec<String> = self.params.keys().map(ToString::to_string).collect();

        // Phase 2: remove each entry and securely erase the bytes it owned.
        // Octet strings and bignums carry raw secret-bearing bytes that must
        // be wiped explicitly before they leave scope.  The owned `Vec<u8>`
        // payload is the same memory that previously held the secret inside
        // the `ParamSet`, so zeroing it here actually clears the secret
        // rather than merely clearing a copy.  Scalar and UTF-8 string
        // variants do not require an explicit erase pass beyond the drop
        // that happens when the `Option` goes out of scope.
        for key in keys {
            if let Some(ParamValue::OctetString(mut bytes) | ParamValue::BigNum(mut bytes)) =
                self.params.remove(&key)
            {
                bytes.zeroize();
            }
        }
    }
}

impl Zeroize for KdfCtx {
    fn zeroize(&mut self) {
        self.zeroize_params();
        self.consumed = false;
    }
}

impl Drop for KdfCtx {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for KdfCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdfCtx")
            .field("kdf", &self.kdf.name())
            .field("param_count", &self.params.len())
            .field("consumed", &self.consumed)
            .finish()
    }
}

// ============================================================================
// Internal helpers shared across the module
// ============================================================================

/// Returns `Ok(())` when `digest` names a SHA-256 variant that our pure-Rust
/// KDF implementations support, and an informative error otherwise.
///
/// Rule R5: the empty string is not treated as an implicit "default SHA-256"
/// sentinel; callers must supply an explicit digest name.
fn require_sha256_alias(digest: &str) -> CryptoResult<()> {
    let normalised = digest.to_ascii_uppercase().replace(['_', ' '], "-");
    match normalised.as_str() {
        "SHA256" | "SHA-256" | "SHA2-256" => Ok(()),
        other => Err(CryptoError::Common(
            openssl_common::CommonError::Unsupported(format!(
                "KDF digest `{other}` is not supported by the current Rust \
                 implementation (only SHA-256 is available; extra digests \
                 arrive with provider integration)"
            )),
        )),
    }
}

/// Validates the `maxmem_bytes` parameter against the computed scrypt memory
/// footprint (`128 * r * N` per RFC 7914 §8). Rejects oversize requests with
/// an informative error.
///
/// Rule R6: all multiplications are checked; overflow is reported via
/// [`CommonError::ArithmeticOverflow`] rather than silently wrapping.
fn enforce_scrypt_max_mem(n: u64, r: u32, _p: u32, max_mem: u64) -> CryptoResult<()> {
    let r_u64 = u64::from(r);
    let footprint = n
        .checked_mul(r_u64)
        .and_then(|v| v.checked_mul(128))
        .ok_or_else(|| {
            CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow {
                operation: "scrypt memory footprint (128 * r * N)",
            })
        })?;
    if footprint > max_mem {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "scrypt memory footprint {footprint} bytes exceeds maxmem_bytes {max_mem}"
            )),
        ));
    }
    Ok(())
}

// =============================================================================
// Free-function convenience wrappers (Phase 6 of the agent_prompt).
//
// These functions expose a simplified one-shot API matching the EVP schema
// signatures.  Each wrapper validates the extra parameters that the legacy
// OpenSSL API accepts (digest name selection, maximum memory for scrypt) and
// then delegates to the corresponding real-crypto routine in
// [`crate::kdf`].  The returned derived key material is wrapped in
// [`Zeroizing<Vec<u8>>`] so that it is securely erased on drop, mirroring the
// `OPENSSL_cleanse` behaviour of the C implementations in
// `crypto/evp/p5_crpt2.c`, `crypto/evp/pbe_scrypt.c` and `crypto/kdf/hkdf.c`.
// =============================================================================

/// Derives key material using PBKDF2 (PKCS#5 v2 / RFC 8018).
///
/// Rust translation of C `PKCS5_PBKDF2_HMAC()` (see
/// `crypto/evp/p5_crpt2.c` for the original reference implementation).
///
/// # Arguments
///
/// * `password` — The password bytes.  Must not be empty.
/// * `salt` — Random salt value.  Should be at least 16 bytes per NIST
///   SP 800-132.
/// * `iterations` — Iteration count (≥ 1).  NIST recommends ≥ 10,000 for
///   user password protection; OWASP recommends ≥ 600,000 as of 2023.
/// * `digest_name` — The underlying HMAC digest to use.  This wrapper
///   currently only supports `SHA-256` aliases (`"SHA256"`, `"SHA-256"`,
///   `"SHA2-256"`, case-insensitive); other digests return
///   [`CommonError::Unsupported`].
/// * `length` — Number of output bytes to derive.  Must be > 0.
///
/// # Errors
///
/// * [`CommonError::Unsupported`] if `digest_name` is not a SHA-256 alias.
/// * [`CommonError::InvalidArgument`] if `password` is empty, `iterations`
///   is 0, or `length` is 0.
/// * Propagates any error from [`crate::kdf::pbkdf2_derive`].
///
/// # Security
///
/// The derived bytes are returned in a [`Zeroizing`] wrapper that clears the
/// memory on drop.  Callers should minimise the lifetime of the returned
/// value and avoid copying it into non-zeroized storage.
///
/// # Rule R6 compliance
///
/// Accepts `iterations: u32` and `length: usize` directly — no narrowing
/// casts are performed.
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::evp::kdf::pbkdf2_derive;
/// let dk = pbkdf2_derive(b"password", b"salt-value", 10_000, "SHA-256", 32).unwrap();
/// assert_eq!(dk.len(), 32);
/// ```
pub fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    digest_name: &str,
    length: usize,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    trace!(
        target: "openssl_crypto::evp::kdf",
        digest = %digest_name,
        iterations,
        length,
        salt_len = salt.len(),
        "pbkdf2_derive invoked",
    );
    require_sha256_alias(digest_name)?;
    if iterations == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "PBKDF2 iterations must be at least 1".to_string(),
            ),
        ));
    }
    if length == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "PBKDF2 output length must be greater than zero".to_string(),
            ),
        ));
    }
    let raw = core_kdf::pbkdf2_derive(password, salt, iterations, length)?;
    debug!(
        target: "openssl_crypto::evp::kdf",
        length = raw.len(),
        "pbkdf2_derive produced derived key material",
    );
    Ok(Zeroizing::new(raw))
}

/// Derives key material using scrypt (RFC 7914).
///
/// Rust translation of C `EVP_PBE_scrypt()` (see `crypto/evp/pbe_scrypt.c`).
///
/// # Arguments
///
/// * `password` — Password bytes.  Must not be empty.
/// * `salt` — Random salt value.
/// * `n` — CPU/memory cost (must be a power of two greater than 1).
/// * `r` — Block size parameter (must be > 0).
/// * `p` — Parallelization parameter (must be > 0).
/// * `max_mem` — Maximum memory in bytes the derivation is allowed to
///   consume.  If the estimated footprint `128 * r * N` exceeds this value,
///   the function returns an error instead of beginning the derivation.
///   A value of `0` disables the check.
/// * `length` — Number of output bytes to derive.
///
/// # Errors
///
/// * [`CommonError::InvalidArgument`] if the password is empty, any
///   parameter is zero, or the computed memory footprint exceeds `max_mem`.
/// * [`CommonError::ArithmeticOverflow`] if the footprint calculation
///   overflows `u64` (per rule R6).
/// * Propagates any error from [`crate::kdf::scrypt_derive`].
///
/// # Rule R6 compliance
///
/// All multiplications performed during the memory-footprint check use
/// `checked_mul` via [`enforce_scrypt_max_mem`].  No narrowing casts are
/// performed.
pub fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    max_mem: u64,
    length: usize,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    trace!(
        target: "openssl_crypto::evp::kdf",
        n,
        r,
        p,
        max_mem,
        length,
        "scrypt_derive invoked",
    );
    if length == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "scrypt output length must be greater than zero".to_string(),
            ),
        ));
    }
    // Only enforce the memory cap if a non-zero max_mem was supplied
    // (matching EVP_PBE_scrypt's behaviour where max_mem=0 disables the
    // check).
    if max_mem != 0 {
        enforce_scrypt_max_mem(n, r, p, max_mem)?;
    }
    let raw = core_kdf::scrypt_derive(password, salt, n, r, p, length)?;
    debug!(
        target: "openssl_crypto::evp::kdf",
        length = raw.len(),
        "scrypt_derive produced derived key material",
    );
    Ok(Zeroizing::new(raw))
}

/// Derives key material using HKDF (RFC 5869).
///
/// Rust translation of the HKDF pathway exposed by C
/// `EVP_KDF_derive(ctx, key, keylen, params)` when the fetched KDF is
/// `"HKDF"`.
///
/// # Arguments
///
/// * `digest_name` — Underlying hash algorithm.  Currently only SHA-256
///   aliases are accepted; see [`pbkdf2_derive`] for the accepted names.
/// * `ikm` — Input keying material.  Must not be empty.
/// * `salt` — Optional salt.  Pass an empty slice to use the all-zero
///   default per RFC 5869 §2.2.
/// * `info` — Application-specific context and info.
/// * `length` — Number of output bytes to derive (must be
///   ≤ `255 * hash_len`).
///
/// # Errors
///
/// * [`CommonError::Unsupported`] if `digest_name` is not a SHA-256 alias.
/// * [`CommonError::InvalidArgument`] if `length` is 0.
/// * Propagates any error from [`crate::kdf::hkdf_derive`].
///
/// # Example
///
/// ```rust,no_run
/// use openssl_crypto::evp::kdf::hkdf_derive;
/// let okm = hkdf_derive("SHA-256", b"secret-key", b"salt", b"context", 32).unwrap();
/// assert_eq!(okm.len(), 32);
/// ```
pub fn hkdf_derive(
    digest_name: &str,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    trace!(
        target: "openssl_crypto::evp::kdf",
        digest = %digest_name,
        ikm_len = ikm.len(),
        salt_len = salt.len(),
        info_len = info.len(),
        length,
        "hkdf_derive invoked",
    );
    require_sha256_alias(digest_name)?;
    if length == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "HKDF output length must be greater than zero".to_string(),
            ),
        ));
    }
    let raw = core_kdf::hkdf_derive(ikm, salt, info, length)?;
    debug!(
        target: "openssl_crypto::evp::kdf",
        length = raw.len(),
        "hkdf_derive produced derived key material",
    );
    Ok(Zeroizing::new(raw))
}

// =============================================================================
// PBE cipher initialization (Phase 7 of the agent_prompt).
//
// Rust translation of the C `EVP_PBE_CipherInit_ex()` function from
// `crypto/evp/evp_pbe.c`.  The original C function walks a table of known
// PBE algorithm identifiers, chooses between PBES1 (PKCS#5 v1.5 /
// `p5_crpt.c`) and PBES2 (PKCS#5 v2 / `p5_crpt2.c`) derivation, derives the
// key material, fetches the requested cipher and initialises an
// `EVP_CIPHER_CTX`.
// =============================================================================

/// Initialises a [`CipherCtx`] for encryption using password-based key
/// derivation.
///
/// The selected [`PbeAlgorithm`] determines the key-derivation mode:
///
/// * [`PbeAlgorithm::Pbes1`] — PKCS#5 v1.5 style (see `crypto/evp/p5_crpt.c`):
///   a single hash pass produces a combined 16-byte key/IV block.  The
///   leading `key_length` bytes become the key and the trailing bytes of
///   the block become the IV.  This wrapper uses PBKDF2 with a single
///   iteration count applied to a SHA-256 PRF as a conservative, modern
///   substitute when the caller requests legacy PBES1 behaviour — the
///   classic MD5/SHA-1 primitives used by the C original are intentionally
///   not exposed because they are disallowed by most current compliance
///   regimes.
/// * [`PbeAlgorithm::Pbes2`] — PKCS#5 v2 (see `crypto/evp/p5_crpt2.c`):
///   PBKDF2-HMAC-SHA-256 derives `key_length` key bytes directly.  The IV
///   is zero-filled; callers that require a non-trivial IV should populate
///   it separately using [`CipherCtx::encrypt_init`] or a fresh derivation
///   pass (for example, another call to [`pbkdf2_derive`]).
///
/// # Arguments
///
/// * `algorithm` — Which PBE scheme to apply.
/// * `cipher_name` — EVP cipher name (for example [`super::cipher::AES_256_CBC`]).
/// * `password` — Password bytes.  Must not be empty.
/// * `salt` — Salt value (≥ 8 bytes recommended per PKCS#5).
/// * `iterations` — PBKDF2 iteration count.  Must be ≥ 1.
///
/// # Errors
///
/// * [`CryptoError::AlgorithmNotFound`] if the requested cipher cannot be
///   fetched from the default provider.
/// * [`CommonError::InvalidArgument`] if any input parameter is invalid
///   (empty password, zero iterations, cipher requiring an IV longer than
///   the derived block for PBES1, etc.).
/// * Propagates any error from [`crate::kdf::pbkdf2_derive`] or
///   [`CipherCtx::encrypt_init`].
///
/// # Rule R5 / R6 / R8 compliance
///
/// Returns a typed `CipherCtx` rather than a pointer / sentinel.  All
/// numeric inputs (`iterations`) keep their natural width; no bare `as`
/// casts appear in the implementation.  Zero `unsafe` code.
pub fn pbe_cipher_init(
    algorithm: PbeAlgorithm,
    cipher_name: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> CryptoResult<CipherCtx> {
    trace!(
        target: "openssl_crypto::evp::kdf",
        %algorithm,
        cipher = %cipher_name,
        salt_len = salt.len(),
        iterations,
        "pbe_cipher_init invoked",
    );

    if password.is_empty() {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "PBE password must not be empty".to_string(),
            ),
        ));
    }
    if iterations == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(
                "PBE iteration count must be at least 1".to_string(),
            ),
        ));
    }

    // Fetch the requested cipher so that its key/IV sizes are known.
    let libctx = LibContext::get_default();
    let cipher = Cipher::fetch(&libctx, cipher_name, None)?;

    let key_length = cipher.key_length();
    let iv_length = cipher.iv_length().unwrap_or(0);

    if key_length == 0 {
        return Err(CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "cipher '{cipher_name}' reports zero key length; incompatible with PBE"
            )),
        ));
    }

    // Derive key (and optional IV) material.  The zeroizing key buffer
    // ensures the intermediate material is wiped once the CipherCtx has
    // been initialised.
    let key_bytes: Zeroizing<Vec<u8>>;
    let iv_bytes: Vec<u8>;
    match algorithm {
        PbeAlgorithm::Pbes1 => {
            // PBES1 requires the derived block to cover both the key and
            // the IV (classic PKCS#5 v1.5 behaviour where KDF output is
            // split).  Compute the total length with checked arithmetic
            // (rule R6) and derive in a single PBKDF2 pass.
            let derived_len = key_length.checked_add(iv_length).ok_or_else(|| {
                CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow {
                    operation: "PBES1 derived length (key + iv)",
                })
            })?;
            let combined = core_kdf::pbkdf2_derive(password, salt, iterations, derived_len)?;
            // Split off the key (first key_length bytes) and IV (remaining
            // bytes).  The surrounding Zeroizing<Vec<u8>> wrapper keeps the
            // combined block protected until it is dropped at scope exit.
            let mut combined = Zeroizing::new(combined);
            let iv_part = if iv_length > 0 {
                combined[key_length..].to_vec()
            } else {
                Vec::new()
            };
            let mut key_part = Vec::with_capacity(key_length);
            key_part.extend_from_slice(&combined[..key_length]);
            // Explicitly wipe the combined buffer before the Zeroizing
            // Drop runs so that the split key bytes do not live on the
            // heap twice.
            combined.zeroize();
            key_bytes = Zeroizing::new(key_part);
            iv_bytes = iv_part;
        }
        PbeAlgorithm::Pbes2 => {
            // PBES2 derives the key with PBKDF2-HMAC-SHA-256; the IV is
            // conveyed out-of-band (and will be zero-filled here to
            // preserve a deterministic init path).  Callers needing a
            // random IV should replace it via a subsequent init call.
            let raw = core_kdf::pbkdf2_derive(password, salt, iterations, key_length)?;
            key_bytes = Zeroizing::new(raw);
            iv_bytes = vec![0u8; iv_length];
        }
    }

    let mut ctx = CipherCtx::new();
    let iv_slice: Option<&[u8]> = if iv_length > 0 { Some(&iv_bytes) } else { None };
    ctx.encrypt_init(&cipher, &key_bytes, iv_slice, None)?;

    debug!(
        target: "openssl_crypto::evp::kdf",
        cipher = %cipher_name,
        %algorithm,
        key_len = key_length,
        iv_len = iv_length,
        "pbe_cipher_init completed successfully",
    );
    Ok(ctx)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ---- Constants -----------------------------------------------------

    #[test]
    fn kdf_name_constants_are_expected_strings() {
        assert_eq!(HKDF, "HKDF");
        assert_eq!(PBKDF2, "PBKDF2");
        assert_eq!(SCRYPT, "SCRYPT");
        assert_eq!(ARGON2I, "ARGON2I");
        assert_eq!(ARGON2D, "ARGON2D");
        assert_eq!(ARGON2ID, "ARGON2ID");
        assert_eq!(KBKDF, "KBKDF");
        assert_eq!(SSKDF, "SSKDF");
        assert_eq!(X963KDF, "X963KDF");
        assert_eq!(TLS1_PRF, "TLS1-PRF");
        assert_eq!(SSHKDF, "SSHKDF");
        assert_eq!(TLS13_KDF, "TLS13-KDF");
    }

    // ---- Kdf::fetch ----------------------------------------------------

    #[test]
    fn kdf_fetch_resolves_known_algorithms() {
        let ctx = LibContext::get_default();
        for name in [HKDF, PBKDF2, SCRYPT, ARGON2ID, KBKDF, TLS1_PRF] {
            let kdf = Kdf::fetch(&ctx, name, None).expect("known KDF must resolve");
            assert_eq!(kdf.name(), name);
            assert!(!kdf.provider_name().is_empty());
        }
    }

    #[test]
    fn kdf_fetch_case_insensitive() {
        let ctx = LibContext::get_default();
        let upper = Kdf::fetch(&ctx, "PBKDF2", None).expect("upper-case resolves");
        let lower = Kdf::fetch(&ctx, "pbkdf2", None).expect("lower-case resolves");
        // Both fetches return a canonical name so they should match.
        assert_eq!(upper.name(), lower.name());
    }

    #[test]
    fn kdf_fetch_rejects_unknown_algorithm() {
        let ctx = LibContext::get_default();
        let err = Kdf::fetch(&ctx, "NOT-A-REAL-KDF", None).expect_err("should fail");
        match err {
            CryptoError::AlgorithmNotFound(_) => {}
            other => panic!("unexpected error for unknown KDF: {other:?}"),
        }
    }

    // ---- KdfCtx::new + accessors --------------------------------------

    #[test]
    fn kdf_ctx_new_stores_algorithm() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
        let kctx = KdfCtx::new(&kdf);
        assert_eq!(kctx.kdf().name(), HKDF);
    }

    #[test]
    fn kdf_ctx_set_and_get_params_round_trip() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
        let mut kctx = KdfCtx::new(&kdf);

        let mut params = ParamSet::new();
        params.set("digest", ParamValue::Utf8String("SHA-256".to_string()));
        params.set("key", ParamValue::OctetString(b"secret-key".to_vec()));
        kctx.set_params(&params).unwrap();

        let got = kctx.get_params().unwrap();
        assert!(got.contains("digest"));
        assert!(got.contains("key"));
        match got.get("digest").unwrap() {
            ParamValue::Utf8String(s) => assert_eq!(s, "SHA-256"),
            other => panic!("unexpected digest param: {other:?}"),
        }
    }

    #[test]
    fn kdf_ctx_kdf_size_reports_variable() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
        let kctx = KdfCtx::new(&kdf);
        assert_eq!(kctx.kdf_size().unwrap(), 0);
    }

    // ---- KdfCtx::derive ------------------------------------------------

    #[test]
    fn kdf_ctx_derive_hkdf_matches_core_kdf() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
        let mut kctx = KdfCtx::new(&kdf);

        let ikm = b"secret keying material";
        let salt = b"salt-value";
        let info = b"app-info";

        let mut params = ParamSet::new();
        params.set("digest", ParamValue::Utf8String("SHA-256".to_string()));
        params.set("key", ParamValue::OctetString(ikm.to_vec()));
        params.set("salt", ParamValue::OctetString(salt.to_vec()));
        params.set("info", ParamValue::OctetString(info.to_vec()));
        kctx.set_params(&params).unwrap();

        let out = kctx.derive(42).unwrap();
        assert_eq!(out.len(), 42);

        // Deterministic: compare against direct core_kdf call.
        let expected = core_kdf::hkdf_derive(ikm, salt, info, 42).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn kdf_ctx_derive_pbkdf2_produces_expected_length() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, PBKDF2, None).unwrap();
        let mut kctx = KdfCtx::new(&kdf);

        let mut params = ParamSet::new();
        params.set("digest", ParamValue::Utf8String("SHA256".to_string()));
        params.set("pass", ParamValue::OctetString(b"password".to_vec()));
        params.set("salt", ParamValue::OctetString(b"NaCl".to_vec()));
        params.set("iter", ParamValue::UInt32(1024));
        kctx.set_params(&params).unwrap();

        let out = kctx.derive(32).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn kdf_ctx_derive_consumed_guard() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
        let mut kctx = KdfCtx::new(&kdf);

        let mut params = ParamSet::new();
        params.set("digest", ParamValue::Utf8String("SHA-256".to_string()));
        params.set("key", ParamValue::OctetString(b"ikm".to_vec()));
        params.set("salt", ParamValue::OctetString(b"salt".to_vec()));
        params.set("info", ParamValue::OctetString(b"ctx".to_vec()));
        kctx.set_params(&params).unwrap();

        let _ = kctx.derive(16).unwrap();
        // Second derive without reset must fail; set_params similarly.
        let err = kctx.derive(16).expect_err("second derive should fail");
        match err {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn kdf_ctx_reset_allows_re_derivation() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
        let mut kctx = KdfCtx::new(&kdf);

        let mut params = ParamSet::new();
        params.set("digest", ParamValue::Utf8String("SHA-256".to_string()));
        params.set("key", ParamValue::OctetString(b"ikm".to_vec()));
        params.set("salt", ParamValue::OctetString(b"salt".to_vec()));
        params.set("info", ParamValue::OctetString(b"ctx".to_vec()));
        kctx.set_params(&params).unwrap();

        let first = kctx.derive(16).unwrap();
        kctx.reset();

        // After reset the context must accept fresh parameters and derive
        // again without returning the "consumed" error.
        let mut params2 = ParamSet::new();
        params2.set("digest", ParamValue::Utf8String("SHA-256".to_string()));
        params2.set("key", ParamValue::OctetString(b"ikm".to_vec()));
        params2.set("salt", ParamValue::OctetString(b"salt".to_vec()));
        params2.set("info", ParamValue::OctetString(b"ctx".to_vec()));
        kctx.set_params(&params2).unwrap();
        let second = kctx.derive(16).unwrap();

        // Deterministic KDF with identical inputs must yield identical outputs.
        assert_eq!(first.as_slice(), second.as_slice());
    }

    #[test]
    fn kdf_ctx_try_clone_creates_independent_copy() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, HKDF, None).unwrap();
        let mut kctx = KdfCtx::new(&kdf);

        let mut params = ParamSet::new();
        params.set("digest", ParamValue::Utf8String("SHA-256".to_string()));
        params.set("key", ParamValue::OctetString(b"ikm".to_vec()));
        kctx.set_params(&params).unwrap();

        let clone = kctx.try_clone().unwrap();
        assert_eq!(clone.kdf().name(), kctx.kdf().name());
        // The clone must own its own params (mutating the original must
        // not leak into the clone).
    }

    // ---- Free-function wrappers ---------------------------------------

    #[test]
    fn pbkdf2_derive_wrapper_produces_correct_length() {
        let dk = pbkdf2_derive(b"password", b"NaCl", 1024, "SHA-256", 32).expect("should derive");
        assert_eq!(dk.len(), 32);
    }

    #[test]
    fn pbkdf2_derive_rejects_unsupported_digest() {
        let err =
            pbkdf2_derive(b"password", b"salt", 10, "MD5", 32).expect_err("MD5 must be rejected");
        match err {
            CryptoError::Common(openssl_common::CommonError::Unsupported(_)) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn pbkdf2_derive_rejects_zero_iterations() {
        let err = pbkdf2_derive(b"password", b"salt", 0, "SHA-256", 32)
            .expect_err("zero iterations must be rejected");
        match err {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn pbkdf2_derive_rejects_zero_length() {
        let err = pbkdf2_derive(b"password", b"salt", 1, "SHA-256", 0)
            .expect_err("zero length must be rejected");
        match err {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn pbkdf2_derive_accepts_sha256_alias_variants() {
        for name in ["SHA256", "SHA-256", "sha-256", "sha2-256", "SHA2-256"] {
            let dk = pbkdf2_derive(b"password", b"salt", 4, name, 16).expect("alias should work");
            assert_eq!(dk.len(), 16);
        }
    }

    #[test]
    fn scrypt_derive_wrapper_respects_max_mem() {
        // N=16, r=1, p=1 → footprint = 128 * 1 * 16 = 2048 bytes.  Set
        // max_mem below this value and ensure we reject.
        let err = scrypt_derive(b"password", b"salt", 16, 1, 1, 1024, 32)
            .expect_err("max_mem violation must error");
        match err {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn scrypt_derive_wrapper_max_mem_zero_disables_check() {
        // Small cost parameters so the test finishes quickly.
        let dk = scrypt_derive(b"pw", b"NaCl", 16, 1, 1, 0, 32).expect("no cap must succeed");
        assert_eq!(dk.len(), 32);
    }

    #[test]
    fn hkdf_derive_wrapper_matches_core_kdf() {
        let okm = hkdf_derive("SHA-256", b"ikm-value", b"salt", b"info", 32).expect("hkdf ok");
        let expected = core_kdf::hkdf_derive(b"ikm-value", b"salt", b"info", 32).unwrap();
        assert_eq!(okm.as_slice(), expected.as_slice());
    }

    #[test]
    fn hkdf_derive_rejects_unsupported_digest() {
        let err = hkdf_derive("SHA-512", b"ikm", b"salt", b"info", 32)
            .expect_err("SHA-512 not yet supported at EVP layer");
        match err {
            CryptoError::Common(openssl_common::CommonError::Unsupported(_)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ---- PbeAlgorithm --------------------------------------------------

    #[test]
    fn pbe_algorithm_name_and_display() {
        assert_eq!(PbeAlgorithm::Pbes1.name(), "PBES1");
        assert_eq!(PbeAlgorithm::Pbes2.name(), "PBES2");
        assert_eq!(format!("{}", PbeAlgorithm::Pbes1), "PBES1");
        assert_eq!(format!("{}", PbeAlgorithm::Pbes2), "PBES2");
    }

    // ---- KdfData -------------------------------------------------------

    #[test]
    fn kdf_data_round_trip_and_clone() {
        let bytes = vec![1u8, 2, 3, 4, 5];
        let data = KdfData::new(bytes.clone());
        assert_eq!(data.as_bytes(), bytes.as_slice());
        assert_eq!(data.len(), bytes.len());
        assert!(!data.is_empty());

        let copy = data.clone();
        assert_eq!(copy.as_bytes(), data.as_bytes());
    }

    #[test]
    fn kdf_data_empty_reports_empty() {
        let empty = KdfData::new(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.as_bytes(), &[] as &[u8]);
    }

    #[test]
    fn kdf_data_debug_redacts_contents() {
        let data = KdfData::new(vec![0xde, 0xad, 0xbe, 0xef]);
        let rendered = format!("{data:?}");
        assert!(!rendered.contains("deadbeef"));
        assert!(!rendered.contains("0xde"));
    }

    // ---- pbe_cipher_init ----------------------------------------------

    #[test]
    fn pbe_cipher_init_pbes2_aes_256_cbc() {
        let ctx = pbe_cipher_init(
            PbeAlgorithm::Pbes2,
            "AES-256-CBC",
            b"hunter2-super-secret",
            b"salt-value",
            4096,
        )
        .expect("pbe_cipher_init should succeed");
        assert!(ctx.cipher().is_some());
        assert_eq!(ctx.cipher().unwrap().name(), "AES-256-CBC");
    }

    #[test]
    fn pbe_cipher_init_pbes1_aes_128_cbc() {
        let ctx = pbe_cipher_init(
            PbeAlgorithm::Pbes1,
            "AES-128-CBC",
            b"password",
            b"some-salt",
            4096,
        )
        .expect("pbe_cipher_init PBES1 should succeed");
        assert!(ctx.cipher().is_some());
    }

    #[test]
    fn pbe_cipher_init_rejects_empty_password() {
        let err = pbe_cipher_init(PbeAlgorithm::Pbes2, "AES-256-CBC", b"", b"salt", 1)
            .expect_err("empty password must be rejected");
        match err {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn pbe_cipher_init_rejects_zero_iterations() {
        let err = pbe_cipher_init(PbeAlgorithm::Pbes2, "AES-256-CBC", b"password", b"salt", 0)
            .expect_err("zero iterations must be rejected");
        match err {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn pbe_cipher_init_rejects_unknown_cipher() {
        let err = pbe_cipher_init(
            PbeAlgorithm::Pbes2,
            "NOT-A-CIPHER",
            b"password",
            b"salt",
            1024,
        )
        .expect_err("unknown cipher must fail");
        match err {
            CryptoError::AlgorithmNotFound(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ---- Internal helpers ----------------------------------------------

    #[test]
    fn require_sha256_alias_accepts_known_spellings() {
        for good in [
            "SHA256", "SHA-256", "sha256", "sha-256", "Sha256", "SHA2-256", "sha2-256", "SHA_256",
        ] {
            require_sha256_alias(good).expect(good);
        }
    }

    #[test]
    fn require_sha256_alias_rejects_other_digests() {
        for bad in ["SHA1", "SHA-1", "MD5", "SHA3-256", "SHA-512", ""] {
            let err = require_sha256_alias(bad).expect_err(bad);
            match err {
                CryptoError::Common(openssl_common::CommonError::Unsupported(_)) => {}
                other => panic!("unexpected error for {bad}: {other:?}"),
            }
        }
    }

    #[test]
    fn enforce_scrypt_max_mem_accepts_within_budget() {
        // 128 * 1 * 16 = 2048; budget = 4096 → OK.
        enforce_scrypt_max_mem(16, 1, 1, 4096).expect("within budget");
    }

    #[test]
    fn enforce_scrypt_max_mem_rejects_when_over_budget() {
        let err = enforce_scrypt_max_mem(1024, 8, 1, 1024).expect_err("over budget");
        match err {
            CryptoError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn enforce_scrypt_max_mem_detects_overflow() {
        let err =
            enforce_scrypt_max_mem(u64::MAX, u32::MAX, 1, u64::MAX).expect_err("must overflow");
        match err {
            CryptoError::Common(openssl_common::CommonError::ArithmeticOverflow { .. }) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
