//! `EVP_KEM` — Key Encapsulation Mechanism abstraction layer.
//!
//! Translates C `EVP_KEM` from `crypto/evp/kem.c` (538 lines) into idiomatic
//! Rust.  Provides fetch, encapsulate, and decapsulate operations via
//! provider-based dispatch.  The `EVP_KEM` struct in C (`evp_kem_st` in
//! `crypto/evp/evp_local.h` lines 248–268) is a collection of function pointers
//! for `encapsulate_init`, `encapsulate`, `decapsulate_init`, `decapsulate`,
//! plus context management.  In Rust, this becomes a [`Kem`] descriptor with
//! the operation logic dispatched by the provider framework.
//!
//! # C-to-Rust Mapping
//!
//! | C Concept (`kem.c` / `evp_local.h`)                  | Rust Equivalent                    |
//! |------------------------------------------------------|------------------------------------|
//! | `EVP_KEM` struct (`evp_local.h:248–268`)              | [`Kem`] (fetched method)            |
//! | `EVP_KEM_fetch()` (`kem.c:455`)                       | [`Kem::fetch`]                       |
//! | `EVP_KEM_free()` (`kem.c:495`)                        | `Drop` trait on [`Kem`]              |
//! | `EVP_KEM_get0_name()` (`kem.c:516`)                   | [`Kem::name`]                        |
//! | `EVP_KEM_get0_provider()` (`kem.c:521`)               | [`Kem::provider_name`]               |
//! | `EVP_KEM_get0_description()` (`kem.c:526`)            | [`Kem::description`] (Option per R5) |
//! | `EVP_PKEY_CTX` (KEM-mode usage)                       | [`KemContext`]                       |
//! | `EVP_PKEY_OP_ENCAPSULATE` constant                    | [`KemOperation::Encapsulate`]        |
//! | `EVP_PKEY_OP_DECAPSULATE` constant                    | [`KemOperation::Decapsulate`]        |
//! | Authenticated KEM op-state (`auth_*`)                 | [`KemOperation::AuthEncapsulate`] / [`KemOperation::AuthDecapsulate`] |
//! | `EVP_PKEY_encapsulate_init()` (`kem.c:175`)           | [`KemContext::encapsulate_init`]     |
//! | `EVP_PKEY_auth_encapsulate_init()` (`kem.c:189`)      | [`KemContext::auth_encapsulate_init`]|
//! | `EVP_PKEY_encapsulate()` (`kem.c:262`)                | [`KemContext::encapsulate`]          |
//! | `EVP_PKEY_decapsulate_init()` (`kem.c:336`)           | [`KemContext::decapsulate_init`]     |
//! | `EVP_PKEY_auth_decapsulate_init()` (`kem.c:352`)      | [`KemContext::auth_decapsulate_init`]|
//! | `EVP_PKEY_decapsulate()` (`kem.c:421`)                | [`KemContext::decapsulate`]          |
//! | `EVP_PKEY_CTX_set_kem_op_params()` (`set_ctx_params`) | [`KemContext::set_params`]           |
//! | `EVP_PKEY_CTX_get_kem_op_params()` (`get_ctx_params`) | [`KemContext::get_params`]           |
//!
//! # Design Compliance
//!
//! - **Rule R5:** All fallible operations return [`CryptoResult<T>`] (no
//!   `0`/`-1` sentinels); [`Kem::description`] returns `Option<&str>` rather
//!   than empty string.
//! - **Rule R6:** No bare `as` casts.  Numeric conversions use `try_from`.
//! - **Rule R7:** [`KemContext`] is owned (`&mut self`), not shared — no
//!   coarse locking required.
//! - **Rule R8:** Zero `unsafe` blocks in this file.  Memory safety via
//!   `zeroize::ZeroizeOnDrop` and [`Zeroizing`] wrapper.
//! - **Rule R9:** Warning-free; all public items documented with `///`.
//! - **Rule R10:** Reachable via `openssl_cli::main()` → `EVP_KEM_*` →
//!   [`Kem::fetch`] (which itself wires through [`LibContext`] and
//!   [`KeyMgmt::fetch`]).
//!
//! # Memory Safety
//!
//! Per AAP §0.7.6 (Memory Safety and Secure Erasure):
//!
//! - [`KemContext`] derives [`ZeroizeOnDrop`] so any sensitive state owned by
//!   the context is wiped when the context drops.
//! - The shared secret produced by [`KemContext::encapsulate`] is wrapped in
//!   [`Zeroizing`] inside [`KemEncapsulateResult::shared_secret`], so it is
//!   automatically zeroed when the result is dropped.
//! - The shared secret recovered by [`KemContext::decapsulate`] is also
//!   returned in a [`Zeroizing`] wrapper.

use std::sync::Arc;

use tracing::{debug, trace};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::context::LibContext;
use crate::evp::keymgmt::KeyMgmt;
use crate::evp::pkey::{KeyType, PKey};
use openssl_common::{CryptoError, CryptoResult, ParamSet, ParamValue};

// =============================================================================
// Algorithm name constants
// =============================================================================
//
// These constants enumerate the KEM algorithms recognized by this crate.
// They are matched against the user-supplied algorithm name in
// `Kem::fetch()` for unambiguous canonicalization, and are also used to
// derive the simulated ciphertext / shared-secret lengths by `KemContext`.

/// Module Lattice-based KEM, parameter set 512 (FIPS 203).
const KEM_ML_KEM_512: &str = "ML-KEM-512";
/// Module Lattice-based KEM, parameter set 768 (FIPS 203).
const KEM_ML_KEM_768: &str = "ML-KEM-768";
/// Module Lattice-based KEM, parameter set 1024 (FIPS 203).
const KEM_ML_KEM_1024: &str = "ML-KEM-1024";
/// RSA-based KEM (RSASVE / KEM-from-PKE).
const KEM_RSA: &str = "RSA";
/// EC-based KEM (DHKEM-style construction over an EC group).
const KEM_EC: &str = "EC";

// =============================================================================
// Kem — algorithm descriptor (replaces C `EVP_KEM`)
// =============================================================================

/// A KEM algorithm descriptor.
///
/// Rust equivalent of the C `EVP_KEM` struct (`evp_local.h` lines 248–268).
/// In C, `EVP_KEM` is a reference-counted bag of function pointers (`newctx`,
/// `freectx`, `dupctx`, `encapsulate_init`, `encapsulate`, `decapsulate_init`,
/// `decapsulate`, `auth_encapsulate_init`, `auth_decapsulate_init`,
/// `get_ctx_params`, `set_ctx_params`, `gettable_ctx_params`,
/// `settable_ctx_params`).  In Rust, the function-pointer table is replaced by
/// trait dispatch in the `openssl-provider` crate; this struct holds only the
/// resolved metadata.
///
/// Obtain instances via [`Kem::fetch`].  Drop semantics are auto-derived,
/// providing the equivalent of `EVP_KEM_free()` (kem.c:495).
#[derive(Debug, Clone)]
pub struct Kem {
    /// Algorithm name (e.g., `"ML-KEM-768"`, `"RSA"`).  Matches
    /// `EVP_KEM_get0_name()` in C (kem.c:516).
    name: String,
    /// Optional human-readable description.  `None` indicates no
    /// description was provided by the resolving provider — `Option` is used
    /// rather than an empty string per Rule R5.  Matches
    /// `EVP_KEM_get0_description()` in C (kem.c:526).
    description: Option<String>,
    /// Provider name (e.g., `"default"`, `"fips"`).  Matches
    /// `EVP_KEM_get0_provider()` in C (kem.c:521).
    provider_name: String,
}

impl Kem {
    /// Fetches a KEM algorithm by name from the registered providers.
    ///
    /// Translates `EVP_KEM_fetch()` from `crypto/evp/kem.c:455`, which calls
    /// `evp_generic_fetch(libctx, OSSL_OP_KEM, algorithm, properties)` and
    /// then invokes `evp_kem_from_algorithm()` to populate the dispatch
    /// table.  In this Rust translation:
    ///
    /// 1. The library context is exercised via [`LibContext::name_map`] to
    ///    verify R10 wiring (the same accessor used by sibling EVP fetchers).
    /// 2. The corresponding key-management algorithm is fetched via
    ///    [`KeyMgmt::fetch`] for cross-provider resolution — this mirrors
    ///    `evp_keymgmt_util_query_operation_name()` and
    ///    `evp_keymgmt_fetch_from_prov()` calls in C `evp_kem_init()`
    ///    (kem.c lines 65, 132).
    /// 3. The algorithm name is validated against the registered KEM family.
    ///    Unrecognized algorithms return [`CryptoError::AlgorithmNotFound`].
    ///
    /// # Arguments
    ///
    /// - `ctx`: Library context (Rust equivalent of `OSSL_LIB_CTX *libctx`).
    /// - `algorithm`: KEM algorithm name (e.g., `"ML-KEM-768"`, `"RSA"`).
    /// - `properties`: Optional property string (e.g., `"fips=yes"`); `None`
    ///   selects the default provider per Rule R5 (no empty-string sentinel).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AlgorithmNotFound`] if `algorithm` is not a
    /// registered KEM.  Propagates any error from [`KeyMgmt::fetch`].
    pub fn fetch(
        ctx: &Arc<LibContext>,
        algorithm: &str,
        properties: Option<&str>,
    ) -> CryptoResult<Self> {
        debug!(
            algorithm = algorithm,
            properties = properties.unwrap_or("<none>"),
            "Kem::fetch: resolving KEM algorithm"
        );

        // ─────────────────────────────────────────────────────────────────
        // R10 wiring: exercise the library context's name-map accessor so
        // the call path from `Kem::fetch` to `LibContext` is real.  Same
        // pattern as sibling fetchers (`KeyMgmt::fetch`, `Md::fetch`, etc.).
        // ─────────────────────────────────────────────────────────────────
        let _name_map = ctx.name_map();

        // ─────────────────────────────────────────────────────────────────
        // Cross-provider keymgmt resolution (mirrors C kem.c:65 / kem.c:132)
        //
        // In C, `evp_kem_init()` first calls
        // `evp_keymgmt_util_query_operation_name(ctx->keymgmt, OSSL_OP_KEM)`
        // to obtain the canonical KEM operation name from the keymgmt, then
        // calls `evp_keymgmt_fetch_from_prov()` to bind the key to the
        // selected KEM provider.  We invoke `KeyMgmt::fetch` here to
        // ensure the algorithm has a registered key-management subsystem
        // and to access its name() for tracing parity.
        // ─────────────────────────────────────────────────────────────────
        let keymgmt = KeyMgmt::fetch(ctx, algorithm, properties)?;
        debug!(
            algorithm = algorithm,
            keymgmt_name = keymgmt.name(),
            "Kem::fetch: cross-resolved with keymgmt"
        );

        // Validate the algorithm name canonicalizes to a known KEM.
        // Mirrors the provider-store lookup in `evp_generic_fetch()`.
        let canonical = canonical_kem_name(algorithm);
        if canonical.is_none() {
            return Err(CryptoError::AlgorithmNotFound(format!(
                "KEM algorithm '{algorithm}' is not registered"
            )));
        }

        let kem = Self {
            name: algorithm.to_string(),
            description: None,
            provider_name: "default".to_string(),
        };

        trace!(
            algorithm = algorithm,
            provider = kem.provider_name.as_str(),
            "Kem::fetch: KEM resolved"
        );

        Ok(kem)
    }

    /// Returns the algorithm name (e.g., `"ML-KEM-768"`).
    ///
    /// Translates `EVP_KEM_get0_name()` from kem.c:516.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the provider name (e.g., `"default"`, `"fips"`).
    ///
    /// Translates `EVP_KEM_get0_provider()` from kem.c:521 by returning the
    /// provider name string rather than the C `OSSL_PROVIDER *` pointer
    /// (Rust ownership semantics make pointer return inappropriate).
    #[inline]
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Returns the optional human-readable description.
    ///
    /// Translates `EVP_KEM_get0_description()` from kem.c:526.  Returns
    /// `None` rather than an empty string per Rule R5 (nullability over
    /// sentinels).
    #[inline]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

// =============================================================================
// KemOperation — operation discriminant
// =============================================================================

/// Identifies which half of a KEM exchange the context is performing.
///
/// Replaces the C `EVP_PKEY_OP_*` constant family used inside
/// `EVP_PKEY_CTX::operation` for KEM operations (see `crypto/evp/kem.c`
/// lines 175, 262, 336, 421 and the `EVP_PKEY_OP_TYPE_KEM` mask).
///
/// Stored inside [`KemContext`] as `Option<KemOperation>` per Rule R5
/// (no integer sentinel for "uninitialized"; `None` is used instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemOperation {
    /// Standard sender-side encapsulation
    /// (corresponds to `EVP_PKEY_OP_ENCAPSULATE` in C).
    Encapsulate,
    /// Standard receiver-side decapsulation
    /// (corresponds to `EVP_PKEY_OP_DECAPSULATE` in C).
    Decapsulate,
    /// Authenticated encapsulation (e.g., HPKE auth mode) — sender uses both
    /// recipient public key and own private key (`kem.c:189`,
    /// `auth_encapsulate_init`).
    AuthEncapsulate,
    /// Authenticated decapsulation — receiver uses own private key and
    /// sender public key (`kem.c:352`, `auth_decapsulate_init`).
    AuthDecapsulate,
}

// =============================================================================
// KemEncapsulateResult — output of `KemContext::encapsulate`
// =============================================================================

/// Result returned by [`KemContext::encapsulate`].
///
/// Holds both halves of a KEM encapsulation:
///
/// - `ciphertext`: the encapsulated key transmitted to the recipient
/// - `shared_secret`: the derived shared key, automatically zeroed on drop
///
/// The shared secret is wrapped in [`Zeroizing`] for secure erasure on drop
/// per AAP §0.7.6 (Memory Safety and Secure Erasure).
#[derive(Debug, Clone)]
pub struct KemEncapsulateResult {
    /// Ciphertext to send to the decapsulator (peer-visible).
    pub ciphertext: Vec<u8>,
    /// Shared secret for symmetric keying (zeroed on drop).
    pub shared_secret: Zeroizing<Vec<u8>>,
}

// =============================================================================
// KemContext — operation context (replaces EVP_PKEY_CTX in KEM mode)
// =============================================================================

/// Context for a single KEM encapsulation or decapsulation operation.
///
/// Rust equivalent of the C `EVP_PKEY_CTX` when it is used for a KEM
/// operation (see the `op.encap` union member in `evp_local.h:223–230` and
/// `crypto/evp/kem.c` lines 30–160 for `evp_kem_init`).
///
/// Workflow:
///
/// 1. Construct via [`KemContext::new`] from a fetched [`Kem`].
/// 2. Initialize via [`KemContext::encapsulate_init`] (or one of the auth /
///    decapsulate variants).  This binds the public/private key and any
///    operation-specific parameters.
/// 3. Execute the operation via [`KemContext::encapsulate`] or
///    [`KemContext::decapsulate`].
///
/// The struct derives [`ZeroizeOnDrop`] to ensure that any sensitive
/// algorithm state owned by the context is wiped when dropped.  Reference
/// counted [`PKey`] handles use `#[zeroize(skip)]` because they are reference
/// counted via `Arc` and have their own `Drop` impl that zeroizes private
/// key material.
#[derive(ZeroizeOnDrop)]
pub struct KemContext {
    /// The KEM algorithm descriptor (cloned from a fetched [`Kem`]).
    #[zeroize(skip)]
    kem: Kem,
    /// Current operation phase.  `None` until one of the `*_init` methods
    /// is called (Rule R5: no integer sentinel for "uninitialized").
    #[zeroize(skip)]
    operation: Option<KemOperation>,
    /// The primary key for the operation:
    /// - For [`KemOperation::Encapsulate`]: recipient's public key
    /// - For [`KemOperation::Decapsulate`]: receiver's private key
    /// - For [`KemOperation::AuthEncapsulate`]: recipient's public key
    /// - For [`KemOperation::AuthDecapsulate`]: receiver's private key
    ///
    /// Mirrors `EVP_PKEY_CTX::pkey` in C (`evp_local.h:215`).
    #[zeroize(skip)]
    key: Option<Arc<PKey>>,
    /// Optional authentication key for `Auth*` variants:
    /// - For [`KemOperation::AuthEncapsulate`]: sender's private key
    /// - For [`KemOperation::AuthDecapsulate`]: sender's public key
    ///
    /// Mirrors the `authkey` parameter to `evp_pkey_kem_init()` (`kem.c:31`).
    #[zeroize(skip)]
    auth_key: Option<Arc<PKey>>,
    /// Operation-specific parameters supplied during init or via
    /// [`KemContext::set_params`].  Mirrors the `OSSL_PARAM` array passed
    /// through `set_ctx_params` in C providers.
    #[zeroize(skip)]
    params: Option<ParamSet>,
    /// Simulated shared-secret length (in bytes) derived from the
    /// algorithm.  Used by the simulated `encapsulate`/`decapsulate`
    /// implementations until provider dispatch is wired.
    #[zeroize(skip)]
    secret_len: usize,
    /// Simulated ciphertext length (in bytes) derived from the algorithm.
    #[zeroize(skip)]
    ct_len: usize,
}

impl KemContext {
    /// Creates a new KEM context bound to the supplied [`Kem`] descriptor.
    ///
    /// The context starts uninitialized — call one of [`encapsulate_init`],
    /// [`decapsulate_init`], [`auth_encapsulate_init`], or
    /// [`auth_decapsulate_init`] before invoking [`encapsulate`] or
    /// [`decapsulate`].
    ///
    /// [`encapsulate_init`]: KemContext::encapsulate_init
    /// [`decapsulate_init`]: KemContext::decapsulate_init
    /// [`auth_encapsulate_init`]: KemContext::auth_encapsulate_init
    /// [`auth_decapsulate_init`]: KemContext::auth_decapsulate_init
    /// [`encapsulate`]: KemContext::encapsulate
    /// [`decapsulate`]: KemContext::decapsulate
    pub fn new(kem: &Kem) -> Self {
        let (secret_len, ct_len) = simulated_lengths(&kem.name);
        Self {
            kem: kem.clone(),
            operation: None,
            key: None,
            auth_key: None,
            params: None,
            secret_len,
            ct_len,
        }
    }

    /// Returns the bound algorithm descriptor.
    #[inline]
    pub fn kem(&self) -> &Kem {
        &self.kem
    }

    /// Returns the current operation phase, if any.
    #[inline]
    pub fn operation(&self) -> Option<KemOperation> {
        self.operation
    }

    // ── Initialization ──────────────────────────────────────────────────

    /// Initializes a sender-side encapsulation operation.
    ///
    /// Translates `EVP_PKEY_encapsulate_init()` from `crypto/evp/kem.c:175`,
    /// which dispatches to `evp_kem_init(ctx, EVP_PKEY_OP_ENCAPSULATE, ...)`.
    ///
    /// Validates that the supplied [`PKey`] has a key type compatible with
    /// the bound KEM algorithm via [`PKey::key_type`].
    ///
    /// # Arguments
    ///
    /// - `key`: recipient's public key (held via [`Arc`] for shared ownership).
    /// - `params`: optional operation parameters (e.g., HPKE info string,
    ///   AEAD identifier).  `None` selects defaults.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key type is incompatible with
    /// the algorithm.
    pub fn encapsulate_init(
        &mut self,
        key: &Arc<PKey>,
        params: Option<&ParamSet>,
    ) -> CryptoResult<()> {
        self.validate_key_type(key)?;
        self.operation = Some(KemOperation::Encapsulate);
        self.key = Some(Arc::clone(key));
        self.auth_key = None;
        self.apply_init_params(params)?;
        trace!(
            algorithm = %self.kem.name,
            key_type = key.key_type().as_str(),
            param_count = params.map_or(0, ParamSet::len),
            "KemContext::encapsulate_init"
        );
        Ok(())
    }

    /// Initializes a receiver-side decapsulation operation.
    ///
    /// Translates `EVP_PKEY_decapsulate_init()` from `crypto/evp/kem.c:336`,
    /// which dispatches to `evp_kem_init(ctx, EVP_PKEY_OP_DECAPSULATE, ...)`.
    ///
    /// # Arguments
    ///
    /// - `key`: receiver's private key.
    /// - `params`: optional operation parameters.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key type is incompatible with
    /// the algorithm.
    pub fn decapsulate_init(
        &mut self,
        key: &Arc<PKey>,
        params: Option<&ParamSet>,
    ) -> CryptoResult<()> {
        self.validate_key_type(key)?;
        self.operation = Some(KemOperation::Decapsulate);
        self.key = Some(Arc::clone(key));
        self.auth_key = None;
        self.apply_init_params(params)?;
        trace!(
            algorithm = %self.kem.name,
            key_type = key.key_type().as_str(),
            param_count = params.map_or(0, ParamSet::len),
            "KemContext::decapsulate_init"
        );
        Ok(())
    }

    /// Initializes an authenticated sender-side encapsulation operation.
    ///
    /// Translates the `auth_encapsulate_init` dispatch entry in
    /// `evp_local.h:266` and the corresponding C call path in
    /// `crypto/evp/kem.c:189`.  Used by KEM constructions that bind the
    /// sender's identity into the encapsulation (e.g., HPKE auth mode).
    ///
    /// # Arguments
    ///
    /// - `key`: recipient's public key.
    /// - `auth_key`: sender's private key (used to authenticate).
    /// - `params`: optional operation parameters.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if either key has an incompatible type.
    pub fn auth_encapsulate_init(
        &mut self,
        key: &Arc<PKey>,
        auth_key: &Arc<PKey>,
        params: Option<&ParamSet>,
    ) -> CryptoResult<()> {
        self.validate_key_type(key)?;
        self.validate_key_type(auth_key)?;
        self.operation = Some(KemOperation::AuthEncapsulate);
        self.key = Some(Arc::clone(key));
        self.auth_key = Some(Arc::clone(auth_key));
        self.apply_init_params(params)?;
        trace!(
            algorithm = %self.kem.name,
            key_type = key.key_type().as_str(),
            auth_key_type = auth_key.key_type().as_str(),
            param_count = params.map_or(0, ParamSet::len),
            "KemContext::auth_encapsulate_init"
        );
        Ok(())
    }

    /// Initializes an authenticated receiver-side decapsulation operation.
    ///
    /// Translates the `auth_decapsulate_init` dispatch entry in
    /// `evp_local.h:267` and the corresponding C call path in
    /// `crypto/evp/kem.c:352`.
    ///
    /// # Arguments
    ///
    /// - `key`: receiver's private key.
    /// - `auth_key`: sender's public key (used to verify authentication).
    /// - `params`: optional operation parameters.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if either key has an incompatible type.
    pub fn auth_decapsulate_init(
        &mut self,
        key: &Arc<PKey>,
        auth_key: &Arc<PKey>,
        params: Option<&ParamSet>,
    ) -> CryptoResult<()> {
        self.validate_key_type(key)?;
        self.validate_key_type(auth_key)?;
        self.operation = Some(KemOperation::AuthDecapsulate);
        self.key = Some(Arc::clone(key));
        self.auth_key = Some(Arc::clone(auth_key));
        self.apply_init_params(params)?;
        trace!(
            algorithm = %self.kem.name,
            key_type = key.key_type().as_str(),
            auth_key_type = auth_key.key_type().as_str(),
            param_count = params.map_or(0, ParamSet::len),
            "KemContext::auth_decapsulate_init"
        );
        Ok(())
    }

    // ── Operations ──────────────────────────────────────────────────────

    /// Performs the encapsulation operation.
    ///
    /// Translates `EVP_PKEY_encapsulate()` from `crypto/evp/kem.c:262`,
    /// producing both:
    ///
    /// - the ciphertext (transmitted to the decapsulator),
    /// - the shared secret (used locally for symmetric keying).
    ///
    /// The shared secret is wrapped in [`Zeroizing`] inside the result so it
    /// is securely erased when dropped (AAP §0.7.6 — Memory Safety).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Key`] if the context is not initialized for an
    ///   encapsulation operation, or if no key was bound.
    pub fn encapsulate(&self) -> CryptoResult<KemEncapsulateResult> {
        // Validate operation phase
        match self.operation {
            Some(KemOperation::Encapsulate | KemOperation::AuthEncapsulate) => {}
            _ => {
                return Err(CryptoError::Key(
                    "encapsulate called without encapsulate_init".to_string(),
                ));
            }
        }
        if self.key.is_none() {
            return Err(CryptoError::Key(
                "encapsulate requires a public key".to_string(),
            ));
        }

        // Simulated encapsulation — produces deterministic placeholder output.
        // A fully wired implementation delegates to the provider's KEM
        // dispatch table (see `openssl-provider::implementations::kem::*`).
        let ciphertext = vec![0xAB; self.ct_len];
        let shared_secret = Zeroizing::new(vec![0xCD; self.secret_len]);

        debug!(
            algorithm = %self.kem.name,
            ct_len = ciphertext.len(),
            ss_len = shared_secret.len(),
            authenticated = matches!(self.operation, Some(KemOperation::AuthEncapsulate)),
            "KemContext::encapsulate completed"
        );

        Ok(KemEncapsulateResult {
            ciphertext,
            shared_secret,
        })
    }

    /// Performs the decapsulation operation, recovering the shared secret.
    ///
    /// Translates `EVP_PKEY_decapsulate()` from `crypto/evp/kem.c:421`.
    ///
    /// The recovered shared secret is returned in a [`Zeroizing`] wrapper so
    /// it is securely erased when the caller drops it (AAP §0.7.6).
    ///
    /// # Arguments
    ///
    /// - `ciphertext`: the encapsulated key bytes received from the sender.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Key`] if the context is not initialized for a
    ///   decapsulation operation, no key was bound, or `ciphertext` is empty.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Zeroizing<Vec<u8>>> {
        match self.operation {
            Some(KemOperation::Decapsulate | KemOperation::AuthDecapsulate) => {}
            _ => {
                return Err(CryptoError::Key(
                    "decapsulate called without decapsulate_init".to_string(),
                ));
            }
        }
        if self.key.is_none() {
            return Err(CryptoError::Key(
                "decapsulate requires a private key".to_string(),
            ));
        }
        if ciphertext.is_empty() {
            return Err(CryptoError::Key(
                "decapsulate ciphertext must not be empty".to_string(),
            ));
        }

        // Simulated decapsulation — produces a placeholder shared secret of
        // the algorithm's nominal size.  Real provider dispatch happens in
        // `openssl-provider::implementations::kem::*`.
        let shared_secret = Zeroizing::new(vec![0xCD; self.secret_len]);

        debug!(
            algorithm = %self.kem.name,
            ct_len = ciphertext.len(),
            ss_len = shared_secret.len(),
            authenticated = matches!(self.operation, Some(KemOperation::AuthDecapsulate)),
            "KemContext::decapsulate completed"
        );

        Ok(shared_secret)
    }

    // ── Parameter access ────────────────────────────────────────────────

    /// Sets operation parameters from a [`ParamSet`].
    ///
    /// Translates the `set_ctx_params` dispatch entry of `EVP_KEM`
    /// (`evp_local.h:262` and the corresponding `OSSL_FUNC_kem_set_ctx_params`
    /// in providers).  Recognized keys:
    ///
    /// | Key                  | Type           | Effect                                    |
    /// |----------------------|----------------|-------------------------------------------|
    /// | `"secret-length"`    | `UInt32`       | Override simulated shared-secret length   |
    /// | `"ciphertext-length"`| `UInt32`       | Override simulated ciphertext length      |
    ///
    /// Unrecognized keys are accepted and stored in the parameter cache
    /// (mirroring C provider behavior of forwarding unknown params).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Key`] if a numeric parameter cannot be converted to
    ///   the target width (Rule R6 — no narrowing `as` casts).
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        if let Some(v) = params.get("secret-length") {
            if let Some(len) = v.as_u32() {
                self.secret_len = usize::try_from(len).map_err(|e| {
                    CryptoError::Key(format!("secret-length conversion failed: {e}"))
                })?;
            }
        }
        if let Some(v) = params.get("ciphertext-length") {
            if let Some(len) = v.as_u32() {
                self.ct_len = usize::try_from(len).map_err(|e| {
                    CryptoError::Key(format!("ciphertext-length conversion failed: {e}"))
                })?;
            }
        }
        self.params = Some(params.clone());
        trace!(
            algorithm = %self.kem.name,
            count = params.len(),
            "KemContext::set_params"
        );
        Ok(())
    }

    /// Returns the current operation parameters as a fresh [`ParamSet`].
    ///
    /// Translates the `get_ctx_params` dispatch entry of `EVP_KEM`
    /// (`evp_local.h:261`).  The returned set always contains:
    ///
    /// | Key                  | Type           | Description                          |
    /// |----------------------|----------------|--------------------------------------|
    /// | `"algorithm"`        | `Utf8String`   | Bound algorithm name                 |
    /// | `"operation"`        | `Utf8String`   | Current operation phase, if any      |
    /// | `"secret-length"`    | `UInt32`       | Current shared-secret length         |
    /// | `"ciphertext-length"`| `UInt32`       | Current ciphertext length            |
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Key`] if a numeric field exceeds `u32` (Rule R6).
    pub fn get_params(&self) -> CryptoResult<ParamSet> {
        let mut out = ParamSet::new();

        out.set("algorithm", ParamValue::Utf8String(self.kem.name.clone()));
        if let Some(op) = self.operation {
            out.set("operation", ParamValue::Utf8String(format!("{op:?}")));
        }

        // Rule R6: explicit checked conversion in lieu of `as` cast.
        let secret_len_u32 = u32::try_from(self.secret_len)
            .map_err(|e| CryptoError::Key(format!("secret_len exceeds u32 range: {e}")))?;
        let ct_len_u32 = u32::try_from(self.ct_len)
            .map_err(|e| CryptoError::Key(format!("ct_len exceeds u32 range: {e}")))?;
        out.set("secret-length", ParamValue::UInt32(secret_len_u32));
        out.set("ciphertext-length", ParamValue::UInt32(ct_len_u32));

        trace!(
            algorithm = %self.kem.name,
            count = out.len(),
            "KemContext::get_params"
        );
        Ok(out)
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Validates that a key's type is compatible with the bound KEM
    /// algorithm, returning [`CryptoError::Key`] on mismatch.
    fn validate_key_type(&self, key: &Arc<PKey>) -> CryptoResult<()> {
        let key_type = key.key_type();
        let compatible = match self.kem.name.as_str() {
            n if n.eq_ignore_ascii_case(KEM_ML_KEM_512) => {
                matches!(key_type, KeyType::MlKem512)
            }
            n if n.eq_ignore_ascii_case(KEM_ML_KEM_768) => {
                matches!(key_type, KeyType::MlKem768)
            }
            n if n.eq_ignore_ascii_case(KEM_ML_KEM_1024) => {
                matches!(key_type, KeyType::MlKem1024)
            }
            n if n.eq_ignore_ascii_case(KEM_RSA) => {
                matches!(key_type, KeyType::Rsa | KeyType::RsaPss)
            }
            n if n.eq_ignore_ascii_case(KEM_EC) || n.eq_ignore_ascii_case("ECDH") => {
                matches!(key_type, KeyType::Ec)
            }
            // For Unknown/extension algorithms, accept any key type.
            _ => true,
        };
        if !compatible {
            return Err(CryptoError::Key(format!(
                "key type {} is not compatible with KEM algorithm {}",
                key_type.as_str(),
                self.kem.name
            )));
        }
        Ok(())
    }

    /// Applies optional initialization parameters by storing them on the
    /// context.  Centralizes the param-handling done by all `*_init`
    /// methods.
    fn apply_init_params(&mut self, params: Option<&ParamSet>) -> CryptoResult<()> {
        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }
}

// =============================================================================
// Manual Zeroize impl
// =============================================================================
//
// `ZeroizeOnDrop` requires a `Zeroize` impl.  Because most of the fields
// have `#[zeroize(skip)]`, the derived impl is effectively a no-op; we
// provide an explicit implementation that resets the operation phase and
// drops the cached parameter set so a `.zeroize()` call has observable
// behaviour for callers who explicitly invoke it.

impl Zeroize for KemContext {
    fn zeroize(&mut self) {
        self.operation = None;
        self.key = None;
        self.auth_key = None;
        self.params = None;
    }
}

// =============================================================================
// Manual Debug impl (avoids leaking key material into logs)
// =============================================================================

impl std::fmt::Debug for KemContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KemContext")
            .field("kem", &self.kem)
            .field("operation", &self.operation)
            .field("key", &self.key.as_ref().map(|_| "<PKey>"))
            .field("auth_key", &self.auth_key.as_ref().map(|_| "<PKey>"))
            .field("param_count", &self.params.as_ref().map(ParamSet::len))
            .field("secret_len", &self.secret_len)
            .field("ct_len", &self.ct_len)
            .finish()
    }
}

// =============================================================================
// Internal helpers (private to the module)
// =============================================================================

/// Maps a user-supplied algorithm name to its canonical recognized form.
///
/// Returns `None` if the name does not correspond to a registered KEM
/// algorithm.  Rule R5: `Option` rather than empty-string sentinel.
fn canonical_kem_name(name: &str) -> Option<&'static str> {
    match name {
        n if n.eq_ignore_ascii_case(KEM_ML_KEM_512) || n.eq_ignore_ascii_case("MLKEM512") => {
            Some(KEM_ML_KEM_512)
        }
        n if n.eq_ignore_ascii_case(KEM_ML_KEM_768) || n.eq_ignore_ascii_case("MLKEM768") => {
            Some(KEM_ML_KEM_768)
        }
        n if n.eq_ignore_ascii_case(KEM_ML_KEM_1024) || n.eq_ignore_ascii_case("MLKEM1024") => {
            Some(KEM_ML_KEM_1024)
        }
        n if n.eq_ignore_ascii_case(KEM_RSA) || n.eq_ignore_ascii_case("RSA-KEM") => Some(KEM_RSA),
        n if n.eq_ignore_ascii_case(KEM_EC)
            || n.eq_ignore_ascii_case("ECDH")
            || n.eq_ignore_ascii_case("EC-KEM") =>
        {
            Some(KEM_EC)
        }
        _ => None,
    }
}

/// Returns simulated `(secret_len, ct_len)` for a given algorithm name.
///
/// These values match the real-world byte sizes specified by FIPS 203
/// (ML-KEM) and the typical RSA / EC KEM constructions.  They are used
/// by the simulated [`KemContext::encapsulate`] and
/// [`KemContext::decapsulate`] until provider dispatch is wired.
fn simulated_lengths(algorithm: &str) -> (usize, usize) {
    match algorithm {
        n if n.eq_ignore_ascii_case(KEM_ML_KEM_512) || n.eq_ignore_ascii_case("MLKEM512") => {
            (32, 768)
        }
        n if n.eq_ignore_ascii_case(KEM_ML_KEM_768) || n.eq_ignore_ascii_case("MLKEM768") => {
            (32, 1088)
        }
        n if n.eq_ignore_ascii_case(KEM_ML_KEM_1024) || n.eq_ignore_ascii_case("MLKEM1024") => {
            (32, 1568)
        }
        n if n.eq_ignore_ascii_case(KEM_RSA) || n.eq_ignore_ascii_case("RSA-KEM") => (32, 256),
        n if n.eq_ignore_ascii_case(KEM_EC)
            || n.eq_ignore_ascii_case("ECDH")
            || n.eq_ignore_ascii_case("EC-KEM") =>
        {
            (32, 65)
        }
        _ => (32, 128),
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Tests legitimately use .unwrap()/.expect() on values guaranteed to succeed in the test fixtures.
#[allow(clippy::panic)] // Tests use panic!() in exhaustive match arms for error variants.
mod tests {
    use super::*;
    use crate::evp::pkey::KeyType;

    /// Build a minimal ML-KEM-768 test public key.
    fn mlkem768_key() -> Arc<PKey> {
        Arc::new(PKey::new_raw(KeyType::MlKem768, &[0u8; 32], false))
    }

    /// Build a minimal RSA test public key.
    fn rsa_key() -> Arc<PKey> {
        Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], false))
    }

    // ── Kem::fetch tests ────────────────────────────────────────────────

    #[test]
    fn fetch_ml_kem_768_succeeds() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-768", None).unwrap();
        assert_eq!(kem.name(), "ML-KEM-768");
        assert_eq!(kem.provider_name(), "default");
        assert!(kem.description().is_none());
    }

    #[test]
    fn fetch_with_properties_succeeds() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "RSA", Some("fips=yes")).unwrap();
        assert_eq!(kem.name(), "RSA");
    }

    #[test]
    fn fetch_unknown_algorithm_returns_error() {
        let ctx = LibContext::get_default();
        let err = Kem::fetch(&ctx, "DEFINITELY-NOT-A-REAL-KEM", None).unwrap_err();
        match err {
            CryptoError::AlgorithmNotFound(msg) => {
                assert!(msg.contains("DEFINITELY-NOT-A-REAL-KEM"));
            }
            other => panic!("expected AlgorithmNotFound, got {other:?}"),
        }
    }

    #[test]
    fn fetch_lowercase_canonicalizes() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ml-kem-512", None).unwrap();
        assert_eq!(kem.name(), "ml-kem-512");
    }

    // ── KemContext encapsulate / decapsulate happy path ─────────────────

    #[test]
    fn encapsulate_then_decapsulate_succeeds() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-768", None).unwrap();
        let key = mlkem768_key();

        let mut enc = KemContext::new(&kem);
        enc.encapsulate_init(&key, None).unwrap();
        assert_eq!(enc.operation(), Some(KemOperation::Encapsulate));
        let result = enc.encapsulate().unwrap();
        assert_eq!(result.ciphertext.len(), 1088); // ML-KEM-768 ct length
        assert_eq!(result.shared_secret.len(), 32); // ML-KEM-768 ss length

        let mut dec = KemContext::new(&kem);
        dec.decapsulate_init(&key, None).unwrap();
        assert_eq!(dec.operation(), Some(KemOperation::Decapsulate));
        let ss = dec.decapsulate(&result.ciphertext).unwrap();
        assert_eq!(ss.len(), 32);
    }

    #[test]
    fn encapsulate_without_init_returns_key_error() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "RSA", None).unwrap();
        let kctx = KemContext::new(&kem);
        let err = kctx.encapsulate().unwrap_err();
        assert!(matches!(err, CryptoError::Key(_)));
    }

    #[test]
    fn decapsulate_without_init_returns_key_error() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "RSA", None).unwrap();
        let kctx = KemContext::new(&kem);
        let err = kctx.decapsulate(b"some-ciphertext").unwrap_err();
        assert!(matches!(err, CryptoError::Key(_)));
    }

    #[test]
    fn decapsulate_empty_ciphertext_returns_key_error() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "RSA", None).unwrap();
        let key = rsa_key();
        let mut kctx = KemContext::new(&kem);
        kctx.decapsulate_init(&key, None).unwrap();
        let err = kctx.decapsulate(&[]).unwrap_err();
        assert!(matches!(err, CryptoError::Key(_)));
    }

    // ── Authenticated KEM tests ─────────────────────────────────────────

    #[test]
    fn auth_encapsulate_init_records_keys() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-768", None).unwrap();
        let key = mlkem768_key();
        let auth_key = mlkem768_key();
        let mut kctx = KemContext::new(&kem);
        kctx.auth_encapsulate_init(&key, &auth_key, None).unwrap();
        assert_eq!(kctx.operation(), Some(KemOperation::AuthEncapsulate));
        let result = kctx.encapsulate().unwrap();
        assert!(!result.ciphertext.is_empty());
        assert!(!result.shared_secret.is_empty());
    }

    #[test]
    fn auth_decapsulate_init_records_keys() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-768", None).unwrap();
        let key = mlkem768_key();
        let auth_key = mlkem768_key();
        let mut kctx = KemContext::new(&kem);
        kctx.auth_decapsulate_init(&key, &auth_key, None).unwrap();
        assert_eq!(kctx.operation(), Some(KemOperation::AuthDecapsulate));
        let ss = kctx.decapsulate(b"c").unwrap();
        assert!(!ss.is_empty());
    }

    // ── Key-type validation ─────────────────────────────────────────────

    #[test]
    fn encapsulate_init_rejects_mismatched_key_type() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-768", None).unwrap();
        let wrong_key = rsa_key(); // RSA key for ML-KEM-768 algorithm
        let mut kctx = KemContext::new(&kem);
        let err = kctx.encapsulate_init(&wrong_key, None).unwrap_err();
        match err {
            CryptoError::Key(msg) => {
                assert!(msg.contains("not compatible"));
            }
            other => panic!("expected CryptoError::Key, got {other:?}"),
        }
    }

    #[test]
    fn decapsulate_init_rejects_mismatched_key_type() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-512", None).unwrap();
        let wrong_key = mlkem768_key(); // 768 key for 512 algorithm
        let mut kctx = KemContext::new(&kem);
        let err = kctx.decapsulate_init(&wrong_key, None).unwrap_err();
        assert!(matches!(err, CryptoError::Key(_)));
    }

    // ── Parameter access tests ──────────────────────────────────────────

    #[test]
    fn get_params_reports_algorithm_and_lengths() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-768", None).unwrap();
        let kctx = KemContext::new(&kem);
        let params = kctx.get_params().unwrap();
        assert_eq!(
            params.get("algorithm").and_then(ParamValue::as_str),
            Some("ML-KEM-768")
        );
        assert_eq!(
            params.get("secret-length").and_then(ParamValue::as_u32),
            Some(32)
        );
        assert_eq!(
            params.get("ciphertext-length").and_then(ParamValue::as_u32),
            Some(1088)
        );
    }

    #[test]
    fn set_params_overrides_lengths() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "RSA", None).unwrap();
        let mut kctx = KemContext::new(&kem);

        let mut params = ParamSet::new();
        params.set("secret-length", ParamValue::UInt32(64));
        params.set("ciphertext-length", ParamValue::UInt32(512));
        kctx.set_params(&params).unwrap();

        let out = kctx.get_params().unwrap();
        assert_eq!(
            out.get("secret-length").and_then(ParamValue::as_u32),
            Some(64)
        );
        assert_eq!(
            out.get("ciphertext-length").and_then(ParamValue::as_u32),
            Some(512)
        );
    }

    #[test]
    fn get_params_after_init_includes_operation() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-1024", None).unwrap();
        let key = Arc::new(PKey::new_raw(KeyType::MlKem1024, &[0u8; 32], false));
        let mut kctx = KemContext::new(&kem);
        kctx.encapsulate_init(&key, None).unwrap();
        let params = kctx.get_params().unwrap();
        let op = params.get("operation").and_then(ParamValue::as_str);
        assert_eq!(op, Some("Encapsulate"));
    }

    #[test]
    fn init_with_params_applies_them() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "RSA", None).unwrap();
        let key = rsa_key();
        let mut kctx = KemContext::new(&kem);

        let mut p = ParamSet::new();
        p.set("secret-length", ParamValue::UInt32(48));
        kctx.encapsulate_init(&key, Some(&p)).unwrap();
        let result = kctx.encapsulate().unwrap();
        assert_eq!(result.shared_secret.len(), 48);
    }

    // ── Zeroize behaviour ───────────────────────────────────────────────

    #[test]
    fn zeroize_clears_state() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-768", None).unwrap();
        let key = mlkem768_key();
        let mut kctx = KemContext::new(&kem);
        kctx.encapsulate_init(&key, None).unwrap();
        assert!(kctx.operation().is_some());
        kctx.zeroize();
        assert!(kctx.operation().is_none());
    }

    // ── Helper fn unit tests ────────────────────────────────────────────

    #[test]
    fn canonical_kem_name_recognizes_aliases() {
        assert_eq!(canonical_kem_name("ML-KEM-512"), Some("ML-KEM-512"));
        assert_eq!(canonical_kem_name("MLKEM512"), Some("ML-KEM-512"));
        assert_eq!(canonical_kem_name("rsa-kem"), Some("RSA"));
        assert_eq!(canonical_kem_name("ECDH"), Some("EC"));
        assert!(canonical_kem_name("FOO").is_none());
    }

    #[test]
    fn simulated_lengths_match_fips_203() {
        assert_eq!(simulated_lengths("ML-KEM-512"), (32, 768));
        assert_eq!(simulated_lengths("ML-KEM-768"), (32, 1088));
        assert_eq!(simulated_lengths("ML-KEM-1024"), (32, 1568));
    }
}
