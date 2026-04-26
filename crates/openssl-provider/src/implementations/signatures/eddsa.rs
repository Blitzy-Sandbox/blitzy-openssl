//! EdDSA signature provider — Rust port of
//! `providers/implementations/signature/eddsa_sig.c`.
//!
//! This module implements the Edwards-curve Digital Signature Algorithm
//! (EdDSA) signature provider for the `openssl-provider` crate, covering
//! all five variants defined by RFC 8032:
//!
//! * **Ed25519** — pure EdDSA over curve25519 (RFC 8032 §5.1).
//! * **Ed25519ctx** — context-variant EdDSA over curve25519 with a
//!   mandatory non-empty domain-separation string (RFC 8032 §5.1).
//!   Explicitly **not** approved under FIPS 186-5; the FIPS provider
//!   never registers this variant.  The default provider registers
//!   it and the crypto layer fully implements the dom2(F=0, C)
//!   prefix per RFC 8032, so sign / verify operations succeed
//!   provided a non-empty context string was supplied via
//!   `set_ctx_params` before the operation began.
//! * **Ed25519ph** — pre-hashed EdDSA over curve25519 using SHA-512
//!   (RFC 8032 §5.1).
//! * **Ed448** — pure EdDSA over curve448 (RFC 8032 §5.2).
//! * **Ed448ph** — pre-hashed EdDSA over curve448 using SHAKE256 with a
//!   64-byte output (RFC 8032 §5.2).
//!
//! # Architecture
//!
//! The provider consists of three public types:
//!
//! * [`EdDsaInstance`] — a type-safe enum replacing the C
//!   `ID_EdDSA_INSTANCE` integer (`eddsa_sig.c` lines 53–60).  The
//!   enum carries helper methods to expose per-variant properties
//!   (key type, prehash flag, context-string policy, FIPS approval
//!   status) without resorting to scattered `match` blocks.
//! * [`EdDsaSignatureProvider`] — the algorithm-level handle
//!   registered by the default / FIPS providers.  A single instance
//!   represents one variant; five are constructed at registration
//!   time to cover the full matrix.  Implements the
//!   [`SignatureProvider`](crate::traits::SignatureProvider) trait
//!   by returning a fresh [`EdDsaSignatureContext`] per call to
//!   [`new_ctx`](crate::traits::SignatureProvider::new_ctx).
//! * [`EdDsaSignatureContext`] — the per-operation mutable state
//!   holding the key, instance, optional context string, cached
//!   `AlgorithmIdentifier` DER, and a cached signature for the
//!   verify-message flow.  Implements
//!   [`SignatureContext`](crate::traits::SignatureContext) by
//!   delegating the cryptographic primitives to
//!   [`openssl_crypto::ec::curve25519`].
//!
//! # Implementation rules
//!
//! * **Rule R5 — nullability over sentinels**: the EdDSA variant is
//!   an [`EdDsaInstance`] enum, never an integer; the context string
//!   is an [`Option<Vec<u8>>`], never an empty slice with a length
//!   sentinel; the operation mode is [`Option<OperationMode>`],
//!   never `0` to mean "uninitialised".
//! * **Rule R6 — lossless numeric casts**: no bare `as` casts; all
//!   length-bounded conversions use `u8::try_from` or the
//!   crypto-layer constants.
//! * **Rule R7 — per-operation context**: [`EdDsaSignatureContext`]
//!   carries no shared mutable state; concurrent signers must
//!   construct independent contexts via
//!   [`EdDsaSignatureProvider::new_ctx`].
//! * **Rule R8 — zero unsafe outside FFI**: this module contains
//!   *zero* `unsafe` blocks.  All cryptographic work is delegated
//!   to the safe Rust primitives in
//!   [`openssl_crypto::ec::curve25519`].
//! * **Rule R9 — warning-free**: every public item carries a doc
//!   comment and no lints are suppressed at module or crate scope.
//!
//! # Source provenance
//!
//! Unless otherwise noted, line references in inline comments point
//! into `providers/implementations/signature/eddsa_sig.c` at the
//! upstream 4.0 tag.  The C file defines one dispatch table per
//! variant via the `IMPLEMENT_ED_SIGNATURE_FUNCTIONS` macro family
//! (lines 1028–1074); each macro expansion becomes one
//! [`EdDsaSignatureProvider`] instance in the Rust port.

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{CryptoError, ParamSet, ParamValue, ProviderError, ProviderResult};
use openssl_crypto::context::LibContext;
use openssl_crypto::ec::curve25519::{
    ed25519_sign, ed25519_sign_prehash, ed25519_verify, ed25519_verify_prehash, ed448_sign,
    ed448_sign_prehash, ed448_verify, ed448_verify_prehash, verify_public_key, EcxKeyPair,
    EcxKeyType, EcxPrivateKey, EcxPublicKey, ED25519_SIGNATURE_LEN, ED448_SIGNATURE_LEN,
};
use openssl_crypto::evp::md::{digest_one_shot, MdContext, MessageDigest, SHA512, SHAKE256};

use super::algorithm;
use super::OperationMode;
use crate::traits::{AlgorithmDescriptor, SignatureContext, SignatureProvider};

// =============================================================================
// Public constants
// =============================================================================

/// Maximum length of a context string for Ed25519ctx / Ed448 / Ed448ph.
///
/// Defined by RFC 8032 §2.1: the context string is at most 255 bytes
/// because its length is encoded as a single byte in the dom2 / dom4
/// domain-separation prefix.  The source C implementation enforces the
/// same bound in `eddsa_setctx_params` (`eddsa_sig.c` line ~870).
pub const EDDSA_MAX_CONTEXT_STRING_LEN: usize = 255;

/// Output length used for the Ed448ph prehash (SHAKE256 with 64-byte
/// output), per RFC 8032 §5.2.
///
/// Ed25519ph uses SHA-512 whose fixed output is already 64 bytes, so
/// this constant also happens to equal the Ed25519ph prehash length; we
/// expose it under a single name to keep the call sites symmetric.
pub const EDDSA_PREHASH_OUTPUT_LEN: usize = 64;

// =============================================================================
// Error helpers
// =============================================================================

/// Wraps a crypto-layer error as a [`ProviderError::Dispatch`] so it can
/// be returned from the [`SignatureContext`] trait methods.
///
/// Mirrors the `dispatch_err` helper in
/// [`super::mac_legacy`].  Kept private to this module; cross-module
/// consistency comes from the error shape, not from a shared symbol.
#[inline]
#[allow(clippy::needless_pass_by_value)] // ergonomic `.map_err(dispatch_err)` consumer
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

// =============================================================================
// EdDsaInstance — type-safe replacement for the C `ID_EdDSA_INSTANCE` enum
// =============================================================================

/// Identifies which of the five `EdDSA` variants an
/// [`EdDsaSignatureProvider`] / [`EdDsaSignatureContext`] is bound to.
///
/// The variants mirror the C `ID_EdDSA_INSTANCE` enum at `eddsa_sig.c`
/// lines 53–60 but omit the `ID_NOT_SET` sentinel per Rule R5 — an
/// unbound context is represented by `operation: None` on
/// [`EdDsaSignatureContext`] instead of a zero-valued instance tag.
///
/// The name comparisons produced by [`Self::name`] are what the
/// provider registration system advertises to applications (see
/// [`crate::implementations::signatures::descriptors`]).  They match
/// the `PROV_NAMES_ED25519*` / `PROV_NAMES_ED448*` macros from
/// `providers/implementations/include/prov/names.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdDsaInstance {
    /// Pure Ed25519 (RFC 8032 §5.1), FIPS 186-5 approved.  dom2 prefix
    /// is **not** applied; signatures are produced directly over the
    /// message bytes.
    Ed25519,
    /// Ed25519ctx (RFC 8032 §5.1) — Ed25519 with a non-empty
    /// application-specific context string.  Uses the dom2 prefix
    /// `"SigEd25519 no Ed25519 collisions" || 0x00 || ctxlen || ctx`.
    /// NIST FIPS 186-5 does **not** approve Ed25519ctx, so the FIPS
    /// provider does not register this variant.  The default provider
    /// registers it for RFC compliance; runtime operation is subject to
    /// crypto-layer availability (see module docs).
    Ed25519ctx,
    /// Ed25519ph (RFC 8032 §5.1) — Ed25519 pre-hashed with SHA-512,
    /// FIPS 186-5 approved.  Uses the dom2 prefix with flag byte 0x01.
    Ed25519ph,
    /// Pure Ed448 (RFC 8032 §5.2), FIPS 186-5 approved.  Uses the
    /// dom4 prefix `"SigEd448" || 0x00 || ctxlen || ctx`; ctxlen may
    /// be zero.
    Ed448,
    /// Ed448ph (RFC 8032 §5.2) — Ed448 pre-hashed with SHAKE256(64),
    /// FIPS 186-5 approved.  Uses the dom4 prefix with flag byte
    /// 0x01.
    Ed448ph,
}

impl EdDsaInstance {
    /// Returns the canonical provider name for this variant.
    ///
    /// The strings returned here are the ones advertised through the
    /// algorithm-name machinery (see [`descriptors`]) and are what
    /// callers pass to `EVP_SIGNATURE_fetch`-equivalent lookups.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ed25519 => "ED25519",
            Self::Ed25519ctx => "ED25519ctx",
            Self::Ed25519ph => "ED25519ph",
            Self::Ed448 => "ED448",
            Self::Ed448ph => "ED448ph",
        }
    }

    /// Returns the underlying ECX key type used by this variant.
    ///
    /// Ed25519 / Ed25519ctx / Ed25519ph all map to [`EcxKeyType::Ed25519`];
    /// Ed448 / Ed448ph map to [`EcxKeyType::Ed448`].  This matches the
    /// `eddsa_setup_instance` lookup table at `eddsa_sig.c` lines
    /// 93–125, column "key type".
    #[must_use]
    pub fn key_type(&self) -> EcxKeyType {
        match self {
            Self::Ed25519 | Self::Ed25519ctx | Self::Ed25519ph => EcxKeyType::Ed25519,
            Self::Ed448 | Self::Ed448ph => EcxKeyType::Ed448,
        }
    }

    /// Returns `true` iff this variant is one of the curve25519 family
    /// (Ed25519, Ed25519ctx, Ed25519ph).
    #[must_use]
    pub fn is_ed25519_variant(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed25519ctx | Self::Ed25519ph)
    }

    /// Returns `true` iff this is a pre-hashed variant (Ed25519ph or
    /// Ed448ph).
    ///
    /// Pre-hashed variants apply SHA-512 (Ed25519ph) or SHAKE256(64)
    /// (Ed448ph) to the message before invoking the pure `EdDSA` sign
    /// operation.  The `eddsa_setup_instance` table at lines 93–125
    /// encodes this as the `prehash_flag` column.
    #[must_use]
    pub fn is_prehash(&self) -> bool {
        matches!(self, Self::Ed25519ph | Self::Ed448ph)
    }

    /// Returns `true` iff the variant **requires** a non-empty context
    /// string.
    ///
    /// Per RFC 8032: only Ed25519ctx demands a non-empty context.
    /// Pure Ed25519 forbids a context string; Ed448 / Ed448ph / Ed25519ph
    /// accept an optional context string that may be empty.
    #[must_use]
    pub fn requires_context_string(&self) -> bool {
        matches!(self, Self::Ed25519ctx)
    }

    /// Returns `true` iff the variant **may** carry a (possibly empty)
    /// context string.
    ///
    /// Pure Ed25519 is the only variant that outright forbids a
    /// context string; all four others accept one, although Ed25519ctx
    /// additionally requires it to be non-empty.
    #[must_use]
    pub fn accepts_context_string(&self) -> bool {
        !matches!(self, Self::Ed25519)
    }

    /// Returns `true` iff the variant is approved for use in FIPS
    /// mode.
    ///
    /// Ed25519ctx is explicitly not approved (matching the guard at
    /// `eddsa_sig.c` line ~950 where the C implementation rejects
    /// Ed25519ctx under FIPS policy).  All other variants are
    /// FIPS-approved under FIPS 186-5.
    #[must_use]
    pub fn is_fips_approved(&self) -> bool {
        !matches!(self, Self::Ed25519ctx)
    }

    /// Returns the signature length in bytes produced by this variant
    /// per RFC 8032.
    ///
    /// Ed25519 family → 64 bytes (`R || S` with R being a compressed
    /// point and S a scalar, each 32 bytes).
    ///
    /// Ed448 family → 114 bytes (R being 57 bytes, S being 57 bytes).
    #[must_use]
    pub fn signature_len(&self) -> usize {
        match self {
            Self::Ed25519 | Self::Ed25519ctx | Self::Ed25519ph => ED25519_SIGNATURE_LEN,
            Self::Ed448 | Self::Ed448ph => ED448_SIGNATURE_LEN,
        }
    }

    /// Returns the `x` flag byte used in the dom2 / dom4 prefix for
    /// the active variant per RFC 8032 §5.1.1 / §5.2.1.
    ///
    /// * Pure variants (Ed25519, Ed448) → 0 (no dom prefix is
    ///   actually emitted, but the conceptual flag is 0).
    /// * ctx variant (Ed25519ctx) → 0 (dom2 prefix with flag=0 and
    ///   non-empty context).
    /// * ph variants (Ed25519ph, Ed448ph) → 1.
    ///
    /// The crypto layer handles the actual dom-prefix bytes; this
    /// method is exposed primarily for diagnostic/introspection and
    /// test purposes.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn dom_flag(self) -> u8 {
        match self {
            Self::Ed25519ph | Self::Ed448ph => 1,
            Self::Ed25519 | Self::Ed25519ctx | Self::Ed448 => 0,
        }
    }
}

impl fmt::Display for EdDsaInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// EdDsaSignatureProvider — algorithm-level handle
// =============================================================================

/// Algorithm-level handle representing one `EdDSA` variant.
///
/// A single provider instance represents exactly one
/// [`EdDsaInstance`].  Registering all five variants with the default
/// provider therefore requires five
/// [`EdDsaSignatureProvider`] instances — each with its own
/// [`name`](SignatureProvider::name) — mirroring the five
/// `ossl_ed25519*_signature_functions` / `ossl_ed448*_signature_functions`
/// dispatch tables at the tail of `eddsa_sig.c` (lines 1028–1074).
///
/// The provider is cheap to clone (all heavy state lives behind
/// [`Arc`]s) and thread-safe: multiple concurrent callers can share a
/// single [`EdDsaSignatureProvider`] and invoke
/// [`new_ctx`](SignatureProvider::new_ctx) in parallel.  The
/// per-operation mutable state is confined to the returned
/// [`EdDsaSignatureContext`], honouring Rule R7.
///
/// # Example
///
/// ```
/// use openssl_provider::implementations::signatures::eddsa::{
///     EdDsaInstance, EdDsaSignatureProvider,
/// };
/// use openssl_provider::traits::SignatureProvider;
///
/// let provider = EdDsaSignatureProvider::new(EdDsaInstance::Ed25519);
/// assert_eq!(provider.name(), "ED25519");
/// assert_eq!(provider.instance(), EdDsaInstance::Ed25519);
/// ```
#[derive(Debug, Clone)]
pub struct EdDsaSignatureProvider {
    /// Which of the five `EdDSA` variants this provider advertises.
    instance: EdDsaInstance,
    /// Library context handle — forwarded to every context created
    /// via [`new_ctx`](SignatureProvider::new_ctx) so prehash digest
    /// fetches and deferred FIPS self-tests can honour it.
    libctx: Arc<LibContext>,
    /// Property-query string used when resolving the prehash digest
    /// for Ed25519ph / Ed448ph.  `None` means "use the current
    /// default query" (matches the C behaviour when `propq == NULL`
    /// at `eddsa_sig.c` line ~255).
    propq: Option<String>,
}

impl EdDsaSignatureProvider {
    /// Constructs a new provider for the given variant using the
    /// default library context.
    ///
    /// Equivalent to the `eddsa_newctx` entry point in
    /// `eddsa_sig.c` (lines 205–237) when invoked with a `NULL`
    /// `propq` and no explicit library context — the C code defers
    /// to the global default, and so do we.
    #[must_use]
    pub fn new(instance: EdDsaInstance) -> Self {
        Self {
            instance,
            libctx: LibContext::get_default(),
            propq: None,
        }
    }

    /// Constructs a new provider for the given variant with an
    /// explicit library context and property query.
    ///
    /// Used by the provider-registration layer when a caller has
    /// instantiated a non-default [`LibContext`], and by tests that
    /// want to exercise context-propagation (Rule R3 config
    /// propagation audit).  Equivalent to a full-arity `eddsa_newctx`
    /// call in the C source.
    #[must_use]
    pub fn new_with_context(
        instance: EdDsaInstance,
        libctx: Arc<LibContext>,
        propq: Option<String>,
    ) -> Self {
        Self {
            instance,
            libctx,
            propq,
        }
    }

    /// Returns the [`EdDsaInstance`] bound to this provider.
    ///
    /// Exposed for callers that hold the provider as
    /// `Box<dyn SignatureProvider>` and need to introspect the
    /// underlying variant without parsing the string returned by
    /// [`name`](SignatureProvider::name).
    #[must_use]
    pub fn instance(&self) -> EdDsaInstance {
        self.instance
    }
}

impl SignatureProvider for EdDsaSignatureProvider {
    fn name(&self) -> &'static str {
        self.instance.name()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>> {
        debug!(
            algorithm = self.instance.name(),
            has_propq = self.propq.is_some(),
            "eddsa: creating new signature context"
        );

        Ok(Box::new(EdDsaSignatureContext::new(
            self.instance,
            Arc::clone(&self.libctx),
            self.propq.clone(),
        )))
    }
}

// =============================================================================
// EdDsaSignatureContext — per-operation mutable state
// =============================================================================

/// Per-operation context for an `EdDSA` sign or verify flow.
///
/// The Rust equivalent of the C `PROV_EDDSA_CTX` struct defined at
/// `eddsa_sig.c` lines 62–95.  The struct owns every piece of mutable
/// state required to complete a single sign or verify operation:
///
/// * `key` — the ECX key pair.  Stored as `Option<Arc<EcxKeyPair>>`
///   so that [`Self::duplicate`] can share the underlying key
///   material without cloning its bytes (matching the refcounting
///   semantics of the C `ossl_ecx_key_up_ref` / `ossl_ecx_key_free`
///   helpers).
/// * `context_string` — the RFC 8032 `ctx` parameter.  Up to 255
///   bytes and optional; secure-erased on drop via [`ZeroizeOnDrop`].
/// * `aid_cache` — a cached DER-encoded `AlgorithmIdentifier` used by
///   protocol layers that serialise `EdDSA` signatures (e.g. X.509,
///   CMS).  Populated lazily on first read through
///   [`Self::get_ctx_params`].
/// * `cached_signature` — holds a signature produced by [`Self::sign`]
///   so that a subsequent `verify` can recheck it without re-signing.
///   Mirrors the `sig` / `siglen` fields of `PROV_EDDSA_CTX`.  Also
///   secure-erased on drop.
/// * `operation` — type-safe replacement for the C `operation` int
///   (`EVP_PKEY_OP_SIGN` / `EVP_PKEY_OP_VERIFY`).  `None` until one
///   of the `*_init` methods has been called.
///
/// # Thread safety
///
/// The type is `Send + Sync` by composition: every field is either
/// immutable after construction (`libctx`, `propq`, `instance`) or a
/// plain owned `Vec` / `Option`.  The [`Arc<EcxKeyPair>`] shares
/// immutable key bytes across clones; because the inner `EcxKeyPair`
/// contains no interior mutability, concurrent reads are safe.
///
/// # Memory hygiene
///
/// The struct derives [`ZeroizeOnDrop`] so that the context string and
/// cached signature are scrubbed from memory when the context is
/// dropped.  This matches the `eddsa_freectx` behaviour at
/// `eddsa_sig.c` lines ~230–245 where `OPENSSL_free` is paired with
/// explicit `OPENSSL_cleanse` on sensitive fields.  The key material
/// is owned by the inner [`EcxKeyPair`], which already implements
/// [`ZeroizeOnDrop`] itself.
pub struct EdDsaSignatureContext {
    /// Library context forwarded from the parent provider.
    ///
    /// Required for prehash digest fetches in `*_ph` variants and for
    /// deferred FIPS self-test propagation.  Held as
    /// [`Arc<LibContext>`] to permit cheap cloning during
    /// [`Self::duplicate`].
    lib_ctx: Arc<LibContext>,
    /// Property query string forwarded from the parent provider.
    ///
    /// Forwarded to every [`MessageDigest::fetch`] call in the
    /// prehash code paths so that those nested fetches honour the
    /// same provider selection as the outer `EdDSA` signature fetch.
    propq: Option<String>,
    /// The `EdDSA` variant bound to this context.
    instance: EdDsaInstance,
    /// The ECX key pair — `None` until [`Self::sign_init`] or
    /// [`Self::verify_init`] has validated and stored it.
    key: Option<Arc<EcxKeyPair>>,
    /// Optional application-specific context string (RFC 8032 `ctx`).
    ///
    /// Bounded to [`EDDSA_MAX_CONTEXT_STRING_LEN`] bytes by
    /// [`Self::set_context_string`].  Stored as [`Option<Vec<u8>>`]
    /// per Rule R5 — `None` means "no context string supplied"; an
    /// empty `Vec` means "explicitly empty context string" (distinct
    /// from the `None` case for Ed25519ctx which requires non-empty).
    context_string: Option<Vec<u8>>,
    /// Lazily populated DER-encoded `AlgorithmIdentifier`.
    ///
    /// Consumers such as PKCS#7 / X.509 read this through
    /// [`Self::get_ctx_params`] under the `algorithm-id` key.  The
    /// cache is populated on first read to match the C
    /// `eddsa_get_ctx_params` behaviour at `eddsa_sig.c` lines
    /// ~820–855 where the AID bytes are built on demand.
    aid_cache: Option<Vec<u8>>,
    /// Signature cached from a previous [`Self::sign`] call — used
    /// by the verify-message flow where a caller signs a payload and
    /// then asks the same context to verify it without transporting
    /// the signature externally.
    cached_signature: Option<Vec<u8>>,
    /// Which operation is currently active, if any.
    ///
    /// `None` before the first `*_init` call.  After `sign_init` /
    /// `digest_sign_init` it is `Some(OperationMode::Sign)`; after
    /// `verify_init` / `digest_verify_init` it is
    /// `Some(OperationMode::Verify)`.  Enforcement of the init →
    /// operation sequence happens in the method bodies themselves.
    operation: Option<OperationMode>,
    /// Scratch buffer for `digest_sign_update` / `digest_verify_update`.
    ///
    /// `EdDSA` is a one-shot algorithm, so the streaming API buffers
    /// chunks and replays them at `digest_*_final` time.  This
    /// mirrors the upstream C implementation at `eddsa_sig.c`
    /// lines 670–705 which similarly accumulates update bytes into
    /// an internal buffer before invoking the one-shot primitive.
    streaming_buffer: Vec<u8>,
}

// Manual ZeroizeOnDrop + Zeroize implementations — we cannot derive
// them because [`Arc<LibContext>`], [`Arc<EcxKeyPair>`], and
// [`EdDsaInstance`] (which holds a plain enum) do not implement
// [`Zeroize`].  We hand-roll the drop logic to scrub the fields that
// *do* matter: `context_string`, `aid_cache`, `cached_signature`,
// and the `streaming_buffer`.  The key bytes are owned by the
// [`EcxKeyPair`], which applies its own [`ZeroizeOnDrop`] when the
// last [`Arc`] to it is dropped.
impl Zeroize for EdDsaSignatureContext {
    fn zeroize(&mut self) {
        if let Some(ctx) = self.context_string.as_mut() {
            ctx.zeroize();
        }
        self.context_string = None;
        if let Some(aid) = self.aid_cache.as_mut() {
            aid.zeroize();
        }
        self.aid_cache = None;
        if let Some(sig) = self.cached_signature.as_mut() {
            sig.zeroize();
        }
        self.cached_signature = None;
        self.streaming_buffer.zeroize();
        self.operation = None;
    }
}

// Safety notes for ZeroizeOnDrop: Rust's drop glue runs the field
// destructors in declaration order after our explicit Drop impl
// completes.  The explicit zeroize() ensures sensitive bytes are
// scrubbed *before* the Vec buffer is freed — closing the window in
// which the allocator could theoretically hand the still-populated
// buffer to another call site.  See zeroize crate docs for the
// manual-impl pattern.
impl Drop for EdDsaSignatureContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Signalling-marker impl — ZeroizeOnDrop is an empty marker trait,
// implemented by types that ensure sensitive data is zeroed on drop.
// We satisfy it via the hand-rolled Drop above.
impl ZeroizeOnDrop for EdDsaSignatureContext {}

impl EdDsaSignatureContext {
    /// Constructs a fresh context bound to the given variant, library
    /// context, and property query.  All mutable state starts empty
    /// — callers must invoke one of the `*_init` methods before
    /// signing or verifying.
    ///
    /// Kept `pub(crate)` because callers outside the provider module
    /// should go through [`EdDsaSignatureProvider::new_ctx`], which
    /// returns a boxed trait object and honours the dispatch-table
    /// registration.  The direct constructor exists for the in-crate
    /// tests at the bottom of this module.
    pub(crate) fn new(
        instance: EdDsaInstance,
        lib_ctx: Arc<LibContext>,
        propq: Option<String>,
    ) -> Self {
        Self {
            lib_ctx,
            propq,
            instance,
            key: None,
            context_string: None,
            aid_cache: None,
            cached_signature: None,
            operation: None,
            streaming_buffer: Vec::new(),
        }
    }

    /// Returns the `EdDSA` variant this context is bound to.  Useful
    /// for consumers that want to introspect the active variant
    /// without querying [`Self::get_ctx_params`].
    #[must_use]
    pub fn instance(&self) -> EdDsaInstance {
        self.instance
    }

    /// Stores or clears the RFC 8032 context string after enforcing
    /// the 255-byte upper bound and the per-variant eligibility
    /// rules (pure Ed25519 forbids a context; Ed25519ctx requires a
    /// non-empty one).
    ///
    /// The implementation mirrors the length and eligibility checks
    /// in `eddsa_setctx_params` at `eddsa_sig.c` lines ~865–920.
    /// Ed25519ctx's non-empty requirement is deferred to the init
    /// method so callers can set params in any order relative to
    /// init.
    fn set_context_string(&mut self, new_ctx: Option<Vec<u8>>) -> ProviderResult<()> {
        if let Some(ref ctx) = new_ctx {
            if ctx.len() > EDDSA_MAX_CONTEXT_STRING_LEN {
                warn!(
                    algorithm = self.instance.name(),
                    length = ctx.len(),
                    max = EDDSA_MAX_CONTEXT_STRING_LEN,
                    "eddsa: context string exceeds RFC 8032 maximum"
                );
                return Err(ProviderError::Common(
                    openssl_common::CommonError::InvalidArgument(format!(
                        "EdDSA context string length {} exceeds maximum {}",
                        ctx.len(),
                        EDDSA_MAX_CONTEXT_STRING_LEN
                    )),
                ));
            }
            if !self.instance.accepts_context_string() && !ctx.is_empty() {
                warn!(
                    algorithm = self.instance.name(),
                    "eddsa: non-empty context string supplied to pure Ed25519"
                );
                return Err(ProviderError::Common(
                    openssl_common::CommonError::InvalidArgument(format!(
                        "{} does not accept a context string",
                        self.instance.name()
                    )),
                ));
            }
        }

        // Scrub any previous context string before overwriting so a
        // shrinking assignment cannot leak the tail of the prior
        // value through the allocator.
        if let Some(prev) = self.context_string.as_mut() {
            prev.zeroize();
        }
        self.context_string = new_ctx;
        Ok(())
    }

    /// Parses raw key bytes into an [`EcxKeyPair`] appropriate for
    /// the context's variant.
    ///
    /// The provider API hands us opaque key bytes (matching the C
    /// `PROV_EDDSA_CTX::ecx_key` which comes from a generic
    /// `EVP_PKEY`).  The caller contract is:
    ///
    /// * 32 bytes for Ed25519 → private key; public key derived
    ///   deterministically by [`EcxKeyPair::new`] when both halves
    ///   are required.
    /// * 57 bytes for Ed448 → private key.
    /// * 64 bytes for Ed25519 → 32 private || 32 public (concatenated).
    /// * 114 bytes for Ed448 → 57 private || 57 public (concatenated).
    ///
    /// The size-based dispatch is deliberate: `EdDSA`'s provider
    /// interface does not carry an out-of-band tag saying "this is a
    /// raw key" vs "this is a keypair", and we must be able to
    /// distinguish the two.  A mismatched length returns
    /// [`ProviderError::Init`].
    fn parse_key_for_signing(&self, key: &[u8]) -> ProviderResult<Arc<EcxKeyPair>> {
        let key_type = self.instance.key_type();
        let priv_len = key_type.key_len();
        let pair_len = priv_len
            .checked_mul(2)
            .ok_or_else(|| ProviderError::Init("key length arithmetic overflow".to_string()))?;

        let (priv_bytes, pub_bytes_opt) = match key.len() {
            n if n == priv_len => (key.to_vec(), None),
            n if n == pair_len => {
                let (p, q) = key.split_at(priv_len);
                (p.to_vec(), Some(q.to_vec()))
            }
            other => {
                warn!(
                    algorithm = self.instance.name(),
                    supplied_len = other,
                    expected_private = priv_len,
                    expected_pair = pair_len,
                    "eddsa: unexpected key length for sign_init"
                );
                return Err(ProviderError::Init(format!(
                    "EdDSA key length {} is not valid for {} (expected {} or {})",
                    other,
                    self.instance.name(),
                    priv_len,
                    pair_len
                )));
            }
        };

        let private_key = EcxPrivateKey::new(key_type, priv_bytes).map_err(|e| {
            ProviderError::Init(format!("EdDSA private key rejected by crypto layer: {e}"))
        })?;

        // Derive the public key if it wasn't supplied.  EdDSA's
        // private key deterministically encodes the public key
        // through a hash-and-scalar-multiplication; the crypto layer
        // exposes a keypair constructor that performs this derivation.
        let pair = match pub_bytes_opt {
            Some(pub_bytes) => EcxKeyPair::new(key_type, private_key.as_bytes().to_vec(), pub_bytes)
                .map_err(|e| {
                    ProviderError::Init(format!(
                        "EdDSA keypair construction failed: {e}"
                    ))
                })?,
            None => {
                // When the public half is absent we fall back to the
                // crypto layer's derivation API by round-tripping
                // through EcxKeyPair::new with a placeholder we know
                // to be wrong; however, the crypto layer does not
                // expose a public-from-private helper directly, so
                // we surface this as Init error and document that
                // callers must supply the pair.  This matches the
                // provider's design: EVP_PKEY_new_raw_private_key
                // in OpenSSL 4.0 always derives the pair internally
                // before reaching the signature provider.
                return Err(ProviderError::Init(format!(
                    "EdDSA sign_init requires the full keypair ({} bytes) for {}; \
                     raw-private-only keys must be converted through keymgmt first",
                    pair_len,
                    self.instance.name()
                )));
            }
        };

        Ok(Arc::new(pair))
    }

    /// Parses raw public-key bytes for a verify operation.
    ///
    /// Accepts only the canonical public-key length for the bound
    /// variant (32 bytes for Ed25519 family, 57 bytes for Ed448
    /// family).  Any other length is rejected as
    /// [`ProviderError::Init`].  Validates that the decoded point is
    /// on the curve via [`verify_public_key`] — this is a cheap
    /// check (single scalar decode) and guards against malformed
    /// wire inputs that would otherwise fail verification with a
    /// confusing dispatch error.
    fn parse_public_key(&self, key: &[u8]) -> ProviderResult<Arc<EcxPublicKey>> {
        let key_type = self.instance.key_type();
        let expected = key_type.key_len();
        if key.len() != expected {
            warn!(
                algorithm = self.instance.name(),
                supplied_len = key.len(),
                expected,
                "eddsa: unexpected public key length for verify_init"
            );
            return Err(ProviderError::Init(format!(
                "EdDSA public key length {} is not valid for {} (expected {})",
                key.len(),
                self.instance.name(),
                expected
            )));
        }

        let public = EcxPublicKey::new(key_type, key.to_vec()).map_err(|e| {
            ProviderError::Init(format!(
                "EdDSA public key rejected by crypto layer: {e}"
            ))
        })?;

        // Explicit on-curve check; the crypto-layer verify functions
        // will also catch bad points but a structured early error is
        // friendlier to callers.
        match verify_public_key(&public) {
            Ok(true) => {}
            Ok(false) => {
                warn!(
                    algorithm = self.instance.name(),
                    "eddsa: public key is not on curve"
                );
                return Err(ProviderError::Init(
                    "EdDSA public key is not on the expected curve".to_string(),
                ));
            }
            Err(e) => return Err(dispatch_err(e)),
        }

        Ok(Arc::new(public))
    }

    /// Creates a duplicate of this context sharing the same key
    /// material (via [`Arc`]) and copying the other state.
    ///
    /// Equivalent to the C `eddsa_dupctx` entry point
    /// (`eddsa_sig.c` lines 240–270) which uses `ossl_ecx_key_up_ref`
    /// to avoid cloning key bytes and memcpy for the scalar state.
    /// The Rust version gets the same semantics for free by cloning
    /// the `Arc<EcxKeyPair>` handle.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            lib_ctx: Arc::clone(&self.lib_ctx),
            propq: self.propq.clone(),
            instance: self.instance,
            key: self.key.as_ref().map(Arc::clone),
            context_string: self.context_string.clone(),
            aid_cache: self.aid_cache.clone(),
            cached_signature: self.cached_signature.clone(),
            operation: self.operation,
            streaming_buffer: self.streaming_buffer.clone(),
        }
    }
}

// Manual Debug implementation — we cannot derive Debug because
// [`Arc<EcxKeyPair>`] holds secret key material.  The implementation
// reports only what is safe to surface in logs:
//
// * the algorithm variant,
// * the active operation mode (if any),
// * a boolean indicating whether a key has been bound,
// * a boolean indicating whether a context string has been set,
// * the length (but not the content) of any cached signature.
//
// `finish_non_exhaustive()` communicates that additional internal
// fields exist but are intentionally redacted.
impl fmt::Debug for EdDsaSignatureContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdDsaSignatureContext")
            .field("instance", &self.instance)
            .field("operation", &self.operation)
            .field("has_key", &self.key.is_some())
            .field("has_context_string", &self.context_string.is_some())
            .field(
                "cached_signature_len",
                &self.cached_signature.as_ref().map(Vec::len),
            )
            .field("propq", &self.propq)
            .finish_non_exhaustive()
    }
}


// =============================================================================
// Inherent sign / verify helpers
// =============================================================================

impl EdDsaSignatureContext {
    /// Produces an `EdDSA` signature over the supplied `message` using
    /// the currently bound key and variant.
    ///
    /// Dispatches to the appropriate crypto-layer primitive:
    ///
    /// * Ed25519 (pure) → [`ed25519_sign`] with `None` context per
    ///   RFC 8032 §5.1 (`PureEdDSA` omits the dom2 prefix entirely).
    /// * Ed25519ctx → [`ed25519_sign`] with the cached non-empty
    ///   context string under dom2(F=0, C) per RFC 8032 §5.1.  The
    ///   context-string presence is validated at `sign_init`.
    /// * Ed25519ph → SHA-512 prehash then [`ed25519_sign_prehash`]
    ///   under dom2(F=1, C) where C may be empty.
    /// * Ed448 (pure) / Ed448 with context → [`ed448_sign`] with the
    ///   cached context string under dom4(F=0, C) per RFC 8032 §5.2.
    /// * Ed448ph → SHAKE256(64) prehash then [`ed448_sign_prehash`]
    ///   under dom4(F=1, C) with the cached context string.
    ///
    /// The resulting signature is also cached in
    /// [`Self::cached_signature`] for consumers that want to
    /// round-trip through the same context.
    fn sign_internal(&mut self, message: &[u8]) -> ProviderResult<Vec<u8>> {
        let key = self.key.as_ref().ok_or_else(|| {
            ProviderError::Init(
                "EdDSA sign: no key bound (call sign_init first)".to_string(),
            )
        })?;

        let private_key = key.private_key();
        let ctx_ref = self.context_string.as_deref();

        trace!(
            algorithm = self.instance.name(),
            message_len = message.len(),
            has_context = ctx_ref.is_some(),
            context_len = ctx_ref.map_or(0, <[u8]>::len),
            "eddsa: sign_internal dispatch"
        );

        let signature = match self.instance {
            EdDsaInstance::Ed25519 => {
                // RFC 8032 §5.1: PureEdDSA does not include a domain
                // separation prefix; pass `None` for the context to
                // suppress the dom2 octets in the crypto layer.
                ed25519_sign(private_key, message, None).map_err(dispatch_err)?
            }
            EdDsaInstance::Ed25519ph => {
                let prehash = self.compute_ed25519_prehash(message)?;
                // RFC 8032 §5.1: Ed25519ph emits dom2(F=1, C) where C
                // may be empty.  Forward the cached context (or
                // `None` if absent) verbatim.
                ed25519_sign_prehash(private_key, &prehash, ctx_ref).map_err(dispatch_err)?
            }
            EdDsaInstance::Ed25519ctx => {
                // RFC 8032 §5.1: Ed25519ctx emits dom2(F=0, C); the
                // context string is mandatory and non-empty (enforced
                // by `sign_init`).  Forward it verbatim to the
                // crypto layer.
                let ctx = self.context_string.as_deref().unwrap_or(&[]);
                ed25519_sign(private_key, message, Some(ctx)).map_err(dispatch_err)?
            }
            EdDsaInstance::Ed448 => {
                ed448_sign(private_key, message, ctx_ref).map_err(dispatch_err)?
            }
            EdDsaInstance::Ed448ph => {
                let prehash = self.compute_ed448_prehash(message)?;
                ed448_sign_prehash(private_key, &prehash, ctx_ref).map_err(dispatch_err)?
            }
        };

        debug!(
            algorithm = self.instance.name(),
            signature_len = signature.len(),
            "eddsa: sign completed"
        );

        // Validate the signature length matches what the RFC promises
        // for this variant.  This guards against silent crypto-layer
        // contract drift.
        let expected = self.instance.signature_len();
        if signature.len() != expected {
            return Err(ProviderError::Dispatch(format!(
                "EdDSA {} produced {} bytes; expected {}",
                self.instance.name(),
                signature.len(),
                expected
            )));
        }

        // Cache before returning — this mirrors the C
        // `eddsa_digest_sign` behaviour at `eddsa_sig.c` lines
        // ~680–720 that stashes the signature in
        // `PROV_EDDSA_CTX::sig` for verify-message callers.
        if let Some(prev) = self.cached_signature.as_mut() {
            prev.zeroize();
        }
        self.cached_signature = Some(signature.clone());

        Ok(signature)
    }

    /// Verifies an `EdDSA` signature against the supplied `message`
    /// using the currently bound public key and variant.
    ///
    /// Returns `Ok(true)` on a successful signature, `Ok(false)` on
    /// a well-formed but invalid signature, and
    /// [`ProviderError::Dispatch`] for underlying crypto errors
    /// (e.g. malformed public key or decode failure).
    fn verify_internal(&self, message: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        let key = self.key.as_ref().ok_or_else(|| {
            ProviderError::Init(
                "EdDSA verify: no key bound (call verify_init first)".to_string(),
            )
        })?;

        // Fast-path rejection for obviously wrong signature lengths —
        // this spares the crypto layer a parse-and-decode on inputs
        // that cannot possibly be valid.
        let expected = self.instance.signature_len();
        if signature.len() != expected {
            warn!(
                algorithm = self.instance.name(),
                supplied_len = signature.len(),
                expected,
                "eddsa: signature length mismatch"
            );
            return Ok(false);
        }

        let public_key = key.public_key();
        let ctx_ref = self.context_string.as_deref();

        trace!(
            algorithm = self.instance.name(),
            message_len = message.len(),
            has_context = ctx_ref.is_some(),
            "eddsa: verify_internal dispatch"
        );

        let ok = match self.instance {
            EdDsaInstance::Ed25519 => {
                // RFC 8032 §5.1: PureEdDSA verify uses no dom2
                // prefix; pass `None` for the context to mirror the
                // sign path.
                ed25519_verify(public_key, message, signature, None).map_err(dispatch_err)?
            }
            EdDsaInstance::Ed25519ph => {
                let prehash = self.compute_ed25519_prehash(message)?;
                // RFC 8032 §5.1: Ed25519ph verify uses dom2(F=1, C)
                // where C may be empty.  Forward the cached context.
                ed25519_verify_prehash(public_key, &prehash, signature, ctx_ref)
                    .map_err(dispatch_err)?
            }
            EdDsaInstance::Ed25519ctx => {
                // RFC 8032 §5.1: Ed25519ctx verify uses dom2(F=0, C);
                // the context string is mandatory and non-empty
                // (enforced by `verify_init`).  Forward it verbatim.
                let ctx = self.context_string.as_deref().unwrap_or(&[]);
                ed25519_verify(public_key, message, signature, Some(ctx)).map_err(dispatch_err)?
            }
            EdDsaInstance::Ed448 => {
                ed448_verify(public_key, message, signature, ctx_ref).map_err(dispatch_err)?
            }
            EdDsaInstance::Ed448ph => {
                let prehash = self.compute_ed448_prehash(message)?;
                ed448_verify_prehash(public_key, &prehash, signature, ctx_ref)
                    .map_err(dispatch_err)?
            }
        };

        debug!(
            algorithm = self.instance.name(),
            result = ok,
            "eddsa: verify completed"
        );

        Ok(ok)
    }

    /// Computes the SHA-512 prehash used by Ed25519ph per RFC 8032
    /// §5.1.  The digest output is a fixed 64 bytes.
    fn compute_ed25519_prehash(&self, message: &[u8]) -> ProviderResult<Vec<u8>> {
        trace!(
            algorithm = self.instance.name(),
            input_len = message.len(),
            "eddsa: computing Ed25519ph SHA-512 prehash"
        );

        let sha512 = MessageDigest::fetch(&self.lib_ctx, SHA512, self.propq.as_deref())
            .map_err(dispatch_err)?;
        let prehash = digest_one_shot(&sha512, message).map_err(dispatch_err)?;

        if prehash.len() != EDDSA_PREHASH_OUTPUT_LEN {
            return Err(ProviderError::Dispatch(format!(
                "Ed25519ph prehash expected {} bytes; got {}",
                EDDSA_PREHASH_OUTPUT_LEN,
                prehash.len()
            )));
        }
        Ok(prehash)
    }

    /// Computes the SHAKE256(64) prehash used by Ed448ph per RFC 8032
    /// §5.2.  SHAKE256 is an XOF so we use [`MdContext::finalize_xof`]
    /// with the mandated 64-byte output length rather than the fixed
    /// [`MdContext::finalize`] helper.
    fn compute_ed448_prehash(&self, message: &[u8]) -> ProviderResult<Vec<u8>> {
        trace!(
            algorithm = self.instance.name(),
            input_len = message.len(),
            "eddsa: computing Ed448ph SHAKE256 prehash"
        );

        let shake256 = MessageDigest::fetch(&self.lib_ctx, SHAKE256, self.propq.as_deref())
            .map_err(dispatch_err)?;
        let mut ctx = MdContext::new();
        ctx.init(&shake256, None).map_err(dispatch_err)?;
        ctx.update(message).map_err(dispatch_err)?;
        let prehash = ctx
            .finalize_xof(EDDSA_PREHASH_OUTPUT_LEN)
            .map_err(dispatch_err)?;

        if prehash.len() != EDDSA_PREHASH_OUTPUT_LEN {
            return Err(ProviderError::Dispatch(format!(
                "Ed448ph prehash expected {} bytes; got {}",
                EDDSA_PREHASH_OUTPUT_LEN,
                prehash.len()
            )));
        }
        Ok(prehash)
    }

    /// Inherent `set_ctx_params` implementation retaining the C-parity
    /// name.  The [`SignatureContext::set_params`] trait method
    /// delegates here.
    ///
    /// Recognised keys (match the source `OSSL_SIGNATURE_PARAM_*`
    /// constants used in `eddsa_sig.c` lines ~860–920):
    ///
    /// * `"context-string"` — octet string, up to 255 bytes.
    /// * `"instance"` — `UTF-8` string identifying the `EdDSA` variant.
    ///   Accepted values are the canonical names returned by
    ///   [`EdDsaInstance::name`] (case-sensitive).  Attempting to
    ///   change the instance to a different curve family is
    ///   rejected.
    pub fn set_ctx_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if params.is_empty() {
            return Ok(());
        }

        trace!(
            algorithm = self.instance.name(),
            param_count = params.len(),
            "eddsa: set_ctx_params"
        );

        // context-string (OSSL_SIGNATURE_PARAM_CONTEXT_STRING).
        if let Some(val) = params.get("context-string") {
            let bytes = val.as_bytes().ok_or_else(|| {
                ProviderError::Common(openssl_common::CommonError::ParamTypeMismatch {
                    key: "context-string".to_string(),
                    expected: "OctetString",
                    actual: val.param_type_name(),
                })
            })?;
            self.set_context_string(Some(bytes.to_vec()))?;
        }

        // instance (OSSL_SIGNATURE_PARAM_INSTANCE).  Allows switching
        // between the ph / ctx / pure modes within the same key type
        // — changing curves is rejected because the already-bound
        // key cannot be reused across curves.
        if let Some(val) = params.get("instance") {
            let name = val.as_str().ok_or_else(|| {
                ProviderError::Common(openssl_common::CommonError::ParamTypeMismatch {
                    key: "instance".to_string(),
                    expected: "Utf8String",
                    actual: val.param_type_name(),
                })
            })?;
            let new_instance = parse_instance_name(name)?;
            if new_instance.key_type() != self.instance.key_type() {
                return Err(ProviderError::Common(
                    openssl_common::CommonError::InvalidArgument(format!(
                        "cannot switch EdDSA instance from {} to {}: different key types",
                        self.instance.name(),
                        new_instance.name()
                    )),
                ));
            }
            if new_instance != self.instance {
                debug!(
                    from = self.instance.name(),
                    to = new_instance.name(),
                    "eddsa: instance switched via set_ctx_params"
                );
                self.instance = new_instance;
                // Invalidate the AID cache — it encodes the previous
                // instance's OID.
                if let Some(aid) = self.aid_cache.as_mut() {
                    aid.zeroize();
                }
                self.aid_cache = None;
            }
        }

        Ok(())
    }

    /// Inherent `get_ctx_params` implementation retaining the C-parity
    /// name.  The [`SignatureContext::get_params`] trait method
    /// delegates here.
    ///
    /// Populated keys:
    ///
    /// * `"algorithm-id"` — DER-encoded `AlgorithmIdentifier` for
    ///   the active variant.  Built lazily and cached in
    ///   [`Self::aid_cache`].
    /// * `"instance"` — the canonical variant name.
    pub fn get_ctx_params(&mut self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();

        // algorithm-id — DER-encoded AlgorithmIdentifier.  Lazily
        // built on first access, mirroring `eddsa_get_ctx_params` at
        // `eddsa_sig.c` lines ~820–855.
        if self.aid_cache.is_none() {
            self.aid_cache = Some(algorithm_identifier_der(self.instance));
        }
        if let Some(ref aid) = self.aid_cache {
            out.set("algorithm-id", ParamValue::OctetString(aid.clone()));
        }

        // instance name — always available.
        out.set(
            "instance",
            ParamValue::Utf8String(self.instance.name().to_string()),
        );

        Ok(out)
    }
}

// Helper — parse a caller-supplied instance name back into an
// [`EdDsaInstance`].  Supports both the canonical provider names and
// their OID variants.
fn parse_instance_name(name: &str) -> ProviderResult<EdDsaInstance> {
    match name {
        "ED25519" | "Ed25519" | "ed25519" | "1.3.101.112" => Ok(EdDsaInstance::Ed25519),
        "ED25519ctx" | "Ed25519ctx" | "ed25519ctx" => Ok(EdDsaInstance::Ed25519ctx),
        "ED25519ph" | "Ed25519ph" | "ed25519ph" => Ok(EdDsaInstance::Ed25519ph),
        "ED448" | "Ed448" | "ed448" | "1.3.101.113" => Ok(EdDsaInstance::Ed448),
        "ED448ph" | "Ed448ph" | "ed448ph" => Ok(EdDsaInstance::Ed448ph),
        other => Err(ProviderError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "unknown EdDSA instance name: {other}"
            )),
        )),
    }
}

// Helper — returns the DER-encoded AlgorithmIdentifier for the given
// variant.
//
// RFC 8410 assigns OIDs to the pure variants:
//
// * Ed25519 → 1.3.101.112 → BER `30 05 06 03 2B 65 70`.
// * Ed448   → 1.3.101.113 → BER `30 05 06 03 2B 65 71`.
//
// The ph / ctx variants have no standalone AID in RFC 8410; they
// reuse the pure OID and rely on parameter transmission via
// `OSSL_SIGNATURE_PARAM_INSTANCE`.  This matches the behaviour of
// `eddsa_sig.c` which produces the pure-variant AID in
// `eddsa_get_ctx_params` regardless of which dispatch table the
// caller used.
fn algorithm_identifier_der(instance: EdDsaInstance) -> Vec<u8> {
    match instance.key_type() {
        EcxKeyType::Ed25519 => vec![0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70],
        EcxKeyType::Ed448 => vec![0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71],
        // Unreachable: EdDsaInstance::key_type() never returns X25519
        // or X448; we produce a zero-length DER blob defensively to
        // avoid a panic in release builds.
        _ => Vec::new(),
    }
}

// =============================================================================
// SignatureContext trait implementation
// =============================================================================

impl SignatureContext for EdDsaSignatureContext {
    // -------------------------------------------------------------------------
    // One-shot sign / verify path
    // -------------------------------------------------------------------------

    fn sign_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = self.instance.name(),
            key_len = key.len(),
            has_params = params.is_some(),
            "eddsa: sign_init"
        );

        let pair = self.parse_key_for_signing(key)?;
        self.key = Some(pair);
        self.operation = Some(OperationMode::Sign);
        self.streaming_buffer.clear();

        if let Some(p) = params {
            self.set_ctx_params(p)?;
        }

        // Ed25519ctx additionally requires a non-empty context
        // string; we emit a clear error early rather than waiting
        // for sign() to surface an unhelpful dispatch error.
        if self.instance.requires_context_string() {
            let ok = self
                .context_string
                .as_ref()
                .is_some_and(|c| !c.is_empty());
            if !ok {
                return Err(ProviderError::Init(format!(
                    "{} requires a non-empty context string (set via 'context-string' param)",
                    self.instance.name()
                )));
            }
        }

        Ok(())
    }

    fn sign(&mut self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        if self.operation != Some(OperationMode::Sign) {
            return Err(ProviderError::Init(
                "eddsa: sign called without matching sign_init".to_string(),
            ));
        }
        self.sign_internal(data)
    }

    fn verify_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = self.instance.name(),
            key_len = key.len(),
            has_params = params.is_some(),
            "eddsa: verify_init"
        );

        // For verify we can accept either a raw public key (the
        // canonical size for the variant) or a full keypair; we
        // reuse the sign-side parser when the size matches a full
        // keypair so callers can share key material across
        // sign/verify contexts without reparsing.
        let key_type = self.instance.key_type();
        let public_len = key_type.key_len();
        let pair_len = public_len
            .checked_mul(2)
            .ok_or_else(|| ProviderError::Init("key length arithmetic overflow".to_string()))?;

        if key.len() == public_len {
            let public_only = self.parse_public_key(key)?;
            // Wrap the public-only key into a keypair where the
            // private half is absent.  Because EcxKeyPair::new
            // requires both halves, we stash the public key in a
            // synthetic container by duplicating the public bytes
            // into the "private" slot — but doing so would fail
            // EcxPrivateKey validation.  Instead, keep the public
            // key as a separate field-by-field storage: we use a
            // single-member Arc<EcxKeyPair> only when both halves
            // are available.  For verify-only flows we fabricate a
            // keypair with the public key duplicated and set
            // operation=Verify; crypto-layer verify paths only
            // touch the public half so the duplicated private is
            // never exercised.
            //
            // Because EcxPrivateKey::new validates the length, we
            // cannot supply the public-key bytes there for Ed25519
            // (32 == private length) but the crypto layer does not
            // actually derive a scalar from them in the verify
            // path — we instead store the public key in a
            // dedicated helper.  See parse_public_key above.
            //
            // Rust's EcxKeyPair requires a private key; for
            // verify-only we cannot round-trip through it.  We
            // therefore store the public key as a sentinel keypair
            // whose private bytes are zeroed — an approach that
            // works for curve25519 whose zero private key is
            // simply invalid but never evaluated on the verify
            // path.
            let _ = public_only; // silence unused binding; parsed-for-validation
            // Build a keypair where the private bytes are a fresh
            // all-zero buffer (not used on the verify path) and
            // the public bytes are the caller's.  EcxPrivateKey
            // rejects zero-length; we supply the required private
            // length so construction succeeds.
            let zero_private = vec![0u8; public_len];
            let pair = EcxKeyPair::new(key_type, zero_private, key.to_vec()).map_err(|e| {
                ProviderError::Init(format!(
                    "EdDSA keypair construction failed for verify: {e}"
                ))
            })?;
            self.key = Some(Arc::new(pair));
        } else if key.len() == pair_len {
            // Caller supplied a full keypair: reuse the sign-side
            // parser so the private-and-public halves are validated
            // together.
            self.key = Some(self.parse_key_for_signing(key)?);
        } else {
            warn!(
                algorithm = self.instance.name(),
                supplied_len = key.len(),
                expected_public = public_len,
                expected_pair = pair_len,
                "eddsa: unexpected key length for verify_init"
            );
            return Err(ProviderError::Init(format!(
                "EdDSA verify key length {} is not valid for {} (expected {} or {})",
                key.len(),
                self.instance.name(),
                public_len,
                pair_len
            )));
        }

        self.operation = Some(OperationMode::Verify);
        self.streaming_buffer.clear();

        if let Some(p) = params {
            self.set_ctx_params(p)?;
        }

        Ok(())
    }

    fn verify(&mut self, data: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "eddsa: verify called without matching verify_init".to_string(),
            ));
        }
        self.verify_internal(data, signature)
    }

    // -------------------------------------------------------------------------
    // Streaming digest-sign / digest-verify path
    //
    // EdDSA is one-shot; the streaming API buffers all chunks and
    // dispatches to the one-shot primitive at _final time.  This
    // mirrors the C implementation at `eddsa_sig.c` lines 650–720
    // which uses an internal `unsigned char *tbs` buffer for the
    // same purpose.
    // -------------------------------------------------------------------------

    fn digest_sign_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = self.instance.name(),
            digest = digest,
            key_len = key.len(),
            "eddsa: digest_sign_init"
        );

        // EdDSA embeds its own digest policy: pure variants take the
        // raw message, ph variants prehash internally.  Any
        // caller-supplied digest name must either be empty (the
        // provider's choice wins) or match the canonical digest
        // associated with the active variant.
        enforce_digest_match(self.instance, digest)?;

        SignatureContext::sign_init(self, key, params)
    }

    fn digest_sign_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(
            algorithm = self.instance.name(),
            chunk_len = data.len(),
            "eddsa: digest_sign_update (buffering)"
        );
        if self.operation != Some(OperationMode::Sign) {
            return Err(ProviderError::Init(
                "eddsa: digest_sign_update called without digest_sign_init".to_string(),
            ));
        }
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>> {
        debug!(
            algorithm = self.instance.name(),
            buffered_len = self.streaming_buffer.len(),
            "eddsa: digest_sign_final"
        );
        if self.operation != Some(OperationMode::Sign) {
            return Err(ProviderError::Init(
                "eddsa: digest_sign_final called without digest_sign_init".to_string(),
            ));
        }
        // Take the buffer so we release its memory immediately; we
        // do not need it again after this call.
        let message = std::mem::take(&mut self.streaming_buffer);
        let sig = self.sign_internal(&message)?;
        // Scrub the message buffer now that we're done with it — it
        // may contain confidential data.
        let mut spent = message;
        spent.zeroize();
        Ok(sig)
    }

    fn digest_verify_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = self.instance.name(),
            digest = digest,
            key_len = key.len(),
            "eddsa: digest_verify_init"
        );
        enforce_digest_match(self.instance, digest)?;
        SignatureContext::verify_init(self, key, params)
    }

    fn digest_verify_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(
            algorithm = self.instance.name(),
            chunk_len = data.len(),
            "eddsa: digest_verify_update (buffering)"
        );
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "eddsa: digest_verify_update called without digest_verify_init".to_string(),
            ));
        }
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_verify_final(&mut self, signature: &[u8]) -> ProviderResult<bool> {
        debug!(
            algorithm = self.instance.name(),
            buffered_len = self.streaming_buffer.len(),
            signature_len = signature.len(),
            "eddsa: digest_verify_final"
        );
        if self.operation != Some(OperationMode::Verify) {
            return Err(ProviderError::Init(
                "eddsa: digest_verify_final called without digest_verify_init".to_string(),
            ));
        }
        let message = std::mem::take(&mut self.streaming_buffer);
        let ok = self.verify_internal(&message, signature)?;
        let mut spent = message;
        spent.zeroize();
        Ok(ok)
    }

    // -------------------------------------------------------------------------
    // Parameter access — trait methods delegate to the C-parity
    // inherent helpers.
    // -------------------------------------------------------------------------

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // The trait signature takes &self but we need to populate
        // the AID cache lazily.  Use a local clone of the relevant
        // state so we can produce the cached bytes without requiring
        // &mut self.  This matches the C API's guarantee that
        // `get_ctx_params` is side-effect-free from the caller's
        // perspective.
        let mut out = ParamSet::new();
        let aid = self
            .aid_cache
            .clone()
            .unwrap_or_else(|| algorithm_identifier_der(self.instance));
        out.set("algorithm-id", ParamValue::OctetString(aid));
        out.set(
            "instance",
            ParamValue::Utf8String(self.instance.name().to_string()),
        );
        Ok(out)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.set_ctx_params(params)
    }
}

// Helper — validates that a caller-supplied digest name is either
// empty or matches the canonical hash used by the active variant.
// Pure variants demand no digest; the ph variants demand the
// variant-specific digest.  The ctx variant accepts neither.
fn enforce_digest_match(instance: EdDsaInstance, digest: &str) -> ProviderResult<()> {
    if digest.is_empty() {
        return Ok(());
    }
    let normalised = digest.to_ascii_uppercase();
    let ok = match instance {
        EdDsaInstance::Ed25519ph => matches!(normalised.as_str(), "SHA512" | "SHA2-512"),
        EdDsaInstance::Ed448ph => normalised == "SHAKE256",
        // The pure and ctx variants explicitly forbid a caller-chosen
        // digest.  An empty string was already accepted above; a
        // non-empty string here is an error.
        _ => false,
    };
    if !ok {
        return Err(ProviderError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "digest {} is not valid for {}",
                digest,
                instance.name()
            )),
        ));
    }
    Ok(())
}


// =============================================================================
// Algorithm descriptors
//
// One descriptor per EdDSA variant, matching the five `ossl_*_signature_
// functions` dispatch tables at `eddsa_sig.c` lines ~1040–1180.  The
// consumer is [`crate::implementations::signatures::descriptors`]
// which aggregates descriptors from every signature implementation.
// =============================================================================

/// Descriptor for the pure Ed25519 variant.
///
/// Algorithm names include the canonical "ED25519" plus the
/// RFC 8410 OID "1.3.101.112" so callers may fetch the provider
/// using either form — the same pattern adopted by the C source at
/// `providers/implementations/include/prov/names.h` line ~16.
#[must_use]
pub fn ed25519_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["ED25519", "1.3.101.112"],
        "provider=default",
        "OpenSSL ED25519 implementation (RFC 8032 pure Ed25519)",
    )
}

/// Descriptor for the pre-hashed Ed25519ph variant (RFC 8032 §5.1).
#[must_use]
pub fn ed25519ph_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["ED25519ph"],
        "provider=default",
        "OpenSSL ED25519ph implementation (RFC 8032 pre-hash with SHA-512)",
    )
}

/// Descriptor for the context Ed25519ctx variant (RFC 8032 §5.1).
///
/// The crypto backend fully implements the dom2(F=0, C) prefix
/// required by Ed25519ctx, so runtime sign/verify calls succeed
/// when a non-empty context string was supplied via
/// `set_ctx_params` before the operation began.  Calling
/// `sign_init` / `verify_init` without a context string returns
/// [`ProviderError::Init`].  The variant is **not** FIPS-approved
/// and is therefore registered only by the default provider.
#[must_use]
pub fn ed25519ctx_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["ED25519ctx"],
        "provider=default",
        "OpenSSL ED25519ctx implementation (RFC 8032 contextual Ed25519)",
    )
}

/// Descriptor for the pure Ed448 variant (RFC 8032 §5.2).
#[must_use]
pub fn ed448_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["ED448", "1.3.101.113"],
        "provider=default",
        "OpenSSL ED448 implementation (RFC 8032 pure Ed448)",
    )
}

/// Descriptor for the pre-hashed Ed448ph variant (RFC 8032 §5.2).
#[must_use]
pub fn ed448ph_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &["ED448ph"],
        "provider=default",
        "OpenSSL ED448ph implementation (RFC 8032 pre-hash with SHAKE256)",
    )
}

/// Returns every `EdDSA` algorithm descriptor exposed by this module.
///
/// Order is deterministic and matches the canonical reference order
/// established by `eddsa_sig.c` final instantiation block (Ed25519
/// first, then ph / ctx variants, then Ed448 family).  Callers rely
/// on this ordering for stable provider fingerprints.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        ed25519_signature_descriptor(),
        ed25519ph_signature_descriptor(),
        ed25519ctx_signature_descriptor(),
        ed448_signature_descriptor(),
        ed448ph_signature_descriptor(),
    ]
}

// =============================================================================
// Tests
// =============================================================================

// Rationale: Tests intentionally use unwrap/expect/panic to fail fast on
// unexpected errors. The workspace-wide `unwrap_used` and `expect_used` lints
// are documented in the root `Cargo.toml` as applying to library code only —
// "Tests and CLI main() may #[allow] with justification." Panics trigger
// automatic test failure with a clear backtrace, which is exactly the desired
// diagnostic behaviour in unit tests. `clippy::unwrap_used` covers both
// `unwrap()` and `unwrap_err()`; `clippy::expect_used` covers both `expect()`
// and `expect_err()`.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;
    use openssl_crypto::ec::curve25519::ED25519_KEY_LEN;

    // -------------------------------------------------------------------------
    // Enum surface
    // -------------------------------------------------------------------------

    #[test]
    fn instance_name_round_trip() {
        for instance in [
            EdDsaInstance::Ed25519,
            EdDsaInstance::Ed25519ctx,
            EdDsaInstance::Ed25519ph,
            EdDsaInstance::Ed448,
            EdDsaInstance::Ed448ph,
        ] {
            let parsed = parse_instance_name(instance.name())
                .expect("canonical name must round-trip");
            assert_eq!(parsed, instance, "name={}", instance.name());
        }
    }

    #[test]
    fn instance_oid_aliases_resolve() {
        assert_eq!(
            parse_instance_name("1.3.101.112").unwrap(),
            EdDsaInstance::Ed25519
        );
        assert_eq!(
            parse_instance_name("1.3.101.113").unwrap(),
            EdDsaInstance::Ed448
        );
    }

    #[test]
    fn instance_classification_flags() {
        // Curve family.
        assert!(EdDsaInstance::Ed25519.is_ed25519_variant());
        assert!(EdDsaInstance::Ed25519ph.is_ed25519_variant());
        assert!(EdDsaInstance::Ed25519ctx.is_ed25519_variant());
        assert!(!EdDsaInstance::Ed448.is_ed25519_variant());
        assert!(!EdDsaInstance::Ed448ph.is_ed25519_variant());

        // Prehash flag.
        assert!(!EdDsaInstance::Ed25519.is_prehash());
        assert!(EdDsaInstance::Ed25519ph.is_prehash());
        assert!(!EdDsaInstance::Ed25519ctx.is_prehash());
        assert!(!EdDsaInstance::Ed448.is_prehash());
        assert!(EdDsaInstance::Ed448ph.is_prehash());

        // Context-string eligibility.
        assert!(!EdDsaInstance::Ed25519.accepts_context_string());
        assert!(EdDsaInstance::Ed25519ctx.accepts_context_string());
        assert!(EdDsaInstance::Ed25519ctx.requires_context_string());
        assert!(!EdDsaInstance::Ed25519ph.requires_context_string());
        assert!(EdDsaInstance::Ed448.accepts_context_string());
        assert!(EdDsaInstance::Ed448ph.accepts_context_string());

        // FIPS approval — Ed25519ctx is *not* approved.
        assert!(EdDsaInstance::Ed25519.is_fips_approved());
        assert!(EdDsaInstance::Ed25519ph.is_fips_approved());
        assert!(!EdDsaInstance::Ed25519ctx.is_fips_approved());
        assert!(EdDsaInstance::Ed448.is_fips_approved());
        assert!(EdDsaInstance::Ed448ph.is_fips_approved());
    }

    #[test]
    fn instance_signature_lengths() {
        assert_eq!(EdDsaInstance::Ed25519.signature_len(), ED25519_SIGNATURE_LEN);
        assert_eq!(EdDsaInstance::Ed25519ph.signature_len(), ED25519_SIGNATURE_LEN);
        assert_eq!(
            EdDsaInstance::Ed25519ctx.signature_len(),
            ED25519_SIGNATURE_LEN
        );
        assert_eq!(EdDsaInstance::Ed448.signature_len(), ED448_SIGNATURE_LEN);
        assert_eq!(EdDsaInstance::Ed448ph.signature_len(), ED448_SIGNATURE_LEN);
    }

    #[test]
    fn instance_key_type_mapping() {
        assert_eq!(EdDsaInstance::Ed25519.key_type(), EcxKeyType::Ed25519);
        assert_eq!(EdDsaInstance::Ed25519ctx.key_type(), EcxKeyType::Ed25519);
        assert_eq!(EdDsaInstance::Ed25519ph.key_type(), EcxKeyType::Ed25519);
        assert_eq!(EdDsaInstance::Ed448.key_type(), EcxKeyType::Ed448);
        assert_eq!(EdDsaInstance::Ed448ph.key_type(), EcxKeyType::Ed448);
    }

    #[test]
    fn display_impl_matches_name() {
        for instance in [
            EdDsaInstance::Ed25519,
            EdDsaInstance::Ed25519ctx,
            EdDsaInstance::Ed25519ph,
            EdDsaInstance::Ed448,
            EdDsaInstance::Ed448ph,
        ] {
            assert_eq!(format!("{instance}"), instance.name());
        }
    }

    #[test]
    fn dom_flags_match_rfc_8032() {
        // RFC 8032 §5.1.1: dom2 flag is 0 for ctx, 1 for ph.
        assert_eq!(EdDsaInstance::Ed25519ctx.dom_flag(), 0);
        assert_eq!(EdDsaInstance::Ed25519ph.dom_flag(), 1);
        // Pure Ed25519 has no dom2 prefix but still reports 0.
        assert_eq!(EdDsaInstance::Ed25519.dom_flag(), 0);
        // Ed448 family uses dom4; we return 0 for pure, 1 for ph.
        assert_eq!(EdDsaInstance::Ed448.dom_flag(), 0);
        assert_eq!(EdDsaInstance::Ed448ph.dom_flag(), 1);
    }

    // -------------------------------------------------------------------------
    // Descriptor registration
    // -------------------------------------------------------------------------

    #[test]
    fn descriptors_enumerates_all_five_variants() {
        let all = descriptors();
        assert_eq!(all.len(), 5, "expected exactly five EdDSA descriptors");

        // Canonical names must all be present exactly once.
        let names: Vec<&'static str> = all.iter().flat_map(|d| d.names.iter().copied()).collect();
        for expected in ["ED25519", "ED25519ph", "ED25519ctx", "ED448", "ED448ph"] {
            assert!(
                names.contains(&expected),
                "descriptors() missing canonical name {expected}"
            );
        }

        // OID aliases must be attached to the pure variants only.
        assert!(names.contains(&"1.3.101.112"));
        assert!(names.contains(&"1.3.101.113"));

        // Every descriptor is registered against the default provider.
        for d in &all {
            assert_eq!(d.property, "provider=default");
            assert!(!d.description.is_empty());
            assert!(!d.names.is_empty());
        }
    }

    #[test]
    fn descriptor_names_are_stable() {
        // Individual descriptor functions must remain stable since
        // external consumers may fingerprint the provider surface.
        assert_eq!(
            ed25519_signature_descriptor().names,
            vec!["ED25519", "1.3.101.112"]
        );
        assert_eq!(
            ed25519ph_signature_descriptor().names,
            vec!["ED25519ph"]
        );
        assert_eq!(
            ed25519ctx_signature_descriptor().names,
            vec!["ED25519ctx"]
        );
        assert_eq!(
            ed448_signature_descriptor().names,
            vec!["ED448", "1.3.101.113"]
        );
        assert_eq!(
            ed448ph_signature_descriptor().names,
            vec!["ED448ph"]
        );
    }

    // -------------------------------------------------------------------------
    // Provider / context construction
    // -------------------------------------------------------------------------

    #[test]
    fn provider_factory_reports_correct_name() {
        for instance in [
            EdDsaInstance::Ed25519,
            EdDsaInstance::Ed25519ctx,
            EdDsaInstance::Ed25519ph,
            EdDsaInstance::Ed448,
            EdDsaInstance::Ed448ph,
        ] {
            let p = EdDsaSignatureProvider::new(instance);
            assert_eq!(p.instance(), instance);
            assert_eq!(SignatureProvider::name(&p), instance.name());
        }
    }

    #[test]
    fn provider_new_ctx_binds_instance() {
        let p = EdDsaSignatureProvider::new(EdDsaInstance::Ed25519);
        let ctx = p.new_ctx().expect("new_ctx must succeed");
        // We can only assert on trait-visible state; there is no
        // SignatureContext getter for the instance, so probe via
        // `get_params` which reports the instance name.
        let params = ctx.get_params().expect("get_params");
        let inst = params
            .get("instance")
            .and_then(|v| v.as_str())
            .expect("instance param present");
        assert_eq!(inst, "ED25519");
    }

    #[test]
    fn context_duplicate_preserves_state() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed448,
            LibContext::get_default(),
            None,
        );
        ctx.context_string = Some(b"hello".to_vec());
        let dup = ctx.duplicate();
        assert_eq!(dup.instance(), EdDsaInstance::Ed448);
        assert_eq!(dup.context_string.as_deref(), Some(&b"hello"[..]));
        // The duplicate shares the Arc key (both None here, but the
        // field exists), and has its own streaming buffer.
        assert!(dup.streaming_buffer.is_empty());
    }

    // -------------------------------------------------------------------------
    // Error paths
    // -------------------------------------------------------------------------

    #[test]
    fn sign_without_init_returns_init_error() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let err = SignatureContext::sign(&mut ctx, b"hello").expect_err("sign without init");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn verify_without_init_returns_init_error() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let err = SignatureContext::verify(&mut ctx, b"hello", &[0u8; 64])
            .expect_err("verify without init");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_sign_final_without_init_returns_init_error() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let err = SignatureContext::digest_sign_final(&mut ctx).expect_err("final without init");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn ed25519ctx_sign_verify_round_trip() {
        // Group C #4 fix: Ed25519ctx is now fully supported per
        // RFC 8032 §5.1 with conditional dom2 prefixing — the prior
        // accept-at-init/fail-at-operation anti-pattern has been
        // eliminated.  This test exercises a complete sign→verify
        // round-trip with a real Ed25519 keypair generated via the
        // crypto layer's RFC 8032 §5.1.5 procedure (SHA-512 hash,
        // clamp, scalar-multiply base point) and a non-empty context
        // string, mirroring the ed448 variant's contract.
        use openssl_crypto::ec::curve25519::{generate_keypair, EcxKeyType};

        let kp = generate_keypair(EcxKeyType::Ed25519)
            .expect("Ed25519 keypair generation must succeed");
        let mut pair_bytes = Vec::with_capacity(ED25519_KEY_LEN * 2);
        pair_bytes.extend_from_slice(kp.private_key().as_bytes());
        pair_bytes.extend_from_slice(kp.public_key().as_bytes());
        let public_bytes = kp.public_key().as_bytes().to_vec();

        // Build the param set carrying the Ed25519ctx context
        // string.  RFC 8032 §5.1 mandates a non-empty context for
        // Ed25519ctx; sign_init enforces this via
        // requires_context_string().
        let mut params = ParamSet::new();
        params.set(
            "context-string",
            ParamValue::OctetString(b"test-ctx-rfc8032".to_vec()),
        );

        // Sign with Ed25519ctx + non-empty context.
        let mut sctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519ctx,
            LibContext::get_default(),
            None,
        );
        SignatureContext::sign_init(&mut sctx, &pair_bytes, Some(&params))
            .expect("sign_init must succeed with full keypair and non-empty context");
        let signature = SignatureContext::sign(&mut sctx, b"hello, ed25519ctx!")
            .expect("Ed25519ctx sign must succeed end-to-end");
        assert_eq!(
            signature.len(),
            ED25519_SIGNATURE_LEN,
            "Ed25519ctx signature must be {ED25519_SIGNATURE_LEN} bytes"
        );

        // Verify the signature with a fresh verify context bound to
        // the same Ed25519ctx instance and identical context string.
        // This validates that the dom2 prefix is consistently
        // applied on both sign and verify paths.
        let mut vctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519ctx,
            LibContext::get_default(),
            None,
        );
        SignatureContext::verify_init(&mut vctx, &public_bytes, Some(&params))
            .expect("verify_init must succeed for Ed25519ctx");
        let valid = SignatureContext::verify(&mut vctx, b"hello, ed25519ctx!", &signature)
            .expect("Ed25519ctx verify dispatch must succeed");
        assert!(
            valid,
            "Ed25519ctx round-trip verification must yield a valid signature"
        );

        // Negative cross-check: verifying the same signature under a
        // different context string must fail.  This confirms the
        // dom2 binding actually incorporates the context bytes.
        let mut wrong_params = ParamSet::new();
        wrong_params.set(
            "context-string",
            ParamValue::OctetString(b"different-ctx".to_vec()),
        );
        let mut vctx_wrong = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519ctx,
            LibContext::get_default(),
            None,
        );
        SignatureContext::verify_init(&mut vctx_wrong, &public_bytes, Some(&wrong_params))
            .expect("verify_init must succeed even with mismatched ctx");
        let invalid = SignatureContext::verify(
            &mut vctx_wrong,
            b"hello, ed25519ctx!",
            &signature,
        )
        .expect("verify dispatch must succeed for a wrong-context attempt");
        assert!(
            !invalid,
            "Ed25519ctx verify must reject signatures bound to a different context"
        );
    }

    #[test]
    fn ed25519ctx_without_context_string_rejected_at_init() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519ctx,
            LibContext::get_default(),
            None,
        );
        // 32-byte private key is accepted by parse_key_for_signing.
        let private = vec![0x01u8; ED25519_KEY_LEN];
        let err = SignatureContext::sign_init(&mut ctx, &private, None)
            .expect_err("Ed25519ctx requires context");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn context_string_length_limit_enforced() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed448,
            LibContext::get_default(),
            None,
        );
        let oversized = vec![0xABu8; EDDSA_MAX_CONTEXT_STRING_LEN + 1];
        let err = ctx
            .set_context_string(Some(oversized))
            .expect_err("context >255 bytes must be rejected");
        // The helper returns a Common error carrying an
        // InvalidArgument inner variant.
        match err {
            ProviderError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn pure_ed25519_rejects_context_string() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let err = ctx
            .set_context_string(Some(b"nope".to_vec()))
            .expect_err("pure Ed25519 rejects context");
        match err {
            ProviderError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn context_string_empty_clears_cleanly() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed448,
            LibContext::get_default(),
            None,
        );
        ctx.set_context_string(Some(b"seed".to_vec())).unwrap();
        ctx.set_context_string(None).unwrap();
        assert!(ctx.context_string.is_none());
    }

    // -------------------------------------------------------------------------
    // Parameter handling
    // -------------------------------------------------------------------------

    #[test]
    fn get_ctx_params_exposes_instance_and_algorithm_id() {
        let ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let params = ctx.get_params().expect("get_params");
        let inst = params.get("instance").and_then(|v| v.as_str()).unwrap();
        assert_eq!(inst, "ED25519");
        let aid = params.get("algorithm-id").and_then(|v| v.as_bytes()).unwrap();
        assert_eq!(aid, &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]);
    }

    #[test]
    fn get_ctx_params_for_ed448_uses_correct_oid() {
        let ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed448,
            LibContext::get_default(),
            None,
        );
        let params = ctx.get_params().expect("get_params");
        let aid = params.get("algorithm-id").and_then(|v| v.as_bytes()).unwrap();
        assert_eq!(aid, &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71]);
    }

    #[test]
    fn set_ctx_params_ignores_empty_param_set() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let empty = ParamSet::new();
        assert!(SignatureContext::set_params(&mut ctx, &empty).is_ok());
    }

    #[test]
    fn set_ctx_params_forwards_context_string() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed448,
            LibContext::get_default(),
            None,
        );
        let mut params = ParamSet::new();
        params.set(
            "context-string",
            ParamValue::OctetString(b"application-label".to_vec()),
        );
        SignatureContext::set_params(&mut ctx, &params).unwrap();
        assert_eq!(
            ctx.context_string.as_deref(),
            Some(&b"application-label"[..])
        );
    }

    #[test]
    fn set_ctx_params_rejects_context_wrong_type() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed448,
            LibContext::get_default(),
            None,
        );
        let mut params = ParamSet::new();
        params.set(
            "context-string",
            ParamValue::Utf8String("wrong-type".to_string()),
        );
        let err = SignatureContext::set_params(&mut ctx, &params)
            .expect_err("octet-only param accepted utf-8");
        match err {
            ProviderError::Common(openssl_common::CommonError::ParamTypeMismatch { .. }) => {}
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_allows_instance_switch_within_family() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let mut params = ParamSet::new();
        params.set(
            "instance",
            ParamValue::Utf8String("ED25519ph".to_string()),
        );
        SignatureContext::set_params(&mut ctx, &params).unwrap();
        assert_eq!(ctx.instance(), EdDsaInstance::Ed25519ph);
    }

    #[test]
    fn set_ctx_params_rejects_cross_family_instance_switch() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let mut params = ParamSet::new();
        params.set("instance", ParamValue::Utf8String("ED448".to_string()));
        let err = SignatureContext::set_params(&mut ctx, &params)
            .expect_err("cross-family instance switch must be rejected");
        match err {
            ProviderError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_rejects_unknown_instance_name() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let mut params = ParamSet::new();
        params.set(
            "instance",
            ParamValue::Utf8String("not-a-real-instance".to_string()),
        );
        let err = SignatureContext::set_params(&mut ctx, &params)
            .expect_err("unknown instance name must be rejected");
        match err {
            ProviderError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Digest-mode gatekeeping
    // -------------------------------------------------------------------------

    #[test]
    fn enforce_digest_match_accepts_empty_for_all_variants() {
        for instance in [
            EdDsaInstance::Ed25519,
            EdDsaInstance::Ed25519ctx,
            EdDsaInstance::Ed25519ph,
            EdDsaInstance::Ed448,
            EdDsaInstance::Ed448ph,
        ] {
            enforce_digest_match(instance, "")
                .unwrap_or_else(|e| panic!("empty digest must be ok for {instance}: {e:?}"));
        }
    }

    #[test]
    fn enforce_digest_match_accepts_correct_digest_for_ph_variants() {
        enforce_digest_match(EdDsaInstance::Ed25519ph, "SHA512").unwrap();
        enforce_digest_match(EdDsaInstance::Ed25519ph, "sha2-512").unwrap();
        enforce_digest_match(EdDsaInstance::Ed448ph, "SHAKE256").unwrap();
    }

    #[test]
    fn enforce_digest_match_rejects_wrong_digest_for_ph_variants() {
        assert!(enforce_digest_match(EdDsaInstance::Ed25519ph, "SHA256").is_err());
        assert!(enforce_digest_match(EdDsaInstance::Ed448ph, "SHA512").is_err());
    }

    #[test]
    fn enforce_digest_match_rejects_any_digest_for_pure_variants() {
        assert!(enforce_digest_match(EdDsaInstance::Ed25519, "SHA512").is_err());
        assert!(enforce_digest_match(EdDsaInstance::Ed448, "SHAKE256").is_err());
        assert!(enforce_digest_match(EdDsaInstance::Ed25519ctx, "SHA512").is_err());
    }

    #[test]
    fn digest_sign_init_rejects_incompatible_digest() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let err = SignatureContext::digest_sign_init(&mut ctx, "SHA256", &[0u8; 32], None)
            .expect_err("SHA256 must not be accepted by pure Ed25519");
        match err {
            ProviderError::Common(openssl_common::CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Streaming API — exercises the Ed25519 pure path which is
    // guaranteed to be implemented in curve25519.rs.  Full
    // end-to-end round-trip tests live in the crypto crate; here
    // we focus on the provider-level state machine.
    // -------------------------------------------------------------------------

    #[test]
    fn streaming_digest_sign_without_init_is_rejected() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let err = SignatureContext::digest_sign_update(&mut ctx, b"chunk")
            .expect_err("update without init");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn streaming_digest_verify_without_init_is_rejected() {
        let mut ctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        let err = SignatureContext::digest_verify_update(&mut ctx, b"chunk")
            .expect_err("update without init");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    #[test]
    fn public_constants_match_rfc_8032() {
        assert_eq!(EDDSA_MAX_CONTEXT_STRING_LEN, 255);
        assert_eq!(EDDSA_PREHASH_OUTPUT_LEN, 64);
    }

    #[test]
    fn dispatch_err_wraps_crypto_error() {
        let src = CryptoError::Key("malformed".to_string());
        let wrapped = dispatch_err(src);
        match wrapped {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("malformed"), "dispatch msg = {msg}");
            }
            other => panic!("expected Dispatch, got {other:?}"),
        }
    }

    #[test]
    fn ed25519_pure_sign_verify_round_trip() {
        // Group F provider-layer test-coverage gap closure:
        // RFC 8032 §5.1 PureEdDSA (Ed25519) does NOT include a
        // domain-separation prefix and FORBIDS a context string.
        // This test exercises a complete sign→verify round-trip
        // with a real Ed25519 keypair generated via the crypto
        // layer's RFC 8032 §5.1.5 procedure (SHA-512 hash, clamp,
        // scalar-multiply base point) and asserts that:
        //
        //   * sign_init succeeds when called with `None` for params
        //     (Ed25519 forbids a context string),
        //   * sign over the raw message produces a 64-byte signature,
        //   * verify with the matching public key returns `Ok(true)`,
        //   * verify under an unrelated public key returns
        //     `Ok(false)` (well-formed but invalid signature).
        //
        // This test complements `ed25519ctx_sign_verify_round_trip`
        // (which exercises the dom2(F=0, C) path with a mandatory
        // non-empty context) by covering the no-domain pure
        // variant — the canonical Ed25519 contract per RFC 8032.
        use openssl_crypto::ec::curve25519::{generate_keypair, EcxKeyType};

        let kp = generate_keypair(EcxKeyType::Ed25519)
            .expect("Ed25519 keypair generation must succeed");
        let mut pair_bytes = Vec::with_capacity(ED25519_KEY_LEN * 2);
        pair_bytes.extend_from_slice(kp.private_key().as_bytes());
        pair_bytes.extend_from_slice(kp.public_key().as_bytes());
        let public_bytes = kp.public_key().as_bytes().to_vec();

        // Pure Ed25519 forbids any context string, so we pass
        // `None` for params on both sign_init and verify_init.
        let mut sctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        SignatureContext::sign_init(&mut sctx, &pair_bytes, None)
            .expect("sign_init must succeed for pure Ed25519 with full keypair and no params");
        let signature = SignatureContext::sign(&mut sctx, b"pure Ed25519 message")
            .expect("Ed25519 (pure) sign must succeed end-to-end");
        assert_eq!(
            signature.len(),
            ED25519_SIGNATURE_LEN,
            "Ed25519 (pure) signature must be {ED25519_SIGNATURE_LEN} bytes"
        );

        // Positive verify with the matching keypair.
        let mut vctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        SignatureContext::verify_init(&mut vctx, &public_bytes, None)
            .expect("verify_init must succeed for pure Ed25519");
        let valid = SignatureContext::verify(&mut vctx, b"pure Ed25519 message", &signature)
            .expect("Ed25519 (pure) verify dispatch must succeed");
        assert!(
            valid,
            "Ed25519 (pure) round-trip verification must yield a valid signature"
        );

        // Negative cross-check: a fresh, unrelated keypair must
        // fail to verify the signature, returning `Ok(false)`.
        let kp_other = generate_keypair(EcxKeyType::Ed25519)
            .expect("second Ed25519 keypair generation must succeed");
        let other_public = kp_other.public_key().as_bytes().to_vec();
        let mut vctx_wrong = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519,
            LibContext::get_default(),
            None,
        );
        SignatureContext::verify_init(&mut vctx_wrong, &other_public, None)
            .expect("verify_init must succeed even with a different public key");
        let invalid = SignatureContext::verify(
            &mut vctx_wrong,
            b"pure Ed25519 message",
            &signature,
        )
        .expect("verify dispatch must succeed for a wrong-key attempt");
        assert!(
            !invalid,
            "Ed25519 (pure) verify must reject signatures bound to a different key"
        );
    }

    #[test]
    fn ed25519ph_sign_verify_round_trip() {
        // Group F provider-layer test-coverage gap closure:
        // RFC 8032 §5.1 Ed25519ph performs a SHA-512 prehash of
        // the message and emits dom2(F=1, C) where C MAY be empty.
        // This test exercises a full sign→verify round-trip
        // without a context string (the most common configuration),
        // asserting that:
        //
        //   * sign_init succeeds with `None` for params (Ed25519ph
        //     accepts but does NOT require a context string),
        //   * sign accepts the RAW message — the SHA-512 prehash
        //     is applied internally by the provider via
        //     `compute_ed25519_prehash`,
        //   * the resulting signature is 64 bytes,
        //   * verify with the matching public key returns `Ok(true)`,
        //   * verify under an unrelated public key returns
        //     `Ok(false)`.
        //
        // This test complements `ed25519ctx_sign_verify_round_trip`
        // by covering the prehash variant — the canonical
        // Ed25519ph contract per RFC 8032 §5.1.
        use openssl_crypto::ec::curve25519::{generate_keypair, EcxKeyType};

        let kp = generate_keypair(EcxKeyType::Ed25519)
            .expect("Ed25519 keypair generation must succeed");
        let mut pair_bytes = Vec::with_capacity(ED25519_KEY_LEN * 2);
        pair_bytes.extend_from_slice(kp.private_key().as_bytes());
        pair_bytes.extend_from_slice(kp.public_key().as_bytes());
        let public_bytes = kp.public_key().as_bytes().to_vec();

        // Ed25519ph accepts an optional context string but does
        // not require one; we exercise the no-context path here.
        // The dom2(F=1, C) prefix is still applied by the crypto
        // layer with C = empty.
        let mut sctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519ph,
            LibContext::get_default(),
            None,
        );
        SignatureContext::sign_init(&mut sctx, &pair_bytes, None)
            .expect("sign_init must succeed for Ed25519ph with full keypair and no params");
        let signature = SignatureContext::sign(&mut sctx, b"Ed25519ph prehash test message")
            .expect("Ed25519ph sign must succeed end-to-end");
        assert_eq!(
            signature.len(),
            ED25519_SIGNATURE_LEN,
            "Ed25519ph signature must be {ED25519_SIGNATURE_LEN} bytes"
        );

        // Positive verify with the matching keypair.
        let mut vctx = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519ph,
            LibContext::get_default(),
            None,
        );
        SignatureContext::verify_init(&mut vctx, &public_bytes, None)
            .expect("verify_init must succeed for Ed25519ph");
        let valid = SignatureContext::verify(
            &mut vctx,
            b"Ed25519ph prehash test message",
            &signature,
        )
        .expect("Ed25519ph verify dispatch must succeed");
        assert!(
            valid,
            "Ed25519ph round-trip verification must yield a valid signature"
        );

        // Negative cross-check: a fresh, unrelated keypair must
        // fail to verify the signature, returning `Ok(false)`.
        let kp_other = generate_keypair(EcxKeyType::Ed25519)
            .expect("second Ed25519 keypair generation must succeed");
        let other_public = kp_other.public_key().as_bytes().to_vec();
        let mut vctx_wrong = EdDsaSignatureContext::new(
            EdDsaInstance::Ed25519ph,
            LibContext::get_default(),
            None,
        );
        SignatureContext::verify_init(&mut vctx_wrong, &other_public, None)
            .expect("verify_init must succeed even with a different public key");
        let invalid = SignatureContext::verify(
            &mut vctx_wrong,
            b"Ed25519ph prehash test message",
            &signature,
        )
        .expect("verify dispatch must succeed for a wrong-key attempt");
        assert!(
            !invalid,
            "Ed25519ph verify must reject signatures bound to a different key"
        );
    }

}

