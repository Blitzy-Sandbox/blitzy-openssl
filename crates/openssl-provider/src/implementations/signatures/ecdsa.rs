//! ECDSA signature provider — sign and verify with NIST P-curves.
//!
//! This module mirrors `providers/implementations/signature/ecdsa_sig.c` from
//! the OpenSSL 4.0 C source.  It exposes a strongly-typed Rust translation of
//! the provider-side ECDSA signature pipeline so the new Rust workspace can be
//! linked into the surrounding provider framework via the
//! [`crate::traits::SignatureProvider`] / [`crate::traits::SignatureContext`]
//! trait pair.
//!
//! # Supported algorithms
//!
//! Both *composable* (digest-of-message supplied externally) and *fixed*
//! signature-algorithm (digest implicitly chosen by the algorithm name) modes
//! are supported.  The full list mirrors the C source `IMPL_ECDSA_SIGALG`
//! macro instantiations:
//!
//! | Variant            | Primary name      | Aliases                                                       |
//! |--------------------|-------------------|---------------------------------------------------------------|
//! | Composable         | `ECDSA`           | —                                                             |
//! | `EcdsaSha1`        | `ECDSA-SHA1`      | `ECDSA-SHA-1`, `ecdsa-with-SHA1`, `1.2.840.10045.4.1`         |
//! | `EcdsaSha224`      | `ECDSA-SHA2-224`  | `ECDSA-SHA224`, `ecdsa-with-SHA224`, `1.2.840.10045.4.3.1`    |
//! | `EcdsaSha256`      | `ECDSA-SHA2-256`  | `ECDSA-SHA256`, `ecdsa-with-SHA256`, `1.2.840.10045.4.3.2`    |
//! | `EcdsaSha384`      | `ECDSA-SHA2-384`  | `ECDSA-SHA384`, `ecdsa-with-SHA384`, `1.2.840.10045.4.3.3`    |
//! | `EcdsaSha512`      | `ECDSA-SHA2-512`  | `ECDSA-SHA512`, `ecdsa-with-SHA512`, `1.2.840.10045.4.3.4`    |
//! | `EcdsaSha3_224`    | `ECDSA-SHA3-224`  | `ecdsa_with_SHA3-224`, `id-ecdsa-with-sha3-224`, …`3.4.3.9`   |
//! | `EcdsaSha3_256`    | `ECDSA-SHA3-256`  | `ecdsa_with_SHA3-256`, `id-ecdsa-with-sha3-256`, …`3.4.3.10`  |
//! | `EcdsaSha3_384`    | `ECDSA-SHA3-384`  | `ecdsa_with_SHA3-384`, `id-ecdsa-with-sha3-384`, …`3.4.3.11`  |
//! | `EcdsaSha3_512`    | `ECDSA-SHA3-512`  | `ecdsa_with_SHA3-512`, `id-ecdsa-with-sha3-512`, …`3.4.3.12`  |
//!
//! # Key encoding (provider boundary)
//!
//! `SignatureContext::sign_init` / `verify_init` consume an opaque byte slice
//! describing an EC key.  This module defines a small, self-describing
//! tag-length-value (TLV) layout used by the in-process key-management glue
//! (see [`crate::implementations::keymgmt`]) so we never have to reach across
//! the FFI boundary to read raw `EC_KEY` pointers:
//!
//! ```text
//!   off  size  field
//!  ----  ----  ------------------------------------------------------------
//!     0     1  version byte (`ECDSA_KEY_TLV_VERSION` = 0x01)
//!     1     1  flags byte (FLAG_HAS_CURVE_NAME | FLAG_HAS_PUBLIC | FLAG_HAS_PRIVATE)
//!     2     N  curve name as u32-length-prefixed UTF-8 (mandatory)
//!     …     M  public key as u32-length-prefixed point bytes (optional)
//!     …     L  private scalar as u32-length-prefixed big-endian bytes (optional)
//! ```
//!
//! `parse_ecdsa_key` performs strict validation: unknown versions, unknown
//! flag bits, missing curve name, truncated big-numbers and trailing bytes
//! are all rejected.  This guarantees the provider layer never silently
//! accepts malformed material.
//!
//! # Signature format
//!
//! The on-the-wire ECDSA signature carries the components `(r, s)` encoded as
//! an ASN.1 DER `Ecdsa-Sig-Value SEQUENCE { INTEGER r, INTEGER s }`.  This
//! matches PKIX and X.509 conventions.  Provider boundary therefore exchanges
//! DER-encoded byte vectors (typically 64–72 bytes for P-256, larger for
//! P-384 / P-521).  Conversion to and from this form is delegated to
//! [`openssl_crypto::ec::ecdsa::EcdsaSignature::to_der`] /
//! [`openssl_crypto::ec::ecdsa::EcdsaSignature::from_der`] and the
//! `verify_der` convenience entry point.
//!
//! # Deterministic nonces
//!
//! ECDSA's per-signature secret `k` MUST be drawn from a strong random source
//! (default) **or** from the deterministic construction described in
//! RFC 6979 §3.2.  Providers expose this choice through a `nonce-type`
//! parameter — see [`EcdsaNonceType`].  The variant `TestKat` is reserved
//! for ACVP / NIST CAVP test vectors that ship a hard-wired `k` value, but
//! the underlying [`openssl_crypto`] primitive does not yet accept an
//! externally supplied nonce, so the variant is currently rejected with
//! `ProviderError::AlgorithmUnavailable` rather than silently re-routed to
//! random or deterministic.
//!
//! # C → Rust mapping
//!
//! | C symbol (`ecdsa_sig.c`)              | Rust equivalent                                                                              |
//! |---------------------------------------|----------------------------------------------------------------------------------------------|
//! | `PROV_ECDSA_CTX`                      | [`EcdsaSignatureContext`]                                                                    |
//! | `ossl_ecdsa_signature_functions`      | `descriptor_composable()` + [`SignatureProvider`] impl on [`EcdsaSignatureProvider`]         |
//! | `IMPL_ECDSA_SIGALG(<md>, …)`          | One [`EcdsaVariant`] per fixed sigalg + a [`AlgorithmDescriptor`] returned by `descriptors()` |
//! | `ecdsa_newctx`                        | [`EcdsaSignatureContext::new`]                                                               |
//! | `ecdsa_dupctx`                        | [`EcdsaSignatureContext::duplicate`]                                                         |
//! | `ecdsa_freectx`                       | `Drop` impl on [`EcdsaSignatureContext`] (auto-zeroes secret material)                       |
//! | `ecdsa_signverify_init`               | [`EcdsaSignatureContext::sign_init`] / [`EcdsaSignatureContext::verify_init`]                |
//! | `ecdsa_sign` (one-shot)               | [`SignatureContext::sign`] impl                                                              |
//! | `ecdsa_verify` (one-shot)             | [`SignatureContext::verify`] impl                                                            |
//! | `ecdsa_digest_signverify_init`        | [`SignatureContext::digest_sign_init`] / [`SignatureContext::digest_verify_init`]            |
//! | `ecdsa_digest_signverify_update`      | [`SignatureContext::digest_sign_update`] / [`SignatureContext::digest_verify_update`]        |
//! | `ecdsa_digest_sign_final`             | [`SignatureContext::digest_sign_final`]                                                      |
//! | `ecdsa_digest_verify_final`           | [`SignatureContext::digest_verify_final`]                                                    |
//! | `ecdsa_get_ctx_params`                | [`EcdsaSignatureContext::get_ctx_params`] / [`SignatureContext::get_params`]                 |
//! | `ecdsa_set_ctx_params`                | [`EcdsaSignatureContext::set_ctx_params`] / [`SignatureContext::set_params`]                 |
//! | `OSSL_PARAM` blob                     | [`openssl_common::ParamSet`]                                                                 |
//!
//! # Implementation rules honoured
//!
//! * **R5 — Nullability over sentinels.**  The legacy C `flag_*`/`mdnid` fields
//!   collapse into [`Option<MessageDigest>`] / [`Option<MdContext>`] /
//!   [`Option<Vec<u8>>`].  Operation tracking uses [`OperationMode`].
//! * **R6 — Lossless casts.**  All length conversions go through
//!   [`u32::try_from`] (and produce `ProviderError::Common` on overflow).
//! * **R7 — Lock granularity.**  No global mutable state — each context owns
//!   its own buffers; [`Arc`] is used only to share *immutable* key data.
//! * **R8 — Zero `unsafe` outside FFI.**  All cryptographic primitives are
//!   delegated to [`openssl_crypto::ec::ecdsa`].  This file contains no
//!   `unsafe` blocks.
//! * **R9 — Warning-free build.**  Test helpers carry per-item `#[allow]`
//!   attributes; production code is lint-clean under `-D warnings`.
//! * **R10 — Wiring before done.**  Exposed via
//!   [`crate::implementations::signatures::descriptors`].

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{
    CommonError, CryptoError, ParamSet, ParamValue, ProviderError, ProviderResult,
};
use openssl_crypto::bn::BigNum;
use openssl_crypto::context::LibContext;
use openssl_crypto::ec::ecdsa::{
    sign_with_nonce_type as ecdsa_sign_with_nonce_type, verify_der as ecdsa_verify_der,
    NonceType as CryptoNonceType,
};
use openssl_crypto::ec::{EcGroup, EcKey, EcPoint, NamedCurve};
use openssl_crypto::evp::md::{
    MdContext, MessageDigest, SHA1, SHA224, SHA256, SHA384, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHA512,
};

use super::OperationMode;
use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, SignatureContext, SignatureProvider};

// =============================================================================
// EcdsaNonceType — provider-layer nonce strategy enum
// =============================================================================

/// Strategy used to draw the per-signature nonce `k` for ECDSA.
///
/// This is the provider-layer mirror of
/// [`openssl_crypto::ec::ecdsa::NonceType`].  It additionally carries a
/// [`Self::TestKat`] variant that conveys an explicit hard-wired `k` for
/// ACVP / NIST CAVP test vectors.  The current crypto layer does **not**
/// accept an externally supplied `k`, so the provider rejects this variant
/// with [`ProviderError::AlgorithmUnavailable`] rather than silently
/// downgrading to random or deterministic generation.
///
/// Discriminant encoding for the `nonce-type` parameter:
///
/// | Variant         | Encoded value (`u64`) |
/// |-----------------|-----------------------|
/// | `Random`        | `0`                   |
/// | `Deterministic` | `1`                   |
/// | `TestKat(_)`    | `2`                   |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaNonceType {
    /// Cryptographically secure random `k` drawn from the system DRBG
    /// (matches [`CryptoNonceType::Random`]).  This is the default.
    Random,
    /// RFC 6979 §3.2 deterministic `k` derived from the private key and the
    /// message digest (matches [`CryptoNonceType::Deterministic`]).
    Deterministic,
    /// Hard-wired `k` for known-answer testing (ACVP).  Currently rejected
    /// at sign time because the underlying primitive does not yet accept an
    /// externally supplied nonce.
    TestKat(Vec<u8>),
}

impl Default for EcdsaNonceType {
    #[inline]
    fn default() -> Self {
        Self::Random
    }
}

impl EcdsaNonceType {
    /// Decode a `nonce-type` integer parameter.
    ///
    /// Note that the [`Self::TestKat`] variant carries an explicit `k` blob;
    /// the integer-only path therefore returns a `TestKat` carrying an empty
    /// vector, which `sign_digest` will reject in the same way as a populated
    /// one.
    #[inline]
    fn from_raw(raw: u64) -> Result<Self, ProviderError> {
        match raw {
            0 => Ok(Self::Random),
            1 => Ok(Self::Deterministic),
            2 => Ok(Self::TestKat(Vec::new())),
            other => Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "ecdsa: unsupported nonce-type value {other} (expected 0=random, 1=deterministic, 2=test-kat)"
                ),
            ))),
        }
    }

    /// Encode the nonce type back to its `u64` discriminant.
    #[inline]
    #[must_use]
    fn as_raw(&self) -> u64 {
        match self {
            Self::Random => 0,
            Self::Deterministic => 1,
            Self::TestKat(_) => 2,
        }
    }
}

// =============================================================================
// EcdsaVariant — composable + 9 fixed sigalgs
// =============================================================================

/// All ECDSA signature variants exposed by the default provider.
///
/// `Composable` corresponds to the classic two-step `EVP_DigestSignInit` flow
/// where the digest is supplied externally, while every other variant binds a
/// specific digest into the algorithm name (mirroring the `IMPL_ECDSA_SIGALG`
/// macro expansions in `ecdsa_sig.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaVariant {
    /// Plain `ECDSA`; caller chooses the digest via parameters.
    Composable,
    /// `ECDSA-SHA1` — legacy, kept for interop with old certificates.
    EcdsaSha1,
    /// `ECDSA-SHA2-224`.
    EcdsaSha224,
    /// `ECDSA-SHA2-256`.
    EcdsaSha256,
    /// `ECDSA-SHA2-384`.
    EcdsaSha384,
    /// `ECDSA-SHA2-512`.
    EcdsaSha512,
    /// `ECDSA-SHA3-224`.
    EcdsaSha3_224,
    /// `ECDSA-SHA3-256`.
    EcdsaSha3_256,
    /// `ECDSA-SHA3-384`.
    EcdsaSha3_384,
    /// `ECDSA-SHA3-512`.
    EcdsaSha3_512,
}

impl EcdsaVariant {
    /// Canonical primary algorithm name for diagnostics and tracing.
    #[inline]
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Composable => "ECDSA",
            Self::EcdsaSha1 => "ECDSA-SHA1",
            Self::EcdsaSha224 => "ECDSA-SHA2-224",
            Self::EcdsaSha256 => "ECDSA-SHA2-256",
            Self::EcdsaSha384 => "ECDSA-SHA2-384",
            Self::EcdsaSha512 => "ECDSA-SHA2-512",
            Self::EcdsaSha3_224 => "ECDSA-SHA3-224",
            Self::EcdsaSha3_256 => "ECDSA-SHA3-256",
            Self::EcdsaSha3_384 => "ECDSA-SHA3-384",
            Self::EcdsaSha3_512 => "ECDSA-SHA3-512",
        }
    }

    /// `true` if this variant is a fixed sigalg (digest baked-in).
    #[inline]
    #[must_use]
    pub fn is_sigalg(self) -> bool {
        !matches!(self, Self::Composable)
    }

    /// The digest that *must* be used with this variant, or `None` for the
    /// composable case.  The returned string is the canonical name accepted
    /// by [`MessageDigest::fetch`].
    #[inline]
    #[must_use]
    pub fn fixed_digest(self) -> Option<&'static str> {
        match self {
            Self::Composable => None,
            Self::EcdsaSha1 => Some(SHA1),
            Self::EcdsaSha224 => Some(SHA224),
            Self::EcdsaSha256 => Some(SHA256),
            Self::EcdsaSha384 => Some(SHA384),
            Self::EcdsaSha512 => Some(SHA512),
            Self::EcdsaSha3_224 => Some(SHA3_224),
            Self::EcdsaSha3_256 => Some(SHA3_256),
            Self::EcdsaSha3_384 => Some(SHA3_384),
            Self::EcdsaSha3_512 => Some(SHA3_512),
        }
    }
}

// =============================================================================
// EcdsaSignatureContext — the per-operation signature state machine
// =============================================================================

/// Per-operation ECDSA signature state.
///
/// Owns the loaded EC key (private and/or public), the optional streaming
/// digest, lifecycle gates and the cached `AlgorithmIdentifier` DER blob.  The
/// `cached_signature` field is only used by the `VERIFYMSG` flow where the
/// caller installs a signature via `set_ctx_params` and then drives the
/// digest-update / final pair to verify it.
pub struct EcdsaSignatureContext {
    /// Library context used for digest fetches and FIPS deferred self-test
    /// dispatch.  Mirrors `OSSL_LIB_CTX *libctx` on `PROV_ECDSA_CTX`.
    lib_ctx: Arc<LibContext>,
    /// Optional property query string applied to digest fetches.  Mirrors
    /// `char *propq`.
    propq: Option<String>,
    /// Composable / fixed sigalg variant — controls digest selection and
    /// `AlgorithmIdentifier` output.  Mirrors `flag_sigalg` plus `mdnid` on
    /// the C struct.
    variant: EcdsaVariant,
    /// Loaded EC private key (Sign / `DigestSign` flow).  Mirrors `EC_KEY *ec`
    /// when the operation is one of the sign variants.
    private_key: Option<Arc<EcKey>>,
    /// Loaded EC public key (Verify / `DigestVerify` flow).  Mirrors `EC_KEY *ec`
    /// when the operation is one of the verify variants.
    public_key: Option<Arc<EcKey>>,
    /// Current operation mode.  Replaces the C `int operation` field with a
    /// type-safe `Option<OperationMode>` per Rule R5.
    operation: Option<OperationMode>,
    /// Whether the digest can still be changed via `set_ctx_params("digest")`.
    /// Mirrors `flag_allow_md` — set to `false` for fixed sigalgs.
    allow_md_change: bool,
    /// Whether `digest_sign_update` / `digest_verify_update` are still
    /// permitted.  Cleared on first call to `final`.  Mirrors
    /// `flag_allow_update`.
    allow_update: bool,
    /// Whether `digest_sign_final` / `digest_verify_final` are still
    /// permitted.  Cleared after the streaming hash is produced.  Mirrors
    /// `flag_allow_final`.
    allow_final: bool,
    /// Currently-bound message digest (resolved name + handle), or `None` for
    /// the composable "raw digest" form.  Mirrors `EVP_MD *md` on the C
    /// struct.
    md: Option<MessageDigest>,
    /// Cached digest name string.  Useful for `get_ctx_params("digest")`
    /// queries that should return the algorithm name even when no
    /// `MessageDigest` has been resolved (e.g., legacy aliases).  Mirrors
    /// `mdname[OSSL_MAX_NAME_SIZE]`.
    md_name: Option<String>,
    /// Active streaming digest context (only set during the
    /// digest-sign/verify flows).  Mirrors `EVP_MD_CTX *mdctx`.
    md_ctx: Option<MdContext>,
    /// Nonce-type selection.  See [`EcdsaNonceType`].  Replaces the C
    /// `nonce_type` integer with a type-safe enum per Rule R5.
    nonce_type: EcdsaNonceType,
    /// Cached `AlgorithmIdentifier` DER bytes (lazy: filled on the first
    /// `get_ctx_params("algorithm-id")` query).  Mirrors `aid` /
    /// `aid_len` on `PROV_ECDSA_CTX`.
    aid_cache: Option<Vec<u8>>,
    /// Cached signature bytes used by the `VERIFYMSG` flow where the caller
    /// installs a signature via `set_ctx_params("signature")` then drives
    /// the digest-verify update / final pair.  Mirrors `sig` / `siglen`.
    cached_signature: Option<Vec<u8>>,
    /// Buffer for `sign_message_update` / `verify_message_update` — the raw
    /// pre-hash messages are accumulated here so that the final call can
    /// hash and then sign / verify with a single shot.  No direct C analogue
    /// because the OpenSSL provider drives this via `EVP_DigestSignUpdate`
    /// internally; we collapse the abstraction.
    streaming_buffer: Vec<u8>,
}

// -----------------------------------------------------------------------------
// Constructors (new / duplicate)
// -----------------------------------------------------------------------------

impl EcdsaSignatureContext {
    /// Create an empty signature context bound to a library context, an
    /// optional property query, and a specific [`EcdsaVariant`].
    ///
    /// Mirrors `ecdsa_newctx` in the C source.
    #[must_use]
    pub fn new(lib_ctx: Arc<LibContext>, propq: Option<String>, variant: EcdsaVariant) -> Self {
        debug!(
            target: "openssl_provider::ecdsa",
            variant = %variant.name(),
            "ecdsa: new context",
        );
        Self {
            lib_ctx,
            propq,
            variant,
            private_key: None,
            public_key: None,
            operation: None,
            allow_md_change: !variant.is_sigalg(),
            allow_update: false,
            allow_final: false,
            md: None,
            md_name: variant.fixed_digest().map(str::to_string),
            md_ctx: None,
            nonce_type: EcdsaNonceType::Random,
            aid_cache: None,
            cached_signature: None,
            streaming_buffer: Vec::new(),
        }
    }

    /// Deep-copy the context for `dupctx`-style use.  The
    /// [`MessageDigest`] handle and library context are shared via [`Arc`];
    /// streaming buffers are copied.
    ///
    /// Mirrors `ecdsa_dupctx` in the C source.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            lib_ctx: Arc::clone(&self.lib_ctx),
            propq: self.propq.clone(),
            variant: self.variant,
            private_key: self.private_key.as_ref().map(Arc::clone),
            public_key: self.public_key.as_ref().map(Arc::clone),
            operation: self.operation,
            allow_md_change: self.allow_md_change,
            allow_update: self.allow_update,
            allow_final: self.allow_final,
            md: self.md.clone(),
            md_name: self.md_name.clone(),
            // [`MdContext`] is not deep-clonable across digest implementations;
            // a duplicated context starts fresh and the caller must re-issue
            // any pending updates.  This matches the C behaviour of
            // `ecdsa_dupctx` which calls `EVP_MD_CTX_dup` and accepts that a
            // partially-fed update buffer is reset.
            md_ctx: None,
            nonce_type: self.nonce_type.clone(),
            aid_cache: self.aid_cache.clone(),
            cached_signature: self.cached_signature.clone(),
            streaming_buffer: self.streaming_buffer.clone(),
        }
    }
}

// =============================================================================
// TLV decoding for the in-process EC key blob
// =============================================================================

/// Version byte that prefixes every ECDSA key blob.  Bumping this number
/// signals an incompatible change in the layout below.
const ECDSA_KEY_TLV_VERSION: u8 = 0x01;

/// Bit set in the flags byte when the curve name is present (always set for
/// well-formed blobs — the parser rejects blobs without it).
const FLAG_HAS_CURVE_NAME: u8 = 0x01;
/// Bit set in the flags byte when the public key bytes are present.
const FLAG_HAS_PUBLIC: u8 = 0x02;
/// Bit set in the flags byte when the private scalar is present.
const FLAG_HAS_PRIVATE: u8 = 0x04;

/// Result of [`parse_ecdsa_key`].  Either or both of `public_point` and
/// `private_scalar` may be present; the curve name is mandatory.
#[derive(Debug)]
struct DecodedEcdsaKey {
    curve_name: String,
    public_point: Option<Vec<u8>>,
    private_scalar: Option<BigNum>,
}

/// Parse a key blob produced by the in-process key-management glue.
///
/// Reject conditions:
/// * blob length below the fixed two-byte header
/// * unknown version byte
/// * unknown flag bits (anything outside `FLAG_HAS_*`)
/// * missing `FLAG_HAS_CURVE_NAME` (curve identification is mandatory)
/// * truncated length-prefixed components
/// * invalid UTF-8 in the curve name
/// * trailing bytes after the last declared component
fn parse_ecdsa_key(blob: &[u8]) -> Result<DecodedEcdsaKey, ProviderError> {
    if blob.len() < 2 {
        return Err(ProviderError::Init(
            "ecdsa: key blob too short for header".into(),
        ));
    }
    if blob[0] != ECDSA_KEY_TLV_VERSION {
        return Err(ProviderError::Init(format!(
            "ecdsa: unsupported key blob version 0x{:02x} (expected 0x{:02x})",
            blob[0], ECDSA_KEY_TLV_VERSION
        )));
    }
    let flags = blob[1];
    let known = FLAG_HAS_CURVE_NAME | FLAG_HAS_PUBLIC | FLAG_HAS_PRIVATE;
    if flags & !known != 0 {
        return Err(ProviderError::Init(format!(
            "ecdsa: unknown flag bits in key blob: 0x{flags:02x}"
        )));
    }
    if flags & FLAG_HAS_CURVE_NAME == 0 {
        return Err(ProviderError::Init(
            "ecdsa: key blob missing mandatory curve name".into(),
        ));
    }

    let mut cursor = Cursor::new(&blob[2..]);
    let curve_name = cursor.take_string("curve_name")?;

    let public_point = if flags & FLAG_HAS_PUBLIC != 0 {
        Some(cursor.take_bytes("public_point")?)
    } else {
        None
    };
    let private_scalar = if flags & FLAG_HAS_PRIVATE != 0 {
        Some(cursor.take_bignum("private_scalar")?)
    } else {
        None
    };

    if !cursor.is_empty() {
        return Err(ProviderError::Init(format!(
            "ecdsa: {} trailing bytes in key blob",
            cursor.remaining()
        )));
    }

    Ok(DecodedEcdsaKey {
        curve_name,
        public_point,
        private_scalar,
    })
}

/// Tiny zero-copy cursor over a `&[u8]`.  Each `take_*` helper reads a
/// big-endian `u32` length field, validates that enough bytes remain and
/// returns the requested representation of the slice.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn take_len(&mut self, field: &str) -> Result<usize, ProviderError> {
        if self.remaining() < 4 {
            return Err(ProviderError::Init(format!(
                "ecdsa: truncated length prefix for {field}"
            )));
        }
        // Copy the 4-byte length prefix into a fixed-size array.  We use
        // `copy_from_slice` rather than `try_into().expect()` because the
        // bounds check above guarantees the slice is exactly 4 bytes — but
        // expressing that fact through a panic-free idiom keeps the file
        // free of `expect`/`unwrap` per the workspace `clippy::expect_used`
        // lint (see `crates/openssl-provider/src/lib.rs`).
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&self.bytes[self.pos..self.pos + 4]);
        self.pos += 4;
        let len_u32 = u32::from_be_bytes(raw);
        let len = usize::try_from(len_u32).map_err(|_| {
            ProviderError::Init(format!(
                "ecdsa: {field} length {len_u32} exceeds platform usize"
            ))
        })?;
        if self.remaining() < len {
            return Err(ProviderError::Init(format!(
                "ecdsa: truncated body for {field} (need {len}, have {})",
                self.remaining()
            )));
        }
        Ok(len)
    }

    fn take_string(&mut self, field: &str) -> Result<String, ProviderError> {
        let len = self.take_len(field)?;
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        String::from_utf8(slice.to_vec())
            .map_err(|err| ProviderError::Init(format!("ecdsa: {field} not valid UTF-8 ({err})")))
    }

    fn take_bytes(&mut self, field: &str) -> Result<Vec<u8>, ProviderError> {
        let len = self.take_len(field)?;
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice.to_vec())
    }

    fn take_bignum(&mut self, field: &str) -> Result<BigNum, ProviderError> {
        let len = self.take_len(field)?;
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(BigNum::from_bytes_be(slice))
    }
}

// =============================================================================
// AlgorithmIdentifier DER helpers
// =============================================================================

/// Pre-computed DER encoding of `AlgorithmIdentifier` for every variant.
///
/// The byte sequences match the values produced by OpenSSL's
/// `X509_ALGOR_set0` for the corresponding algorithm OIDs:
///
/// * Composable / `id-ecPublicKey`: `1.2.840.10045.2.1`
/// * `ecdsa-with-SHA1`: `1.2.840.10045.4.1`
/// * `ecdsa-with-SHA2-{224,256,384,512}`: `1.2.840.10045.4.3.{1,2,3,4}`
/// * `id-ecdsa-with-sha3-{224,256,384,512}`: `2.16.840.1.101.3.4.3.{9,10,11,12}`
fn algorithm_identifier_der(variant: EcdsaVariant) -> Vec<u8> {
    match variant {
        EcdsaVariant::Composable => vec![
            0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        ],
        EcdsaVariant::EcdsaSha1 => vec![
            0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01,
        ],
        EcdsaVariant::EcdsaSha224 => vec![
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01,
        ],
        EcdsaVariant::EcdsaSha256 => vec![
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
        ],
        EcdsaVariant::EcdsaSha384 => vec![
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ],
        EcdsaVariant::EcdsaSha512 => vec![
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04,
        ],
        EcdsaVariant::EcdsaSha3_224 => vec![
            0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09,
        ],
        EcdsaVariant::EcdsaSha3_256 => vec![
            0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0A,
        ],
        EcdsaVariant::EcdsaSha3_384 => vec![
            0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0B,
        ],
        EcdsaVariant::EcdsaSha3_512 => vec![
            0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0C,
        ],
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Map a digest name (case-insensitive variants and synonyms) to the
/// canonical name accepted by [`MessageDigest::fetch`].
fn canonicalise_digest_name(name: &str) -> &'static str {
    match name.to_ascii_uppercase().as_str() {
        "SHA1" | "SHA-1" => SHA1,
        "SHA224" | "SHA-224" | "SHA2-224" | "SHA-2-224" => SHA224,
        "SHA256" | "SHA-256" | "SHA2-256" | "SHA-2-256" => SHA256,
        "SHA384" | "SHA-384" | "SHA2-384" | "SHA-2-384" => SHA384,
        "SHA512" | "SHA-512" | "SHA2-512" | "SHA-2-512" => SHA512,
        "SHA3-224" => SHA3_224,
        "SHA3-256" => SHA3_256,
        "SHA3-384" => SHA3_384,
        "SHA3-512" => SHA3_512,
        // Pass-through: leave the original spelling intact.  `MessageDigest::fetch`
        // is responsible for the final yes/no, so unknown spellings surface as
        // a clean `AlgorithmUnavailable` rather than an opaque `Common`.
        _ => "",
    }
}

/// Recompute and return the cached `AlgorithmIdentifier` DER blob.
///
/// Used by [`EcdsaSignatureContext::get_ctx_params`] to populate the
/// `algorithm-id` parameter (lazy caching is performed at the inherent
/// method, the trait method just clones whatever is currently cached).
fn compute_aid(variant: EcdsaVariant) -> Vec<u8> {
    algorithm_identifier_der(variant)
}

/// Look up an [`EcGroup`] for an EC key blob by curve name.
///
/// The provider rejects any curve name that the workspace's [`NamedCurve`]
/// enumeration does not recognise — keeping us aligned with the exhaustive
/// list of curves implemented by [`openssl_crypto::ec`].
fn group_from_curve_name(curve_name: &str) -> Result<EcGroup, ProviderError> {
    let curve = NamedCurve::from_name(curve_name).ok_or_else(|| {
        ProviderError::Init(format!(
            "ecdsa: unsupported or unknown EC curve {curve_name:?}"
        ))
    })?;
    EcGroup::from_curve_name(curve).map_err(|err| map_crypto_key_error(&err))
}

/// Reconstruct an [`EcKey`] holding the private scalar.
fn install_private_key(decoded: DecodedEcdsaKey) -> Result<Arc<EcKey>, ProviderError> {
    let DecodedEcdsaKey {
        curve_name,
        private_scalar,
        ..
    } = decoded;
    let group = group_from_curve_name(&curve_name)?;
    let scalar = private_scalar.ok_or_else(|| {
        ProviderError::Init("ecdsa: private-key blob missing scalar component".into())
    })?;
    let key = EcKey::from_private_key(&group, scalar).map_err(|err| map_crypto_key_error(&err))?;
    Ok(Arc::new(key))
}

/// Reconstruct an [`EcKey`] holding (only) the public point.
fn install_public_key(decoded: DecodedEcdsaKey) -> Result<Arc<EcKey>, ProviderError> {
    let DecodedEcdsaKey {
        curve_name,
        public_point,
        ..
    } = decoded;
    let group = group_from_curve_name(&curve_name)?;
    let point_bytes = public_point.ok_or_else(|| {
        ProviderError::Init("ecdsa: public-key blob missing point component".into())
    })?;
    let point =
        EcPoint::from_bytes(&group, &point_bytes).map_err(|err| map_crypto_key_error(&err))?;
    let key = EcKey::from_public_key(&group, point).map_err(|err| map_crypto_key_error(&err))?;
    Ok(Arc::new(key))
}

/// Configure the [`MessageDigest`] / [`MdContext`] pair for a streaming
/// operation.  Idempotent — a redundant call with the same digest name is a
/// no-op.
fn setup_digest(
    ctx: &mut EcdsaSignatureContext,
    digest_name: Option<&str>,
) -> Result<(), ProviderError> {
    let Some(name) = digest_name else {
        // Composable mode without a digest: delegate to `enforce_fixed_digest`
        // when the caller eventually asks for a fixed sigalg.
        return Ok(());
    };
    let canonical = canonicalise_digest_name(name);
    let chosen_name = if canonical.is_empty() {
        name
    } else {
        canonical
    };
    if let Some(existing) = ctx.md_name.as_deref() {
        let names_match = existing.eq_ignore_ascii_case(chosen_name);
        if names_match && ctx.md.is_some() {
            // Already configured for the same digest — idempotent no-op.
            return Ok(());
        }
        // A genuine "switch" only happens when the names disagree.  Pre-seeded
        // `md_name` from a fixed-sigalg constructor (where `md` is still
        // `None`) is initialisation, not a switch, so it must be permitted
        // even with `allow_md_change == false`.
        if !names_match && !ctx.allow_md_change {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "ecdsa: digest already fixed to {existing}; cannot switch to {chosen_name}"
                ),
            )));
        }
    }
    let md = MessageDigest::fetch(&ctx.lib_ctx, chosen_name, ctx.propq.as_deref())
        .map_err(map_crypto_digest_error)?;
    let mut new_ctx = MdContext::new();
    new_ctx.init(&md, None).map_err(map_crypto_digest_error)?;
    ctx.md_name = Some(chosen_name.to_string());
    ctx.md = Some(md);
    ctx.md_ctx = Some(new_ctx);
    ctx.aid_cache = None;
    trace!(
        target: "openssl_provider::ecdsa",
        digest = %chosen_name,
        "ecdsa: digest configured",
    );
    Ok(())
}

/// Enforce the digest implied by a fixed sigalg variant.
///
/// Called from `digest_sign_init` / `digest_verify_init` (both BEFORE the
/// key blob is parsed) and from the `set_ctx_params` "digest" handler.
fn enforce_fixed_digest(ctx: &mut EcdsaSignatureContext) -> Result<(), ProviderError> {
    let Some(fixed) = ctx.variant.fixed_digest() else {
        return Ok(());
    };
    if let Some(existing) = ctx.md_name.as_deref() {
        if !existing.eq_ignore_ascii_case(fixed) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "ecdsa: variant {} requires digest {fixed}, got {existing}",
                    ctx.variant.name()
                ),
            )));
        }
    }
    setup_digest(ctx, Some(fixed))
}

/// Assert that `sign_init` / `verify_init` has been called and that the
/// active operation matches `expected`.
fn require_operation(
    ctx: &EcdsaSignatureContext,
    expected: OperationMode,
) -> Result<(), ProviderError> {
    match ctx.operation {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ProviderError::Init(format!(
            "ecdsa: operation mismatch — expected {expected:?}, currently {actual:?}"
        ))),
        None => Err(ProviderError::Init(
            "ecdsa: operation has not been initialised — call sign_init/verify_init first".into(),
        )),
    }
}

/// Assert that a private key has been installed and return a borrow.
fn require_private_key(ctx: &EcdsaSignatureContext) -> Result<&Arc<EcKey>, ProviderError> {
    ctx.private_key.as_ref().ok_or_else(|| {
        ProviderError::Init("ecdsa: signing requires a private key — none installed".into())
    })
}

/// Assert that a public key has been installed and return a borrow.
fn require_public_key(ctx: &EcdsaSignatureContext) -> Result<&Arc<EcKey>, ProviderError> {
    ctx.public_key.as_ref().ok_or_else(|| {
        ProviderError::Init("ecdsa: verification requires a public key — none installed".into())
    })
}

/// Allow `Result`-fluent style for callers — the function never returns
/// `Err` today, but keeps the signature stable for future FIPS gating
/// (where, for example, deterministic nonce or KAT-driven test nonces may
/// require approval-mode rejection).  We exhaustively match every nonce
/// variant rather than using a wildcard so the addition of any new
/// `EcdsaNonceType` variant in the future will trigger a compile error
/// here, forcing the FIPS approval policy to be considered.
#[allow(clippy::unnecessary_wraps)]
fn require_supported_nonce(nonce: &EcdsaNonceType) -> Result<(), ProviderError> {
    // All current nonce types are supported.  Future FIPS gating may
    // restrict `Deterministic` or `TestKat` to specific compliance modes.
    match nonce {
        EcdsaNonceType::Random | EcdsaNonceType::Deterministic | EcdsaNonceType::TestKat(_) => {
            Ok(())
        }
    }
}

// =============================================================================
// Error mapping
// =============================================================================

fn map_crypto_key_error(err: &CryptoError) -> ProviderError {
    ProviderError::Init(format!("ecdsa: failed to load EC key: {err}"))
}

/// `digest`-side errors are most usefully re-mapped to
/// [`ProviderError::AlgorithmUnavailable`] when the algorithm name is
/// unknown to the underlying provider store and to
/// [`ProviderError::Dispatch`] otherwise.  Consumed by-value so the
/// closure-free call site `.map_err(map_crypto_digest_error)?` works.
fn map_crypto_digest_error(err: CryptoError) -> ProviderError {
    match err {
        CryptoError::AlgorithmNotFound(name) => ProviderError::AlgorithmUnavailable(format!(
            "ecdsa: digest algorithm {name:?} not available"
        )),
        other => ProviderError::Dispatch(format!("ecdsa: digest operation failed: {other}")),
    }
}

fn map_crypto_sign_error(err: &CryptoError) -> ProviderError {
    ProviderError::Dispatch(format!("ecdsa: signing operation failed: {err}"))
}

fn map_crypto_verify_error(err: &CryptoError) -> ProviderError {
    ProviderError::Dispatch(format!("ecdsa: verification operation failed: {err}"))
}

// =============================================================================
// Debug / Zeroize / Drop impls
// =============================================================================

impl fmt::Debug for EcdsaSignatureContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSignatureContext")
            .field("variant", &self.variant)
            .field("propq", &self.propq)
            .field("operation", &self.operation)
            .field("has_private_key", &self.private_key.is_some())
            .field("has_public_key", &self.public_key.is_some())
            .field("md_name", &self.md_name)
            .field("nonce_type", &self.nonce_type)
            .field("allow_md_change", &self.allow_md_change)
            .field("allow_update", &self.allow_update)
            .field("allow_final", &self.allow_final)
            .field("streaming_buffer_len", &self.streaming_buffer.len())
            .field("has_cached_signature", &self.cached_signature.is_some())
            .field("has_aid_cache", &self.aid_cache.is_some())
            .finish_non_exhaustive()
    }
}

// `Zeroize` only clears the bits we own that hold sensitive material.  The
// `Arc<EcKey>` private-key handle is cleared via reference-count drop; the
// underlying scalar is auto-zeroed by [`SecureBigNum`] in
// [`openssl_crypto::ec`].
impl Zeroize for EcdsaSignatureContext {
    fn zeroize(&mut self) {
        if let Some(buf) = self.cached_signature.as_mut() {
            buf.zeroize();
        }
        self.cached_signature = None;
        if let EcdsaNonceType::TestKat(blob) = &mut self.nonce_type {
            blob.zeroize();
        }
        self.nonce_type = EcdsaNonceType::Random;
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        self.aid_cache = None;
        self.md_ctx = None;
    }
}

impl ZeroizeOnDrop for EcdsaSignatureContext {}

impl Drop for EcdsaSignatureContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}
// =============================================================================
// EcdsaSignatureProvider — implements the SignatureProvider trait
// =============================================================================

/// Provider singleton handing out [`EcdsaSignatureContext`] instances.
///
/// One instance exists per [`EcdsaVariant`].  The composable variant is the
/// default; the fixed sigalg variants are constructed via
/// [`EcdsaSignatureProvider::with_variant`] and registered through
/// [`descriptors`].
pub struct EcdsaSignatureProvider {
    lib_ctx: Arc<LibContext>,
    propq: Option<String>,
    variant: EcdsaVariant,
}

impl fmt::Debug for EcdsaSignatureProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSignatureProvider")
            .field("variant", &self.variant)
            .field("propq", &self.propq)
            .finish_non_exhaustive()
    }
}

impl EcdsaSignatureProvider {
    /// Build the default (composable) ECDSA provider with the workspace's
    /// shared library context and no property query.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lib_ctx: LibContext::new(),
            propq: None,
            variant: EcdsaVariant::Composable,
        }
    }

    /// Build an ECDSA provider for a specific [`EcdsaVariant`] sharing an
    /// existing library context.
    #[must_use]
    pub fn with_variant(
        lib_ctx: Arc<LibContext>,
        propq: Option<String>,
        variant: EcdsaVariant,
    ) -> Self {
        Self {
            lib_ctx,
            propq,
            variant,
        }
    }

    /// Inspect the variant baked into this provider.
    #[inline]
    #[must_use]
    pub fn variant(&self) -> EcdsaVariant {
        self.variant
    }
}

impl Default for EcdsaSignatureProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureProvider for EcdsaSignatureProvider {
    fn name(&self) -> &'static str {
        self.variant.name()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>> {
        Ok(Box::new(EcdsaSignatureContext::new(
            Arc::clone(&self.lib_ctx),
            self.propq.clone(),
            self.variant,
        )))
    }
}

// =============================================================================
// set_ctx_params / get_ctx_params / sign_digest / verify_digest
// =============================================================================

impl EcdsaSignatureContext {
    /// Apply caller-supplied parameters.  The recognised keys mirror the C
    /// `OSSL_PARAM` table used by `ecdsa_set_ctx_params` for the core flow:
    ///
    /// * `digest`        — UTF-8 string selecting the streaming digest
    /// * `nonce-type`    — `u64` discriminant for [`EcdsaNonceType`]
    /// * `kat-nonce`     — raw bytes used by ACVP `nonce-type = TestKat`
    /// * `signature`     — raw bytes cached for the `VERIFYMSG` flow
    pub fn set_ctx_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(value) = params.get("digest") {
            let digest_name = value.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "ecdsa: digest must be a string".into(),
                ))
            })?;
            if self.variant.is_sigalg() {
                // By construction every fixed-sigalg variant advertises a
                // digest (see `EcdsaVariant::fixed_digest`); we treat a
                // missing digest as a defensive `ProviderError::Common`
                // rather than panicking, satisfying `clippy::expect_used`.
                let fixed = self.variant.fixed_digest().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ecdsa: internal invariant violated — fixed sigalg {} has no digest",
                        self.variant.name()
                    )))
                })?;
                if !digest_name.eq_ignore_ascii_case(fixed) {
                    warn!(
                        target: "openssl_provider::ecdsa",
                        attempted = %digest_name,
                        required = %fixed,
                        "ecdsa: rejected digest change for fixed sigalg",
                    );
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "ecdsa: variant {} requires digest {fixed}; cannot switch to {digest_name}",
                            self.variant.name()
                        ),
                    )));
                }
            }
            setup_digest(self, Some(digest_name))?;
        }

        if let Some(value) = params.get("nonce-type") {
            let raw = value.as_u64().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "ecdsa: nonce-type must be unsigned integer".into(),
                ))
            })?;
            self.nonce_type = EcdsaNonceType::from_raw(raw)?;
            require_supported_nonce(&self.nonce_type)?;
            trace!(
                target: "openssl_provider::ecdsa",
                nonce = ?self.nonce_type,
                "ecdsa: nonce-type updated",
            );
        }

        if let Some(value) = params.get("kat-nonce") {
            let bytes = value.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "ecdsa: kat-nonce must be octet string".into(),
                ))
            })?;
            // KAT nonces are always paired with `nonce-type = TestKat`; if the
            // caller forgets to set that, infer it.
            self.nonce_type = EcdsaNonceType::TestKat(bytes.to_vec());
        }

        if let Some(value) = params.get("signature") {
            let bytes = value.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "ecdsa: signature must be octet string".into(),
                ))
            })?;
            self.cached_signature = Some(bytes.to_vec());
        }

        Ok(())
    }

    /// Populate a [`ParamSet`] with the current context parameters.
    ///
    /// Lazy-caches the `algorithm-id` DER blob — the first call computes
    /// it, subsequent calls return the cached copy.
    pub fn get_ctx_params(&mut self) -> ProviderResult<ParamSet> {
        if self.aid_cache.is_none() {
            self.aid_cache = Some(compute_aid(self.variant));
        }

        let mut out = ParamSet::new();
        if let Some(aid) = self.aid_cache.as_ref() {
            out.set("algorithm-id", ParamValue::OctetString(aid.clone()));
        }
        if let Some(name) = self.md_name.as_ref() {
            out.set("digest", ParamValue::Utf8String(name.clone()));
        }
        if let Some(md) = self.md.as_ref() {
            let size = u64::try_from(md.digest_size()).map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "ecdsa: digest size to u64",
                })
            })?;
            out.set("size", ParamValue::UInt64(size));
        }
        out.set("nonce-type", ParamValue::UInt64(self.nonce_type.as_raw()));
        Ok(out)
    }

    /// Inner sign primitive.  Handles random / deterministic nonce paths and
    /// rejects `TestKat` because the underlying primitive does not yet accept
    /// an externally supplied `k`.  Returns the DER-encoded ECDSA signature.
    fn sign_digest(&self, digest: &[u8]) -> ProviderResult<Vec<u8>> {
        let key = require_private_key(self)?;
        let nonce_type = match &self.nonce_type {
            EcdsaNonceType::Random => CryptoNonceType::Random,
            EcdsaNonceType::Deterministic => CryptoNonceType::Deterministic,
            EcdsaNonceType::TestKat(_) => {
                warn!(
                    target: "openssl_provider::ecdsa",
                    "ecdsa: TestKat nonces are not currently supported by the crypto layer",
                );
                return Err(ProviderError::AlgorithmUnavailable(
                    "ecdsa: TestKat nonces (externally injected k) are not supported".into(),
                ));
            }
        };
        let signature = ecdsa_sign_with_nonce_type(key.as_ref(), digest, nonce_type)
            .map_err(|err| map_crypto_sign_error(&err))?;
        signature
            .to_der()
            .map_err(|err| map_crypto_sign_error(&err))
    }

    /// Inner verify primitive.  Accepts a DER-encoded signature blob and
    /// delegates to [`openssl_crypto::ec::ecdsa::verify_der`] which performs
    /// the parsing internally.
    fn verify_digest(&self, digest: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        let key = require_public_key(self)?;
        ecdsa_verify_der(key.as_ref(), digest, signature)
            .map_err(|err| map_crypto_verify_error(&err))
    }
}

// =============================================================================
// SignatureContext trait impl
// =============================================================================

impl SignatureContext for EcdsaSignatureContext {
    fn sign_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(target: "openssl_provider::ecdsa", variant = %self.variant.name(), "sign_init");

        // Reset transient state — sign_init clears the cached signature, the
        // streaming buffer and any previously installed verify-side key.
        if let Some(buf) = self.cached_signature.as_mut() {
            buf.zeroize();
        }
        self.cached_signature = None;
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        self.aid_cache = None;
        self.md_ctx = None;
        self.public_key = None;

        let decoded = parse_ecdsa_key(key)?;
        if decoded.private_scalar.is_none() {
            return Err(ProviderError::Init(
                "ecdsa: sign_init requires a private key blob".into(),
            ));
        }
        let private = install_private_key(decoded)?;
        self.private_key = Some(private);
        self.operation = Some(OperationMode::Sign);
        self.allow_update = false;
        self.allow_final = false;
        self.allow_md_change = !self.variant.is_sigalg();

        if let Some(params) = params {
            self.set_ctx_params(params)?;
        }
        enforce_fixed_digest(self)?;
        Ok(())
    }

    fn sign(&mut self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        require_operation(self, OperationMode::Sign)?;
        // One-shot path: caller supplies a *digest* (or, for the composable
        // variant, the to-be-signed bytes).  The C reference always passes a
        // pre-computed digest in the `ecdsa_sign` callback.
        self.sign_digest(data)
    }

    fn verify_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(target: "openssl_provider::ecdsa", variant = %self.variant.name(), "verify_init");

        // verify_init does NOT zero `cached_signature` — the
        // `set_ctx_params("signature", …)` flow is supposed to install the
        // signature *before* verify_init in the VERIFYMSG dance.  The
        // streaming buffer however is reset.
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        self.aid_cache = None;
        self.md_ctx = None;
        self.private_key = None;

        let decoded = parse_ecdsa_key(key)?;
        if decoded.public_point.is_none() && decoded.private_scalar.is_none() {
            return Err(ProviderError::Init(
                "ecdsa: verify_init requires a public-key blob".into(),
            ));
        }
        let public = if decoded.public_point.is_some() {
            install_public_key(decoded)?
        } else {
            // Some callers re-use the private blob for verification — derive
            // the public key by re-loading the scalar (the EC layer
            // recomputes the public point internally).
            install_private_key(decoded)?
        };
        self.public_key = Some(public);
        self.operation = Some(OperationMode::Verify);
        self.allow_update = false;
        self.allow_final = false;
        self.allow_md_change = !self.variant.is_sigalg();

        if let Some(params) = params {
            self.set_ctx_params(params)?;
        }
        enforce_fixed_digest(self)?;
        Ok(())
    }

    fn verify(&mut self, data: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        require_operation(self, OperationMode::Verify)?;
        self.verify_digest(data, signature)
    }

    fn digest_sign_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            target: "openssl_provider::ecdsa",
            variant = %self.variant.name(),
            digest = %digest,
            "digest_sign_init",
        );

        if let Some(buf) = self.cached_signature.as_mut() {
            buf.zeroize();
        }
        self.cached_signature = None;
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        self.aid_cache = None;
        self.public_key = None;

        if self.variant.is_sigalg() {
            // Defensive: every fixed sigalg has a digest by construction.
            // Returning a structured error rather than panicking keeps
            // this code path clippy-clean (`expect_used`).
            let fixed = self.variant.fixed_digest().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "ecdsa: internal invariant violated — fixed sigalg {} has no digest",
                    self.variant.name()
                )))
            })?;
            if !digest.eq_ignore_ascii_case(fixed) {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ecdsa: variant {} requires digest {fixed}, got {digest}",
                        self.variant.name()
                    ),
                )));
            }
        }
        // Configure digest first so `enforce_fixed_digest` picks it up cleanly.
        let canonical = canonicalise_digest_name(digest);
        let chosen = if canonical.is_empty() {
            digest
        } else {
            canonical
        };
        self.md_name = Some(chosen.to_string());
        setup_digest(self, Some(chosen))?;

        let decoded = parse_ecdsa_key(key)?;
        if decoded.private_scalar.is_none() {
            return Err(ProviderError::Init(
                "ecdsa: digest_sign_init requires a private key blob".into(),
            ));
        }
        self.private_key = Some(install_private_key(decoded)?);
        self.operation = Some(OperationMode::Sign);
        self.allow_update = true;
        self.allow_final = true;
        self.allow_md_change = false;

        if let Some(params) = params {
            self.set_ctx_params(params)?;
        }
        enforce_fixed_digest(self)?;
        Ok(())
    }

    fn digest_sign_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        require_operation(self, OperationMode::Sign)?;
        if !self.allow_update {
            return Err(ProviderError::Init(
                "ecdsa: streaming updates not permitted in this state".into(),
            ));
        }
        let md_ctx = self.md_ctx.as_mut().ok_or_else(|| {
            ProviderError::Init("ecdsa: digest_sign_update without digest configured".into())
        })?;
        md_ctx.update(data).map_err(map_crypto_digest_error)?;
        // Mirror the C reference's `pbuf` for legacy `EVP_PKEY_sign`-style
        // VERIFYMSG plumbing.
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>> {
        require_operation(self, OperationMode::Sign)?;
        if !self.allow_final {
            return Err(ProviderError::Init(
                "ecdsa: digest_sign_final not permitted in this state".into(),
            ));
        }
        let mut md_ctx = self.md_ctx.take().ok_or_else(|| {
            ProviderError::Init("ecdsa: digest_sign_final without digest configured".into())
        })?;
        let mut digest = md_ctx.finalize().map_err(map_crypto_digest_error)?;

        self.allow_update = false;
        self.allow_final = false;

        let signature = self.sign_digest(&digest);
        digest.zeroize();
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        signature
    }

    fn digest_verify_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            target: "openssl_provider::ecdsa",
            variant = %self.variant.name(),
            digest = %digest,
            "digest_verify_init",
        );

        // Verify-side does NOT clear the cached signature — the VERIFYMSG
        // flow installs it via set_ctx_params before init.
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        self.aid_cache = None;
        self.private_key = None;

        if self.variant.is_sigalg() {
            // Defensive: every fixed sigalg has a digest by construction.
            // Returning a structured error rather than panicking keeps
            // this code path clippy-clean (`expect_used`).
            let fixed = self.variant.fixed_digest().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "ecdsa: internal invariant violated — fixed sigalg {} has no digest",
                    self.variant.name()
                )))
            })?;
            if !digest.eq_ignore_ascii_case(fixed) {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ecdsa: variant {} requires digest {fixed}, got {digest}",
                        self.variant.name()
                    ),
                )));
            }
        }
        let canonical = canonicalise_digest_name(digest);
        let chosen = if canonical.is_empty() {
            digest
        } else {
            canonical
        };
        self.md_name = Some(chosen.to_string());
        setup_digest(self, Some(chosen))?;

        let decoded = parse_ecdsa_key(key)?;
        if decoded.public_point.is_none() && decoded.private_scalar.is_none() {
            return Err(ProviderError::Init(
                "ecdsa: digest_verify_init requires a public-key blob".into(),
            ));
        }
        let public = if decoded.public_point.is_some() {
            install_public_key(decoded)?
        } else {
            install_private_key(decoded)?
        };
        self.public_key = Some(public);
        self.operation = Some(OperationMode::Verify);
        self.allow_update = true;
        self.allow_final = true;
        self.allow_md_change = false;

        if let Some(params) = params {
            self.set_ctx_params(params)?;
        }
        enforce_fixed_digest(self)?;
        Ok(())
    }

    fn digest_verify_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        require_operation(self, OperationMode::Verify)?;
        if !self.allow_update {
            return Err(ProviderError::Init(
                "ecdsa: streaming updates not permitted in this state".into(),
            ));
        }
        let md_ctx = self.md_ctx.as_mut().ok_or_else(|| {
            ProviderError::Init("ecdsa: digest_verify_update without digest configured".into())
        })?;
        md_ctx.update(data).map_err(map_crypto_digest_error)?;
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_verify_final(&mut self, signature: &[u8]) -> ProviderResult<bool> {
        require_operation(self, OperationMode::Verify)?;
        if !self.allow_final {
            return Err(ProviderError::Init(
                "ecdsa: digest_verify_final not permitted in this state".into(),
            ));
        }
        let mut md_ctx = self.md_ctx.take().ok_or_else(|| {
            ProviderError::Init("ecdsa: digest_verify_final without digest configured".into())
        })?;
        let mut digest = md_ctx.finalize().map_err(map_crypto_digest_error)?;

        self.allow_update = false;
        self.allow_final = false;

        let result = self.verify_digest(&digest, signature);
        digest.zeroize();
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        result
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();
        let aid = self
            .aid_cache
            .clone()
            .unwrap_or_else(|| compute_aid(self.variant));
        out.set("algorithm-id", ParamValue::OctetString(aid));
        if let Some(name) = self.md_name.as_ref() {
            out.set("digest", ParamValue::Utf8String(name.clone()));
        }
        if let Some(md) = self.md.as_ref() {
            let size = u64::try_from(md.digest_size()).map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "ecdsa: digest size to u64",
                })
            })?;
            out.set("size", ParamValue::UInt64(size));
        }
        out.set("nonce-type", ParamValue::UInt64(self.nonce_type.as_raw()));
        Ok(out)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Trivial wrapper for the trait-object dispatch path.
        EcdsaSignatureContext::set_ctx_params(self, params)
    }
}

// =============================================================================
// 4 inherent message-mode helpers (for legacy direct callers)
// =============================================================================

impl EcdsaSignatureContext {
    /// Inherent message-mode counterpart to `digest_sign_update`.
    pub fn sign_message_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        <Self as SignatureContext>::digest_sign_update(self, data)
    }

    /// Inherent message-mode counterpart to `digest_sign_final`.
    pub fn sign_message_final(&mut self) -> ProviderResult<Vec<u8>> {
        <Self as SignatureContext>::digest_sign_final(self)
    }

    /// Inherent message-mode counterpart to `digest_verify_update`.
    pub fn verify_message_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        <Self as SignatureContext>::digest_verify_update(self, data)
    }

    /// Inherent message-mode counterpart to `digest_verify_final`.  Pulls
    /// the cached signature installed by the `VERIFYMSG` flow.
    pub fn verify_message_final(&mut self) -> ProviderResult<bool> {
        let sig = self.cached_signature.clone().ok_or_else(|| {
            ProviderError::Init(
                "ecdsa: verify_message_final called without a cached signature — set one via set_ctx_params(\"signature\", ...) first".into(),
            )
        })?;
        <Self as SignatureContext>::digest_verify_final(self, &sig)
    }
}

// =============================================================================
// Registration descriptors — composable + 9 fixed sigalgs
// =============================================================================

/// The well-known property string attached to every default-provider ECDSA
/// algorithm.  Matches the C `ALG("...", "provider=default,fips=yes")`.
const ECDSA_PROPERTY: &str = "provider=default,fips=yes";

fn descriptor_composable() -> AlgorithmDescriptor {
    algorithm(
        &["ECDSA"],
        ECDSA_PROPERTY,
        "ECDSA over NIST P-curves (composable: caller supplies the digest)",
    )
}

fn descriptor_ecdsa_sha1() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA1",
            "ECDSA-SHA-1",
            "ecdsa-with-SHA1",
            "1.2.840.10045.4.1",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA1 fixed signature algorithm",
    )
}

fn descriptor_ecdsa_sha224() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA2-224",
            "ECDSA-SHA224",
            "ecdsa-with-SHA224",
            "1.2.840.10045.4.3.1",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA2-224 fixed signature algorithm",
    )
}

fn descriptor_ecdsa_sha256() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA2-256",
            "ECDSA-SHA256",
            "ecdsa-with-SHA256",
            "1.2.840.10045.4.3.2",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA2-256 fixed signature algorithm",
    )
}

fn descriptor_ecdsa_sha384() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA2-384",
            "ECDSA-SHA384",
            "ecdsa-with-SHA384",
            "1.2.840.10045.4.3.3",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA2-384 fixed signature algorithm",
    )
}

fn descriptor_ecdsa_sha512() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA2-512",
            "ECDSA-SHA512",
            "ecdsa-with-SHA512",
            "1.2.840.10045.4.3.4",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA2-512 fixed signature algorithm",
    )
}

fn descriptor_ecdsa_sha3_224() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA3-224",
            "ecdsa_with_SHA3-224",
            "id-ecdsa-with-sha3-224",
            "2.16.840.1.101.3.4.3.9",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA3-224 fixed signature algorithm",
    )
}

fn descriptor_ecdsa_sha3_256() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA3-256",
            "ecdsa_with_SHA3-256",
            "id-ecdsa-with-sha3-256",
            "2.16.840.1.101.3.4.3.10",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA3-256 fixed signature algorithm",
    )
}

fn descriptor_ecdsa_sha3_384() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA3-384",
            "ecdsa_with_SHA3-384",
            "id-ecdsa-with-sha3-384",
            "2.16.840.1.101.3.4.3.11",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA3-384 fixed signature algorithm",
    )
}

fn descriptor_ecdsa_sha3_512() -> AlgorithmDescriptor {
    algorithm(
        &[
            "ECDSA-SHA3-512",
            "ecdsa_with_SHA3-512",
            "id-ecdsa-with-sha3-512",
            "2.16.840.1.101.3.4.3.12",
        ],
        ECDSA_PROPERTY,
        "ECDSA-with-SHA3-512 fixed signature algorithm",
    )
}

/// Aggregate every ECDSA algorithm descriptor exposed by this module —
/// `ECDSA` (composable) plus the nine fixed sigalg variants in the order
/// emitted by `ossl_signature_functions[]` in the C source.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        descriptor_composable(),
        descriptor_ecdsa_sha1(),
        descriptor_ecdsa_sha224(),
        descriptor_ecdsa_sha256(),
        descriptor_ecdsa_sha384(),
        descriptor_ecdsa_sha512(),
        descriptor_ecdsa_sha3_224(),
        descriptor_ecdsa_sha3_256(),
        descriptor_ecdsa_sha3_384(),
        descriptor_ecdsa_sha3_512(),
    ]
}

// =============================================================================
// Unit tests
// =============================================================================
//
// Tests are organised in six categories, paralleling the structure of the DSA
// reference implementation:
//   1. Nonce-type surface (4 tests)
//   2. EcdsaVariant surface (3 tests)
//   3. EcdsaSignatureProvider surface (4 tests)
//   4. EcdsaSignatureContext direct surface (8 tests)
//   5. Descriptor surface (5 tests)
//   6. Sign→Verify round-trip surface (3 tests)
//
// All cryptographic round-trips use the openssl-crypto crate exclusively —
// this file remains 100 % `unsafe`-free per Rule R8.
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use openssl_crypto::ec::PointConversionForm;

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /// Allocate a fresh shared library context for use in tests.
    fn make_lib_ctx() -> Arc<LibContext> {
        LibContext::new()
    }

    /// Append a u32 big-endian length prefix followed by the payload bytes
    /// to `dst` — the format required by the TLV blob parser exercised by
    /// `parse_ecdsa_key`.
    fn append_lp(dst: &mut Vec<u8>, payload: &[u8]) {
        let len = u32::try_from(payload.len()).expect("payload fits in u32");
        dst.extend_from_slice(&len.to_be_bytes());
        dst.extend_from_slice(payload);
    }

    /// Build a private-key blob (curve name + private scalar).
    fn build_private_blob(curve_name: &str, priv_bytes: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.push(ECDSA_KEY_TLV_VERSION);
        blob.push(FLAG_HAS_CURVE_NAME | FLAG_HAS_PRIVATE);
        append_lp(&mut blob, curve_name.as_bytes());
        append_lp(&mut blob, priv_bytes);
        blob
    }

    /// Build a public-key blob (curve name + uncompressed point).
    fn build_public_blob(curve_name: &str, point_bytes: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.push(ECDSA_KEY_TLV_VERSION);
        blob.push(FLAG_HAS_CURVE_NAME | FLAG_HAS_PUBLIC);
        append_lp(&mut blob, curve_name.as_bytes());
        append_lp(&mut blob, point_bytes);
        blob
    }

    /// Generate a fresh P-256 keypair and return the in-memory key alongside
    /// the matching private/public TLV blobs.  The blobs can be fed directly
    /// to `sign_init` and `verify_init`.
    fn p256_keypair_blobs() -> (EcKey, Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let priv_scalar = key.private_key().unwrap().to_bytes_be();
        let pub_point = key
            .public_key()
            .unwrap()
            .to_bytes(key.group(), PointConversionForm::Uncompressed)
            .unwrap();
        let curve_name = NamedCurve::Prime256v1.name();
        let priv_blob = build_private_blob(curve_name, &priv_scalar);
        let pub_blob = build_public_blob(curve_name, &pub_point);
        (key, priv_blob, pub_blob)
    }

    /// Hash `message` with SHA-256 using the public digest API and return
    /// the 32-byte output.  Mirrors the digest pipeline used internally by
    /// the digest-sign/verify operations.
    fn sha256_digest(lib_ctx: &Arc<LibContext>, message: &[u8]) -> Vec<u8> {
        let md = MessageDigest::fetch(lib_ctx, SHA256, None).unwrap();
        let mut md_ctx = MdContext::new();
        md_ctx.init(&md, None).unwrap();
        md_ctx.update(message).unwrap();
        md_ctx.finalize().unwrap()
    }

    // ---------------------------------------------------------------------
    // 1. Nonce-type surface (4 tests)
    // ---------------------------------------------------------------------

    #[test]
    fn nonce_type_default_is_random() {
        let nt: EcdsaNonceType = EcdsaNonceType::default();
        assert_eq!(nt, EcdsaNonceType::Random);
        assert_eq!(nt.as_raw(), 0);
    }

    #[test]
    fn nonce_type_from_raw_maps_correctly() {
        assert_eq!(EcdsaNonceType::from_raw(0).unwrap(), EcdsaNonceType::Random);
        assert_eq!(
            EcdsaNonceType::from_raw(1).unwrap(),
            EcdsaNonceType::Deterministic,
        );
        // raw == 2 yields a TestKat with an empty nonce buffer; subsequent
        // `kat-nonce` parameter writes populate the buffer.
        match EcdsaNonceType::from_raw(2).unwrap() {
            EcdsaNonceType::TestKat(buf) => assert!(buf.is_empty()),
            other => panic!("expected TestKat variant, got {other:?}"),
        }
    }

    #[test]
    fn nonce_type_as_raw_round_trip() {
        for raw in 0u64..=2u64 {
            let parsed = EcdsaNonceType::from_raw(raw).unwrap();
            assert_eq!(parsed.as_raw(), raw, "round-trip mismatch for raw={raw}");
        }
        // Custom TestKat payloads still report raw=2 — the carried bytes do
        // not change the discriminant.
        let kat = EcdsaNonceType::TestKat(vec![0xAA; 16]);
        assert_eq!(kat.as_raw(), 2);
    }

    #[test]
    fn nonce_type_rejects_unknown_values() {
        for bad in [3u64, 4u64, 100u64, u64::MAX] {
            let err = EcdsaNonceType::from_raw(bad).unwrap_err();
            assert!(
                matches!(&err, ProviderError::Common(CommonError::InvalidArgument(_)),),
                "expected ProviderError::Common(InvalidArgument) for raw={bad}, got {err:?}",
            );
        }
    }

    // ---------------------------------------------------------------------
    // 2. EcdsaVariant surface (3 tests)
    // ---------------------------------------------------------------------

    #[test]
    fn variant_name_returns_canonical_name() {
        let cases: &[(EcdsaVariant, &'static str)] = &[
            (EcdsaVariant::Composable, "ECDSA"),
            (EcdsaVariant::EcdsaSha1, "ECDSA-SHA1"),
            (EcdsaVariant::EcdsaSha224, "ECDSA-SHA2-224"),
            (EcdsaVariant::EcdsaSha256, "ECDSA-SHA2-256"),
            (EcdsaVariant::EcdsaSha384, "ECDSA-SHA2-384"),
            (EcdsaVariant::EcdsaSha512, "ECDSA-SHA2-512"),
            (EcdsaVariant::EcdsaSha3_224, "ECDSA-SHA3-224"),
            (EcdsaVariant::EcdsaSha3_256, "ECDSA-SHA3-256"),
            (EcdsaVariant::EcdsaSha3_384, "ECDSA-SHA3-384"),
            (EcdsaVariant::EcdsaSha3_512, "ECDSA-SHA3-512"),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.name(), *expected, "variant {variant:?}");
        }
    }

    #[test]
    fn variant_is_sigalg_distinguishes_composable() {
        assert!(
            !EcdsaVariant::Composable.is_sigalg(),
            "Composable must not advertise as a fixed sigalg",
        );
        for v in [
            EcdsaVariant::EcdsaSha1,
            EcdsaVariant::EcdsaSha224,
            EcdsaVariant::EcdsaSha256,
            EcdsaVariant::EcdsaSha384,
            EcdsaVariant::EcdsaSha512,
            EcdsaVariant::EcdsaSha3_224,
            EcdsaVariant::EcdsaSha3_256,
            EcdsaVariant::EcdsaSha3_384,
            EcdsaVariant::EcdsaSha3_512,
        ] {
            assert!(v.is_sigalg(), "variant {v:?} must be a fixed sigalg");
        }
    }

    #[test]
    fn variant_fixed_digest_returns_correct_digest() {
        assert_eq!(EcdsaVariant::Composable.fixed_digest(), None);
        assert_eq!(EcdsaVariant::EcdsaSha1.fixed_digest(), Some(SHA1));
        assert_eq!(EcdsaVariant::EcdsaSha224.fixed_digest(), Some(SHA224));
        assert_eq!(EcdsaVariant::EcdsaSha256.fixed_digest(), Some(SHA256));
        assert_eq!(EcdsaVariant::EcdsaSha384.fixed_digest(), Some(SHA384));
        assert_eq!(EcdsaVariant::EcdsaSha512.fixed_digest(), Some(SHA512));
        assert_eq!(EcdsaVariant::EcdsaSha3_224.fixed_digest(), Some(SHA3_224));
        assert_eq!(EcdsaVariant::EcdsaSha3_256.fixed_digest(), Some(SHA3_256));
        assert_eq!(EcdsaVariant::EcdsaSha3_384.fixed_digest(), Some(SHA3_384));
        assert_eq!(EcdsaVariant::EcdsaSha3_512.fixed_digest(), Some(SHA3_512));
    }

    // ---------------------------------------------------------------------
    // 3. EcdsaSignatureProvider surface (4 tests)
    // ---------------------------------------------------------------------

    #[test]
    fn provider_new_defaults_to_composable() {
        let p = EcdsaSignatureProvider::new();
        assert_eq!(p.variant(), EcdsaVariant::Composable);
        assert_eq!(p.name(), "ECDSA");
        // Default::default() must agree with new().
        let q = EcdsaSignatureProvider::default();
        assert_eq!(q.variant(), p.variant());
    }

    #[test]
    fn provider_with_variant_creates_correct_variant() {
        let p =
            EcdsaSignatureProvider::with_variant(make_lib_ctx(), None, EcdsaVariant::EcdsaSha256);
        assert_eq!(p.variant(), EcdsaVariant::EcdsaSha256);
        assert_eq!(p.name(), "ECDSA-SHA2-256");

        let q = EcdsaSignatureProvider::with_variant(
            make_lib_ctx(),
            Some("provider=default".to_string()),
            EcdsaVariant::EcdsaSha3_512,
        );
        assert_eq!(q.variant(), EcdsaVariant::EcdsaSha3_512);
        assert_eq!(q.name(), "ECDSA-SHA3-512");
    }

    #[test]
    fn provider_variant_getter_covers_all_variants() {
        let variants = [
            EcdsaVariant::Composable,
            EcdsaVariant::EcdsaSha1,
            EcdsaVariant::EcdsaSha224,
            EcdsaVariant::EcdsaSha256,
            EcdsaVariant::EcdsaSha384,
            EcdsaVariant::EcdsaSha512,
            EcdsaVariant::EcdsaSha3_224,
            EcdsaVariant::EcdsaSha3_256,
            EcdsaVariant::EcdsaSha3_384,
            EcdsaVariant::EcdsaSha3_512,
        ];
        for v in variants {
            let p = EcdsaSignatureProvider::with_variant(make_lib_ctx(), None, v);
            assert_eq!(
                p.variant(),
                v,
                "variant getter returned wrong value for {v:?}"
            );
        }
    }

    #[test]
    fn provider_new_ctx_returns_boxed_context() {
        let p =
            EcdsaSignatureProvider::with_variant(make_lib_ctx(), None, EcdsaVariant::EcdsaSha384);
        // Successful call must yield a usable boxed trait object.
        let _ctx: Box<dyn SignatureContext> = p.new_ctx().unwrap();
        // SignatureProvider::name reflects the chosen variant.
        assert_eq!(p.name(), "ECDSA-SHA2-384");
    }

    // ---------------------------------------------------------------------
    // 4. EcdsaSignatureContext direct surface (8 tests)
    // ---------------------------------------------------------------------

    #[test]
    fn context_new_initial_state_composable() {
        let ctx = EcdsaSignatureContext::new(make_lib_ctx(), None, EcdsaVariant::Composable);
        assert_eq!(ctx.variant, EcdsaVariant::Composable);
        assert!(ctx.private_key.is_none());
        assert!(ctx.public_key.is_none());
        assert!(ctx.operation.is_none());
        assert!(
            ctx.allow_md_change,
            "composable mode must allow digest change"
        );
        assert!(!ctx.allow_update);
        assert!(!ctx.allow_final);
        assert!(ctx.md.is_none());
        assert!(ctx.md_name.is_none(), "composable has no fixed digest");
        assert!(ctx.md_ctx.is_none());
        assert_eq!(ctx.nonce_type, EcdsaNonceType::Random);
        assert!(ctx.aid_cache.is_none());
        assert!(ctx.cached_signature.is_none());
        assert!(ctx.streaming_buffer.is_empty());
    }

    #[test]
    fn context_new_md_name_for_fixed_sigalg() {
        let cases: &[(EcdsaVariant, &'static str)] = &[
            (EcdsaVariant::EcdsaSha1, SHA1),
            (EcdsaVariant::EcdsaSha224, SHA224),
            (EcdsaVariant::EcdsaSha256, SHA256),
            (EcdsaVariant::EcdsaSha384, SHA384),
            (EcdsaVariant::EcdsaSha512, SHA512),
            (EcdsaVariant::EcdsaSha3_224, SHA3_224),
            (EcdsaVariant::EcdsaSha3_256, SHA3_256),
            (EcdsaVariant::EcdsaSha3_384, SHA3_384),
            (EcdsaVariant::EcdsaSha3_512, SHA3_512),
        ];
        for (variant, expected) in cases {
            let ctx = EcdsaSignatureContext::new(make_lib_ctx(), None, *variant);
            assert_eq!(
                ctx.md_name.as_deref(),
                Some(*expected),
                "fixed sigalg {variant:?} must publish digest {expected}",
            );
            assert!(
                !ctx.allow_md_change,
                "fixed sigalg {variant:?} must lock the digest",
            );
        }
    }

    #[test]
    fn context_new_propq_is_stored() {
        let ctx = EcdsaSignatureContext::new(
            make_lib_ctx(),
            Some("provider=fips".to_string()),
            EcdsaVariant::Composable,
        );
        assert_eq!(ctx.propq.as_deref(), Some("provider=fips"));
    }

    #[test]
    fn context_duplicate_clones_state() {
        let mut ctx = EcdsaSignatureContext::new(
            make_lib_ctx(),
            Some("propq=foo".to_string()),
            EcdsaVariant::EcdsaSha384,
        );
        // Populate optional fields so we can confirm they survive duplication.
        ctx.streaming_buffer.extend_from_slice(b"abc");
        ctx.aid_cache = Some(vec![0xCA, 0xFE]);
        ctx.cached_signature = Some(vec![0xBE, 0xEF]);
        ctx.nonce_type = EcdsaNonceType::Deterministic;
        ctx.allow_update = true;
        ctx.allow_final = true;

        let dup = ctx.duplicate();
        assert_eq!(dup.variant, ctx.variant);
        assert_eq!(dup.propq.as_deref(), Some("propq=foo"));
        assert_eq!(dup.streaming_buffer, ctx.streaming_buffer);
        assert_eq!(dup.aid_cache, ctx.aid_cache);
        assert_eq!(dup.cached_signature, ctx.cached_signature);
        assert_eq!(dup.nonce_type, ctx.nonce_type);
        assert_eq!(dup.allow_update, ctx.allow_update);
        assert_eq!(dup.allow_final, ctx.allow_final);
        assert_eq!(dup.md_name, ctx.md_name);
        // The streaming digest context is intentionally reset on duplicate so
        // that the clone starts in a clean update/finalise lifecycle.
        assert!(
            dup.md_ctx.is_none(),
            "md_ctx must be reset on duplicate to avoid double-feeding state",
        );
    }

    #[test]
    fn context_sign_without_init_errors() {
        let mut ctx = EcdsaSignatureContext::new(make_lib_ctx(), None, EcdsaVariant::Composable);
        let err = ctx.sign(b"not a real digest").unwrap_err();
        assert!(
            matches!(err, ProviderError::Init(_)),
            "expected ProviderError::Init for sign-before-init, got {err:?}",
        );
    }

    #[test]
    fn context_verify_without_init_errors() {
        let mut ctx = EcdsaSignatureContext::new(make_lib_ctx(), None, EcdsaVariant::Composable);
        let err = ctx
            .verify(b"not a real digest", b"not a real signature")
            .unwrap_err();
        assert!(
            matches!(err, ProviderError::Init(_)),
            "expected ProviderError::Init for verify-before-init, got {err:?}",
        );
    }

    #[test]
    fn context_digest_sign_final_without_init_errors() {
        let mut ctx = EcdsaSignatureContext::new(make_lib_ctx(), None, EcdsaVariant::Composable);
        let err = ctx.digest_sign_final().unwrap_err();
        assert!(
            matches!(err, ProviderError::Init(_)),
            "expected ProviderError::Init for digest_sign_final-before-init, got {err:?}",
        );
    }

    #[test]
    fn context_digest_verify_final_without_init_errors() {
        let mut ctx = EcdsaSignatureContext::new(make_lib_ctx(), None, EcdsaVariant::Composable);
        let err = ctx.digest_verify_final(b"sig").unwrap_err();
        assert!(
            matches!(err, ProviderError::Init(_)),
            "expected ProviderError::Init for digest_verify_final-before-init, got {err:?}",
        );
    }

    // ---------------------------------------------------------------------
    // 5. Descriptor surface (5 tests)
    // ---------------------------------------------------------------------

    #[test]
    fn descriptors_count_is_ten() {
        let d = descriptors();
        assert_eq!(
            d.len(),
            10,
            "expected 10 descriptors (composable + 9 fixed sigalgs)",
        );
    }

    #[test]
    fn descriptors_first_is_composable() {
        let d = descriptors();
        let first = d.first().expect("descriptors must be non-empty");
        assert_eq!(first.names.first().copied(), Some("ECDSA"));
        assert!(
            first.description.contains("composable"),
            "first descriptor must describe the composable variant, got {:?}",
            first.description,
        );
    }

    #[test]
    fn descriptors_order_matches_spec() {
        let names: Vec<&'static str> = descriptors()
            .into_iter()
            .map(|d| {
                *d.names
                    .first()
                    .expect("each descriptor has at least one name")
            })
            .collect();
        let expected = vec![
            "ECDSA",
            "ECDSA-SHA1",
            "ECDSA-SHA2-224",
            "ECDSA-SHA2-256",
            "ECDSA-SHA2-384",
            "ECDSA-SHA2-512",
            "ECDSA-SHA3-224",
            "ECDSA-SHA3-256",
            "ECDSA-SHA3-384",
            "ECDSA-SHA3-512",
        ];
        assert_eq!(names, expected);
    }

    #[test]
    fn descriptors_aliases_match() {
        let descs = descriptors();
        let expected: Vec<Vec<&'static str>> = vec![
            vec!["ECDSA"],
            vec![
                "ECDSA-SHA1",
                "ECDSA-SHA-1",
                "ecdsa-with-SHA1",
                "1.2.840.10045.4.1",
            ],
            vec![
                "ECDSA-SHA2-224",
                "ECDSA-SHA224",
                "ecdsa-with-SHA224",
                "1.2.840.10045.4.3.1",
            ],
            vec![
                "ECDSA-SHA2-256",
                "ECDSA-SHA256",
                "ecdsa-with-SHA256",
                "1.2.840.10045.4.3.2",
            ],
            vec![
                "ECDSA-SHA2-384",
                "ECDSA-SHA384",
                "ecdsa-with-SHA384",
                "1.2.840.10045.4.3.3",
            ],
            vec![
                "ECDSA-SHA2-512",
                "ECDSA-SHA512",
                "ecdsa-with-SHA512",
                "1.2.840.10045.4.3.4",
            ],
            vec![
                "ECDSA-SHA3-224",
                "ecdsa_with_SHA3-224",
                "id-ecdsa-with-sha3-224",
                "2.16.840.1.101.3.4.3.9",
            ],
            vec![
                "ECDSA-SHA3-256",
                "ecdsa_with_SHA3-256",
                "id-ecdsa-with-sha3-256",
                "2.16.840.1.101.3.4.3.10",
            ],
            vec![
                "ECDSA-SHA3-384",
                "ecdsa_with_SHA3-384",
                "id-ecdsa-with-sha3-384",
                "2.16.840.1.101.3.4.3.11",
            ],
            vec![
                "ECDSA-SHA3-512",
                "ecdsa_with_SHA3-512",
                "id-ecdsa-with-sha3-512",
                "2.16.840.1.101.3.4.3.12",
            ],
        ];
        assert_eq!(descs.len(), expected.len());
        for (got, want) in descs.iter().zip(expected.iter()) {
            assert_eq!(
                &got.names,
                want,
                "alias list mismatch for descriptor {:?}",
                got.names.first(),
            );
        }
    }

    #[test]
    fn descriptor_property_string_and_descriptions_present() {
        for d in descriptors() {
            assert_eq!(
                d.property, ECDSA_PROPERTY,
                "property must equal {ECDSA_PROPERTY:?} for {:?}",
                d.names,
            );
            assert!(
                !d.description.is_empty(),
                "description must be non-empty for {:?}",
                d.names,
            );
            assert!(
                d.description.contains("ECDSA") || d.description.contains("ecdsa"),
                "description must mention ECDSA for {:?}, got {:?}",
                d.names,
                d.description,
            );
        }
    }

    // ---------------------------------------------------------------------
    // 6. Sign→Verify round-trip surface (3 tests)
    // ---------------------------------------------------------------------

    #[test]
    fn roundtrip_composable_p256() {
        let lib_ctx = make_lib_ctx();
        let (_key, priv_blob, pub_blob) = p256_keypair_blobs();

        // Composable mode: caller pre-hashes the message and passes the digest
        // bytes directly to `sign`/`verify`.
        let digest = sha256_digest(&lib_ctx, b"hello, ecdsa");

        let mut signer =
            EcdsaSignatureContext::new(Arc::clone(&lib_ctx), None, EcdsaVariant::Composable);
        signer.sign_init(&priv_blob, None).unwrap();
        let signature = signer.sign(&digest).unwrap();

        // P-256 DER signatures are 64..=72 bytes for valid (r, s) pairs;
        // the lower bound permits the ~1-in-256 case where r or s is short.
        assert!(
            (60..=72).contains(&signature.len()),
            "unexpected DER signature length {} for P-256 (expected 60..=72)",
            signature.len(),
        );

        let mut verifier =
            EcdsaSignatureContext::new(Arc::clone(&lib_ctx), None, EcdsaVariant::Composable);
        verifier.verify_init(&pub_blob, None).unwrap();
        let ok = verifier.verify(&digest, &signature).unwrap();
        assert!(ok, "freshly-produced signature must verify");
    }

    #[test]
    fn roundtrip_fixed_sigalg_sha256_p256() {
        let lib_ctx = make_lib_ctx();
        let (_key, priv_blob, pub_blob) = p256_keypair_blobs();
        let message: &[u8] = b"the quick brown fox jumps over the lazy dog";

        // Fixed sigalg: caller supplies the raw message; the context streams
        // it through the locked digest and then signs the digest output.
        let mut signer =
            EcdsaSignatureContext::new(Arc::clone(&lib_ctx), None, EcdsaVariant::EcdsaSha256);
        signer.digest_sign_init(SHA256, &priv_blob, None).unwrap();
        signer.digest_sign_update(message).unwrap();
        let signature = signer.digest_sign_final().unwrap();
        assert!(
            (60..=72).contains(&signature.len()),
            "unexpected DER signature length {} for P-256+SHA-256",
            signature.len(),
        );

        let mut verifier =
            EcdsaSignatureContext::new(Arc::clone(&lib_ctx), None, EcdsaVariant::EcdsaSha256);
        verifier
            .digest_verify_init(SHA256, &pub_blob, None)
            .unwrap();
        verifier.digest_verify_update(message).unwrap();
        let ok = verifier.digest_verify_final(&signature).unwrap();
        assert!(ok, "freshly-produced ECDSA-SHA2-256 signature must verify",);
    }

    #[test]
    fn roundtrip_verify_fails_on_modified_signature() {
        let lib_ctx = make_lib_ctx();
        let (_key, priv_blob, pub_blob) = p256_keypair_blobs();
        let digest = sha256_digest(&lib_ctx, b"original message");

        // Produce a valid signature.
        let mut signer =
            EcdsaSignatureContext::new(Arc::clone(&lib_ctx), None, EcdsaVariant::Composable);
        signer.sign_init(&priv_blob, None).unwrap();
        let mut signature = signer.sign(&digest).unwrap();

        // Tamper with a byte in the middle of the DER blob.  Either the DER
        // parser rejects the malformed structure (Err) or the verifier
        // produces Ok(false) — both outcomes are acceptable forgery
        // detection; only Ok(true) is unacceptable.
        let mid = signature.len() / 2;
        signature[mid] ^= 0xFF;

        let mut verifier =
            EcdsaSignatureContext::new(Arc::clone(&lib_ctx), None, EcdsaVariant::Composable);
        verifier.verify_init(&pub_blob, None).unwrap();
        let res = verifier.verify(&digest, &signature);
        // Either verifier rejection (`Ok(false)`) or a DER parse/format
        // error (`Err(_)`) is acceptable — both signal that the modified
        // signature did not authenticate.  The forbidden outcome is
        // `Ok(true)`, which would indicate a verifier bug.
        match res {
            Ok(false) | Err(_) => {}
            Ok(true) => panic!("modified signature must not verify"),
        }
    }
}
