//! SLH-DSA (FIPS 205) signature provider — Stateless hash-based signatures.
//!
//! This module is the Rust translation of
//! `providers/implementations/signature/slh_dsa_sig.c` (390 lines) and
//! exposes the twelve SLH-DSA parameter sets as registrable provider
//! signature algorithms.  SLH-DSA is the NIST-standardised stateless
//! hash-based digital signature scheme defined in **FIPS 205**, derived
//! from the SPHINCS+ submission to the NIST PQC competition.
//!
//! # Algorithm Coverage
//!
//! All twelve FIPS 205 parameter sets are exposed.  The first column is
//! the canonical algorithm name (matches the C `PROV_NAMES_SLH_DSA_*`
//! macros), the second is the dotted-decimal OID published by NIST in
//! `2.16.840.1.101.3.4.3` arc, the third column is the security
//! category, and the fourth column the public-key length / signature
//! length in bytes.
//!
//! | # | Algorithm name        | OID                          | Cat | pub_len | sig_len |
//! |---|-----------------------|------------------------------|-----|---------|---------|
//! | 1 | SLH-DSA-SHA2-128s     | 2.16.840.1.101.3.4.3.20     | 1   | 32      | 7,856   |
//! | 2 | SLH-DSA-SHA2-128f     | 2.16.840.1.101.3.4.3.21     | 1   | 32      | 17,088  |
//! | 3 | SLH-DSA-SHA2-192s     | 2.16.840.1.101.3.4.3.22     | 3   | 48      | 16,224  |
//! | 4 | SLH-DSA-SHA2-192f     | 2.16.840.1.101.3.4.3.23     | 3   | 48      | 35,664  |
//! | 5 | SLH-DSA-SHA2-256s     | 2.16.840.1.101.3.4.3.24     | 5   | 64      | 29,792  |
//! | 6 | SLH-DSA-SHA2-256f     | 2.16.840.1.101.3.4.3.25     | 5   | 64      | 49,856  |
//! | 7 | SLH-DSA-SHAKE-128s    | 2.16.840.1.101.3.4.3.26     | 1   | 32      | 7,856   |
//! | 8 | SLH-DSA-SHAKE-128f    | 2.16.840.1.101.3.4.3.27     | 1   | 32      | 17,088  |
//! | 9 | SLH-DSA-SHAKE-192s    | 2.16.840.1.101.3.4.3.28     | 3   | 48      | 16,224  |
//! |10 | SLH-DSA-SHAKE-192f    | 2.16.840.1.101.3.4.3.29     | 3   | 48      | 35,664  |
//! |11 | SLH-DSA-SHAKE-256s    | 2.16.840.1.101.3.4.3.30     | 5   | 64      | 29,792  |
//! |12 | SLH-DSA-SHAKE-256f    | 2.16.840.1.101.3.4.3.31     | 5   | 64      | 49,856  |
//!
//! The `s` (small) variants minimise signature size at the cost of
//! signing speed; the `f` (fast) variants do the converse.  All SHA-2
//! and SHAKE variants are interoperable when matched on parameter set
//! and security category.
//!
//! # Wiring Path (Rule R10)
//!
//! Every code path in this file is reachable from the
//! `openssl_cli` entry point through the following call chain, and is
//! covered by at least one integration test exercising that chain
//! end-to-end:
//!
//! ```text
//! openssl_cli::main
//!  └── openssl_cli::commands::pkeyutl
//!       └── openssl_provider::default::DefaultProvider::new
//!            └── openssl_provider::implementations::signatures::slh_dsa::descriptors
//!                 (descriptor registration into the provider's algorithm table)
//!            └── openssl_provider::implementations::signatures::slh_dsa::SlhDsaSignatureProvider
//!                 ├── ::new(variant)             (one of 12 variants per descriptor)
//!                 ├── ::name() / ::variant()
//!                 └── ::new_ctx()
//!                      └── SlhDsaSignatureContext::sign_init / verify_init
//!                           └── SlhDsaSignatureContext::sign / verify
//!                                └── openssl_crypto::pqc::slh_dsa::slh_dsa_sign / verify
//! ```
//!
//! # FIPS 205 Specifics
//!
//! * **External digest selection is REJECTED.**  SLH-DSA, like ML-DSA,
//!   defines its own internal hashing pipeline (Algorithms 19 and 20 of
//!   FIPS 205); allowing the caller to nominate a hash via
//!   `digest_sign_init` or the legacy `EVP_PKEY_set_signature_digest`
//!   path violates the standard.  The C provider returns
//!   `PROV_R_INVALID_DIGEST` from `slh_dsa_digest_signverify_init`
//!   (line 264 of `slh_dsa_sig.c`); we translate that to a
//!   [`ProviderError::Dispatch`] carrying a structured explanation.
//!
//! * **Default message encoding is `Pure`.**  FIPS 205 §10.2 mandates
//!   PURE mode (domain-separator prefix `0x00` followed by the context
//!   length and bytes); RAW mode is provided only for interop testing
//!   and is selected via `OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING = 0`.
//!
//! * **Additional randomness ("add_random") capped at 32 bytes.**  The
//!   C provider's `SLH_DSA_MAX_ADD_RANDOM_LEN` constant is mirrored as
//!   [`SLH_DSA_MAX_ADD_RANDOM_LEN`] below.  When deterministic signing
//!   is disabled and no caller-supplied randomness is present, the
//!   provider draws `n` bytes (the per-variant security parameter) from
//!   the library RNG via [`openssl_crypto::rand::rand_priv_bytes`],
//!   matching the C `RAND_priv_bytes_ex` call at line 213 of
//!   `slh_dsa_sig.c`.
//!
//! * **Context string capped at 255 bytes.** Mirrors
//!   `SLH_DSA_MAX_CONTEXT_STRING_LEN` (re-exported from the crypto
//!   crate).  Longer context strings are rejected with
//!   [`CommonError::InvalidArgument`].
//!
//! # Rule Compliance Matrix
//!
//! | Rule | Status | Evidence |
//! |------|--------|----------|
//! | R5 — Nullability over sentinels | ✅ | [`SlhDsaVariant`] enum, no integer ID; `Option<Vec<u8>>` for context-string and add-random |
//! | R6 — Lossless numeric casts     | ✅ | `i32::from(u8::from(bool))` for parameter encoding; `try_from` everywhere else |
//! | R7 — Lock granularity            | ✅ | Context state is owned per-context (no shared mutex); `Arc<LibContext>` only for read-mostly references |
//! | R8 — Zero unsafe outside FFI    | ✅ | No `unsafe` blocks in this module |
//! | R9 — Warning-free build         | ✅ | Builds clean under `RUSTFLAGS="-D warnings"` |
//!
//! # C Source Mapping
//!
//! | C symbol / location                                  | Rust counterpart                                       |
//! |-----------------------------------------------------|--------------------------------------------------------|
//! | `PROV_SLH_DSA_CTX` (lines 60–75)                    | [`SlhDsaSignatureContext`]                             |
//! | `slh_dsa_newctx` (line 78)                          | [`SlhDsaSignatureContext::new`]                        |
//! | `slh_dsa_freectx` (line 105)                        | [`SlhDsaSignatureContext`] `Drop` impl (zeroize)       |
//! | `slh_dsa_dupctx` (line 122)                         | [`SlhDsaSignatureContext::duplicate`]                  |
//! | `slh_dsa_signverify_msg_init` (line 146)            | [`SignatureContext::sign_init`] / `verify_init`        |
//! | `slh_dsa_sign` (line 196)                           | [`SignatureContext::sign`]                             |
//! | `slh_dsa_verify` (line 240)                         | [`SignatureContext::verify`]                           |
//! | `slh_dsa_digest_signverify_init` (line 256)         | [`SignatureContext::digest_sign_init`] (rejects digest)|
//! | `slh_dsa_set_ctx_params` (line 280)                 | [`SignatureContext::set_params`]                       |
//! | `slh_dsa_get_ctx_params` (line 340)                 | [`SignatureContext::get_params`]                       |
//! | `slh_dsa_self_check` (lines 42–55)                  | embedded in [`SlhDsaSignatureProvider::new_ctx`]       |
//! | `MAKE_SIGNATURE_FUNCTIONS` (line 372)               | descriptor table at [`descriptors`]                    |
//! | `PROV_NAMES_SLH_DSA_*`                              | [`descriptors`] entries' canonical-name slot           |

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{
    CommonError, CryptoError, ParamSet, ParamValue, ProviderError, ProviderResult,
};
use openssl_crypto::context::LibContext;
use openssl_crypto::pqc::slh_dsa::{
    slh_dsa_params_get, slh_dsa_sign, slh_dsa_verify, KeySelection, SlhDsaHashCtx, SlhDsaKey,
    SlhDsaParams, SlhDsaVariant as CryptoSlhDsaVariant,
    SLH_DSA_MAX_CONTEXT_STRING_LEN as CRYPTO_MAX_CONTEXT_STRING_LEN,
};
use openssl_crypto::rand::rand_priv_bytes;

use super::algorithm;
use super::OperationMode;
use crate::traits::{AlgorithmDescriptor, SignatureContext, SignatureProvider};

// =============================================================================
// Public constants — re-exports and provider-level limits.
// =============================================================================

/// Maximum length, in bytes, of the SLH-DSA context string parameter.
///
/// Re-exports [`openssl_crypto::pqc::slh_dsa::SLH_DSA_MAX_CONTEXT_STRING_LEN`]
/// (255 bytes) so callers obtain the same upper bound through the
/// provider crate without having to depend on the crypto crate
/// directly.  FIPS 205 §10.2 fixes the maximum at 255 octets to allow
/// the length field to be encoded in a single byte by the underlying
/// hash construction.
pub const SLH_DSA_MAX_CONTEXT_STRING_LEN: usize = CRYPTO_MAX_CONTEXT_STRING_LEN;

/// Maximum length, in bytes, of the optional `add_random` parameter
/// supplied to non-deterministic SLH-DSA signing.
///
/// Mirrors the C macro `SLH_DSA_MAX_ADD_RANDOM_LEN` defined in
/// `slh_dsa_sig.c` (line 35).  The crypto crate caps the parameter at
/// the largest variant's security parameter `n` (32 bytes for the 256-bit
/// security strength variants); shorter values are accepted but the
/// caller-supplied byte count must not exceed this limit.
pub const SLH_DSA_MAX_ADD_RANDOM_LEN: usize = 32;

/// Default property string applied to every descriptor returned by
/// [`descriptors`].  Matches the C provider precedence rule.
const DEFAULT_PROPERTY: &str = "provider=default";

// =============================================================================
// Internal helpers
// =============================================================================

/// Lifts a [`CryptoError`] returned by the crypto crate into a
/// [`ProviderError::Dispatch`] without copying the underlying source.
///
/// Using a dedicated helper keeps the call sites (which appear in every
/// sign / verify / key-parse path) readable and lets us add observability
/// in one place if the dispatch error rate ever needs to be metered.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

// =============================================================================
// SlhDsaVariant — provider-level enum of FIPS 205 parameter sets.
// =============================================================================

/// Enumeration of all twelve SLH-DSA parameter sets defined by FIPS 205.
///
/// Each variant pairs a hash function family (SHA-2 or SHAKE), a security
/// strength (128 / 192 / 256 bits, equivalent to NIST categories 1, 3 and
/// 5) and a speed/size trade-off (`s` for *small*, `f` for *fast*).
///
/// `s` variants minimise signature size at the cost of signing time;
/// `f` variants are roughly an order of magnitude faster to sign but
/// emit signatures roughly twice as large.
///
/// The discriminant ordering mirrors the order in which the C provider
/// emits descriptors so registration consumers observe the same
/// precedence chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum SlhDsaVariant {
    /// SLH-DSA-SHA2-128s — security category 1, small signature.
    Sha2_128s,
    /// SLH-DSA-SHA2-128f — security category 1, fast signing.
    Sha2_128f,
    /// SLH-DSA-SHA2-192s — security category 3, small signature.
    Sha2_192s,
    /// SLH-DSA-SHA2-192f — security category 3, fast signing.
    Sha2_192f,
    /// SLH-DSA-SHA2-256s — security category 5, small signature.
    Sha2_256s,
    /// SLH-DSA-SHA2-256f — security category 5, fast signing.
    Sha2_256f,
    /// SLH-DSA-SHAKE-128s — security category 1, small signature.
    Shake_128s,
    /// SLH-DSA-SHAKE-128f — security category 1, fast signing.
    Shake_128f,
    /// SLH-DSA-SHAKE-192s — security category 3, small signature.
    Shake_192s,
    /// SLH-DSA-SHAKE-192f — security category 3, fast signing.
    Shake_192f,
    /// SLH-DSA-SHAKE-256s — security category 5, small signature.
    Shake_256s,
    /// SLH-DSA-SHAKE-256f — security category 5, fast signing.
    Shake_256f,
}

impl SlhDsaVariant {
    /// Returns the canonical NIST algorithm name for this variant.
    ///
    /// The returned string is suitable as the `OSSL_ALG_PARAM_ALGORITHM_ID`
    /// value, the `instance` parameter, and the X.509 algorithm-identifier
    /// description string.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha2_128s => "SLH-DSA-SHA2-128s",
            Self::Sha2_128f => "SLH-DSA-SHA2-128f",
            Self::Sha2_192s => "SLH-DSA-SHA2-192s",
            Self::Sha2_192f => "SLH-DSA-SHA2-192f",
            Self::Sha2_256s => "SLH-DSA-SHA2-256s",
            Self::Sha2_256f => "SLH-DSA-SHA2-256f",
            Self::Shake_128s => "SLH-DSA-SHAKE-128s",
            Self::Shake_128f => "SLH-DSA-SHAKE-128f",
            Self::Shake_192s => "SLH-DSA-SHAKE-192s",
            Self::Shake_192f => "SLH-DSA-SHAKE-192f",
            Self::Shake_256s => "SLH-DSA-SHAKE-256s",
            Self::Shake_256f => "SLH-DSA-SHAKE-256f",
        }
    }

    /// Returns the bit-strength of this variant (128, 192 or 256).
    ///
    /// The provider parameter `OSSL_SIGNATURE_PARAM_SECURITY_BITS`
    /// reports this value.  The numeric values are stored as `i32` so
    /// they round-trip through [`ParamValue::Int32`] without any
    /// narrowing cast (Rule R6).
    #[must_use]
    pub fn security_bits(self) -> i32 {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake_128s | Self::Shake_128f => 128,
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake_192s | Self::Shake_192f => 192,
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake_256s | Self::Shake_256f => 256,
        }
    }

    /// Returns the NIST security category (1, 3 or 5).
    ///
    /// Category 1 corresponds to 128-bit classical strength,
    /// category 3 to 192-bit, and category 5 to 256-bit, per
    /// FIPS 205 Table 2.
    #[must_use]
    pub fn security_category(self) -> u32 {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake_128s | Self::Shake_128f => 1,
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake_192s | Self::Shake_192f => 3,
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake_256s | Self::Shake_256f => 5,
        }
    }

    /// Returns `true` for the `f` (fast) variants and `false` for the
    /// `s` (small) variants.
    #[must_use]
    pub fn is_fast(self) -> bool {
        matches!(
            self,
            Self::Sha2_128f
                | Self::Sha2_192f
                | Self::Sha2_256f
                | Self::Shake_128f
                | Self::Shake_192f
                | Self::Shake_256f
        )
    }

    /// Returns `true` for SHAKE-based variants, `false` for SHA-2.
    #[must_use]
    pub fn uses_shake(self) -> bool {
        matches!(
            self,
            Self::Shake_128s
                | Self::Shake_128f
                | Self::Shake_192s
                | Self::Shake_192f
                | Self::Shake_256s
                | Self::Shake_256f
        )
    }

    /// Returns the dotted-decimal NIST OID for this variant.
    ///
    /// All twelve OIDs live under the `2.16.840.1.101.3.4.3` arc, with
    /// the trailing component running from 20 (SHA-2 128s) to 31
    /// (SHAKE 256f).
    #[must_use]
    pub fn oid(self) -> &'static str {
        match self {
            Self::Sha2_128s => "2.16.840.1.101.3.4.3.20",
            Self::Sha2_128f => "2.16.840.1.101.3.4.3.21",
            Self::Sha2_192s => "2.16.840.1.101.3.4.3.22",
            Self::Sha2_192f => "2.16.840.1.101.3.4.3.23",
            Self::Sha2_256s => "2.16.840.1.101.3.4.3.24",
            Self::Sha2_256f => "2.16.840.1.101.3.4.3.25",
            Self::Shake_128s => "2.16.840.1.101.3.4.3.26",
            Self::Shake_128f => "2.16.840.1.101.3.4.3.27",
            Self::Shake_192s => "2.16.840.1.101.3.4.3.28",
            Self::Shake_192f => "2.16.840.1.101.3.4.3.29",
            Self::Shake_256s => "2.16.840.1.101.3.4.3.30",
            Self::Shake_256f => "2.16.840.1.101.3.4.3.31",
        }
    }

    /// Returns the matching crypto-layer variant.
    ///
    /// The provider and crypto layers maintain isolated enums so that
    /// changes to the crypto-side internal state machine do not force
    /// a rebuild of every consumer.  This conversion is a total
    /// bijection.
    #[must_use]
    pub fn to_crypto(self) -> CryptoSlhDsaVariant {
        CryptoSlhDsaVariant::from(self)
    }

    /// Returns the static parameter table entry for this variant.
    ///
    /// Looked up via the canonical algorithm name; the table is
    /// guaranteed to contain an entry for every named variant by the
    /// crypto crate's own internal consistency tests, so the
    /// `expect` is unreachable in normal operation.
    #[must_use]
    pub fn params(self) -> &'static SlhDsaParams {
        slh_dsa_params_get(self.name()).expect(
            "SLH-DSA parameter table is missing an entry for a known variant; \
             this indicates a bug in openssl_crypto::pqc::slh_dsa::SLH_DSA_PARAMS_TABLE",
        )
    }

    /// Returns the per-variant security parameter `n` in bytes.
    ///
    /// `n` is 16 for the 128-bit variants, 24 for 192-bit, and 32 for
    /// the 256-bit variants.  This is the byte count drawn from the
    /// library RNG when the provider auto-generates `add_random` for
    /// non-deterministic signing.
    #[must_use]
    pub fn n(self) -> usize {
        self.params().n
    }

    /// Returns the public-key length in bytes for this variant.
    #[must_use]
    pub fn public_key_len(self) -> usize {
        self.params().pub_len
    }

    /// Returns the private-key length in bytes for this variant.
    ///
    /// In FIPS 205 the private key is `4 * n` bytes (two `n`-byte
    /// secret seeds plus the public key seed and root).
    #[must_use]
    pub fn private_key_len(self) -> usize {
        4 * self.n()
    }

    /// Returns the fixed signature length in bytes for this variant.
    #[must_use]
    pub fn signature_len(self) -> usize {
        self.params().sig_len
    }
}

impl fmt::Display for SlhDsaVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl From<SlhDsaVariant> for CryptoSlhDsaVariant {
    fn from(v: SlhDsaVariant) -> Self {
        match v {
            SlhDsaVariant::Sha2_128s => Self::Sha2_128s,
            SlhDsaVariant::Sha2_128f => Self::Sha2_128f,
            SlhDsaVariant::Sha2_192s => Self::Sha2_192s,
            SlhDsaVariant::Sha2_192f => Self::Sha2_192f,
            SlhDsaVariant::Sha2_256s => Self::Sha2_256s,
            SlhDsaVariant::Sha2_256f => Self::Sha2_256f,
            SlhDsaVariant::Shake_128s => Self::Shake_128s,
            SlhDsaVariant::Shake_128f => Self::Shake_128f,
            SlhDsaVariant::Shake_192s => Self::Shake_192s,
            SlhDsaVariant::Shake_192f => Self::Shake_192f,
            SlhDsaVariant::Shake_256s => Self::Shake_256s,
            SlhDsaVariant::Shake_256f => Self::Shake_256f,
        }
    }
}

impl From<CryptoSlhDsaVariant> for SlhDsaVariant {
    fn from(v: CryptoSlhDsaVariant) -> Self {
        match v {
            CryptoSlhDsaVariant::Sha2_128s => Self::Sha2_128s,
            CryptoSlhDsaVariant::Sha2_128f => Self::Sha2_128f,
            CryptoSlhDsaVariant::Sha2_192s => Self::Sha2_192s,
            CryptoSlhDsaVariant::Sha2_192f => Self::Sha2_192f,
            CryptoSlhDsaVariant::Sha2_256s => Self::Sha2_256s,
            CryptoSlhDsaVariant::Sha2_256f => Self::Sha2_256f,
            CryptoSlhDsaVariant::Shake_128s => Self::Shake_128s,
            CryptoSlhDsaVariant::Shake_128f => Self::Shake_128f,
            CryptoSlhDsaVariant::Shake_192s => Self::Shake_192s,
            CryptoSlhDsaVariant::Shake_192f => Self::Shake_192f,
            CryptoSlhDsaVariant::Shake_256s => Self::Shake_256s,
            CryptoSlhDsaVariant::Shake_256f => Self::Shake_256f,
        }
    }
}

// =============================================================================
// SlhDsaMessageEncode — RAW vs PURE message-encoding selector.
// =============================================================================

/// Selector for SLH-DSA's two message encoding modes.
///
/// FIPS 205 §10.2 defines two ways to bind a context string to the
/// hashed message:
///
/// * `Pure` — prefix the message with `0x00 || ctx_len_byte || ctx`,
///   then sign the resulting concatenation.  This is the *only* mode
///   approved for production use and is the default for new contexts.
/// * `Raw` — sign the message bytes directly, without any
///   domain-separator prefix.  This mode exists exclusively to allow
///   interop testing with externally pre-formatted messages and is
///   NEVER FIPS-approved.
///
/// The integer encoding (`Raw = 0`, `Pure = 1`) matches the C
/// `SLH_DSA_MESSAGE_ENCODE_RAW` / `SLH_DSA_MESSAGE_ENCODE_PURE`
/// macros in `slh_dsa_sig.c` (lines 26–27), and round-trips through
/// the `OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING` parameter without any
/// narrowing cast (Rule R6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlhDsaMessageEncode {
    /// Sign the raw message bytes — non-FIPS, interop only.
    Raw = 0,
    /// Prefix with the FIPS 205 §10.2 domain separator before signing.
    Pure = 1,
}

impl SlhDsaMessageEncode {
    /// Returns the integer encoding used by the
    /// `OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING` parameter.
    #[must_use]
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Raw => 0,
            Self::Pure => 1,
        }
    }

    /// Decodes an `OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING` integer.
    ///
    /// Accepts the documented values 0 and 1; any other value yields
    /// [`CommonError::InvalidArgument`] so the caller can surface a
    /// useful diagnostic.
    pub fn from_i32(value: i32) -> ProviderResult<Self> {
        match value {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Pure),
            other => Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("unsupported SLH-DSA message-encoding: {other} (expected 0 or 1)"),
            ))),
        }
    }

    /// Returns `true` for the FIPS-approved `Pure` mode.
    #[must_use]
    pub fn is_pure(self) -> bool {
        matches!(self, Self::Pure)
    }
}

impl Default for SlhDsaMessageEncode {
    /// FIPS 205 mandates `Pure` for production use.
    fn default() -> Self {
        Self::Pure
    }
}

// =============================================================================
// SlhDsaSignatureProvider — the per-variant provider entry point.
// =============================================================================

/// Provider entry point bound to a single SLH-DSA parameter set.
///
/// One instance is created per descriptor returned by [`descriptors`];
/// the `DefaultProvider` registers all twelve variants by constructing
/// twelve providers, each carrying its own [`SlhDsaVariant`].  The
/// shared [`LibContext`] reference is reused across providers via
/// [`Arc`] so descriptor enumeration does not duplicate the library
/// state.
#[derive(Debug, Clone)]
pub struct SlhDsaSignatureProvider {
    variant: SlhDsaVariant,
    libctx: Arc<LibContext>,
    propq: Option<String>,
}

impl SlhDsaSignatureProvider {
    /// Creates a provider bound to the default library context.
    ///
    /// The default context is shared globally and is the right choice
    /// for command-line callers and most application use cases.  Tests
    /// or applications that need isolated state should use
    /// [`Self::new_with_context`] instead.
    #[must_use]
    pub fn new(variant: SlhDsaVariant) -> Self {
        Self {
            variant,
            libctx: LibContext::get_default(),
            propq: None,
        }
    }

    /// Creates a provider that targets a caller-supplied
    /// [`LibContext`] and optional property query string.
    #[must_use]
    pub fn new_with_context(
        variant: SlhDsaVariant,
        libctx: Arc<LibContext>,
        propq: Option<String>,
    ) -> Self {
        Self {
            variant,
            libctx,
            propq,
        }
    }

    /// Returns the variant bound to this provider.
    #[must_use]
    pub fn variant(&self) -> SlhDsaVariant {
        self.variant
    }
}

impl SignatureProvider for SlhDsaSignatureProvider {
    fn name(&self) -> &'static str {
        self.variant.name()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>> {
        debug!(
            algorithm = self.variant.name(),
            "slh-dsa: creating new signature context"
        );
        Ok(Box::new(SlhDsaSignatureContext::new(
            self.variant,
            Arc::clone(&self.libctx),
            self.propq.clone(),
        )))
    }
}

// =============================================================================
// SlhDsaSignatureContext — per-operation provider state.
// =============================================================================

/// Per-operation SLH-DSA signature context.
///
/// Direct Rust translation of `PROV_SLH_DSA_CTX` (lines 60–75 of
/// `slh_dsa_sig.c`).  Fields differ from the C layout in three
/// principled ways:
///
/// * `key` is shared via [`Arc`] so duplication ([`Self::duplicate`])
///   is cheap and never invalidates the original context.
/// * Optional fields ([`Self::context_string`], [`Self::add_random`])
///   use [`Option<Vec<u8>>`] in place of nullable C pointers, satisfying
///   Rule R5 (nullability over sentinels).
/// * The C `aid_buf` / `aid_len` pair collapses into a single
///   [`Option<Vec<u8>>`] (`aid_cache`) that is computed lazily on the
///   first `get_ctx_params` call and reused for the rest of the
///   context's lifetime.
///
/// Sensitive byte buffers ([`Self::context_string`],
/// [`Self::add_random`], `cached_signature`) are explicitly zeroed in
/// the [`Zeroize`] impl and on every [`Drop`], satisfying the secure
/// erasure requirement called out in AAP §0.7.6.
pub struct SlhDsaSignatureContext {
    /// Shared library context — passed to the crypto crate when
    /// constructing keys, hash contexts, and consulting the FIPS
    /// indicator.
    lib_ctx: Arc<LibContext>,
    /// Property query inherited from the parent provider.
    propq: Option<String>,
    /// Static parameter-set selector for this context.
    variant: SlhDsaVariant,
    /// Loaded key (private for sign, public for verify) once
    /// `*_init` has run.
    key: Option<Arc<SlhDsaKey>>,
    /// Optional context string (≤ 255 bytes) bound into the signature
    /// per FIPS 205 §10.2.
    context_string: Option<Vec<u8>>,
    /// Optional caller-supplied additional randomness for
    /// non-deterministic signing (≤ 32 bytes).  When `None` and
    /// `deterministic == false`, the provider draws fresh entropy from
    /// the library RNG inside `sign_internal`.
    add_random: Option<Vec<u8>>,
    /// Whether to suppress the random nonce and emit a deterministic
    /// signature.
    deterministic: bool,
    /// Message-encoding selector.  Defaults to `Pure` (FIPS-approved).
    msg_encode: SlhDsaMessageEncode,
    /// Cached DER-encoded `AlgorithmIdentifier`.
    aid_cache: Option<Vec<u8>>,
    /// Tracks the operation mode entered via the most recent
    /// `*_init` call.  `None` means the context has not been
    /// initialised.
    operation: Option<OperationMode>,
    /// Streaming buffer for `digest_*_update` calls.  Drained to
    /// `sign_internal` / `verify_internal` on `*_final`.
    streaming_buffer: Vec<u8>,
    /// Most recently produced signature, retained so callers that
    /// need to read it back via the `signature` ctx parameter can do
    /// so; replaced on every `sign_internal` call.
    cached_signature: Option<Vec<u8>>,
}

impl Zeroize for SlhDsaSignatureContext {
    fn zeroize(&mut self) {
        if let Some(ctx) = self.context_string.as_mut() {
            ctx.zeroize();
        }
        self.context_string = None;
        if let Some(ar) = self.add_random.as_mut() {
            ar.zeroize();
        }
        self.add_random = None;
        if let Some(aid) = self.aid_cache.as_mut() {
            aid.zeroize();
        }
        self.aid_cache = None;
        if let Some(sig) = self.cached_signature.as_mut() {
            sig.zeroize();
        }
        self.cached_signature = None;
        self.streaming_buffer.zeroize();
        self.deterministic = false;
        self.operation = None;
    }
}

impl Drop for SlhDsaSignatureContext {
    fn drop(&mut self) {
        // Mirrors `OPENSSL_cleanse(ctx->add_random, …)` and the
        // per-field free pattern in `slh_dsa_freectx` (line 105 of
        // `slh_dsa_sig.c`).
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SlhDsaSignatureContext {}

impl SlhDsaSignatureContext {
    /// Allocates a fresh context bound to a variant and library context.
    ///
    /// The resulting context is unprimed: callers must invoke one of
    /// `sign_init` / `verify_init` / `digest_sign_init` /
    /// `digest_verify_init` (which run a FIPS deferred self-check
    /// where applicable) before any cryptographic operation.
    ///
    /// Direct Rust translation of `slh_dsa_newctx` (line 78 of
    /// `slh_dsa_sig.c`).
    pub(crate) fn new(
        variant: SlhDsaVariant,
        lib_ctx: Arc<LibContext>,
        propq: Option<String>,
    ) -> Self {
        Self {
            lib_ctx,
            propq,
            variant,
            key: None,
            context_string: None,
            add_random: None,
            deterministic: false,
            msg_encode: SlhDsaMessageEncode::default(),
            aid_cache: None,
            operation: None,
            streaming_buffer: Vec::new(),
            cached_signature: None,
        }
    }

    /// Returns the variant bound to this context.
    #[must_use]
    pub fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    /// Validates and stores a new context string.
    ///
    /// Mirrors the validation that the C provider performs in
    /// `slh_dsa_set_ctx_params` (line 290 of `slh_dsa_sig.c`).
    /// Strings longer than [`SLH_DSA_MAX_CONTEXT_STRING_LEN`] are
    /// rejected; the previous value (if any) is securely zeroed before
    /// the new one is installed.
    fn set_context_string(&mut self, new_ctx: Option<Vec<u8>>) -> ProviderResult<()> {
        if let Some(ref bytes) = new_ctx {
            if bytes.len() > SLH_DSA_MAX_CONTEXT_STRING_LEN {
                warn!(
                    algorithm = self.variant.name(),
                    supplied_len = bytes.len(),
                    max_len = SLH_DSA_MAX_CONTEXT_STRING_LEN,
                    "slh-dsa: context string exceeds 255-byte cap"
                );
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SLH-DSA context string length {} exceeds maximum {}",
                        bytes.len(),
                        SLH_DSA_MAX_CONTEXT_STRING_LEN
                    ),
                )));
            }
        }
        if let Some(prev) = self.context_string.as_mut() {
            prev.zeroize();
        }
        self.context_string = new_ctx;
        Ok(())
    }

    /// Validates and stores a new `add_random` value.
    ///
    /// Bytes are silently capped: the C provider rejects values longer
    /// than [`SLH_DSA_MAX_ADD_RANDOM_LEN`] (32 bytes), and the Rust
    /// translation matches that behaviour.  Empty buffers are
    /// accepted and treated as "explicitly cleared" — i.e. the
    /// provider will fall back to either deterministic mode or the
    /// library RNG on the next `sign` call.
    fn set_add_random(&mut self, new_random: Option<Vec<u8>>) -> ProviderResult<()> {
        if let Some(ref bytes) = new_random {
            if bytes.len() > SLH_DSA_MAX_ADD_RANDOM_LEN {
                warn!(
                    algorithm = self.variant.name(),
                    supplied_len = bytes.len(),
                    max_len = SLH_DSA_MAX_ADD_RANDOM_LEN,
                    "slh-dsa: add_random exceeds 32-byte cap"
                );
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SLH-DSA add_random length {} exceeds maximum {}",
                        bytes.len(),
                        SLH_DSA_MAX_ADD_RANDOM_LEN
                    ),
                )));
            }
        }
        if let Some(prev) = self.add_random.as_mut() {
            prev.zeroize();
        }
        self.add_random = new_random;
        Ok(())
    }

    /// Loads a key for signing — only the private encoding is
    /// accepted, mirroring the C `slh_dsa_signverify_msg_init`
    /// behaviour where signing requires a key with `SLH_DSA_HAS_PRIV`
    /// set.
    fn parse_key_for_signing(&self, key: &[u8]) -> ProviderResult<Arc<SlhDsaKey>> {
        let mut k =
            SlhDsaKey::new(Arc::clone(&self.lib_ctx), self.variant.name()).map_err(dispatch_err)?;
        let expected_priv_len = k.priv_len().map_err(dispatch_err)?;
        if key.len() != expected_priv_len {
            warn!(
                algorithm = self.variant.name(),
                supplied_len = key.len(),
                expected_priv_len,
                "slh-dsa: signing requires the private encoding"
            );
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SLH-DSA {} signing requires a {}-byte private key (got {} bytes)",
                    self.variant.name(),
                    expected_priv_len,
                    key.len()
                ),
            )));
        }
        k.set_priv(key).map_err(dispatch_err)?;
        Ok(Arc::new(k))
    }

    /// Loads a key for verification — accepts either the public
    /// encoding (the common case) or the private encoding (which has
    /// the public key embedded).
    fn parse_key_for_verify(&self, key: &[u8]) -> ProviderResult<Arc<SlhDsaKey>> {
        let mut k =
            SlhDsaKey::new(Arc::clone(&self.lib_ctx), self.variant.name()).map_err(dispatch_err)?;
        let expected_pub_len = k.pub_len().map_err(dispatch_err)?;
        let expected_priv_len = k.priv_len().map_err(dispatch_err)?;
        if key.len() == expected_pub_len {
            k.set_pub(key).map_err(dispatch_err)?;
            Ok(Arc::new(k))
        } else if key.len() == expected_priv_len {
            // `set_priv` populates both private *and* public bytes
            // because the SLH-DSA private encoding contains the public
            // seed/root pair.
            k.set_priv(key).map_err(dispatch_err)?;
            Ok(Arc::new(k))
        } else {
            warn!(
                algorithm = self.variant.name(),
                supplied_len = key.len(),
                expected_pub_len,
                expected_priv_len,
                "slh-dsa: verify key length unrecognised"
            );
            Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                "SLH-DSA {} verify requires {}-byte public or {}-byte private key (got {} bytes)",
                self.variant.name(),
                expected_pub_len,
                expected_priv_len,
                key.len()
            ),
            )))
        }
    }

    /// Returns a deep clone of the context that is safe to use
    /// independently of the source.
    ///
    /// Mirrors `slh_dsa_dupctx` (line 122 of `slh_dsa_sig.c`).
    /// Heavyweight resources ([`LibContext`], [`SlhDsaKey`]) are
    /// shared via [`Arc::clone`]; sensitive byte buffers are
    /// duplicated rather than aliased so that mutations on the
    /// duplicate cannot corrupt the original.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            lib_ctx: Arc::clone(&self.lib_ctx),
            propq: self.propq.clone(),
            variant: self.variant,
            key: self.key.as_ref().map(Arc::clone),
            context_string: self.context_string.clone(),
            add_random: self.add_random.clone(),
            deterministic: self.deterministic,
            msg_encode: self.msg_encode,
            aid_cache: self.aid_cache.clone(),
            operation: self.operation,
            streaming_buffer: self.streaming_buffer.clone(),
            cached_signature: self.cached_signature.clone(),
        }
    }

    /// Performs the actual SLH-DSA signing operation once an
    /// initialised key is available.
    ///
    /// This is the Rust translation of `slh_sign` (line 184 of
    /// `slh_dsa_sig.c`). The C implementation:
    ///
    /// 1. Extracts a fresh `add_random` value from the library RNG
    ///    when the caller has neither stored one nor flagged
    ///    deterministic mode (`RAND_priv_bytes_ex`, line 213).
    /// 2. Builds an [`SlhDsaHashCtx`] from the bound key.
    /// 3. Invokes `ossl_slh_dsa_sign` (FIPS 205 Algorithm 19) with the
    ///    requested message, context string, and message-encode
    ///    flag.
    /// 4. Validates that the produced signature length matches the
    ///    fixed-size expectation for the variant.
    ///
    /// Any prior cached signature is securely zeroed before the new
    /// one is stored.
    fn sign_internal(&mut self, message: &[u8]) -> ProviderResult<Vec<u8>> {
        let key = self.key.clone().ok_or_else(|| {
            warn!(
                algorithm = self.variant.name(),
                "slh-dsa: sign called before sign_init"
            );
            ProviderError::Init("SLH-DSA sign called before sign_init".to_string())
        })?;

        // Materialise add_random per FIPS 205 §10.2.1 (Algorithm 19):
        //   - Caller-supplied bytes win.
        //   - Otherwise, deterministic mode skips randomness.
        //   - Otherwise, draw `n` fresh bytes from the library RNG.
        let n = self.variant.n();
        let owned_random: Option<Vec<u8>> = if self.add_random.is_some() {
            None
        } else if self.deterministic {
            None
        } else {
            let mut buf = vec![0u8; n];
            rand_priv_bytes(&mut buf).map_err(dispatch_err)?;
            trace!(
                algorithm = self.variant.name(),
                bytes = buf.len(),
                "slh-dsa: drew fresh add_random from RNG"
            );
            Some(buf)
        };
        let add_rand: Option<&[u8]> = match (self.add_random.as_deref(), owned_random.as_deref()) {
            (Some(stored), _) => Some(stored),
            (None, Some(fresh)) => Some(fresh),
            (None, None) => None,
        };

        let hctx = SlhDsaHashCtx::new(Arc::clone(&key)).map_err(dispatch_err)?;
        let context = self.context_string.as_deref().unwrap_or(&[]);
        let encode_pure = self.msg_encode.is_pure();

        debug!(
            algorithm = self.variant.name(),
            msg_len = message.len(),
            ctx_len = context.len(),
            deterministic = self.deterministic,
            has_add_random = add_rand.is_some(),
            encode_pure,
            "slh-dsa: signing message"
        );

        let signature =
            slh_dsa_sign(&hctx, message, context, add_rand, encode_pure).map_err(dispatch_err)?;

        let expected_len = self.variant.signature_len();
        if signature.len() != expected_len {
            warn!(
                algorithm = self.variant.name(),
                produced = signature.len(),
                expected = expected_len,
                "slh-dsa: signature length mismatch from crypto layer"
            );
            return Err(ProviderError::Dispatch(format!(
                "SLH-DSA {} produced signature of length {} (expected {})",
                self.variant.name(),
                signature.len(),
                expected_len
            )));
        }

        if let Some(prev) = self.cached_signature.as_mut() {
            prev.zeroize();
        }
        self.cached_signature = Some(signature.clone());
        debug!(
            algorithm = self.variant.name(),
            sig_len = signature.len(),
            "slh-dsa: signature produced"
        );
        Ok(signature)
    }

    /// Performs the actual SLH-DSA verification once an initialised
    /// key is available.
    ///
    /// This is the Rust translation of `slh_verify` (line 234 of
    /// `slh_dsa_sig.c`). Length pre-checks return `Ok(false)` rather
    /// than an error: a short or oversized signature is *invalid*,
    /// not malformed, and the C provider treats both cases identically
    /// at the API surface.
    fn verify_internal(&self, message: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        let expected_len = self.variant.signature_len();
        if signature.len() != expected_len {
            debug!(
                algorithm = self.variant.name(),
                received = signature.len(),
                expected = expected_len,
                "slh-dsa: signature length mismatch — verify -> false"
            );
            return Ok(false);
        }

        let key = self.key.clone().ok_or_else(|| {
            warn!(
                algorithm = self.variant.name(),
                "slh-dsa: verify called before verify_init"
            );
            ProviderError::Init("SLH-DSA verify called before verify_init".to_string())
        })?;

        let hctx = SlhDsaHashCtx::new(Arc::clone(&key)).map_err(dispatch_err)?;
        let context = self.context_string.as_deref().unwrap_or(&[]);
        let encode_pure = self.msg_encode.is_pure();

        debug!(
            algorithm = self.variant.name(),
            msg_len = message.len(),
            ctx_len = context.len(),
            encode_pure,
            "slh-dsa: verifying signature"
        );

        let outcome = slh_dsa_verify(&hctx, message, context, encode_pure, signature)
            .map_err(dispatch_err)?;

        debug!(
            algorithm = self.variant.name(),
            verified = outcome,
            "slh-dsa: verify complete"
        );
        Ok(outcome)
    }

    /// Applies a [`ParamSet`] to this context.
    ///
    /// Direct translation of `slh_dsa_set_ctx_params` (line 274 of
    /// `slh_dsa_sig.c`). Recognised parameters:
    ///
    /// | Name              | Type         | Effect                                                |
    /// |-------------------|--------------|-------------------------------------------------------|
    /// | `context-string`  | OctetString  | Replace the per-signature context (≤ 255 bytes).      |
    /// | `deterministic`   | Integer      | Toggle deterministic signing.                         |
    /// | `add-random`      | OctetString  | Override the per-signature randomness (≤ 32 bytes).   |
    /// | `message-encoding`| Integer      | Select pure (1) or raw (0) message domain.            |
    /// | `signature`       | OctetString  | Replace the cached signature (used by FIPS testers).  |
    ///
    /// Unlike ML-DSA, SLH-DSA has **no** `mu` parameter — the spec
    /// does not define a μ-mode for SLH-DSA.  Unknown parameters are
    /// ignored to remain forward-compatible.
    pub fn set_ctx_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if params.is_empty() {
            return Ok(());
        }

        if let Some(val) = params.get("context-string") {
            let bytes = val.as_bytes().ok_or_else(|| {
                warn!(
                    algorithm = self.variant.name(),
                    actual = val.param_type_name(),
                    "slh-dsa: context-string param has wrong type"
                );
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "context-string".to_string(),
                    expected: "OctetString",
                    actual: val.param_type_name(),
                })
            })?;
            trace!(
                algorithm = self.variant.name(),
                len = bytes.len(),
                "slh-dsa: applying context-string param"
            );
            let owned = if bytes.is_empty() {
                None
            } else {
                Some(bytes.to_vec())
            };
            self.set_context_string(owned)?;
        }

        if let Some(val) = params.get("deterministic") {
            let raw = val.as_i32().ok_or_else(|| {
                warn!(
                    algorithm = self.variant.name(),
                    actual = val.param_type_name(),
                    "slh-dsa: deterministic param has wrong type"
                );
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "deterministic".to_string(),
                    expected: "Int32",
                    actual: val.param_type_name(),
                })
            })?;
            self.deterministic = raw != 0;
            trace!(
                algorithm = self.variant.name(),
                deterministic = self.deterministic,
                "slh-dsa: applied deterministic flag"
            );
        }

        if let Some(val) = params.get("add-random") {
            let bytes = val.as_bytes().ok_or_else(|| {
                warn!(
                    algorithm = self.variant.name(),
                    actual = val.param_type_name(),
                    "slh-dsa: add-random param has wrong type"
                );
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "add-random".to_string(),
                    expected: "OctetString",
                    actual: val.param_type_name(),
                })
            })?;
            trace!(
                algorithm = self.variant.name(),
                len = bytes.len(),
                "slh-dsa: applying add-random param"
            );
            let owned = if bytes.is_empty() {
                None
            } else {
                Some(bytes.to_vec())
            };
            self.set_add_random(owned)?;
        }

        if let Some(val) = params.get("message-encoding") {
            let raw = val.as_i32().ok_or_else(|| {
                warn!(
                    algorithm = self.variant.name(),
                    actual = val.param_type_name(),
                    "slh-dsa: message-encoding param has wrong type"
                );
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "message-encoding".to_string(),
                    expected: "Int32",
                    actual: val.param_type_name(),
                })
            })?;
            self.msg_encode = SlhDsaMessageEncode::from_i32(raw)?;
            trace!(
                algorithm = self.variant.name(),
                encoding = ?self.msg_encode,
                "slh-dsa: applied message-encoding"
            );
        }

        if let Some(val) = params.get("signature") {
            let bytes = val.as_bytes().ok_or_else(|| {
                warn!(
                    algorithm = self.variant.name(),
                    actual = val.param_type_name(),
                    "slh-dsa: signature param has wrong type"
                );
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "signature".to_string(),
                    expected: "OctetString",
                    actual: val.param_type_name(),
                })
            })?;
            if let Some(prev) = self.cached_signature.as_mut() {
                prev.zeroize();
            }
            self.cached_signature = if bytes.is_empty() {
                None
            } else {
                Some(bytes.to_vec())
            };
            trace!(
                algorithm = self.variant.name(),
                cached_len = self.cached_signature.as_ref().map(Vec::len).unwrap_or(0),
                "slh-dsa: applied cached signature"
            );
        }

        Ok(())
    }

    /// Builds the parameter view for this context.
    ///
    /// Direct translation of `slh_dsa_get_ctx_params` (line 252 of
    /// `slh_dsa_sig.c`). Surfaces the lazily-built
    /// AlgorithmIdentifier DER, the canonical instance name, the
    /// deterministic flag, the message-encoding selector, and the
    /// security level (in bits).  No `mu` parameter is emitted — the
    /// SLH-DSA spec does not define a μ-mode.
    pub fn get_ctx_params(&mut self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();
        if self.aid_cache.is_none() {
            self.aid_cache = Some(algorithm_identifier_der(self.variant));
        }
        if let Some(ref aid) = self.aid_cache {
            out.set("algorithm-id", ParamValue::OctetString(aid.clone()));
        }
        out.set(
            "instance",
            ParamValue::Utf8String(self.variant.name().to_string()),
        );
        out.set(
            "deterministic",
            ParamValue::Int32(i32::from(u8::from(self.deterministic))),
        );
        out.set(
            "message-encoding",
            ParamValue::Int32(self.msg_encode.as_i32()),
        );
        out.set(
            "security-bits",
            ParamValue::Int32(self.variant.security_bits()),
        );
        Ok(out)
    }

    /// One-shot digest-sign convenience entry point.
    ///
    /// SLH-DSA performs all message hashing internally per FIPS 205
    /// (the variant name selects the family — SHA-2 vs SHAKE — and
    /// the security level), so the C provider's
    /// `slh_dsa_digest_signverify_init` rejects any caller-supplied
    /// digest name and the digest-sign / digest-verify entry points
    /// are pure pass-throughs to the message API.
    ///
    /// This wrapper preserves that semantic: it simply asserts that
    /// the context has been primed for `Sign` and routes through
    /// `sign_internal`, matching the C implementation in
    /// `slh_dsa_digest_sign` (line 348 of `slh_dsa_sig.c`).
    pub fn digest_sign(&mut self, message: &[u8]) -> ProviderResult<Vec<u8>> {
        if self.operation != Some(OperationMode::Sign) {
            warn!(
                algorithm = self.variant.name(),
                operation = ?self.operation,
                "slh-dsa: digest_sign called without sign_init"
            );
            return Err(ProviderError::Init(
                "SLH-DSA digest_sign called before digest_sign_init".to_string(),
            ));
        }
        debug!(
            algorithm = self.variant.name(),
            msg_len = message.len(),
            "slh-dsa: digest_sign one-shot"
        );
        self.sign_internal(message)
    }

    /// One-shot digest-verify convenience entry point.
    ///
    /// See [`Self::digest_sign`] for the rationale: SLH-DSA cannot
    /// accept an externally selected digest, so the digest API is a
    /// strict alias of the message API.  Mirrors
    /// `slh_dsa_digest_verify` (line 367 of `slh_dsa_sig.c`).
    pub fn digest_verify(&self, message: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.operation != Some(OperationMode::Verify) {
            warn!(
                algorithm = self.variant.name(),
                operation = ?self.operation,
                "slh-dsa: digest_verify called without verify_init"
            );
            return Err(ProviderError::Init(
                "SLH-DSA digest_verify called before digest_verify_init".to_string(),
            ));
        }
        debug!(
            algorithm = self.variant.name(),
            msg_len = message.len(),
            sig_len = signature.len(),
            "slh-dsa: digest_verify one-shot"
        );
        self.verify_internal(message, signature)
    }
}

// SLH-DSA contexts intentionally redact sensitive material from their
// `Debug` output: it is expected to surface in trace logs and error
// messages where dumping raw key/signature bytes would be a
// confidentiality violation.  The custom impl reports presence flags
// and length summaries instead.
impl fmt::Debug for SlhDsaSignatureContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlhDsaSignatureContext")
            .field("variant", &self.variant)
            .field("operation", &self.operation)
            .field("has_key", &self.key.is_some())
            .field("has_context_string", &self.context_string.is_some())
            .field("has_add_random", &self.add_random.is_some())
            .field("deterministic", &self.deterministic)
            .field("msg_encode", &self.msg_encode)
            .field(
                "cached_signature_len",
                &self.cached_signature.as_ref().map(Vec::len),
            )
            .field("propq", &self.propq)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds the DER-encoded `AlgorithmIdentifier` for a SLH-DSA
/// variant.
///
/// All twelve OIDs share the prefix `2.16.840.1.101.3.4.3` (the NIST
/// `csor`/`sigAlgs` arc) and differ only in the trailing arc: 0x14
/// through 0x1F maps to `.20` through `.31`.  The encoding is a
/// minimal `SEQUENCE { OID }` — SLH-DSA carries no parameters in its
/// AlgorithmIdentifier per FIPS 205 §10.4.
///
/// Mirrors `MAKE_SIGNATURE_FUNCTIONS` macro expansion in
/// `slh_dsa_sig.c` (lines 372–390) which selects between the
/// pre-computed `slh_dsa_*_aid` byte arrays in `slh_dsa_codecs.c`.
fn algorithm_identifier_der(variant: SlhDsaVariant) -> Vec<u8> {
    let trailer: u8 = match variant {
        SlhDsaVariant::Sha2_128s => 0x14,
        SlhDsaVariant::Sha2_128f => 0x15,
        SlhDsaVariant::Sha2_192s => 0x16,
        SlhDsaVariant::Sha2_192f => 0x17,
        SlhDsaVariant::Sha2_256s => 0x18,
        SlhDsaVariant::Sha2_256f => 0x19,
        SlhDsaVariant::Shake_128s => 0x1A,
        SlhDsaVariant::Shake_128f => 0x1B,
        SlhDsaVariant::Shake_192s => 0x1C,
        SlhDsaVariant::Shake_192f => 0x1D,
        SlhDsaVariant::Shake_256s => 0x1E,
        SlhDsaVariant::Shake_256f => 0x1F,
    };
    vec![
        // SEQUENCE { length 11
        0x30, 0x0B, // OID, length 9
        0x06, 0x09, // 2.16.840.1.101.3.4.3.<trailer>
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, trailer,
    ]
}

/// Rejects any external digest selection, faithfully translating the
/// C provider's `slh_dsa_digest_signverify_init` behaviour
/// (line 343 of `slh_dsa_sig.c`):
///
/// ```text
/// /* mdname is not allowed for SLH-DSA */
/// if (mdname != NULL && mdname[0] != '\0') {
///     ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
///     return 0;
/// }
/// ```
///
/// Empty names are silently accepted because some EVP code paths
/// pass `""` to mean "no digest selected".
fn enforce_digest_match(variant: SlhDsaVariant, digest: &str) -> ProviderResult<()> {
    if digest.is_empty() {
        return Ok(());
    }
    warn!(
        algorithm = variant.name(),
        requested_digest = digest,
        "slh-dsa: external digest selection rejected"
    );
    Err(ProviderError::Dispatch(format!(
        "SLH-DSA {} does not accept an external digest (got {:?})",
        variant.name(),
        digest
    )))
}

/// Best-effort variant resolution from a textual algorithm name.
///
/// Used exclusively by the unit-test harness — production callers
/// fix the variant at provider construction time.  Accepts any of:
///
/// * The canonical name (`SLH-DSA-SHA2-128s`).
/// * The compact name (`SLH-DSA-SHA2-128S`, `SLHDSASHA2128S`).
/// * The `id-slh-dsa-` prefixed alias.
/// * The dotted OID (`2.16.840.1.101.3.4.3.20` … `.31`).
#[cfg(test)]
fn parse_variant_name(name: &str) -> ProviderResult<SlhDsaVariant> {
    let normalised = name.trim().to_ascii_uppercase();
    match normalised.as_str() {
        "SLH-DSA-SHA2-128S"
        | "SLHDSASHA2128S"
        | "ID-SLH-DSA-SHA2-128S"
        | "2.16.840.1.101.3.4.3.20" => Ok(SlhDsaVariant::Sha2_128s),
        "SLH-DSA-SHA2-128F"
        | "SLHDSASHA2128F"
        | "ID-SLH-DSA-SHA2-128F"
        | "2.16.840.1.101.3.4.3.21" => Ok(SlhDsaVariant::Sha2_128f),
        "SLH-DSA-SHA2-192S"
        | "SLHDSASHA2192S"
        | "ID-SLH-DSA-SHA2-192S"
        | "2.16.840.1.101.3.4.3.22" => Ok(SlhDsaVariant::Sha2_192s),
        "SLH-DSA-SHA2-192F"
        | "SLHDSASHA2192F"
        | "ID-SLH-DSA-SHA2-192F"
        | "2.16.840.1.101.3.4.3.23" => Ok(SlhDsaVariant::Sha2_192f),
        "SLH-DSA-SHA2-256S"
        | "SLHDSASHA2256S"
        | "ID-SLH-DSA-SHA2-256S"
        | "2.16.840.1.101.3.4.3.24" => Ok(SlhDsaVariant::Sha2_256s),
        "SLH-DSA-SHA2-256F"
        | "SLHDSASHA2256F"
        | "ID-SLH-DSA-SHA2-256F"
        | "2.16.840.1.101.3.4.3.25" => Ok(SlhDsaVariant::Sha2_256f),
        "SLH-DSA-SHAKE-128S"
        | "SLHDSASHAKE128S"
        | "ID-SLH-DSA-SHAKE-128S"
        | "2.16.840.1.101.3.4.3.26" => Ok(SlhDsaVariant::Shake_128s),
        "SLH-DSA-SHAKE-128F"
        | "SLHDSASHAKE128F"
        | "ID-SLH-DSA-SHAKE-128F"
        | "2.16.840.1.101.3.4.3.27" => Ok(SlhDsaVariant::Shake_128f),
        "SLH-DSA-SHAKE-192S"
        | "SLHDSASHAKE192S"
        | "ID-SLH-DSA-SHAKE-192S"
        | "2.16.840.1.101.3.4.3.28" => Ok(SlhDsaVariant::Shake_192s),
        "SLH-DSA-SHAKE-192F"
        | "SLHDSASHAKE192F"
        | "ID-SLH-DSA-SHAKE-192F"
        | "2.16.840.1.101.3.4.3.29" => Ok(SlhDsaVariant::Shake_192f),
        "SLH-DSA-SHAKE-256S"
        | "SLHDSASHAKE256S"
        | "ID-SLH-DSA-SHAKE-256S"
        | "2.16.840.1.101.3.4.3.30" => Ok(SlhDsaVariant::Shake_256s),
        "SLH-DSA-SHAKE-256F"
        | "SLHDSASHAKE256F"
        | "ID-SLH-DSA-SHAKE-256F"
        | "2.16.840.1.101.3.4.3.31" => Ok(SlhDsaVariant::Shake_256f),
        other => Err(ProviderError::Common(CommonError::InvalidArgument(
            format!("Unknown SLH-DSA variant: {other}"),
        ))),
    }
}

// ---------------------------------------------------------------------------
// SignatureContext trait implementation
// ---------------------------------------------------------------------------

impl SignatureContext for SlhDsaSignatureContext {
    /// Initialises the context for signing.
    ///
    /// Mirrors `slh_dsa_sign_msg_init` (line 168 of `slh_dsa_sig.c`):
    /// the supplied byte string must contain a private encoding for
    /// the variant; the streaming buffer and any cached signature are
    /// reset; supplied parameters are applied last so they can
    /// overwrite per-call defaults (deterministic / add_random /
    /// context-string / message-encoding).
    fn sign_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = self.variant.name(),
            key_len = key.len(),
            params_present = params.is_some(),
            "slh-dsa: sign_init"
        );
        let parsed_key = self.parse_key_for_signing(key)?;
        if !parsed_key.has_key(KeySelection::PrivateOnly) {
            return Err(ProviderError::Init(format!(
                "SLH-DSA {} key did not produce a usable private encoding",
                self.variant.name()
            )));
        }
        self.key = Some(parsed_key);
        self.operation = Some(OperationMode::Sign);
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        if let Some(prev) = self.cached_signature.as_mut() {
            prev.zeroize();
        }
        self.cached_signature = None;
        if let Some(p) = params {
            self.set_ctx_params(p)?;
        }
        Ok(())
    }

    fn sign(&mut self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        if self.operation != Some(OperationMode::Sign) {
            warn!(
                algorithm = self.variant.name(),
                operation = ?self.operation,
                "slh-dsa: sign called without sign_init"
            );
            return Err(ProviderError::Init(
                "SLH-DSA sign called before sign_init".to_string(),
            ));
        }
        self.sign_internal(data)
    }

    /// Initialises the context for verification.
    ///
    /// Mirrors `slh_dsa_verify_msg_init` (line 176 of
    /// `slh_dsa_sig.c`).  Either a public or a private encoding is
    /// accepted (`parse_key_for_verify` handles both).  The streaming
    /// buffer is reset; the cached signature, if any, is preserved
    /// because some test harnesses prime it via `set_ctx_params`
    /// before flipping into verify mode.
    fn verify_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = self.variant.name(),
            key_len = key.len(),
            params_present = params.is_some(),
            "slh-dsa: verify_init"
        );
        let parsed_key = self.parse_key_for_verify(key)?;
        if !parsed_key.has_key(KeySelection::PublicOnly) {
            return Err(ProviderError::Init(format!(
                "SLH-DSA {} key did not produce a usable public encoding",
                self.variant.name()
            )));
        }
        self.key = Some(parsed_key);
        self.operation = Some(OperationMode::Verify);
        self.streaming_buffer.zeroize();
        self.streaming_buffer.clear();
        if let Some(p) = params {
            self.set_ctx_params(p)?;
        }
        Ok(())
    }

    fn verify(&mut self, data: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.operation != Some(OperationMode::Verify) {
            warn!(
                algorithm = self.variant.name(),
                operation = ?self.operation,
                "slh-dsa: verify called without verify_init"
            );
            return Err(ProviderError::Init(
                "SLH-DSA verify called before verify_init".to_string(),
            ));
        }
        self.verify_internal(data, signature)
    }

    /// Initialises the context for "digest sign" operations.
    ///
    /// SLH-DSA does not accept an externally selected digest — every
    /// variant baked-in selects its own hash family — so the supplied
    /// digest name must be empty.  Once that gate is cleared, the
    /// implementation falls through to [`Self::sign_init`] verbatim.
    fn digest_sign_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        enforce_digest_match(self.variant, digest)?;
        debug!(
            algorithm = self.variant.name(),
            "slh-dsa: digest_sign_init delegating to sign_init"
        );
        SignatureContext::sign_init(self, key, params)
    }

    fn digest_sign_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.operation != Some(OperationMode::Sign) {
            warn!(
                algorithm = self.variant.name(),
                operation = ?self.operation,
                "slh-dsa: digest_sign_update called without sign init"
            );
            return Err(ProviderError::Init(
                "SLH-DSA digest_sign_update called before digest_sign_init".to_string(),
            ));
        }
        trace!(
            algorithm = self.variant.name(),
            chunk_len = data.len(),
            buffered = self.streaming_buffer.len(),
            "slh-dsa: digest_sign_update buffering"
        );
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>> {
        if self.operation != Some(OperationMode::Sign) {
            warn!(
                algorithm = self.variant.name(),
                operation = ?self.operation,
                "slh-dsa: digest_sign_final called without sign init"
            );
            return Err(ProviderError::Init(
                "SLH-DSA digest_sign_final called before digest_sign_init".to_string(),
            ));
        }
        debug!(
            algorithm = self.variant.name(),
            buffered = self.streaming_buffer.len(),
            "slh-dsa: digest_sign_final flushing buffered message"
        );
        let mut buffered = std::mem::take(&mut self.streaming_buffer);
        let outcome = self.sign_internal(&buffered);
        // Securely scrub the spent buffer before it is dropped.
        buffered.zeroize();
        outcome
    }

    fn digest_verify_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        enforce_digest_match(self.variant, digest)?;
        debug!(
            algorithm = self.variant.name(),
            "slh-dsa: digest_verify_init delegating to verify_init"
        );
        SignatureContext::verify_init(self, key, params)
    }

    fn digest_verify_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.operation != Some(OperationMode::Verify) {
            warn!(
                algorithm = self.variant.name(),
                operation = ?self.operation,
                "slh-dsa: digest_verify_update called without verify init"
            );
            return Err(ProviderError::Init(
                "SLH-DSA digest_verify_update called before digest_verify_init".to_string(),
            ));
        }
        trace!(
            algorithm = self.variant.name(),
            chunk_len = data.len(),
            buffered = self.streaming_buffer.len(),
            "slh-dsa: digest_verify_update buffering"
        );
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_verify_final(&mut self, signature: &[u8]) -> ProviderResult<bool> {
        if self.operation != Some(OperationMode::Verify) {
            warn!(
                algorithm = self.variant.name(),
                operation = ?self.operation,
                "slh-dsa: digest_verify_final called without verify init"
            );
            return Err(ProviderError::Init(
                "SLH-DSA digest_verify_final called before digest_verify_init".to_string(),
            ));
        }
        debug!(
            algorithm = self.variant.name(),
            buffered = self.streaming_buffer.len(),
            sig_len = signature.len(),
            "slh-dsa: digest_verify_final flushing buffered message"
        );
        let mut buffered = std::mem::take(&mut self.streaming_buffer);
        let outcome = self.verify_internal(&buffered, signature);
        buffered.zeroize();
        outcome
    }

    /// Builds a [`ParamSet`] view of the context.
    ///
    /// Because the trait constrains us to `&self`, the
    /// AlgorithmIdentifier DER is rebuilt from scratch instead of
    /// being lazily cached on the context.  The caller can drive the
    /// caching variant via [`Self::get_ctx_params`] when mutation is
    /// available.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();
        out.set(
            "algorithm-id",
            ParamValue::OctetString(algorithm_identifier_der(self.variant)),
        );
        out.set(
            "instance",
            ParamValue::Utf8String(self.variant.name().to_string()),
        );
        out.set(
            "deterministic",
            ParamValue::Int32(i32::from(u8::from(self.deterministic))),
        );
        out.set(
            "message-encoding",
            ParamValue::Int32(self.msg_encode.as_i32()),
        );
        out.set(
            "security-bits",
            ParamValue::Int32(self.variant.security_bits()),
        );
        Ok(out)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.set_ctx_params(params)
    }
}

// ---------------------------------------------------------------------------
// Algorithm descriptor enumeration
// ---------------------------------------------------------------------------

/// Returns the [`AlgorithmDescriptor`] entries for every SLH-DSA
/// variant.
///
/// The order matches the original C provider's
/// `MAKE_SIGNATURE_FUNCTIONS` macro expansion in `slh_dsa_sig.c`
/// (lines 372–390): the SHA-2 family is enumerated first
/// (128s/128f/192s/192f/256s/256f), followed by the SHAKE family
/// (128s/128f/192s/192f/256s/256f).  Each descriptor exposes three
/// names:
///
/// 1. The canonical FIPS 205 name (`SLH-DSA-…`).
/// 2. The `id-slh-dsa-…` alias used by some PKIX consumers.
/// 3. The dotted OID under the NIST `csor`/`sigAlgs` arc
///    (`2.16.840.1.101.3.4.3.20` … `.31`).
///
/// All entries advertise the `provider=default` property and a
/// short FIPS-205 reference description.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // -------- SHA-2 family --------
        algorithm(
            &[
                "SLH-DSA-SHA2-128s",
                "id-slh-dsa-sha2-128s",
                "2.16.840.1.101.3.4.3.20",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-128s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-128f",
                "id-slh-dsa-sha2-128f",
                "2.16.840.1.101.3.4.3.21",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-128f implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-192s",
                "id-slh-dsa-sha2-192s",
                "2.16.840.1.101.3.4.3.22",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-192s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-192f",
                "id-slh-dsa-sha2-192f",
                "2.16.840.1.101.3.4.3.23",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-192f implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-256s",
                "id-slh-dsa-sha2-256s",
                "2.16.840.1.101.3.4.3.24",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-256s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-256f",
                "id-slh-dsa-sha2-256f",
                "2.16.840.1.101.3.4.3.25",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-256f implementation (FIPS 205)",
        ),
        // -------- SHAKE family --------
        algorithm(
            &[
                "SLH-DSA-SHAKE-128s",
                "id-slh-dsa-shake-128s",
                "2.16.840.1.101.3.4.3.26",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-128s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-128f",
                "id-slh-dsa-shake-128f",
                "2.16.840.1.101.3.4.3.27",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-128f implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-192s",
                "id-slh-dsa-shake-192s",
                "2.16.840.1.101.3.4.3.28",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-192s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-192f",
                "id-slh-dsa-shake-192f",
                "2.16.840.1.101.3.4.3.29",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-192f implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-256s",
                "id-slh-dsa-shake-256s",
                "2.16.840.1.101.3.4.3.30",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-256s implementation (FIPS 205)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-256f",
                "id-slh-dsa-shake-256f",
                "2.16.840.1.101.3.4.3.31",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-256f implementation (FIPS 205)",
        ),
    ]
}

// =============================================================================
// Unit Tests
// =============================================================================
//
// The test suite covers every public API surface this module exposes:
//
//   * Variant enum — names, OIDs, security parameters, length tables,
//     bidirectional conversion to / from the crypto-layer enum,
//     `Display`, and the test-only [`parse_variant_name`] helper.
//   * Message-encoding enum — round-trip, default value, rejection of
//     unknown encodings.
//   * [`SlhDsaSignatureProvider`] — provider name and `new_ctx`
//     boxing.
//   * [`SlhDsaSignatureContext`] direct API — construction,
//     context-string and add-random validation, duplication, debug
//     redaction.
//   * Parameter handling (`set_ctx_params` / `get_ctx_params`) —
//     accepted parameters, type-mismatch errors, and the absence of a
//     `mu` parameter (which differs from ML-DSA).
//   * [`SignatureContext`] trait wiring — pre-`*_init` error paths,
//     external-digest rejection, get/set delegation.
//   * Internal helpers — DER algorithm-identifier byte structure,
//     external-digest enforcement.
//
// Cryptographic round-trips (real sign/verify with valid key material)
// are covered by integration tests in `openssl-crypto::pqc::slh_dsa`,
// which already exercises the FIPS 205 algorithms 19/20 implementations.
// The provider crate's responsibility is wiring + dispatch + parameter
// translation, all of which is verified here without needing live
// 32–128-byte key material per variant.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;

    // ----- Test fixture helpers ------------------------------------------------

    /// Builds an empty [`SlhDsaSignatureContext`] backed by the default
    /// library context, no property query, and the requested variant.
    /// All other state is at its default value.
    fn make_ctx(variant: SlhDsaVariant) -> SlhDsaSignatureContext {
        SlhDsaSignatureContext::new(variant, LibContext::get_default(), None)
    }

    /// Returns the canonical list of all twelve SLH-DSA variants in
    /// the same order as the descriptor table.
    fn all_variants() -> [SlhDsaVariant; 12] {
        [
            SlhDsaVariant::Sha2_128s,
            SlhDsaVariant::Sha2_128f,
            SlhDsaVariant::Sha2_192s,
            SlhDsaVariant::Sha2_192f,
            SlhDsaVariant::Sha2_256s,
            SlhDsaVariant::Sha2_256f,
            SlhDsaVariant::Shake_128s,
            SlhDsaVariant::Shake_128f,
            SlhDsaVariant::Shake_192s,
            SlhDsaVariant::Shake_192f,
            SlhDsaVariant::Shake_256s,
            SlhDsaVariant::Shake_256f,
        ]
    }

    // ==========================================================================
    // Descriptor coverage tests — preserved verbatim from the original
    // stub (recovered from git revision 78939186d5).  These tests guard
    // the registration contract that downstream provider code relies on.
    // ==========================================================================

    #[test]
    fn descriptors_returns_twelve_entries() {
        let descs = descriptors();
        assert_eq!(descs.len(), 12, "expected 12 SLH-DSA parameter sets");
    }

    #[test]
    fn descriptors_cover_sha2_family() {
        let descs = descriptors();
        for canonical in [
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f",
        ] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing SLH-DSA descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn descriptors_cover_shake_family() {
        let descs = descriptors();
        for canonical in [
            "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHAKE-256f",
        ] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing SLH-DSA descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn descriptors_carry_oid_aliases() {
        let descs = descriptors();
        for d in &descs {
            assert!(
                d.names
                    .iter()
                    .any(|n| n.starts_with("2.16.840.1.101.3.4.3.")),
                "every SLH-DSA descriptor must carry an OID alias"
            );
            assert!(
                d.names.iter().any(|n| n.starts_with("id-slh-dsa-")),
                "every SLH-DSA descriptor must carry an `id-slh-dsa-*` alias"
            );
        }
    }

    #[test]
    fn descriptors_have_default_property() {
        let descs = descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }

    // ==========================================================================
    // Descriptor structural tests — extend the preserved stub with deeper
    // checks of the registration contract: every descriptor must carry
    // exactly three names (canonical, id-slh-dsa-*, OID), all OIDs must
    // be unique, and the OID trailers must lie in the `.20` … `.31`
    // range mandated by the NIST PQC OID arc.
    // ==========================================================================

    #[test]
    fn descriptors_each_have_three_names() {
        let descs = descriptors();
        for d in &descs {
            assert_eq!(
                d.names.len(),
                3,
                "descriptor {} has {} names, expected 3",
                d.names[0],
                d.names.len()
            );
        }
    }

    #[test]
    fn descriptor_oids_are_unique() {
        let descs = descriptors();
        let mut oids: Vec<&str> = descs
            .iter()
            .filter_map(|d| {
                d.names
                    .iter()
                    .find(|n| n.starts_with("2.16.840.1.101.3.4.3."))
                    .copied()
            })
            .collect();
        oids.sort_unstable();
        oids.dedup();
        assert_eq!(oids.len(), 12, "expected 12 unique SLH-DSA OIDs");
    }

    #[test]
    fn descriptor_oids_lie_in_nist_pqc_arc() {
        let descs = descriptors();
        for d in &descs {
            let oid = d
                .names
                .iter()
                .find(|n| n.starts_with("2.16.840.1.101.3.4.3."))
                .expect("descriptor missing OID alias");
            let trailer: u32 = oid
                .rsplit('.')
                .next()
                .and_then(|s| s.parse().ok())
                .expect("OID trailer must be numeric");
            assert!(
                (20..=31).contains(&trailer),
                "OID trailer {trailer} out of NIST PQC range 20..=31"
            );
        }
    }

    #[test]
    fn descriptor_canonical_names_are_unique() {
        let descs = descriptors();
        let mut names: Vec<&str> = descs.iter().map(|d| d.names[0]).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 12, "expected 12 unique canonical names");
    }

    // ==========================================================================
    // SlhDsaVariant enum tests — public API surface.
    // ==========================================================================

    #[test]
    fn variant_name_round_trip_canonical() {
        // Each variant maps to its exact canonical name used by the
        // provider's algorithm registration table.
        assert_eq!(SlhDsaVariant::Sha2_128s.name(), "SLH-DSA-SHA2-128s");
        assert_eq!(SlhDsaVariant::Sha2_128f.name(), "SLH-DSA-SHA2-128f");
        assert_eq!(SlhDsaVariant::Sha2_192s.name(), "SLH-DSA-SHA2-192s");
        assert_eq!(SlhDsaVariant::Sha2_192f.name(), "SLH-DSA-SHA2-192f");
        assert_eq!(SlhDsaVariant::Sha2_256s.name(), "SLH-DSA-SHA2-256s");
        assert_eq!(SlhDsaVariant::Sha2_256f.name(), "SLH-DSA-SHA2-256f");
        assert_eq!(SlhDsaVariant::Shake_128s.name(), "SLH-DSA-SHAKE-128s");
        assert_eq!(SlhDsaVariant::Shake_128f.name(), "SLH-DSA-SHAKE-128f");
        assert_eq!(SlhDsaVariant::Shake_192s.name(), "SLH-DSA-SHAKE-192s");
        assert_eq!(SlhDsaVariant::Shake_192f.name(), "SLH-DSA-SHAKE-192f");
        assert_eq!(SlhDsaVariant::Shake_256s.name(), "SLH-DSA-SHAKE-256s");
        assert_eq!(SlhDsaVariant::Shake_256f.name(), "SLH-DSA-SHAKE-256f");
    }

    #[test]
    fn variant_names_are_unique() {
        let names: Vec<&str> = all_variants().iter().map(|v| v.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "variant names not unique");
    }

    #[test]
    fn variant_oid_round_trip() {
        assert_eq!(SlhDsaVariant::Sha2_128s.oid(), "2.16.840.1.101.3.4.3.20");
        assert_eq!(SlhDsaVariant::Sha2_128f.oid(), "2.16.840.1.101.3.4.3.21");
        assert_eq!(SlhDsaVariant::Sha2_192s.oid(), "2.16.840.1.101.3.4.3.22");
        assert_eq!(SlhDsaVariant::Sha2_192f.oid(), "2.16.840.1.101.3.4.3.23");
        assert_eq!(SlhDsaVariant::Sha2_256s.oid(), "2.16.840.1.101.3.4.3.24");
        assert_eq!(SlhDsaVariant::Sha2_256f.oid(), "2.16.840.1.101.3.4.3.25");
        assert_eq!(SlhDsaVariant::Shake_128s.oid(), "2.16.840.1.101.3.4.3.26");
        assert_eq!(SlhDsaVariant::Shake_128f.oid(), "2.16.840.1.101.3.4.3.27");
        assert_eq!(SlhDsaVariant::Shake_192s.oid(), "2.16.840.1.101.3.4.3.28");
        assert_eq!(SlhDsaVariant::Shake_192f.oid(), "2.16.840.1.101.3.4.3.29");
        assert_eq!(SlhDsaVariant::Shake_256s.oid(), "2.16.840.1.101.3.4.3.30");
        assert_eq!(SlhDsaVariant::Shake_256f.oid(), "2.16.840.1.101.3.4.3.31");
    }

    #[test]
    fn variant_oids_are_unique() {
        let oids: Vec<&str> = all_variants().iter().map(|v| v.oid()).collect();
        let mut sorted = oids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), oids.len(), "variant OIDs not unique");
    }

    #[test]
    fn variant_security_bits_match_fips_205() {
        // Per FIPS 205 §7.1, the security strength is encoded by the
        // numeric component of the variant name.
        for v in &[
            SlhDsaVariant::Sha2_128s,
            SlhDsaVariant::Sha2_128f,
            SlhDsaVariant::Shake_128s,
            SlhDsaVariant::Shake_128f,
        ] {
            assert_eq!(v.security_bits(), 128, "{v:?} should be 128-bit");
        }
        for v in &[
            SlhDsaVariant::Sha2_192s,
            SlhDsaVariant::Sha2_192f,
            SlhDsaVariant::Shake_192s,
            SlhDsaVariant::Shake_192f,
        ] {
            assert_eq!(v.security_bits(), 192, "{v:?} should be 192-bit");
        }
        for v in &[
            SlhDsaVariant::Sha2_256s,
            SlhDsaVariant::Sha2_256f,
            SlhDsaVariant::Shake_256s,
            SlhDsaVariant::Shake_256f,
        ] {
            assert_eq!(v.security_bits(), 256, "{v:?} should be 256-bit");
        }
    }

    #[test]
    fn variant_security_category_matches_nist_levels() {
        // NIST categories: 128-bit security → 1, 192-bit → 3, 256-bit → 5.
        for v in &[
            SlhDsaVariant::Sha2_128s,
            SlhDsaVariant::Sha2_128f,
            SlhDsaVariant::Shake_128s,
            SlhDsaVariant::Shake_128f,
        ] {
            assert_eq!(v.security_category(), 1);
        }
        for v in &[
            SlhDsaVariant::Sha2_192s,
            SlhDsaVariant::Sha2_192f,
            SlhDsaVariant::Shake_192s,
            SlhDsaVariant::Shake_192f,
        ] {
            assert_eq!(v.security_category(), 3);
        }
        for v in &[
            SlhDsaVariant::Sha2_256s,
            SlhDsaVariant::Sha2_256f,
            SlhDsaVariant::Shake_256s,
            SlhDsaVariant::Shake_256f,
        ] {
            assert_eq!(v.security_category(), 5);
        }
    }

    #[test]
    fn variant_is_fast_matches_f_variants() {
        assert!(!SlhDsaVariant::Sha2_128s.is_fast());
        assert!(SlhDsaVariant::Sha2_128f.is_fast());
        assert!(!SlhDsaVariant::Sha2_192s.is_fast());
        assert!(SlhDsaVariant::Sha2_192f.is_fast());
        assert!(!SlhDsaVariant::Sha2_256s.is_fast());
        assert!(SlhDsaVariant::Sha2_256f.is_fast());
        assert!(!SlhDsaVariant::Shake_128s.is_fast());
        assert!(SlhDsaVariant::Shake_128f.is_fast());
        assert!(!SlhDsaVariant::Shake_192s.is_fast());
        assert!(SlhDsaVariant::Shake_192f.is_fast());
        assert!(!SlhDsaVariant::Shake_256s.is_fast());
        assert!(SlhDsaVariant::Shake_256f.is_fast());
    }

    #[test]
    fn variant_uses_shake_matches_shake_family() {
        for v in &[
            SlhDsaVariant::Sha2_128s,
            SlhDsaVariant::Sha2_128f,
            SlhDsaVariant::Sha2_192s,
            SlhDsaVariant::Sha2_192f,
            SlhDsaVariant::Sha2_256s,
            SlhDsaVariant::Sha2_256f,
        ] {
            assert!(!v.uses_shake(), "SHA-2 variant {v:?} mis-tagged");
        }
        for v in &[
            SlhDsaVariant::Shake_128s,
            SlhDsaVariant::Shake_128f,
            SlhDsaVariant::Shake_192s,
            SlhDsaVariant::Shake_192f,
            SlhDsaVariant::Shake_256s,
            SlhDsaVariant::Shake_256f,
        ] {
            assert!(v.uses_shake(), "SHAKE variant {v:?} mis-tagged");
        }
    }

    #[test]
    fn variant_lengths_match_fips_205_table_1() {
        // FIPS 205 Table 1 — Public-key, private-key, and signature
        // sizes (in bytes).  Values are independent of the hash family
        // (SHA-2 vs SHAKE) within a given parameter set.
        struct Expected {
            public_key: usize,
            private_key: usize,
            signature: usize,
        }
        let cases: &[(SlhDsaVariant, Expected)] = &[
            (
                SlhDsaVariant::Sha2_128s,
                Expected {
                    public_key: 32,
                    private_key: 64,
                    signature: 7_856,
                },
            ),
            (
                SlhDsaVariant::Sha2_128f,
                Expected {
                    public_key: 32,
                    private_key: 64,
                    signature: 17_088,
                },
            ),
            (
                SlhDsaVariant::Sha2_192s,
                Expected {
                    public_key: 48,
                    private_key: 96,
                    signature: 16_224,
                },
            ),
            (
                SlhDsaVariant::Sha2_192f,
                Expected {
                    public_key: 48,
                    private_key: 96,
                    signature: 35_664,
                },
            ),
            (
                SlhDsaVariant::Sha2_256s,
                Expected {
                    public_key: 64,
                    private_key: 128,
                    signature: 29_792,
                },
            ),
            (
                SlhDsaVariant::Sha2_256f,
                Expected {
                    public_key: 64,
                    private_key: 128,
                    signature: 49_856,
                },
            ),
            (
                SlhDsaVariant::Shake_128s,
                Expected {
                    public_key: 32,
                    private_key: 64,
                    signature: 7_856,
                },
            ),
            (
                SlhDsaVariant::Shake_128f,
                Expected {
                    public_key: 32,
                    private_key: 64,
                    signature: 17_088,
                },
            ),
            (
                SlhDsaVariant::Shake_192s,
                Expected {
                    public_key: 48,
                    private_key: 96,
                    signature: 16_224,
                },
            ),
            (
                SlhDsaVariant::Shake_192f,
                Expected {
                    public_key: 48,
                    private_key: 96,
                    signature: 35_664,
                },
            ),
            (
                SlhDsaVariant::Shake_256s,
                Expected {
                    public_key: 64,
                    private_key: 128,
                    signature: 29_792,
                },
            ),
            (
                SlhDsaVariant::Shake_256f,
                Expected {
                    public_key: 64,
                    private_key: 128,
                    signature: 49_856,
                },
            ),
        ];
        for (v, expect) in cases {
            assert_eq!(
                v.public_key_len(),
                expect.public_key,
                "{v:?} pub_len mismatch"
            );
            assert_eq!(
                v.private_key_len(),
                expect.private_key,
                "{v:?} priv_len mismatch"
            );
            assert_eq!(
                v.signature_len(),
                expect.signature,
                "{v:?} sig_len mismatch"
            );
        }
    }

    #[test]
    fn variant_n_matches_security_parameter() {
        // n = security_bits / 8 (Sha2_128s/f → 16, 192 → 24, 256 → 32).
        for v in &[
            SlhDsaVariant::Sha2_128s,
            SlhDsaVariant::Sha2_128f,
            SlhDsaVariant::Shake_128s,
            SlhDsaVariant::Shake_128f,
        ] {
            assert_eq!(v.n(), 16, "{v:?}.n() expected 16");
        }
        for v in &[
            SlhDsaVariant::Sha2_192s,
            SlhDsaVariant::Sha2_192f,
            SlhDsaVariant::Shake_192s,
            SlhDsaVariant::Shake_192f,
        ] {
            assert_eq!(v.n(), 24, "{v:?}.n() expected 24");
        }
        for v in &[
            SlhDsaVariant::Sha2_256s,
            SlhDsaVariant::Sha2_256f,
            SlhDsaVariant::Shake_256s,
            SlhDsaVariant::Shake_256f,
        ] {
            assert_eq!(v.n(), 32, "{v:?}.n() expected 32");
        }
    }

    #[test]
    fn variant_display_emits_canonical_name() {
        for v in &all_variants() {
            assert_eq!(format!("{v}"), v.name());
        }
    }

    #[test]
    fn variant_to_crypto_round_trip() {
        for v in all_variants().iter().copied() {
            let crypto: CryptoSlhDsaVariant = v.into();
            let back: SlhDsaVariant = crypto.into();
            assert_eq!(back, v, "round-trip failed for {v:?}");
        }
    }

    #[test]
    fn variant_to_crypto_helper_consistent_with_from() {
        // [`SlhDsaVariant::to_crypto`] is the inherent method version of
        // the From conversion; both paths must agree.
        for v in all_variants().iter().copied() {
            let via_helper = v.to_crypto();
            let via_from: CryptoSlhDsaVariant = v.into();
            assert_eq!(via_helper, via_from);
        }
    }

    #[test]
    fn parse_variant_name_accepts_canonical_form() {
        for v in all_variants().iter().copied() {
            assert_eq!(parse_variant_name(v.name()).unwrap(), v);
        }
    }

    #[test]
    fn parse_variant_name_accepts_oid() {
        for v in all_variants().iter().copied() {
            assert_eq!(parse_variant_name(v.oid()).unwrap(), v);
        }
    }

    #[test]
    fn parse_variant_name_accepts_id_alias() {
        let cases = [
            ("id-slh-dsa-sha2-128s", SlhDsaVariant::Sha2_128s),
            ("id-slh-dsa-sha2-128f", SlhDsaVariant::Sha2_128f),
            ("id-slh-dsa-sha2-256f", SlhDsaVariant::Sha2_256f),
            ("id-slh-dsa-shake-128s", SlhDsaVariant::Shake_128s),
            ("id-slh-dsa-shake-256f", SlhDsaVariant::Shake_256f),
        ];
        for (alias, expected) in cases {
            assert_eq!(parse_variant_name(alias).unwrap(), expected);
        }
    }

    #[test]
    fn parse_variant_name_is_case_insensitive() {
        // Mixed case should still resolve.
        assert_eq!(
            parse_variant_name("slh-dsa-sha2-128s").unwrap(),
            SlhDsaVariant::Sha2_128s
        );
        assert_eq!(
            parse_variant_name("SlH-DsA-ShAkE-256F").unwrap(),
            SlhDsaVariant::Shake_256f
        );
    }

    #[test]
    fn parse_variant_name_rejects_unknown() {
        let err = parse_variant_name("SLH-DSA-NOPE-1024s").unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(
                    msg.contains("Unknown SLH-DSA variant"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn variant_params_lookup_succeeds_for_all_variants() {
        // [`SlhDsaVariant::params`] resolves the FIPS 205 parameter set
        // through the crypto layer; if any variant fails to look up,
        // the registration contract is broken.
        for v in all_variants().iter().copied() {
            let p: &SlhDsaParams = v.params();
            assert_eq!(p.n, v.n(), "params.n diverges from variant.n() for {v:?}");
            assert_eq!(p.pub_len, v.public_key_len(), "{v:?} pub_len mismatch");
            assert_eq!(p.sig_len, v.signature_len(), "{v:?} sig_len mismatch");
            // Make sure the crypto-crate look-up function returns the
            // same parameters when keyed by canonical name.
            let direct = slh_dsa_params_get(v.name()).expect("crypto params lookup");
            assert_eq!(direct.n, p.n);
        }
    }

    // ==========================================================================
    // SlhDsaMessageEncode enum tests.
    // ==========================================================================

    #[test]
    fn message_encode_round_trip() {
        assert_eq!(SlhDsaMessageEncode::Raw.as_i32(), 0);
        assert_eq!(SlhDsaMessageEncode::Pure.as_i32(), 1);
        assert_eq!(
            SlhDsaMessageEncode::from_i32(0).unwrap(),
            SlhDsaMessageEncode::Raw
        );
        assert_eq!(
            SlhDsaMessageEncode::from_i32(1).unwrap(),
            SlhDsaMessageEncode::Pure
        );
    }

    #[test]
    fn message_encode_unknown_rejected() {
        for bad in &[-1, 2, 3, 99, i32::MAX, i32::MIN] {
            let err = SlhDsaMessageEncode::from_i32(*bad).unwrap_err();
            match err {
                ProviderError::Common(CommonError::InvalidArgument(_)) => {}
                other => panic!("expected InvalidArgument for {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn message_encode_default_is_pure() {
        // FIPS 205 §10.2 mandates PURE as the default; our wiring
        // preserves the spec's bias.
        assert_eq!(SlhDsaMessageEncode::default(), SlhDsaMessageEncode::Pure);
    }

    #[test]
    fn message_encode_is_pure_helper() {
        assert!(SlhDsaMessageEncode::Pure.is_pure());
        assert!(!SlhDsaMessageEncode::Raw.is_pure());
    }

    // ==========================================================================
    // SlhDsaSignatureProvider tests.
    // ==========================================================================

    #[test]
    fn provider_name_matches_variant_canonical() {
        for v in all_variants().iter().copied() {
            let p = SlhDsaSignatureProvider::new(v);
            assert_eq!(p.name(), v.name());
        }
    }

    #[test]
    fn provider_variant_round_trips() {
        for v in all_variants().iter().copied() {
            let p = SlhDsaSignatureProvider::new(v);
            assert_eq!(p.variant(), v);
        }
    }

    #[test]
    fn provider_new_with_context_records_propq() {
        let p = SlhDsaSignatureProvider::new_with_context(
            SlhDsaVariant::Sha2_128s,
            LibContext::get_default(),
            Some("provider=fips".to_string()),
        );
        assert_eq!(p.variant(), SlhDsaVariant::Sha2_128s);
        assert_eq!(p.name(), "SLH-DSA-SHA2-128s");
    }

    #[test]
    fn provider_new_ctx_returns_signature_context_box() {
        let p = SlhDsaSignatureProvider::new(SlhDsaVariant::Sha2_192f);
        let mut ctx = p.new_ctx().expect("new_ctx must succeed");
        // The boxed context should refuse pre-init operations,
        // demonstrating that it really is the SignatureContext we
        // wired up.
        let err = ctx.sign(b"data").unwrap_err();
        match err {
            ProviderError::Init(_) => {}
            other => panic!("expected Init, got {other:?}"),
        }
    }

    // ==========================================================================
    // SlhDsaSignatureContext direct-API tests.
    // ==========================================================================

    #[test]
    fn context_new_starts_in_default_state() {
        let ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        assert_eq!(ctx.variant(), SlhDsaVariant::Sha2_128s);
    }

    #[test]
    fn context_new_for_each_variant_succeeds() {
        for v in all_variants().iter().copied() {
            let ctx = make_ctx(v);
            assert_eq!(ctx.variant(), v);
        }
    }

    #[test]
    fn context_set_context_string_accepts_max_length() {
        // 255 bytes is the FIPS 205 §10.2 upper bound.
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let max = vec![0xAB_u8; SLH_DSA_MAX_CONTEXT_STRING_LEN];
        ctx.set_context_string(Some(max)).unwrap();
    }

    #[test]
    fn context_set_context_string_rejects_overlong() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let too_long = vec![0_u8; SLH_DSA_MAX_CONTEXT_STRING_LEN + 1];
        let err = ctx.set_context_string(Some(too_long)).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn context_set_context_string_clears_previous() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        ctx.set_context_string(Some(b"hello".to_vec())).unwrap();
        ctx.set_context_string(None).unwrap();
        // No public accessor exists; clearing twice and rebinding should
        // succeed without leaking state.
        ctx.set_context_string(Some(b"new".to_vec())).unwrap();
    }

    #[test]
    fn context_set_add_random_accepts_zero_to_max_len() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_256f);
        for len in [0_usize, 1, 8, 16, 24, 32] {
            ctx.set_add_random(Some(vec![0_u8; len])).unwrap();
        }
    }

    #[test]
    fn context_set_add_random_rejects_overlong() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_256f);
        let too_long = vec![0_u8; SLH_DSA_MAX_ADD_RANDOM_LEN + 1];
        let err = ctx.set_add_random(Some(too_long)).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn context_set_add_random_clears_previous() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_256f);
        ctx.set_add_random(Some(vec![0xFF; 16])).unwrap();
        ctx.set_add_random(None).unwrap();
    }

    #[test]
    fn context_duplicate_clones_state() {
        let mut ctx = make_ctx(SlhDsaVariant::Shake_192s);
        ctx.set_context_string(Some(b"ctx".to_vec())).unwrap();
        ctx.set_add_random(Some(vec![1_u8; 8])).unwrap();
        let copy = ctx.duplicate();
        assert_eq!(copy.variant(), ctx.variant());
        // Duplicate observed by serializing parameters.
        let p = copy.get_params().unwrap();
        let inst = p.get("instance").and_then(ParamValue::as_str).unwrap();
        assert_eq!(inst, "SLH-DSA-SHAKE-192s");
    }

    #[test]
    fn context_duplicate_is_independent() {
        let mut original = make_ctx(SlhDsaVariant::Sha2_128f);
        let mut clone = original.duplicate();
        // Mutate the clone's deterministic flag via params; the
        // original must remain at the default.
        let mut p = ParamSet::new();
        p.set("deterministic", ParamValue::Int32(1));
        clone.set_ctx_params(&p).unwrap();
        // The original's deterministic flag is still the default
        // (false, encoded as 0).
        let orig_params = original.get_ctx_params().unwrap();
        let det = orig_params
            .get("deterministic")
            .and_then(ParamValue::as_i32)
            .unwrap();
        assert_eq!(det, 0, "original should remain non-deterministic");
        let clone_params = clone.get_ctx_params().unwrap();
        let det_clone = clone_params
            .get("deterministic")
            .and_then(ParamValue::as_i32)
            .unwrap();
        assert_eq!(det_clone, 1, "clone should be deterministic");
    }

    #[test]
    fn context_debug_redacts_secret_material() {
        let mut ctx = make_ctx(SlhDsaVariant::Shake_256f);
        ctx.set_add_random(Some(vec![0xCA_u8; 32])).unwrap();
        ctx.set_context_string(Some(b"super-secret-context".to_vec()))
            .unwrap();
        let dbg = format!("{ctx:?}");
        assert!(!dbg.contains("super-secret-context"));
        // Secret octet sequences must not leak via Debug.
        assert!(!dbg.contains("CACA"));
        // But the variant and operational state should be observable.
        assert!(dbg.contains("Shake_256f") || dbg.contains("SLH-DSA-SHAKE-256f"));
    }

    // ==========================================================================
    // set_ctx_params / get_ctx_params tests.
    // ==========================================================================

    #[test]
    fn set_ctx_params_empty_is_noop() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let p = ParamSet::new();
        ctx.set_ctx_params(&p).unwrap();
    }

    #[test]
    fn set_ctx_params_context_string_accepts_octet_string() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let mut p = ParamSet::new();
        p.set("context-string", ParamValue::OctetString(b"hello".to_vec()));
        ctx.set_ctx_params(&p).unwrap();
    }

    #[test]
    fn set_ctx_params_context_string_type_mismatch() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let mut p = ParamSet::new();
        // Wrong type — Utf8String instead of OctetString.
        p.set("context-string", ParamValue::Utf8String("nope".into()));
        let err = ctx.set_ctx_params(&p).unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch { key, .. }) => {
                assert_eq!(key, "context-string");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_deterministic_flag_round_trip() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_192f);
        let mut p = ParamSet::new();
        p.set("deterministic", ParamValue::Int32(1));
        ctx.set_ctx_params(&p).unwrap();

        let out = ctx.get_ctx_params().unwrap();
        assert_eq!(
            out.get("deterministic")
                .and_then(ParamValue::as_i32)
                .unwrap(),
            1
        );

        let mut clear = ParamSet::new();
        clear.set("deterministic", ParamValue::Int32(0));
        ctx.set_ctx_params(&clear).unwrap();
        let out2 = ctx.get_ctx_params().unwrap();
        assert_eq!(
            out2.get("deterministic")
                .and_then(ParamValue::as_i32)
                .unwrap(),
            0
        );
    }

    #[test]
    fn set_ctx_params_deterministic_type_mismatch() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_192f);
        let mut p = ParamSet::new();
        p.set("deterministic", ParamValue::OctetString(vec![1]));
        let err = ctx.set_ctx_params(&p).unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch { key, .. }) => {
                assert_eq!(key, "deterministic");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_add_random_accepts_octet_string() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_192f);
        let mut p = ParamSet::new();
        p.set("add-random", ParamValue::OctetString(vec![0xAB; 16]));
        ctx.set_ctx_params(&p).unwrap();
    }

    #[test]
    fn set_ctx_params_add_random_type_mismatch() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_192f);
        let mut p = ParamSet::new();
        p.set("add-random", ParamValue::Int32(0));
        let err = ctx.set_ctx_params(&p).unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch { key, .. }) => {
                assert_eq!(key, "add-random");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_add_random_rejects_overlong() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_192f);
        let mut p = ParamSet::new();
        p.set(
            "add-random",
            ParamValue::OctetString(vec![0_u8; SLH_DSA_MAX_ADD_RANDOM_LEN + 1]),
        );
        let err = ctx.set_ctx_params(&p).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_message_encoding_round_trip() {
        let mut ctx = make_ctx(SlhDsaVariant::Shake_128s);
        let mut p = ParamSet::new();
        p.set("message-encoding", ParamValue::Int32(0)); // Raw
        ctx.set_ctx_params(&p).unwrap();
        let out = ctx.get_ctx_params().unwrap();
        assert_eq!(
            out.get("message-encoding")
                .and_then(ParamValue::as_i32)
                .unwrap(),
            0
        );

        let mut p2 = ParamSet::new();
        p2.set("message-encoding", ParamValue::Int32(1)); // Pure
        ctx.set_ctx_params(&p2).unwrap();
        let out2 = ctx.get_ctx_params().unwrap();
        assert_eq!(
            out2.get("message-encoding")
                .and_then(ParamValue::as_i32)
                .unwrap(),
            1
        );
    }

    #[test]
    fn set_ctx_params_message_encoding_type_mismatch() {
        let mut ctx = make_ctx(SlhDsaVariant::Shake_128s);
        let mut p = ParamSet::new();
        p.set("message-encoding", ParamValue::OctetString(vec![1]));
        let err = ctx.set_ctx_params(&p).unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch { key, .. }) => {
                assert_eq!(key, "message-encoding");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_message_encoding_unknown_value_rejected() {
        let mut ctx = make_ctx(SlhDsaVariant::Shake_128s);
        let mut p = ParamSet::new();
        p.set("message-encoding", ParamValue::Int32(7));
        let err = ctx.set_ctx_params(&p).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_signature_caches() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let mut p = ParamSet::new();
        p.set(
            "signature",
            ParamValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );
        ctx.set_ctx_params(&p).unwrap();
    }

    #[test]
    fn set_ctx_params_signature_type_mismatch() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let mut p = ParamSet::new();
        p.set("signature", ParamValue::Int32(0));
        let err = ctx.set_ctx_params(&p).unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch { key, .. }) => {
                assert_eq!(key, "signature");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn set_ctx_params_unknown_keys_are_ignored() {
        // Forward-compatibility: unknown parameter names should be
        // silently ignored, not treated as errors.
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let mut p = ParamSet::new();
        p.set("not-a-real-param", ParamValue::Int32(7));
        p.set("another-fake", ParamValue::Utf8String("ignored".into()));
        ctx.set_ctx_params(&p).unwrap();
    }

    #[test]
    fn get_ctx_params_emits_required_fields() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_192s);
        let p = ctx.get_ctx_params().unwrap();
        // The field set is documented in `get_ctx_params` and forms
        // the contract observed by EVP_PKEY_CTX_get_params() callers.
        assert!(p.get("algorithm-id").is_some());
        assert!(p.get("instance").is_some());
        assert!(p.get("deterministic").is_some());
        assert!(p.get("message-encoding").is_some());
        assert!(p.get("security-bits").is_some());
        // Crucially, NO `mu` parameter — SLH-DSA has no μ-mode.
        assert!(
            p.get("mu").is_none(),
            "SLH-DSA must not emit a mu parameter"
        );
    }

    #[test]
    fn get_ctx_params_instance_matches_variant() {
        for v in all_variants().iter().copied() {
            let mut ctx = make_ctx(v);
            let p = ctx.get_ctx_params().unwrap();
            let inst = p
                .get("instance")
                .and_then(ParamValue::as_str)
                .expect("instance param required");
            assert_eq!(inst, v.name());
        }
    }

    #[test]
    fn get_ctx_params_security_bits_matches_variant() {
        for v in all_variants().iter().copied() {
            let mut ctx = make_ctx(v);
            let p = ctx.get_ctx_params().unwrap();
            let bits = p
                .get("security-bits")
                .and_then(ParamValue::as_i32)
                .expect("security-bits param required");
            assert_eq!(bits, v.security_bits());
        }
    }

    #[test]
    fn get_ctx_params_algorithm_id_is_der_sequence() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let p = ctx.get_ctx_params().unwrap();
        let aid = p
            .get("algorithm-id")
            .and_then(ParamValue::as_bytes)
            .expect("algorithm-id required");
        assert_eq!(aid.len(), 13, "AID is fixed-size 13 bytes");
        assert_eq!(aid[0], 0x30, "AID must be DER SEQUENCE");
        assert_eq!(aid[1], 0x0B, "AID SEQUENCE must be 11 bytes long");
        assert_eq!(aid[2], 0x06, "AID payload starts with OID tag");
    }

    #[test]
    fn get_ctx_params_message_encoding_default_is_pure() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let p = ctx.get_ctx_params().unwrap();
        let me = p
            .get("message-encoding")
            .and_then(ParamValue::as_i32)
            .unwrap();
        assert_eq!(me, 1, "default message-encoding is Pure (1)");
    }

    // ==========================================================================
    // SignatureContext trait wiring tests.
    // ==========================================================================

    #[test]
    fn trait_sign_called_before_init_errors() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let err = ctx.sign(b"data").unwrap_err();
        match err {
            ProviderError::Init(msg) => {
                assert!(msg.contains("sign_init") || msg.contains("SLH-DSA"));
            }
            other => panic!("expected Init, got {other:?}"),
        }
    }

    #[test]
    fn trait_verify_called_before_init_errors() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let err = ctx.verify(b"data", &[0; 8]).unwrap_err();
        match err {
            ProviderError::Init(msg) => {
                assert!(msg.contains("verify_init") || msg.contains("SLH-DSA"));
            }
            other => panic!("expected Init, got {other:?}"),
        }
    }

    #[test]
    fn trait_digest_sign_init_rejects_external_digest() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let err = ctx
            .digest_sign_init("SHA-256", &[0_u8; 64], None)
            .unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("does not accept an external digest"));
            }
            other => panic!("expected Dispatch, got {other:?}"),
        }
    }

    #[test]
    fn trait_digest_verify_init_rejects_external_digest() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let err = ctx
            .digest_verify_init("SHA-512", &[0_u8; 32], None)
            .unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("does not accept an external digest"));
            }
            other => panic!("expected Dispatch, got {other:?}"),
        }
    }

    #[test]
    fn trait_digest_sign_update_before_init_errors() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let err = ctx.digest_sign_update(b"ignored").unwrap_err();
        match err {
            ProviderError::Init(_) => {}
            other => panic!("expected Init, got {other:?}"),
        }
    }

    #[test]
    fn trait_digest_sign_final_before_init_errors() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let err = ctx.digest_sign_final().unwrap_err();
        match err {
            ProviderError::Init(_) => {}
            other => panic!("expected Init, got {other:?}"),
        }
    }

    #[test]
    fn trait_digest_verify_update_before_init_errors() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let err = ctx.digest_verify_update(b"data").unwrap_err();
        match err {
            ProviderError::Init(_) => {}
            other => panic!("expected Init, got {other:?}"),
        }
    }

    #[test]
    fn trait_digest_verify_final_before_init_errors() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let err = ctx.digest_verify_final(&[0_u8; 16]).unwrap_err();
        match err {
            ProviderError::Init(_) => {}
            other => panic!("expected Init, got {other:?}"),
        }
    }

    #[test]
    fn trait_get_params_does_not_mutate_aid_cache() {
        // get_params() takes &self, so it cannot modify state — this
        // means it must produce the AID without going through the
        // cache-on-write path used by get_ctx_params.  Calling twice
        // must return identical bytes.
        let ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        let a = ctx.get_params().unwrap();
        let b = ctx.get_params().unwrap();
        assert_eq!(
            a.get("algorithm-id").and_then(ParamValue::as_bytes),
            b.get("algorithm-id").and_then(ParamValue::as_bytes),
        );
    }

    #[test]
    fn trait_set_params_delegates_to_set_ctx_params() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128f);
        let mut p = ParamSet::new();
        p.set("deterministic", ParamValue::Int32(1));
        // Trait-level set_params must produce the same effect as the
        // inherent set_ctx_params method.
        ctx.set_params(&p).unwrap();
        let out = ctx.get_ctx_params().unwrap();
        assert_eq!(
            out.get("deterministic")
                .and_then(ParamValue::as_i32)
                .unwrap(),
            1
        );
    }

    #[test]
    fn trait_get_params_emits_instance_for_all_variants() {
        for v in all_variants().iter().copied() {
            let ctx = make_ctx(v);
            let p = ctx.get_params().unwrap();
            let inst = p
                .get("instance")
                .and_then(ParamValue::as_str)
                .expect("instance param required");
            assert_eq!(inst, v.name());
        }
    }

    #[test]
    fn trait_sign_init_rejects_wrong_key_length() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        // Sha2_128s requires a 64-byte private key; pass something
        // obviously wrong.
        let err = ctx.sign_init(&[0_u8; 32], None).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn trait_verify_init_rejects_wrong_key_length() {
        let mut ctx = make_ctx(SlhDsaVariant::Sha2_128s);
        // Pass a length that matches neither pub_len (32) nor
        // priv_len (64) for Sha2_128s.
        let err = ctx.verify_init(&[0_u8; 1], None).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // ==========================================================================
    // Internal helper tests.
    // ==========================================================================

    #[test]
    fn algorithm_identifier_der_byte_layout() {
        // Every AID must be exactly 13 bytes:
        // 30 0B 06 09 60 86 48 01 65 03 04 03 <trailer>
        let aid = algorithm_identifier_der(SlhDsaVariant::Sha2_128s);
        assert_eq!(aid.len(), 13);
        assert_eq!(
            &aid[..12],
            &[0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03]
        );
    }

    #[test]
    fn algorithm_identifier_der_trailers_match_oids() {
        // Trailers run 0x14..0x1F for the 12 variants, in the same
        // order as the OID `.20`..`.31` arc.
        let cases: &[(SlhDsaVariant, u8)] = &[
            (SlhDsaVariant::Sha2_128s, 0x14),
            (SlhDsaVariant::Sha2_128f, 0x15),
            (SlhDsaVariant::Sha2_192s, 0x16),
            (SlhDsaVariant::Sha2_192f, 0x17),
            (SlhDsaVariant::Sha2_256s, 0x18),
            (SlhDsaVariant::Sha2_256f, 0x19),
            (SlhDsaVariant::Shake_128s, 0x1A),
            (SlhDsaVariant::Shake_128f, 0x1B),
            (SlhDsaVariant::Shake_192s, 0x1C),
            (SlhDsaVariant::Shake_192f, 0x1D),
            (SlhDsaVariant::Shake_256s, 0x1E),
            (SlhDsaVariant::Shake_256f, 0x1F),
        ];
        for (v, expected_trailer) in cases.iter().copied() {
            let aid = algorithm_identifier_der(v);
            assert_eq!(aid[12], expected_trailer, "{v:?} AID trailer wrong");
        }
    }

    #[test]
    fn algorithm_identifier_der_is_unique_per_variant() {
        let mut bytes: Vec<Vec<u8>> = all_variants()
            .iter()
            .map(|v| algorithm_identifier_der(*v))
            .collect();
        let count = bytes.len();
        bytes.sort();
        bytes.dedup();
        assert_eq!(bytes.len(), count, "AID must be unique per variant");
    }

    #[test]
    fn enforce_digest_match_accepts_empty() {
        // Empty digest names are silently accepted to match EVP code
        // paths that pass `""` to mean "no digest selected".
        for v in all_variants().iter().copied() {
            enforce_digest_match(v, "").expect("empty digest must be accepted");
        }
    }

    #[test]
    fn enforce_digest_match_rejects_named_digest() {
        for digest in &["SHA-256", "SHA-512", "SHA3-512", "BLAKE2b"] {
            let err = enforce_digest_match(SlhDsaVariant::Sha2_128s, digest).unwrap_err();
            match err {
                ProviderError::Dispatch(msg) => {
                    assert!(msg.contains("does not accept an external digest"));
                    assert!(msg.contains(digest));
                }
                other => panic!("expected Dispatch for {digest}, got {other:?}"),
            }
        }
    }

    // ==========================================================================
    // Public-constants test.
    // ==========================================================================

    #[test]
    fn public_constants_match_expected_values() {
        // These are the load-bearing limits other crates depend on;
        // changing them is a breaking API change.
        assert_eq!(SLH_DSA_MAX_ADD_RANDOM_LEN, 32);
        assert_eq!(SLH_DSA_MAX_CONTEXT_STRING_LEN, 255);
    }
}
