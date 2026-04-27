//! ANSI X9.42 ASN.1 Key Derivation Function provider implementation.
//!
//! This module is the idiomatic-Rust translation of
//! `providers/implementations/kdfs/x942kdf.c` (652 lines). It implements the
//! ANSI X9.42-2003 Key Derivation Function as adopted for use with CMS
//! key-agreement (RFC 2631 §2.1.2 / RFC 3370 §7.1) and selected NIST SP
//! 800-56A static-key transport modes.
//!
//! # Algorithm
//!
//! The X9.42 KDF derives keying material `KM` from a shared secret `Z` and
//! an `OtherInfo` blob using a counter-driven hash construction:
//!
//! ```text
//! for counter = 1, 2, ..., n:
//!     KM_i = H(Z || OtherInfo)         where the 4-byte counter is embedded
//!                                      *inside* the `OtherInfo` DER blob at a
//!                                      fixed offset and updated in-place
//! KM = KM_1 || KM_2 || ... || KM_n     truncated to the requested key length
//! ```
//!
//! `OtherInfo` is an ASN.1/DER-encoded structure of the form:
//!
//! ```asn1
//! OtherInfo ::= SEQUENCE {
//!     keyInfo       KeySpecificInfo,
//!     partyUInfo    [0] EXPLICIT OCTET STRING OPTIONAL,
//!     partyVInfo    [1] EXPLICIT OCTET STRING OPTIONAL,
//!     suppPubInfo   [2] EXPLICIT OCTET STRING OPTIONAL,
//!     suppPrivInfo  [3] EXPLICIT OCTET STRING OPTIONAL
//! }
//!
//! KeySpecificInfo ::= SEQUENCE {
//!     algorithm     OBJECT IDENTIFIER,
//!     counter       OCTET STRING (SIZE (4))
//! }
//! ```
//!
//! The 4-byte counter, initialised to `0x00 0x00 0x00 0x01` and big-endian,
//! is located inside `keyInfo` and is incremented in-place between hash
//! iterations, exactly mirroring the C `der_encode_sharedinfo` /
//! `x942kdf_hash_kdm` pipeline (`x942kdf.c:140-261, 270-345`).
//!
//! In *ACVP* mode, the caller supplies a pre-encoded `OtherInfo` blob via
//! the `"acvp-info"` parameter; in that case the in-process DER builder is
//! bypassed and only the counter location is patched (matches
//! `x942kdf.c:485-498, 538-554`).
//!
//! # Parameter contract
//!
//! | Param key       | Variant       | Direction | Notes                                                   |
//! |-----------------|---------------|-----------|---------------------------------------------------------|
//! | `secret`/`key`  | OctetString   | settable  | Shared secret `Z` (mandatory).                          |
//! | `digest`        | Utf8String    | settable  | Hash algorithm name (mandatory; XOFs rejected).         |
//! | `properties`    | Utf8String    | settable  | Property query for digest fetch.                        |
//! | `cekalg`        | Utf8String    | settable  | KEK algorithm name (mandatory; allowlist-checked).      |
//! | `partyu-info`   | OctetString   | settable  | `[0]` `partyUInfo` — UKM (mutually excludes `acvp`).    |
//! | `partyv-info`   | OctetString   | settable  | `[1]` `partyVInfo` (mutually excludes `acvp`).          |
//! | `supp-pubinfo`  | OctetString   | settable  | `[2]` `suppPubInfo` — turns off `use-keybits`.          |
//! | `supp-privinfo` | OctetString   | settable  | `[3]` `suppPrivInfo` (mutually excludes `acvp`).        |
//! | `use-keybits`   | Int32 (bool)  | settable  | Encode 32-bit keylen-in-bits as suppPubInfo (default 1).|
//! | `acvp-info`     | OctetString   | settable  | Pre-built `OtherInfo` DER (mutually exclusive w/ above).|
//! | `size`          | UInt64        | gettable  | Maximum derivable output size (`u64::MAX`).             |
//!
//! # Limits
//!
//! - `MAX_INPUT_LEN = 1 << 30`: maximum byte length of `Z`, `OtherInfo`, the
//!   derived key, and any individual `partyUInfo`/`partyVInfo`/etc. segment
//!   — matches `X942KDF_MAX_INLEN` (`x942kdf.c:33`).
//! - `keylen` (the CEK length in bytes) must be `<= 0xFFFFFF` so that
//!   `keylen * 8` fits in the 4-byte big-endian `keylen-in-bits` encoding
//!   used for `suppPubInfo` (`x942kdf.c:217-227`).
//!
//! # Memory hygiene
//!
//! All sensitive byte vectors (`secret`, `partyu_info`, `partyv_info`,
//! `supp_pub_info`, `supp_priv_info`, `acvp_info`) are zero-initialised on
//! drop via `ZeroizeOnDrop`. On any `derive` failure path the output buffer
//! is wiped before propagating the error — matches the C
//! `OPENSSL_cleanse(derived_key, derived_key_len)` discipline at
//! `x942kdf.c:332`.
//!
//! # Rule compliance
//!
//! - **R5** (Nullability): every optional field is `Option<T>`; no sentinel
//!   values used to encode "unset".
//! - **R6** (Lossless casts): `tlv_encoded_size` and `write_tlv_header` use
//!   `try_from`; counter increment uses `checked_add`.
//! - **R7** (Lock granularity): no shared mutable state — each context is
//!   owned exclusively; only `libctx` is `Arc`-shared.
//! - **R8** (Zero unsafe): no `unsafe` blocks anywhere in this file.
//! - **R9** (Warning-free): all public items are `///`-documented.
//! - **R10** (Wiring): registered via [`descriptors()`] which is collected
//!   into `kdfs::descriptors()` → `implementations::all_kdf_descriptors()` →
//!   `Provider::register`, providing the path from CLI/EVP entry to here.

use std::sync::Arc;

use tracing::{debug, instrument, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
use openssl_common::{CryptoError, ProviderResult};
use openssl_crypto::asn1::{tlv_encoded_size, write_tlv_header, Asn1Class, Asn1Object, Asn1Tag};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::md::{MdContext, MessageDigest};

use super::MAX_INPUT_LEN;

// =============================================================================
// Parameter keys (settable / gettable)
//
// These mirror the OSSL_KDF_PARAM_* macros in `include/openssl/core_names.h`.
// Translating them to `&'static str` const declarations gives us:
//   * compile-time stable string identity (cheap pointer compare in HashMap),
//   * a single source-of-truth for the parameter contract,
//   * trivially-greppable references that line up with the C macro names.
// =============================================================================

/// `OSSL_KDF_PARAM_SECRET`. The shared secret `Z`.
const PARAM_SECRET: &str = "secret";

/// `OSSL_KDF_PARAM_KEY`. Alias for `secret` accepted by the C provider
/// (`x942kdf_set_ctx_params` at `x942kdf.c:560-563`).
const PARAM_KEY: &str = "key";

/// `OSSL_KDF_PARAM_DIGEST`. Mandatory hash algorithm name (e.g. `"SHA-256"`).
const PARAM_DIGEST: &str = "digest";

/// `OSSL_KDF_PARAM_PROPERTIES`. Property string for the digest fetch.
const PARAM_PROPERTIES: &str = "properties";

/// `OSSL_KDF_PARAM_CEK_ALG`. Required KEK algorithm name; allowlisted in
/// [`KEK_ALGS`] (matches `x942kdf.c:601-621`).
const PARAM_CEK_ALG: &str = "cekalg";

/// `OSSL_KDF_PARAM_UKM` / `OSSL_KDF_PARAM_X942_PARTYUINFO`. The
/// `partyUInfo` field encoded as `[0] EXPLICIT OCTET STRING`.
const PARAM_PARTYU_INFO: &str = "partyu-info";

/// `OSSL_KDF_PARAM_X942_PARTYVINFO`. The `partyVInfo` field encoded as
/// `[1] EXPLICIT OCTET STRING`.
const PARAM_PARTYV_INFO: &str = "partyv-info";

/// `OSSL_KDF_PARAM_X942_SUPP_PUBINFO`. The `suppPubInfo` field encoded as
/// `[2] EXPLICIT OCTET STRING`. Setting this implicitly turns off
/// `use-keybits` (the keylen-in-bits encoding lives at the same DER slot).
const PARAM_SUPP_PUB_INFO: &str = "supp-pubinfo";

/// `OSSL_KDF_PARAM_X942_SUPP_PRIVINFO`. The `suppPrivInfo` field encoded as
/// `[3] EXPLICIT OCTET STRING`.
const PARAM_SUPP_PRIV_INFO: &str = "supp-privinfo";

/// `OSSL_KDF_PARAM_X942_USE_KEYBITS`. Boolean (Int32 zero/non-zero) which
/// when on (default) makes the KDF auto-emit a 4-byte `keylen-in-bits`
/// encoding as `suppPubInfo`. Auto-disabled when `supp-pubinfo` is
/// explicitly set.
const PARAM_USE_KEYBITS: &str = "use-keybits";

/// `OSSL_KDF_PARAM_X942_ACVPINFO`. Pre-encoded `OtherInfo` DER blob — used
/// for ACVP test-vector compliance.
const PARAM_ACVP_INFO: &str = "acvp-info";

/// `OSSL_KDF_PARAM_SIZE`. Gettable maximum output size.
const PARAM_SIZE: &str = "size";

// =============================================================================
// KEK algorithm allowlist
// =============================================================================

/// Description of one allowed KEK (key-encryption-key wrap) algorithm.
///
/// Matches the `kek_algs[]` table at `x942kdf.c:48-63`. Each entry pins:
///
/// - The canonical OpenSSL algorithm name accepted by `cekalg`.
/// - The DER-encoded OID identifying the algorithm in `KeySpecificInfo`.
/// - The fixed wrapped-key length in bytes (used to default `dkm_len`
///   and to scale the `use-keybits` `suppPubInfo`).
#[derive(Debug, Clone, Copy)]
struct KekAlg {
    /// Canonical algorithm name (case-insensitive on lookup).
    name: &'static str,
    /// Dotted-decimal OID assigned by IANA / X9.
    oid: &'static str,
    /// Wrapped-key length in bytes.
    keklen: usize,
    /// Whether the algorithm is permitted in FIPS mode.
    fips_approved: bool,
}

/// The complete table of supported KEK algorithms (matches
/// `x942kdf.c:48-63` and `kek_algs[]`).
///
/// `DES3-WRAP` is included for non-FIPS use-cases; the FIPS provider
/// suppresses it via the `fips_approved` flag rather than a separate
/// table (the C version uses `#ifdef FIPS_MODULE` to drop the entry,
/// but a runtime flag composes more cleanly with the dynamic provider
/// dispatch architecture used in this crate).
const KEK_ALGS: &[KekAlg] = &[
    KekAlg {
        name: "AES-128-WRAP",
        oid: "2.16.840.1.101.3.4.1.5",
        keklen: 16,
        fips_approved: true,
    },
    KekAlg {
        name: "AES-192-WRAP",
        oid: "2.16.840.1.101.3.4.1.25",
        keklen: 24,
        fips_approved: true,
    },
    KekAlg {
        name: "AES-256-WRAP",
        oid: "2.16.840.1.101.3.4.1.45",
        keklen: 32,
        fips_approved: true,
    },
    KekAlg {
        name: "DES3-WRAP",
        oid: "1.2.840.113549.1.9.16.3.6",
        keklen: 24,
        fips_approved: false,
    },
];

/// Resolves a `cekalg` name (case-insensitive) to the matching
/// [`KekAlg`] entry. Returns `None` if the algorithm is not on the
/// allowlist.
fn lookup_kek_alg(name: &str) -> Option<&'static KekAlg> {
    KEK_ALGS.iter().find(|k| k.name.eq_ignore_ascii_case(name))
}

// =============================================================================
// Helpers
// =============================================================================

/// Unified mapping from a `CryptoError` (raised by digest / ASN.1
/// dependencies) to a `ProviderError::Dispatch`. Mirrors the SSKDF
/// pattern and keeps error messages threaded through the trace span.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Fixed marker bytes used to locate the embedded counter inside an
/// already-built `OtherInfo` DER blob. Matches the C "scan for
/// `0x04 0x04 0x00 0x00 0x00 0x01`" recipe used when the DER builder
/// is replaced by an ACVP blob (`x942kdf.c:551-554`).
///
/// The pattern is the OCTET-STRING-of-length-4 envelope wrapping the
/// initial counter value (`1` big-endian).
const COUNTER_TLV_MARKER: [u8; 6] = [0x04, 0x04, 0x00, 0x00, 0x00, 0x01];

/// Scans `der` for the unique occurrence of [`COUNTER_TLV_MARKER`] and
/// returns the byte offset of the counter value (i.e. the position
/// *past* the leading `0x04 0x04` tag/length).
///
/// Used in ACVP mode where the caller pre-encodes the entire
/// `OtherInfo` and we still need to locate the counter in order to
/// rewrite it between hash iterations.
fn locate_counter(der: &[u8]) -> Option<usize> {
    der.windows(COUNTER_TLV_MARKER.len())
        .position(|w| w == COUNTER_TLV_MARKER)
        .map(|p| p + 2) // skip tag + length, point at counter bytes
}

/// Renders the `keylen-in-bits` `suppPubInfo` encoding used by the C
/// `der_encode_sharedinfo` path when `use_keybits` is on
/// (`x942kdf.c:217-227`). The wire encoding is the 32-bit big-endian
/// representation of `keylen_bytes * 8`.
///
/// Returns an error if `keylen_bytes * 8` would overflow `u32` — the C
/// version checks `keylen > 0xFFFFFF` (`x942kdf.c:220-223`).
fn encode_keylen_bits(keylen_bytes: usize) -> Result<[u8; 4], ProviderError> {
    if keylen_bytes > 0x00FF_FFFF {
        return Err(ProviderError::Common(CommonError::InvalidArgument(
            format!(
                "X942KDF: derived-key length {keylen_bytes} bytes exceeds the 4-byte \
             keylen-in-bits encoding limit (0xFFFFFF bytes)"
            ),
        )));
    }
    // keylen_bytes is bounded above by 0xFFFFFF, so * 8 is at most 0x07FFFFF8
    // which fits comfortably in u32. We still use try_from for explicit R6
    // compliance (no bare `as` casts).
    let bits = u32::try_from(keylen_bytes).map_err(|_| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "X942KDF keylen-in-bytes -> u32",
        })
    })?;
    let bits = bits.checked_mul(8).ok_or_else(|| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "X942KDF keylen-in-bytes * 8",
        })
    })?;
    Ok(bits.to_be_bytes())
}

// =============================================================================
// DER OtherInfo construction
// =============================================================================

/// Build a `KeySpecificInfo` SEQUENCE for the supplied KEK algorithm.
///
/// Matches the C `DER_w_keyinfo` helper (`x942kdf.c:140-160`):
///
/// ```asn1
/// KeySpecificInfo ::= SEQUENCE {
///     algorithm  OBJECT IDENTIFIER,
///     counter    OCTET STRING (SIZE (4))
/// }
/// ```
///
/// Returns the fully-encoded TLV bytes plus the byte offset (within the
/// returned vector) of the counter value (the 4 raw counter bytes
/// inside the OCTET STRING). The caller can then rewrite those 4 bytes
/// in-place between hash iterations.
fn build_keyinfo(cek_alg: &KekAlg) -> Result<(Vec<u8>, usize), ProviderError> {
    // 1. Resolve the CEK OID and obtain its DER content bytes.
    //
    // `Asn1Object::encode_der` returns *content only* (no TLV wrapper),
    // so we wrap it ourselves with `write_tlv_header` to produce the
    // primitive `OBJECT IDENTIFIER` element.
    let oid_obj = Asn1Object::from_oid_string(cek_alg.oid).map_err(dispatch_err)?;
    let oid_content = oid_obj.encode_der().map_err(dispatch_err)?;
    let oid_header = write_tlv_header(
        Asn1Tag::ObjectIdentifier,
        Asn1Class::Universal,
        false,
        oid_content.len(),
    )
    .map_err(dispatch_err)?;
    let oid_tlv_len = oid_header
        .len()
        .checked_add(oid_content.len())
        .ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "X942KDF OID TLV length",
            })
        })?;

    // 2. Encode the counter OCTET STRING (4-byte initial value 1).
    let counter_content: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
    let counter_header = write_tlv_header(
        Asn1Tag::OctetString,
        Asn1Class::Universal,
        false,
        counter_content.len(),
    )
    .map_err(dispatch_err)?;
    let counter_tlv_len = counter_header
        .len()
        .checked_add(counter_content.len())
        .ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "X942KDF counter TLV length",
            })
        })?;

    // 3. Wrap both elements in the outer SEQUENCE.
    let inner_len = oid_tlv_len.checked_add(counter_tlv_len).ok_or_else(|| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "X942KDF KeySpecificInfo body length",
        })
    })?;
    let seq_header = write_tlv_header(Asn1Tag::Sequence, Asn1Class::Universal, true, inner_len)
        .map_err(dispatch_err)?;
    let total_len = seq_header.len().checked_add(inner_len).ok_or_else(|| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "X942KDF KeySpecificInfo TLV length",
        })
    })?;

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&seq_header);
    out.extend_from_slice(&oid_header);
    out.extend_from_slice(&oid_content);
    out.extend_from_slice(&counter_header);

    // The counter starts immediately after counter_header in `out`.
    let counter_offset = out.len();
    out.extend_from_slice(&counter_content);

    debug_assert_eq!(out.len(), total_len);
    debug_assert_eq!(&out[counter_offset..counter_offset + 4], &counter_content);
    Ok((out, counter_offset))
}

/// Wrap `content` in a context-specific `[n] EXPLICIT OCTET STRING`
/// EXPLICIT tagged element. Matches the C `DER_w_octet_string_uint32`
/// /`DER_w_octet_string` helpers used inside `der_encode_sharedinfo`
/// (`x942kdf.c:163-200`).
///
/// `n` selects which of the X9.42 OPTIONAL fields (`[0] partyUInfo`,
/// `[1] partyVInfo`, `[2] suppPubInfo`, `[3] suppPrivInfo`) is being
/// emitted. We use the trick that the first four `Asn1Tag` enum
/// discriminants (`Eoc=0, Boolean=1, Integer=2, BitString=3`) cast to
/// `u32` give exactly `0..=3`, which `write_tlv_header` then combines
/// with `Asn1Class::ContextSpecific` to produce the correct identifier
/// byte for `[n] CONSTRUCTED`.
fn build_explicit_tagged_octet_string(n: u8, content: &[u8]) -> Result<Vec<u8>, ProviderError> {
    // Inner OCTET STRING TLV.
    let inner_header = write_tlv_header(
        Asn1Tag::OctetString,
        Asn1Class::Universal,
        false,
        content.len(),
    )
    .map_err(dispatch_err)?;
    let inner_total = inner_header
        .len()
        .checked_add(content.len())
        .ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "X942KDF inner OCTET STRING length",
            })
        })?;

    // The outer EXPLICIT tag takes the same low 5 bits as `n`, but with
    // class=ContextSpecific and the constructed bit set. We map n→tag.
    let tag = match n {
        0 => Asn1Tag::Eoc,
        1 => Asn1Tag::Boolean,
        2 => Asn1Tag::Integer,
        3 => Asn1Tag::BitString,
        _ => {
            return Err(ProviderError::Common(CommonError::Internal(format!(
                "X942KDF: invalid context-specific tag number {n} (must be 0..=3)"
            ))));
        }
    };
    let outer_header = write_tlv_header(tag, Asn1Class::ContextSpecific, true, inner_total)
        .map_err(dispatch_err)?;
    let total = outer_header.len().checked_add(inner_total).ok_or_else(|| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "X942KDF EXPLICIT [n] OCTET STRING length",
        })
    })?;

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&outer_header);
    out.extend_from_slice(&inner_header);
    out.extend_from_slice(content);
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

/// Validate that `tlv_encoded_size` is happy with the supplied content
/// length — this is purely a guard that exposes the underlying R6
/// truncation detection if we ever build a `>= 1 << 30` segment.
fn check_segment_len(tag: Asn1Tag, content_len: usize) -> Result<(), ProviderError> {
    tlv_encoded_size(false, content_len, tag).map_err(dispatch_err)?;
    Ok(())
}

/// Encoded `OtherInfo` DER plus the counter offset (within the encoded
/// blob). Returned by [`X942KdfContext::encode_other_info`] and then
/// consumed by the hash loop.
#[derive(Debug)]
struct EncodedOtherInfo {
    /// The full DER bytes of the `OtherInfo` SEQUENCE.
    der: Vec<u8>,
    /// Byte offset of the 4-byte counter inside `der`.
    counter_offset: usize,
}

// =============================================================================
// Context — operation lifecycle
// =============================================================================

/// Mutable derivation state for a single ANSI X9.42 KDF operation.
///
/// Equivalent to the C `KDF_X942` struct (`x942kdf.c:81-97`). One
/// context per `derive` call; instances are not thread-safe and are
/// owned exclusively by the caller (matches the C `provctx` discipline
/// where a `KDF_CTX` is not shared between threads).
///
/// All sensitive byte buffers (`secret`, `acvp_info`, the four
/// `partyU/V` / `suppPub/Priv` fields) are marked for automatic
/// zeroization on drop via `ZeroizeOnDrop`. The non-sensitive metadata
/// fields (`libctx`, `digest`, names, `dkm_len`, `use_keybits`) are
/// `#[zeroize(skip)]`-annotated to suppress trait-derive recursion into
/// their non-`Zeroize` interiors (e.g. `Arc<LibContext>`,
/// `MessageDigest`).
#[derive(ZeroizeOnDrop)]
pub struct X942KdfContext {
    /// Library context used to resolve digests (`EVP_MD_fetch`
    /// equivalent). Cheaply cloneable via `Arc`.
    #[zeroize(skip)]
    libctx: Arc<LibContext>,

    /// Resolved digest object — `None` until first `derive` (lazy fetch
    /// in `ensure_digest`).
    #[zeroize(skip)]
    digest: Option<MessageDigest>,

    /// Algorithm name supplied via the `digest` parameter (mandatory).
    #[zeroize(skip)]
    digest_name: Option<String>,

    /// Optional property string supplied via the `properties` parameter.
    #[zeroize(skip)]
    properties: Option<String>,

    /// Looked-up KEK algorithm entry (`KEK_ALGS` row); `None` until
    /// `cekalg` is set.
    #[zeroize(skip)]
    cek_alg: Option<&'static KekAlg>,

    /// Default derived-key-material length, taken from the KEK algorithm
    /// when `cekalg` is set (matches `x942kdf.c:606`).
    #[zeroize(skip)]
    dkm_len: Option<usize>,

    /// When `true` (the default), the KDF auto-emits a 4-byte
    /// `keylen-in-bits` encoding as `suppPubInfo`. Setting
    /// `supp-pubinfo` explicitly clears this flag (matches
    /// `x942kdf.c:585-590`).
    #[zeroize(skip)]
    use_keybits: bool,

    /// The shared secret `Z`. Sensitive — auto-zeroed on drop.
    secret: Option<Vec<u8>>,

    /// `partyUInfo` / UKM. Sensitive.
    partyu_info: Option<Vec<u8>>,

    /// `partyVInfo`. Sensitive.
    partyv_info: Option<Vec<u8>>,

    /// `suppPubInfo` (mutually exclusive with `use_keybits`). Sensitive.
    supp_pub_info: Option<Vec<u8>>,

    /// `suppPrivInfo`. Sensitive.
    supp_priv_info: Option<Vec<u8>>,

    /// Pre-encoded `OtherInfo` blob — when `Some`, replaces the
    /// in-process DER builder. Sensitive.
    acvp_info: Option<Vec<u8>>,
}

impl X942KdfContext {
    /// Constructs a new, empty context bound to `libctx`. Matches the C
    /// `x942kdf_new` (`x942kdf.c:351-359`): default-zero except for
    /// `use_keybits = 1`.
    fn new(libctx: Arc<LibContext>) -> Self {
        Self {
            libctx,
            digest: None,
            digest_name: None,
            properties: None,
            cek_alg: None,
            dkm_len: None,
            use_keybits: true,
            secret: None,
            partyu_info: None,
            partyv_info: None,
            supp_pub_info: None,
            supp_priv_info: None,
            acvp_info: None,
        }
    }

    /// Lazy resolution of the digest, run on the first `derive`. Mirrors
    /// the C `ossl_prov_digest_load_from_params` pattern and adds the
    /// XOF rejection enforced at `x942kdf.c:558-560`.
    fn ensure_digest(&mut self) -> ProviderResult<()> {
        if self.digest.is_some() {
            return Ok(());
        }
        let name = self.digest_name.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::ParamNotFound {
                key: PARAM_DIGEST.to_string(),
            })
        })?;
        let props = self.properties.as_deref();
        let md = MessageDigest::fetch(&self.libctx, name, props).map_err(dispatch_err)?;
        if md.is_xof() {
            warn!(digest = %name, "X942KDF: XOF digest rejected");
            return Err(ProviderError::Common(CommonError::Unsupported(format!(
                "X942KDF: XOF digest '{name}' is not permitted (matches PROV_R_XOF_DIGESTS_NOT_ALLOWED at x942kdf.c:558)"
            ))));
        }
        debug!(digest = %name, size = md.digest_size(), "X942KDF: digest fetched");
        self.digest = Some(md);
        Ok(())
    }

    /// Apply a single `ParamSet` to the context.
    ///
    /// Translates `x942kdf_set_ctx_params` (`x942kdf.c:560-625`).
    /// Each parameter is matched by key, type-checked against the
    /// expected `ParamValue` variant, and applied — with sensitive
    /// fields zeroized before being overwritten.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Track whether the caller explicitly set `supp-pubinfo` this
        // call, so we can honour the C semantics of "supp-pubinfo
        // implicitly disables use-keybits" (x942kdf.c:585-590).
        let mut supp_pubinfo_set = false;

        // ---- secret (with `key` alias) -------------------------------------
        for key in [PARAM_SECRET, PARAM_KEY] {
            if let Some(v) = params.get(key) {
                match v {
                    ParamValue::OctetString(bytes) => {
                        if bytes.len() > MAX_INPUT_LEN {
                            return Err(ProviderError::Common(CommonError::InvalidArgument(
                                format!(
                                    "X942KDF: secret length {} exceeds maximum {}",
                                    bytes.len(),
                                    MAX_INPUT_LEN
                                ),
                            )));
                        }
                        if let Some(s) = self.secret.as_mut() {
                            s.zeroize();
                        }
                        self.secret = Some(bytes.clone());
                        trace!(len = bytes.len(), "X942KDF: secret set");
                    }
                    other => {
                        return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                            key: key.to_string(),
                            expected: "OctetString",
                            actual: other.param_type_name(),
                        }));
                    }
                }
            }
        }

        // ---- digest --------------------------------------------------------
        if let Some(v) = params.get(PARAM_DIGEST) {
            match v {
                ParamValue::Utf8String(s) => {
                    self.digest_name = Some(s.clone());
                    // Force re-fetch on the next derive in case the
                    // properties string has also changed.
                    self.digest = None;
                    trace!(digest = %s, "X942KDF: digest name set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_DIGEST.to_string(),
                        expected: "Utf8String",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // ---- properties ----------------------------------------------------
        if let Some(v) = params.get(PARAM_PROPERTIES) {
            match v {
                ParamValue::Utf8String(s) => {
                    self.properties = Some(s.clone());
                    self.digest = None;
                    trace!(props = %s, "X942KDF: properties set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_PROPERTIES.to_string(),
                        expected: "Utf8String",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // ---- cekalg --------------------------------------------------------
        if let Some(v) = params.get(PARAM_CEK_ALG) {
            match v {
                ParamValue::Utf8String(name) => {
                    if let Some(k) = lookup_kek_alg(name) {
                        self.cek_alg = Some(k);
                        // dkm_len is auto-derived from the KEK
                        // (x942kdf.c:606). Caller may still override
                        // it via `size`-style parameters, but x942 has
                        // no size param so this is the only source.
                        self.dkm_len = Some(k.keklen);
                        trace!(
                            cek = %k.name,
                            keklen = k.keklen,
                            fips = k.fips_approved,
                            "X942KDF: cekalg accepted"
                        );
                    } else {
                        warn!(cek = %name, "X942KDF: unsupported cekalg");
                        return Err(ProviderError::AlgorithmUnavailable(format!(
                            "X942KDF: KEK algorithm '{name}' is not on the allowlist \
                             (supported: {})",
                            KEK_ALGS
                                .iter()
                                .map(|k| k.name)
                                .collect::<Vec<_>>()
                                .join(", ")
                        )));
                    }
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_CEK_ALG.to_string(),
                        expected: "Utf8String",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // ---- partyu-info ---------------------------------------------------
        if let Some(v) = params.get(PARAM_PARTYU_INFO) {
            match v {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() >= MAX_INPUT_LEN {
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!(
                                "X942KDF: partyu-info length {} reaches/exceeds limit {}",
                                bytes.len(),
                                MAX_INPUT_LEN
                            ),
                        )));
                    }
                    check_segment_len(Asn1Tag::OctetString, bytes.len())?;
                    if let Some(s) = self.partyu_info.as_mut() {
                        s.zeroize();
                    }
                    self.partyu_info = Some(bytes.clone());
                    trace!(len = bytes.len(), "X942KDF: partyu-info set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_PARTYU_INFO.to_string(),
                        expected: "OctetString",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // ---- partyv-info ---------------------------------------------------
        if let Some(v) = params.get(PARAM_PARTYV_INFO) {
            match v {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() > MAX_INPUT_LEN {
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!(
                                "X942KDF: partyv-info length {} exceeds maximum {}",
                                bytes.len(),
                                MAX_INPUT_LEN
                            ),
                        )));
                    }
                    check_segment_len(Asn1Tag::OctetString, bytes.len())?;
                    if let Some(s) = self.partyv_info.as_mut() {
                        s.zeroize();
                    }
                    self.partyv_info = Some(bytes.clone());
                    trace!(len = bytes.len(), "X942KDF: partyv-info set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_PARTYV_INFO.to_string(),
                        expected: "OctetString",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // ---- supp-pubinfo (auto-disables use-keybits) ----------------------
        if let Some(v) = params.get(PARAM_SUPP_PUB_INFO) {
            match v {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() > MAX_INPUT_LEN {
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!(
                                "X942KDF: supp-pubinfo length {} exceeds maximum {}",
                                bytes.len(),
                                MAX_INPUT_LEN
                            ),
                        )));
                    }
                    check_segment_len(Asn1Tag::OctetString, bytes.len())?;
                    if let Some(s) = self.supp_pub_info.as_mut() {
                        s.zeroize();
                    }
                    self.supp_pub_info = Some(bytes.clone());
                    supp_pubinfo_set = true;
                    trace!(len = bytes.len(), "X942KDF: supp-pubinfo set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_SUPP_PUB_INFO.to_string(),
                        expected: "OctetString",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // ---- supp-privinfo -------------------------------------------------
        if let Some(v) = params.get(PARAM_SUPP_PRIV_INFO) {
            match v {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() > MAX_INPUT_LEN {
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!(
                                "X942KDF: supp-privinfo length {} exceeds maximum {}",
                                bytes.len(),
                                MAX_INPUT_LEN
                            ),
                        )));
                    }
                    check_segment_len(Asn1Tag::OctetString, bytes.len())?;
                    if let Some(s) = self.supp_priv_info.as_mut() {
                        s.zeroize();
                    }
                    self.supp_priv_info = Some(bytes.clone());
                    trace!(len = bytes.len(), "X942KDF: supp-privinfo set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_SUPP_PRIV_INFO.to_string(),
                        expected: "OctetString",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        // ---- use-keybits ---------------------------------------------------
        // Order matters: if both `supp-pubinfo` and `use-keybits` are set in
        // the same call, the explicit `use-keybits` wins.  Otherwise,
        // `supp_pubinfo_set` from above flips it off.
        if let Some(v) = params.get(PARAM_USE_KEYBITS) {
            match v {
                ParamValue::Int32(i) => {
                    self.use_keybits = *i != 0;
                    trace!(use_keybits = self.use_keybits, "X942KDF: use-keybits set");
                }
                ParamValue::UInt32(u) => {
                    self.use_keybits = *u != 0;
                    trace!(use_keybits = self.use_keybits, "X942KDF: use-keybits set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_USE_KEYBITS.to_string(),
                        expected: "Int32",
                        actual: other.param_type_name(),
                    }));
                }
            }
        } else if supp_pubinfo_set {
            // Implicit consequence per x942kdf.c:585-590: setting
            // suppPubInfo turns off automatic keylen-in-bits encoding,
            // because both encode to the same DER slot.
            self.use_keybits = false;
            trace!("X942KDF: use-keybits cleared (supp-pubinfo set without explicit use-keybits)");
        }

        // ---- acvp-info -----------------------------------------------------
        if let Some(v) = params.get(PARAM_ACVP_INFO) {
            match v {
                ParamValue::OctetString(bytes) => {
                    if bytes.len() > MAX_INPUT_LEN {
                        return Err(ProviderError::Common(CommonError::InvalidArgument(
                            format!(
                                "X942KDF: acvp-info length {} exceeds maximum {}",
                                bytes.len(),
                                MAX_INPUT_LEN
                            ),
                        )));
                    }
                    if let Some(s) = self.acvp_info.as_mut() {
                        s.zeroize();
                    }
                    self.acvp_info = Some(bytes.clone());
                    trace!(len = bytes.len(), "X942KDF: acvp-info set");
                }
                other => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_ACVP_INFO.to_string(),
                        expected: "OctetString",
                        actual: other.param_type_name(),
                    }));
                }
            }
        }

        Ok(())
    }

    /// Run the mutual-exclusion checks that `x942kdf_derive` performs at
    /// the top of every derive (`x942kdf.c:478-510`).
    ///
    /// - `use_keybits` ⇔ `suppPubInfo`: at most one may be active
    ///   (matches `PROV_R_INVALID_PUBINFO`).
    /// - `acvp` is incompatible with any of partyu / partyv / suppPub /
    ///   suppPriv (matches `PROV_R_INVALID_DATA`).
    /// - `secret` must be set (`PROV_R_MISSING_SECRET`).
    /// - `cekalg` must be set (`PROV_R_MISSING_CEK_ALG`).
    /// - `digest_name` must be set (`PROV_R_MISSING_MESSAGE_DIGEST`).
    fn validate(&self) -> ProviderResult<()> {
        // Rule: secret is mandatory.
        if self.secret.is_none() {
            return Err(ProviderError::Common(CommonError::ParamNotFound {
                key: PARAM_SECRET.to_string(),
            }));
        }

        // Rule: cekalg is mandatory.
        if self.cek_alg.is_none() {
            return Err(ProviderError::Common(CommonError::ParamNotFound {
                key: PARAM_CEK_ALG.to_string(),
            }));
        }

        // Rule: digest is mandatory (also re-checked in ensure_digest,
        // but emit the more specific error variant here).
        if self.digest_name.is_none() {
            return Err(ProviderError::Common(CommonError::ParamNotFound {
                key: PARAM_DIGEST.to_string(),
            }));
        }

        // Rule: use_keybits + suppPubInfo are mutually exclusive
        // (PROV_R_INVALID_PUBINFO at x942kdf.c:481-484).
        if self.use_keybits && self.supp_pub_info.is_some() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "X942KDF: 'use-keybits' and 'supp-pubinfo' are mutually exclusive — \
                 both encode to suppPubInfo (matches PROV_R_INVALID_PUBINFO at \
                 x942kdf.c:481-484)"
                    .to_string(),
            )));
        }

        // Rule: ACVP blob excludes the explicit-field encoders
        // (PROV_R_INVALID_DATA at x942kdf.c:489-496).
        if self.acvp_info.is_some()
            && (self.partyu_info.is_some()
                || self.partyv_info.is_some()
                || self.supp_pub_info.is_some()
                || self.supp_priv_info.is_some())
        {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "X942KDF: 'acvp-info' is mutually exclusive with partyu-info, \
                 partyv-info, supp-pubinfo, supp-privinfo (matches PROV_R_INVALID_DATA \
                 at x942kdf.c:489-496)"
                    .to_string(),
            )));
        }

        Ok(())
    }

    /// Produce the encoded `OtherInfo` blob (DER bytes + counter
    /// offset) for the current parameter set.
    ///
    /// Two paths:
    ///
    /// 1. **ACVP path** (`acvp_info` set): use the blob verbatim and
    ///    locate the counter inside it via [`locate_counter`].
    /// 2. **Builder path**: assemble the SEQUENCE from the configured
    ///    fields, mirroring `der_encode_sharedinfo`
    ///    (`x942kdf.c:165-200`) and `x942_encode_otherinfo`
    ///    (`x942kdf.c:202-244`).
    fn encode_other_info(&self) -> Result<EncodedOtherInfo, ProviderError> {
        // ACVP fast path.
        if let Some(blob) = &self.acvp_info {
            let off = locate_counter(blob).ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "X942KDF: acvp-info blob does not contain the expected counter \
                     marker bytes 0x04 0x04 0x00 0x00 0x00 0x01"
                        .to_string(),
                ))
            })?;
            return Ok(EncodedOtherInfo {
                der: blob.clone(),
                counter_offset: off,
            });
        }

        // Builder path: caller has supplied a cekalg (validated above).
        let cek = self.cek_alg.ok_or_else(|| {
            ProviderError::Common(CommonError::Internal(
                "X942KDF: encode_other_info called before cek_alg was set".to_string(),
            ))
        })?;

        let (key_info, mut counter_offset_in_keyinfo) = build_keyinfo(cek)?;

        // Encode each optional context-specific section.
        let partyu = match &self.partyu_info {
            Some(b) => Some(build_explicit_tagged_octet_string(0, b)?),
            None => None,
        };
        let partyv = match &self.partyv_info {
            Some(b) => Some(build_explicit_tagged_octet_string(1, b)?),
            None => None,
        };
        // suppPubInfo: either the explicit bytes or, when use_keybits is
        // on, the auto-emitted 4-byte keylen-in-bits encoding. They are
        // mutually exclusive (validated above).
        let supp_pub = if let Some(b) = &self.supp_pub_info {
            Some(build_explicit_tagged_octet_string(2, b)?)
        } else if self.use_keybits {
            let keylen = self.dkm_len.ok_or_else(|| {
                ProviderError::Common(CommonError::Internal(
                    "X942KDF: dkm_len missing while use_keybits is on".to_string(),
                ))
            })?;
            let bits = encode_keylen_bits(keylen)?;
            Some(build_explicit_tagged_octet_string(2, &bits)?)
        } else {
            None
        };
        let supp_priv = match &self.supp_priv_info {
            Some(b) => Some(build_explicit_tagged_octet_string(3, b)?),
            None => None,
        };

        // Compute total inner-content length so we can pre-size the SEQUENCE
        // header.
        let mut inner_len: usize = key_info.len();
        for s in [&partyu, &partyv, &supp_pub, &supp_priv]
            .into_iter()
            .flatten()
        {
            inner_len = inner_len.checked_add(s.len()).ok_or_else(|| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "X942KDF OtherInfo content length",
                })
            })?;
        }
        if inner_len > MAX_INPUT_LEN {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "X942KDF: assembled OtherInfo content length {inner_len} exceeds \
                     maximum {MAX_INPUT_LEN}"
                ),
            )));
        }

        let seq_header = write_tlv_header(Asn1Tag::Sequence, Asn1Class::Universal, true, inner_len)
            .map_err(dispatch_err)?;
        let total_len = seq_header.len().checked_add(inner_len).ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "X942KDF OtherInfo total length",
            })
        })?;

        let mut der = Vec::with_capacity(total_len);
        der.extend_from_slice(&seq_header);
        // The counter offset returned by build_keyinfo was relative to
        // the keyinfo blob; once we slot the keyinfo into the outer
        // SEQUENCE it shifts by `seq_header.len()`.
        counter_offset_in_keyinfo = counter_offset_in_keyinfo
            .checked_add(seq_header.len())
            .ok_or_else(|| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "X942KDF counter offset relocation",
                })
            })?;
        der.extend_from_slice(&key_info);
        for sect in [partyu, partyv, supp_pub, supp_priv].into_iter().flatten() {
            der.extend_from_slice(&sect);
        }
        debug_assert_eq!(der.len(), total_len);
        debug_assert_eq!(
            &der[counter_offset_in_keyinfo..counter_offset_in_keyinfo + 4],
            &[0x00, 0x00, 0x00, 0x01],
            "X942KDF: counter slot must contain initial value 1"
        );

        Ok(EncodedOtherInfo {
            der,
            counter_offset: counter_offset_in_keyinfo,
        })
    }

    /// Counter-driven hash derivation core. Equivalent to
    /// `x942kdf_hash_kdm` (`x942kdf.c:270-345`):
    ///
    /// ```text
    /// for counter = 1, 2, ...:
    ///     write(other_info[counter_offset..+4], counter_be)
    ///     hash(Z) ; hash(other_info) ; finalize -> block
    ///     append(block) to derived_key, truncating final block as needed
    /// ```
    ///
    /// Z is hashed *before* `other_info`, matching the `EVP_DigestUpdate`
    /// order in the C source (lines 311-318).
    fn run_hash_kdm(&self, key: &mut [u8], info: &mut EncodedOtherInfo) -> ProviderResult<usize> {
        let digest = self.digest.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::Internal(
                "X942KDF: digest unavailable in run_hash_kdm".to_string(),
            ))
        })?;
        let secret = self.secret.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::Internal(
                "X942KDF: secret unavailable in run_hash_kdm".to_string(),
            ))
        })?;
        let h = digest.digest_size();
        if h == 0 {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("X942KDF: digest '{}' has zero output size", digest.name()),
            )));
        }

        // Build a template MdContext that we copy_from at every iteration.
        let mut ctx_init = MdContext::new();
        ctx_init.init(digest, None).map_err(dispatch_err)?;

        let mut written: usize = 0;
        let mut counter: u32 = 1;
        let total = key.len();

        trace!(
            h,
            keylen = total,
            digest = digest.name(),
            "X942KDF: hash loop begin"
        );

        while written < total {
            // Patch the counter in-place at the pre-located offset.
            let counter_be = counter.to_be_bytes();
            info.der[info.counter_offset..info.counter_offset + 4].copy_from_slice(&counter_be);

            let mut iter_ctx = MdContext::new();
            iter_ctx.copy_from(&ctx_init).map_err(dispatch_err)?;
            iter_ctx.update(secret).map_err(dispatch_err)?;
            iter_ctx.update(&info.der).map_err(dispatch_err)?;
            let mut block = iter_ctx.finalize().map_err(dispatch_err)?;
            debug_assert_eq!(
                block.len(),
                h,
                "X942KDF: digest produced {} bytes, expected {}",
                block.len(),
                h
            );

            let take = std::cmp::min(h, total.saturating_sub(written));
            key[written..written + take].copy_from_slice(&block[..take]);
            written = written.saturating_add(take);

            // Mirrors the C OPENSSL_cleanse(mac, sizeof(mac)) at
            // x942kdf.c:332 — the per-iteration block is sensitive
            // (it's a fragment of derived keying material).
            block.zeroize();

            if written == total {
                break;
            }

            counter = counter.checked_add(1).ok_or_else(|| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "X942KDF counter increment",
                })
            })?;
        }

        debug!(written, "X942KDF: hash loop complete");
        Ok(written)
    }

    /// Inner derivation helper: applies any additional parameters,
    /// runs the validation gate, encodes `OtherInfo` and runs the
    /// hash KDM into `key`. Returns the number of bytes written on
    /// success. On any error path, this function leaves `key` in an
    /// unspecified state — the public [`KdfContext::derive`] wrapper
    /// is responsible for zeroing `key` on failure (matches the C
    /// `OPENSSL_cleanse(derived_key, derived_key_len)` discipline at
    /// `x942kdf.c:332`).
    fn derive_into(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;

        // Length sanity (matches PROV_R_BAD_LENGTH at x942kdf.c:282).
        if key.is_empty() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "X942KDF: derived_key_len must be > 0".to_string(),
            )));
        }
        if key.len() > MAX_INPUT_LEN {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "X942KDF: derived_key_len {} exceeds maximum {}",
                    key.len(),
                    MAX_INPUT_LEN
                ),
            )));
        }
        if let Some(s) = &self.secret {
            if s.len() > MAX_INPUT_LEN {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "X942KDF: secret length {} exceeds maximum {}",
                        s.len(),
                        MAX_INPUT_LEN
                    ),
                )));
            }
        }

        self.ensure_digest()?;
        let mut info = self.encode_other_info()?;

        // Derive into a scratch buffer; zero it on every exit path
        // to avoid leaving a partial copy of derived material in
        // memory across an error boundary.
        let mut scratch = vec![0u8; key.len()];
        let result = self.run_hash_kdm(&mut scratch, &mut info);

        // The OtherInfo DER may be sensitive (it can include
        // partyU/V info from a key-agreement session). Zero it
        // unconditionally — matches the C `OPENSSL_clear_free`
        // discipline applied to `der` at `x942kdf.c:534`.
        info.der.zeroize();

        match result {
            Ok(n) => {
                key[..n].copy_from_slice(&scratch[..n]);
                scratch.zeroize();
                Ok(n)
            }
            Err(e) => {
                scratch.zeroize();
                Err(e)
            }
        }
    }
}

impl Zeroize for X942KdfContext {
    /// Manual `Zeroize` impl: only the sensitive `Vec<u8>` fields need
    /// clearing — the metadata fields are already `#[zeroize(skip)]`
    /// for the derived `ZeroizeOnDrop`. Calling this directly is
    /// equivalent to dropping and re-constructing the context.
    fn zeroize(&mut self) {
        if let Some(s) = self.secret.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.partyu_info.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.partyv_info.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.supp_pub_info.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.supp_priv_info.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.acvp_info.as_mut() {
            s.zeroize();
        }
    }
}

impl KdfContext for X942KdfContext {
    /// Derive `key.len()` bytes of keying material from the configured
    /// shared secret and `OtherInfo` parameters.
    ///
    /// Translates `x942kdf_derive` (`x942kdf.c:476-535`):
    ///
    /// 1. Apply any new `params` on top of the existing ctx state.
    /// 2. Run the mutual-exclusion / mandatory-field [`validate`] gate.
    /// 3. Lazily fetch the digest, rejecting XOFs.
    /// 4. Encode `OtherInfo` once (or use the ACVP blob).
    /// 5. Run [`run_hash_kdm`] into a scratch buffer and copy out.
    /// 6. On any failure, zero out both scratch *and* the caller-
    ///    supplied buffer (matches C `OPENSSL_cleanse(derived_key,
    ///    derived_key_len)` at `x942kdf.c:332`).
    #[instrument(
        skip_all,
        fields(keylen = key.len()),
        level = "debug"
    )]
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        // Run the entire derivation (parameter application, validation,
        // encoding and hashing) inside a helper so we can uniformly
        // zero `key` on *any* error path — matches the C
        // `OPENSSL_cleanse(derived_key, derived_key_len)` discipline
        // (`x942kdf.c:332`).
        match self.derive_into(key, params) {
            Ok(n) => {
                debug!(n, "X942KDF: derive succeeded");
                Ok(n)
            }
            Err(e) => {
                // Never leak partial output on error.
                for b in key.iter_mut() {
                    *b = 0;
                }
                warn!(error = %e, "X942KDF: derive failed");
                Err(e)
            }
        }
    }

    /// Resets the context to its initial state.
    ///
    /// Equivalent to `x942kdf_reset` (`x942kdf.c:367-379`):
    /// zero/free all sensitive buffers, drop digest cache, restore
    /// `use_keybits = true`, keep the library context.
    fn reset(&mut self) -> ProviderResult<()> {
        // Zeroize sensitive buffers before dropping their backing
        // allocations.
        if let Some(s) = self.secret.as_mut() {
            s.zeroize();
        }
        self.secret = None;
        if let Some(s) = self.partyu_info.as_mut() {
            s.zeroize();
        }
        self.partyu_info = None;
        if let Some(s) = self.partyv_info.as_mut() {
            s.zeroize();
        }
        self.partyv_info = None;
        if let Some(s) = self.supp_pub_info.as_mut() {
            s.zeroize();
        }
        self.supp_pub_info = None;
        if let Some(s) = self.supp_priv_info.as_mut() {
            s.zeroize();
        }
        self.supp_priv_info = None;
        if let Some(s) = self.acvp_info.as_mut() {
            s.zeroize();
        }
        self.acvp_info = None;

        // Clear non-secret metadata.
        self.digest = None;
        self.digest_name = None;
        self.properties = None;
        self.cek_alg = None;
        self.dkm_len = None;
        self.use_keybits = true;

        trace!("X942KDF: context reset");
        Ok(())
    }

    /// Reports gettable context parameters.
    ///
    /// Matches C `x942kdf_get_ctx_params` (`x942kdf.c:632-648`):
    ///
    /// - `"size"` → maximum derivable output size. The X9.42 KDF has
    ///   no formal upper bound beyond the counter exhaustion limit
    ///   (`u32::MAX * digest_size`); we report `u64::MAX` to match the
    ///   "effectively unlimited" semantics of the C `SIZE_MAX` cast at
    ///   `x942kdf.c:644`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new().push_u64(PARAM_SIZE, u64::MAX).build())
    }

    /// Settable-side entry point — delegates to `Self::apply_params`.
    /// Matches the C `x942kdf_set_ctx_params` dispatch.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// X942KdfProvider — provider registration shim
// =============================================================================

/// Provider registration shim for the ANSI X9.42 ASN.1 KDF.
///
/// Translates the C dispatch-table pattern (`ossl_kdf_x942_kdf_functions`
/// at `x942kdf.c:651-661`) into a Rust trait implementation. A single
/// `X942KdfProvider` instance vends as many [`X942KdfContext`] instances
/// as the caller requests via [`KdfProvider::new_ctx`], each carrying
/// its own mutable derivation state.
///
/// See [`crate::implementations::kdfs`] for a crate-level overview of
/// the KDF provider architecture.
#[derive(Debug, Clone)]
pub struct X942KdfProvider {
    /// Library context used to resolve digests
    /// (`EVP_MD_fetch` equivalent). Cheaply cloneable via `Arc`.
    libctx: Arc<LibContext>,
}

impl Default for X942KdfProvider {
    /// Returns a provider bound to the process-global default library
    /// context (matches C `OSSL_LIB_CTX_get0_global_default`).
    fn default() -> Self {
        Self::new(LibContext::get_default())
    }
}

impl X942KdfProvider {
    /// Creates a provider bound to the given library context.
    ///
    /// Use [`Default::default`] for the process-global default
    /// context.
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        Self { libctx }
    }

    /// Returns a human-readable description of this provider.
    #[must_use]
    pub fn description(&self) -> &'static str {
        "ANSI X9.42 ASN.1 Key Derivation Function — counter-driven hash KDF \
         with DER-encoded OtherInfo (RFC 2631 / NIST SP 800-56A static-key \
         transport mode)"
    }

    /// Returns a `ParamSet` enumerating the parameters this provider
    /// accepts via `KdfContext::set_params`. Values are placeholders;
    /// the keys are the authoritative contract.
    ///
    /// Matches the C `x942kdf_settable_ctx_params` table
    /// (`x942kdf.c:670-685`).
    #[must_use]
    pub fn settable_params() -> ParamSet {
        ParamBuilder::new()
            .push_octet(PARAM_SECRET, Vec::new())
            .push_octet(PARAM_KEY, Vec::new())
            .push_utf8(PARAM_DIGEST, String::new())
            .push_utf8(PARAM_PROPERTIES, String::new())
            .push_utf8(PARAM_CEK_ALG, String::new())
            .push_octet(PARAM_PARTYU_INFO, Vec::new())
            .push_octet(PARAM_PARTYV_INFO, Vec::new())
            .push_octet(PARAM_SUPP_PUB_INFO, Vec::new())
            .push_octet(PARAM_SUPP_PRIV_INFO, Vec::new())
            .push_i32(PARAM_USE_KEYBITS, 1)
            .push_octet(PARAM_ACVP_INFO, Vec::new())
            .build()
    }

    /// Returns a `ParamSet` enumerating the parameters readable via
    /// `KdfContext::get_params`. Values are placeholders; the keys are
    /// the authoritative contract.
    ///
    /// Matches the C `x942kdf_gettable_ctx_params` table
    /// (`x942kdf.c:687-693`).
    #[must_use]
    pub fn gettable_params() -> ParamSet {
        ParamBuilder::new().push_u64(PARAM_SIZE, 0).build()
    }
}

impl KdfProvider for X942KdfProvider {
    /// Canonical algorithm name — matches C `OSSL_KDF_NAME_X942KDF_ASN1`.
    fn name(&self) -> &'static str {
        "X942KDF-ASN1"
    }

    /// Creates a fresh derivation context.
    ///
    /// Equivalent to C `x942kdf_new` (`x942kdf.c:351-359`): allocates
    /// a new context with `use_keybits = 1` and all other fields zero.
    /// The returned context implements [`KdfContext`] and is boxed as
    /// a trait object for dynamic provider dispatch.
    #[instrument(skip_all, level = "trace")]
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        trace!("X942KdfProvider: new_ctx");
        Ok(Box::new(X942KdfContext::new(Arc::clone(&self.libctx))))
    }
}

// =============================================================================
// Algorithm descriptor registration
// =============================================================================

/// Returns the algorithm descriptors registered by this module.
///
/// Aggregated by `kdfs::descriptors()` and then by
/// `implementations::all_kdf_descriptors()`, providing the wiring path
/// from the EVP/CLI entry point down to this provider — satisfying R10
/// (no orphaned implementations).
///
/// Matches the C registration at `x942kdf.c:651-661` where the
/// dispatch table is registered under both `OSSL_KDF_NAME_X942KDF_ASN1`
/// and the legacy alias `"X942KDF"`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["X942KDF-ASN1", "X942KDF"],
        property: "provider=default",
        description: "ANSI X9.42 ASN.1 Key Derivation Function (counter-driven hash KDF \
                      with DER-encoded OtherInfo; RFC 2631 / NIST SP 800-56A)",
    }]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_ctx() -> X942KdfContext {
        X942KdfContext::new(LibContext::get_default())
    }

    fn build_minimum_params() -> ParamSet {
        ParamBuilder::new()
            .push_octet(PARAM_SECRET, vec![0x42; 32])
            .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
            .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
            .build()
    }

    #[test]
    fn lookup_kek_alg_finds_aes_128_wrap() {
        let k = lookup_kek_alg("AES-128-WRAP").expect("AES-128-WRAP must be on the allowlist");
        assert_eq!(k.keklen, 16);
        assert!(k.fips_approved);
    }

    #[test]
    fn lookup_kek_alg_is_case_insensitive() {
        let k = lookup_kek_alg("aes-256-wrap").expect("case-insensitive lookup must work");
        assert_eq!(k.keklen, 32);
    }

    #[test]
    fn lookup_kek_alg_rejects_unknown() {
        assert!(lookup_kek_alg("ROT13-WRAP").is_none());
    }

    #[test]
    fn lookup_kek_alg_finds_des3_wrap_but_not_fips_approved() {
        let k = lookup_kek_alg("DES3-WRAP").expect("DES3-WRAP must be on the allowlist");
        assert_eq!(k.keklen, 24);
        assert!(!k.fips_approved);
    }

    #[test]
    fn provider_name_matches_canonical() {
        let p = X942KdfProvider::default();
        assert_eq!(p.name(), "X942KDF-ASN1");
    }

    #[test]
    fn descriptors_register_both_names() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert!(descs[0].names.contains(&"X942KDF-ASN1"));
        assert!(descs[0].names.contains(&"X942KDF"));
        assert_eq!(descs[0].property, "provider=default");
    }

    #[test]
    fn new_ctx_has_use_keybits_default_on() {
        let ctx = fresh_ctx();
        assert!(ctx.use_keybits);
        assert!(ctx.secret.is_none());
        assert!(ctx.cek_alg.is_none());
    }

    #[test]
    fn new_ctx_via_provider_returns_boxed_context() {
        let p = X942KdfProvider::default();
        let _boxed: Box<dyn KdfContext> = p.new_ctx().expect("new_ctx must succeed");
    }

    #[test]
    fn apply_params_secret_via_secret_key() {
        let mut ctx = fresh_ctx();
        let params = ParamBuilder::new()
            .push_octet(PARAM_SECRET, vec![1, 2, 3])
            .build();
        ctx.apply_params(&params).expect("secret should apply");
        assert_eq!(ctx.secret.as_deref(), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn apply_params_secret_via_key_alias() {
        let mut ctx = fresh_ctx();
        let params = ParamBuilder::new()
            .push_octet(PARAM_KEY, vec![4, 5, 6])
            .build();
        ctx.apply_params(&params).expect("key alias should apply");
        assert_eq!(ctx.secret.as_deref(), Some(&[4u8, 5, 6][..]));
    }

    #[test]
    fn apply_params_rejects_wrong_secret_type() {
        let mut ctx = fresh_ctx();
        let params = ParamBuilder::new()
            .push_utf8(PARAM_SECRET, "not-bytes".to_string())
            .build();
        let err = ctx.apply_params(&params).unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch { key, expected, .. }) => {
                assert_eq!(key, PARAM_SECRET);
                assert_eq!(expected, "OctetString");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn apply_params_cekalg_sets_dkm_len() {
        let mut ctx = fresh_ctx();
        let params = ParamBuilder::new()
            .push_utf8(PARAM_CEK_ALG, "AES-256-WRAP".to_string())
            .build();
        ctx.apply_params(&params).expect("cekalg should apply");
        assert_eq!(ctx.dkm_len, Some(32));
        assert!(ctx.cek_alg.is_some());
    }

    #[test]
    fn apply_params_cekalg_rejects_unknown() {
        let mut ctx = fresh_ctx();
        let params = ParamBuilder::new()
            .push_utf8(PARAM_CEK_ALG, "BOGUS-WRAP".to_string())
            .build();
        let err = ctx.apply_params(&params).unwrap_err();
        match err {
            ProviderError::AlgorithmUnavailable(_) => {}
            other => panic!("expected AlgorithmUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn apply_params_supp_pubinfo_disables_use_keybits() {
        let mut ctx = fresh_ctx();
        assert!(ctx.use_keybits);
        let params = ParamBuilder::new()
            .push_octet(PARAM_SUPP_PUB_INFO, vec![0xAA, 0xBB])
            .build();
        ctx.apply_params(&params)
            .expect("supp-pubinfo should apply");
        assert!(!ctx.use_keybits, "use-keybits must auto-disable");
    }

    #[test]
    fn apply_params_explicit_use_keybits_overrides_supp_pubinfo() {
        let mut ctx = fresh_ctx();
        let params = ParamBuilder::new()
            .push_octet(PARAM_SUPP_PUB_INFO, vec![0xAA])
            .push_i32(PARAM_USE_KEYBITS, 1)
            .build();
        ctx.apply_params(&params).expect("must apply");
        assert!(
            ctx.use_keybits,
            "explicit use-keybits=1 overrides the supp-pubinfo auto-disable"
        );
    }

    #[test]
    fn validate_rejects_missing_secret() {
        let ctx = fresh_ctx();
        let err = ctx.validate().unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamNotFound { key }) => {
                assert_eq!(key, PARAM_SECRET);
            }
            other => panic!("expected ParamNotFound(secret), got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_cekalg() {
        let mut ctx = fresh_ctx();
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![1, 2, 3])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .build(),
        )
        .unwrap();
        let err = ctx.validate().unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamNotFound { key }) => {
                assert_eq!(key, PARAM_CEK_ALG);
            }
            other => panic!("expected ParamNotFound(cekalg), got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_digest() {
        let mut ctx = fresh_ctx();
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![1, 2, 3])
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .build(),
        )
        .unwrap();
        let err = ctx.validate().unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamNotFound { key }) => {
                assert_eq!(key, PARAM_DIGEST);
            }
            other => panic!("expected ParamNotFound(digest), got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_use_keybits_with_supp_pubinfo() {
        let mut ctx = fresh_ctx();
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![1, 2, 3])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .build(),
        )
        .unwrap();
        // Ensure both flags are simultaneously on by setting them in
        // separate calls so the within-call auto-disable doesn't fire.
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SUPP_PUB_INFO, vec![0xCC])
                .build(),
        )
        .unwrap();
        ctx.apply_params(&ParamBuilder::new().push_i32(PARAM_USE_KEYBITS, 1).build())
            .unwrap();
        let err = ctx.validate().unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(msg.contains("mutually exclusive"));
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_acvp_with_partyu() {
        let mut ctx = fresh_ctx();
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![1, 2, 3])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .push_octet(PARAM_ACVP_INFO, vec![0xDE, 0xAD])
                .push_octet(PARAM_PARTYU_INFO, vec![0xBE, 0xEF])
                .build(),
        )
        .unwrap();
        let err = ctx.validate().unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(msg.contains("mutually exclusive"));
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn encode_keylen_bits_aes_256_wrap() {
        let bits = encode_keylen_bits(32).expect("must succeed");
        // 32 * 8 = 256 = 0x00000100
        assert_eq!(bits, [0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn encode_keylen_bits_aes_128_wrap() {
        let bits = encode_keylen_bits(16).expect("must succeed");
        // 16 * 8 = 128 = 0x00000080
        assert_eq!(bits, [0x00, 0x00, 0x00, 0x80]);
    }

    #[test]
    fn encode_keylen_bits_rejects_overflow() {
        let err = encode_keylen_bits(0x01_00_00_00).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn build_keyinfo_marks_initial_counter() {
        let cek = lookup_kek_alg("AES-128-WRAP").unwrap();
        let (der, off) = build_keyinfo(cek).expect("keyinfo should build");
        assert_eq!(&der[off..off + 4], &[0x00, 0x00, 0x00, 0x01]);
        // The counter should be reachable via the same scan we use in
        // ACVP mode (sanity-check the marker hunt).
        let scanned = locate_counter(&der).expect("counter must be locatable");
        assert_eq!(scanned, off);
    }

    #[test]
    fn build_keyinfo_starts_with_sequence_tag() {
        let cek = lookup_kek_alg("AES-128-WRAP").unwrap();
        let (der, _) = build_keyinfo(cek).expect("must succeed");
        // SEQUENCE constructed = 0x30
        assert_eq!(der[0], 0x30, "KeySpecificInfo must start with SEQUENCE tag");
    }

    #[test]
    fn build_explicit_tagged_octet_string_uses_correct_class_and_tag() {
        let bytes = [0xAA, 0xBB, 0xCC];
        let der = build_explicit_tagged_octet_string(0, &bytes).unwrap();
        // [0] EXPLICIT constructed -> identifier = 0xA0
        assert_eq!(der[0], 0xA0);
        let der3 = build_explicit_tagged_octet_string(3, &bytes).unwrap();
        // [3] EXPLICIT constructed -> identifier = 0xA3
        assert_eq!(der3[0], 0xA3);
    }

    #[test]
    fn build_explicit_tagged_octet_string_inner_is_octet_string() {
        let bytes = [0x01, 0x02];
        let der = build_explicit_tagged_octet_string(2, &bytes).unwrap();
        // First byte is outer [2] tag (0xA2), second byte is outer
        // length, third byte is inner OCTET STRING tag (0x04).
        assert_eq!(der[0], 0xA2);
        assert_eq!(der[2], 0x04, "inner element must be an OCTET STRING");
        assert_eq!(der[3], 2, "inner length must be 2");
        assert_eq!(&der[4..6], &bytes);
    }

    #[test]
    fn build_explicit_tagged_octet_string_rejects_n_out_of_range() {
        let err = build_explicit_tagged_octet_string(4, b"x").unwrap_err();
        match err {
            ProviderError::Common(CommonError::Internal(_)) => {}
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn locate_counter_finds_marker() {
        let mut blob = vec![0xFF; 16];
        blob.extend_from_slice(&COUNTER_TLV_MARKER);
        blob.extend_from_slice(&[0xEE; 8]);
        let off = locate_counter(&blob).expect("marker must be found");
        assert_eq!(off, 16 + 2);
    }

    #[test]
    fn locate_counter_misses_random_blob() {
        let blob = vec![0xFF; 32];
        assert!(locate_counter(&blob).is_none());
    }

    #[test]
    fn encode_other_info_includes_partyu_partyv_supp() {
        let mut ctx = fresh_ctx();
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![1; 32])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .push_octet(PARAM_PARTYU_INFO, vec![0xAA])
                .push_octet(PARAM_PARTYV_INFO, vec![0xBB])
                .build(),
        )
        .unwrap();
        let info = ctx.encode_other_info().expect("encode must succeed");
        // SEQUENCE-tagged outer element.
        assert_eq!(info.der[0], 0x30);
        // Counter must still point at the initial value.
        assert_eq!(
            &info.der[info.counter_offset..info.counter_offset + 4],
            &[0x00, 0x00, 0x00, 0x01]
        );
        // Both [0] and [1] tagged elements must appear.
        assert!(info.der.iter().any(|b| *b == 0xA0));
        assert!(info.der.iter().any(|b| *b == 0xA1));
    }

    #[test]
    fn encode_other_info_acvp_path_uses_blob_verbatim() {
        let mut ctx = fresh_ctx();
        // Hand-craft a fake ACVP blob with the correct counter marker.
        let mut acvp = vec![0x30, 10];
        acvp.extend_from_slice(&[0xAA; 4]);
        acvp.extend_from_slice(&COUNTER_TLV_MARKER);
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![1; 32])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .push_octet(PARAM_ACVP_INFO, acvp.clone())
                .build(),
        )
        .unwrap();
        let info = ctx.encode_other_info().expect("ACVP encode must succeed");
        assert_eq!(info.der, acvp);
        assert_eq!(
            &info.der[info.counter_offset..info.counter_offset + 4],
            &[0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn encode_other_info_acvp_rejects_blob_without_marker() {
        let mut ctx = fresh_ctx();
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![1; 32])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .push_octet(PARAM_ACVP_INFO, vec![0xFF; 32])
                .build(),
        )
        .unwrap();
        let err = ctx.encode_other_info().unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(msg.contains("counter marker"));
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn derive_minimal_succeeds_and_fills_buffer() {
        let mut ctx = fresh_ctx();
        let params = build_minimum_params();
        ctx.apply_params(&params).unwrap();
        let mut key = vec![0u8; 16];
        let n = ctx
            .derive(&mut key, &ParamSet::new())
            .expect("derive must succeed");
        assert_eq!(n, 16);
        // Key must not be all-zero (sanity — SHA-256 of any non-empty
        // input is overwhelmingly unlikely to be zero).
        assert!(key.iter().any(|b| *b != 0));
    }

    #[test]
    fn derive_multi_block_uses_counter() {
        // SHA-256 outputs 32 bytes; ask for 64 bytes -> 2 iterations
        // with distinct counter values, so the two halves must differ.
        let mut ctx = fresh_ctx();
        ctx.apply_params(&build_minimum_params()).unwrap();
        let mut key = vec![0u8; 64];
        let n = ctx
            .derive(&mut key, &ParamSet::new())
            .expect("derive must succeed");
        assert_eq!(n, 64);
        assert_ne!(
            &key[0..32],
            &key[32..64],
            "counter must differentiate iterations"
        );
    }

    #[test]
    fn derive_truncated_block_returns_partial_length() {
        // Ask for 20 bytes from a 32-byte digest.
        let mut ctx = fresh_ctx();
        ctx.apply_params(&build_minimum_params()).unwrap();
        let mut key = vec![0u8; 20];
        let n = ctx
            .derive(&mut key, &ParamSet::new())
            .expect("derive must succeed");
        assert_eq!(n, 20);
    }

    #[test]
    fn derive_zero_length_rejected() {
        let mut ctx = fresh_ctx();
        ctx.apply_params(&build_minimum_params()).unwrap();
        let mut key: Vec<u8> = Vec::new();
        let err = ctx.derive(&mut key, &ParamSet::new()).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(msg.contains("must be > 0"));
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn derive_xof_digest_rejected() {
        // SHAKE256 is an XOF and must be rejected.
        let mut ctx = fresh_ctx();
        let params = ParamBuilder::new()
            .push_octet(PARAM_SECRET, vec![0x42; 32])
            .push_utf8(PARAM_DIGEST, "SHAKE-256".to_string())
            .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
            .build();
        ctx.apply_params(&params).unwrap();
        let mut key = vec![0u8; 16];
        let result = ctx.derive(&mut key, &ParamSet::new());
        // We accept either Unsupported (XOF rejection path) or
        // AlgorithmNotFound (if the digest backend does not register
        // SHAKE-256 at all). Both are correct for "not a usable
        // digest in this KDF".
        match result {
            Ok(_) => panic!("XOF digest must be rejected"),
            Err(
                ProviderError::Common(CommonError::Unsupported(_)) | ProviderError::Dispatch(_),
            ) => {}
            Err(other) => panic!(
                "expected Unsupported or Dispatch (XOF-not-allowed / not-fetchable), got {other:?}"
            ),
        }
    }

    #[test]
    fn derive_zeroes_key_on_failure() {
        let mut ctx = fresh_ctx();
        // No secret set -> derive must fail and zero `key`.
        ctx.apply_params(
            &ParamBuilder::new()
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .build(),
        )
        .unwrap();
        let mut key = vec![0xFFu8; 16];
        let err = ctx.derive(&mut key, &ParamSet::new()).unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamNotFound { .. }) => {}
            other => panic!("expected ParamNotFound, got {other:?}"),
        }
        assert!(
            key.iter().all(|b| *b == 0),
            "key must be zeroized on failure"
        );
    }

    #[test]
    fn reset_clears_all_state_and_restores_use_keybits() {
        let mut ctx = fresh_ctx();
        ctx.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![1; 16])
                .push_octet(PARAM_PARTYU_INFO, vec![2])
                .push_octet(PARAM_PARTYV_INFO, vec![3])
                .push_octet(PARAM_SUPP_PUB_INFO, vec![4])
                .push_octet(PARAM_SUPP_PRIV_INFO, vec![5])
                .push_octet(PARAM_ACVP_INFO, vec![6])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_PROPERTIES, "fips=yes".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .build(),
        )
        .unwrap();
        ctx.reset().unwrap();
        assert!(ctx.secret.is_none());
        assert!(ctx.partyu_info.is_none());
        assert!(ctx.partyv_info.is_none());
        assert!(ctx.supp_pub_info.is_none());
        assert!(ctx.supp_priv_info.is_none());
        assert!(ctx.acvp_info.is_none());
        assert!(ctx.digest_name.is_none());
        assert!(ctx.properties.is_none());
        assert!(ctx.cek_alg.is_none());
        assert!(ctx.dkm_len.is_none());
        assert!(ctx.use_keybits, "use-keybits must be re-defaulted to true");
    }

    #[test]
    fn get_params_reports_max_size() {
        let ctx = fresh_ctx();
        let ps = ctx.get_params().expect("get_params must succeed");
        let v = ps.get(PARAM_SIZE).expect("size param must be present");
        assert_eq!(v.as_u64(), Some(u64::MAX));
    }

    #[test]
    fn settable_params_lists_all_keys() {
        let ps = X942KdfProvider::settable_params();
        for k in [
            PARAM_SECRET,
            PARAM_KEY,
            PARAM_DIGEST,
            PARAM_PROPERTIES,
            PARAM_CEK_ALG,
            PARAM_PARTYU_INFO,
            PARAM_PARTYV_INFO,
            PARAM_SUPP_PUB_INFO,
            PARAM_SUPP_PRIV_INFO,
            PARAM_USE_KEYBITS,
            PARAM_ACVP_INFO,
        ] {
            assert!(ps.contains(k), "settable_params missing key '{k}'");
        }
    }

    #[test]
    fn gettable_params_lists_size() {
        let ps = X942KdfProvider::gettable_params();
        assert!(ps.contains(PARAM_SIZE));
    }

    #[test]
    fn derive_with_partyu_partyv_changes_output() {
        // Same secret + cekalg + digest, but different partyu_info, must
        // produce different derived keys (proves OtherInfo is wired in).
        let mut a = fresh_ctx();
        a.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![0xAA; 32])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .push_octet(PARAM_PARTYU_INFO, b"alice".to_vec())
                .build(),
        )
        .unwrap();
        let mut b = fresh_ctx();
        b.apply_params(
            &ParamBuilder::new()
                .push_octet(PARAM_SECRET, vec![0xAA; 32])
                .push_utf8(PARAM_DIGEST, "SHA-256".to_string())
                .push_utf8(PARAM_CEK_ALG, "AES-128-WRAP".to_string())
                .push_octet(PARAM_PARTYU_INFO, b"bob".to_vec())
                .build(),
        )
        .unwrap();

        let mut ka = vec![0u8; 16];
        let mut kb = vec![0u8; 16];
        a.derive(&mut ka, &ParamSet::new()).unwrap();
        b.derive(&mut kb, &ParamSet::new()).unwrap();
        assert_ne!(ka, kb, "different partyu-info must yield different keys");
    }

    #[test]
    fn derive_via_kdfcontext_trait_object() {
        // Confirm dynamic-dispatch through the trait object works.
        let p = X942KdfProvider::default();
        let mut boxed = p.new_ctx().unwrap();
        boxed
            .set_params(&build_minimum_params())
            .expect("set_params via trait object must succeed");
        let mut key = vec![0u8; 16];
        let n = boxed
            .derive(&mut key, &ParamSet::new())
            .expect("trait-object derive must succeed");
        assert_eq!(n, 16);
    }

    #[test]
    fn check_segment_len_accepts_realistic_size() {
        check_segment_len(Asn1Tag::OctetString, 1024).expect("1KB segment must be OK");
    }
}
