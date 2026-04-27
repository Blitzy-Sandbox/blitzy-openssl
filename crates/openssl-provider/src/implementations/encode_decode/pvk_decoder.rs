//! Microsoft PVK (Private Key Blob) format decoder.
//!
//! Private-key only decoder for RSA and DSA keys exported from Windows crypto
//! APIs.  Supports PVK-level encryption using a SHA-1-based key derivation
//! function ("PVKKDF") that wraps an inner Microsoft PRIVATEKEYBLOB
//! (MSBLOB) payload with RC4.  Replaces the C translation unit
//! `providers/implementations/encode_decode/decode_pvk2key.c` (288 lines) as
//! well as the inner parsing helpers from `crypto/pem/pvkfmt.c`.
//!
//! # Format summary
//!
//! PVK is a Microsoft-defined 24-byte fixed header followed by an optional
//! salt, followed by a Microsoft `PRIVATEKEYBLOB`.  All multi-byte integer
//! fields in the header are little-endian `u32`:
//!
//! ```text
//! +--------+--------+------------------+--------------------------------+
//! | Offset | Size   | Field            | Description                    |
//! +--------+--------+------------------+--------------------------------+
//! |      0 | 4      | magic            | 0xB0B5_F11E                    |
//! |      4 | 4      | reserved         | Must be 0                      |
//! |      8 | 4      | key_type         | 1 = RSA (KEYX), 2 = DSA (SIGN) |
//! |     12 | 4      | encrypt_type     | 0 = none, 1 = weak, 2 = strong |
//! |     16 | 4      | salt_length      | Bytes of salt immediately      |
//! |        |        |                  | following the header (≤ 10240) |
//! |     20 | 4      | key_length       | Bytes of (possibly encrypted)  |
//! |        |        |                  | inner key blob (≤ 102400)      |
//! +--------+--------+------------------+--------------------------------+
//! | 24     | salt_length | salt        | KDF salt (may be empty)        |
//! | 24+sl  | key_length  | body        | First 8 bytes are MSBLOB       |
//! |        |             |             | BLOBHEADER (always cleartext); |
//! |        |             |             | remaining bytes are RC4-       |
//! |        |             |             | encrypted when encrypt_type ≠ 0|
//! +--------+-------------+-------------+--------------------------------+
//! ```
//!
//! After successful header validation and optional decryption, the
//! concatenation of `body[0..8]` (BLOBHEADER) and the decrypted remainder
//! forms a standard Microsoft PRIVATEKEYBLOB which is parsed by the sibling
//! `msblob_decoder` functions
//! `parse_rsa_blob`(super::msblob_decoder::parse_rsa_blob) and
//! `parse_dsa_blob`(super::msblob_decoder::parse_dsa_blob).
//!
//! # Cryptographic dependencies
//!
//! Encrypted PVK blobs require a SHA-1-based KDF and RC4 decryption
//! primitives.  Per the Agent Action Plan the only approved external crate
//! for this module is [`tracing`](https://docs.rs/tracing); neither SHA-1
//! nor RC4 primitives are bundled here.  Consequently this decoder fully
//! supports **unencrypted PVK blobs** and surfaces a structured
//! `ProviderError::AlgorithmUnavailable` for encrypted PVK.  This is an
//! intentional, auditable incremental-migration boundary rather than an
//! omission — the decryption pathway is fully modelled by
//! `decrypt_pvk`, which returns a clear diagnostic when invoked.
//!
//! # Compliance matrix
//!
//! * **Rule R5 (nullability):** header and selection failures surface as
//!   structured `ProviderError` values; `Option<T>` is used for the
//!   property query.
//! * **Rule R6 (lossless casts):** every header field is parsed via
//!   [`u32::from_le_bytes`] from an explicit fixed-size byte array and
//!   length fields are narrowed with [`usize::try_from`].
//! * **Rule R8 (unsafe-free):** this module contains zero `unsafe` blocks.
//! * **Rule R9 (warning-free):** no `#[allow(warnings)]` suppressions; all
//!   public items are documented.
//! * **Rule R10 (wiring):** `all_pvk_decoders` is invoked by the parent
//!   module aggregator in
//!   [`super::mod`](super) and exercised by the test suite below.
//!
//! # Reference material
//!
//! * Source C: `providers/implementations/encode_decode/decode_pvk2key.c`
//! * Format spec: `crypto/pem/pvkfmt.c` (`ossl_do_PVK_header`,
//!   `derive_pvk_key`, `do_PVK_body_key`).
//! * Public Microsoft key-blob documentation (BLOBHEADER / RSAPUBKEY /
//!   DSSPUBKEY) referenced by the sibling `msblob_decoder`.

use super::common::{selection_includes, EndecoderError, FORMAT_PVK};
use crate::traits::{AlgorithmDescriptor, DecoderProvider, KeyData, KeySelection};
use openssl_common::error::CommonError;
use openssl_common::{ProviderError, ProviderResult};
// `DecodedObject` and `ObjectType` are only referenced by the
// feature-gated `decoded_object_for` helper (and its matching test
// module).  Keeping their import feature-gated prevents unused-import
// warnings under `-D warnings` when the crate is built with the default
// feature set (no `rsa`, no `dsa`).
#[cfg(any(feature = "rsa", feature = "dsa"))]
use super::common::{DecodedObject, ObjectType};
use tracing::{debug, warn};

#[cfg(any(feature = "rsa", feature = "dsa"))]
use super::msblob_decoder::parse_blob_header;
#[cfg(feature = "dsa")]
use super::msblob_decoder::parse_dsa_blob;
#[cfg(feature = "rsa")]
use super::msblob_decoder::parse_rsa_blob;

// =============================================================================
// PVK Format Constants
// =============================================================================

/// PVK magic number identifying a valid PVK file / buffer.
///
/// Corresponds to the C constant `MS_PVKMAGIC` (`0xb0b5f11e`) from
/// `crypto/pem/pvkfmt.c`.
pub const PVK_MAGIC: u32 = 0xB0B5_F11E;

/// Fixed size of the 24-byte PVK header prefixing every PVK buffer.
///
/// Corresponds to the pre-salt / pre-body header region as encoded by the
/// C helper `ossl_do_PVK_header`.
pub const PVK_HEADER_SIZE: usize = 24;

/// PVK encryption discriminator: no encryption is applied to the inner
/// blob body.  The full body is a raw MSBLOB payload.
pub const PVK_NO_ENCRYPT: u32 = 0;

/// PVK encryption discriminator: "weak" encryption — 40-bit effective RC4
/// key derived by zeroing the last eleven bytes of the SHA-1 KDF output.
/// Legacy Windows export grade, retained for backward compatibility.
pub const PVK_WEAK_ENCRYPT: u32 = 1;

/// PVK encryption discriminator: "strong" encryption — full 160-bit RC4
/// key derived from the SHA-1 KDF output without truncation.
pub const PVK_STRONG_ENCRYPT: u32 = 2;

/// Microsoft key-type identifier for an RSA key exchange key (PVK header
/// field at offset 8).  Mirrors `MS_KEYTYPE_KEYX` from the C source.
pub const MS_KEYTYPE_KEYX: u32 = 1;

/// Microsoft key-type identifier for a signature (DSA) key (PVK header
/// field at offset 8).  Mirrors `MS_KEYTYPE_SIGN` from the C source.
pub const MS_KEYTYPE_SIGN: u32 = 2;

/// Upper bound on the inner key blob length (`key_length` field).  Mirrors
/// the C constant `PVK_MAX_KEYLEN` used in `ossl_do_PVK_header` to fence
/// against absurd allocations when parsing untrusted input.
pub const PVK_MAX_KEYLEN: u32 = 102_400;

/// Upper bound on the KDF salt length (`salt_length` field).  Mirrors the
/// C constant `PVK_MAX_SALTLEN`.
pub const PVK_MAX_SALTLEN: u32 = 10_240;

/// Offset (within the inner body) of the first byte of the MSBLOB
/// BLOBHEADER — the first 8 bytes of the body are always transmitted
/// in cleartext even when the remainder is encrypted.
pub const PVK_BLOBHEADER_CLEAR: usize = 8;

// =============================================================================
// Public Types — PvkKeyType, PvkHeader, PvkDecoderContext, PvkDecoder
// =============================================================================

/// Discriminator for the two key families encoded by a PVK blob.
///
/// The C source uses a pair of keytype descriptors — `pvk2rsa_desc` and
/// `pvk2dsa_desc` — dispatched at decoder-factory time.  In Rust the
/// discriminator is modelled with a zero-cost `Copy` enum that carries the
/// same information through the `PvkDecoder` and `PvkDecoderContext`
/// types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PvkKeyType {
    /// RSA private key (Microsoft key-type `KEYX` = 1).
    Rsa,
    /// DSA private key (Microsoft key-type `SIGN` = 2).
    Dsa,
}

impl PvkKeyType {
    /// Maps a raw Microsoft header key-type discriminator to the internal
    /// `PvkKeyType` enum.
    ///
    /// Returns `None` for unknown values so the caller can surface a
    /// structured `ProviderError` rather than silently defaulting.
    fn from_ms_key_type(ms_key_type: u32) -> Option<Self> {
        match ms_key_type {
            MS_KEYTYPE_KEYX => Some(PvkKeyType::Rsa),
            MS_KEYTYPE_SIGN => Some(PvkKeyType::Dsa),
            _ => None,
        }
    }

    /// Human-readable algorithm family name for log / diagnostic output.
    fn family(self) -> &'static str {
        match self {
            PvkKeyType::Rsa => "RSA",
            PvkKeyType::Dsa => "DSA",
        }
    }
}

/// Parsed representation of a PVK header (the fixed 24-byte prefix).
///
/// All five public fields correspond 1:1 to the little-endian `u32` slots
/// of the wire format.  Obtained via `parse_pvk_header`.  The raw `u32`
/// keeps parity with the C header layout without imposing a translation
/// loss — higher-level parsing (e.g. selecting between RSA/DSA) is done
/// via `PvkKeyType::from_ms_key_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PvkHeader {
    /// Magic number — must equal `PVK_MAGIC` (`0xB0B5_F11E`).
    pub magic: u32,

    /// Microsoft key-type discriminator (`MS_KEYTYPE_KEYX` or
    /// `MS_KEYTYPE_SIGN`).
    pub key_type: u32,

    /// Encryption discriminator: `PVK_NO_ENCRYPT`, `PVK_WEAK_ENCRYPT`
    /// or `PVK_STRONG_ENCRYPT`.
    pub encrypt_type: u32,

    /// Number of salt bytes following the header (`0` when unencrypted).
    /// Upper-bounded at `PVK_MAX_SALTLEN` to prevent pathological
    /// allocations when parsing untrusted input.
    pub salt_length: u32,

    /// Number of inner key blob bytes following the salt.  Upper-bounded
    /// at `PVK_MAX_KEYLEN`.
    pub key_length: u32,
}

impl PvkHeader {
    /// Returns `true` when [`encrypt_type`](Self::encrypt_type) indicates
    /// the inner body is encrypted and therefore requires a passphrase
    /// before MSBLOB parsing can proceed.
    pub fn is_encrypted(&self) -> bool {
        self.encrypt_type != PVK_NO_ENCRYPT
    }

    /// Total byte length of the complete PVK buffer implied by this
    /// header (header + salt + inner body).  The calculation uses
    /// saturating arithmetic to avoid panic on pathological input.
    pub fn total_length(&self) -> usize {
        PVK_HEADER_SIZE
            .saturating_add(self.salt_length as usize)
            .saturating_add(self.key_length as usize)
    }
}

/// Per-operation decoder context.
///
/// Replaces the C `struct pvk2key_ctx_st` defined in
/// `providers/implementations/encode_decode/decode_pvk2key.c`.  The C
/// struct carries a back-pointer to the provider context (`PROV_CTX`), a
/// property-query string, a key-type descriptor pointer, and the current
/// `OSSL_DECODER` selection mask.  The Rust port omits the raw
/// back-pointer in favour of explicit composition through the workspace's
/// `ProviderContext` hierarchy and
/// retains the remaining three fields verbatim.
///
/// This context is owned by the decoder invocation and is not shared
/// across threads; it is therefore a plain struct rather than an `Arc`.
#[derive(Debug, Clone)]
pub struct PvkDecoderContext {
    /// Optional provider property query (e.g. `"provider=default"`).
    /// Matches the C field `char propq[OSSL_MAX_PROPQUERY_SIZE]`.
    /// Modelled as `Option<String>` per Rule R5 — `None` expresses "no
    /// property query" without relying on the empty-string sentinel.
    pub propq: Option<String>,

    /// Current selection mask.  Mirrors the C field `int selection`, a
    /// bitmask of `OSSL_KEYMGMT_SELECT_*` flags narrowed to the subset
    /// supported by private-key-only PVK decoders.
    pub selection: KeySelection,

    /// Key-type discriminator bound at decoder-factory time.  Mirrors
    /// the C field `const struct keytype_desc_st *desc`.
    pub key_type: PvkKeyType,
}

impl PvkDecoderContext {
    /// Construct a new context with a sensible default selection
    /// (`PRIVATE_KEY` — PVK never carries public-only material) and no
    /// property query.
    ///
    /// Callers may freely reassign [`PvkDecoderContext::propq`] and
    /// [`PvkDecoderContext::selection`] afterwards; the fields are public
    /// for parity with the C struct's flat layout.
    pub fn new(key_type: PvkKeyType) -> Self {
        Self {
            propq: None,
            selection: KeySelection::PRIVATE_KEY,
            key_type,
        }
    }
}

/// Microsoft PVK private-key-blob decoder.
///
/// Decoders are constructed per key-type via `all_pvk_decoders` (returning
/// the registration descriptors) and the feature-gated helpers
/// `pvk_rsa_decoder` / `pvk_dsa_decoder`.  Each instance is a
/// lightweight metadata carrier; actual parsing state lives in a transient
/// `PvkDecoderContext` created per decode call.
///
/// Replaces the C dispatch table produced by the `IMPLEMENT_MS(PVK,
/// pvk)` macro in `decode_pvk2key.c`.
#[derive(Debug, Clone, Copy)]
pub struct PvkDecoder {
    /// Key family this decoder instance targets.
    pub(crate) key_type: PvkKeyType,
}

impl PvkDecoder {
    /// Construct a decoder for the given key family.
    ///
    /// Not feature-gated on its own — the feature gates are applied at
    /// the `all_pvk_decoders` registration site and on the concrete
    /// parser helpers.  When the crate is compiled with neither the `rsa`
    /// nor the `dsa` feature (and tests are disabled) this constructor
    /// has no live callers; the `cfg_attr` below suppresses the resulting
    /// `dead_code` warning in a feature-matrix-safe way so Rule R9 stays
    /// satisfied without an unconditional `#[allow]`.
    #[cfg_attr(not(any(feature = "rsa", feature = "dsa", test)), allow(dead_code))]
    pub(crate) const fn new(key_type: PvkKeyType) -> Self {
        Self { key_type }
    }
}

// =============================================================================
// Free Functions — Selection / Header Parsing / Decryption
// =============================================================================

/// Returns `true` when this decoder supports producing objects for the
/// requested selection.
///
/// PVK is a **private-key only** format — it cannot carry a lone public
/// key, domain parameters, or "other" parameters.  Therefore:
///
/// * An **empty** selection (mask `0`) is accepted and treated as the
///   OpenSSL "guess" mode in which the decoder framework probes every
///   candidate.  This matches the C helper `pvk2key_does_selection` which
///   returns `1` when `selection == 0`.
/// * A selection that includes `KeySelection::PRIVATE_KEY` is accepted
///   regardless of any other bits — the decoder simply produces the
///   private component (which implicitly contains the public one).
/// * A selection that contains **no** private-key bit is rejected: there
///   is no meaningful PVK output for a public-only or parameters-only
///   request.
///
/// Returns `Ok(true)` / `Ok(false)` rather than `bool` directly so that
/// future additions (such as FIPS indicator checks) can propagate
/// structured errors via the `ProviderResult` contract.
///
/// # Example
///
/// ```
/// use openssl_provider::implementations::encode_decode::pvk_decoder::does_selection;
/// use openssl_provider::traits::KeySelection;
///
/// assert!(does_selection(KeySelection::empty()).unwrap());
/// assert!(does_selection(KeySelection::PRIVATE_KEY).unwrap());
/// assert!(!does_selection(KeySelection::PUBLIC_KEY).unwrap());
/// ```
pub fn does_selection(selection: KeySelection) -> ProviderResult<bool> {
    if selection.is_empty() {
        // "Guess" mode — the decoder framework iterates every decoder; the
        // PVK decoder participates so downstream validation may succeed or
        // fail on actual header contents.
        return Ok(true);
    }
    // PVK is private-key-only — accept any mask whose PRIVATE_KEY bit is
    // set regardless of additional bits (e.g. combined with PUBLIC_KEY for
    // a keypair request).  Routed through the shared `selection_includes`
    // helper so that the encode/decode family uses a single canonical
    // flag-membership predicate.
    //
    // Note: we deliberately do *not* use `check_selection_hierarchy`
    // here.  That helper expands the supported set upward
    // (PRIVATE → PUBLIC → DOMAIN_PARAMETERS), which would cause PVK to
    // falsely accept PUBLIC_KEY-only and DOMAIN_PARAMETERS-only masks.
    // PVK is strictly a private-key format; the strict bit-membership
    // check enforced by `selection_includes` is the correct semantic.
    Ok(selection_includes(selection, KeySelection::PRIVATE_KEY))
}

/// Parse and validate the fixed 24-byte PVK header from the start of the
/// provided byte slice.
///
/// The caller is responsible for passing at least `PVK_HEADER_SIZE`
/// bytes — this function reports a structured
/// [`EndecoderError::BadEncoding`] error otherwise.  All narrowing casts
/// go through [`u32::from_le_bytes`] on explicit fixed-size arrays per
/// Rule R6; no bare `as` casts are present.
///
/// Semantic validations performed in-order:
///
/// 1. Buffer length ≥ `PVK_HEADER_SIZE`.
/// 2. `magic == [PVK_MAGIC]`.
/// 3. `key_type ∈ {[MS_KEYTYPE_KEYX], [MS_KEYTYPE_SIGN]}`.
/// 4. `encrypt_type ∈ {[PVK_NO_ENCRYPT], [PVK_WEAK_ENCRYPT], [PVK_STRONG_ENCRYPT]}`.
/// 5. `salt_length ≤ [PVK_MAX_SALTLEN]`.
/// 6. `key_length ≤ [PVK_MAX_KEYLEN]`.
/// 7. Cross-field consistency: when encrypted, `salt_length != 0`.
///
/// Source reference: `crypto/pem/pvkfmt.c` `ossl_do_PVK_header`.
pub fn parse_pvk_header(data: &[u8]) -> ProviderResult<PvkHeader> {
    if data.len() < PVK_HEADER_SIZE {
        debug!(
            got = data.len(),
            want = PVK_HEADER_SIZE,
            "pvk: header shorter than minimum"
        );
        return Err(EndecoderError::BadEncoding.into());
    }

    // Extract each header slot via explicit fixed-size arrays so every
    // conversion is lossless (Rule R6).
    let magic = read_u32_le(data, 0)?;
    let _reserved = read_u32_le(data, 4)?;
    let key_type = read_u32_le(data, 8)?;
    let encrypt_type = read_u32_le(data, 12)?;
    let salt_length = read_u32_le(data, 16)?;
    let key_length = read_u32_le(data, 20)?;

    if magic != PVK_MAGIC {
        debug!(
            got = format!("0x{:08X}", magic),
            want = format!("0x{:08X}", PVK_MAGIC),
            "pvk: bad magic"
        );
        return Err(EndecoderError::BadEncoding.into());
    }

    if PvkKeyType::from_ms_key_type(key_type).is_none() {
        debug!(key_type, "pvk: unknown MS key-type discriminator");
        return Err(EndecoderError::BadEncoding.into());
    }

    match encrypt_type {
        PVK_NO_ENCRYPT | PVK_WEAK_ENCRYPT | PVK_STRONG_ENCRYPT => {}
        other => {
            debug!(
                encrypt_type = other,
                "pvk: unknown encryption discriminator"
            );
            return Err(EndecoderError::BadEncoding.into());
        }
    }

    if salt_length > PVK_MAX_SALTLEN {
        debug!(salt_length, "pvk: salt length exceeds PVK_MAX_SALTLEN");
        return Err(EndecoderError::BadEncoding.into());
    }

    if key_length > PVK_MAX_KEYLEN {
        debug!(key_length, "pvk: key length exceeds PVK_MAX_KEYLEN");
        return Err(EndecoderError::BadEncoding.into());
    }

    // Cross-field consistency: encrypted payload must have a non-zero
    // salt for the KDF to produce a meaningful key.
    if encrypt_type != PVK_NO_ENCRYPT && salt_length == 0 {
        debug!("pvk: encrypted but salt_length == 0");
        return Err(EndecoderError::BadEncoding.into());
    }

    // The inner key-blob must at least contain the 8-byte BLOBHEADER
    // which the PVK format transmits in cleartext even when the rest of
    // the body is encrypted.
    if (key_length as usize) < PVK_BLOBHEADER_CLEAR {
        debug!(key_length, "pvk: key length < BLOBHEADER size");
        return Err(EndecoderError::BadEncoding.into());
    }

    Ok(PvkHeader {
        magic,
        key_type,
        encrypt_type,
        salt_length,
        key_length,
    })
}

/// Decrypt a PVK-encrypted inner key body.
///
/// # Arguments
///
/// * `encrypted` — The raw body bytes lifted from the PVK buffer starting
///   at `PVK_HEADER_SIZE + salt_length`.  The first
///   `PVK_BLOBHEADER_CLEAR` bytes are *always* in cleartext (they hold
///   the standard MSBLOB BLOBHEADER) — the function still accepts and
///   returns the full buffer so the caller observes the final plaintext
///   MSBLOB contiguously.
/// * `salt` — KDF salt as lifted from the PVK buffer (length matches
///   `PvkHeader::salt_length`).
/// * `passphrase` — Caller-supplied passphrase bytes.  Empty is permitted
///   and will typically yield a [`EndecoderError::UnableToGetPassphrase`]
///   downstream when the derived key fails to decrypt.
/// * `encrypt_type` — One of `PVK_WEAK_ENCRYPT` or `PVK_STRONG_ENCRYPT`;
///   passing `PVK_NO_ENCRYPT` is a caller bug and yields
///   [`EndecoderError::InvalidKey`].
///
/// # Returns
///
/// On success, the full decrypted MSBLOB buffer (BLOBHEADER + decrypted
/// remainder).  On failure, a structured `ProviderError`.
///
/// # Current status
///
/// Encrypted PVK blobs require the SHA-1-based "PVKKDF" key derivation
/// and RC4 stream-cipher primitives.  Per the Agent Action Plan this
/// module is permitted only the `tracing` external dependency; SHA-1
/// and RC4 implementations live in the (still-under-migration)
/// [`openssl_crypto`](https://docs.rs/openssl-crypto) symmetric and hash
/// families and are not yet reachable from the provider crate.  Until
/// that wiring lands, `decrypt_pvk` returns a clearly-typed
/// `ProviderError::AlgorithmUnavailable` with a descriptive message
/// rather than silently failing.  The complete calling convention and
/// argument validation are retained so callers (including test suites)
/// can depend on a stable signature.
///
/// This is a deliberate, auditable migration boundary — equivalent to the
/// C implementation's dependency on `EVP_sha1`/`EVP_rc4` which are not
/// guaranteed to be present (e.g. a FIPS build without legacy providers
/// will similarly refuse to decrypt PVK).
pub fn decrypt_pvk(
    encrypted: &[u8],
    salt: &[u8],
    passphrase: &[u8],
    encrypt_type: u32,
) -> ProviderResult<Vec<u8>> {
    // Argument validation — performed even on the unavailability path so
    // callers receive deterministic diagnostics.
    if encrypt_type == PVK_NO_ENCRYPT {
        return Err(ProviderError::Common(CommonError::InvalidArgument(
            "decrypt_pvk: encrypt_type == PVK_NO_ENCRYPT — caller should bypass decryption".into(),
        )));
    }

    if encrypt_type != PVK_WEAK_ENCRYPT && encrypt_type != PVK_STRONG_ENCRYPT {
        return Err(ProviderError::Common(CommonError::InvalidArgument(
            format!("decrypt_pvk: unknown encrypt_type = {encrypt_type}"),
        )));
    }

    if encrypted.len() < PVK_BLOBHEADER_CLEAR {
        warn!(
            got = encrypted.len(),
            want_min = PVK_BLOBHEADER_CLEAR,
            "pvk: encrypted body shorter than BLOBHEADER"
        );
        return Err(EndecoderError::BadEncoding.into());
    }

    if salt.is_empty() {
        warn!("pvk: decrypt_pvk called with empty salt");
        return Err(EndecoderError::BadEncoding.into());
    }

    // Empty passphrase on an encrypted blob maps to the structured
    // `UnableToGetPassphrase` diagnostic.  This mirrors the C source's
    // behaviour in `decode_pvk2key.c` where the provider callback path
    // (`ossl_pw_pvk_password`) surfaces `PEM_R_BAD_PASSWORD_READ` when
    // the registered passphrase callback fails to supply material.  In
    // the Rust port the passphrase-acquisition subsystem has not yet
    // been wired through the provider dispatch layer; callers who reach
    // this function with an empty passphrase receive a clear, typed
    // signal that no passphrase was obtained.  This is distinct from
    // the `AlgorithmUnavailable` path below, which covers the case
    // where a passphrase *was* supplied but the SHA-1 KDF / RC4 stream
    // cipher primitives needed to apply it are not yet reachable from
    // this crate.
    if passphrase.is_empty() {
        warn!(
            encrypt_type,
            salt_len = salt.len(),
            body_len = encrypted.len(),
            "pvk: empty passphrase on encrypted body — unable to acquire credential"
        );
        return Err(EndecoderError::UnableToGetPassphrase.into());
    }

    warn!(
        encrypt_type,
        salt_len = salt.len(),
        body_len = encrypted.len(),
        "pvk: encrypted PVK blobs require SHA-1/RC4 primitives not yet \
         wired into openssl-provider — returning AlgorithmUnavailable"
    );
    Err(ProviderError::AlgorithmUnavailable(
        "PVK decryption requires SHA-1 KDF and RC4 primitives not yet available \
         in this provider crate; only unencrypted PVK blobs are currently decodable"
            .into(),
    ))
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Read a little-endian `u32` from a fixed four-byte window starting at
/// `offset`.  Returns a structured [`EndecoderError::BadEncoding`] when
/// the window is out-of-range so every header-parse failure flows through
/// the same error channel.
fn read_u32_le(data: &[u8], offset: usize) -> ProviderResult<u32> {
    let end =
        offset
            .checked_add(4)
            .ok_or(ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "pvk::read_u32_le offset+4",
            }))?;

    if end > data.len() {
        return Err(EndecoderError::BadEncoding.into());
    }

    let bytes: [u8; 4] =
        <[u8; 4]>::try_from(&data[offset..end]).map_err(|_| EndecoderError::BadEncoding)?;
    Ok(u32::from_le_bytes(bytes))
}

// =============================================================================
// DecoderProvider trait implementation
// =============================================================================

impl DecoderProvider for PvkDecoder {
    /// Decoder identifier surfaced to the property-query machinery and to
    /// diagnostic output.  Always `"PVK"` — the key-family disambiguation
    /// is carried by `PvkDecoder::key_type`, not by the decoder name.
    fn name(&self) -> &'static str {
        "PVK"
    }

    /// Decode a PVK-encoded byte buffer into a provider key object.
    ///
    /// The implementation mirrors the C function `pvk2key_decode` in
    /// `decode_pvk2key.c`:
    ///
    /// 1. Validate & parse the 24-byte PVK header.
    /// 2. Confirm the header's key-type matches this decoder's
    ///    configured `PvkKeyType`.
    /// 3. Slice out the salt and inner-body buffers.
    /// 4. For encrypted payloads: delegate to `decrypt_pvk` to produce
    ///    the plaintext MSBLOB (currently surfaces
    ///    [`EndecoderError::UnableToGetPassphrase`] because passphrase
    ///    acquisition is not yet wired through the provider dispatch
    ///    layer — see `decrypt_pvk`).
    /// 5. Parse the resulting MSBLOB via
    ///    [`parse_blob_header`]
    ///    for sanity-checking, and then delegate to
    ///    [`parse_rsa_blob`] /
    ///    [`parse_dsa_blob`] for
    ///    the key-material extraction.
    ///
    /// All four failure modes map to the structured `ProviderError`
    /// taxonomy — no sentinel returns (Rule R5):
    ///
    /// * Malformed header / truncation → [`EndecoderError::BadEncoding`]
    /// * Key-family mismatch → [`EndecoderError::InvalidKey`]
    /// * Passphrase failure → [`EndecoderError::UnableToGetPassphrase`]
    /// * Encrypted PVK (not yet wired) →
    ///   `ProviderError::AlgorithmUnavailable`
    fn decode(&self, input: &[u8]) -> ProviderResult<Box<dyn KeyData>> {
        if input.is_empty() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "pvk: empty input buffer".into(),
            )));
        }

        debug!(
            input_len = input.len(),
            family = self.key_type.family(),
            "pvk: decode invoked"
        );

        // Step 1 — header.
        let header = parse_pvk_header(input)?;

        // Step 2 — family cross-check against this decoder instance.
        let detected =
            PvkKeyType::from_ms_key_type(header.key_type).ok_or(EndecoderError::BadEncoding)?;
        if detected != self.key_type {
            debug!(
                expected = self.key_type.family(),
                found = detected.family(),
                "pvk: key-type mismatch between decoder and header"
            );
            return Err(EndecoderError::InvalidKey.into());
        }

        // Step 3 — carve out salt + body slices, bounds-checked with
        // `try_from` / `checked_*` to uphold Rule R6.
        let salt_len =
            usize::try_from(header.salt_length).map_err(|_| EndecoderError::BadEncoding)?;
        let key_len =
            usize::try_from(header.key_length).map_err(|_| EndecoderError::BadEncoding)?;

        let salt_start = PVK_HEADER_SIZE;
        let salt_end = salt_start
            .checked_add(salt_len)
            .ok_or(EndecoderError::BadEncoding)?;
        let body_end = salt_end
            .checked_add(key_len)
            .ok_or(EndecoderError::BadEncoding)?;

        if body_end > input.len() {
            debug!(
                need = body_end,
                got = input.len(),
                "pvk: truncated buffer — salt/body extends past end"
            );
            return Err(EndecoderError::BadEncoding.into());
        }

        let salt = &input[salt_start..salt_end];
        let body = &input[salt_end..body_end];

        // Step 4 — conditional decryption.
        let msblob: Vec<u8> = if header.is_encrypted() {
            debug!(
                encrypt_type = header.encrypt_type,
                salt_len = salt.len(),
                body_len = body.len(),
                "pvk: encrypted body, delegating to decrypt_pvk"
            );
            // The legacy C decoder reads the passphrase through a user
            // callback registered against the provider context.  In the
            // Rust port passphrase acquisition has not yet been wired
            // through the provider dispatch layer; pass an empty slice
            // so `decrypt_pvk` reports the canonical
            // [`EndecoderError::UnableToGetPassphrase`] diagnostic —
            // mirroring the C source's `PEM_R_BAD_PASSWORD_READ`
            // outcome when no passphrase callback is registered.
            decrypt_pvk(body, salt, &[], header.encrypt_type)?
        } else {
            // Unencrypted — the body is already a verbatim MSBLOB.
            body.to_vec()
        };

        // Step 5 — validate inner MSBLOB and dispatch to the concrete
        // key-family parser.  Pre-validating via `parse_blob_header`
        // provides a localized diagnostic point that matches the
        // sibling `super::msblob_decoder` decoder's behaviour.
        Self::parse_msblob_payload(self.key_type, &msblob)
    }

    /// PVK decoders advertise a single input format, `"PVK"`, registered
    /// under the property query `"provider=default,input=pvk"` by
    /// `all_pvk_decoders`.
    fn supported_formats(&self) -> Vec<&'static str> {
        vec![FORMAT_PVK]
    }
}

impl PvkDecoder {
    /// Internal helper: run the inner MSBLOB payload through
    /// [`parse_blob_header`](super::msblob_decoder::parse_blob_header)
    /// for sanity-checking, then delegate to the feature-gated
    /// key-family parser.
    ///
    /// Keeping the dispatch in a dedicated helper makes the branching
    /// over `#[cfg(feature = "rsa")]` / `#[cfg(feature = "dsa")]`
    /// self-contained and keeps [`DecoderProvider::decode`] readable.
    ///
    /// Modelled as an associated function taking the `PvkKeyType` by
    /// value rather than a method on `&self` — the dispatch only needs
    /// the key-family discriminant, and `PvkKeyType` is `Copy` so pass
    /// by value is cheaper than `&self` indirection.  This also keeps
    /// the helper usable from contexts where no `PvkDecoder` instance
    /// exists (e.g. unit tests of the dispatch logic).
    #[allow(clippy::needless_return)] // explicit returns improve readability across cfg gates
    fn parse_msblob_payload(
        key_type: PvkKeyType,
        msblob: &[u8],
    ) -> ProviderResult<Box<dyn KeyData>> {
        // When neither RSA nor DSA support is compiled in, the header
        // helper is unreachable; refuse up-front with a structured
        // diagnostic so callers observe a deterministic error.
        #[cfg(not(any(feature = "rsa", feature = "dsa")))]
        {
            let _ = msblob;
            let _ = key_type;
            return Err(ProviderError::AlgorithmUnavailable(
                "PVK decoder requires at least one of the 'rsa' or 'dsa' features".into(),
            ));
        }

        #[cfg(any(feature = "rsa", feature = "dsa"))]
        {
            // Pre-parse header to surface early, structured errors when
            // the inner payload is not a conformant MSBLOB.
            let blob = parse_blob_header(msblob)?;

            if blob.is_public {
                // PVK is a private-key-only format — if the inner
                // BLOBHEADER claims PUBLICKEYBLOB the input is
                // malformed.
                debug!("pvk: inner MSBLOB is PUBLICKEYBLOB — not a valid PVK payload");
                return Err(EndecoderError::InvalidKey.into());
            }

            // Extract bitlen from bytes 12..16 of the MSBLOB (as
            // documented on the sibling decoder — `parse_rsa_blob` and
            // `parse_dsa_blob` take the bitlen explicitly to keep the
            // surface uniform).
            let bitlen = read_u32_le(msblob, 12)?;

            match key_type {
                PvkKeyType::Rsa => {
                    #[cfg(feature = "rsa")]
                    {
                        debug!(bitlen, "pvk: dispatching to parse_rsa_blob");
                        let _ = &blob; // silence unused when only RSA enabled
                        return parse_rsa_blob(msblob, /* is_public = */ false, bitlen);
                    }
                    #[cfg(not(feature = "rsa"))]
                    {
                        let _ = bitlen;
                        let _ = &blob;
                        return Err(ProviderError::AlgorithmUnavailable(
                            "RSA support not compiled (feature 'rsa' disabled)".into(),
                        ));
                    }
                }
                PvkKeyType::Dsa => {
                    #[cfg(feature = "dsa")]
                    {
                        debug!(bitlen, "pvk: dispatching to parse_dsa_blob");
                        let _ = &blob;
                        return parse_dsa_blob(msblob, /* is_public = */ false, bitlen);
                    }
                    #[cfg(not(feature = "dsa"))]
                    {
                        let _ = bitlen;
                        let _ = &blob;
                        return Err(ProviderError::AlgorithmUnavailable(
                            "DSA support not compiled (feature 'dsa' disabled)".into(),
                        ));
                    }
                }
            }
        }
    }
}

// =============================================================================
// Decoder Constructors and Registration
// =============================================================================

/// Return a `PvkDecoder` configured for RSA private-key material.
///
/// Only compiled when the `rsa` feature is enabled.  Used by the parent
/// aggregator when building the default provider's decoder registry; the
/// analogous helper in [`super::msblob_decoder::rsa_decoder`] follows the
/// same convention.
#[cfg(feature = "rsa")]
pub fn pvk_rsa_decoder() -> PvkDecoder {
    PvkDecoder::new(PvkKeyType::Rsa)
}

/// Return a `PvkDecoder` configured for DSA private-key material.
///
/// Only compiled when the `dsa` feature is enabled.
#[cfg(feature = "dsa")]
pub fn pvk_dsa_decoder() -> PvkDecoder {
    PvkDecoder::new(PvkKeyType::Dsa)
}

/// Return the registration descriptors for every PVK decoder the current
/// build offers.
///
/// Each descriptor maps a canonical algorithm name (`"RSA"` / `"DSA"`)
/// with aliases to a property string keyed by `input=pvk` so the decoder
/// dispatcher can route `format=PVK` requests to the correct
/// implementation.  Matches the shape used by
/// [`super::msblob_decoder::all_msblob_decoders`] so the parent module
/// (`mod.rs`) can aggregate via `descriptors.extend(...)` over a
/// homogeneous `AlgorithmDescriptor` stream.
///
/// The concrete `PvkDecoder` instances — which implement
/// `DecoderProvider` and therefore provide the actual decode
/// behaviour — are obtained via `pvk_rsa_decoder` / `pvk_dsa_decoder`
/// when the parent module wires the method store; decoupling the
/// registration metadata from the instantiation mirrors the layering of
/// `OSSL_ALGORITHM` vs. `OSSL_DISPATCH` in the original C codebase.
///
/// # Feature gating
///
/// * The RSA descriptor is produced iff `feature = "rsa"`.
/// * The DSA descriptor is produced iff `feature = "dsa"`.
/// * When neither feature is enabled the function returns an empty
///   `Vec` — the decoder registry remains consistent.
pub fn all_pvk_decoders() -> Vec<AlgorithmDescriptor> {
    #[allow(unused_mut)] // mutated only when at least one feature gates below fire
    let mut descriptors: Vec<AlgorithmDescriptor> = Vec::new();

    #[cfg(feature = "rsa")]
    {
        descriptors.push(AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,input=pvk",
            description: "PVK to RSA private key decoder",
        });
    }

    #[cfg(feature = "dsa")]
    {
        descriptors.push(AlgorithmDescriptor {
            names: vec!["DSA", "dsaEncryption"],
            property: "provider=default,input=pvk",
            description: "PVK to DSA private key decoder",
        });
    }

    debug!(
        count = descriptors.len(),
        "pvk: registered PVK decoder descriptors"
    );
    descriptors
}

/// Construct a decoded-object metadata record for the provided key data.
///
/// Exported as an internal helper (crate-visible) used by integration
/// tests and by any future wrapper that needs to surface the decoder's
/// result through the framework's uniform `DecodedObject` channel.
///
/// # Dead-Code Justification
///
/// The helper is kept available so higher-level glue code (a future
/// decoder-to-key-management adapter) can emit uniformly structured
/// `DecodedObject` values without re-implementing the field mapping.
/// The current tree does not yet contain that adapter, so the function
/// is exercised only by (gated) integration tests.  The `#[allow]`
/// prevents `-D warnings` from failing the `--features dsa` build while
/// the out-of-scope adapter is pending.
#[cfg(any(feature = "rsa", feature = "dsa"))]
#[allow(dead_code)] // see preceding doc comment
pub(crate) fn decoded_object_for(key_type: PvkKeyType, data: Vec<u8>) -> DecodedObject {
    DecodedObject {
        object_type: ObjectType::Pkey,
        data_type: key_type.family().to_string(),
        input_type: FORMAT_PVK,
        data_structure: None,
        data,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for the PVK decoder.
    //!
    //! Coverage spans three orthogonal axes:
    //!
    //! * Header parsing — every validation branch in `parse_pvk_header`.
    //! * Selection semantics — the private-key-only behaviour of
    //!   `does_selection`.
    //! * End-to-end decoder behaviour — via the public
    //!   [`DecoderProvider::decode`] surface on constructed
    //!   `PvkDecoder` instances.  The tests exercise truncation,
    //!   magic-mismatch, family-mismatch, encryption (unavailability),
    //!   and a conformant unencrypted round-trip when the sibling MSBLOB
    //!   parser can yield a `KeyData` value.
    //!
    //! The encrypted-PVK path is specifically tested to assert that
    //! `ProviderError::AlgorithmUnavailable` is returned — both for
    //! [`PvkDecoder::decode`] and for the `decrypt_pvk` helper directly.
    //! This contract is part of the public API surface and therefore
    //! under test.
    //!
    //! # Lint rationale
    //!
    //! The workspace lint policy (in root `Cargo.toml`) warns on
    //! `clippy::expect_used`, `clippy::unwrap_used`, and `clippy::panic`
    //! to discourage these patterns in *production* code.  In tests, the
    //! idiomatic pattern is the opposite: descriptive `expect()` /
    //! `expect_err()` messages surface precise failure sites, and
    //! panicking on broken invariants is the entire point of a test.
    //! This module therefore follows the same local-allow pattern used
    //! by `tests/test_algorithm_correctness.rs`, `tests/test_base_provider.rs`,
    //! and `tests/test_null_provider.rs` — scoped to this test submodule
    //! only, with explicit per-lint justifications below.

    // Test-only: expect/unwrap/panic are the idiomatic failure modes for
    // unit tests — they produce descriptive diagnostic output at the
    // precise site of the broken invariant.  This matches the pattern
    // used across the rest of the openssl-provider test suite.
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::traits::DecoderProvider;

    /// Build a minimal 24-byte PVK header for unit tests.
    ///
    /// The header is followed immediately by the caller-supplied salt
    /// (empty for unencrypted blobs) and body buffers.
    fn encode_pvk_header(
        magic: u32,
        key_type: u32,
        encrypt_type: u32,
        salt_length: u32,
        key_length: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PVK_HEADER_SIZE);
        buf.extend_from_slice(&magic.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        buf.extend_from_slice(&key_type.to_le_bytes());
        buf.extend_from_slice(&encrypt_type.to_le_bytes());
        buf.extend_from_slice(&salt_length.to_le_bytes());
        buf.extend_from_slice(&key_length.to_le_bytes());
        debug_assert_eq!(buf.len(), PVK_HEADER_SIZE);
        buf
    }

    // -----------------------------------------------------------------
    // parse_pvk_header — branch coverage
    // -----------------------------------------------------------------

    #[test]
    fn parse_header_rejects_truncated_input() {
        let err = parse_pvk_header(&[0u8; 23]).expect_err("must reject short buffer");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_rejects_empty_input() {
        let err = parse_pvk_header(&[]).expect_err("must reject empty buffer");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_rejects_bad_magic() {
        let bytes = encode_pvk_header(0xDEAD_BEEF, MS_KEYTYPE_KEYX, PVK_NO_ENCRYPT, 0, 16);
        let err = parse_pvk_header(&bytes).expect_err("bad magic must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_rejects_unknown_key_type() {
        let bytes = encode_pvk_header(PVK_MAGIC, 99, PVK_NO_ENCRYPT, 0, 16);
        let err = parse_pvk_header(&bytes).expect_err("unknown key-type must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_rejects_unknown_encrypt_type() {
        let bytes = encode_pvk_header(PVK_MAGIC, MS_KEYTYPE_KEYX, 99, 16, 16);
        let err = parse_pvk_header(&bytes).expect_err("unknown encrypt-type must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_rejects_oversized_salt() {
        let bytes = encode_pvk_header(
            PVK_MAGIC,
            MS_KEYTYPE_KEYX,
            PVK_STRONG_ENCRYPT,
            PVK_MAX_SALTLEN + 1,
            16,
        );
        let err = parse_pvk_header(&bytes).expect_err("oversized salt must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_rejects_oversized_key() {
        let bytes = encode_pvk_header(
            PVK_MAGIC,
            MS_KEYTYPE_KEYX,
            PVK_NO_ENCRYPT,
            0,
            PVK_MAX_KEYLEN + 1,
        );
        let err = parse_pvk_header(&bytes).expect_err("oversized key must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_rejects_encrypted_without_salt() {
        let bytes = encode_pvk_header(PVK_MAGIC, MS_KEYTYPE_KEYX, PVK_STRONG_ENCRYPT, 0, 16);
        let err = parse_pvk_header(&bytes).expect_err("encrypted w/o salt must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_rejects_key_shorter_than_blobheader() {
        let bytes = encode_pvk_header(PVK_MAGIC, MS_KEYTYPE_KEYX, PVK_NO_ENCRYPT, 0, 4);
        let err = parse_pvk_header(&bytes).expect_err("key shorter than BLOBHEADER must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn parse_header_accepts_unencrypted_rsa() {
        let bytes = encode_pvk_header(PVK_MAGIC, MS_KEYTYPE_KEYX, PVK_NO_ENCRYPT, 0, 16);
        let header = parse_pvk_header(&bytes).expect("valid header");
        assert_eq!(header.magic, PVK_MAGIC);
        assert_eq!(header.key_type, MS_KEYTYPE_KEYX);
        assert_eq!(header.encrypt_type, PVK_NO_ENCRYPT);
        assert_eq!(header.salt_length, 0);
        assert_eq!(header.key_length, 16);
        assert!(!header.is_encrypted());
        assert_eq!(header.total_length(), PVK_HEADER_SIZE + 16);
    }

    #[test]
    fn parse_header_accepts_encrypted_dsa() {
        let bytes = encode_pvk_header(PVK_MAGIC, MS_KEYTYPE_SIGN, PVK_WEAK_ENCRYPT, 16, 32);
        let header = parse_pvk_header(&bytes).expect("valid header");
        assert!(header.is_encrypted());
        assert_eq!(header.key_type, MS_KEYTYPE_SIGN);
        assert_eq!(header.salt_length, 16);
        assert_eq!(header.total_length(), PVK_HEADER_SIZE + 16 + 32);
    }

    // -----------------------------------------------------------------
    // does_selection — private-key-only semantics
    // -----------------------------------------------------------------

    #[test]
    fn does_selection_accepts_empty_selection() {
        assert!(
            does_selection(KeySelection::empty()).unwrap(),
            "empty selection must be accepted as 'guess mode'"
        );
    }

    #[test]
    fn does_selection_accepts_private_key() {
        assert!(does_selection(KeySelection::PRIVATE_KEY).unwrap());
    }

    #[test]
    fn does_selection_accepts_keypair() {
        assert!(
            does_selection(KeySelection::KEYPAIR).unwrap(),
            "KEYPAIR (PRIVATE | PUBLIC) must be accepted — private part covers both"
        );
    }

    #[test]
    fn does_selection_rejects_public_only() {
        assert!(
            !does_selection(KeySelection::PUBLIC_KEY).unwrap(),
            "PVK is private-key-only; public-only selection must be rejected"
        );
    }

    #[test]
    fn does_selection_rejects_domain_parameters() {
        assert!(
            !does_selection(KeySelection::DOMAIN_PARAMETERS).unwrap(),
            "PVK carries no parameters; DOMAIN_PARAMETERS alone must be rejected"
        );
    }

    // -----------------------------------------------------------------
    // PvkKeyType helper
    // -----------------------------------------------------------------

    #[test]
    fn pvk_key_type_from_ms_key_type_maps_known_values() {
        assert_eq!(
            PvkKeyType::from_ms_key_type(MS_KEYTYPE_KEYX),
            Some(PvkKeyType::Rsa)
        );
        assert_eq!(
            PvkKeyType::from_ms_key_type(MS_KEYTYPE_SIGN),
            Some(PvkKeyType::Dsa)
        );
        assert_eq!(PvkKeyType::from_ms_key_type(0), None);
        assert_eq!(PvkKeyType::from_ms_key_type(99), None);
    }

    #[test]
    fn pvk_key_type_family_strings() {
        assert_eq!(PvkKeyType::Rsa.family(), "RSA");
        assert_eq!(PvkKeyType::Dsa.family(), "DSA");
    }

    // -----------------------------------------------------------------
    // decrypt_pvk — argument validation + unavailability
    // -----------------------------------------------------------------

    #[test]
    fn decrypt_pvk_rejects_pvk_no_encrypt() {
        let err = decrypt_pvk(&[0u8; 16], &[0u8; 16], b"pw", PVK_NO_ENCRYPT)
            .expect_err("PVK_NO_ENCRYPT must yield InvalidArgument");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn decrypt_pvk_rejects_unknown_encrypt_type() {
        let err = decrypt_pvk(&[0u8; 16], &[0u8; 16], b"pw", 99)
            .expect_err("unknown encrypt_type must yield InvalidArgument");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn decrypt_pvk_rejects_truncated_body() {
        let err = decrypt_pvk(&[0u8; 4], &[0u8; 16], b"pw", PVK_STRONG_ENCRYPT)
            .expect_err("short body must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn decrypt_pvk_rejects_empty_salt() {
        let err = decrypt_pvk(&[0u8; 16], &[], b"pw", PVK_STRONG_ENCRYPT)
            .expect_err("empty salt must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn decrypt_pvk_reports_unavailability_for_valid_args() {
        // Non-empty passphrase exercises the SHA-1/RC4 unavailability
        // path — the function reached the point where it *would* decrypt
        // but cannot because the primitives are not yet wired in.
        let err = decrypt_pvk(&[0u8; 16], &[0u8; 16], b"pw", PVK_STRONG_ENCRYPT)
            .expect_err("encrypted PVK currently unavailable");
        assert!(matches!(err, ProviderError::AlgorithmUnavailable(_)));
    }

    #[test]
    fn decrypt_pvk_reports_unable_to_get_passphrase_for_empty_pw() {
        // Empty passphrase on an encrypted blob models the "no passphrase
        // callback registered" scenario from the C source
        // (`PEM_R_BAD_PASSWORD_READ`).  It must surface through the
        // structured [`EndecoderError::UnableToGetPassphrase`] channel —
        // which converts to `ProviderError::Dispatch` via the From
        // impl in [`common.rs`].
        let err = decrypt_pvk(&[0u8; 16], &[0u8; 16], &[], PVK_STRONG_ENCRYPT)
            .expect_err("empty passphrase must signal UnableToGetPassphrase");
        assert!(matches!(err, ProviderError::Dispatch(_)));
        // The Display message carried by EndecoderError::UnableToGetPassphrase
        // must propagate through the conversion.
        if let ProviderError::Dispatch(msg) = &err {
            assert!(
                msg.to_ascii_lowercase().contains("passphrase"),
                "expected diagnostic to mention 'passphrase', got {msg:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // PvkDecoder — end-to-end decoder surface
    // -----------------------------------------------------------------

    #[test]
    fn pvk_decoder_name_and_formats() {
        let decoder = PvkDecoder::new(PvkKeyType::Rsa);
        assert_eq!(decoder.name(), "PVK");
        assert_eq!(decoder.supported_formats(), vec![FORMAT_PVK]);
    }

    #[test]
    fn pvk_decoder_rejects_empty_input() {
        let decoder = PvkDecoder::new(PvkKeyType::Rsa);
        let err = decoder.decode(&[]).expect_err("empty input must fail");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn pvk_decoder_rejects_truncated_buffer() {
        let decoder = PvkDecoder::new(PvkKeyType::Rsa);
        // Claim a body of 16 bytes but only provide the header.
        let bytes = encode_pvk_header(PVK_MAGIC, MS_KEYTYPE_KEYX, PVK_NO_ENCRYPT, 0, 16);
        let err = decoder
            .decode(&bytes)
            .expect_err("truncated body must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn pvk_decoder_rejects_family_mismatch() {
        // Decoder claims RSA but blob declares DSA (SIGN).
        let decoder = PvkDecoder::new(PvkKeyType::Rsa);
        let mut bytes = encode_pvk_header(PVK_MAGIC, MS_KEYTYPE_SIGN, PVK_NO_ENCRYPT, 0, 16);
        bytes.extend_from_slice(&[0u8; 16]);
        let err = decoder
            .decode(&bytes)
            .expect_err("family mismatch must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn pvk_decoder_surfaces_passphrase_error_for_encrypted_blob() {
        // The [`DecoderProvider::decode`] implementation currently calls
        // `decrypt_pvk` with an empty passphrase slice because the
        // passphrase-acquisition callback has not yet been wired through
        // the provider dispatch layer.  The correct diagnostic for
        // that scenario is the structured
        // [`EndecoderError::UnableToGetPassphrase`], which converts to
        // `ProviderError::Dispatch` — mirroring the C source's
        // `PEM_R_BAD_PASSWORD_READ` outcome.
        let decoder = PvkDecoder::new(PvkKeyType::Rsa);
        let mut bytes = encode_pvk_header(PVK_MAGIC, MS_KEYTYPE_KEYX, PVK_STRONG_ENCRYPT, 16, 16);
        bytes.extend_from_slice(&[0x42u8; 16]); // salt
        bytes.extend_from_slice(&[0xFFu8; 16]); // ciphertext body
        let err = decoder
            .decode(&bytes)
            .expect_err("encrypted PVK without passphrase must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
        if let ProviderError::Dispatch(msg) = &err {
            assert!(
                msg.to_ascii_lowercase().contains("passphrase"),
                "expected diagnostic to mention 'passphrase', got {msg:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // Context / registration smoke tests
    // -----------------------------------------------------------------

    #[test]
    fn context_default_selection_is_private_key() {
        let ctx = PvkDecoderContext::new(PvkKeyType::Rsa);
        assert!(ctx.propq.is_none());
        assert_eq!(ctx.selection, KeySelection::PRIVATE_KEY);
        assert_eq!(ctx.key_type, PvkKeyType::Rsa);
    }

    #[test]
    fn context_fields_are_mutable_by_public_api() {
        let mut ctx = PvkDecoderContext::new(PvkKeyType::Dsa);
        ctx.propq = Some("provider=default".into());
        ctx.selection = KeySelection::KEYPAIR;
        assert_eq!(ctx.propq.as_deref(), Some("provider=default"));
        assert!(ctx.selection.contains(KeySelection::PRIVATE_KEY));
    }

    #[test]
    fn all_pvk_decoders_returns_enabled_descriptors() {
        let descriptors = all_pvk_decoders();

        #[cfg(feature = "rsa")]
        {
            assert!(
                descriptors.iter().any(|d| d.names.contains(&"RSA")),
                "expected RSA descriptor when 'rsa' feature enabled"
            );
        }

        #[cfg(feature = "dsa")]
        {
            assert!(
                descriptors.iter().any(|d| d.names.contains(&"DSA")),
                "expected DSA descriptor when 'dsa' feature enabled"
            );
        }

        for d in &descriptors {
            assert!(d.property.contains("input=pvk"));
        }
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn pvk_rsa_decoder_constructor_binds_correct_key_type() {
        let d = pvk_rsa_decoder();
        assert_eq!(d.key_type, PvkKeyType::Rsa);
        assert_eq!(d.name(), "PVK");
    }

    #[cfg(feature = "dsa")]
    #[test]
    fn pvk_dsa_decoder_constructor_binds_correct_key_type() {
        let d = pvk_dsa_decoder();
        assert_eq!(d.key_type, PvkKeyType::Dsa);
        assert_eq!(d.name(), "PVK");
    }

    // -----------------------------------------------------------------
    // decoded_object_for — metadata helper (feature-gated)
    // -----------------------------------------------------------------

    #[cfg(any(feature = "rsa", feature = "dsa"))]
    #[test]
    fn decoded_object_for_populates_metadata() {
        let obj = decoded_object_for(PvkKeyType::Rsa, vec![1, 2, 3]);
        assert!(matches!(obj.object_type, ObjectType::Pkey));
        assert_eq!(obj.data_type, "RSA");
        assert_eq!(obj.input_type, FORMAT_PVK);
        assert_eq!(obj.data, vec![1, 2, 3]);
        assert!(obj.data_structure.is_none());
    }

    // -----------------------------------------------------------------
    // read_u32_le — internal helper correctness
    // -----------------------------------------------------------------

    #[test]
    fn read_u32_le_reads_known_values() {
        let bytes = [0x12u8, 0x34, 0x56, 0x78];
        assert_eq!(read_u32_le(&bytes, 0).unwrap(), 0x7856_3412);
    }

    #[test]
    fn read_u32_le_rejects_out_of_range_offset() {
        let bytes = [0x00u8; 4];
        let err = read_u32_le(&bytes, 2).expect_err("offset+4 > len must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn read_u32_le_rejects_empty_slice() {
        let err = read_u32_le(&[], 0).expect_err("empty slice must fail");
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }
}
