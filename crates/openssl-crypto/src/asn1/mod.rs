//! ASN.1/DER encoding and decoding for the OpenSSL Rust workspace.
//!
//! This module provides the Rust equivalent of OpenSSL's `crypto/asn1/` subsystem
//! (65 C files, ~15,859 lines). It defines the fundamental ASN.1 types used
//! throughout the cryptographic library: integers, bit strings, octet strings,
//! object identifiers, time values, and composite types (`AlgorithmIdentifier`,
//! `DigestInfo`, Validity, PKCS#5/8 parameter structures, etc.).
//!
//! # Architecture
//!
//! The module is split into two files:
//! - `mod.rs` (this file): Core ASN.1 types, low-level TLV operations, string
//!   handling, time types, OID handling, signing/verification helpers, I/O.
//! - [`template`]: Template system for structured types (SEQUENCE, SET, CHOICE)
//!   including the `Asn1Item` trait, encode/decode engine, and SET OF sorter.
//!
//! # DER Encoding/Decoding
//!
//! Low-level DER operations leverage the `RustCrypto` [`der`] crate for TLV
//! primitives. Higher-level operations (signing, verification, key I/O)
//! delegate to the appropriate algorithm modules.
//!
//! # Type Mapping (C → Rust)
//!
//! | C Type              | Rust Type                 | Notes                         |
//! |---------------------|---------------------------|-------------------------------|
//! | `ASN1_INTEGER`      | [`Asn1Integer`]           | Arbitrary-precision, signed   |
//! | `ASN1_ENUMERATED`   | [`Asn1Enumerated`]        | Like INTEGER, ENUMERATED tag  |
//! | `ASN1_BIT_STRING`   | [`Asn1BitString`]         | With unused-bits tracking     |
//! | `ASN1_OCTET_STRING` | [`Asn1OctetString`]       | Raw byte buffer               |
//! | `ASN1_OBJECT`       | [`Asn1Object`]            | OID with NID mapping          |
//! | `ASN1_STRING`       | [`Asn1String`]            | Tagged string (IA5, UTF8, …)  |
//! | `ASN1_TIME`         | [`Asn1Time`]              | CHOICE(UTCTime, `GeneralTime`)  |
//! | `ASN1_TYPE`         | [`Asn1Type`]              | ANY type — tagged union       |
//! | `ASN1_NULL`         | [`Asn1Null`]              | NULL value                    |
//! | `ASN1_BOOLEAN`      | [`Asn1Boolean`]           | Boolean with DEFAULT support  |
//! | `X509_ALGOR`        | [`AlgorithmIdentifier`]   | `AlgorithmIdentifier`           |
//! | `X509_SIG`          | [`DigestInfo`]            | `DigestInfo` (PKCS#1)           |
//! | `X509_VAL`          | [`Validity`]              | Certificate validity period   |
//! | `PBEPARAM`          | [`PbeParam`]              | PKCS#5 PBE parameters         |
//! | `PBE2PARAM`         | [`Pbes2Param`]            | PKCS#5 v2 PBES2 parameters    |
//! | `PBKDF2PARAM`       | [`Pbkdf2Param`]           | PKCS#5 PBKDF2 parameters      |
//! | `SCRYPT_PARAMS`     | [`ScryptParam`]           | scrypt parameters (RFC 7914)  |
//! | `PKCS8_PRIV_KEY_INFO` | [`Pkcs8PrivateKeyInfo`] | PKCS#8 `PrivateKeyInfo`         |
//! | `NETSCAPE_SPKI`     | [`NetscapeSpki`]          | Signed Public Key & Challenge |
//! | `NETSCAPE_SPKAC`    | [`Spkac`]                 | Public Key & Challenge inner  |
//!
//! # Design Principles
//!
//! - **Zero unsafe** (Rule R8): All operations use safe Rust via the `der` crate.
//! - **Option over sentinel** (Rule R5): No NULL pointers, no `-1` returns.
//! - **Checked arithmetic** (Rule R6): `try_from` / checked ops instead of `as`.
//! - **Secure erasure**: Private key material derives `ZeroizeOnDrop`.
//! - **Wiring** (Rule R10): Exported via `openssl_crypto::asn1::*` and reachable
//!   from EVP, X.509, PEM, PKCS, CMP, TS, OCSP, and CT modules.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All C sentinel returns (NULL, 0, -1, -2) converted
//!   to `Option<T>` or [`CryptoResult<T>`].
//! - **R6 (Lossless Casts):** All narrowing conversions use `usize::try_from()`
//!   or saturating arithmetic; no bare `as` casts in public APIs.
//! - **R7 (Lock Granularity):** No shared mutable state in core ASN.1 types.
//! - **R8 (Zero Unsafe):** Crate-level `#![forbid(unsafe_code)]` enforced.
//! - **R9 (Warning-Free):** Every public item has `///` doc comments.

pub mod template;

use std::cmp::Ordering;
use std::fmt;
use std::io::{BufRead, Read, Write};

use openssl_common::{CryptoError, CryptoResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bn::BigNum;

// =============================================================================
// Tag and Class Enums
// =============================================================================
//
// Maps C `V_ASN1_*` constants from `include/openssl/asn1.h` into idiomatic
// Rust enums with explicit discriminants.

/// ASN.1 universal tag numbers per ITU-T X.680.
///
/// Replaces C `V_ASN1_*` constants from `include/openssl/asn1.h`.
/// The discriminant values are the tag numbers defined by X.680 §8.1.2.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Asn1Tag {
    /// End-of-contents marker (for BER indefinite-length encodings).
    Eoc = 0,
    /// BOOLEAN (tag 1).
    Boolean = 1,
    /// INTEGER (tag 2).
    Integer = 2,
    /// BIT STRING (tag 3).
    BitString = 3,
    /// OCTET STRING (tag 4).
    OctetString = 4,
    /// NULL (tag 5).
    Null = 5,
    /// OBJECT IDENTIFIER (tag 6).
    ObjectIdentifier = 6,
    /// `ObjectDescriptor` (tag 7).
    ObjectDescriptor = 7,
    /// EXTERNAL (tag 8).
    External = 8,
    /// REAL (tag 9).
    Real = 9,
    /// ENUMERATED (tag 10).
    Enumerated = 10,
    /// `UTF8String` (tag 12).
    Utf8String = 12,
    /// SEQUENCE / SEQUENCE OF (tag 16).
    Sequence = 16,
    /// SET / SET OF (tag 17).
    Set = 17,
    /// `NumericString` (tag 18).
    NumericString = 18,
    /// `PrintableString` (tag 19).
    PrintableString = 19,
    /// `T61String` / `TeletexString` (tag 20).
    T61String = 20,
    /// `VideotexString` (tag 21).
    VideotexString = 21,
    /// `IA5String` (tag 22).
    Ia5String = 22,
    /// `UTCTime` (tag 23).
    UtcTime = 23,
    /// `GeneralizedTime` (tag 24).
    GeneralizedTime = 24,
    /// `GraphicString` (tag 25).
    GraphicString = 25,
    /// `VisibleString` / `ISO646String` (tag 26).
    VisibleString = 26,
    /// `GeneralString` (tag 27).
    GeneralString = 27,
    /// `UniversalString` (tag 28).
    UniversalString = 28,
    /// `BMPString` (tag 30).
    BmpString = 30,
}

impl Asn1Tag {
    /// Convert a raw tag number (0–30) to an [`Asn1Tag`].
    ///
    /// Returns `None` for tag numbers that are not defined ASN.1 universal
    /// tags or that exceed the 5-bit single-byte tag limit.
    #[must_use]
    pub fn from_u8(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Eoc),
            1 => Some(Self::Boolean),
            2 => Some(Self::Integer),
            3 => Some(Self::BitString),
            4 => Some(Self::OctetString),
            5 => Some(Self::Null),
            6 => Some(Self::ObjectIdentifier),
            7 => Some(Self::ObjectDescriptor),
            8 => Some(Self::External),
            9 => Some(Self::Real),
            10 => Some(Self::Enumerated),
            12 => Some(Self::Utf8String),
            16 => Some(Self::Sequence),
            17 => Some(Self::Set),
            18 => Some(Self::NumericString),
            19 => Some(Self::PrintableString),
            20 => Some(Self::T61String),
            21 => Some(Self::VideotexString),
            22 => Some(Self::Ia5String),
            23 => Some(Self::UtcTime),
            24 => Some(Self::GeneralizedTime),
            25 => Some(Self::GraphicString),
            26 => Some(Self::VisibleString),
            27 => Some(Self::GeneralString),
            28 => Some(Self::UniversalString),
            30 => Some(Self::BmpString),
            _ => None,
        }
    }

    /// Return the numeric tag value as a `u8`.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// ASN.1 tag class per ITU-T X.680 §8.1.2.2.
///
/// Replaces C `V_ASN1_UNIVERSAL` / `V_ASN1_APPLICATION` /
/// `V_ASN1_CONTEXT_SPECIFIC` / `V_ASN1_PRIVATE` constants.
/// The discriminant values match the class bit patterns in the identifier
/// octet (top two bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Asn1Class {
    /// Universal class — standard ASN.1 types.
    Universal = 0x00,
    /// Application class — application-specific tags.
    Application = 0x40,
    /// Context-specific class — meaning derived from context.
    ContextSpecific = 0x80,
    /// Private class — private-use tags.
    Private = 0xC0,
}

impl Asn1Class {
    /// Convert the top two bits of the identifier octet to a class.
    #[must_use]
    pub fn from_identifier_byte(byte: u8) -> Self {
        match byte & 0xC0 {
            0x00 => Self::Universal,
            0x40 => Self::Application,
            0x80 => Self::ContextSpecific,
            _ => Self::Private,
        }
    }
}

/// ASN.1 tag number type — an unsigned integer covering arbitrarily large
/// tag numbers (the DER representation uses base-128 continuation bytes for
/// tags ≥ 31 per X.690 §8.1.2.4).
pub type TagNumber = u32;

// =============================================================================
// StringFlags (C ASN1_STRING_FLAG_* constants)
// =============================================================================

bitflags::bitflags! {
    /// Flags for [`Asn1String`] — replaces C `ASN1_STRING_FLAG_*` constants
    /// from `include/openssl/asn1.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StringFlags: u32 {
        /// Indicates that a BIT STRING has a non-zero number of unused bits
        /// encoded in the low 3 bits of this flag field.
        const BITS_LEFT = 0x08;
        /// Indefinite-length (BER) encoding was used during parsing.
        const NDEF = 0x10;
    }
}

// =============================================================================
// Asn1Error (from crypto/asn1/asn1_err.c — ~100 ASN1_R_* reason codes)
// =============================================================================

/// ASN.1-specific errors.
///
/// Replaces C `ASN1_R_*` reason codes from `crypto/asn1/asn1_err.c`. The C
/// implementation uses ~100 distinct reason codes; this enum consolidates
/// them into ergonomic variants suitable for Rust error handling.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Asn1Error {
    /// The tag byte does not match an expected ASN.1 universal tag.
    ///
    /// Replaces `ASN1_R_WRONG_TAG`, `ASN1_R_UNEXPECTED_EOC`,
    /// `ASN1_R_BAD_TAG_VALUE_FOUND`.
    #[error("invalid tag: 0x{0:02x}")]
    InvalidTag(u8),

    /// The input ended before the complete value was consumed.
    ///
    /// Replaces `ASN1_R_TOO_SHORT`, `ASN1_R_UNEXPECTED_EOC`,
    /// `ASN1_R_HEADER_TOO_LONG`.
    #[error("truncated data: expected {expected} bytes, got {actual}")]
    TruncatedData {
        /// Number of bytes required.
        expected: usize,
        /// Number of bytes actually available.
        actual: usize,
    },

    /// The length encoding is malformed (e.g., leading zeros in long form,
    /// reserved 0xFF byte, or length exceeding the buffer).
    ///
    /// Replaces `ASN1_R_INVALID_BIT_STRING_BITS_LEFT`, `ASN1_R_DECODE_ERROR`,
    /// `ASN1_R_BAD_LENGTH`.
    #[error("invalid length encoding")]
    InvalidLength,

    /// Maximum allowed nesting depth was exceeded.
    ///
    /// Replaces `ASN1_R_NESTED_TOO_DEEP`.
    /// OpenSSL's limit (`ASN1_MAX_CONSTRUCTED_NEST`) is 30.
    #[error("maximum nesting depth exceeded (limit: {0})")]
    NestingDepthExceeded(usize),

    /// A time string does not conform to the expected format.
    ///
    /// Replaces `ASN1_R_INVALID_TIME_FORMAT`, `ASN1_R_INVALID_UTF8STRING`.
    #[error("invalid time format: {0}")]
    InvalidTimeFormat(String),

    /// Byte content is not valid for the declared string type
    /// (e.g., non-ASCII in `IA5String`, non-printable in `PrintableString`).
    ///
    /// Replaces `ASN1_R_ILLEGAL_CHARACTERS`, `ASN1_R_INVALID_STRING_TABLE_VALUE`.
    #[error("invalid string content for type {tag:?}")]
    InvalidStringContent {
        /// The string type that was being validated.
        tag: Asn1Tag,
    },

    /// An object identifier string is malformed.
    ///
    /// Replaces `ASN1_R_INVALID_OBJECT_ENCODING`,
    /// `ASN1_R_FIRST_NUM_TOO_LARGE`, `ASN1_R_SECOND_NUMBER_TOO_LARGE`.
    #[error("invalid OID: {0}")]
    InvalidOid(String),

    /// An integer value exceeds the supported representation.
    ///
    /// Replaces `ASN1_R_INTEGER_TOO_LARGE_FOR_LONG`.
    #[error("integer overflow")]
    IntegerOverflow,

    /// A DER encoding operation failed.
    ///
    /// Replaces `ASN1_R_ENCODE_ERROR`, `ASN1_R_UNSUPPORTED_TYPE`.
    #[error("encoding error: {0}")]
    EncodingError(String),

    /// A DER decoding operation failed.
    ///
    /// Replaces `ASN1_R_DECODE_ERROR`, `ASN1_R_TYPE_NOT_PRIMITIVE`,
    /// `ASN1_R_TYPE_NOT_CONSTRUCTED`.
    #[error("decoding error: {0}")]
    DecodingError(String),

    /// An operation or feature is not supported by this implementation.
    ///
    /// Replaces `ASN1_R_UNSUPPORTED_TYPE`, `ASN1_R_UNSUPPORTED_CIPHER`.
    #[error("unsupported feature: {0}")]
    Unsupported(String),
}

/// Convert [`Asn1Error`] into [`CryptoError`] for seamless `?` propagation.
///
/// All ASN.1 errors map to `CryptoError::Encoding(String)` preserving the
/// `Display` representation of the original variant for diagnostics.
impl From<Asn1Error> for CryptoError {
    fn from(e: Asn1Error) -> Self {
        CryptoError::Encoding(e.to_string())
    }
}

/// Convert a `der::Error` into [`Asn1Error`] preserving error context.
impl From<der::Error> for Asn1Error {
    fn from(e: der::Error) -> Self {
        Asn1Error::DecodingError(e.to_string())
    }
}

// =============================================================================
// Asn1String — the fundamental tagged-string type
// =============================================================================
//
// From crypto/asn1/asn1_lib.c (466 lines). Almost all ASN.1 string types
// (IA5String, UTF8String, PrintableString, etc.) share this same underlying
// structure; only the tag discriminator differs.

/// General-purpose ASN.1 string type — the Rust equivalent of C `ASN1_STRING`.
///
/// Nearly all ASN.1 string types (`IA5String`, `UTF8String`, `PrintableString`,
/// `BIT STRING`, `OCTET STRING`, etc.) are represented as `Asn1String` with a
/// tag discriminator. Source: `crypto/asn1/asn1_lib.c`.
#[derive(Debug, Clone)]
pub struct Asn1String {
    /// The ASN.1 tag identifying the string type.
    tag: Asn1Tag,
    /// Raw byte content of the string.
    data: Vec<u8>,
    /// Flags (bits-left for BIT STRING, NDEF marker, etc.).
    flags: StringFlags,
}

impl Asn1String {
    /// Create a new empty ASN.1 string of the given type.
    ///
    /// Replaces C `ASN1_STRING_type_new()`.
    #[must_use]
    pub fn new(tag: Asn1Tag) -> Self {
        Self {
            tag,
            data: Vec::new(),
            flags: StringFlags::empty(),
        }
    }

    /// Set the string content to a copy of the given bytes.
    ///
    /// Replaces C `ASN1_STRING_set()` (always succeeds in the Rust version
    /// since allocation failures are communicated by `std::alloc` panics
    /// as elsewhere in Rust).
    pub fn set(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.data.clear();
        self.data.extend_from_slice(data);
        Ok(())
    }

    /// Return a read-only slice of the string data.
    ///
    /// Replaces C `ASN1_STRING_get0_data()` — which returned a nullable
    /// pointer. Rule R5: this returns a slice that is empty but never null.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Return the length of the string in bytes.
    ///
    /// Replaces C `ASN1_STRING_length()`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return the tag identifying the string type.
    ///
    /// Replaces C `ASN1_STRING_type()`.
    #[must_use]
    pub fn tag(&self) -> Asn1Tag {
        self.tag
    }

    /// Return `true` if the string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the flags associated with the string.
    #[must_use]
    pub fn flags(&self) -> StringFlags {
        self.flags
    }

    /// Set the flags associated with the string.
    pub fn set_flags(&mut self, flags: StringFlags) {
        self.flags = flags;
    }

    /// Create a duplicate of this string — replaces C `ASN1_STRING_dup()`.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        self.clone()
    }
}

impl PartialEq for Asn1String {
    /// Equality for `Asn1String` compares both the tag and the byte content.
    /// Replaces C `ASN1_STRING_cmp()`.
    fn eq(&self, other: &Self) -> bool {
        self.tag == other.tag && self.data == other.data
    }
}

impl Eq for Asn1String {}

impl fmt::Display for Asn1String {
    /// Display the string. For text-encoded types, attempts UTF-8 decoding;
    /// for binary types, renders as hex. Replaces C `ASN1_STRING_print()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tag {
            Asn1Tag::Utf8String
            | Asn1Tag::PrintableString
            | Asn1Tag::Ia5String
            | Asn1Tag::VisibleString
            | Asn1Tag::NumericString
            | Asn1Tag::T61String
            | Asn1Tag::GeneralString => {
                // Best-effort UTF-8 display; non-UTF-8 bytes become `.`.
                for &b in &self.data {
                    if b.is_ascii_graphic() || b == b' ' {
                        f.write_fmt(format_args!("{}", b as char))?;
                    } else {
                        f.write_str(".")?;
                    }
                }
                Ok(())
            }
            _ => {
                // Fallback: hex representation
                for b in &self.data {
                    f.write_fmt(format_args!("{b:02x}"))?;
                }
                Ok(())
            }
        }
    }
}

// =============================================================================
// Asn1Integer — arbitrary-precision signed integer
// =============================================================================
//
// From crypto/asn1/a_int.c (655 lines). DER encoding uses two's complement
// per X.690 §8.3 with a leading-zero rule: for non-negative values whose
// high bit is set, a leading 0x00 byte prefix is required.

/// ASN.1 INTEGER — arbitrary-precision signed integer.
///
/// Internal representation: magnitude bytes (big-endian, unsigned) plus a
/// sign flag. DER encoding follows X.690 §8.3 using two's complement.
///
/// Source: `crypto/asn1/a_int.c` (655 lines).
#[derive(Debug, Clone)]
pub struct Asn1Integer {
    /// Magnitude bytes (big-endian, unsigned).
    data: Vec<u8>,
    /// Sign flag: `true` if negative.
    negative: bool,
}

impl Default for Asn1Integer {
    fn default() -> Self {
        Self::new()
    }
}

impl Asn1Integer {
    /// Create a new zero-valued ASN.1 INTEGER.
    ///
    /// The canonical encoding of 0 is a single zero byte (length = 1,
    /// data = `[0x00]`), matching the C convention in `a_int.c`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: vec![0],
            negative: false,
        }
    }

    /// Create an ASN.1 INTEGER from a signed 64-bit value.
    ///
    /// Replaces C `ASN1_INTEGER_set_int64()`.
    #[must_use]
    pub fn from_i64(val: i64) -> Self {
        if val == 0 {
            return Self::new();
        }
        let (negative, magnitude) = if val < 0 {
            // `i64::unsigned_abs` correctly handles `i64::MIN` (returns
            // `1 << 63`) without any lossy cast.
            (true, val.unsigned_abs())
        } else {
            // `val > 0` (zero handled above) so this `try_from` cannot fail.
            (false, u64::try_from(val).unwrap_or(0))
        };
        Self::from_u64_with_sign(magnitude, negative)
    }

    /// Create an ASN.1 INTEGER from an unsigned 64-bit value.
    ///
    /// Replaces C `ASN1_INTEGER_set_uint64()`.
    #[must_use]
    pub fn from_u64(val: u64) -> Self {
        Self::from_u64_with_sign(val, false)
    }

    /// Create an INTEGER from a magnitude and explicit sign.
    fn from_u64_with_sign(val: u64, negative: bool) -> Self {
        if val == 0 {
            return Self::new();
        }
        let be = val.to_be_bytes();
        // Strip leading zeros from the magnitude.
        let first_nonzero = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        Self {
            data: be[first_nonzero..].to_vec(),
            negative,
        }
    }

    /// Return the integer as a signed 64-bit value.
    ///
    /// Replaces C `ASN1_INTEGER_get_int64()`. Returns `Asn1Error::IntegerOverflow`
    /// if the value does not fit in an `i64`.
    pub fn to_i64(&self) -> CryptoResult<i64> {
        if self.data.len() > 8 {
            return Err(Asn1Error::IntegerOverflow.into());
        }
        // Pack magnitude into a u64.
        let mut mag: u64 = 0;
        for &b in &self.data {
            mag = (mag << 8) | u64::from(b);
        }
        if self.negative {
            // Two's complement: need mag <= ABS_INT64_MIN = 2^63.
            if mag > (i64::MAX as u64) + 1 {
                return Err(Asn1Error::IntegerOverflow.into());
            }
            if mag == (i64::MAX as u64) + 1 {
                Ok(i64::MIN)
            } else {
                // Safe: mag is at most i64::MAX here.
                i64::try_from(mag)
                    .map(|v| -v)
                    .map_err(|_| Asn1Error::IntegerOverflow.into())
            }
        } else {
            i64::try_from(mag).map_err(|_| Asn1Error::IntegerOverflow.into())
        }
    }

    /// Return the integer as an unsigned 64-bit value.
    ///
    /// Replaces C `ASN1_INTEGER_get_uint64()`. Returns
    /// `Asn1Error::IntegerOverflow` if the value is negative or exceeds
    /// `u64::MAX`.
    pub fn to_u64(&self) -> CryptoResult<u64> {
        if self.negative {
            return Err(Asn1Error::IntegerOverflow.into());
        }
        if self.data.len() > 8 {
            return Err(Asn1Error::IntegerOverflow.into());
        }
        let mut mag: u64 = 0;
        for &b in &self.data {
            mag = (mag << 8) | u64::from(b);
        }
        Ok(mag)
    }

    /// Encode this INTEGER as DER content bytes (without tag/length header).
    ///
    /// Replaces the C `i2c_ASN1_INTEGER()` function from `a_int.c`, producing
    /// two's-complement encoding per X.690 §8.3.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        // Special case zero.
        if self.data.iter().all(|&b| b == 0) {
            return Ok(vec![0]);
        }

        if self.negative {
            // Two's complement: invert bits and add one.
            //
            // First, trim leading zero magnitude bytes to get the minimal
            // representation, then compute the two's complement.
            let first_nz = self.data.iter().position(|&b| b != 0).unwrap_or(0);
            let mag = &self.data[first_nz..];

            // Complement and add 1.
            let mut inverted: Vec<u8> = mag.iter().map(|b| !b).collect();
            // Add 1 to the two's-complement byte array.
            let mut carry: u16 = 1;
            for byte in inverted.iter_mut().rev() {
                let sum = u16::from(*byte) + carry;
                *byte = (sum & 0xff) as u8;
                carry = sum >> 8;
                if carry == 0 {
                    break;
                }
            }
            // If the high bit is not set, we need a 0xFF prefix to indicate
            // negative (e.g., -128 = [0x80], -129 = [0xFF, 0x7F]).
            if inverted[0] & 0x80 == 0 {
                let mut out = vec![0xFF];
                out.extend(inverted);
                Ok(out)
            } else {
                Ok(inverted)
            }
        } else {
            // Non-negative: strip leading zero bytes but ensure the high bit
            // of the first byte is 0 (prepend 0x00 if needed).
            let first_nz = self.data.iter().position(|&b| b != 0).unwrap_or(0);
            let mag = &self.data[first_nz..];
            if mag[0] & 0x80 != 0 {
                let mut out = vec![0x00];
                out.extend_from_slice(mag);
                Ok(out)
            } else {
                Ok(mag.to_vec())
            }
        }
    }

    /// Decode an INTEGER from DER content bytes (without tag/length header).
    ///
    /// Replaces the C `c2i_ASN1_INTEGER()` function from `a_int.c`.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        if data.is_empty() {
            return Err(Asn1Error::DecodingError("INTEGER content is empty".into()).into());
        }

        // Reject illegal padding per X.690 §8.3.2: the first 9 bits of a
        // multi-byte INTEGER must not all be zero and must not all be one.
        if data.len() >= 2 {
            let first = data[0];
            let second_high = (data[1] & 0x80) >> 7;
            if (first == 0x00 && second_high == 0) || (first == 0xFF && second_high == 1) {
                return Err(Asn1Error::DecodingError("INTEGER has illegal padding".into()).into());
            }
        }

        let negative = (data[0] & 0x80) != 0;
        if negative {
            // Undo two's complement: invert and add 1.
            let mut inverted: Vec<u8> = data.iter().map(|b| !b).collect();
            let mut carry: u16 = 1;
            for byte in inverted.iter_mut().rev() {
                let sum = u16::from(*byte) + carry;
                *byte = (sum & 0xff) as u8;
                carry = sum >> 8;
                if carry == 0 {
                    break;
                }
            }
            // Strip leading zeros from magnitude.
            let first_nz = inverted
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(inverted.len() - 1);
            Ok(Self {
                data: inverted[first_nz..].to_vec(),
                negative: true,
            })
        } else {
            // Strip leading zero byte if present (sign byte).
            let start = usize::from(data.len() > 1 && data[0] == 0);
            Ok(Self {
                data: data[start..].to_vec(),
                negative: false,
            })
        }
    }

    /// Convert a [`BigNum`] to an ASN.1 INTEGER.
    ///
    /// Replaces C `BN_to_ASN1_INTEGER()` from `crypto/asn1/a_int.c`.
    pub fn from_bn(bn: &BigNum) -> CryptoResult<Self> {
        let negative = bn.is_negative();
        let mag = bn.to_bytes_be();
        if mag.is_empty() {
            Ok(Self::new())
        } else {
            Ok(Self {
                data: mag,
                negative,
            })
        }
    }

    /// Convert this INTEGER to a [`BigNum`].
    ///
    /// Replaces C `ASN1_INTEGER_to_BN()` from `crypto/asn1/a_int.c`.
    pub fn to_bn(&self) -> CryptoResult<BigNum> {
        let mut bn = BigNum::from_bytes_be(&self.data);
        bn.set_negative(self.negative);
        Ok(bn)
    }

    /// Return `true` if this INTEGER is negative.
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// Return the raw magnitude bytes (big-endian, unsigned).
    #[must_use]
    pub fn magnitude(&self) -> &[u8] {
        &self.data
    }
}

impl PartialEq for Asn1Integer {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Asn1Integer {}

impl PartialOrd for Asn1Integer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Asn1Integer {
    /// Sign-aware comparison — replaces C `ASN1_INTEGER_cmp()`.
    ///
    /// Handles the edge case where both values are numerically zero but may
    /// have different sign flags (both are considered equal).
    fn cmp(&self, other: &Self) -> Ordering {
        // Normalise zero: zero has no sign.
        let self_zero = self.data.iter().all(|&b| b == 0);
        let other_zero = other.data.iter().all(|&b| b == 0);
        let self_neg = self.negative && !self_zero;
        let other_neg = other.negative && !other_zero;

        match (self_neg, other_neg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => compare_magnitude(&self.data, &other.data),
            (true, true) => compare_magnitude(&other.data, &self.data),
        }
    }
}

/// Compare two big-endian magnitude byte arrays as unsigned integers.
fn compare_magnitude(a: &[u8], b: &[u8]) -> Ordering {
    // Strip leading zeros for fair length comparison.
    let a_start = a.iter().position(|&x| x != 0).unwrap_or(a.len());
    let b_start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    let a = &a[a_start..];
    let b = &b[b_start..];
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        other => other,
    }
}

// =============================================================================
// Asn1Enumerated — like INTEGER but with tag 10
// =============================================================================

/// ASN.1 ENUMERATED — structurally identical to INTEGER but with tag 10.
///
/// Source: `crypto/asn1/a_int.c` (shares implementation with INTEGER via
/// `ASN1_ITEM_ENUMERATED`). Used for enumeration values (e.g., CRL reasons).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1Enumerated {
    /// Magnitude bytes (big-endian, unsigned).
    data: Vec<u8>,
    /// Sign flag.
    negative: bool,
}

impl Default for Asn1Enumerated {
    fn default() -> Self {
        Self::new()
    }
}

impl Asn1Enumerated {
    /// Create a new ENUMERATED with value 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: vec![0],
            negative: false,
        }
    }

    /// Create an ENUMERATED from a signed 64-bit value.
    #[must_use]
    pub fn from_i64(val: i64) -> Self {
        let int = Asn1Integer::from_i64(val);
        Self {
            data: int.data,
            negative: int.negative,
        }
    }

    /// Create an ENUMERATED from an unsigned 64-bit value.
    #[must_use]
    pub fn from_u64(val: u64) -> Self {
        let int = Asn1Integer::from_u64(val);
        Self {
            data: int.data,
            negative: int.negative,
        }
    }

    /// Convert this ENUMERATED to a signed 64-bit integer.
    pub fn to_i64(&self) -> CryptoResult<i64> {
        let int = Asn1Integer {
            data: self.data.clone(),
            negative: self.negative,
        };
        int.to_i64()
    }

    /// Convert this ENUMERATED to an unsigned 64-bit integer.
    pub fn to_u64(&self) -> CryptoResult<u64> {
        let int = Asn1Integer {
            data: self.data.clone(),
            negative: self.negative,
        };
        int.to_u64()
    }

    /// Encode this ENUMERATED as DER content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let int = Asn1Integer {
            data: self.data.clone(),
            negative: self.negative,
        };
        int.encode_der()
    }

    /// Decode an ENUMERATED from DER content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let int = Asn1Integer::decode_der(data)?;
        Ok(Self {
            data: int.data,
            negative: int.negative,
        })
    }
}

// =============================================================================
// Asn1BitString — BIT STRING with unused-bits tracking
// =============================================================================
//
// From crypto/asn1/a_bitstr.c (296 lines). Per X.690 §8.6.2, BIT STRING
// content begins with an "unused bits" byte (0–7) followed by the raw bit
// octets. Canonical DER encoding requires trailing unused bits to be zero.

/// ASN.1 BIT STRING with unused-bits tracking.
///
/// Represents a sequence of bits using a byte buffer with an explicit count
/// of unused bits in the last byte. Per X.690 §11.2, DER-canonical encoding
/// requires all unused trailing bits to be zero.
///
/// Source: `crypto/asn1/a_bitstr.c` (296 lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1BitString {
    /// Raw bit data (unused trailing bits should be zero).
    data: Vec<u8>,
    /// Number of unused trailing bits in the last byte (0..=7).
    unused_bits: u8,
}

impl Default for Asn1BitString {
    fn default() -> Self {
        Self::new()
    }
}

impl Asn1BitString {
    /// Create a new empty BIT STRING.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            unused_bits: 0,
        }
    }

    /// Set the bit-string content and unused-bit count.
    ///
    /// Replaces C `ASN1_BIT_STRING_set()`. Returns an error if
    /// `unused_bits > 7` or if `unused_bits > 0` with empty data.
    pub fn set_data(&mut self, data: &[u8], unused_bits: u8) -> CryptoResult<()> {
        if unused_bits > 7 {
            return Err(Asn1Error::EncodingError(format!(
                "unused_bits must be 0-7, got {unused_bits}"
            ))
            .into());
        }
        if data.is_empty() && unused_bits != 0 {
            return Err(Asn1Error::EncodingError(
                "unused_bits must be 0 when data is empty".into(),
            )
            .into());
        }
        self.data = data.to_vec();
        self.unused_bits = unused_bits;
        // Canonicalise: mask off unused bits in the last byte.
        if unused_bits > 0 {
            if let Some(last) = self.data.last_mut() {
                let mask = 0xFFu8 << unused_bits;
                *last &= mask;
            }
        }
        Ok(())
    }

    /// Get the value of a specific bit by index (0 = most significant bit of
    /// first byte). Returns `false` for out-of-range indices.
    ///
    /// Replaces C `ASN1_BIT_STRING_get_bit()`.
    #[must_use]
    pub fn get_bit(&self, index: usize) -> bool {
        let byte_index = index / 8;
        let bit_index = 7 - (index % 8);
        if byte_index >= self.data.len() {
            return false;
        }
        // Check if this bit is within the meaningful range (not trailing
        // unused).
        if byte_index == self.data.len() - 1 && (index % 8) >= 8 - self.unused_bits as usize {
            return false;
        }
        (self.data[byte_index] & (1 << bit_index)) != 0
    }

    /// Set the value of a specific bit. Extends the data buffer as needed.
    ///
    /// Replaces C `ASN1_BIT_STRING_set_bit()`.
    pub fn set_bit(&mut self, index: usize, value: bool) -> CryptoResult<()> {
        let byte_index = index / 8;
        let bit_index = 7 - (index % 8);
        // Expand buffer if needed.
        if byte_index >= self.data.len() {
            self.data.resize(byte_index + 1, 0);
            self.unused_bits = 0;
        }
        if value {
            self.data[byte_index] |= 1u8 << bit_index;
        } else {
            self.data[byte_index] &= !(1u8 << bit_index);
        }
        // Update unused_bits if we extended data.
        // If this is the last byte and we changed a bit within the meaningful
        // range, the unused_bits count may need updating.
        let target_unused = 7u8 - u8::try_from(index % 8).unwrap_or(0);
        if byte_index == self.data.len() - 1 && target_unused < self.unused_bits {
            self.unused_bits = target_unused;
        }
        Ok(())
    }

    /// Check if a specific bit is set — convenience alias for `get_bit`.
    ///
    /// Replaces C `ASN1_BIT_STRING_check()`.
    #[must_use]
    pub fn check_bit(&self, index: usize) -> bool {
        self.get_bit(index)
    }

    /// Encode the BIT STRING as DER content bytes (leading unused-bits byte
    /// followed by the bit octets).
    ///
    /// Replaces C `i2c_ASN1_BIT_STRING()` from `a_bitstr.c`.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::with_capacity(self.data.len() + 1);
        out.push(self.unused_bits);
        // Apply canonical masking: unused trailing bits must be zero.
        if self.unused_bits > 0 && !self.data.is_empty() {
            let mut d = self.data.clone();
            if let Some(last) = d.last_mut() {
                let mask = 0xFFu8 << self.unused_bits;
                *last &= mask;
            }
            out.extend_from_slice(&d);
        } else {
            out.extend_from_slice(&self.data);
        }
        Ok(out)
    }

    /// Decode a BIT STRING from DER content bytes (leading unused-bits byte
    /// followed by the bit octets).
    ///
    /// Replaces C `c2i_ASN1_BIT_STRING()` from `a_bitstr.c`.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        if data.is_empty() {
            return Err(Asn1Error::InvalidLength.into());
        }
        let unused_bits = data[0];
        if unused_bits > 7 {
            return Err(Asn1Error::InvalidLength.into());
        }
        // Per X.690 §8.6.2.3: if data length is 1 (only the unused-bits byte),
        // unused_bits must be 0.
        if data.len() == 1 && unused_bits != 0 {
            return Err(Asn1Error::InvalidLength.into());
        }
        Ok(Self {
            data: data[1..].to_vec(),
            unused_bits,
        })
    }

    /// Return the raw bit-string bytes (without the unused-bits prefix).
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Return the number of unused trailing bits (0..=7).
    #[must_use]
    pub fn unused_bits(&self) -> u8 {
        self.unused_bits
    }

    /// Return the total number of bits in the string.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        self.data.len() * 8 - self.unused_bits as usize
    }
}

// =============================================================================
// Asn1OctetString — raw byte buffer
// =============================================================================

/// ASN.1 OCTET STRING — raw byte buffer.
///
/// Source: `crypto/asn1/a_octet.c` (30 lines — thin wrapper). This type is
/// a simple byte container; the DER encoding is just the raw bytes.
///
/// Implements `Zeroize` so OCTET STRING contents carrying sensitive material
/// (e.g., PKCS#8 private key bytes) can be securely erased. This is required
/// by [`Pkcs8PrivateKeyInfo`] which derives `ZeroizeOnDrop`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1OctetString {
    /// Raw byte content.
    data: Vec<u8>,
}

impl Zeroize for Asn1OctetString {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Default for Asn1OctetString {
    fn default() -> Self {
        Self::new()
    }
}

impl Asn1OctetString {
    /// Create a new empty OCTET STRING.
    #[must_use]
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create an OCTET STRING wrapping the given bytes.
    #[must_use]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Return the raw byte content.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Return the length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the OCTET STRING is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Encode as DER content bytes (identity — just the raw bytes).
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.data.clone())
    }

    /// Decode from DER content bytes (identity).
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            data: data.to_vec(),
        })
    }
}

// =============================================================================
// Asn1Object — OBJECT IDENTIFIER (OID)
// =============================================================================
//
// From crypto/asn1/a_object.c (395 lines). OID encoding per X.690 §8.19:
// first two arcs are combined as `first * 40 + second`, subsequent arcs are
// encoded in base-128 with the high bit indicating continuation.

/// ASN.1 OBJECT IDENTIFIER (OID).
///
/// Stores the DER-encoded content bytes and optional text/NID mappings.
///
/// Source: `crypto/asn1/a_object.c` (395 lines).
#[derive(Debug, Clone)]
pub struct Asn1Object {
    /// DER-encoded OID content bytes (without tag/length).
    oid_bytes: Vec<u8>,
    /// Numeric ID in the OpenSSL OID database (`None` if unregistered).
    nid: Option<i32>,
    /// Short name (e.g., "sha256").
    short_name: Option<String>,
    /// Long name (e.g., "sha256WithRSAEncryption").
    long_name: Option<String>,
}

impl Asn1Object {
    /// Parse an OID from dotted-decimal text (e.g., `"1.2.840.113549.1.1.11"`).
    ///
    /// Replaces C `OBJ_txt2obj()` and `a2d_ASN1_OBJECT()` from
    /// `crypto/asn1/a_object.c`. Supports arbitrary-precision arc values via
    /// base-128 encoding per X.690 §8.19.
    pub fn from_oid_string(oid: &str) -> CryptoResult<Self> {
        let arcs: Vec<&str> = oid.split('.').collect();
        if arcs.len() < 2 {
            return Err(
                Asn1Error::InvalidOid(format!("OID must have at least 2 arcs: {oid}")).into(),
            );
        }

        // Parse first arc: must be 0, 1, or 2.
        let first: u32 = arcs[0]
            .parse()
            .map_err(|_| Asn1Error::InvalidOid(format!("invalid first arc: {}", arcs[0])))?;
        if first > 2 {
            return Err(Asn1Error::InvalidOid(format!(
                "first arc must be 0, 1, or 2; got {first}"
            ))
            .into());
        }

        // Parse second arc: must be <= 39 if first is 0 or 1.
        let second: u64 = arcs[1]
            .parse()
            .map_err(|_| Asn1Error::InvalidOid(format!("invalid second arc: {}", arcs[1])))?;
        if first < 2 && second > 39 {
            return Err(Asn1Error::InvalidOid(format!(
                "second arc must be 0-39 when first arc is 0 or 1; got {second}"
            ))
            .into());
        }

        let mut bytes = Vec::new();
        // Combine first two arcs: first*40 + second.
        let combined = u64::from(first) * 40 + second;
        encode_base128(combined, &mut bytes);

        // Encode remaining arcs.
        for arc in &arcs[2..] {
            let value: u64 = arc
                .parse()
                .map_err(|_| Asn1Error::InvalidOid(format!("invalid arc: {arc}")))?;
            encode_base128(value, &mut bytes);
        }

        Ok(Self {
            oid_bytes: bytes,
            nid: None,
            short_name: None,
            long_name: None,
        })
    }

    /// Convert this OID back to dotted-decimal text.
    ///
    /// Replaces C `OBJ_obj2txt()` from `crypto/asn1/a_object.c`.
    pub fn to_oid_string(&self) -> CryptoResult<String> {
        if self.oid_bytes.is_empty() {
            return Err(Asn1Error::InvalidOid("empty OID".into()).into());
        }

        let mut out = String::new();
        let mut iter = self.oid_bytes.iter().copied().peekable();

        // Decode first combined value.
        let first_value = decode_base128(&mut iter)?;
        let (first, second) = if first_value < 80 {
            (first_value / 40, first_value % 40)
        } else {
            (2, first_value - 80)
        };
        out.push_str(&first.to_string());
        out.push('.');
        out.push_str(&second.to_string());

        // Decode remaining arcs.
        while iter.peek().is_some() {
            let arc = decode_base128(&mut iter)?;
            out.push('.');
            out.push_str(&arc.to_string());
        }

        Ok(out)
    }

    /// Return the numeric ID (NID) associated with this OID, if registered.
    ///
    /// Replaces C `OBJ_obj2nid()`.
    #[must_use]
    pub fn nid(&self) -> Option<i32> {
        self.nid
    }

    /// Return the short name associated with this OID, if registered.
    ///
    /// Replaces C `OBJ_nid2sn()`.
    #[must_use]
    pub fn short_name(&self) -> Option<&str> {
        self.short_name.as_deref()
    }

    /// Return the long name associated with this OID, if registered.
    ///
    /// Replaces C `OBJ_nid2ln()`.
    #[must_use]
    pub fn long_name(&self) -> Option<&str> {
        self.long_name.as_deref()
    }

    /// Return the raw DER-encoded OID bytes (without tag/length).
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.oid_bytes
    }

    /// Encode the OID as DER content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.oid_bytes.clone())
    }

    /// Decode an OID from DER content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        if data.is_empty() {
            return Err(Asn1Error::InvalidOid("empty OID encoding".into()).into());
        }
        // Validate that the encoding is well-formed per X.690 §8.19.2:
        // - Last byte of each sub-identifier must have MSB = 0.
        // - No sub-identifier may begin with 0x80 (leading zero in base-128).
        let mut expecting_start = true;
        for (i, &b) in data.iter().enumerate() {
            if expecting_start && b == 0x80 && i + 1 < data.len() && (data[i + 1] & 0x80) != 0 {
                // Leading zero in continuation.
                return Err(Asn1Error::InvalidOid("non-canonical OID encoding".into()).into());
            }
            expecting_start = (b & 0x80) == 0;
        }
        if !expecting_start {
            return Err(Asn1Error::InvalidOid("OID ends mid-sub-identifier".into()).into());
        }

        Ok(Self {
            oid_bytes: data.to_vec(),
            nid: None,
            short_name: None,
            long_name: None,
        })
    }
}

impl PartialEq for Asn1Object {
    /// Equality replaces C `OBJ_cmp()`.
    fn eq(&self, other: &Self) -> bool {
        self.oid_bytes == other.oid_bytes
    }
}

impl Eq for Asn1Object {}

impl fmt::Display for Asn1Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_oid_string() {
            Ok(s) => f.write_str(&s),
            Err(_) => f.write_str("<invalid-oid>"),
        }
    }
}

/// Encode a value in base-128 with MSB = 1 for continuation bytes, MSB = 0
/// for the final byte.
fn encode_base128(mut value: u64, out: &mut Vec<u8>) {
    if value == 0 {
        out.push(0);
        return;
    }
    let mut bytes = Vec::new();
    while value > 0 {
        let byte = (value & 0x7f) as u8;
        bytes.push(byte);
        value >>= 7;
    }
    bytes.reverse();
    for (i, b) in bytes.iter().enumerate() {
        let is_last = i == bytes.len() - 1;
        if is_last {
            out.push(*b);
        } else {
            out.push(*b | 0x80);
        }
    }
}

/// Decode a base-128 value from a byte iterator.
fn decode_base128(iter: &mut std::iter::Peekable<impl Iterator<Item = u8>>) -> CryptoResult<u64> {
    let mut value: u64 = 0;
    let mut bytes_read = 0usize;
    loop {
        let b = iter
            .next()
            .ok_or_else(|| Asn1Error::InvalidOid("truncated OID".into()))?;
        bytes_read += 1;
        // Guard against overflow of u64 (10 bytes * 7 bits = 70 bits > 64 bits).
        if bytes_read > 10 {
            return Err(Asn1Error::IntegerOverflow.into());
        }
        // Check for overflow in the shift.
        if value > (u64::MAX >> 7) {
            return Err(Asn1Error::IntegerOverflow.into());
        }
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

// =============================================================================
// Time types — Asn1Time, TimeFormat, TimeDiff
// =============================================================================
//
// From crypto/asn1/a_time.c (569 lines), a_utctm.c (105 lines),
// a_gentm.c (91 lines), a_time_posix.c (283 lines).
//
// Time ::= CHOICE {
//     utcTime         UTCTime,          -- YYMMDDHHMMSSZ, years 1950-2049
//     generalTime     GeneralizedTime   -- YYYYMMDDHHMMSSZ, any year
// }

/// ASN.1 time format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeFormat {
    /// `UTCTime` with 2-digit year (valid for 1950-2049 per RFC 5280).
    Utc,
    /// `GeneralizedTime` with 4-digit year.
    Generalized,
}

/// Difference between two `Asn1Time` values.
///
/// Replaces the `(pday, psec)` output of C `ASN1_TIME_diff()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeDiff {
    /// Whole days between the two times.
    pub days: i32,
    /// Seconds remainder (sign matches `days`).
    pub seconds: i64,
}

/// ASN.1 Time value — CHOICE of `UTCTime` or `GeneralizedTime`.
///
/// Stores calendar components (year/month/day/hour/minute/second) plus the
/// original format. All values are assumed to be UTC (trailing `Z`);
/// timezone offsets are not supported in strict RFC 5280 mode.
///
/// Source: `crypto/asn1/a_time.c` (569 lines), `a_utctm.c`, `a_gentm.c`,
/// `a_time_posix.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Time {
    /// Calendar year (full 4-digit value, not reduced).
    year: u16,
    /// Month 1..=12.
    month: u8,
    /// Day of month 1..=31.
    day: u8,
    /// Hour 0..=23.
    hour: u8,
    /// Minute 0..=59.
    minute: u8,
    /// Second 0..=59 (leap seconds are not supported).
    second: u8,
    /// Original encoding format.
    format: TimeFormat,
}

/// Minimum supported POSIX time (year 0000 = -62167219200).
const MIN_POSIX_TIME: i64 = -62_167_219_200;
/// Maximum supported POSIX time (year 9999 = 253402300799).
const MAX_POSIX_TIME: i64 = 253_402_300_799;

impl Asn1Time {
    /// Construct an `Asn1Time` from calendar components.
    ///
    /// The format is automatically chosen by [`Self::normalize`]; callers
    /// may override by constructing a `TimeFormat` directly via
    /// [`Self::with_format`].
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> CryptoResult<Self> {
        validate_calendar(year, month, day, hour, minute, second)?;
        let format = if (1950..=2049).contains(&year) {
            TimeFormat::Utc
        } else {
            TimeFormat::Generalized
        };
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            format,
        })
    }

    /// Construct an `Asn1Time` with an explicit format.
    pub fn with_format(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        format: TimeFormat,
    ) -> CryptoResult<Self> {
        validate_calendar(year, month, day, hour, minute, second)?;
        if format == TimeFormat::Utc && !(1950..=2049).contains(&year) {
            return Err(Asn1Error::InvalidTimeFormat(format!(
                "UTCTime year must be 1950-2049, got {year}"
            ))
            .into());
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            format,
        })
    }

    /// Explicitly override the ASN.1 format (`UTCTime` vs `GeneralizedTime`).
    ///
    /// Used by the generator language (`ASN1_generate_nconf`) to honour
    /// caller-specified type directives like `UTCTIME:...` or `GENTIME:...`.
    /// Replaces the manual type re-tagging in `crypto/asn1/asn1_gen.c`.
    ///
    /// Returns an error if `format` is `TimeFormat::Utc` but the year is
    /// outside the `UTCTime` range (1950-2049); `TimeFormat::Generalized` is
    /// always valid.
    pub fn force_format(&mut self, format: TimeFormat) -> CryptoResult<()> {
        if format == TimeFormat::Utc && !(1950..=2049).contains(&self.year) {
            return Err(Asn1Error::InvalidTimeFormat(format!(
                "UTCTime year must be 1950-2049, got {}",
                self.year
            ))
            .into());
        }
        self.format = format;
        Ok(())
    }

    /// Return the current system time, using `GeneralizedTime` format for
    /// dates outside the `UTCTime` range (1950-2049).
    pub fn now() -> CryptoResult<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Asn1Error::InvalidTimeFormat(format!("system time error: {e}")))?;
        let secs = i64::try_from(now.as_secs())
            .map_err(|_| Asn1Error::InvalidTimeFormat("time overflow".into()))?;
        Self::from_unix_timestamp(secs)
    }

    /// Construct from a POSIX timestamp (seconds since 1970-01-01 UTC).
    ///
    /// Replaces C `ASN1_TIME_set()`. Valid range is year 0000..=9999.
    pub fn from_unix_timestamp(ts: i64) -> CryptoResult<Self> {
        if !(MIN_POSIX_TIME..=MAX_POSIX_TIME).contains(&ts) {
            return Err(Asn1Error::InvalidTimeFormat(format!(
                "timestamp {ts} out of supported range"
            ))
            .into());
        }
        let (year, month, day, hour, minute, second) = posix_to_calendar(ts);
        Self::new(year, month, day, hour, minute, second)
    }

    /// Return the POSIX timestamp (seconds since 1970-01-01 UTC).
    ///
    /// Replaces the timegm-like conversion in `a_time_posix.c`.
    pub fn to_unix_timestamp(&self) -> CryptoResult<i64> {
        calendar_to_posix(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
    }

    /// Parse a time string in either `UTCTime` (`YYMMDDHHMMSSZ`) or
    /// `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) format.
    ///
    /// Replaces C `ASN1_TIME_set_string()` and
    /// `ASN1_TIME_set_string_X509()`. Only the strict RFC 5280 `Z`
    /// (UTC) suffix is accepted.
    pub fn parse(time_str: &str) -> CryptoResult<Self> {
        // Must end in 'Z' for strict RFC 5280.
        let trimmed = time_str.trim_end_matches('\0');
        if !trimmed.ends_with('Z') {
            return Err(
                Asn1Error::InvalidTimeFormat(format!("time must end in 'Z': {trimmed}")).into(),
            );
        }
        let body = &trimmed[..trimmed.len() - 1];
        // UTCTime: 12 chars  (YYMMDDHHMMSS)
        // GeneralizedTime: 14 chars (YYYYMMDDHHMMSS)
        match body.len() {
            12 => parse_utc_time(body),
            14 => parse_generalized_time(body),
            _ => Err(Asn1Error::InvalidTimeFormat(format!(
                "expected 12 or 14 digits before 'Z', got {}",
                body.len()
            ))
            .into()),
        }
    }

    // Note: formatting is provided by the `Display` impl below; callers still
    // get the schema-required `to_string()` method via the blanket
    // `impl<T: Display> ToString for T`. This avoids the
    // `inherent_to_string_shadow_display` lint while preserving the public
    // API surface.

    /// Compute the difference between two times as (days, seconds).
    ///
    /// Replaces C `ASN1_TIME_diff()`. Both times are converted to POSIX
    /// timestamps and subtracted; the result is split into days + seconds
    /// such that `|seconds| < 86400`.
    pub fn diff(&self, other: &Asn1Time) -> CryptoResult<TimeDiff> {
        let t1 = self.to_unix_timestamp()?;
        let t2 = other.to_unix_timestamp()?;
        let delta = t2.checked_sub(t1).ok_or(Asn1Error::IntegerOverflow)?;
        let days_i64 = delta / 86_400;
        let days = i32::try_from(days_i64).map_err(|_| Asn1Error::IntegerOverflow)?;
        let seconds = delta - days_i64 * 86_400;
        Ok(TimeDiff { days, seconds })
    }

    /// Produce a new time adjusted by the specified day and second offsets.
    ///
    /// Replaces C `X509_time_adj_ex()`.
    pub fn adjust(&self, offset_days: i32, offset_seconds: i64) -> CryptoResult<Self> {
        let ts = self.to_unix_timestamp()?;
        let day_offset = i64::from(offset_days)
            .checked_mul(86_400)
            .ok_or(Asn1Error::IntegerOverflow)?;
        let new_ts = ts
            .checked_add(day_offset)
            .and_then(|v| v.checked_add(offset_seconds))
            .ok_or(Asn1Error::IntegerOverflow)?;
        Self::from_unix_timestamp(new_ts)
    }

    /// Normalise the format selection: use `UTCTime` for years 1950-2049 and
    /// `GeneralizedTime` otherwise.
    ///
    /// Replaces the auto-selection logic in C `ASN1_TIME_to_tm()` +
    /// `ASN1_TIME_adj()`.
    #[must_use]
    pub fn normalize(&self) -> Self {
        let format = if (1950..=2049).contains(&self.year) {
            TimeFormat::Utc
        } else {
            TimeFormat::Generalized
        };
        Self { format, ..*self }
    }

    /// Encode as DER content bytes (the ASCII representation without
    /// tag/length).
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.to_string().into_bytes())
    }

    /// Decode from DER content bytes. The format is inferred from the
    /// length (12 chars = `UTCTime`, 14 chars = `GeneralizedTime`).
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let s = std::str::from_utf8(data)
            .map_err(|_| Asn1Error::InvalidTimeFormat("time bytes are not valid UTF-8".into()))?;
        Self::parse(s)
    }

    /// Return the year component (full 4-digit value).
    #[must_use]
    pub fn year(&self) -> u16 {
        self.year
    }
    /// Return the month component (1..=12).
    #[must_use]
    pub fn month(&self) -> u8 {
        self.month
    }
    /// Return the day component (1..=31).
    #[must_use]
    pub fn day(&self) -> u8 {
        self.day
    }
    /// Return the hour component (0..=23).
    #[must_use]
    pub fn hour(&self) -> u8 {
        self.hour
    }
    /// Return the minute component (0..=59).
    #[must_use]
    pub fn minute(&self) -> u8 {
        self.minute
    }
    /// Return the second component (0..=59).
    #[must_use]
    pub fn second(&self) -> u8 {
        self.second
    }
    /// Return the encoding format.
    #[must_use]
    pub fn format(&self) -> TimeFormat {
        self.format
    }
}

impl fmt::Display for Asn1Time {
    /// Format this time as a string in its native format:
    /// `YYMMDDHHMMSSZ` for `UTCTime` or `YYYYMMDDHHMMSSZ` for
    /// `GeneralizedTime`. This is the Rust equivalent of C
    /// `ASN1_TIME_print()` in its native format.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.format {
            TimeFormat::Utc => {
                let yy = self.year % 100;
                write!(
                    f,
                    "{:02}{:02}{:02}{:02}{:02}{:02}Z",
                    yy, self.month, self.day, self.hour, self.minute, self.second
                )
            }
            TimeFormat::Generalized => write!(
                f,
                "{:04}{:02}{:02}{:02}{:02}{:02}Z",
                self.year, self.month, self.day, self.hour, self.minute, self.second
            ),
        }
    }
}

impl PartialOrd for Asn1Time {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Asn1Time {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.to_unix_timestamp() {
            Ok(t1) => match other.to_unix_timestamp() {
                Ok(t2) => t1.cmp(&t2),
                Err(_) => Ordering::Less,
            },
            Err(_) => Ordering::Greater,
        }
    }
}

/// Parse a `UTCTime` body (12 ASCII digits, `YYMMDDHHMMSS`).
fn parse_utc_time(body: &str) -> CryptoResult<Asn1Time> {
    let digits = parse_ascii_digits(body, 12)?;
    let yy = digits[0] * 10 + digits[1];
    // Per RFC 5280: YY >= 50 means 19YY, YY < 50 means 20YY.
    let year: u16 = if yy >= 50 {
        1900 + u16::from(yy)
    } else {
        2000 + u16::from(yy)
    };
    let month = digits[2] * 10 + digits[3];
    let day = digits[4] * 10 + digits[5];
    let hour = digits[6] * 10 + digits[7];
    let minute = digits[8] * 10 + digits[9];
    let second = digits[10] * 10 + digits[11];
    Asn1Time::with_format(year, month, day, hour, minute, second, TimeFormat::Utc)
}

/// Parse a `GeneralizedTime` body (14 ASCII digits, `YYYYMMDDHHMMSS`).
fn parse_generalized_time(body: &str) -> CryptoResult<Asn1Time> {
    let digits = parse_ascii_digits(body, 14)?;
    let year = u16::from(digits[0]) * 1000
        + u16::from(digits[1]) * 100
        + u16::from(digits[2]) * 10
        + u16::from(digits[3]);
    let month = digits[4] * 10 + digits[5];
    let day = digits[6] * 10 + digits[7];
    let hour = digits[8] * 10 + digits[9];
    let minute = digits[10] * 10 + digits[11];
    let second = digits[12] * 10 + digits[13];
    Asn1Time::with_format(
        year,
        month,
        day,
        hour,
        minute,
        second,
        TimeFormat::Generalized,
    )
}

/// Parse `expected_len` ASCII digit characters into a `Vec<u8>` of values
/// 0..=9. Fails if any character is non-digit or the length is wrong.
fn parse_ascii_digits(s: &str, expected_len: usize) -> CryptoResult<Vec<u8>> {
    if s.len() != expected_len {
        return Err(Asn1Error::InvalidTimeFormat(format!(
            "expected {expected_len} digits, got {}",
            s.len()
        ))
        .into());
    }
    let mut out = Vec::with_capacity(expected_len);
    for ch in s.chars() {
        let d = ch.to_digit(10).ok_or_else(|| {
            Asn1Error::InvalidTimeFormat(format!("non-digit in time string: '{ch}'"))
        })?;
        // digit() is 0..=9 so u8::try_from always succeeds but we use it
        // for R6 compliance.
        let d_u8 = u8::try_from(d).map_err(|_| Asn1Error::IntegerOverflow)?;
        out.push(d_u8);
    }
    Ok(out)
}

/// Validate a calendar tuple including leap-year-aware day-of-month checks.
fn validate_calendar(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> CryptoResult<()> {
    if !(1..=12).contains(&month) {
        return Err(Asn1Error::InvalidTimeFormat(format!("month {month} out of range")).into());
    }
    if !(1..=31).contains(&day) {
        return Err(Asn1Error::InvalidTimeFormat(format!("day {day} out of range")).into());
    }
    let max_day = days_in_month(year, month);
    if day > max_day {
        return Err(Asn1Error::InvalidTimeFormat(format!(
            "day {day} exceeds {max_day} for {year}-{month}"
        ))
        .into());
    }
    if hour > 23 {
        return Err(Asn1Error::InvalidTimeFormat(format!("hour {hour} out of range")).into());
    }
    if minute > 59 {
        return Err(Asn1Error::InvalidTimeFormat(format!("minute {minute} out of range")).into());
    }
    if second > 59 {
        return Err(Asn1Error::InvalidTimeFormat(format!("second {second} out of range")).into());
    }
    Ok(())
}

/// Check if `year` is a leap year (Gregorian calendar rules).
const fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Return the number of days in `month` for the given `year`.
fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Convert calendar components to a POSIX timestamp using the Howard Hinnant
/// algorithm (see `a_time_posix.c`).
fn calendar_to_posix(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> CryptoResult<i64> {
    // Validate on every call (cheap).
    validate_calendar(year, month, day, hour, minute, second)?;

    let y = i64::from(year) - i64::from(month <= 2);
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days.checked_mul(86_400).ok_or(Asn1Error::IntegerOverflow)?;
    let time_of_day = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    seconds
        .checked_add(time_of_day)
        .ok_or_else(|| Asn1Error::IntegerOverflow.into())
}

/// Convert a POSIX timestamp to calendar components (Howard Hinnant).
fn posix_to_calendar(ts: i64) -> (u16, u8, u8, u8, u8, u8) {
    // Split into days + time-of-day, handling negative remainders.
    let mut days = ts.div_euclid(86_400);
    let tod = ts.rem_euclid(86_400);
    // `tod` is in `[0, 86_400)` by construction, so `tod / 3600 ∈ [0, 23]`,
    // `(tod % 3600) / 60 ∈ [0, 59]`, and `tod % 60 ∈ [0, 59]`. Each fits in
    // a u8 losslessly; `try_from` elides the truncation warning without a
    // branch in the happy path.
    let hour = u8::try_from(tod / 3600).unwrap_or(0);
    let minute = u8::try_from((tod % 3600) / 60).unwrap_or(0);
    let second = u8::try_from(tod % 60).unwrap_or(0);

    days += 719_468;
    let era = if days >= 0 {
        days / 146_097
    } else {
        (days - 146_096) / 146_097
    };
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);

    (
        u16::try_from(year).unwrap_or(0),
        u8::try_from(m).unwrap_or(1),
        u8::try_from(d).unwrap_or(1),
        hour,
        minute,
        second,
    )
}

// =============================================================================
// Asn1Null and Asn1Boolean
// =============================================================================

/// ASN.1 NULL — zero-length value.
///
/// Source: `crypto/asn1/tasn_typ.c` line 75 (`ASN1_ITEM_TEMPLATE(ASN1_NULL)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Asn1Null;

impl Asn1Null {
    /// Construct a new NULL value.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Encode as DER content bytes (always empty).
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(Vec::new())
    }

    /// Decode from DER content bytes. Non-empty content is an error per
    /// X.690 §8.8.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        if !data.is_empty() {
            return Err(Asn1Error::DecodingError(format!(
                "NULL must have empty content, got {} bytes",
                data.len()
            ))
            .into());
        }
        Ok(Self)
    }
}

/// ASN.1 BOOLEAN with support for DEFAULT TRUE / DEFAULT FALSE variants.
///
/// Source: `crypto/asn1/tasn_typ.c` lines 69-71
/// (`ASN1_BOOLEAN`, `ASN1_TBOOLEAN`, `ASN1_FBOOLEAN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Boolean {
    /// The boolean value.
    pub value: bool,
    /// Default value for OPTIONAL fields.
    ///
    /// - `Some(true)` — `DEFAULT TRUE`
    /// - `Some(false)` — `DEFAULT FALSE`
    /// - `None` — no default (always encoded)
    pub default_value: Option<bool>,
}

impl Asn1Boolean {
    /// Construct a plain BOOLEAN without any default.
    #[must_use]
    pub const fn new(value: bool) -> Self {
        Self {
            value,
            default_value: None,
        }
    }

    /// Construct a BOOLEAN with `DEFAULT TRUE`.
    #[must_use]
    pub const fn with_default_true(value: bool) -> Self {
        Self {
            value,
            default_value: Some(true),
        }
    }

    /// Construct a BOOLEAN with `DEFAULT FALSE`.
    #[must_use]
    pub const fn with_default_false(value: bool) -> Self {
        Self {
            value,
            default_value: Some(false),
        }
    }

    /// Return `true` if the value equals the declared default (so it may be
    /// omitted in DER-canonical encoding).
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.default_value == Some(self.value)
    }

    /// Encode as a DER content byte: `0x00` for false, `0xFF` for true
    /// (per X.690 §11.1).
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(vec![if self.value { 0xFF } else { 0x00 }])
    }

    /// Decode from a DER content byte. Per DER, the byte must be `0x00`
    /// (false) or `0xFF` (true).
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        if data.len() != 1 {
            return Err(Asn1Error::DecodingError(format!(
                "BOOLEAN must be 1 byte, got {}",
                data.len()
            ))
            .into());
        }
        let value = match data[0] {
            0x00 => false,
            0xFF => true,
            b => {
                return Err(Asn1Error::DecodingError(format!(
                    "non-canonical BOOLEAN byte: 0x{b:02x}"
                ))
                .into());
            }
        };
        Ok(Self {
            value,
            default_value: None,
        })
    }
}

impl From<bool> for Asn1Boolean {
    fn from(value: bool) -> Self {
        Self::new(value)
    }
}

// =============================================================================
// Asn1Type — ANY type (tagged union)
// =============================================================================
//
// From crypto/asn1/a_type.c (139 lines). ASN1_TYPE is a union that can hold
// any ASN.1 value via a type discriminator. In Rust this maps naturally to
// an enum.

/// ASN.1 ANY type — tagged union that can hold any ASN.1 value.
///
/// Replaces C `ASN1_TYPE` from `crypto/asn1/a_type.c`.
#[derive(Debug, Clone)]
pub enum Asn1Type {
    /// BOOLEAN.
    Boolean(Asn1Boolean),
    /// INTEGER.
    Integer(Asn1Integer),
    /// BIT STRING.
    BitString(Asn1BitString),
    /// OCTET STRING.
    OctetString(Asn1OctetString),
    /// NULL.
    Null(Asn1Null),
    /// OBJECT IDENTIFIER.
    ObjectIdentifier(Asn1Object),
    /// ENUMERATED.
    Enumerated(Asn1Enumerated),
    /// `UTF8String`.
    Utf8String(Asn1String),
    /// SEQUENCE (stored as raw DER content bytes).
    Sequence(Vec<u8>),
    /// SET (stored as raw DER content bytes).
    Set(Vec<u8>),
    /// `PrintableString`.
    PrintableString(Asn1String),
    /// `T61String` (`TeletexString`).
    T61String(Asn1String),
    /// `IA5String`.
    Ia5String(Asn1String),
    /// `UTCTime`.
    UtcTime(Asn1Time),
    /// `GeneralizedTime`.
    GeneralizedTime(Asn1Time),
    /// `VisibleString`.
    VisibleString(Asn1String),
    /// `UniversalString`.
    UniversalString(Asn1String),
    /// `BMPString`.
    BmpString(Asn1String),
    /// Unrecognised or application-specific type.
    Other {
        /// Tag number.
        tag: Asn1Tag,
        /// Tag class.
        class: Asn1Class,
        /// Raw content bytes.
        data: Vec<u8>,
    },
}

impl Asn1Type {
    /// Return the ASN.1 tag associated with this value.
    ///
    /// Replaces C `ASN1_TYPE_get()`.
    #[must_use]
    pub fn get_tag(&self) -> Asn1Tag {
        match self {
            Self::Boolean(_) => Asn1Tag::Boolean,
            Self::Integer(_) => Asn1Tag::Integer,
            Self::BitString(_) => Asn1Tag::BitString,
            Self::OctetString(_) => Asn1Tag::OctetString,
            Self::Null(_) => Asn1Tag::Null,
            Self::ObjectIdentifier(_) => Asn1Tag::ObjectIdentifier,
            Self::Enumerated(_) => Asn1Tag::Enumerated,
            Self::Utf8String(_) => Asn1Tag::Utf8String,
            Self::Sequence(_) => Asn1Tag::Sequence,
            Self::Set(_) => Asn1Tag::Set,
            Self::PrintableString(_) => Asn1Tag::PrintableString,
            Self::T61String(_) => Asn1Tag::T61String,
            Self::Ia5String(_) => Asn1Tag::Ia5String,
            Self::UtcTime(_) => Asn1Tag::UtcTime,
            Self::GeneralizedTime(_) => Asn1Tag::GeneralizedTime,
            Self::VisibleString(_) => Asn1Tag::VisibleString,
            Self::UniversalString(_) => Asn1Tag::UniversalString,
            Self::BmpString(_) => Asn1Tag::BmpString,
            Self::Other { tag, .. } => *tag,
        }
    }

    /// Replace the current value with `value`.
    ///
    /// Replaces C `ASN1_TYPE_set()`.
    pub fn set(&mut self, value: Asn1Type) {
        *self = value;
    }

    /// Encode this value as a full DER TLV (tag + length + content).
    ///
    /// This is symmetric with [`Self::decode_der`]: the bytes returned here
    /// are directly consumable by `Self::decode_der`. For the primitive
    /// variants (INTEGER, BOOLEAN, OCTET STRING, …) the inner type's
    /// `encode_der` produces the content octets; this method wraps them in
    /// the appropriate identifier and length octets.
    ///
    /// For `Self::Other { class, tag, data }`, the `class` is preserved
    /// (so context-specific / application / private tags round-trip
    /// correctly) and the content is taken from `data` verbatim.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        // Determine the (class, constructed, content) triple. Everything is
        // universal + primitive except SEQUENCE/SET (constructed) and the
        // `Other` variant (which preserves its original class).
        let (class, constructed, content): (Asn1Class, bool, Vec<u8>) = match self {
            Self::Boolean(v) => (Asn1Class::Universal, false, v.encode_der()?),
            Self::Integer(v) => (Asn1Class::Universal, false, v.encode_der()?),
            Self::BitString(v) => (Asn1Class::Universal, false, v.encode_der()?),
            Self::OctetString(v) => (Asn1Class::Universal, false, v.encode_der()?),
            Self::Null(v) => (Asn1Class::Universal, false, v.encode_der()?),
            Self::ObjectIdentifier(v) => (Asn1Class::Universal, false, v.encode_der()?),
            Self::Enumerated(v) => (Asn1Class::Universal, false, v.encode_der()?),
            Self::Utf8String(v)
            | Self::PrintableString(v)
            | Self::T61String(v)
            | Self::Ia5String(v)
            | Self::VisibleString(v)
            | Self::UniversalString(v)
            | Self::BmpString(v) => (Asn1Class::Universal, false, v.data().to_vec()),
            Self::Sequence(v) | Self::Set(v) => (Asn1Class::Universal, true, v.clone()),
            Self::UtcTime(v) | Self::GeneralizedTime(v) => {
                (Asn1Class::Universal, false, v.encode_der()?)
            }
            Self::Other { class, data, .. } => (*class, false, data.clone()),
        };
        let tag = self.get_tag();
        let mut out = write_tlv_header(tag, class, constructed, content.len())?;
        out.extend_from_slice(&content);
        Ok(out)
    }

    /// Decode a full DER-encoded value (with tag + length) into an
    /// `Asn1Type`. Unknown tags become `Other { .. }`.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let header = parse_tlv_header(data)?;
        let start = header.header_length;
        let clen = header
            .content_length
            .ok_or_else(|| Asn1Error::DecodingError("indefinite length not supported".into()))?;
        let end = start.checked_add(clen).ok_or(Asn1Error::IntegerOverflow)?;
        if end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: end,
                actual: data.len(),
            }
            .into());
        }
        let content = &data[start..end];

        if header.class != Asn1Class::Universal {
            return Ok(Self::Other {
                tag: header.tag,
                class: header.class,
                data: content.to_vec(),
            });
        }

        Ok(match header.tag {
            Asn1Tag::Boolean => Self::Boolean(Asn1Boolean::decode_der(content)?),
            Asn1Tag::Integer => Self::Integer(Asn1Integer::decode_der(content)?),
            Asn1Tag::BitString => Self::BitString(Asn1BitString::decode_der(content)?),
            Asn1Tag::OctetString => Self::OctetString(Asn1OctetString::decode_der(content)?),
            Asn1Tag::Null => Self::Null(Asn1Null::decode_der(content)?),
            Asn1Tag::ObjectIdentifier => Self::ObjectIdentifier(Asn1Object::decode_der(content)?),
            Asn1Tag::Enumerated => Self::Enumerated(Asn1Enumerated::decode_der(content)?),
            Asn1Tag::Utf8String => {
                let mut s = Asn1String::new(Asn1Tag::Utf8String);
                s.set(content)?;
                Self::Utf8String(s)
            }
            Asn1Tag::Sequence => Self::Sequence(content.to_vec()),
            Asn1Tag::Set => Self::Set(content.to_vec()),
            Asn1Tag::PrintableString => {
                let mut s = Asn1String::new(Asn1Tag::PrintableString);
                s.set(content)?;
                Self::PrintableString(s)
            }
            Asn1Tag::T61String => {
                let mut s = Asn1String::new(Asn1Tag::T61String);
                s.set(content)?;
                Self::T61String(s)
            }
            Asn1Tag::Ia5String => {
                let mut s = Asn1String::new(Asn1Tag::Ia5String);
                s.set(content)?;
                Self::Ia5String(s)
            }
            Asn1Tag::UtcTime => Self::UtcTime(Asn1Time::decode_der(content)?),
            Asn1Tag::GeneralizedTime => Self::GeneralizedTime(Asn1Time::decode_der(content)?),
            Asn1Tag::VisibleString => {
                let mut s = Asn1String::new(Asn1Tag::VisibleString);
                s.set(content)?;
                Self::VisibleString(s)
            }
            Asn1Tag::UniversalString => {
                let mut s = Asn1String::new(Asn1Tag::UniversalString);
                s.set(content)?;
                Self::UniversalString(s)
            }
            Asn1Tag::BmpString => {
                let mut s = Asn1String::new(Asn1Tag::BmpString);
                s.set(content)?;
                Self::BmpString(s)
            }
            other => Self::Other {
                tag: other,
                class: header.class,
                data: content.to_vec(),
            },
        })
    }
}

impl PartialEq for Asn1Type {
    /// Equality replaces C `ASN1_TYPE_cmp()`: two values are equal iff they
    /// have the same tag and the same raw DER-content encoding.
    fn eq(&self, other: &Self) -> bool {
        if self.get_tag() != other.get_tag() {
            return false;
        }
        match (self.encode_der(), other.encode_der()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

// =============================================================================
// StringEncoding — MBString encoding discriminator
// =============================================================================

/// String encoding used by `select_string_type` / `transcode_string`.
///
/// Replaces C `MBSTRING_ASC` / `MBSTRING_BMP` / `MBSTRING_UNIV` /
/// `MBSTRING_UTF8` from `a_mbstr.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    /// 7-bit ASCII (single byte per char).
    Ascii,
    /// UTF-8 (variable bytes per char).
    Utf8,
    /// ISO-8859-1 / Latin-1 (single byte per char).
    Latin1,
    /// UCS-2 (2 bytes per char, big-endian).
    Ucs2,
    /// UCS-4 (4 bytes per char, big-endian).
    Ucs4,
}

// =============================================================================
// TlvHeader — parsed TLV metadata
// =============================================================================

/// Parsed TLV header returned by [`parse_tlv_header`].
#[derive(Debug, Clone)]
pub struct TlvHeader {
    /// The tag value.
    pub tag: Asn1Tag,
    /// The tag class.
    pub class: Asn1Class,
    /// `true` if this is a constructed (compound) encoding.
    pub constructed: bool,
    /// Content length in bytes (`None` for indefinite BER encoding).
    pub content_length: Option<usize>,
    /// Total header (tag + length) size in bytes.
    pub header_length: usize,
}

// =============================================================================
// Composite X.509 types: AlgorithmIdentifier, DigestInfo, Validity
// =============================================================================

/// X.509 `AlgorithmIdentifier`: algorithm OID + optional parameters.
///
/// ```text
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///     algorithm               OBJECT IDENTIFIER,
///     parameters              ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```
///
/// Source: `crypto/asn1/x_algor.c` (203 lines).
#[derive(Debug, Clone, PartialEq)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID.
    pub algorithm: Asn1Object,
    /// Optional parameters (NULL for many algorithms, SEQUENCE for others).
    pub parameters: Option<Asn1Type>,
}

impl AlgorithmIdentifier {
    /// Construct a new `AlgorithmIdentifier`.
    #[must_use]
    pub fn new(algorithm: Asn1Object, parameters: Option<Asn1Type>) -> Self {
        Self {
            algorithm,
            parameters,
        }
    }

    /// Encode as DER content bytes of the outer SEQUENCE (without the outer
    /// SEQUENCE tag/length).
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();
        // Encode OID as a full TLV.
        let alg_content = self.algorithm.encode_der()?;
        let alg_hdr = write_tlv_header(
            Asn1Tag::ObjectIdentifier,
            Asn1Class::Universal,
            false,
            alg_content.len(),
        )?;
        out.extend_from_slice(&alg_hdr);
        out.extend_from_slice(&alg_content);

        // Encode parameters if present. `Asn1Type::encode_der` already
        // returns a full TLV (tag + length + content), so we simply append
        // the bytes — no additional wrapping required.
        if let Some(params) = &self.parameters {
            out.extend_from_slice(&params.encode_der()?);
        }
        Ok(out)
    }

    /// Decode from DER-encoded SEQUENCE content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        // Parse the OID (first element).
        let alg_hdr = parse_tlv_header(data)?;
        if alg_hdr.tag != Asn1Tag::ObjectIdentifier {
            return Err(
                Asn1Error::DecodingError("AlgorithmIdentifier: expected OID".into()).into(),
            );
        }
        let alg_start = alg_hdr.header_length;
        let alg_end = alg_start
            .checked_add(alg_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if alg_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: alg_end,
                actual: data.len(),
            }
            .into());
        }
        let algorithm = Asn1Object::decode_der(&data[alg_start..alg_end])?;

        // Parse optional parameters.
        let parameters = if alg_end < data.len() {
            Some(Asn1Type::decode_der(&data[alg_end..])?)
        } else {
            None
        };

        Ok(Self {
            algorithm,
            parameters,
        })
    }
}

/// `DigestInfo` — the PKCS#1 / PKCS#7 `DigestInfo` structure.
///
/// ```text
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest OCTET STRING
/// }
/// ```
///
/// Source: `crypto/asn1/x_sig.c` (40 lines).
#[derive(Debug, Clone, PartialEq)]
pub struct DigestInfo {
    /// Digest algorithm identifier.
    pub digest_algorithm: AlgorithmIdentifier,
    /// Digest value.
    pub digest: Asn1OctetString,
}

impl DigestInfo {
    /// Construct a new `DigestInfo`.
    #[must_use]
    pub fn new(digest_algorithm: AlgorithmIdentifier, digest: Asn1OctetString) -> Self {
        Self {
            digest_algorithm,
            digest,
        }
    }

    /// Encode as DER SEQUENCE content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();
        let alg_content = self.digest_algorithm.encode_der()?;
        let alg_hdr = write_tlv_header(
            Asn1Tag::Sequence,
            Asn1Class::Universal,
            true,
            alg_content.len(),
        )?;
        out.extend_from_slice(&alg_hdr);
        out.extend_from_slice(&alg_content);

        let dig_content = self.digest.encode_der()?;
        let dig_hdr = write_tlv_header(
            Asn1Tag::OctetString,
            Asn1Class::Universal,
            false,
            dig_content.len(),
        )?;
        out.extend_from_slice(&dig_hdr);
        out.extend_from_slice(&dig_content);

        Ok(out)
    }

    /// Decode from DER SEQUENCE content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let alg_hdr = parse_tlv_header(data)?;
        if alg_hdr.tag != Asn1Tag::Sequence {
            return Err(Asn1Error::DecodingError(
                "DigestInfo: expected SEQUENCE for algorithm".into(),
            )
            .into());
        }
        let alg_start = alg_hdr.header_length;
        let alg_end = alg_start
            .checked_add(alg_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if alg_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: alg_end,
                actual: data.len(),
            }
            .into());
        }
        let digest_algorithm = AlgorithmIdentifier::decode_der(&data[alg_start..alg_end])?;

        let dig_hdr = parse_tlv_header(&data[alg_end..])?;
        if dig_hdr.tag != Asn1Tag::OctetString {
            return Err(Asn1Error::DecodingError(
                "DigestInfo: expected OCTET STRING for digest".into(),
            )
            .into());
        }
        let dig_start = alg_end + dig_hdr.header_length;
        let dig_end = dig_start
            .checked_add(dig_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if dig_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: dig_end,
                actual: data.len(),
            }
            .into());
        }
        let digest = Asn1OctetString::decode_der(&data[dig_start..dig_end])?;

        Ok(Self {
            digest_algorithm,
            digest,
        })
    }
}

/// Validity period for an X.509 certificate.
///
/// ```text
/// Validity ::= SEQUENCE {
///     notBefore Time,
///     notAfter  Time
/// }
/// ```
///
/// Source: `crypto/asn1/x_val.c` (21 lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validity {
    /// Not-before time.
    pub not_before: Asn1Time,
    /// Not-after time.
    pub not_after: Asn1Time,
}

impl Validity {
    /// Construct a new Validity period.
    #[must_use]
    pub fn new(not_before: Asn1Time, not_after: Asn1Time) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// Check that `not_before <= not_after`.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.not_before <= self.not_after
    }

    /// Encode as DER SEQUENCE content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();
        for time in [&self.not_before, &self.not_after] {
            let content = time.encode_der()?;
            let tag = match time.format() {
                TimeFormat::Utc => Asn1Tag::UtcTime,
                TimeFormat::Generalized => Asn1Tag::GeneralizedTime,
            };
            let hdr = write_tlv_header(tag, Asn1Class::Universal, false, content.len())?;
            out.extend_from_slice(&hdr);
            out.extend_from_slice(&content);
        }
        Ok(out)
    }

    /// Decode from DER SEQUENCE content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let nb_hdr = parse_tlv_header(data)?;
        let nb_start = nb_hdr.header_length;
        let nb_end = nb_start
            .checked_add(nb_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if nb_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: nb_end,
                actual: data.len(),
            }
            .into());
        }
        let not_before = Asn1Time::decode_der(&data[nb_start..nb_end])?;

        let na_hdr = parse_tlv_header(&data[nb_end..])?;
        let na_start = nb_end + na_hdr.header_length;
        let na_end = na_start
            .checked_add(na_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if na_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: na_end,
                actual: data.len(),
            }
            .into());
        }
        let not_after = Asn1Time::decode_der(&data[na_start..na_end])?;

        Ok(Self {
            not_before,
            not_after,
        })
    }
}

// =============================================================================
// PKCS#5 and PKCS#8 Parameter Types
// =============================================================================

/// PKCS#5 v1.5 PBE parameters.
///
/// ```text
/// PBEParameter ::= SEQUENCE {
///     salt           OCTET STRING (SIZE(8..*)),
///     iterationCount INTEGER
/// }
/// ```
///
/// Source: `crypto/asn1/p5_pbe.c` (113 lines).
#[derive(Debug, Clone, PartialEq)]
pub struct PbeParam {
    /// Salt bytes (>= 8 bytes per RFC 8018).
    pub salt: Asn1OctetString,
    /// Iteration count.
    pub iteration_count: Asn1Integer,
}

impl PbeParam {
    /// Default iteration count used by OpenSSL (`PKCS5_DEFAULT_ITER`).
    pub const DEFAULT_ITER: u64 = 2048;

    /// Construct new PBE parameters.
    #[must_use]
    pub fn new(salt: Asn1OctetString, iteration_count: Asn1Integer) -> Self {
        Self {
            salt,
            iteration_count,
        }
    }

    /// Encode as DER SEQUENCE content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();

        let salt_content = self.salt.encode_der()?;
        let salt_hdr = write_tlv_header(
            Asn1Tag::OctetString,
            Asn1Class::Universal,
            false,
            salt_content.len(),
        )?;
        out.extend_from_slice(&salt_hdr);
        out.extend_from_slice(&salt_content);

        let iter_content = self.iteration_count.encode_der()?;
        let iter_hdr = write_tlv_header(
            Asn1Tag::Integer,
            Asn1Class::Universal,
            false,
            iter_content.len(),
        )?;
        out.extend_from_slice(&iter_hdr);
        out.extend_from_slice(&iter_content);

        Ok(out)
    }

    /// Decode from DER SEQUENCE content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let salt_hdr = parse_tlv_header(data)?;
        if salt_hdr.tag != Asn1Tag::OctetString {
            return Err(
                Asn1Error::DecodingError("PbeParam: expected OCTET STRING salt".into()).into(),
            );
        }
        let s_start = salt_hdr.header_length;
        let s_end = s_start
            .checked_add(salt_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if s_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: s_end,
                actual: data.len(),
            }
            .into());
        }
        let salt = Asn1OctetString::decode_der(&data[s_start..s_end])?;

        let iter_hdr = parse_tlv_header(&data[s_end..])?;
        if iter_hdr.tag != Asn1Tag::Integer {
            return Err(Asn1Error::DecodingError(
                "PbeParam: expected INTEGER iteration count".into(),
            )
            .into());
        }
        let i_start = s_end + iter_hdr.header_length;
        let i_end = i_start
            .checked_add(iter_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if i_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: i_end,
                actual: data.len(),
            }
            .into());
        }
        let iteration_count = Asn1Integer::decode_der(&data[i_start..i_end])?;

        Ok(Self {
            salt,
            iteration_count,
        })
    }
}

/// PKCS#5 v2 PBES2 parameters (the outer container for PBKDF2 / scrypt + cipher).
///
/// ```text
/// PBES2-params ::= SEQUENCE {
///     keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
///     encryptionScheme  AlgorithmIdentifier {{PBES2-Encs}}
/// }
/// ```
///
/// Source: `crypto/asn1/p5_pbev2.c` (280 lines).
#[derive(Debug, Clone, PartialEq)]
pub struct Pbes2Param {
    /// Key-derivation function `AlgorithmIdentifier` (usually PBKDF2 or scrypt).
    pub key_derivation: AlgorithmIdentifier,
    /// Encryption scheme `AlgorithmIdentifier` (e.g. aes-128-cbc).
    pub encryption: AlgorithmIdentifier,
}

impl Pbes2Param {
    /// Construct a new PBES2 parameter block.
    #[must_use]
    pub fn new(key_derivation: AlgorithmIdentifier, encryption: AlgorithmIdentifier) -> Self {
        Self {
            key_derivation,
            encryption,
        }
    }

    /// Encode as DER SEQUENCE content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();
        for algo in [&self.key_derivation, &self.encryption] {
            let content = algo.encode_der()?;
            let hdr =
                write_tlv_header(Asn1Tag::Sequence, Asn1Class::Universal, true, content.len())?;
            out.extend_from_slice(&hdr);
            out.extend_from_slice(&content);
        }
        Ok(out)
    }

    /// Decode from DER SEQUENCE content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let kdf_hdr = parse_tlv_header(data)?;
        if kdf_hdr.tag != Asn1Tag::Sequence {
            return Err(
                Asn1Error::DecodingError("Pbes2Param: expected SEQUENCE for KDF".into()).into(),
            );
        }
        let kdf_start = kdf_hdr.header_length;
        let kdf_end = kdf_start
            .checked_add(kdf_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if kdf_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: kdf_end,
                actual: data.len(),
            }
            .into());
        }
        let key_derivation = AlgorithmIdentifier::decode_der(&data[kdf_start..kdf_end])?;

        let enc_hdr = parse_tlv_header(&data[kdf_end..])?;
        if enc_hdr.tag != Asn1Tag::Sequence {
            return Err(Asn1Error::DecodingError(
                "Pbes2Param: expected SEQUENCE for encryption".into(),
            )
            .into());
        }
        let enc_start = kdf_end + enc_hdr.header_length;
        let enc_end = enc_start
            .checked_add(enc_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if enc_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: enc_end,
                actual: data.len(),
            }
            .into());
        }
        let encryption = AlgorithmIdentifier::decode_der(&data[enc_start..enc_end])?;

        Ok(Self {
            key_derivation,
            encryption,
        })
    }
}

/// PKCS#5 v2 PBKDF2 parameters (RFC 8018).
///
/// ```text
/// PBKDF2-params ::= SEQUENCE {
///     salt            CHOICE { specified OCTET STRING, otherSource AlgorithmIdentifier },
///     iterationCount  INTEGER (1..MAX),
///     keyLength       INTEGER (1..MAX) OPTIONAL,
///     prf             AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
/// }
/// ```
///
/// Source: `crypto/asn1/p5_pbev2.c`.
#[derive(Debug, Clone, PartialEq)]
pub struct Pbkdf2Param {
    /// Salt (specified OCTET STRING form only — otherSource unsupported).
    pub salt: Asn1OctetString,
    /// Iteration count.
    pub iteration_count: Asn1Integer,
    /// Optional derived key length.
    pub key_length: Option<Asn1Integer>,
    /// Optional pseudo-random function (defaults to HMAC-SHA1 if absent).
    pub prf: Option<AlgorithmIdentifier>,
}

impl Pbkdf2Param {
    /// Construct a new PBKDF2 parameter block.
    #[must_use]
    pub fn new(
        salt: Asn1OctetString,
        iteration_count: Asn1Integer,
        key_length: Option<Asn1Integer>,
        prf: Option<AlgorithmIdentifier>,
    ) -> Self {
        Self {
            salt,
            iteration_count,
            key_length,
            prf,
        }
    }

    /// Encode as DER SEQUENCE content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();

        let salt_content = self.salt.encode_der()?;
        let salt_hdr = write_tlv_header(
            Asn1Tag::OctetString,
            Asn1Class::Universal,
            false,
            salt_content.len(),
        )?;
        out.extend_from_slice(&salt_hdr);
        out.extend_from_slice(&salt_content);

        let iter_content = self.iteration_count.encode_der()?;
        let iter_hdr = write_tlv_header(
            Asn1Tag::Integer,
            Asn1Class::Universal,
            false,
            iter_content.len(),
        )?;
        out.extend_from_slice(&iter_hdr);
        out.extend_from_slice(&iter_content);

        if let Some(kl) = &self.key_length {
            let kl_content = kl.encode_der()?;
            let kl_hdr = write_tlv_header(
                Asn1Tag::Integer,
                Asn1Class::Universal,
                false,
                kl_content.len(),
            )?;
            out.extend_from_slice(&kl_hdr);
            out.extend_from_slice(&kl_content);
        }

        if let Some(prf) = &self.prf {
            let prf_content = prf.encode_der()?;
            let prf_hdr = write_tlv_header(
                Asn1Tag::Sequence,
                Asn1Class::Universal,
                true,
                prf_content.len(),
            )?;
            out.extend_from_slice(&prf_hdr);
            out.extend_from_slice(&prf_content);
        }

        Ok(out)
    }

    /// Decode from DER SEQUENCE content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let mut pos = 0usize;

        let salt_hdr = parse_tlv_header(&data[pos..])?;
        if salt_hdr.tag != Asn1Tag::OctetString {
            return Err(
                Asn1Error::DecodingError("Pbkdf2Param: expected OCTET STRING salt".into()).into(),
            );
        }
        let s_start = pos + salt_hdr.header_length;
        let s_end = s_start
            .checked_add(salt_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if s_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: s_end,
                actual: data.len(),
            }
            .into());
        }
        let salt = Asn1OctetString::decode_der(&data[s_start..s_end])?;
        pos = s_end;

        let iter_hdr = parse_tlv_header(&data[pos..])?;
        if iter_hdr.tag != Asn1Tag::Integer {
            return Err(Asn1Error::DecodingError(
                "Pbkdf2Param: expected INTEGER iteration count".into(),
            )
            .into());
        }
        let i_start = pos + iter_hdr.header_length;
        let i_end = i_start
            .checked_add(iter_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if i_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: i_end,
                actual: data.len(),
            }
            .into());
        }
        let iteration_count = Asn1Integer::decode_der(&data[i_start..i_end])?;
        pos = i_end;

        let mut key_length = None;
        let mut prf = None;

        while pos < data.len() {
            let hdr = parse_tlv_header(&data[pos..])?;
            let c_start = pos + hdr.header_length;
            let c_end = c_start
                .checked_add(hdr.content_length.unwrap_or(0))
                .ok_or(Asn1Error::IntegerOverflow)?;
            if c_end > data.len() {
                return Err(Asn1Error::TruncatedData {
                    expected: c_end,
                    actual: data.len(),
                }
                .into());
            }
            match hdr.tag {
                Asn1Tag::Integer => {
                    key_length = Some(Asn1Integer::decode_der(&data[c_start..c_end])?);
                }
                Asn1Tag::Sequence => {
                    prf = Some(AlgorithmIdentifier::decode_der(&data[c_start..c_end])?);
                }
                _ => {
                    return Err(Asn1Error::DecodingError(
                        "Pbkdf2Param: unexpected optional field".into(),
                    )
                    .into())
                }
            }
            pos = c_end;
        }

        Ok(Self {
            salt,
            iteration_count,
            key_length,
            prf,
        })
    }
}

/// scrypt parameters (RFC 7914).
///
/// ```text
/// scrypt-params ::= SEQUENCE {
///     salt           OCTET STRING,
///     costParameter  INTEGER (1..MAX),
///     blockSize      INTEGER (1..MAX),
///     parallelization INTEGER (1..MAX),
///     keyLength      INTEGER (1..MAX) OPTIONAL
/// }
/// ```
///
/// Source: `crypto/asn1/p5_scrypt.c` (318 lines).
#[derive(Debug, Clone, PartialEq)]
pub struct ScryptParam {
    /// Salt bytes.
    pub salt: Asn1OctetString,
    /// CPU/memory cost parameter N.
    pub cost: Asn1Integer,
    /// Block size parameter r.
    pub block_size: Asn1Integer,
    /// Parallelization parameter p.
    pub parallelization: Asn1Integer,
    /// Optional derived key length.
    pub key_length: Option<Asn1Integer>,
}

impl ScryptParam {
    /// Construct a new scrypt parameter block.
    #[must_use]
    pub fn new(
        salt: Asn1OctetString,
        cost: Asn1Integer,
        block_size: Asn1Integer,
        parallelization: Asn1Integer,
        key_length: Option<Asn1Integer>,
    ) -> Self {
        Self {
            salt,
            cost,
            block_size,
            parallelization,
            key_length,
        }
    }

    /// Encode as DER SEQUENCE content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();

        let salt_content = self.salt.encode_der()?;
        let salt_hdr = write_tlv_header(
            Asn1Tag::OctetString,
            Asn1Class::Universal,
            false,
            salt_content.len(),
        )?;
        out.extend_from_slice(&salt_hdr);
        out.extend_from_slice(&salt_content);

        for field in [&self.cost, &self.block_size, &self.parallelization] {
            let c = field.encode_der()?;
            let h = write_tlv_header(Asn1Tag::Integer, Asn1Class::Universal, false, c.len())?;
            out.extend_from_slice(&h);
            out.extend_from_slice(&c);
        }

        if let Some(kl) = &self.key_length {
            let c = kl.encode_der()?;
            let h = write_tlv_header(Asn1Tag::Integer, Asn1Class::Universal, false, c.len())?;
            out.extend_from_slice(&h);
            out.extend_from_slice(&c);
        }

        Ok(out)
    }

    /// Decode from DER SEQUENCE content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let mut pos = 0usize;

        let salt_hdr = parse_tlv_header(&data[pos..])?;
        if salt_hdr.tag != Asn1Tag::OctetString {
            return Err(
                Asn1Error::DecodingError("ScryptParam: expected OCTET STRING salt".into()).into(),
            );
        }
        let s_start = pos + salt_hdr.header_length;
        let s_end = s_start
            .checked_add(salt_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if s_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: s_end,
                actual: data.len(),
            }
            .into());
        }
        let salt = Asn1OctetString::decode_der(&data[s_start..s_end])?;
        pos = s_end;

        let mut integers: Vec<Asn1Integer> = Vec::with_capacity(4);

        while pos < data.len() && integers.len() < 4 {
            let hdr = parse_tlv_header(&data[pos..])?;
            if hdr.tag != Asn1Tag::Integer {
                break;
            }
            let c_start = pos + hdr.header_length;
            let c_end = c_start
                .checked_add(hdr.content_length.unwrap_or(0))
                .ok_or(Asn1Error::IntegerOverflow)?;
            if c_end > data.len() {
                return Err(Asn1Error::TruncatedData {
                    expected: c_end,
                    actual: data.len(),
                }
                .into());
            }
            integers.push(Asn1Integer::decode_der(&data[c_start..c_end])?);
            pos = c_end;
        }

        if integers.len() < 3 {
            return Err(Asn1Error::DecodingError(
                "ScryptParam: requires cost, blockSize, and parallelization".into(),
            )
            .into());
        }

        // After the loop, `integers` holds the decoded INTEGERs in DER stream
        // order: `[cost, blockSize, parallelization]` for the 3-integer case,
        // or `[cost, blockSize, parallelization, keyLength]` for the 4-integer
        // case (RFC 7914). Since `Vec::pop` removes from the END, we must pop
        // the optional `keyLength` FIRST (when present) to leave the three
        // required fields in their proper LIFO order for subsequent pops.
        let key_length = if integers.len() == 4 {
            integers.pop()
        } else {
            None
        };
        // `integers.len() >= 3` is enforced above; propagate via `?` to avoid
        // `expect()` (clippy `expect_used`) even though the `None` path is
        // unreachable.
        let decode_err =
            || CryptoError::Encoding("ScryptParam: missing required INTEGER component".into());
        let parallelization = integers.pop().ok_or_else(decode_err)?;
        let block_size = integers.pop().ok_or_else(decode_err)?;
        let cost = integers.pop().ok_or_else(decode_err)?;

        Ok(Self {
            salt,
            cost,
            block_size,
            parallelization,
            key_length,
        })
    }
}

/// PKCS#8 `PrivateKeyInfo`.
///
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///     version                   Version,
///     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///     privateKey                PrivateKey,
///     attributes           [0]  IMPLICIT Attributes OPTIONAL
/// }
/// ```
///
/// Source: `crypto/asn1/p8_pkey.c` (110 lines).
///
/// Derives `ZeroizeOnDrop` so that private key material is securely erased
/// from memory when the struct is dropped (per AAP §0.7.6).
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct Pkcs8PrivateKeyInfo {
    /// PKCS#8 version (must be 0 or 1).
    #[zeroize(skip)]
    pub version: Asn1Integer,
    /// Private key algorithm.
    #[zeroize(skip)]
    pub algorithm: AlgorithmIdentifier,
    /// Private key value (zeroized on drop).
    pub private_key: Asn1OctetString,
}

impl Zeroize for Pkcs8PrivateKeyInfo {
    fn zeroize(&mut self) {
        self.private_key.data.zeroize();
    }
}

impl PartialEq for Pkcs8PrivateKeyInfo {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.algorithm == other.algorithm
            && self.private_key == other.private_key
    }
}

impl Pkcs8PrivateKeyInfo {
    /// Construct a new `PrivateKeyInfo`.
    ///
    /// Per RFC 5208, `version` must be 0 (v1). RFC 5958 defines v2 = 1 which
    /// adds the optional public key field; both are accepted here, higher
    /// values are rejected.
    pub fn new(
        version: Asn1Integer,
        algorithm: AlgorithmIdentifier,
        private_key: Asn1OctetString,
    ) -> CryptoResult<Self> {
        let v = version.to_i64()?;
        if !(0..=1).contains(&v) {
            return Err(Asn1Error::DecodingError(format!(
                "Pkcs8PrivateKeyInfo: invalid version {v}"
            ))
            .into());
        }
        Ok(Self {
            version,
            algorithm,
            private_key,
        })
    }

    /// Encode as DER SEQUENCE content bytes.
    pub fn encode_der(&self) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();

        let ver_content = self.version.encode_der()?;
        let ver_hdr = write_tlv_header(
            Asn1Tag::Integer,
            Asn1Class::Universal,
            false,
            ver_content.len(),
        )?;
        out.extend_from_slice(&ver_hdr);
        out.extend_from_slice(&ver_content);

        let alg_content = self.algorithm.encode_der()?;
        let alg_hdr = write_tlv_header(
            Asn1Tag::Sequence,
            Asn1Class::Universal,
            true,
            alg_content.len(),
        )?;
        out.extend_from_slice(&alg_hdr);
        out.extend_from_slice(&alg_content);

        let pk_content = self.private_key.encode_der()?;
        let pk_hdr = write_tlv_header(
            Asn1Tag::OctetString,
            Asn1Class::Universal,
            false,
            pk_content.len(),
        )?;
        out.extend_from_slice(&pk_hdr);
        out.extend_from_slice(&pk_content);

        Ok(out)
    }

    /// Decode from DER SEQUENCE content bytes.
    pub fn decode_der(data: &[u8]) -> CryptoResult<Self> {
        let ver_hdr = parse_tlv_header(data)?;
        if ver_hdr.tag != Asn1Tag::Integer {
            return Err(Asn1Error::DecodingError(
                "Pkcs8PrivateKeyInfo: expected INTEGER version".into(),
            )
            .into());
        }
        let v_start = ver_hdr.header_length;
        let v_end = v_start
            .checked_add(ver_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if v_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: v_end,
                actual: data.len(),
            }
            .into());
        }
        let version = Asn1Integer::decode_der(&data[v_start..v_end])?;

        let alg_hdr = parse_tlv_header(&data[v_end..])?;
        if alg_hdr.tag != Asn1Tag::Sequence {
            return Err(Asn1Error::DecodingError(
                "Pkcs8PrivateKeyInfo: expected SEQUENCE algorithm".into(),
            )
            .into());
        }
        let a_start = v_end + alg_hdr.header_length;
        let a_end = a_start
            .checked_add(alg_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if a_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: a_end,
                actual: data.len(),
            }
            .into());
        }
        let algorithm = AlgorithmIdentifier::decode_der(&data[a_start..a_end])?;

        let pk_hdr = parse_tlv_header(&data[a_end..])?;
        if pk_hdr.tag != Asn1Tag::OctetString {
            return Err(Asn1Error::DecodingError(
                "Pkcs8PrivateKeyInfo: expected OCTET STRING private key".into(),
            )
            .into());
        }
        let p_start = a_end + pk_hdr.header_length;
        let p_end = p_start
            .checked_add(pk_hdr.content_length.unwrap_or(0))
            .ok_or(Asn1Error::IntegerOverflow)?;
        if p_end > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: p_end,
                actual: data.len(),
            }
            .into());
        }
        let private_key = Asn1OctetString::decode_der(&data[p_start..p_end])?;

        Self::new(version, algorithm, private_key)
    }
}

// =============================================================================
// Netscape SPKI / SPKAC
// =============================================================================

/// Signed Public-Key-And-Challenge (Netscape SPKAC).
///
/// ```text
/// PublicKeyAndChallenge ::= SEQUENCE {
///     spki    SubjectPublicKeyInfo,
///     challenge IA5STRING
/// }
/// ```
///
/// Source: `crypto/asn1/x_spki.c` (29 lines).
#[derive(Debug, Clone, PartialEq)]
pub struct Spkac {
    /// `SubjectPublicKeyInfo` stored as raw DER (SEQUENCE content bytes).
    pub public_key_and_challenge: Vec<u8>,
    /// Client-supplied challenge string (`IA5String`).
    pub challenge: Asn1String,
}

impl Spkac {
    /// Construct a new SPKAC.
    #[must_use]
    pub fn new(public_key_and_challenge: Vec<u8>, challenge: Asn1String) -> Self {
        Self {
            public_key_and_challenge,
            challenge,
        }
    }
}

/// Netscape Signed Public Key and Challenge wrapper.
///
/// ```text
/// SignedPublicKeyAndChallenge ::= SEQUENCE {
///     publicKeyAndChallenge  PublicKeyAndChallenge,
///     signatureAlgorithm     AlgorithmIdentifier,
///     signature              BIT STRING
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NetscapeSpki {
    /// The signed payload.
    pub spkac: Spkac,
    /// Signature algorithm identifier.
    pub signature_algorithm: AlgorithmIdentifier,
    /// Signature value.
    pub signature: Asn1BitString,
}

impl NetscapeSpki {
    /// Construct a new Netscape SPKI.
    #[must_use]
    pub fn new(
        spkac: Spkac,
        signature_algorithm: AlgorithmIdentifier,
        signature: Asn1BitString,
    ) -> Self {
        Self {
            spkac,
            signature_algorithm,
            signature,
        }
    }
}

// =============================================================================
// StringConstraint (string table entry)
// =============================================================================

/// A string-table entry describing constraints for a given NID.
///
/// Mirrors C `ASN1_STRING_TABLE` from `crypto/asn1/a_strnid.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringConstraint {
    /// Numeric identifier.
    pub nid: i32,
    /// Minimum length in characters (inclusive).
    pub min_size: usize,
    /// Maximum length in characters (inclusive). `usize::MAX` means unlimited.
    pub max_size: usize,
    /// Bitmask of allowed string types (combinations of `B_ASN1_*` in C).
    pub mask: u32,
    /// Miscellaneous flags (e.g. `STABLE_NO_MASK`).
    pub flags: u32,
}

// =============================================================================
// SmimeData — parsed S/MIME wrapper
// =============================================================================

/// A parsed (or to-be-written) S/MIME message.
///
/// Replaces `SMIME_read_ASN1` / `SMIME_write_ASN1` wrapper data from
/// `crypto/asn1/asn_mime.c` (1075 lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmimeData {
    /// Raw content (after MIME-decoding, canonicalised to DER).
    pub content: Vec<u8>,
    /// Content-Type header (e.g. `application/pkcs7-signature`).
    pub content_type: String,
    /// Additional MIME headers, preserved in order.
    pub headers: Vec<(String, String)>,
}

impl SmimeData {
    /// Construct a new `SmimeData`.
    #[must_use]
    pub fn new(content: Vec<u8>, content_type: String, headers: Vec<(String, String)>) -> Self {
        Self {
            content,
            content_type,
            headers,
        }
    }
}

// =============================================================================
// Low-Level TLV (Tag-Length-Value) Operations
// =============================================================================
//
// These functions implement DER/BER TLV header parsing/writing per X.690.
// Source: `crypto/asn1/asn1_lib.c` (`ASN1_get_object()` at line 46,
//         `ASN1_put_object()`, `ASN1_object_size()`).
//
// Layout of a TLV:
//
//   +-------------+----------------+-----------------+
//   | identifier  | length         | contents        |
//   | octet(s)    | octet(s)       | octets          |
//   +-------------+----------------+-----------------+
//
// Identifier octet (X.690 §8.1.2):
//   bits 8-7: tag class   (00=universal, 01=application, 10=context, 11=private)
//   bit    6: primitive/constructed (0/1)
//   bits 5-1: tag number  (if 31, multi-byte base-128 encoding follows)
//
// Length octet (X.690 §8.1.3):
//   short form: bit 8 = 0, bits 7-1 = length (0-127)
//   long form : bit 8 = 1, bits 7-1 = n = length-of-length (1-126)
//   indefinite: single byte 0x80 (content terminated by EOC 00 00)

/// Flag bit in an identifier octet indicating constructed form.
const TLV_CONSTRUCTED_BIT: u8 = 0x20;

/// Mask selecting the tag number in the identifier octet (when < 31).
const TLV_SHORT_TAG_MASK: u8 = 0x1F;

/// Value indicating the long (base-128) tag-number form.
const TLV_LONG_FORM_TAG: u8 = 0x1F;

/// Mask for the class bits in the identifier octet.
const TLV_CLASS_MASK: u8 = 0xC0;

/// Sentinel length octet indicating indefinite-length form.
const TLV_INDEFINITE_LENGTH: u8 = 0x80;

/// Absolute cap on supported TLV content length (4 GiB - 1).
///
/// This matches OpenSSL's practical cap and prevents pathological allocations
/// from malicious input. Higher values are mathematically representable in
/// `usize` on 64-bit hosts but are refused to keep behaviour uniform across
/// 32-bit and 64-bit targets.
const TLV_MAX_CONTENT_LENGTH: usize = 0xFFFF_FFFF;

/// Parse a DER/BER TLV header from the start of `data`.
///
/// Replaces C `ASN1_get_object()` from `crypto/asn1/asn1_lib.c:46`.
///
/// Returns a [`TlvHeader`] carrying the tag number, class, primitive/constructed
/// flag, content length (`None` for indefinite-length BER), and header length
/// (number of octets consumed from `data`).
///
/// Per AAP Rule R5, errors are returned via `CryptoResult` rather than
/// the out-of-band `0x80` / `0x81` sentinels of the C API.
///
/// # Errors
///
/// * `Asn1Error::TruncatedData` if `data` is shorter than the header
/// * `Asn1Error::InvalidTag` if the tag number exceeds `u32::MAX`
/// * `Asn1Error::InvalidLength` if the length field is malformed
pub fn parse_tlv_header(data: &[u8]) -> CryptoResult<TlvHeader> {
    if data.is_empty() {
        return Err(Asn1Error::TruncatedData {
            expected: 1,
            actual: 0,
        }
        .into());
    }

    let id = data[0];
    let class_bits = id & TLV_CLASS_MASK;
    let class = match class_bits {
        0x00 => Asn1Class::Universal,
        0x40 => Asn1Class::Application,
        0x80 => Asn1Class::ContextSpecific,
        0xC0 => Asn1Class::Private,
        _ => unreachable!("class_bits covers all values of id & 0xC0"),
    };
    let constructed = (id & TLV_CONSTRUCTED_BIT) != 0;

    let mut pos: usize = 1;
    let tag_number: u32 = if (id & TLV_SHORT_TAG_MASK) == TLV_LONG_FORM_TAG {
        // Long-form tag: base-128 number in subsequent octets, high bit set
        // on all but the final octet.
        decode_base128_tag(data, &mut pos)?
    } else {
        // Short-form tag (< 31): the five low bits of the identifier octet.
        u32::from(id & TLV_SHORT_TAG_MASK)
    };

    // Map the numeric tag + class to an `Asn1Tag` variant. Non-Universal
    // classes don't correspond to standardised tag values, so we use
    // `Asn1Tag::Eoc` as a placeholder marker and rely on the `class` field.
    let tag = if class == Asn1Class::Universal {
        asn1_tag_from_number(tag_number)?
    } else {
        // For non-Universal classes the caller should examine `class` and
        // the raw tag number via `header.header_length` / content bytes.
        // We store an opaque placeholder so the enum remains sound.
        match tag_number {
            0 => Asn1Tag::Eoc,
            _ => {
                // Pick an Asn1Tag whose numeric value best represents a
                // "generic" tagged value. We map through `Asn1Tag::Eoc`
                // (value 0) when no Universal mapping is possible.
                Asn1Tag::Eoc
            }
        }
    };

    if pos >= data.len() {
        return Err(Asn1Error::TruncatedData {
            expected: pos + 1,
            actual: data.len(),
        }
        .into());
    }

    let len_octet = data[pos];
    pos += 1;

    let content_length: Option<usize> = if len_octet == TLV_INDEFINITE_LENGTH {
        // Indefinite length (BER only; invalid in strict DER but we still parse
        // it to support S/MIME and streaming inputs).
        None
    } else if (len_octet & 0x80) == 0 {
        // Short form: 0-127.
        Some(usize::from(len_octet))
    } else {
        // Long form: next `n` octets are the length (big-endian).
        let n = usize::from(len_octet & 0x7F);
        if n == 0 || n > 8 {
            // n == 0 is "reserved for future use" (X.690 §8.1.3.5); n > 8
            // cannot fit in `u64` and therefore cannot fit in `usize`.
            return Err(Asn1Error::InvalidLength.into());
        }
        if pos.checked_add(n).ok_or(Asn1Error::IntegerOverflow)? > data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: pos + n,
                actual: data.len(),
            }
            .into());
        }
        let mut acc: u64 = 0;
        for &b in &data[pos..pos + n] {
            acc = acc.checked_shl(8).ok_or(Asn1Error::IntegerOverflow)?;
            acc = acc
                .checked_add(u64::from(b))
                .ok_or(Asn1Error::IntegerOverflow)?;
        }
        pos += n;
        let len = usize::try_from(acc).map_err(|_| Asn1Error::IntegerOverflow)?;
        if len > TLV_MAX_CONTENT_LENGTH {
            return Err(Asn1Error::InvalidLength.into());
        }
        Some(len)
    };

    Ok(TlvHeader {
        tag,
        class,
        constructed,
        content_length,
        header_length: pos,
    })
}

/// Decode the long (base-128) form of a tag number.
///
/// On entry `pos` points one past the identifier octet. On success `pos`
/// is advanced to the first octet *after* the encoded tag number.
fn decode_base128_tag(data: &[u8], pos: &mut usize) -> CryptoResult<u32> {
    let mut tag_number: u32 = 0;
    let mut bytes_consumed = 0usize;

    loop {
        if *pos >= data.len() {
            return Err(Asn1Error::TruncatedData {
                expected: *pos + 1,
                actual: data.len(),
            }
            .into());
        }
        let b = data[*pos];
        *pos += 1;
        bytes_consumed += 1;

        // A sequence of leading 0x80 bytes would encode a leading-zero tag,
        // which is a canonical-encoding violation. (X.690 §8.1.2.4.2 (c))
        if bytes_consumed == 1 && b == 0x80 {
            return Err(Asn1Error::InvalidTag(b).into());
        }

        tag_number = tag_number
            .checked_shl(7)
            .ok_or(Asn1Error::IntegerOverflow)?;
        tag_number = tag_number
            .checked_add(u32::from(b & 0x7F))
            .ok_or(Asn1Error::IntegerOverflow)?;

        if (b & 0x80) == 0 {
            break;
        }

        // Cap at 5 bytes — a 32-bit tag requires at most ceil(32/7) = 5
        // continuation bytes.
        if bytes_consumed > 5 {
            return Err(Asn1Error::IntegerOverflow.into());
        }
    }

    // Long-form encoding is only legal for tag numbers >= 31.
    if tag_number < 31 {
        // `tag_number < 31` guarantees the value fits in `u8`, so the
        // `try_from` cannot fail; the fallback is defensive only.
        return Err(Asn1Error::InvalidTag(u8::try_from(tag_number).unwrap_or(u8::MAX)).into());
    }

    Ok(tag_number)
}

/// Map a Universal-class numeric tag to an [`Asn1Tag`] variant.
fn asn1_tag_from_number(n: u32) -> CryptoResult<Asn1Tag> {
    Ok(match n {
        0 => Asn1Tag::Eoc,
        1 => Asn1Tag::Boolean,
        2 => Asn1Tag::Integer,
        3 => Asn1Tag::BitString,
        4 => Asn1Tag::OctetString,
        5 => Asn1Tag::Null,
        6 => Asn1Tag::ObjectIdentifier,
        7 => Asn1Tag::ObjectDescriptor,
        8 => Asn1Tag::External,
        9 => Asn1Tag::Real,
        10 => Asn1Tag::Enumerated,
        12 => Asn1Tag::Utf8String,
        16 => Asn1Tag::Sequence,
        17 => Asn1Tag::Set,
        18 => Asn1Tag::NumericString,
        19 => Asn1Tag::PrintableString,
        20 => Asn1Tag::T61String,
        21 => Asn1Tag::VideotexString,
        22 => Asn1Tag::Ia5String,
        23 => Asn1Tag::UtcTime,
        24 => Asn1Tag::GeneralizedTime,
        25 => Asn1Tag::GraphicString,
        26 => Asn1Tag::VisibleString,
        27 => Asn1Tag::GeneralString,
        28 => Asn1Tag::UniversalString,
        30 => Asn1Tag::BmpString,
        other => {
            // Clamp to a valid u8 for the error variant.
            let byte = u8::try_from(other & 0xFF).unwrap_or(0xFF);
            return Err(Asn1Error::InvalidTag(byte).into());
        }
    })
}

/// Write a DER TLV header.
///
/// Replaces C `ASN1_put_object()` from `crypto/asn1/asn1_lib.c`.
///
/// The resulting byte vector contains identifier octet(s) followed by the
/// length encoding in definite form. Indefinite length is not produced by
/// this helper — callers that need indefinite-length (BER) encoding should
/// emit an identifier octet with the constructed bit set, the literal byte
/// `0x80`, the nested content, and a final `0x00 0x00` EOC marker manually.
///
/// # Arguments
///
/// * `tag` — the ASN.1 tag number
/// * `class` — the tag class (Universal, Application, Context, Private)
/// * `constructed` — whether this is a constructed (SEQUENCE/SET) or primitive
///   encoding
/// * `content_length` — the length of the content (value) following the header
///
/// # Errors
///
/// * `Asn1Error::InvalidLength` if `content_length` exceeds
///   `TLV_MAX_CONTENT_LENGTH`
pub fn write_tlv_header(
    tag: Asn1Tag,
    class: Asn1Class,
    constructed: bool,
    content_length: usize,
) -> CryptoResult<Vec<u8>> {
    if content_length > TLV_MAX_CONTENT_LENGTH {
        return Err(Asn1Error::InvalidLength.into());
    }

    let tag_number = tag as u32;
    let mut out = Vec::with_capacity(6);

    // Identifier octet(s).
    let class_byte = class as u8;
    let constructed_byte = if constructed { TLV_CONSTRUCTED_BIT } else { 0 };

    if tag_number < 31 {
        let id = class_byte | constructed_byte | u8::try_from(tag_number).unwrap_or(0);
        out.push(id);
    } else {
        let id = class_byte | constructed_byte | TLV_LONG_FORM_TAG;
        out.push(id);
        encode_base128_tag(tag_number, &mut out);
    }

    // Length octet(s).
    if content_length < 0x80 {
        // Guarded by `content_length < 0x80`, so the cast is lossless.
        out.push(u8::try_from(content_length).unwrap_or(0));
    } else {
        // Long-form: count bytes needed.
        let mut n: u32 = 0;
        let mut tmp = content_length;
        while tmp > 0 {
            n += 1;
            tmp >>= 8;
        }
        // n bytes needed; n in range 1..=4 for content_length <= 4 GiB - 1.
        let n_u8 = u8::try_from(n).map_err(|_| Asn1Error::InvalidLength)?;
        out.push(0x80 | n_u8);
        // Shift out the high bytes first (big-endian).
        for i in (0..n).rev() {
            let shift = i.checked_mul(8).ok_or(Asn1Error::IntegerOverflow)?;
            // `& 0xFF` confines the value to `[0, 255]`, which fits in `u8`
            // losslessly. `try_from` documents the invariant and elides the
            // truncation warning; the fallback is unreachable.
            let byte = u8::try_from((content_length >> shift) & 0xFF).unwrap_or(0);
            out.push(byte);
        }
    }

    Ok(out)
}

/// Encode a tag number in the long (base-128) form.
///
/// High bit is set on all but the last octet.
fn encode_base128_tag(mut tag_number: u32, out: &mut Vec<u8>) {
    // Gather bytes in a temporary small buffer (up to 5 bytes for a 32-bit tag).
    let mut buf: [u8; 5] = [0; 5];
    let mut n: usize = 0;
    loop {
        let b = (tag_number & 0x7F) as u8;
        buf[n] = b;
        n += 1;
        tag_number >>= 7;
        if tag_number == 0 {
            break;
        }
    }
    // Emit in reverse order; set high bit on all but the last.
    for i in (0..n).rev() {
        let mut b = buf[i];
        if i != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

/// Calculate the total encoded size of a TLV with the given content length.
///
/// Replaces C `ASN1_object_size()` from `crypto/asn1/asn1_lib.c`.
///
/// # Errors
///
/// * `Asn1Error::InvalidLength` if the content length exceeds the supported
///   cap (`TLV_MAX_CONTENT_LENGTH`)
/// * `Asn1Error::IntegerOverflow` if adding the header to the content
///   overflows `usize`
pub fn tlv_encoded_size(
    constructed: bool,
    content_length: usize,
    tag: Asn1Tag,
) -> CryptoResult<usize> {
    // Silence unused-var warning in `--release`: `constructed` does not affect
    // the encoded *size*, only the identifier octet bits.
    let _ = constructed;

    if content_length > TLV_MAX_CONTENT_LENGTH {
        return Err(Asn1Error::InvalidLength.into());
    }

    // Identifier octet count.
    let id_len: usize = if (tag as u32) < 31 {
        1
    } else {
        // 1 leading identifier octet + ceil(log2(tag_number)/7) continuation bytes.
        let mut n: u32 = tag as u32;
        let mut cont: usize = 0;
        while n > 0 {
            cont += 1;
            n >>= 7;
        }
        1 + cont
    };

    // Length octet count.
    let len_len: usize = if content_length < 0x80 {
        1
    } else {
        let mut n = content_length;
        let mut k: usize = 0;
        while n > 0 {
            k += 1;
            n >>= 8;
        }
        1 + k
    };

    id_len
        .checked_add(len_len)
        .and_then(|hdr| hdr.checked_add(content_length))
        .ok_or_else(|| Asn1Error::IntegerOverflow.into())
}

// =============================================================================
// String Handling Utilities
// =============================================================================
//
// These functions implement ASN.1 string-type selection, validation, and
// transcoding per X.520/PKIX rules.
//
// Source files:
//   crypto/asn1/a_mbstr.c    (393 lines) — multi-byte string copy/select
//   crypto/asn1/a_print.c    ( 98 lines) — PrintableString checks
//   crypto/asn1/a_strex.c    (624 lines) — RFC 2253 escaping
//   crypto/asn1/a_strnid.c   (235 lines) — string-table lookup
//   crypto/asn1/a_utf8.c     (138 lines) — UTF-8 codec
//   crypto/asn1/charmap.h    ( 34 lines) — char classification bits

// -----------------------------------------------------------------------------
// Character classification masks (from charmap.h)
// -----------------------------------------------------------------------------

/// Character is a `PrintableString` constituent (A-Za-z0-9 ' ( ) + , - . / : = ?).
const CHARTYPE_PRINTABLESTRING: u8 = 0x01;
/// Character is a hyphen-minus separating `RelativeDistinguishedName` segments.
const CHARTYPE_RFC2253_QUOTE_LAST: u8 = 0x02;
/// Character needs escaping anywhere in an RDN.
const CHARTYPE_RFC2253_ESC_ANY: u8 = 0x04;
/// Character needs escaping if it is the first character.
const CHARTYPE_RFC2253_ESC_FIRST: u8 = 0x08;
/// Character needs escaping if it is the last character.
const CHARTYPE_RFC2253_ESC_LAST: u8 = 0x10;
/// Character is valid in an `IA5String` (ASCII 0-127).
const CHARTYPE_IA5STRING: u8 = 0x20;
/// Character should always be hex-escaped via `\\xx`.
const CHARTYPE_FIRST_ESC_2253: u8 = 0x40;
/// Reserved for "last character needs escaping (RFC 2253)".
const CHARTYPE_LAST_ESC_2253: u8 = 0x80;

/// Generate the 128-entry character classification table.
///
/// Mirrors the contents of `crypto/asn1/charmap.h` (generated in the C tree
/// from `mkcharmap.pl`), giving per-ASCII-codepoint classification bits.
const fn build_char_type_table() -> [u8; 128] {
    let mut table = [0u8; 128];
    // IA5String: all of 0..=127.
    let mut idx: usize = 0;
    while idx < 128 {
        table[idx] = CHARTYPE_IA5STRING;
        idx += 1;
    }
    // PrintableString: A-Z a-z 0-9 and specific punctuation.
    let mut ch: u8 = b'A';
    while ch <= b'Z' {
        table[ch as usize] |= CHARTYPE_PRINTABLESTRING;
        ch += 1;
    }
    ch = b'a';
    while ch <= b'z' {
        table[ch as usize] |= CHARTYPE_PRINTABLESTRING;
        ch += 1;
    }
    ch = b'0';
    while ch <= b'9' {
        table[ch as usize] |= CHARTYPE_PRINTABLESTRING;
        ch += 1;
    }
    // Printable punctuation: space ' ( ) + , - . / : = ?
    let printable_punct = b" '()+,-./:=?";
    let mut punct_idx: usize = 0;
    while punct_idx < printable_punct.len() {
        table[printable_punct[punct_idx] as usize] |= CHARTYPE_PRINTABLESTRING;
        punct_idx += 1;
    }
    // RFC 2253 escape-any: , + " \ < > ;
    let esc_any = b",+\"\\<>;";
    let mut esc_idx: usize = 0;
    while esc_idx < esc_any.len() {
        table[esc_any[esc_idx] as usize] |= CHARTYPE_RFC2253_ESC_ANY;
        esc_idx += 1;
    }
    // RFC 2253 escape-first: leading '#' or ' '
    table[b'#' as usize] |= CHARTYPE_RFC2253_ESC_FIRST;
    table[b' ' as usize] |= CHARTYPE_RFC2253_ESC_FIRST | CHARTYPE_RFC2253_ESC_LAST;
    // Control characters (0-31) and 127 should be hex-escaped.
    let mut ctrl: usize = 0;
    while ctrl < 32 {
        table[ctrl] |= CHARTYPE_FIRST_ESC_2253 | CHARTYPE_LAST_ESC_2253;
        ctrl += 1;
    }
    table[127] |= CHARTYPE_FIRST_ESC_2253 | CHARTYPE_LAST_ESC_2253;
    // Quote-last: handled via LAST_ESC_2253 for trailing whitespace.
    table[b' ' as usize] |= CHARTYPE_RFC2253_QUOTE_LAST;
    table
}

/// Per-ASCII-codepoint classification table (used by RFC 2253 escaping and
/// by `validate_string_content`).
static CHAR_TYPE_TABLE: [u8; 128] = build_char_type_table();

// -----------------------------------------------------------------------------
// NID / string-table constraint data (from tbl_standard.h + a_strnid.c)
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// B_ASN1_* string-type bitmask constants
// -----------------------------------------------------------------------------
//
// These constants mirror the `B_ASN1_*` macros in `include/openssl/asn1.h`.
// They are exposed as `pub const` so callers (and future template-based
// builders) can construct string-type masks matching the C API bit layout.

/// Bitmask: `NumericString` (tag 18).
pub const B_ASN1_NUMERICSTRING: u32 = 0x0001;
/// Bitmask: `PrintableString` (tag 19).
pub const B_ASN1_PRINTABLESTRING: u32 = 0x0002;
/// Bitmask: `T61String` / `TeletexString` (tag 20).
pub const B_ASN1_T61STRING: u32 = 0x0004;
/// Bitmask: `TeletexString` — alias for [`B_ASN1_T61STRING`].
pub const B_ASN1_TELETEXSTRING: u32 = 0x0004;
/// Bitmask: `VideotexString` (tag 21).
pub const B_ASN1_VIDEOTEXSTRING: u32 = 0x0008;
/// Bitmask: `IA5String` (tag 22).
pub const B_ASN1_IA5STRING: u32 = 0x0010;
/// Bitmask: `GraphicString` (tag 25).
pub const B_ASN1_GRAPHICSTRING: u32 = 0x0020;
/// Bitmask: `VisibleString` / `ISO646String` (tag 26).
pub const B_ASN1_VISIBLESTRING: u32 = 0x0040;
/// Bitmask: `GeneralString` (tag 27).
pub const B_ASN1_GENERALSTRING: u32 = 0x0080;
/// Bitmask: `UniversalString` (tag 28).
pub const B_ASN1_UNIVERSALSTRING: u32 = 0x0100;
/// Bitmask: `OctetString` (not a string per X.680, but valid in some masks).
pub const B_ASN1_OCTET_STRING: u32 = 0x0200;
/// Bitmask: `BitString` (tag 3).
pub const B_ASN1_BITSTRING: u32 = 0x0400;
/// Bitmask: `BMPString` (tag 30).
pub const B_ASN1_BMPSTRING: u32 = 0x0800;
/// Bitmask: Unknown/unclassified string type.
pub const B_ASN1_UNKNOWN: u32 = 0x1000;
/// Bitmask: `UTF8String` (tag 12).
pub const B_ASN1_UTF8STRING: u32 = 0x2000;

/// Mask covering string types permitted in PKCS#9 contexts
/// (e.g. challenge password attribute).
const PKCS9STRING_TYPE: u32 = B_ASN1_UTF8STRING
    | B_ASN1_BMPSTRING
    | B_ASN1_PRINTABLESTRING
    | B_ASN1_T61STRING
    | B_ASN1_IA5STRING;

/// Mask covering the X.520 "`DirectoryString`" CHOICE.
const DIRSTRING_TYPE: u32 = B_ASN1_PRINTABLESTRING
    | B_ASN1_UTF8STRING
    | B_ASN1_BMPSTRING
    | B_ASN1_T61STRING
    | B_ASN1_UNIVERSALSTRING;

/// Flag: ignore the global mask for this NID.
pub const STABLE_NO_MASK: u32 = 0x0002;

/// Standard NID → [`StringConstraint`] table (sorted by NID).
///
/// Mirrors `tbl_standard.h` in the C source. Values are based on RFC 3280
/// size limits for Distinguished Name attribute types.
static STRING_TABLE_ENTRIES: &[StringConstraint] = &[
    // NID 13: commonName — ub-common-name 64 characters
    StringConstraint {
        nid: 13,
        min_size: 1,
        max_size: 64,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 14: countryName — PrintableString, 2 characters
    StringConstraint {
        nid: 14,
        min_size: 2,
        max_size: 2,
        mask: B_ASN1_PRINTABLESTRING,
        flags: STABLE_NO_MASK,
    },
    // NID 15: localityName — ub-locality-name 128 characters
    StringConstraint {
        nid: 15,
        min_size: 1,
        max_size: 128,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 16: stateOrProvinceName — ub-state-name 128 characters
    StringConstraint {
        nid: 16,
        min_size: 1,
        max_size: 128,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 17: organizationName — ub-organization-name 64 characters
    StringConstraint {
        nid: 17,
        min_size: 1,
        max_size: 64,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 18: organizationalUnitName — ub-organizational-unit-name 64
    StringConstraint {
        nid: 18,
        min_size: 1,
        max_size: 64,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 41: name — ub-name 32768 characters
    StringConstraint {
        nid: 41,
        min_size: 1,
        max_size: 32768,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 42: givenName — ub-name 32768 characters
    StringConstraint {
        nid: 42,
        min_size: 1,
        max_size: 32768,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 43: initials — ub-name 32768 characters
    StringConstraint {
        nid: 43,
        min_size: 1,
        max_size: 32768,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 44: surname
    StringConstraint {
        nid: 44,
        min_size: 1,
        max_size: 32768,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 45: uniqueIdentifier — BIT STRING
    StringConstraint {
        nid: 45,
        min_size: 1,
        max_size: usize::MAX,
        mask: B_ASN1_BITSTRING,
        flags: STABLE_NO_MASK,
    },
    // NID 47: serialNumber — PrintableString
    StringConstraint {
        nid: 47,
        min_size: 1,
        max_size: 64,
        mask: B_ASN1_PRINTABLESTRING,
        flags: STABLE_NO_MASK,
    },
    // NID 48: title — ub-title 64 characters
    StringConstraint {
        nid: 48,
        min_size: 1,
        max_size: 64,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 49: description
    StringConstraint {
        nid: 49,
        min_size: 1,
        max_size: 1024,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 51: dnQualifier — PrintableString
    StringConstraint {
        nid: 51,
        // `u32::MAX as usize` is a widening cast on every supported target
        // (`usize >= 32` bits) and mirrors the C tables' `-1` sentinel for
        // "no minimum applies" — preserved here for byte-for-byte parity
        // with the legacy constraint table in `tbl_standard.h`.
        min_size: u32::MAX as usize,
        max_size: usize::MAX,
        mask: B_ASN1_PRINTABLESTRING,
        flags: STABLE_NO_MASK,
    },
    // NID 54: friendlyName — BMPString (PKCS#9)
    StringConstraint {
        nid: 54,
        min_size: 1,
        max_size: usize::MAX,
        mask: B_ASN1_BMPSTRING,
        flags: STABLE_NO_MASK,
    },
    // NID 93: emailAddress — IA5String, 128 characters (RFC 3280)
    StringConstraint {
        nid: 93,
        min_size: 1,
        max_size: 128,
        mask: B_ASN1_IA5STRING,
        flags: STABLE_NO_MASK,
    },
    // NID 100: pseudonym
    StringConstraint {
        nid: 100,
        min_size: 1,
        max_size: 128,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 105: name
    StringConstraint {
        nid: 105,
        min_size: 1,
        max_size: 32768,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 106: dnsName — IA5String
    StringConstraint {
        nid: 106,
        min_size: 1,
        max_size: 255,
        mask: B_ASN1_IA5STRING,
        flags: STABLE_NO_MASK,
    },
    // NID 107: rfc822Name — IA5String
    StringConstraint {
        nid: 107,
        min_size: 1,
        max_size: 128,
        mask: B_ASN1_IA5STRING,
        flags: STABLE_NO_MASK,
    },
    // NID 108: uri — IA5String
    StringConstraint {
        nid: 108,
        min_size: 1,
        max_size: usize::MAX,
        mask: B_ASN1_IA5STRING,
        flags: STABLE_NO_MASK,
    },
    // NID 170: unstructuredName — PKCS#9
    StringConstraint {
        nid: 170,
        min_size: 1,
        max_size: 255,
        mask: PKCS9STRING_TYPE | B_ASN1_IA5STRING,
        flags: STABLE_NO_MASK,
    },
    // NID 180: unstructuredAddress
    StringConstraint {
        nid: 180,
        min_size: 1,
        max_size: usize::MAX,
        mask: PKCS9STRING_TYPE,
        flags: 0,
    },
    // NID 188: pkcs9-challengePassword
    StringConstraint {
        nid: 188,
        min_size: 1,
        max_size: usize::MAX,
        mask: PKCS9STRING_TYPE,
        flags: 0,
    },
    // NID 290: SNMPv2-usmUser
    StringConstraint {
        nid: 290,
        min_size: 1,
        max_size: 255,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 661: streetAddress
    StringConstraint {
        nid: 661,
        min_size: 1,
        max_size: 128,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
    // NID 1052: userID
    StringConstraint {
        nid: 1052,
        min_size: 1,
        max_size: 256,
        mask: DIRSTRING_TYPE,
        flags: 0,
    },
];

/// Look up the string-table constraint for a given NID.
///
/// Replaces C `ASN1_STRING_TABLE_get()` from `crypto/asn1/a_strnid.c:180`.
/// Returns `None` if the NID is not in the standard table.
#[must_use]
pub fn string_table_get(nid: i32) -> Option<StringConstraint> {
    STRING_TABLE_ENTRIES
        .binary_search_by_key(&nid, |e| e.nid)
        .ok()
        .map(|idx| STRING_TABLE_ENTRIES[idx])
}

// -----------------------------------------------------------------------------
// Select / validate string types
// -----------------------------------------------------------------------------

/// Select the *minimal* ASN.1 string type that can represent the data under
/// the supplied input encoding.
///
/// Replaces C `ASN1_mbstring_copy()` / `ASN1_mbstring_ncopy()` from
/// `crypto/asn1/a_mbstr.c:27`.
///
/// Priority (smallest to largest): `PrintableString` < `IA5String` < `T61String`
/// < `BmpString` < `UniversalString` < `Utf8String`. For non-ASCII inputs,
/// `Utf8String` is selected unconditionally.
pub fn select_string_type(data: &[u8], encoding: StringEncoding) -> CryptoResult<Asn1Tag> {
    // First: validate that the input is well-formed under its declared encoding.
    match encoding {
        StringEncoding::Ascii | StringEncoding::Latin1 => {
            // 8-bit encodings: every byte is acceptable as a codepoint
            // (ASCII codepoints 0-127 map to Printable / IA5; Latin-1 adds
            // 128-255 which requires T61/BMP/UTF8).
        }
        StringEncoding::Utf8 => {
            // Validate UTF-8 by running the codec.
            let mut pos = 0;
            while pos < data.len() {
                let (_, consumed) = utf8_decode_one(&data[pos..])?;
                pos += consumed;
            }
        }
        StringEncoding::Ucs2 => {
            if data.len() % 2 != 0 {
                return Err(Asn1Error::InvalidStringContent {
                    tag: Asn1Tag::BmpString,
                }
                .into());
            }
        }
        StringEncoding::Ucs4 => {
            if data.len() % 4 != 0 {
                return Err(Asn1Error::InvalidStringContent {
                    tag: Asn1Tag::UniversalString,
                }
                .into());
            }
        }
    }

    // Second: scan codepoints to determine the narrowest acceptable type.
    let mut only_printable = true;
    let mut only_ia5 = true;
    let mut only_bmp = true;

    match encoding {
        StringEncoding::Ascii | StringEncoding::Latin1 => {
            for &b in data {
                let cp = u32::from(b);
                if !codepoint_is_printable(cp) {
                    only_printable = false;
                }
                if cp >= 0x80 {
                    only_ia5 = false;
                }
                if cp >= 0x10000 {
                    only_bmp = false;
                }
            }
        }
        StringEncoding::Utf8 => {
            let mut pos = 0;
            while pos < data.len() {
                let (cp, consumed) = utf8_decode_one(&data[pos..])?;
                pos += consumed;
                if !codepoint_is_printable(cp) {
                    only_printable = false;
                }
                if cp >= 0x80 {
                    only_ia5 = false;
                }
                if cp >= 0x10000 {
                    only_bmp = false;
                }
            }
        }
        StringEncoding::Ucs2 => {
            for chunk in data.chunks_exact(2) {
                let cp = u32::from_be_bytes([0, 0, chunk[0], chunk[1]]);
                if !codepoint_is_printable(cp) {
                    only_printable = false;
                }
                if cp >= 0x80 {
                    only_ia5 = false;
                }
                if cp >= 0x10000 {
                    only_bmp = false;
                }
            }
        }
        StringEncoding::Ucs4 => {
            for chunk in data.chunks_exact(4) {
                let cp = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if cp > 0x10_FFFF {
                    return Err(Asn1Error::InvalidStringContent {
                        tag: Asn1Tag::UniversalString,
                    }
                    .into());
                }
                if !codepoint_is_printable(cp) {
                    only_printable = false;
                }
                if cp >= 0x80 {
                    only_ia5 = false;
                }
                if cp >= 0x10000 {
                    only_bmp = false;
                }
            }
        }
    }

    if only_printable {
        Ok(Asn1Tag::PrintableString)
    } else if only_ia5 {
        Ok(Asn1Tag::Ia5String)
    } else if only_bmp {
        Ok(Asn1Tag::BmpString)
    } else {
        Ok(Asn1Tag::Utf8String)
    }
}

/// Check whether a Unicode codepoint is valid in `PrintableString`.
fn codepoint_is_printable(cp: u32) -> bool {
    if cp >= 0x80 {
        return false;
    }
    // cp < 0x80, so truncation to u8 is lossless.
    let byte = (cp & 0xFF) as u8;
    (CHAR_TYPE_TABLE[byte as usize] & CHARTYPE_PRINTABLESTRING) != 0
}

/// Decode one UTF-8 codepoint.
///
/// Returns the codepoint value plus the number of bytes consumed.
fn utf8_decode_one(data: &[u8]) -> CryptoResult<(u32, usize)> {
    if data.is_empty() {
        return Err(Asn1Error::TruncatedData {
            expected: 1,
            actual: 0,
        }
        .into());
    }
    let b0 = data[0];
    if b0 < 0x80 {
        return Ok((u32::from(b0), 1));
    }
    let (expected_len, start): (usize, u32) = if b0 < 0xC2 {
        return Err(Asn1Error::InvalidStringContent {
            tag: Asn1Tag::Utf8String,
        }
        .into());
    } else if b0 < 0xE0 {
        (2, u32::from(b0 & 0x1F))
    } else if b0 < 0xF0 {
        (3, u32::from(b0 & 0x0F))
    } else if b0 < 0xF5 {
        (4, u32::from(b0 & 0x07))
    } else {
        return Err(Asn1Error::InvalidStringContent {
            tag: Asn1Tag::Utf8String,
        }
        .into());
    };

    if data.len() < expected_len {
        return Err(Asn1Error::TruncatedData {
            expected: expected_len,
            actual: data.len(),
        }
        .into());
    }
    let mut cp = start;
    for &b in &data[1..expected_len] {
        if (b & 0xC0) != 0x80 {
            return Err(Asn1Error::InvalidStringContent {
                tag: Asn1Tag::Utf8String,
            }
            .into());
        }
        cp = (cp << 6) | u32::from(b & 0x3F);
    }
    // Reject overlong encodings and surrogate codepoints.
    let min_for_length = match expected_len {
        2 => 0x0080,
        3 => 0x0800,
        4 => 0x1_0000,
        _ => 0,
    };
    if cp < min_for_length || cp > 0x10_FFFF || (0xD800..=0xDFFF).contains(&cp) {
        return Err(Asn1Error::InvalidStringContent {
            tag: Asn1Tag::Utf8String,
        }
        .into());
    }
    Ok((cp, expected_len))
}

/// Encode a Unicode codepoint as UTF-8.
///
/// Returns the number of bytes written.
fn utf8_encode_one(cp: u32, out: &mut Vec<u8>) -> CryptoResult<usize> {
    if cp > 0x10_FFFF || (0xD800..=0xDFFF).contains(&cp) {
        return Err(Asn1Error::InvalidStringContent {
            tag: Asn1Tag::Utf8String,
        }
        .into());
    }
    // UTF-8 encoding intentionally extracts specific bit ranges of the codepoint.
    // All casts below are bounded (masked or shifted such that the result fits in u8).
    if cp < 0x80 {
        // cp < 0x80, so cp fits in u8 losslessly.
        out.push((cp & 0x7F) as u8);
        Ok(1)
    } else if cp < 0x800 {
        // (cp >> 6) < 0x20, so fits in u8.
        out.push(0xC0 | ((cp >> 6) & 0x1F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
        Ok(2)
    } else if cp < 0x1_0000 {
        // (cp >> 12) < 0x10, so fits in u8.
        out.push(0xE0 | ((cp >> 12) & 0x0F) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
        Ok(3)
    } else {
        // cp <= 0x10_FFFF (verified above), so (cp >> 18) <= 4.
        out.push(0xF0 | ((cp >> 18) & 0x07) as u8);
        out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
        Ok(4)
    }
}

/// Transcode a string from one ASN.1 string encoding to another.
///
/// Supports all combinations of [`StringEncoding`]. Replaces the implicit
/// conversions performed by `ASN1_mbstring_copy()` in `crypto/asn1/a_mbstr.c`.
pub fn transcode_string(
    data: &[u8],
    from: StringEncoding,
    to: StringEncoding,
) -> CryptoResult<Vec<u8>> {
    // Step 1: decode `data` into a Vec<u32> of codepoints.
    let codepoints: Vec<u32> = match from {
        StringEncoding::Ascii => {
            for &b in data {
                if b >= 0x80 {
                    return Err(Asn1Error::InvalidStringContent {
                        tag: Asn1Tag::PrintableString,
                    }
                    .into());
                }
            }
            data.iter().map(|&b| u32::from(b)).collect()
        }
        StringEncoding::Latin1 => data.iter().map(|&b| u32::from(b)).collect(),
        StringEncoding::Utf8 => {
            let mut cps = Vec::with_capacity(data.len());
            let mut pos = 0;
            while pos < data.len() {
                let (cp, consumed) = utf8_decode_one(&data[pos..])?;
                cps.push(cp);
                pos += consumed;
            }
            cps
        }
        StringEncoding::Ucs2 => {
            if data.len() % 2 != 0 {
                return Err(Asn1Error::InvalidStringContent {
                    tag: Asn1Tag::BmpString,
                }
                .into());
            }
            data.chunks_exact(2)
                .map(|c| u32::from_be_bytes([0, 0, c[0], c[1]]))
                .collect()
        }
        StringEncoding::Ucs4 => {
            if data.len() % 4 != 0 {
                return Err(Asn1Error::InvalidStringContent {
                    tag: Asn1Tag::UniversalString,
                }
                .into());
            }
            data.chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        }
    };

    // Step 2: encode into the target encoding.
    match to {
        StringEncoding::Ascii => {
            let mut out = Vec::with_capacity(codepoints.len());
            for cp in codepoints {
                if cp >= 0x80 {
                    return Err(Asn1Error::InvalidStringContent {
                        tag: Asn1Tag::PrintableString,
                    }
                    .into());
                }
                // cp < 0x80, so fits in u8 losslessly.
                out.push((cp & 0x7F) as u8);
            }
            Ok(out)
        }
        StringEncoding::Latin1 => {
            let mut out = Vec::with_capacity(codepoints.len());
            for cp in codepoints {
                if cp >= 0x100 {
                    return Err(Asn1Error::InvalidStringContent {
                        tag: Asn1Tag::T61String,
                    }
                    .into());
                }
                // cp < 0x100, so fits in u8 losslessly.
                out.push((cp & 0xFF) as u8);
            }
            Ok(out)
        }
        StringEncoding::Utf8 => {
            let mut out = Vec::with_capacity(codepoints.len() * 2);
            for cp in codepoints {
                utf8_encode_one(cp, &mut out)?;
            }
            Ok(out)
        }
        StringEncoding::Ucs2 => {
            let mut out = Vec::with_capacity(codepoints.len() * 2);
            for cp in codepoints {
                if cp > 0xFFFF {
                    return Err(Asn1Error::InvalidStringContent {
                        tag: Asn1Tag::BmpString,
                    }
                    .into());
                }
                // cp <= 0xFFFF, so each byte-shift result fits in u8.
                out.push(((cp >> 8) & 0xFF) as u8);
                out.push((cp & 0xFF) as u8);
            }
            Ok(out)
        }
        StringEncoding::Ucs4 => {
            let mut out = Vec::with_capacity(codepoints.len() * 4);
            for cp in codepoints {
                if cp > 0x10_FFFF {
                    return Err(Asn1Error::InvalidStringContent {
                        tag: Asn1Tag::UniversalString,
                    }
                    .into());
                }
                out.push((cp >> 24) as u8);
                out.push(((cp >> 16) & 0xFF) as u8);
                out.push(((cp >> 8) & 0xFF) as u8);
                out.push((cp & 0xFF) as u8);
            }
            Ok(out)
        }
    }
}

/// Check whether a byte sequence is valid for a given ASN.1 string tag.
///
/// Replaces C `ASN1_STRING_print()`'s per-tag validation pathway plus the
/// auxiliary `ASN1_PRINTABLE_type()` predicate from `crypto/asn1/a_print.c`.
#[must_use]
pub fn validate_string_content(data: &[u8], tag: Asn1Tag) -> bool {
    match tag {
        Asn1Tag::PrintableString => data
            .iter()
            .all(|&b| b < 0x80 && (CHAR_TYPE_TABLE[b as usize] & CHARTYPE_PRINTABLESTRING) != 0),
        Asn1Tag::Ia5String | Asn1Tag::NumericString | Asn1Tag::VisibleString => {
            data.iter().all(|&b| b < 0x80)
        }
        Asn1Tag::Utf8String => {
            let mut pos = 0;
            while pos < data.len() {
                match utf8_decode_one(&data[pos..]) {
                    Ok((_, consumed)) => pos += consumed,
                    Err(_) => return false,
                }
            }
            true
        }
        Asn1Tag::BmpString => {
            if data.len() % 2 != 0 {
                return false;
            }
            for chunk in data.chunks_exact(2) {
                let cp = u32::from_be_bytes([0, 0, chunk[0], chunk[1]]);
                if (0xD800..=0xDFFF).contains(&cp) {
                    return false;
                }
            }
            true
        }
        Asn1Tag::UniversalString => {
            if data.len() % 4 != 0 {
                return false;
            }
            for chunk in data.chunks_exact(4) {
                let cp = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if cp > 0x10_FFFF || (0xD800..=0xDFFF).contains(&cp) {
                    return false;
                }
            }
            true
        }
        Asn1Tag::UtcTime | Asn1Tag::GeneralizedTime => {
            // Times are ASCII with a very restricted alphabet; we leave strict
            // validation to `Asn1Time::parse`.
            data.iter()
                .all(|&b| b.is_ascii_digit() || b == b'Z' || b == b'+' || b == b'-' || b == b'.')
        }
        // T61String/GeneralString/GraphicString permit full 8-bit content and are
        // treated as always-valid; non-string types (OctetString, BitString,
        // Null, Integer, Enumerated, Boolean, ObjectIdentifier) treat content as
        // opaque; unknown/unsupported tags also pass through.
        _ => true,
    }
}

/// Format an [`Asn1String`] with RFC 2253 escaping for X.509 name display.
///
/// Replaces C `ASN1_STRING_print_ex()` / `do_esc_char()` from
/// `crypto/asn1/a_strex.c:80`.
///
/// The output is a UTF-8 Rust `String` with `\\`-escaping applied to
/// reserved characters, hex escapes for control bytes, and the tag-specific
/// decoding applied (PrintableString/IA5/UTF8/BMP/Universal).
#[must_use]
pub fn format_string_rfc2253(string: &Asn1String) -> String {
    let data = string.data();

    // Convert tag-specific encoding into codepoints.
    let codepoints: Vec<u32> = match string.tag() {
        Asn1Tag::BmpString => {
            if data.len() % 2 != 0 {
                return format!("#{}", hex_encode(data));
            }
            data.chunks_exact(2)
                .map(|c| u32::from_be_bytes([0, 0, c[0], c[1]]))
                .collect()
        }
        Asn1Tag::UniversalString => {
            if data.len() % 4 != 0 {
                return format!("#{}", hex_encode(data));
            }
            data.chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        }
        Asn1Tag::Utf8String => {
            let mut cps = Vec::with_capacity(data.len());
            let mut pos = 0;
            while pos < data.len() {
                match utf8_decode_one(&data[pos..]) {
                    Ok((cp, consumed)) => {
                        cps.push(cp);
                        pos += consumed;
                    }
                    Err(_) => return format!("#{}", hex_encode(data)),
                }
            }
            cps
        }
        _ => data.iter().map(|&b| u32::from(b)).collect(),
    };

    // Apply RFC 2253 escaping and codepoint transcoding.
    let mut out = String::with_capacity(codepoints.len());
    let n = codepoints.len();
    for (i, &cp) in codepoints.iter().enumerate() {
        let first = i == 0;
        let last = i + 1 == n;
        if cp < 0x80 {
            let cls = CHAR_TYPE_TABLE[cp as usize];
            let esc_any = (cls & CHARTYPE_RFC2253_ESC_ANY) != 0;
            let esc_first = first && (cls & CHARTYPE_RFC2253_ESC_FIRST) != 0;
            let esc_last = last && (cls & CHARTYPE_RFC2253_ESC_LAST) != 0;
            let hex_escape = (cls & (CHARTYPE_FIRST_ESC_2253 | CHARTYPE_LAST_ESC_2253)) != 0
                && (cp < 0x20 || cp == 0x7F);
            if hex_escape {
                out.push_str(&format!("\\{cp:02X}"));
            } else if esc_any || esc_first || esc_last {
                out.push('\\');
                // cp < 0x80, so fits in u8 losslessly.
                out.push(((cp & 0x7F) as u8) as char);
            } else {
                // cp < 0x80, so fits in u8 losslessly.
                out.push(((cp & 0x7F) as u8) as char);
            }
        } else if let Some(ch) = char::from_u32(cp) {
            out.push(ch);
        } else {
            // Lone surrogate or out-of-range: encode as `\UXXXXXXXX`.
            out.push_str(&format!("\\U{cp:08X}"));
        }
    }
    out
}

/// Hex-encode bytes as an uppercase ASCII string (used for `#...` RFC 2253
/// dump fallback).
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

// =============================================================================
// Signing and verification helpers
// =============================================================================
//
// Source files:
//   crypto/asn1/a_sign.c     (signs an ASN.1 item)
//   crypto/asn1/a_verify.c   (verifies a signature on an ASN.1 item)
//
// The actual cryptographic operations live in the `evp` module. These helpers
// provide the algorithm-identifier wrapping and dispatch plumbing.

/// Minimal subset of EVP signing/verification operations required by the
/// `sign_item` / `verify_item` helpers. Concrete implementations live in
/// [`crate::evp`]; tests may supply in-process stubs that implement the trait
/// directly.
pub trait SignDigest {
    /// Return the DER-encoded `AlgorithmIdentifier` for this signer.
    fn algorithm_identifier(&self) -> CryptoResult<AlgorithmIdentifier>;
    /// Sign the provided digest/data buffer, returning the raw signature bytes.
    fn sign(&self, data: &[u8]) -> CryptoResult<Vec<u8>>;
    /// Verify the provided signature against the data, returning `true` on
    /// match.
    fn verify(&self, data: &[u8], signature: &[u8]) -> CryptoResult<bool>;
}

/// Sign the DER encoding of an ASN.1 item and return the result as an
/// [`Asn1BitString`] together with the populated [`AlgorithmIdentifier`].
///
/// Replaces C `ASN1_item_sign()` / `ASN1_item_sign_ex()` from
/// `crypto/asn1/a_sign.c:46`.
///
/// # Parameters
/// * `data` — DER encoding of the item to be signed (`tbsCertificate`-like).
/// * `algorithm` — mutable slot that is populated with the signer's
///   `AlgorithmIdentifier` on success.
/// * `signer` — any type implementing [`SignDigest`] (typically an `EvpKey`).
pub fn sign_item(
    data: &[u8],
    algorithm: &mut AlgorithmIdentifier,
    signer: &dyn SignDigest,
) -> CryptoResult<Asn1BitString> {
    // Populate the AlgorithmIdentifier from the signer.
    *algorithm = signer.algorithm_identifier()?;
    // Delegate signing to the EVP trait object.
    let sig_bytes = signer.sign(data)?;
    // Signatures are carried as BIT STRINGs with zero unused bits in X.509.
    let mut bitstring = Asn1BitString::new();
    bitstring.set_data(&sig_bytes, 0)?;
    Ok(bitstring)
}

/// Verify a signature on the DER encoding of an ASN.1 item.
///
/// Replaces C `ASN1_item_verify()` / `ASN1_item_verify_ex()` from
/// `crypto/asn1/a_verify.c:52`.
///
/// Returns `Ok(true)` on verification success, `Ok(false)` on a well-formed
/// but mismatched signature, and `Err(_)` for malformed inputs or I/O errors.
pub fn verify_item(
    data: &[u8],
    algorithm: &AlgorithmIdentifier,
    signature: &Asn1BitString,
    verifier: &dyn SignDigest,
) -> CryptoResult<bool> {
    // Cross-check the supplied algorithm against the verifier's expectation.
    let verifier_alg = verifier.algorithm_identifier()?;
    if verifier_alg.algorithm != algorithm.algorithm {
        return Err(Asn1Error::DecodingError(format!(
            "signature algorithm mismatch: expected {:?}, got {:?}",
            verifier_alg.algorithm.short_name(),
            algorithm.algorithm.short_name()
        ))
        .into());
    }
    // BIT STRING must have zero unused bits to be a valid signature carrier.
    if signature.unused_bits() != 0 {
        return Err(Asn1Error::DecodingError(
            "signature BIT STRING has non-zero unused bits".to_string(),
        )
        .into());
    }
    verifier.verify(data, signature.data())
}

// =============================================================================
// DER I/O helpers
// =============================================================================
//
// Source files:
//   crypto/asn1/a_d2i_fp.c  (stream decoder from BIO/file)
//   crypto/asn1/a_i2d_fp.c  (stream encoder to BIO/file)
//   crypto/asn1/bio_asn1.c  (TLV filter BIO)
//   crypto/asn1/bio_ndef.c  (indefinite-length streaming)

/// Default upper bound on a single DER object read from a stream (10 MiB).
const DEFAULT_MAX_DER_OBJECT: usize = 10 * 1024 * 1024;

/// Read one complete DER-encoded ASN.1 item from `reader`.
///
/// Replaces C `ASN1_d2i_fp()` / `ASN1_item_d2i_bio()` from
/// `crypto/asn1/a_d2i_fp.c:44`.
///
/// The function first peeks the TLV header to determine the required total
/// length, then reads exactly that many bytes. If the top-level encoding is
/// indefinite-length, it streams until the terminating `00 00` EOC pair is
/// encountered.
///
/// `max_size` bounds the total accepted length; `0` means "use the default
/// cap of 10 MiB".
pub fn read_der_from_reader<R: Read>(reader: &mut R, max_size: usize) -> CryptoResult<Vec<u8>> {
    let cap = if max_size == 0 {
        DEFAULT_MAX_DER_OBJECT
    } else {
        max_size
    };

    // Stage 1: read enough bytes to parse the identifier/length header. The
    // identifier can be up to 6 bytes (1 + 5 base-128 continuation) and the
    // length up to 9 bytes (1 + 8 big-endian size octets).
    let mut buf = Vec::with_capacity(32);
    // Read one byte at a time until we have a parseable header. This is
    // simple and safe and handles both short and long forms without
    // over-reading.
    loop {
        let mut one = [0u8; 1];
        let n = reader
            .read(&mut one)
            .map_err(|e| CryptoError::Encoding(format!("read_der_from_reader: {e}")))?;
        if n == 0 {
            return Err(Asn1Error::TruncatedData {
                expected: 1,
                actual: 0,
            }
            .into());
        }
        buf.push(one[0]);
        match parse_tlv_header(&buf) {
            Ok(header) => {
                match header.content_length {
                    Some(content_len) => {
                        let total = header
                            .header_length
                            .checked_add(content_len)
                            .ok_or(Asn1Error::IntegerOverflow)?;
                        if total > cap {
                            return Err(Asn1Error::DecodingError(format!(
                                "DER object length {total} exceeds cap {cap}"
                            ))
                            .into());
                        }
                        if buf.len() < total {
                            let remaining = total - buf.len();
                            let old_len = buf.len();
                            buf.resize(total, 0);
                            reader
                                .read_exact(&mut buf[old_len..old_len + remaining])
                                .map_err(|e| {
                                    CryptoError::Encoding(format!("read_der_from_reader body: {e}"))
                                })?;
                        }
                        return Ok(buf);
                    }
                    None => {
                        // Indefinite length: scan content byte-by-byte until
                        // terminating EOC (`00 00`) at the outermost level.
                        return read_indefinite_length_body(reader, buf, cap);
                    }
                }
            }
            Err(e) => {
                // Not enough bytes yet — the parser emits TruncatedData until
                // the header is complete.
                let more_needed = matches!(
                    e,
                    CryptoError::Encoding(ref s) if s.contains("truncated data")
                );
                if !more_needed {
                    return Err(e);
                }
                // Bound runaway loops from a stream that never produces a
                // valid header.
                if buf.len() > 32 {
                    return Err(Asn1Error::InvalidLength.into());
                }
            }
        }
    }
}

/// Continue reading an indefinite-length DER object body, returning once the
/// outermost EOC terminator has been consumed.
///
/// This function maintains a nesting `depth` that starts at `1` (accounting
/// for the caller's own indefinite-length construction) and increments on
/// every nested constructed indefinite-length TLV it encounters. When it
/// sees an EOC (`00 00`) terminator it decrements the depth; once depth
/// reaches zero the full outer object (including its EOC) is returned.
///
/// An important subtlety: TLV headers can be multiple bytes long (for
/// example INTEGER `02 01 05` is a 2-byte header), so parsing must
/// incrementally read from the stream until the header is complete. The
/// inner loop below drives that read-until-parseable behaviour, mirroring
/// the outer `read_der_from_reader` logic.
fn read_indefinite_length_body<R: Read>(
    reader: &mut R,
    mut buf: Vec<u8>,
    cap: usize,
) -> CryptoResult<Vec<u8>> {
    let mut depth: usize = 1;
    let mut pos = buf.len();
    loop {
        // Drive reads until we can parse a complete header starting at `pos`.
        let header = loop {
            match parse_tlv_header(&buf[pos..]) {
                Ok(h) => break h,
                Err(e) => {
                    // Only extend the buffer for true truncation errors.
                    // Any other parse error (e.g. invalid length form) is
                    // surfaced immediately.
                    let more_needed = matches!(
                        &e,
                        CryptoError::Encoding(s) if s.contains("truncated data")
                    );
                    if !more_needed {
                        return Err(e);
                    }
                    let mut one = [0u8; 1];
                    let n = reader.read(&mut one).map_err(|io_err| {
                        CryptoError::Encoding(format!("read_der_from_reader: {io_err}"))
                    })?;
                    if n == 0 {
                        return Err(Asn1Error::TruncatedData {
                            expected: 1,
                            actual: 0,
                        }
                        .into());
                    }
                    buf.push(one[0]);
                    if buf.len() > cap {
                        return Err(Asn1Error::DecodingError(format!(
                            "indefinite-length object exceeds cap {cap}"
                        ))
                        .into());
                    }
                }
            }
        };
        pos = pos
            .checked_add(header.header_length)
            .ok_or(Asn1Error::IntegerOverflow)?;
        if header.tag == Asn1Tag::Eoc && header.class == Asn1Class::Universal && !header.constructed
        {
            // EOC terminator: decrement nesting and check for completion.
            depth = depth.checked_sub(1).ok_or(Asn1Error::InvalidLength)?;
            if depth == 0 {
                return Ok(buf);
            }
            continue;
        }
        match header.content_length {
            Some(clen) => {
                // Definite length: skip `clen` bytes.
                let end = pos.checked_add(clen).ok_or(Asn1Error::IntegerOverflow)?;
                while buf.len() < end {
                    let mut one = [0u8; 1];
                    let n = reader.read(&mut one).map_err(|io_err| {
                        CryptoError::Encoding(format!("read_der_from_reader: {io_err}"))
                    })?;
                    if n == 0 {
                        return Err(Asn1Error::TruncatedData {
                            expected: end - buf.len(),
                            actual: 0,
                        }
                        .into());
                    }
                    buf.push(one[0]);
                    if buf.len() > cap {
                        return Err(Asn1Error::DecodingError(format!(
                            "indefinite-length object exceeds cap {cap}"
                        ))
                        .into());
                    }
                }
                pos = end;
            }
            None => {
                depth = depth.checked_add(1).ok_or(Asn1Error::IntegerOverflow)?;
            }
        }
    }
}

/// Write all bytes from `data` to `writer`.
///
/// Replaces C `ASN1_i2d_fp()` / `ASN1_item_i2d_bio()` from
/// `crypto/asn1/a_i2d_fp.c`.
pub fn write_der_to_writer<W: Write>(data: &[u8], writer: &mut W) -> CryptoResult<()> {
    writer
        .write_all(data)
        .map_err(|e| CryptoError::Encoding(format!("write_der_to_writer: {e}")))?;
    writer
        .flush()
        .map_err(|e| CryptoError::Encoding(format!("write_der_to_writer flush: {e}")))?;
    Ok(())
}

// =============================================================================
// S/MIME support (from asn_mime.c, 1075 lines)
// =============================================================================

/// Maximum MIME header line length allowed before giving up (RFC 5322 caps
/// lines at 998 octets; we add a margin).
const SMIME_MAX_LINE: usize = 16 * 1024;

/// Parse an S/MIME message from `reader`, extracting MIME headers and the raw
/// body. Replaces C `SMIME_read_ASN1()` from `crypto/asn1/asn_mime.c:310`.
///
/// This is a minimal RFC 2046 parser: it reads headers up to the first blank
/// line, collects the body as bytes, and populates `content_type` from the
/// `Content-Type` header if present.
pub fn smime_read<R: BufRead>(mut reader: R) -> CryptoResult<SmimeData> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_type = String::new();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| CryptoError::Encoding(format!("smime_read header: {e}")))?;
        if n == 0 {
            // EOF before end of headers
            return Err(Asn1Error::TruncatedData {
                expected: 1,
                actual: 0,
            }
            .into());
        }
        if n > SMIME_MAX_LINE {
            return Err(Asn1Error::DecodingError(format!(
                "MIME header line exceeds {SMIME_MAX_LINE} bytes"
            ))
            .into());
        }
        // Strip trailing CR and LF characters (normalise CRLF/LF/CR endings).
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        if line.is_empty() {
            break; // End of headers
        }
        // Handle header folding: continuation lines start with SP or TAB and
        // are appended to the previous header value.
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some(idx) = line.find(':') {
            let (name, value) = line.split_at(idx);
            let name = name.trim().to_string();
            let value = value[1..].trim().to_string();
            if name.eq_ignore_ascii_case("content-type") {
                content_type.clone_from(&value);
            }
            headers.push((name, value));
        } else {
            return Err(Asn1Error::DecodingError(format!("malformed MIME header: {line}")).into());
        }
    }

    // Read the body as raw bytes.
    let mut content = Vec::new();
    let _ = reader
        .read_to_end(&mut content)
        .map_err(|e| CryptoError::Encoding(format!("smime_read body: {e}")))?;

    Ok(SmimeData {
        content,
        content_type,
        headers,
    })
}

/// Write an S/MIME message (MIME headers + raw body) to `writer`.
///
/// Replaces C `SMIME_write_ASN1()` from `crypto/asn1/asn_mime.c:152`.
///
/// Line endings are canonicalised to CRLF per RFC 2046.
pub fn smime_write<W: Write>(data: &SmimeData, writer: &mut W) -> CryptoResult<()> {
    // MIME headers (in the order supplied by the caller).
    for (name, value) in &data.headers {
        writer
            .write_all(name.as_bytes())
            .map_err(|e| CryptoError::Encoding(format!("smime_write header: {e}")))?;
        writer
            .write_all(b": ")
            .map_err(|e| CryptoError::Encoding(format!("smime_write: {e}")))?;
        writer
            .write_all(value.as_bytes())
            .map_err(|e| CryptoError::Encoding(format!("smime_write: {e}")))?;
        writer
            .write_all(b"\r\n")
            .map_err(|e| CryptoError::Encoding(format!("smime_write: {e}")))?;
    }
    // Emit Content-Type if not already supplied by `headers`.
    let has_ct = data
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-type"));
    if !has_ct && !data.content_type.is_empty() {
        writer
            .write_all(b"Content-Type: ")
            .map_err(|e| CryptoError::Encoding(format!("smime_write: {e}")))?;
        writer
            .write_all(data.content_type.as_bytes())
            .map_err(|e| CryptoError::Encoding(format!("smime_write: {e}")))?;
        writer
            .write_all(b"\r\n")
            .map_err(|e| CryptoError::Encoding(format!("smime_write: {e}")))?;
    }
    // Blank line between headers and body.
    writer
        .write_all(b"\r\n")
        .map_err(|e| CryptoError::Encoding(format!("smime_write: {e}")))?;
    // Body — canonicalise bare LFs to CRLF.
    let mut prev_was_cr = false;
    for &b in &data.content {
        if b == b'\n' && !prev_was_cr {
            writer
                .write_all(b"\r\n")
                .map_err(|e| CryptoError::Encoding(format!("smime_write body: {e}")))?;
        } else {
            writer
                .write_all(&[b])
                .map_err(|e| CryptoError::Encoding(format!("smime_write body: {e}")))?;
        }
        prev_was_cr = b == b'\r';
    }
    writer
        .flush()
        .map_err(|e| CryptoError::Encoding(format!("smime_write flush: {e}")))?;
    Ok(())
}

// =============================================================================
// Parse / dump diagnostic (from asn1_parse.c, 381 lines)
// =============================================================================

/// Maximum nesting depth honoured by `parse_dump` before emitting a
/// truncation marker. Matches the C default (`ASN1_PARSE_MAXDEPTH`).
const PARSE_DUMP_MAX_DEPTH: usize = 128;

/// Textually dump the TLV structure of a DER-encoded buffer for debugging.
///
/// Replaces C `ASN1_parse_dump()` / `asn1_parse2()` from
/// `crypto/asn1/asn1_parse.c:75`.
///
/// The output mimics the format produced by `openssl asn1parse`, showing
/// offsets, lengths, and tag names.
pub fn parse_dump(data: &[u8], indent: usize) -> CryptoResult<String> {
    let mut out = String::new();
    dump_recursive(data, 0, indent, 0, &mut out)?;
    Ok(out)
}

/// Recursive worker for [`parse_dump`].
fn dump_recursive(
    data: &[u8],
    offset: usize,
    indent_per_level: usize,
    depth: usize,
    out: &mut String,
) -> CryptoResult<()> {
    if depth >= PARSE_DUMP_MAX_DEPTH {
        out.push_str(&format!(
            "{:indent$}<max depth exceeded>\n",
            "",
            indent = depth * indent_per_level
        ));
        return Ok(());
    }
    let mut pos: usize = 0;
    while pos < data.len() {
        let slice = &data[pos..];
        let header = parse_tlv_header(slice)?;
        let body_start = header.header_length;
        let content_len = header
            .content_length
            .unwrap_or_else(|| slice.len().saturating_sub(body_start));
        let total = body_start
            .checked_add(content_len)
            .ok_or(Asn1Error::IntegerOverflow)?;
        if total > slice.len() {
            return Err(Asn1Error::TruncatedData {
                expected: total,
                actual: slice.len(),
            }
            .into());
        }

        let abs_offset = offset.checked_add(pos).ok_or(Asn1Error::IntegerOverflow)?;
        let indent_prefix = " ".repeat(depth * indent_per_level);
        let tag_label = format_tag_label(&header);
        let length_label = header
            .content_length
            .map_or_else(|| "l=inf  ".to_string(), |l| format!("l={l:5}"));
        let kind_label = if header.constructed { "cons" } else { "prim" };
        let hl = header.header_length;
        out.push_str(&format!(
            "{indent_prefix}{abs_offset:5}:d={depth:<2} hl={hl:2} {length_label} {kind_label}: {tag_label}\n"
        ));

        if header.constructed {
            let inner = &slice[body_start..body_start + content_len];
            dump_recursive(
                inner,
                abs_offset + body_start,
                indent_per_level,
                depth + 1,
                out,
            )?;
        } else {
            // Primitive leaf: emit a one-line hex preview (up to 32 bytes).
            let inner = &slice[body_start..body_start + content_len];
            if !inner.is_empty() {
                let preview_len = inner.len().min(32);
                let hex_preview = hex_encode(&inner[..preview_len]);
                let cont = if inner.len() > preview_len { "…" } else { "" };
                out.push_str(&format!("{indent_prefix}  bytes: {hex_preview}{cont}\n"));
            }
        }

        pos = pos.checked_add(total).ok_or(Asn1Error::IntegerOverflow)?;
    }
    Ok(())
}

/// Format a human-readable tag label for `parse_dump`.
fn format_tag_label(header: &TlvHeader) -> String {
    let class_str = match header.class {
        Asn1Class::Universal => "",
        Asn1Class::Application => "APPL ",
        Asn1Class::ContextSpecific => "CTX  ",
        Asn1Class::Private => "PRIV ",
    };
    let tag_str = match header.tag {
        Asn1Tag::Eoc => "EOC",
        Asn1Tag::Boolean => "BOOLEAN",
        Asn1Tag::Integer => "INTEGER",
        Asn1Tag::BitString => "BIT STRING",
        Asn1Tag::OctetString => "OCTET STRING",
        Asn1Tag::Null => "NULL",
        Asn1Tag::ObjectIdentifier => "OBJECT",
        Asn1Tag::ObjectDescriptor => "OBJECT DESCRIPTOR",
        Asn1Tag::External => "EXTERNAL",
        Asn1Tag::Real => "REAL",
        Asn1Tag::Enumerated => "ENUMERATED",
        Asn1Tag::Utf8String => "UTF8STRING",
        Asn1Tag::Sequence => "SEQUENCE",
        Asn1Tag::Set => "SET",
        Asn1Tag::NumericString => "NumericString",
        Asn1Tag::PrintableString => "PrintableString",
        Asn1Tag::T61String => "T61STRING",
        Asn1Tag::VideotexString => "VideotexString",
        Asn1Tag::Ia5String => "IA5STRING",
        Asn1Tag::UtcTime => "UTCTIME",
        Asn1Tag::GeneralizedTime => "GENERALIZEDTIME",
        Asn1Tag::GraphicString => "GraphicString",
        Asn1Tag::VisibleString => "VisibleString",
        Asn1Tag::GeneralString => "GeneralString",
        Asn1Tag::UniversalString => "UniversalString",
        Asn1Tag::BmpString => "BMPSTRING",
    };
    format!("{class_str}{tag_str}")
}

// =============================================================================
// Generator language (from asn1_gen.c, 791 lines)
// =============================================================================

/// Generate a DER-encoded ASN.1 value from a human-readable description.
///
/// Replaces C `ASN1_generate_nconf()` / `ASN1_generate_v3()` from
/// `crypto/asn1/asn1_gen.c:71`.
///
/// Supported forms (OpenSSL mini-language):
/// * `BOOLEAN:TRUE` / `BOOL:FALSE`
/// * `INTEGER:<value>` (decimal or `0x...` hex)
/// * `NULL`
/// * `OCTETSTRING:<hex>` or `OCT:<hex>`
/// * `UTF8:<text>` / `UTF8String:<text>`
/// * `IA5:<text>` / `IA5String:<text>`
/// * `PRINTABLESTRING:<text>`
/// * `BITSTRING:<hex>` / `BITSTR:<hex>`
/// * `OID:<numeric-oid>` (e.g. `OID:1.2.840.113549.1.1.11`)
/// * `FORMAT:<ASCII|HEX>,<content>`
/// * `SEQUENCE:<name>` / `SET:<name>` are intentionally left unimplemented
///   (they require the configuration-file named-section lookup that is
///   not available in this no-std-friendly context).
pub fn generate_from_config(value: &str) -> CryptoResult<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Asn1Error::EncodingError("empty generator input".to_string()).into());
    }

    let (type_part, payload) = match trimmed.find(':') {
        Some(idx) => (&trimmed[..idx], Some(&trimmed[idx + 1..])),
        None => (trimmed, None),
    };
    let type_upper = type_part.to_ascii_uppercase();

    // Normalise "FORMAT:ASCII,text" / "FORMAT:HEX,cafebabe" prefixes.
    let (format_is_hex, payload) = if type_upper == "FORMAT" {
        let p =
            payload.ok_or_else(|| Asn1Error::EncodingError("FORMAT missing value".to_string()))?;
        let (fmt, rest) = p
            .split_once(',')
            .ok_or_else(|| Asn1Error::EncodingError("FORMAT needs comma".to_string()))?;
        let fmt = fmt.trim().to_ascii_uppercase();
        let is_hex = match fmt.as_str() {
            "HEX" => true,
            "ASCII" | "UTF8" => false,
            _ => {
                return Err(Asn1Error::EncodingError(format!("unknown FORMAT {fmt}")).into());
            }
        };
        // Re-parse the remainder.
        let (t, pl) = match rest.find(':') {
            Some(i) => (rest[..i].to_ascii_uppercase(), Some(&rest[i + 1..])),
            None => (rest.to_ascii_uppercase(), None),
        };
        return generate_typed(&t, pl, is_hex);
    } else {
        (false, payload)
    };
    generate_typed(&type_upper, payload, format_is_hex)
}

/// Inner helper for [`generate_from_config`] dispatching on the type tag.
fn generate_typed(
    type_upper: &str,
    payload: Option<&str>,
    format_is_hex: bool,
) -> CryptoResult<Vec<u8>> {
    match type_upper {
        "NULL" => {
            let mut out = write_tlv_header(Asn1Tag::Null, Asn1Class::Universal, false, 0)?;
            let _ = format_is_hex;
            let _ = payload;
            Ok(out_with_header(&mut out, &[]))
        }
        "BOOL" | "BOOLEAN" => {
            let v = payload
                .ok_or_else(|| Asn1Error::EncodingError("BOOLEAN requires value".to_string()))?;
            let bit = match v.trim().to_ascii_uppercase().as_str() {
                "TRUE" | "YES" | "Y" | "1" => 0xFFu8,
                "FALSE" | "NO" | "N" | "0" => 0x00u8,
                other => {
                    return Err(Asn1Error::EncodingError(format!(
                        "invalid BOOLEAN value: {other}"
                    ))
                    .into());
                }
            };
            let mut out = write_tlv_header(Asn1Tag::Boolean, Asn1Class::Universal, false, 1)?;
            out.push(bit);
            Ok(out)
        }
        "INT" | "INTEGER" => {
            let v = payload
                .ok_or_else(|| Asn1Error::EncodingError("INTEGER requires value".to_string()))?;
            let int = parse_integer_literal(v.trim())?;
            int.encode_der()
        }
        "ENUM" | "ENUMERATED" => {
            let v = payload
                .ok_or_else(|| Asn1Error::EncodingError("ENUMERATED requires value".to_string()))?;
            let int = parse_integer_literal(v.trim())?;
            let enumerated = Asn1Enumerated::from_i64(int.to_i64()?);
            enumerated.encode_der()
        }
        "OCT" | "OCTET" | "OCTETSTRING" => {
            let v = payload.unwrap_or("");
            let bytes = if format_is_hex {
                hex_decode(v)?
            } else {
                v.as_bytes().to_vec()
            };
            let mut out = write_tlv_header(
                Asn1Tag::OctetString,
                Asn1Class::Universal,
                false,
                bytes.len(),
            )?;
            out.extend_from_slice(&bytes);
            Ok(out)
        }
        "UTF8" | "UTF8STRING" => {
            let v = payload.unwrap_or("");
            let bytes = v.as_bytes().to_vec();
            let mut s = Asn1String::new(Asn1Tag::Utf8String);
            s.set(&bytes)?;
            encode_string_tlv(&s)
        }
        "IA5" | "IA5STRING" => {
            let v = payload.unwrap_or("");
            if !validate_string_content(v.as_bytes(), Asn1Tag::Ia5String) {
                return Err(Asn1Error::InvalidStringContent {
                    tag: Asn1Tag::Ia5String,
                }
                .into());
            }
            let mut s = Asn1String::new(Asn1Tag::Ia5String);
            s.set(v.as_bytes())?;
            encode_string_tlv(&s)
        }
        "PRINTABLE" | "PRINTABLESTRING" => {
            let v = payload.unwrap_or("");
            if !validate_string_content(v.as_bytes(), Asn1Tag::PrintableString) {
                return Err(Asn1Error::InvalidStringContent {
                    tag: Asn1Tag::PrintableString,
                }
                .into());
            }
            let mut s = Asn1String::new(Asn1Tag::PrintableString);
            s.set(v.as_bytes())?;
            encode_string_tlv(&s)
        }
        "T61" | "T61STRING" | "TELETEXSTRING" => {
            let v = payload.unwrap_or("");
            let mut s = Asn1String::new(Asn1Tag::T61String);
            s.set(v.as_bytes())?;
            encode_string_tlv(&s)
        }
        "BMP" | "BMPSTRING" => {
            let v = payload.unwrap_or("");
            let bytes = transcode_string(v.as_bytes(), StringEncoding::Utf8, StringEncoding::Ucs2)?;
            let mut s = Asn1String::new(Asn1Tag::BmpString);
            s.set(&bytes)?;
            encode_string_tlv(&s)
        }
        "UNIV" | "UNIVERSALSTRING" => {
            let v = payload.unwrap_or("");
            let bytes = transcode_string(v.as_bytes(), StringEncoding::Utf8, StringEncoding::Ucs4)?;
            let mut s = Asn1String::new(Asn1Tag::UniversalString);
            s.set(&bytes)?;
            encode_string_tlv(&s)
        }
        "VISIBLE" | "VISIBLESTRING" => {
            let v = payload.unwrap_or("");
            if !validate_string_content(v.as_bytes(), Asn1Tag::VisibleString) {
                return Err(Asn1Error::InvalidStringContent {
                    tag: Asn1Tag::VisibleString,
                }
                .into());
            }
            let mut s = Asn1String::new(Asn1Tag::VisibleString);
            s.set(v.as_bytes())?;
            encode_string_tlv(&s)
        }
        "BITSTR" | "BITSTRING" => {
            let v = payload.unwrap_or("");
            let bytes = if format_is_hex {
                hex_decode(v)?
            } else {
                v.as_bytes().to_vec()
            };
            let mut bs = Asn1BitString::new();
            bs.set_data(&bytes, 0)?;
            bs.encode_der()
        }
        "OID" | "OBJECT" | "OBJECT_IDENTIFIER" => {
            let v = payload.ok_or_else(|| {
                Asn1Error::EncodingError("OID requires numeric value".to_string())
            })?;
            let obj = Asn1Object::from_oid_string(v.trim())?;
            obj.encode_der()
        }
        "UTCTIME" => {
            let v = payload
                .ok_or_else(|| Asn1Error::EncodingError("UTCTIME requires value".to_string()))?;
            let t = Asn1Time::parse(v.trim())?;
            let mut utc = t;
            utc.force_format(TimeFormat::Utc)?;
            utc.encode_der()
        }
        "GENTIME" | "GENERALIZEDTIME" => {
            let v = payload.ok_or_else(|| {
                Asn1Error::EncodingError("GENERALIZEDTIME requires value".to_string())
            })?;
            let t = Asn1Time::parse(v.trim())?;
            let mut gen = t;
            gen.force_format(TimeFormat::Generalized)?;
            gen.encode_der()
        }
        other => {
            Err(Asn1Error::Unsupported(format!("generator type {other} not supported")).into())
        }
    }
}

/// Helper for `generate_typed` that returns a header-only byte vector
/// (0-length content). The `out` argument already contains the header; this
/// is a convenience wrapper used only for NULL.
fn out_with_header(out: &mut Vec<u8>, extra: &[u8]) -> Vec<u8> {
    out.extend_from_slice(extra);
    std::mem::take(out)
}

/// Encode an [`Asn1String`] as a single universal-class primitive TLV.
fn encode_string_tlv(s: &Asn1String) -> CryptoResult<Vec<u8>> {
    let content = s.data();
    let mut out = write_tlv_header(s.tag(), Asn1Class::Universal, false, content.len())?;
    out.extend_from_slice(content);
    Ok(out)
}

/// Parse an integer literal (decimal or `0x` hex) into an [`Asn1Integer`].
fn parse_integer_literal(s: &str) -> CryptoResult<Asn1Integer> {
    let (negative, body) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };
    let (radix, digits) =
        if let Some(rest) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            (16, rest)
        } else {
            (10, body)
        };
    if digits.is_empty() {
        return Err(Asn1Error::EncodingError(format!("invalid INTEGER literal: {s}")).into());
    }
    // Parse as i128 for a broad range; overflow yields a decoding error.
    let magnitude = i128::from_str_radix(digits, radix)
        .map_err(|_| Asn1Error::EncodingError(format!("INTEGER literal out of range: {s}")))?;
    let signed = if negative {
        magnitude.checked_neg().ok_or(Asn1Error::IntegerOverflow)?
    } else {
        magnitude
    };
    let narrowed = i64::try_from(signed).map_err(|_| Asn1Error::IntegerOverflow)?;
    Ok(Asn1Integer::from_i64(narrowed))
}

/// Decode an ASCII hex string (ignoring whitespace).
fn hex_decode(s: &str) -> CryptoResult<Vec<u8>> {
    let filtered: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if filtered.len() % 2 != 0 {
        return Err(
            Asn1Error::EncodingError("hex string has odd number of digits".to_string()).into(),
        );
    }
    let mut out = Vec::with_capacity(filtered.len() / 2);
    let bytes = filtered.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Convert a single ASCII hex digit to its numeric value.
fn hex_nibble(b: u8) -> CryptoResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Asn1Error::EncodingError(format!("invalid hex digit: {}", b as char)).into()),
    }
}

#[cfg(test)]
mod tests {
    //! Comprehensive unit tests for the ASN.1/DER module.
    //!
    //! Covers every public API surface (tags, classes, all fundamental types,
    //! composite types, TLV operations, string handling, time types, signing
    //! helpers, I/O streaming, S/MIME, generator language, parse dump, and
    //! error types) along with the critical private helpers (base-128 encoding,
    //! hex/ASCII helpers) that are exercised indirectly via the public API.

    use super::*;
    use crate::bn::BigNum;
    use std::io::Cursor;

    // ------------------------------------------------------------------
    // Asn1Tag & Asn1Class
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_tag_discriminants_match_universal_numbers() {
        assert_eq!(Asn1Tag::Eoc as u8, 0);
        assert_eq!(Asn1Tag::Boolean as u8, 1);
        assert_eq!(Asn1Tag::Integer as u8, 2);
        assert_eq!(Asn1Tag::BitString as u8, 3);
        assert_eq!(Asn1Tag::OctetString as u8, 4);
        assert_eq!(Asn1Tag::Null as u8, 5);
        assert_eq!(Asn1Tag::ObjectIdentifier as u8, 6);
        assert_eq!(Asn1Tag::Enumerated as u8, 10);
        assert_eq!(Asn1Tag::Utf8String as u8, 12);
        assert_eq!(Asn1Tag::Sequence as u8, 16);
        assert_eq!(Asn1Tag::Set as u8, 17);
        assert_eq!(Asn1Tag::PrintableString as u8, 19);
        assert_eq!(Asn1Tag::UtcTime as u8, 23);
        assert_eq!(Asn1Tag::GeneralizedTime as u8, 24);
        assert_eq!(Asn1Tag::BmpString as u8, 30);
    }

    #[test]
    fn test_asn1_class_values() {
        assert_eq!(Asn1Class::Universal as u8, 0x00);
        assert_eq!(Asn1Class::Application as u8, 0x40);
        assert_eq!(Asn1Class::ContextSpecific as u8, 0x80);
        assert_eq!(Asn1Class::Private as u8, 0xC0);
    }

    // ------------------------------------------------------------------
    // Asn1String
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_string_new_is_empty() {
        let s = Asn1String::new(Asn1Tag::PrintableString);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.tag(), Asn1Tag::PrintableString);
        assert_eq!(s.data(), b"");
    }

    #[test]
    fn test_asn1_string_set_and_accessors() {
        let mut s = Asn1String::new(Asn1Tag::Utf8String);
        s.set(b"hello").unwrap();
        assert_eq!(s.len(), 5);
        assert!(!s.is_empty());
        assert_eq!(s.data(), b"hello");
    }

    #[test]
    fn test_asn1_string_partial_eq_matches_tag_and_data() {
        let mut a = Asn1String::new(Asn1Tag::PrintableString);
        a.set(b"abc").unwrap();
        let mut b = Asn1String::new(Asn1Tag::PrintableString);
        b.set(b"abc").unwrap();
        assert_eq!(a, b);

        // Different tag -> unequal
        let mut c = Asn1String::new(Asn1Tag::Utf8String);
        c.set(b"abc").unwrap();
        assert_ne!(a, c);

        // Different data -> unequal
        let mut d = Asn1String::new(Asn1Tag::PrintableString);
        d.set(b"abd").unwrap();
        assert_ne!(a, d);
    }

    #[test]
    fn test_asn1_string_duplicate_is_independent() {
        let mut original = Asn1String::new(Asn1Tag::PrintableString);
        original.set(b"hello").unwrap();
        let mut dup = original.duplicate();
        dup.set(b"world").unwrap();
        assert_eq!(original.data(), b"hello");
        assert_eq!(dup.data(), b"world");
    }

    #[test]
    fn test_asn1_string_display_printable_graphic() {
        let mut s = Asn1String::new(Asn1Tag::PrintableString);
        s.set(b"Hello World").unwrap();
        assert_eq!(format!("{s}"), "Hello World");
    }

    #[test]
    fn test_asn1_string_display_printable_non_graphic_becomes_dot() {
        let mut s = Asn1String::new(Asn1Tag::PrintableString);
        s.set(&[b'A', 0x00, b'B']).unwrap();
        assert_eq!(format!("{s}"), "A.B");
    }

    #[test]
    fn test_asn1_string_display_binary_tag_lowercase_hex() {
        // BmpString falls into the binary / hex arm of Display
        let mut s = Asn1String::new(Asn1Tag::BmpString);
        s.set(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(format!("{s}"), "deadbeef");
    }

    // ------------------------------------------------------------------
    // Asn1Integer
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_integer_zero() {
        let z = Asn1Integer::new();
        assert_eq!(z.to_i64().unwrap(), 0);
        assert_eq!(z.encode_der().unwrap(), vec![0x00]);
    }

    #[test]
    fn test_asn1_integer_from_i64_positive_small() {
        let n = Asn1Integer::from_i64(5);
        assert_eq!(n.to_i64().unwrap(), 5);
        assert_eq!(n.encode_der().unwrap(), vec![0x05]);
    }

    #[test]
    fn test_asn1_integer_from_i64_positive_127_no_prefix() {
        let n = Asn1Integer::from_i64(127);
        assert_eq!(n.encode_der().unwrap(), vec![0x7F]);
    }

    #[test]
    fn test_asn1_integer_from_i64_positive_128_needs_leading_zero() {
        // 128 encodes as [0x80], but high bit looks negative -> prepend 0x00
        let n = Asn1Integer::from_i64(128);
        assert_eq!(n.encode_der().unwrap(), vec![0x00, 0x80]);
        assert_eq!(n.to_i64().unwrap(), 128);
    }

    #[test]
    fn test_asn1_integer_from_i64_minus_one() {
        let n = Asn1Integer::from_i64(-1);
        assert_eq!(n.encode_der().unwrap(), vec![0xFF]);
        assert_eq!(n.to_i64().unwrap(), -1);
    }

    #[test]
    fn test_asn1_integer_from_i64_minus_128_no_prefix() {
        // -128: two's complement = 0x80, high bit already set
        let n = Asn1Integer::from_i64(-128);
        assert_eq!(n.encode_der().unwrap(), vec![0x80]);
        assert_eq!(n.to_i64().unwrap(), -128);
    }

    #[test]
    fn test_asn1_integer_from_i64_minus_129_needs_ff_prefix() {
        // -129: two's complement = 0xFF7F; first byte high bit not set -> prefix 0xFF
        let n = Asn1Integer::from_i64(-129);
        assert_eq!(n.encode_der().unwrap(), vec![0xFF, 0x7F]);
        assert_eq!(n.to_i64().unwrap(), -129);
    }

    #[test]
    fn test_asn1_integer_from_i64_extremes() {
        let max = Asn1Integer::from_i64(i64::MAX);
        assert_eq!(max.to_i64().unwrap(), i64::MAX);

        let min = Asn1Integer::from_i64(i64::MIN);
        assert_eq!(min.to_i64().unwrap(), i64::MIN);
    }

    #[test]
    fn test_asn1_integer_from_u64_max() {
        let n = Asn1Integer::from_u64(u64::MAX);
        assert_eq!(n.to_u64().unwrap(), u64::MAX);
    }

    #[test]
    fn test_asn1_integer_to_u64_rejects_negative() {
        let n = Asn1Integer::from_i64(-1);
        let err = n.to_u64();
        assert!(err.is_err());
    }

    #[test]
    fn test_asn1_integer_decode_der_roundtrip() {
        for value in &[
            0i64,
            1,
            127,
            128,
            -1,
            -128,
            -129,
            32767,
            -32768,
            i64::MAX,
            i64::MIN,
        ] {
            let encoded = Asn1Integer::from_i64(*value).encode_der().unwrap();
            let decoded = Asn1Integer::decode_der(&encoded).unwrap();
            assert_eq!(
                decoded.to_i64().unwrap(),
                *value,
                "roundtrip failed for value {value}"
            );
        }
    }

    #[test]
    fn test_asn1_integer_decode_der_rejects_empty() {
        let err = Asn1Integer::decode_der(&[]).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("integer"));
    }

    #[test]
    fn test_asn1_integer_decode_der_rejects_illegal_positive_padding() {
        // 0x00, 0x01 -> unnecessary leading zero for a positive value
        let err = Asn1Integer::decode_der(&[0x00, 0x01]).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("padding"));
    }

    #[test]
    fn test_asn1_integer_decode_der_rejects_illegal_negative_padding() {
        // 0xFF, 0x80 -> unnecessary leading 0xFF for a negative value
        let err = Asn1Integer::decode_der(&[0xFF, 0x80]).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("padding"));
    }

    #[test]
    fn test_asn1_integer_ord_zero_vs_positive_vs_negative() {
        let neg = Asn1Integer::from_i64(-5);
        let zero = Asn1Integer::from_i64(0);
        let pos = Asn1Integer::from_i64(5);
        assert!(neg < zero);
        assert!(zero < pos);
        assert!(neg < pos);
        assert_eq!(zero.cmp(&Asn1Integer::from_i64(0)), Ordering::Equal);
    }

    #[test]
    fn test_asn1_integer_bn_roundtrip_positive() {
        let bn = BigNum::from_bytes_be(&[0x12, 0x34, 0x56, 0x78]);
        let integer = Asn1Integer::from_bn(&bn).unwrap();
        let bn_back = integer.to_bn().unwrap();
        assert_eq!(bn_back.to_bytes_be(), vec![0x12, 0x34, 0x56, 0x78]);
        assert!(!bn_back.is_negative());
    }

    #[test]
    fn test_asn1_integer_bn_roundtrip_negative() {
        let mut bn = BigNum::from_bytes_be(&[0x12, 0x34]);
        bn.set_negative(true);
        let integer = Asn1Integer::from_bn(&bn).unwrap();
        let bn_back = integer.to_bn().unwrap();
        assert!(bn_back.is_negative());
        assert_eq!(bn_back.to_bytes_be(), vec![0x12, 0x34]);
    }

    // ------------------------------------------------------------------
    // Asn1Enumerated
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_enumerated_roundtrip() {
        let e = Asn1Enumerated::from_i64(42);
        assert_eq!(e.to_i64().unwrap(), 42);
        let encoded = e.encode_der().unwrap();
        let decoded = Asn1Enumerated::decode_der(&encoded).unwrap();
        assert_eq!(decoded.to_i64().unwrap(), 42);
    }

    #[test]
    fn test_asn1_enumerated_negative_roundtrip() {
        let e = Asn1Enumerated::from_i64(-99);
        let encoded = e.encode_der().unwrap();
        let decoded = Asn1Enumerated::decode_der(&encoded).unwrap();
        assert_eq!(decoded.to_i64().unwrap(), -99);
    }

    // ------------------------------------------------------------------
    // Asn1BitString
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_bitstring_new() {
        let bs = Asn1BitString::new();
        assert_eq!(bs.data(), &[] as &[u8]);
        assert_eq!(bs.unused_bits(), 0);
    }

    #[test]
    fn test_asn1_bitstring_set_data_valid() {
        let mut bs = Asn1BitString::new();
        bs.set_data(&[0xF0], 4).unwrap();
        assert_eq!(bs.data(), &[0xF0]);
        assert_eq!(bs.unused_bits(), 4);
        assert_eq!(bs.bit_len(), 4);
    }

    #[test]
    fn test_asn1_bitstring_set_data_rejects_too_many_unused_bits() {
        let mut bs = Asn1BitString::new();
        let err = bs.set_data(&[0xF0], 8).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("unused"));
    }

    #[test]
    fn test_asn1_bitstring_set_data_rejects_empty_with_unused_bits() {
        let mut bs = Asn1BitString::new();
        let err = bs.set_data(&[], 1).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("unused"));
    }

    #[test]
    fn test_asn1_bitstring_set_data_canonicalizes_trailing_bits() {
        let mut bs = Asn1BitString::new();
        // Provide 0xFF with 4 unused bits -> low nibble should be masked to 0
        bs.set_data(&[0xFF], 4).unwrap();
        assert_eq!(bs.data(), &[0xF0]);
    }

    #[test]
    fn test_asn1_bitstring_get_bit() {
        let mut bs = Asn1BitString::new();
        bs.set_data(&[0b1010_0000], 0).unwrap();
        assert!(bs.get_bit(0));
        assert!(!bs.get_bit(1));
        assert!(bs.get_bit(2));
        assert!(!bs.get_bit(3));
    }

    #[test]
    fn test_asn1_bitstring_get_bit_out_of_range_returns_false() {
        let bs = Asn1BitString::new();
        assert!(!bs.get_bit(100));
    }

    #[test]
    fn test_asn1_bitstring_check_bit_is_alias_for_get_bit() {
        let mut bs = Asn1BitString::new();
        bs.set_data(&[0b1010_0000], 0).unwrap();
        for i in 0..8 {
            assert_eq!(bs.get_bit(i), bs.check_bit(i), "disagreement at bit {i}");
        }
    }

    #[test]
    fn test_asn1_bitstring_set_bit_extends_buffer() {
        let mut bs = Asn1BitString::new();
        bs.set_bit(10, true).unwrap();
        assert!(bs.get_bit(10));
        assert!(!bs.get_bit(9));
    }

    #[test]
    fn test_asn1_bitstring_encode_der_format() {
        let mut bs = Asn1BitString::new();
        bs.set_data(&[0xF8], 3).unwrap();
        let encoded = bs.encode_der().unwrap();
        // Content: [unused_bits, data...]
        assert_eq!(encoded, vec![0x03, 0xF8]);
    }

    #[test]
    fn test_asn1_bitstring_decode_der_empty_rejected() {
        let err = Asn1BitString::decode_der(&[]).unwrap_err();
        assert!(
            format!("{err}").to_lowercase().contains("length")
                || format!("{err}").to_lowercase().contains("empty")
        );
    }

    #[test]
    fn test_asn1_bitstring_decode_der_unused_bits_over_seven() {
        let err = Asn1BitString::decode_der(&[8]).unwrap_err();
        let _ = err; // just need to be an error
    }

    #[test]
    fn test_asn1_bitstring_decode_der_canonical_zero_content_with_nonzero_unused() {
        // single-byte content with non-zero unused_bits: per X.690 this is invalid
        let err = Asn1BitString::decode_der(&[2]).unwrap_err();
        let _ = err;
    }

    #[test]
    fn test_asn1_bitstring_roundtrip() {
        let mut original = Asn1BitString::new();
        original.set_data(&[0xA5, 0x5A], 2).unwrap();
        let encoded = original.encode_der().unwrap();
        let decoded = Asn1BitString::decode_der(&encoded).unwrap();
        assert_eq!(decoded.data(), original.data());
        assert_eq!(decoded.unused_bits(), original.unused_bits());
    }

    // ------------------------------------------------------------------
    // Asn1OctetString
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_octet_string_accessors() {
        let os = Asn1OctetString::new();
        assert_eq!(os.len(), 0);
        assert_eq!(os.data(), &[] as &[u8]);
    }

    #[test]
    fn test_asn1_octet_string_from_bytes_roundtrip() {
        let os = Asn1OctetString::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(os.len(), 4);
        assert_eq!(os.data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = os.encode_der().unwrap();
        let decoded = Asn1OctetString::decode_der(&encoded).unwrap();
        assert_eq!(decoded, os);
    }

    #[test]
    fn test_asn1_octet_string_partial_eq_and_clone() {
        let a = Asn1OctetString::from_bytes(vec![1, 2, 3]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // Asn1Object
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_object_from_oid_string_valid() {
        let obj = Asn1Object::from_oid_string("1.2.840.113549.1.1.11").unwrap();
        let s = obj.to_oid_string().unwrap();
        assert_eq!(s, "1.2.840.113549.1.1.11");
    }

    #[test]
    fn test_asn1_object_from_oid_string_rejects_single_arc() {
        let err = Asn1Object::from_oid_string("1").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("arc"));
    }

    #[test]
    fn test_asn1_object_from_oid_string_rejects_first_arc_above_two() {
        let err = Asn1Object::from_oid_string("3.0").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("first"));
    }

    #[test]
    fn test_asn1_object_from_oid_string_rejects_second_arc_over_39_with_low_first() {
        let err = Asn1Object::from_oid_string("1.40").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("second"));
    }

    #[test]
    fn test_asn1_object_from_oid_string_accepts_high_second_arc_when_first_is_two() {
        // First = 2 exempts second arc from 0..=39 restriction
        let obj = Asn1Object::from_oid_string("2.100.3").unwrap();
        assert_eq!(obj.to_oid_string().unwrap(), "2.100.3");
    }

    #[test]
    fn test_asn1_object_from_oid_string_rejects_non_numeric_arc() {
        let err = Asn1Object::from_oid_string("1.abc").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("arc"));
        let err = Asn1Object::from_oid_string("abc.1").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("arc"));
        let err = Asn1Object::from_oid_string("1.2.abc").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("arc"));
    }

    #[test]
    fn test_asn1_object_roundtrip_der() {
        let obj = Asn1Object::from_oid_string("1.2.840.113549.1.1.11").unwrap();
        let encoded = obj.encode_der().unwrap();
        let decoded = Asn1Object::decode_der(&encoded).unwrap();
        assert_eq!(decoded.to_oid_string().unwrap(), "1.2.840.113549.1.1.11");
    }

    #[test]
    fn test_asn1_object_decode_der_rejects_empty() {
        let err = Asn1Object::decode_der(&[]).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("oid"));
    }

    #[test]
    fn test_asn1_object_decode_der_rejects_non_canonical_encoding() {
        // 0x80, 0x80, 0x01 has a leading 0x80 continuation byte -> non-canonical
        let err = Asn1Object::decode_der(&[0x80, 0x80, 0x01]).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("canonical"));
    }

    #[test]
    fn test_asn1_object_decode_der_rejects_mid_sub_identifier() {
        // 0x2A, 0x86 -> 0x86 has continuation bit set but no following byte
        let err = Asn1Object::decode_der(&[0x2A, 0x86]).unwrap_err();
        let _ = err;
    }

    #[test]
    fn test_asn1_object_partial_eq_compares_oid_bytes() {
        let a = Asn1Object::from_oid_string("1.2.3").unwrap();
        let b = Asn1Object::from_oid_string("1.2.3").unwrap();
        assert_eq!(a, b);

        let c = Asn1Object::from_oid_string("1.2.4").unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn test_asn1_object_display_delegates_to_oid_string() {
        let obj = Asn1Object::from_oid_string("1.2.840").unwrap();
        assert_eq!(format!("{obj}"), "1.2.840");
    }

    // ------------------------------------------------------------------
    // Asn1Null
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_null_encode_der_empty() {
        let n = Asn1Null::new();
        assert_eq!(n.encode_der().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_asn1_null_decode_der_empty_ok() {
        Asn1Null::decode_der(&[]).unwrap();
    }

    #[test]
    fn test_asn1_null_decode_der_non_empty_rejected() {
        let err = Asn1Null::decode_der(&[0x00]).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("null"));
    }

    // ------------------------------------------------------------------
    // Asn1Boolean
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_boolean_encode_true() {
        let b = Asn1Boolean::new(true);
        assert_eq!(b.encode_der().unwrap(), vec![0xFF]);
    }

    #[test]
    fn test_asn1_boolean_encode_false() {
        let b = Asn1Boolean::new(false);
        assert_eq!(b.encode_der().unwrap(), vec![0x00]);
    }

    #[test]
    fn test_asn1_boolean_decode_true() {
        let b = Asn1Boolean::decode_der(&[0xFF]).unwrap();
        assert!(b.value);
    }

    #[test]
    fn test_asn1_boolean_decode_false() {
        let b = Asn1Boolean::decode_der(&[0x00]).unwrap();
        assert!(!b.value);
    }

    #[test]
    fn test_asn1_boolean_decode_non_canonical_one_rejected() {
        let err = Asn1Boolean::decode_der(&[0x01]).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("boolean"));
    }

    #[test]
    fn test_asn1_boolean_decode_empty_rejected() {
        let err = Asn1Boolean::decode_der(&[]).unwrap_err();
        let _ = err;
    }

    #[test]
    fn test_asn1_boolean_decode_two_bytes_rejected() {
        let err = Asn1Boolean::decode_der(&[0xFF, 0x00]).unwrap_err();
        let _ = err;
    }

    // ------------------------------------------------------------------
    // Asn1Type
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_type_get_tag() {
        assert_eq!(
            Asn1Type::Boolean(Asn1Boolean::new(true)).get_tag(),
            Asn1Tag::Boolean
        );
        assert_eq!(
            Asn1Type::Integer(Asn1Integer::from_i64(5)).get_tag(),
            Asn1Tag::Integer
        );
        assert_eq!(Asn1Type::Null(Asn1Null::new()).get_tag(), Asn1Tag::Null);
        assert_eq!(
            Asn1Type::OctetString(Asn1OctetString::from_bytes(vec![])).get_tag(),
            Asn1Tag::OctetString
        );
    }

    #[test]
    fn test_asn1_type_roundtrip_integer() {
        let t = Asn1Type::Integer(Asn1Integer::from_i64(42));
        let encoded = t.encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&encoded).unwrap();
        match decoded {
            Asn1Type::Integer(n) => assert_eq!(n.to_i64().unwrap(), 42),
            _ => panic!("wrong variant decoded"),
        }
    }

    #[test]
    fn test_asn1_type_roundtrip_boolean() {
        let t = Asn1Type::Boolean(Asn1Boolean::new(true));
        let encoded = t.encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&encoded).unwrap();
        match decoded {
            Asn1Type::Boolean(b) => assert!(b.value),
            _ => panic!("wrong variant decoded"),
        }
    }

    #[test]
    fn test_asn1_type_roundtrip_null() {
        let t = Asn1Type::Null(Asn1Null::new());
        let encoded = t.encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&encoded).unwrap();
        assert!(matches!(decoded, Asn1Type::Null(_)));
    }

    // ------------------------------------------------------------------
    // Asn1Time
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_time_new_within_utc_range_picks_utc() {
        let t = Asn1Time::new(2023, 1, 15, 12, 30, 45).unwrap();
        assert_eq!(t.format(), TimeFormat::Utc);
    }

    #[test]
    fn test_asn1_time_new_outside_utc_range_picks_generalized() {
        let t = Asn1Time::new(2050, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(t.format(), TimeFormat::Generalized);

        let t = Asn1Time::new(1949, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(t.format(), TimeFormat::Generalized);
    }

    #[test]
    fn test_asn1_time_with_format_utc_rejects_year_out_of_range() {
        let err = Asn1Time::with_format(2050, 1, 1, 0, 0, 0, TimeFormat::Utc).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("utc"));
    }

    #[test]
    fn test_asn1_time_parse_utc() {
        let t = Asn1Time::parse("230115123045Z").unwrap();
        assert_eq!(t.format(), TimeFormat::Utc);
        assert_eq!(t.year(), 2023);
        assert_eq!(t.month(), 1);
        assert_eq!(t.day(), 15);
        assert_eq!(t.hour(), 12);
        assert_eq!(t.minute(), 30);
        assert_eq!(t.second(), 45);
    }

    #[test]
    fn test_asn1_time_parse_generalized() {
        let t = Asn1Time::parse("20230115123045Z").unwrap();
        assert_eq!(t.format(), TimeFormat::Generalized);
        assert_eq!(t.year(), 2023);
    }

    #[test]
    fn test_asn1_time_parse_rejects_short_input() {
        let err = Asn1Time::parse("230115Z").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("digit"));
    }

    #[test]
    fn test_asn1_time_parse_rejects_missing_z() {
        let err = Asn1Time::parse("230115123045").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("z"));
    }

    #[test]
    fn test_asn1_time_to_string_utc() {
        let t = Asn1Time::new(2023, 1, 15, 12, 30, 45).unwrap();
        assert_eq!(t.to_string(), "230115123045Z");
    }

    #[test]
    fn test_asn1_time_to_string_generalized() {
        let t = Asn1Time::new(2050, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(t.to_string(), "20500101000000Z");
    }

    #[test]
    fn test_asn1_time_der_content_only_ascii() {
        let t = Asn1Time::new(2023, 1, 15, 12, 30, 45).unwrap();
        let encoded = t.encode_der().unwrap();
        assert_eq!(encoded, b"230115123045Z");
    }

    #[test]
    fn test_asn1_time_decode_der_roundtrip() {
        let t = Asn1Time::new(2023, 1, 15, 12, 30, 45).unwrap();
        let encoded = t.encode_der().unwrap();
        let decoded = Asn1Time::decode_der(&encoded).unwrap();
        assert_eq!(decoded, t);
    }

    #[test]
    fn test_asn1_time_ord() {
        let earlier = Asn1Time::new(2023, 1, 15, 12, 0, 0).unwrap();
        let later = Asn1Time::new(2023, 1, 15, 12, 0, 1).unwrap();
        assert!(earlier < later);
        assert_eq!(earlier.cmp(&earlier), Ordering::Equal);
    }

    #[test]
    fn test_asn1_time_diff_seconds() {
        // Asn1Time::diff follows OpenSSL's `ASN1_TIME_diff(from, to)` convention:
        // `self.diff(other)` computes `other - self`.
        let t1 = Asn1Time::new(2023, 1, 15, 12, 0, 0).unwrap();
        let t2 = Asn1Time::new(2023, 1, 15, 12, 0, 30).unwrap();
        let diff = t1.diff(&t2).unwrap();
        assert_eq!(diff.seconds, 30);
        assert_eq!(diff.days, 0);
    }

    // ------------------------------------------------------------------
    // Validity
    // ------------------------------------------------------------------

    #[test]
    fn test_validity_is_valid_normal_order() {
        let not_before = Asn1Time::new(2023, 1, 1, 0, 0, 0).unwrap();
        let not_after = Asn1Time::new(2024, 1, 1, 0, 0, 0).unwrap();
        let v = Validity::new(not_before, not_after);
        assert!(v.is_valid());
    }

    #[test]
    fn test_validity_is_valid_equal_times() {
        // Inclusive upper bound: equal times should still be valid
        let same = Asn1Time::new(2023, 1, 1, 0, 0, 0).unwrap();
        let v = Validity::new(same.clone(), same);
        assert!(v.is_valid());
    }

    #[test]
    fn test_validity_is_valid_reversed_times() {
        let later = Asn1Time::new(2024, 1, 1, 0, 0, 0).unwrap();
        let earlier = Asn1Time::new(2023, 1, 1, 0, 0, 0).unwrap();
        let v = Validity::new(later, earlier);
        assert!(!v.is_valid());
    }

    #[test]
    fn test_validity_der_roundtrip() {
        let not_before = Asn1Time::new(2023, 1, 1, 0, 0, 0).unwrap();
        let not_after = Asn1Time::new(2024, 6, 30, 23, 59, 59).unwrap();
        let v = Validity::new(not_before, not_after);
        let encoded = v.encode_der().unwrap();
        let decoded = Validity::decode_der(&encoded).unwrap();
        assert_eq!(decoded.not_before, v.not_before);
        assert_eq!(decoded.not_after, v.not_after);
    }

    // ------------------------------------------------------------------
    // AlgorithmIdentifier
    // ------------------------------------------------------------------

    #[test]
    fn test_algorithm_identifier_no_parameters_roundtrip() {
        let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.11").unwrap();
        let alg = AlgorithmIdentifier::new(oid, None);
        let encoded = alg.encode_der().unwrap();
        let decoded = AlgorithmIdentifier::decode_der(&encoded).unwrap();
        assert_eq!(decoded.algorithm, alg.algorithm);
        assert!(decoded.parameters.is_none());
    }

    #[test]
    fn test_algorithm_identifier_with_null_parameters_roundtrip() {
        let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.11").unwrap();
        let alg = AlgorithmIdentifier::new(oid, Some(Asn1Type::Null(Asn1Null::new())));
        let encoded = alg.encode_der().unwrap();
        let decoded = AlgorithmIdentifier::decode_der(&encoded).unwrap();
        assert_eq!(decoded.algorithm, alg.algorithm);
        assert!(matches!(decoded.parameters, Some(Asn1Type::Null(_))));
    }

    // ------------------------------------------------------------------
    // DigestInfo
    // ------------------------------------------------------------------

    #[test]
    fn test_digest_info_roundtrip() {
        let oid = Asn1Object::from_oid_string("2.16.840.1.101.3.4.2.1").unwrap();
        let alg = AlgorithmIdentifier::new(oid, Some(Asn1Type::Null(Asn1Null::new())));
        let digest =
            Asn1OctetString::from_bytes(vec![0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]);
        let di = DigestInfo::new(alg, digest);
        let encoded = di.encode_der().unwrap();
        let decoded = DigestInfo::decode_der(&encoded).unwrap();
        assert_eq!(
            decoded.digest_algorithm.algorithm,
            di.digest_algorithm.algorithm
        );
        assert_eq!(decoded.digest, di.digest);
    }

    // ------------------------------------------------------------------
    // PbeParam / Pbes2Param / Pbkdf2Param / ScryptParam
    // ------------------------------------------------------------------

    #[test]
    fn test_pbe_param_default_iter_constant() {
        assert_eq!(PbeParam::DEFAULT_ITER, 2048);
    }

    #[test]
    fn test_pbe_param_roundtrip() {
        let salt =
            Asn1OctetString::from_bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let iter = Asn1Integer::from_i64(2048);
        let p = PbeParam::new(salt, iter);
        let encoded = p.encode_der().unwrap();
        let decoded = PbeParam::decode_der(&encoded).unwrap();
        assert_eq!(decoded.salt, p.salt);
        assert_eq!(decoded.iteration_count.to_i64().unwrap(), 2048);
    }

    #[test]
    fn test_pbes2_param_roundtrip() {
        let kdf_oid = Asn1Object::from_oid_string("1.2.840.113549.1.5.12").unwrap();
        let kdf = AlgorithmIdentifier::new(kdf_oid, None);
        let enc_oid = Asn1Object::from_oid_string("2.16.840.1.101.3.4.1.42").unwrap();
        let enc = AlgorithmIdentifier::new(enc_oid, None);
        let p = Pbes2Param::new(kdf, enc);
        let encoded = p.encode_der().unwrap();
        let decoded = Pbes2Param::decode_der(&encoded).unwrap();
        assert_eq!(decoded.key_derivation.algorithm, p.key_derivation.algorithm);
        assert_eq!(decoded.encryption.algorithm, p.encryption.algorithm);
    }

    #[test]
    fn test_pbkdf2_param_roundtrip_minimal() {
        let salt = Asn1OctetString::from_bytes(vec![0x01, 0x02, 0x03, 0x04]);
        let iter = Asn1Integer::from_i64(1000);
        let p = Pbkdf2Param::new(salt, iter, None, None);
        let encoded = p.encode_der().unwrap();
        let decoded = Pbkdf2Param::decode_der(&encoded).unwrap();
        assert_eq!(decoded.salt, p.salt);
        assert_eq!(decoded.iteration_count.to_i64().unwrap(), 1000);
        assert!(decoded.key_length.is_none());
        assert!(decoded.prf.is_none());
    }

    #[test]
    fn test_pbkdf2_param_roundtrip_with_key_length() {
        let salt = Asn1OctetString::from_bytes(vec![0x01, 0x02]);
        let iter = Asn1Integer::from_i64(1000);
        let key_length = Asn1Integer::from_i64(32);
        let p = Pbkdf2Param::new(salt, iter, Some(key_length), None);
        let encoded = p.encode_der().unwrap();
        let decoded = Pbkdf2Param::decode_der(&encoded).unwrap();
        assert_eq!(decoded.key_length.unwrap().to_i64().unwrap(), 32);
    }

    #[test]
    fn test_scrypt_param_roundtrip_full() {
        let salt = Asn1OctetString::from_bytes(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let cost = Asn1Integer::from_i64(16384);
        let block_size = Asn1Integer::from_i64(8);
        let parallelization = Asn1Integer::from_i64(1);
        let key_length = Asn1Integer::from_i64(32);
        let p = ScryptParam::new(salt, cost, block_size, parallelization, Some(key_length));
        let encoded = p.encode_der().unwrap();
        let decoded = ScryptParam::decode_der(&encoded).unwrap();
        assert_eq!(decoded.salt.data(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(decoded.cost.to_i64().unwrap(), 16384);
        assert_eq!(decoded.block_size.to_i64().unwrap(), 8);
        assert_eq!(decoded.parallelization.to_i64().unwrap(), 1);
        assert_eq!(decoded.key_length.unwrap().to_i64().unwrap(), 32);
    }

    #[test]
    fn test_scrypt_param_roundtrip_without_key_length() {
        let salt = Asn1OctetString::from_bytes(vec![0xAA]);
        let cost = Asn1Integer::from_i64(16384);
        let block_size = Asn1Integer::from_i64(8);
        let parallelization = Asn1Integer::from_i64(1);
        let p = ScryptParam::new(salt, cost, block_size, parallelization, None);
        let encoded = p.encode_der().unwrap();
        let decoded = ScryptParam::decode_der(&encoded).unwrap();
        // 3-integer path should yield None for key_length
        assert!(decoded.key_length.is_none());
        assert_eq!(decoded.cost.to_i64().unwrap(), 16384);
        assert_eq!(decoded.block_size.to_i64().unwrap(), 8);
        assert_eq!(decoded.parallelization.to_i64().unwrap(), 1);
    }

    // ------------------------------------------------------------------
    // Pkcs8PrivateKeyInfo
    // ------------------------------------------------------------------

    #[test]
    fn test_pkcs8_private_key_info_new_version_zero_ok() {
        let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.1").unwrap();
        let alg = AlgorithmIdentifier::new(oid, Some(Asn1Type::Null(Asn1Null::new())));
        let key = Asn1OctetString::from_bytes(vec![0x01, 0x02]);
        let pki = Pkcs8PrivateKeyInfo::new(Asn1Integer::from_i64(0), alg, key);
        assert!(pki.is_ok());
    }

    #[test]
    fn test_pkcs8_private_key_info_new_version_one_ok() {
        let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.1").unwrap();
        let alg = AlgorithmIdentifier::new(oid, None);
        let key = Asn1OctetString::from_bytes(vec![0x01]);
        let pki = Pkcs8PrivateKeyInfo::new(Asn1Integer::from_i64(1), alg, key);
        assert!(pki.is_ok());
    }

    #[test]
    fn test_pkcs8_private_key_info_new_version_two_rejected() {
        let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.1").unwrap();
        let alg = AlgorithmIdentifier::new(oid, None);
        let key = Asn1OctetString::from_bytes(vec![0x01]);
        let err = Pkcs8PrivateKeyInfo::new(Asn1Integer::from_i64(2), alg, key).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("version"));
    }

    #[test]
    fn test_pkcs8_private_key_info_new_negative_version_rejected() {
        let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.1").unwrap();
        let alg = AlgorithmIdentifier::new(oid, None);
        let key = Asn1OctetString::from_bytes(vec![0x01]);
        let err = Pkcs8PrivateKeyInfo::new(Asn1Integer::from_i64(-1), alg, key).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("version"));
    }

    // ------------------------------------------------------------------
    // Spkac / NetscapeSpki / SmimeData
    // ------------------------------------------------------------------

    #[test]
    fn test_spkac_constructor() {
        let mut challenge = Asn1String::new(Asn1Tag::Ia5String);
        challenge.set(b"challenge").unwrap();
        let _spkac = Spkac::new(vec![0x30, 0x00], challenge);
    }

    #[test]
    fn test_netscape_spki_constructor() {
        let mut challenge = Asn1String::new(Asn1Tag::Ia5String);
        challenge.set(b"c").unwrap();
        let spkac = Spkac::new(vec![0x30, 0x00], challenge);
        let oid = Asn1Object::from_oid_string("1.2").unwrap();
        let alg = AlgorithmIdentifier::new(oid, None);
        let sig = Asn1BitString::new();
        let _nsspki = NetscapeSpki::new(spkac, alg, sig);
    }

    #[test]
    fn test_smime_data_constructor() {
        let sd = SmimeData::new(
            b"hello".to_vec(),
            "text/plain".to_string(),
            vec![("X-Foo".to_string(), "bar".to_string())],
        );
        assert_eq!(sd.content, b"hello");
        assert_eq!(sd.content_type, "text/plain");
        assert_eq!(sd.headers.len(), 1);
    }

    // ------------------------------------------------------------------
    // StringConstraint (POD) / string_table_get
    // ------------------------------------------------------------------

    #[test]
    fn test_string_table_get_unregistered_returns_none() {
        // Use a NID that is extremely unlikely to be registered
        assert!(string_table_get(99_999).is_none());
    }

    #[test]
    fn test_string_table_get_country_name() {
        // NID 14 = countryName: max_size 2 PrintableString, STABLE_NO_MASK
        let c = string_table_get(14).unwrap();
        assert_eq!(c.nid, 14);
        assert_eq!(c.max_size, 2);
        assert_eq!(c.mask, B_ASN1_PRINTABLESTRING);
        assert_eq!(c.flags, STABLE_NO_MASK);
    }

    #[test]
    fn test_string_constraint_literal_construction() {
        let c = StringConstraint {
            nid: 100,
            min_size: 0,
            max_size: 64,
            mask: B_ASN1_UTF8STRING,
            flags: 0,
        };
        assert_eq!(c.nid, 100);
        assert_eq!(c.max_size, 64);
    }

    // ------------------------------------------------------------------
    // B_ASN1_* string-type bitmask constants
    // ------------------------------------------------------------------

    #[test]
    fn test_b_asn1_string_type_constants() {
        assert_eq!(B_ASN1_NUMERICSTRING, 0x0001);
        assert_eq!(B_ASN1_PRINTABLESTRING, 0x0002);
        assert_eq!(B_ASN1_T61STRING, 0x0004);
        assert_eq!(B_ASN1_TELETEXSTRING, 0x0004); // alias
        assert_eq!(B_ASN1_VIDEOTEXSTRING, 0x0008);
        assert_eq!(B_ASN1_IA5STRING, 0x0010);
        assert_eq!(B_ASN1_GRAPHICSTRING, 0x0020);
        assert_eq!(B_ASN1_VISIBLESTRING, 0x0040);
        assert_eq!(B_ASN1_GENERALSTRING, 0x0080);
        assert_eq!(B_ASN1_UNIVERSALSTRING, 0x0100);
        assert_eq!(B_ASN1_OCTET_STRING, 0x0200);
        assert_eq!(B_ASN1_BITSTRING, 0x0400);
        assert_eq!(B_ASN1_BMPSTRING, 0x0800);
        assert_eq!(B_ASN1_UNKNOWN, 0x1000);
        assert_eq!(B_ASN1_UTF8STRING, 0x2000);
        assert_eq!(STABLE_NO_MASK, 0x0002);
    }

    // ------------------------------------------------------------------
    // StringFlags (bitflags)
    // ------------------------------------------------------------------

    #[test]
    fn test_string_flags_values() {
        assert_eq!(StringFlags::BITS_LEFT.bits(), 0x08);
        assert_eq!(StringFlags::NDEF.bits(), 0x10);
    }

    #[test]
    fn test_string_flags_insert_remove_contains() {
        let mut f = StringFlags::empty();
        assert!(!f.contains(StringFlags::BITS_LEFT));
        f.insert(StringFlags::BITS_LEFT);
        assert!(f.contains(StringFlags::BITS_LEFT));
        f.remove(StringFlags::BITS_LEFT);
        assert!(!f.contains(StringFlags::BITS_LEFT));
    }

    // ------------------------------------------------------------------
    // parse_tlv_header / write_tlv_header / tlv_encoded_size
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_tlv_header_empty_rejected() {
        let err = parse_tlv_header(&[]).unwrap_err();
        // `Asn1Error::TruncatedData` is mapped to `CryptoError::Encoding(String)`
        // via `impl From<Asn1Error> for CryptoError`.
        assert!(matches!(err, CryptoError::Encoding(_)));
    }

    #[test]
    fn test_parse_tlv_header_simple_integer() {
        let h = parse_tlv_header(&[0x02, 0x01, 0x05]).unwrap();
        assert_eq!(h.tag, Asn1Tag::Integer);
        assert_eq!(h.class, Asn1Class::Universal);
        assert!(!h.constructed);
        assert_eq!(h.content_length, Some(1));
        assert_eq!(h.header_length, 2);
    }

    #[test]
    fn test_parse_tlv_header_constructed_sequence() {
        let h = parse_tlv_header(&[0x30, 0x03, 0x02, 0x01, 0x05]).unwrap();
        assert_eq!(h.tag, Asn1Tag::Sequence);
        assert!(h.constructed);
        assert_eq!(h.content_length, Some(3));
        assert_eq!(h.header_length, 2);
    }

    #[test]
    fn test_parse_tlv_header_indefinite_length() {
        let h = parse_tlv_header(&[0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]).unwrap();
        assert_eq!(h.tag, Asn1Tag::Sequence);
        assert_eq!(h.content_length, None);
        assert_eq!(h.header_length, 2);
    }

    #[test]
    fn test_parse_tlv_header_long_form_length() {
        let mut buf = vec![0x30, 0x82, 0x01, 0x00];
        buf.extend_from_slice(&[0; 256]);
        let h = parse_tlv_header(&buf).unwrap();
        assert_eq!(h.tag, Asn1Tag::Sequence);
        assert_eq!(h.content_length, Some(256));
        assert_eq!(h.header_length, 4);
    }

    #[test]
    fn test_write_tlv_header_simple_integer() {
        let out = write_tlv_header(Asn1Tag::Integer, Asn1Class::Universal, false, 1).unwrap();
        assert_eq!(out, vec![0x02, 0x01]);
    }

    #[test]
    fn test_write_tlv_header_constructed_sequence() {
        let out = write_tlv_header(Asn1Tag::Sequence, Asn1Class::Universal, true, 3).unwrap();
        assert_eq!(out, vec![0x30, 0x03]);
    }

    #[test]
    fn test_write_tlv_header_long_form_128() {
        let out = write_tlv_header(Asn1Tag::Sequence, Asn1Class::Universal, true, 128).unwrap();
        assert_eq!(out, vec![0x30, 0x81, 0x80]);
    }

    #[test]
    fn test_write_tlv_header_long_form_256() {
        let out = write_tlv_header(Asn1Tag::Sequence, Asn1Class::Universal, true, 256).unwrap();
        assert_eq!(out, vec![0x30, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_tlv_encoded_size_short_form() {
        assert_eq!(tlv_encoded_size(false, 1, Asn1Tag::Integer).unwrap(), 3);
        assert_eq!(tlv_encoded_size(false, 0, Asn1Tag::Null).unwrap(), 2);
    }

    #[test]
    fn test_tlv_encoded_size_long_form() {
        // 128 bytes content + 2-byte tag/len prefix + 1-byte long-form length indicator = 131
        assert_eq!(tlv_encoded_size(true, 128, Asn1Tag::Sequence).unwrap(), 131);
    }

    // ------------------------------------------------------------------
    // select_string_type
    // ------------------------------------------------------------------

    #[test]
    fn test_select_string_type_printable_preferred_for_basic_ascii() {
        let t = select_string_type(b"Hello World 123", StringEncoding::Ascii).unwrap();
        assert_eq!(t, Asn1Tag::PrintableString);
    }

    #[test]
    fn test_select_string_type_upgrades_to_ia5_for_underscore() {
        let t = select_string_type(b"name_with_underscore", StringEncoding::Ascii).unwrap();
        assert_eq!(t, Asn1Tag::Ia5String);
    }

    #[test]
    fn test_select_string_type_utf8_bmp_chars_yields_bmp_string() {
        // Café: é is U+00E9 (BMP)
        let t = select_string_type("Café".as_bytes(), StringEncoding::Utf8).unwrap();
        assert_eq!(t, Asn1Tag::BmpString);
    }

    #[test]
    fn test_select_string_type_utf8_supplementary_yields_utf8_string() {
        // U+1F600 (😀) requires 4 UTF-8 bytes — non-BMP
        let t = select_string_type("😀".as_bytes(), StringEncoding::Utf8).unwrap();
        assert_eq!(t, Asn1Tag::Utf8String);
    }

    // ------------------------------------------------------------------
    // transcode_string
    // ------------------------------------------------------------------

    #[test]
    fn test_transcode_ascii_to_utf8_identity() {
        let out = transcode_string(b"Hello", StringEncoding::Ascii, StringEncoding::Utf8).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn test_transcode_ascii_rejects_non_ascii_input() {
        let err =
            transcode_string(&[0x80], StringEncoding::Ascii, StringEncoding::Utf8).unwrap_err();
        let _ = err;
    }

    #[test]
    fn test_transcode_utf8_to_latin1_round_trip() {
        // é (U+00E9) is in Latin-1
        let out = transcode_string(
            "Café".as_bytes(),
            StringEncoding::Utf8,
            StringEncoding::Latin1,
        )
        .unwrap();
        assert_eq!(out, vec![b'C', b'a', b'f', 0xE9]);

        let round = transcode_string(&out, StringEncoding::Latin1, StringEncoding::Utf8).unwrap();
        assert_eq!(round, "Café".as_bytes());
    }

    #[test]
    fn test_transcode_utf8_to_latin1_rejects_out_of_range() {
        // U+0100 is beyond Latin-1
        let err = transcode_string("Ā".as_bytes(), StringEncoding::Utf8, StringEncoding::Latin1)
            .unwrap_err();
        let _ = err;
    }

    #[test]
    fn test_transcode_utf8_to_ucs2_big_endian() {
        let out = transcode_string(b"AB", StringEncoding::Utf8, StringEncoding::Ucs2).unwrap();
        // Big-endian: 0x00 0x41 0x00 0x42
        assert_eq!(out, vec![0x00, 0x41, 0x00, 0x42]);
    }

    #[test]
    fn test_transcode_ucs2_to_utf8_big_endian() {
        let out = transcode_string(
            &[0x00, 0x41, 0x00, 0x42],
            StringEncoding::Ucs2,
            StringEncoding::Utf8,
        )
        .unwrap();
        assert_eq!(out, b"AB");
    }

    #[test]
    fn test_transcode_ucs2_odd_length_rejected() {
        let err = transcode_string(
            &[0x00, 0x41, 0x00],
            StringEncoding::Ucs2,
            StringEncoding::Utf8,
        )
        .unwrap_err();
        let _ = err;
    }

    #[test]
    fn test_transcode_ucs4_non_multiple_of_four_rejected() {
        let err = transcode_string(
            &[0x00, 0x00, 0x00],
            StringEncoding::Ucs4,
            StringEncoding::Utf8,
        )
        .unwrap_err();
        let _ = err;
    }

    // ------------------------------------------------------------------
    // validate_string_content
    // ------------------------------------------------------------------

    #[test]
    fn test_validate_string_content_printable_rejects_underscore() {
        assert!(!validate_string_content(
            b"has_underscore",
            Asn1Tag::PrintableString
        ));
        assert!(validate_string_content(
            b"no underscore",
            Asn1Tag::PrintableString
        ));
    }

    #[test]
    fn test_validate_string_content_ia5_accepts_ascii() {
        assert!(validate_string_content(
            b"anything~!@#$%^&*()",
            Asn1Tag::Ia5String
        ));
    }

    #[test]
    fn test_validate_string_content_ia5_rejects_high_byte() {
        assert!(!validate_string_content(&[0x80], Asn1Tag::Ia5String));
    }

    #[test]
    fn test_validate_string_content_utf8_accepts_valid_utf8() {
        assert!(validate_string_content(
            "hello world — Café 😀".as_bytes(),
            Asn1Tag::Utf8String
        ));
    }

    #[test]
    fn test_validate_string_content_utf8_rejects_invalid_utf8() {
        assert!(!validate_string_content(&[0xC3, 0x28], Asn1Tag::Utf8String));
    }

    #[test]
    fn test_validate_string_content_bmp_requires_even_length() {
        assert!(!validate_string_content(&[0x00], Asn1Tag::BmpString));
        assert!(validate_string_content(&[0x00, 0x41], Asn1Tag::BmpString));
    }

    // ------------------------------------------------------------------
    // format_string_rfc2253
    // ------------------------------------------------------------------

    #[test]
    fn test_format_string_rfc2253_plain() {
        let mut s = Asn1String::new(Asn1Tag::PrintableString);
        s.set(b"Hello").unwrap();
        let out = format_string_rfc2253(&s);
        assert_eq!(out, "Hello");
    }

    #[test]
    fn test_format_string_rfc2253_escapes_comma() {
        let mut s = Asn1String::new(Asn1Tag::PrintableString);
        s.set(b"A,B").unwrap();
        let out = format_string_rfc2253(&s);
        assert!(out.contains("\\,"));
    }

    #[test]
    fn test_format_string_rfc2253_escapes_backslash() {
        let mut s = Asn1String::new(Asn1Tag::PrintableString);
        s.set(b"A\\B").unwrap();
        let out = format_string_rfc2253(&s);
        assert!(out.contains("\\\\"));
    }

    // ------------------------------------------------------------------
    // read_der_from_reader / write_der_to_writer
    // ------------------------------------------------------------------

    #[test]
    fn test_read_der_short_definite_length() {
        let input = [0x02u8, 0x01, 0x05];
        let mut r = Cursor::new(input.to_vec());
        let data = read_der_from_reader(&mut r, 0).unwrap();
        assert_eq!(data, input);
    }

    #[test]
    fn test_read_der_truncated_body_rejected() {
        // Claims 5 bytes of content but only provides 2
        let input = [0x02u8, 0x05, 0x01, 0x02];
        let mut r = Cursor::new(input.to_vec());
        let err = read_der_from_reader(&mut r, 0).unwrap_err();
        let _ = err;
    }

    #[test]
    fn test_read_der_rejects_over_cap() {
        // SEQUENCE with length 0x0400 (1024 bytes) but max_size = 100
        let input = [0x30u8, 0x82, 0x04, 0x00];
        let mut r = Cursor::new(input.to_vec());
        let err = read_der_from_reader(&mut r, 100).unwrap_err();
        assert!(
            format!("{err}").to_lowercase().contains("cap")
                || format!("{err}").to_lowercase().contains("exceed")
                || format!("{err}").to_lowercase().contains("length")
        );
    }

    #[test]
    fn test_read_der_indefinite_length() {
        // SEQUENCE indefinite, INTEGER 5, EOC
        let input = [0x30u8, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00];
        let mut r = Cursor::new(input.to_vec());
        let data = read_der_from_reader(&mut r, 0).unwrap();
        assert_eq!(data, input);
    }

    #[test]
    fn test_write_der_to_writer_then_read_roundtrip() {
        let input = vec![0x30u8, 0x03, 0x02, 0x01, 0x42];
        let mut buf = Vec::new();
        write_der_to_writer(&input, &mut buf).unwrap();
        assert_eq!(buf, input);

        let mut r = Cursor::new(buf);
        let read_back = read_der_from_reader(&mut r, 0).unwrap();
        assert_eq!(read_back, input);
    }

    // ------------------------------------------------------------------
    // smime_read / smime_write
    // ------------------------------------------------------------------

    #[test]
    fn test_smime_read_valid() {
        let input = b"Content-Type: application/pkcs7-mime\r\nSubject: Test\r\n\r\nbody bytes";
        let cur = Cursor::new(input.to_vec());
        let sd = smime_read(cur).unwrap();
        assert_eq!(sd.content_type, "application/pkcs7-mime");
        assert_eq!(sd.content, b"body bytes");
        assert!(sd
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Subject")));
    }

    #[test]
    fn test_smime_read_header_folding() {
        let input = b"X-Long: start\r\n next\r\n\r\nbody";
        let cur = Cursor::new(input.to_vec());
        let sd = smime_read(cur).unwrap();
        let folded = sd
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("X-Long"))
            .map(|(_, v)| v.clone())
            .expect("folded header missing");
        assert!(folded.contains("start"));
        assert!(folded.contains("next"));
    }

    #[test]
    fn test_smime_read_malformed_header_rejected() {
        let input = b"NoColonHere\r\n\r\nbody";
        let cur = Cursor::new(input.to_vec());
        let err = smime_read(cur).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("header"));
    }

    #[test]
    fn test_smime_write_produces_parseable_output() {
        let sd = SmimeData::new(
            b"body bytes".to_vec(),
            "application/pkcs7-mime".to_string(),
            vec![("Subject".to_string(), "Test".to_string())],
        );
        let mut buf: Vec<u8> = Vec::new();
        smime_write(&sd, &mut buf).unwrap();
        let cur = Cursor::new(buf);
        let parsed = smime_read(cur).unwrap();
        assert_eq!(parsed.content_type, "application/pkcs7-mime");
        assert_eq!(parsed.content, b"body bytes");
    }

    // ------------------------------------------------------------------
    // parse_dump
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_dump_integer_leaf() {
        let input = [0x02u8, 0x01, 0x05];
        let out = parse_dump(&input, 2).unwrap();
        // Top-level TLV line
        assert!(out.contains("INTEGER"));
        assert!(out.contains("prim"));
        // Primitive bytes preview line uses uppercase hex
        assert!(out.contains("bytes: 05"));
    }

    #[test]
    fn test_parse_dump_sequence_with_nested_integer() {
        // SEQUENCE { INTEGER 5 }
        let input = [0x30u8, 0x03, 0x02, 0x01, 0x05];
        let out = parse_dump(&input, 2).unwrap();
        assert!(out.contains("SEQUENCE"));
        assert!(out.contains("cons"));
        assert!(out.contains("INTEGER"));
        assert!(out.contains("bytes: 05"));
    }

    #[test]
    fn test_parse_dump_octet_string_preview_uppercase_hex() {
        let input = [0x04u8, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let out = parse_dump(&input, 2).unwrap();
        assert!(out.contains("OCTET STRING"));
        assert!(out.contains("bytes: DEADBEEF"));
    }

    #[test]
    fn test_parse_dump_large_octet_string_has_ellipsis() {
        let mut input = vec![0x04u8, 0x40]; // 64 byte content
        input.extend(std::iter::repeat(0xAAu8).take(64));
        let out = parse_dump(&input, 2).unwrap();
        assert!(out.contains("OCTET STRING"));
        assert!(out.contains("…"));
    }

    // ------------------------------------------------------------------
    // generate_from_config
    // ------------------------------------------------------------------

    #[test]
    fn test_generate_from_config_null_is_full_tlv() {
        let out = generate_from_config("NULL").unwrap();
        assert_eq!(out, vec![0x05, 0x00]);
    }

    #[test]
    fn test_generate_from_config_bool_true_is_full_tlv() {
        let out = generate_from_config("BOOL:TRUE").unwrap();
        assert_eq!(out, vec![0x01, 0x01, 0xFF]);
    }

    #[test]
    fn test_generate_from_config_bool_false_is_full_tlv() {
        let out = generate_from_config("BOOL:FALSE").unwrap();
        assert_eq!(out, vec![0x01, 0x01, 0x00]);
    }

    #[test]
    fn test_generate_from_config_bool_invalid_rejected() {
        let err = generate_from_config("BOOL:maybe").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("boolean"));
    }

    #[test]
    fn test_generate_from_config_integer_is_content_only() {
        // INTEGER branch calls encode_der() -> content-only
        let out = generate_from_config("INTEGER:5").unwrap();
        assert_eq!(out, vec![0x05]);
    }

    #[test]
    fn test_generate_from_config_integer_negative() {
        let out = generate_from_config("INTEGER:-1").unwrap();
        assert_eq!(out, vec![0xFF]);
    }

    #[test]
    fn test_generate_from_config_integer_hex() {
        let out = generate_from_config("INTEGER:0x10").unwrap();
        assert_eq!(out, vec![0x10]);
    }

    #[test]
    fn test_generate_from_config_octet_string_is_full_tlv() {
        let out = generate_from_config("OCTETSTRING:hello").unwrap();
        // tag=0x04, len=5, bytes = hello
        assert_eq!(out, vec![0x04, 0x05, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_generate_from_config_octet_string_hex_format() {
        let out = generate_from_config("FORMAT:HEX,OCT:deadbeef").unwrap();
        assert_eq!(out, vec![0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_generate_from_config_utf8_is_full_tlv() {
        let out = generate_from_config("UTF8:hi").unwrap();
        assert_eq!(out, vec![0x0C, 0x02, b'h', b'i']);
    }

    #[test]
    fn test_generate_from_config_empty_rejected() {
        let err = generate_from_config("").unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("empty"));
    }

    #[test]
    fn test_generate_from_config_unsupported_type_rejected() {
        let err = generate_from_config("NOSUCHTYPE:value").unwrap_err();
        assert!(
            format!("{err}").to_lowercase().contains("not supported")
                || format!("{err}").to_lowercase().contains("unsupported")
        );
    }

    // ------------------------------------------------------------------
    // sign_item / verify_item (with a mock signer)
    // ------------------------------------------------------------------

    struct MockSigner {
        oid: String,
        outputs: Vec<u8>,
    }

    impl SignDigest for MockSigner {
        fn algorithm_identifier(&self) -> CryptoResult<AlgorithmIdentifier> {
            let oid = Asn1Object::from_oid_string(&self.oid)?;
            Ok(AlgorithmIdentifier::new(oid, None))
        }

        fn sign(&self, _data: &[u8]) -> CryptoResult<Vec<u8>> {
            Ok(self.outputs.clone())
        }

        fn verify(&self, _data: &[u8], signature: &[u8]) -> CryptoResult<bool> {
            Ok(signature == self.outputs.as_slice())
        }
    }

    #[test]
    fn test_sign_item_sets_algorithm_and_returns_bit_string() {
        let signer = MockSigner {
            oid: "1.2.840.113549.1.1.11".to_string(),
            outputs: vec![0xAB, 0xCD, 0xEF],
        };
        let placeholder = Asn1Object::from_oid_string("1.2").unwrap();
        let mut alg = AlgorithmIdentifier::new(placeholder, None);
        let sig = sign_item(b"data", &mut alg, &signer).unwrap();
        assert_eq!(
            alg.algorithm.to_oid_string().unwrap(),
            "1.2.840.113549.1.1.11"
        );
        assert_eq!(sig.data(), &[0xAB, 0xCD, 0xEF]);
        assert_eq!(sig.unused_bits(), 0);
    }

    #[test]
    fn test_verify_item_accepts_correct_signature() {
        let signer = MockSigner {
            oid: "1.2.840.113549.1.1.11".to_string(),
            outputs: vec![0xAB, 0xCD, 0xEF],
        };
        let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.11").unwrap();
        let alg = AlgorithmIdentifier::new(oid, None);
        let mut sig = Asn1BitString::new();
        sig.set_data(&[0xAB, 0xCD, 0xEF], 0).unwrap();
        assert!(verify_item(b"data", &alg, &sig, &signer).unwrap());
    }

    #[test]
    fn test_verify_item_rejects_nonzero_unused_bits() {
        let signer = MockSigner {
            oid: "1.2.840.113549.1.1.11".to_string(),
            outputs: vec![0xF8],
        };
        let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.11").unwrap();
        let alg = AlgorithmIdentifier::new(oid, None);
        let mut sig = Asn1BitString::new();
        sig.set_data(&[0xF8], 3).unwrap();
        let err = verify_item(b"data", &alg, &sig, &signer).unwrap_err();
        let _ = err;
    }

    // ------------------------------------------------------------------
    // Asn1Error → CryptoError conversion
    // ------------------------------------------------------------------

    #[test]
    fn test_asn1_error_converts_to_crypto_error() {
        let err = Asn1Error::InvalidLength;
        let _: CryptoError = err.into();
    }

    #[test]
    fn test_asn1_error_display_formats() {
        let e = Asn1Error::InvalidTag(0xFF);
        assert!(format!("{e}").contains("tag"));

        let e = Asn1Error::TruncatedData {
            expected: 10,
            actual: 3,
        };
        let s = format!("{e}");
        assert!(s.contains("10"));
        assert!(s.contains("3"));

        let e = Asn1Error::InvalidOid("bad".to_string());
        assert!(format!("{e}").contains("bad"));

        let e = Asn1Error::NestingDepthExceeded(128);
        assert!(format!("{e}").contains("128"));
    }

    // ------------------------------------------------------------------
    // TimeDiff (smoke test public fields)
    // ------------------------------------------------------------------

    #[test]
    fn test_time_diff_public_fields() {
        // Asn1Time::diff follows OpenSSL's `ASN1_TIME_diff(from, to)` convention:
        // `b.diff(&a)` computes `a - b` (i.e., a is later, so the positive diff
        // is "from b to a").
        let a = Asn1Time::new(2024, 1, 2, 0, 0, 10).unwrap();
        let b = Asn1Time::new(2024, 1, 1, 0, 0, 0).unwrap();
        let d = b.diff(&a).unwrap();
        assert_eq!(d.days, 1);
        assert_eq!(d.seconds, 10);
    }
}
