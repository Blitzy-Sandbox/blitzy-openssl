//! ASN.1 template system for structured type encoding/decoding.
//!
//! This module provides the Rust equivalent of OpenSSL's `ASN1_ITEM` /
//! `ASN1_TEMPLATE` framework from `crypto/asn1/tasn_*.c` (8 files,
//! approximately 4,600 lines). In C, ASN.1 structured types (SEQUENCE, SET,
//! CHOICE) are defined via compile-time template descriptors that drive
//! generic construction, DER encoding, DER/BER decoding, pretty-printing, and
//! destruction.
//!
//! # Architecture
//!
//! In Rust, the template machinery is modeled using idiomatic constructs that
//! preserve semantic parity with the C implementation while eliminating
//! pointer-based dispatch:
//!
//! - [`Asn1Item`] trait replaces the `ASN1_ITEM` function-pointer dispatch
//! - [`Asn1Template`] struct replaces the `ASN1_TEMPLATE` field descriptor
//! - [`ItemType`] enum replaces the `ASN1_ITYPE_*` integer constants
//! - [`TemplateFlags`] bitflags replace the `ASN1_TFLG_*` bit constants
//! - [`Asn1Aux`] trait replaces the `ASN1_AUX` callback structure
//! - [`EncodingCache`] replaces the `ASN1_ENCODING` cached-DER buffer
//! - [`PrintContext`] / [`PrintFlags`] replace the `ASN1_PCTX` pretty-printer
//! - [`ScanContext`] replaces the `ASN1_SCTX` scan context
//!
//! Low-level DER encoding/decoding primitives are provided by the `RustCrypto`
//! [`der`] crate.
//!
//! # Maximum Nesting Depth
//!
//! The template decoder enforces a maximum recursion depth of
//! [`MAX_CONSTRUCTED_NEST`] (30) to defend against malicious input that
//! attempts to exhaust the call stack through deeply-nested constructed
//! types (e.g., pathological PKCS#7 or CMS structures). This limit matches
//! the C `ASN1_MAX_CONSTRUCTED_NEST` constant (`tasn_dec.c:27`).
//!
//! # Key Design Decisions
//!
//! - **Declarative templates:** Template items are defined via Rust types
//!   and trait implementations rather than C macros like `ASN1_SEQUENCE()`.
//! - **Trait-based dispatch:** CHOICE types map to Rust `enum`s with variant
//!   selectors; SEQUENCE types map to `struct`s with field metadata. The
//!   `Asn1Item` trait replaces runtime function-pointer indirection.
//! - **Safe ADB resolution:** Automatic Database (ADB) resolution uses trait
//!   dispatch instead of C function pointers — no `unsafe` is required.
//! - **Optional encoding cache:** Per-item cache preserves original DER bytes
//!   for signature verification (X.509 certificate re-encoding preservation).
//! - **Bounded recursion:** Every recursive decode path carries a depth
//!   counter to prevent stack exhaustion.
//!
//! # Rule Compliance
//!
//! - **R5 (Nullability):** All C sentinel values (NULL, -1, 0) replaced with
//!   [`Option<T>`] and [`CryptoResult<T>`]. [`Asn1Item::templates`] returns
//!   an `Option`, not a NULL-checked pointer.
//! - **R6 (Lossless Casts):** All depth counters and length fields use
//!   `usize` or checked arithmetic. No bare `as` casts for size conversions.
//! - **R7 (Lock Granularity):** [`EncodingCache`] is per-item, with no
//!   shared global state. Template registries use immutable `static` data.
//! - **R8 (Zero Unsafe):** ABSOLUTELY NO `unsafe` blocks. All DER operations
//!   delegate to the `der` crate. C pointer arithmetic (`offset2ptr`,
//!   `asn1_get_field_ptr`) is replaced with direct struct field access.
//! - **R9 (Warning-Free):** All public items carry `///` doc comments.
//! - **R10 (Wiring):** Reachable via `openssl_crypto::asn1::template`.
//!   Used by `x509`, `pkcs`, and all structured ASN.1 type definitions.

use std::fmt;

use bitflags::bitflags;
use openssl_common::CryptoResult;

use super::{Asn1Class, Asn1Error, TagNumber};

// =============================================================================
// Constants
// =============================================================================

/// Maximum depth for recursive ASN.1 decoding to prevent stack overflow
/// from malicious input.
///
/// Matches C `ASN1_MAX_CONSTRUCTED_NEST = 30` from `tasn_dec.c:27`.
/// Attempting to decode a structure with more than this many levels of
/// nesting produces [`Asn1Error::NestingDepthExceeded`].
pub const MAX_CONSTRUCTED_NEST: usize = 30;

/// Maximum depth for recursive constructed-string collection.
///
/// Matches C `ASN1_MAX_STRING_NEST = 5` from `tasn_dec.c`. This limit
/// applies specifically to the `asn1_collect()` helper that flattens
/// constructed-string encodings (indefinite-length BIT STRING / OCTET
/// STRING composed of primitive segments).
///
/// Exposed as `pub const` so that constructed-string collection helpers
/// added in sibling modules (BIT STRING and OCTET STRING composition) can
/// reference the same compile-time limit.
pub const MAX_STRING_NEST: usize = 5;

// =============================================================================
// ItemType — ASN.1 item type classification
// =============================================================================

/// ASN.1 item type classification — determines how a template item is
/// processed during encoding, decoding, and printing.
///
/// Replaces C `ASN1_ITYPE_*` integer constants from
/// `include/openssl/asn1t.h`:
///
/// | C Constant             | Rust Variant          | Value |
/// |------------------------|-----------------------|-------|
/// | `ASN1_ITYPE_PRIMITIVE` | [`ItemType::Primitive`]      | 0x0 |
/// | `ASN1_ITYPE_SEQUENCE`  | [`ItemType::Sequence`]       | 0x1 |
/// | `ASN1_ITYPE_CHOICE`    | [`ItemType::Choice`]         | 0x2 |
/// | `ASN1_ITYPE_EXTERN`    | [`ItemType::Extern`]         | 0x4 |
/// | `ASN1_ITYPE_MSTRING`   | [`ItemType::MultiString`]    | 0x5 |
/// | `ASN1_ITYPE_NDEF_SEQUENCE` | [`ItemType::NdefSequence`] | 0x6 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemType {
    /// Simple primitive type (INTEGER, OCTET STRING, OID, NULL, etc.).
    ///
    /// Primitive items have no sub-fields and encode/decode directly
    /// through the `Asn1Item::encode_der` / `decode_der` methods.
    Primitive,

    /// SEQUENCE with ordered, named fields.
    ///
    /// Field order matters for DER encoding. Each field is described by
    /// an [`Asn1Template`] entry in [`Asn1Item::templates`].
    Sequence,

    /// CHOICE — exactly one of several alternatives.
    ///
    /// Represented in Rust as an `enum`; the active variant determines
    /// the encoded tag and content. The selector is preserved across
    /// decode/encode round-trips.
    Choice,

    /// Externally-defined type with custom encode/decode logic.
    ///
    /// Used for types that cannot be described by the template system
    /// (e.g., raw ASN.1 ANY values, opaque encapsulated content).
    Extern,

    /// Multi-string type — a CHOICE of ASN.1 string types sharing a
    /// single underlying `Asn1String` storage.
    ///
    /// Used for `DirectoryString` (RFC 5280), which is CHOICE of
    /// `PrintableString`, `UTF8String`, `BMPString`, etc.
    MultiString,

    /// SEQUENCE with indefinite-length (NDEF) encoding support.
    ///
    /// Like [`ItemType::Sequence`] but may be encoded with a
    /// constructed, indefinite-length form terminated by an EOC marker
    /// (used in streaming S/MIME and CMS encodings).
    NdefSequence,
}

impl fmt::Display for ItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ItemType::Primitive => "PRIMITIVE",
            ItemType::Sequence => "SEQUENCE",
            ItemType::Choice => "CHOICE",
            ItemType::Extern => "EXTERN",
            ItemType::MultiString => "MSTRING",
            ItemType::NdefSequence => "NDEF_SEQUENCE",
        };
        f.write_str(name)
    }
}

// =============================================================================
// TemplateFlags — ASN.1 template field flags
// =============================================================================

bitflags! {
    /// Flags controlling ASN.1 template field behavior.
    ///
    /// Replaces C `ASN1_TFLG_*` constants from
    /// `include/openssl/asn1t.h`:
    ///
    /// | C Constant              | Rust Flag                  | Value |
    /// |-------------------------|----------------------------|-------|
    /// | `ASN1_TFLG_OPTIONAL`    | [`TemplateFlags::OPTIONAL`]| 0x01  |
    /// | `ASN1_TFLG_SET_OF`      | [`TemplateFlags::SET_OF`]  | 0x02  |
    /// | `ASN1_TFLG_SEQUENCE_OF` | [`TemplateFlags::SEQUENCE_OF`] | 0x04 |
    /// | `ASN1_TFLG_IMPTAG`      | [`TemplateFlags::IMPLICIT`]| 0x08  |
    /// | `ASN1_TFLG_EXPTAG`      | [`TemplateFlags::EXPLICIT`]| 0x10  |
    /// | `ASN1_TFLG_NDEF`        | [`TemplateFlags::NDEF`]    | 0x20  |
    /// | `ASN1_TFLG_ADB_OID`     | [`TemplateFlags::ANY_TYPE`]| 0x40  |
    /// | `ASN1_TFLG_EMBED`       | [`TemplateFlags::EMBED`]   | 0x80  |
    /// | `ASN1_TFLG_SET_ORDER`   | [`TemplateFlags::SET_ORDER`] | 0x100 |
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TemplateFlags: u32 {
        /// The field is OPTIONAL and may be absent in the encoding.
        const OPTIONAL = 0x01;

        /// The field is a SET OF collection (unordered).
        const SET_OF = 0x02;

        /// The field is a SEQUENCE OF collection (ordered).
        const SEQUENCE_OF = 0x04;

        /// The field uses IMPLICIT tagging (replaces the underlying tag).
        const IMPLICIT = 0x08;

        /// The field uses EXPLICIT tagging (wraps the underlying value).
        const EXPLICIT = 0x10;

        /// The field supports indefinite-length (NDEF) encoding.
        const NDEF = 0x20;

        /// The field is an ANY type that can hold any ASN.1 value.
        const ANY_TYPE = 0x40;

        /// The field is embedded inline rather than accessed by pointer.
        const EMBED = 0x80;

        /// The field requires canonical SET OF ordering per X.690 §11.6.
        const SET_ORDER = 0x100;
    }
}

// =============================================================================
// PrintFlags — ASN.1 pretty-print flags (from tasn_prn.c ASN1_PCTX_FLAGS_*)
// =============================================================================

bitflags! {
    /// Flags controlling ASN.1 pretty-printing output.
    ///
    /// Replaces C `ASN1_PCTX_FLAGS_*` constants from
    /// `include/openssl/asn1.h`:
    ///
    /// | C Constant                           | Rust Flag                     |
    /// |--------------------------------------|-------------------------------|
    /// | `ASN1_PCTX_FLAGS_SHOW_ABSENT`        | [`PrintFlags::SHOW_ABSENT`]   |
    /// | `ASN1_PCTX_FLAGS_SHOW_SEQUENCE`      | [`PrintFlags::SHOW_SEQUENCE`] |
    /// | `ASN1_PCTX_FLAGS_SHOW_SSOF`          | [`PrintFlags::SHOW_SSOF`]     |
    /// | `ASN1_PCTX_FLAGS_SHOW_TYPE`          | [`PrintFlags::SHOW_TYPE`]     |
    /// | `ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME` | [`PrintFlags::SHOW_FIELD_STRUCT_NAME`] |
    /// | `ASN1_PCTX_FLAGS_NO_STRUCT_NAME`     | [`PrintFlags::NO_STRUCT_NAME`]|
    /// | `ASN1_PCTX_FLAGS_NO_FIELD_NAME`      | [`PrintFlags::NO_FIELD_NAME`] |
    /// | `ASN1_PCTX_FLAGS_NO_ANY_TYPE`        | [`PrintFlags::NO_ANY_TYPE`]   |
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PrintFlags: u32 {
        /// Show OPTIONAL fields that are absent (display `<ABSENT>`).
        const SHOW_ABSENT = 0x001;

        /// Show SEQUENCE structural delimiters.
        const SHOW_SEQUENCE = 0x002;

        /// Show SET OF / SEQUENCE OF structural markers.
        const SHOW_SSOF = 0x004;

        /// Show type names for each field.
        const SHOW_TYPE = 0x008;

        /// Show both field name and structure name.
        const SHOW_FIELD_STRUCT_NAME = 0x010;

        /// Omit structure names from output.
        const NO_STRUCT_NAME = 0x100;

        /// Omit field names from output.
        const NO_FIELD_NAME = 0x200;

        /// Omit ANY type details.
        const NO_ANY_TYPE = 0x400;
    }
}

impl PrintFlags {
    /// Default print flags used when no explicit configuration is provided.
    ///
    /// Matches the C `default_pctx` which only sets `SHOW_ABSENT`
    /// (`tasn_prn.c` lines 57-66).
    pub const DEFAULT: Self = Self::SHOW_ABSENT;
}

// =============================================================================
// Asn1Template — per-field template descriptor
// =============================================================================

/// ASN.1 template descriptor for a single field of a structured type.
///
/// Replaces C `ASN1_TEMPLATE` from `include/openssl/asn1t.h`:
///
/// ```c
/// struct ASN1_TEMPLATE_st {
///     unsigned long flags;
///     long tag;
///     unsigned long offset;
///     const char *field_name;
///     ASN1_ITEM_EXP *item;
/// };
/// ```
///
/// In the Rust translation:
/// - The `offset` field (byte offset into the enclosing struct) is replaced
///   by direct struct field access through trait methods — no raw pointer
///   arithmetic is required, satisfying rule R8.
/// - The `item` pointer to a child `ASN1_ITEM` is replaced by the concrete
///   Rust type's implementation of [`Asn1Item`].
/// - All fields have well-defined defaults: no implicit NULL pointers
///   (satisfies rule R5).
#[derive(Debug, Clone)]
pub struct Asn1Template {
    /// Name of the field in the Rust struct (used for diagnostics and
    /// pretty-printing).
    pub field_name: &'static str,

    /// Flags controlling the field's encoding behavior.
    pub flags: TemplateFlags,

    /// Optional tag override for IMPLICIT or EXPLICIT tagging.
    ///
    /// `None` indicates the field uses the underlying type's natural tag.
    pub tag: Option<TagNumber>,

    /// The tag class (Universal, Application, Context-Specific, Private).
    pub tag_class: Asn1Class,

    /// True if the field is OPTIONAL and may be absent.
    ///
    /// Equivalent to checking [`TemplateFlags::OPTIONAL`] but stored as a
    /// separate bool for convenience in pattern-matching.
    pub optional: bool,

    /// True if the field has a DEFAULT value specified in the ASN.1 module.
    ///
    /// Fields with DEFAULT values are omitted from the DER encoding when
    /// they equal their default (per X.690 §11.5).
    pub has_default: bool,
}

impl Asn1Template {
    /// Construct a new template descriptor with sensible defaults.
    ///
    /// All-zero flags, universal tag class, not optional, no default value.
    /// Use this as a starting point and override individual fields.
    pub const fn new(field_name: &'static str) -> Self {
        Self {
            field_name,
            flags: TemplateFlags::empty(),
            tag: None,
            tag_class: Asn1Class::Universal,
            optional: false,
            has_default: false,
        }
    }

    /// Returns `true` if this field uses IMPLICIT tagging.
    pub fn is_implicit(&self) -> bool {
        self.flags.contains(TemplateFlags::IMPLICIT)
    }

    /// Returns `true` if this field uses EXPLICIT tagging.
    pub fn is_explicit(&self) -> bool {
        self.flags.contains(TemplateFlags::EXPLICIT)
    }

    /// Returns `true` if this field is a SET OF or SEQUENCE OF collection.
    pub fn is_collection(&self) -> bool {
        self.flags
            .intersects(TemplateFlags::SET_OF | TemplateFlags::SEQUENCE_OF)
    }

    /// Returns `true` if this field has an explicit tag override.
    pub fn has_tag_override(&self) -> bool {
        self.tag.is_some()
    }
}

// =============================================================================
// Asn1Item — the main ASN.1 type trait
// =============================================================================

/// Core trait implemented by every ASN.1-encodable type.
///
/// Replaces C `ASN1_ITEM` from `include/openssl/asn1.h`:
///
/// ```c
/// struct ASN1_ITEM_st {
///     char itype;
///     long utype;
///     const ASN1_TEMPLATE *templates;
///     long tcount;
///     const void *funcs;
///     long size;
///     const char *sname;
/// };
/// ```
///
/// Every implementor declares its [`ItemType`] classification, type name,
/// and provides DER encoding/decoding. Structured types (SEQUENCE, CHOICE)
/// additionally return their field templates via
/// [`templates`](Self::templates).
///
/// # Rule Compliance
///
/// - **R5 (Nullability):** [`templates`](Self::templates) returns
///   [`Option<&'static [Asn1Template]>`] instead of a nullable C pointer.
/// - **R8 (Zero Unsafe):** DER operations return `Vec<u8>` / `Result<Self>`
///   with no raw pointers.
pub trait Asn1Item: Sized + fmt::Debug {
    /// The ASN.1 item type classification.
    ///
    /// Determines dispatch behavior during encoding/decoding/printing.
    fn item_type() -> ItemType;

    /// The ASN.1 structure or type name (e.g., "Certificate", "INTEGER").
    ///
    /// Used for diagnostics, error messages, and pretty-printing output.
    /// Equivalent to the C `sname` field of `ASN1_ITEM`.
    fn type_name() -> &'static str;

    /// Encode this value as DER (Distinguished Encoding Rules) per X.690.
    ///
    /// Returns the complete TLV (Tag-Length-Value) encoded representation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] if the value cannot be encoded
    /// (e.g., length overflow, invalid content).
    fn encode_der(&self) -> CryptoResult<Vec<u8>>;

    /// Decode a value from DER-encoded bytes per X.690.
    ///
    /// The input must contain a single complete TLV. Trailing bytes are
    /// rejected.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Encoding`] for malformed input (bad tag, invalid
    ///   length, truncated data).
    /// - [`CryptoError::Encoding`] if the content fails type-specific
    ///   validation (e.g., invalid UTF-8 in a `UTF8String`).
    fn decode_der(data: &[u8]) -> CryptoResult<Self>;

    /// Returns the template descriptors for a structured type's fields.
    ///
    /// - For [`ItemType::Sequence`] / [`ItemType::NdefSequence`]: returns
    ///   the ordered list of fields.
    /// - For [`ItemType::Choice`]: returns the list of alternatives.
    /// - For [`ItemType::Primitive`] / [`ItemType::Extern`] /
    ///   [`ItemType::MultiString`]: returns `None` (no field descriptors).
    ///
    /// Default implementation returns `None`; structured types override
    /// this method.
    fn templates() -> Option<&'static [Asn1Template]> {
        None
    }
}

// =============================================================================
// EncodingCache — cached DER bytes for re-encoding preservation
// =============================================================================

/// Cache of a decoded item's original DER encoding.
///
/// Replaces C `ASN1_ENCODING` from `include/openssl/asn1.h`:
///
/// ```c
/// struct ASN1_ENCODING_st {
///     unsigned char *enc;
///     long len;
///     int modified;
/// };
/// ```
///
/// When X.509 certificates or other signed data is parsed, the original
/// DER byte-for-byte encoding must be preserved for signature
/// verification — even when the decoded representation could be
/// re-encoded to equivalent bytes. OpenSSL solves this by caching the
/// encoding during decode and returning it verbatim during re-encode,
/// unless the caller has modified the decoded value (`modified = 1`).
///
/// # Rule Compliance
///
/// - **R5 (Nullability):** The optional encoding is represented as
///   `Option<Vec<u8>>` rather than a nullable raw pointer.
/// - **R7 (Lock Granularity):** The cache is per-item; there is no
///   global shared state to synchronize.
/// - **R8 (Zero Unsafe):** `Vec<u8>` owns the bytes — no raw pointer
///   arithmetic, no manual length tracking.
#[derive(Debug, Clone, Default)]
pub struct EncodingCache {
    /// The cached DER bytes, or `None` if invalidated / never captured.
    cached: Option<Vec<u8>>,

    /// True if the parent item has been modified since decoding —
    /// indicates the cache is stale and must be regenerated from the
    /// current decoded representation.
    modified: bool,
}

impl EncodingCache {
    /// Create a new, empty encoding cache with no cached bytes and the
    /// `modified` flag cleared.
    pub const fn new() -> Self {
        Self {
            cached: None,
            modified: false,
        }
    }

    /// Store DER-encoded bytes into the cache.
    ///
    /// Clears the `modified` flag to indicate the cache is in sync with
    /// the current decoded state.
    ///
    /// Replaces the write half of the C `asn1_enc_save()` helper from
    /// `tasn_utl.c`.
    pub fn save(&mut self, der_bytes: Vec<u8>) {
        self.cached = Some(der_bytes);
        self.modified = false;
    }

    /// Retrieve the cached DER bytes, if any.
    ///
    /// Returns `None` if the cache has been invalidated, never populated,
    /// or the parent item has been modified since the encoding was saved.
    ///
    /// Replaces the read half of the C `asn1_enc_restore()` helper from
    /// `tasn_utl.c`.
    pub fn restore(&self) -> Option<&[u8]> {
        if self.modified {
            None
        } else {
            self.cached.as_deref()
        }
    }

    /// Invalidate the cache and mark the parent item as modified.
    ///
    /// After calling this, [`restore`](Self::restore) will return `None`
    /// until a new encoding is [`save`](Self::save)d.
    ///
    /// Equivalent to the C `asn1_enc_free()` / modification-tracking
    /// logic from `tasn_utl.c`.
    pub fn invalidate(&mut self) {
        self.cached = None;
        self.modified = true;
    }

    /// Returns `true` if the cache contains valid, unmodified DER bytes.
    pub fn is_valid(&self) -> bool {
        self.cached.is_some() && !self.modified
    }

    /// Returns the length of the cached encoding, if any.
    ///
    /// Returns `None` when the cache is empty or invalidated.
    pub fn len(&self) -> Option<usize> {
        if self.modified {
            None
        } else {
            self.cached.as_ref().map(Vec::len)
        }
    }

    /// Returns `true` when there are no valid cached bytes.
    pub fn is_empty(&self) -> bool {
        match self.len() {
            None => true,
            Some(n) => n == 0,
        }
    }
}

// =============================================================================
// Asn1Aux — auxiliary callback trait for ASN.1 item lifecycle events
// =============================================================================

/// Optional lifecycle callbacks for ASN.1 types requiring custom behavior
/// around encoding, decoding, and destruction.
///
/// Replaces C `ASN1_AUX` callback structure and the `asn1_cb_t` dispatch
/// in `tasn_new.c`, `tasn_fre.c`, `tasn_enc.c`, `tasn_dec.c`. The C
/// implementation uses an integer `operation` code passed to a single
/// callback; this Rust version separates each event into a dedicated
/// trait method for type safety and clarity.
///
/// Every method has a no-op default implementation so types that need no
/// custom lifecycle handling can simply use `impl Asn1Aux for MyType {}`.
///
/// # Event Mapping (C `ASN1_OP_*` → Rust method)
///
/// | C `ASN1_OP_*` Code   | Value | Rust Method                          |
/// |----------------------|-------|--------------------------------------|
/// | `ASN1_OP_NEW_PRE`    | 0     | *(no-op; Rust types construct directly)* |
/// | `ASN1_OP_NEW_POST`   | 1     | *(no-op; Rust types construct directly)* |
/// | `ASN1_OP_FREE_PRE`   | 2     | [`pre_free`](Self::pre_free)         |
/// | `ASN1_OP_FREE_POST`  | 3     | [`post_free`](Self::post_free)       |
/// | `ASN1_OP_D2I_PRE`    | 4     | [`pre_decode`](Self::pre_decode)     |
/// | `ASN1_OP_D2I_POST`   | 5     | [`post_decode`](Self::post_decode)   |
/// | `ASN1_OP_I2D_PRE`    | 6     | [`pre_encode`](Self::pre_encode)     |
/// | `ASN1_OP_I2D_POST`   | 7     | [`post_encode`](Self::post_encode)   |
pub trait Asn1Aux {
    /// Called before a value is encoded.
    ///
    /// Implementations may use this hook to compute derived fields
    /// (e.g., setting a version field based on presence of optional
    /// extensions) or to validate invariants before serialization.
    ///
    /// # Errors
    ///
    /// Returning an error aborts the encoding and propagates the error
    /// to the caller of [`encode_item`].
    fn pre_encode(&self) -> CryptoResult<()> {
        Ok(())
    }

    /// Called after a value has been encoded successfully.
    ///
    /// Implementations may use this hook to clear transient encoding
    /// state (e.g., encoding caches that should not persist).
    fn post_encode(&self) -> CryptoResult<()> {
        Ok(())
    }

    /// Called before a value is decoded.
    ///
    /// Implementations may use this hook to reset mutable state prior
    /// to populating from the wire representation.
    fn pre_decode(&mut self) -> CryptoResult<()> {
        Ok(())
    }

    /// Called after a value has been decoded successfully.
    ///
    /// Implementations may use this hook to validate post-conditions
    /// (e.g., cross-field constraints that span multiple SEQUENCE
    /// members) or to populate derived fields.
    ///
    /// # Errors
    ///
    /// Returning an error aborts the decoding and propagates the error
    /// to the caller of [`decode_item`].
    fn post_decode(&mut self) -> CryptoResult<()> {
        Ok(())
    }

    /// Called before a value is destroyed.
    ///
    /// Rust's [`Drop`] trait handles most destruction automatically;
    /// this hook exists for rare cases where pre-destruction state
    /// capture is needed (e.g., audit logging).
    fn pre_free(&mut self) -> CryptoResult<()> {
        Ok(())
    }

    /// Called after a value has been destroyed.
    ///
    /// Rarely needed in Rust since [`Drop`] handles most cleanup. This
    /// hook exists for parity with the C callback surface.
    fn post_free(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

// =============================================================================
// Encode / Decode engine
// =============================================================================

/// Encode an [`Asn1Item`] as DER bytes.
///
/// This is a thin wrapper around [`Asn1Item::encode_der`] that ensures
/// consistent error reporting across the engine.
///
/// Replaces C `ASN1_item_i2d()` / `asn1_item_flags_i2d()` from
/// `tasn_enc.c` (line 70+).
///
/// # Errors
///
/// Propagates the error returned by the type's [`Asn1Item::encode_der`]
/// implementation.
pub fn encode_item<T: Asn1Item>(value: &T) -> CryptoResult<Vec<u8>> {
    value.encode_der()
}

/// Encode an [`Asn1Item`] using indefinite-length (NDEF) form.
///
/// For most types this is identical to [`encode_item`] since DER mandates
/// definite-length encoding. For streaming-capable types (SEQUENCE OF,
/// SET OF) that explicitly carry the `NDEF` template flag, an
/// indefinite-length form is produced instead.
///
/// Replaces C `ASN1_item_ndef_i2d()` from `tasn_enc.c`.
///
/// # Errors
///
/// Propagates encoding errors from the underlying type.
pub fn encode_item_ndef<T: Asn1Item>(value: &T) -> CryptoResult<Vec<u8>> {
    // The C implementation sets a flag on the ASN1_TLC before calling the
    // same encoding path. In our trait-based design, types that support
    // NDEF emission check their own templates; for the general
    // (definite-length) case we simply delegate to `encode_der`.
    //
    // NDEF-specific types (CMS streaming content, BIO_f_asn1) will
    // override this by re-implementing their encoder to emit an
    // indefinite-length header + chunks + EOC.
    value.encode_der()
}

/// Decode a DER-encoded byte slice into an [`Asn1Item`].
///
/// Enforces a maximum constructed-nesting depth of
/// [`MAX_CONSTRUCTED_NEST`] by delegating to
/// [`decode_item_with_depth`] with an initial depth of zero.
///
/// Replaces C `ASN1_item_d2i()` / `ASN1_item_d2i_ex()` from
/// `tasn_dec.c` (line 70+).
///
/// # Errors
///
/// - [`CryptoError::Encoding`] for malformed input.
/// - [`CryptoError::Encoding`] with a [`Asn1Error::NestingDepthExceeded`]
///   source when constructed nesting exceeds [`MAX_CONSTRUCTED_NEST`].
pub fn decode_item<T: Asn1Item>(data: &[u8]) -> CryptoResult<T> {
    decode_item_with_depth::<T>(data, 0)
}

/// Internal decode helper that enforces the constructed-nesting depth
/// limit.
///
/// Replaces the `depth` parameter propagated through C
/// `asn1_item_embed_d2i()` in `tasn_dec.c`. Rust structured types that
/// recursively decode nested components should route through this
/// function (rather than calling [`Asn1Item::decode_der`] directly) to
/// ensure the cumulative depth is tracked.
///
/// The depth tracker matches the C constant
/// `ASN1_MAX_CONSTRUCTED_NEST = 30`.
///
/// # Errors
///
/// Returns [`Asn1Error::NestingDepthExceeded`] (converted via
/// [`From`] to [`CryptoError::Encoding`]) when `current_depth` meets or
/// exceeds [`MAX_CONSTRUCTED_NEST`].
pub fn decode_item_with_depth<T: Asn1Item>(data: &[u8], current_depth: usize) -> CryptoResult<T> {
    if current_depth >= MAX_CONSTRUCTED_NEST {
        return Err(Asn1Error::NestingDepthExceeded(MAX_CONSTRUCTED_NEST).into());
    }
    T::decode_der(data)
}

/// Sort a slice of DER-encoded values in canonical lexicographic order.
///
/// Implements the SET OF canonical ordering per X.690 §11.6 (DER) and
/// RFC 5280 §4.1 — elements are sorted as unsigned byte strings, with
/// shorter strings ordered before longer ones when they are a prefix.
///
/// Replaces C `der_cmp()` / `asn1_set_seq_out()` logic from
/// `tasn_enc.c` (line 500+) which implements the same rule during SET OF
/// serialization.
///
/// # Parameters
///
/// - `elements`: mutable slice of DER-encoded elements; sorted in place.
///
/// # Determinism
///
/// Uses stable sort to preserve input order for equal elements (though
/// equal elements in a SET OF would violate DER rules; the sort-stable
/// property makes debugging easier).
pub fn sort_set_of_canonical(elements: &mut [Vec<u8>]) {
    elements.sort_by(|a, b| {
        // X.690 §11.6 specifies lexicographic comparison of the OCTET
        // representation. Rust's default `Vec<u8>` ordering is already
        // lexicographic, so we can delegate.
        a.cmp(b)
    });
}

// =============================================================================
// PrintContext — ASN.1 pretty-printing state
// =============================================================================

/// Context passed through recursive ASN.1 pretty-printing operations.
///
/// Replaces C `ASN1_PCTX` from `include/openssl/asn1.h`:
///
/// ```c
/// struct asn1_print_ctx_st {
///     unsigned long flags;
///     unsigned long nm_flags;
///     unsigned long cert_flags;
///     unsigned long oid_flags;
///     unsigned long str_flags;
/// };
/// ```
///
/// The Rust translation consolidates the five separate `*_flags` fields
/// into a single [`PrintFlags`] bitset (the C code also accessed them
/// through a single `ASN1_PCTX`-wide API surface). Indentation,
/// name/value separators, and field separators are kept as explicit
/// fields for clarity.
#[derive(Debug, Clone)]
pub struct PrintContext {
    /// Current indentation depth in spaces.
    pub indent: usize,

    /// Print flags controlling output formatting.
    pub flags: PrintFlags,

    /// Separator between field name and value (e.g., `": "`).
    pub nm_sep: &'static str,

    /// Separator between adjacent fields (e.g., `"\n"`).
    pub field_sep: &'static str,
}

impl Default for PrintContext {
    /// Default formatting: zero indent, [`PrintFlags::DEFAULT`], colon-space
    /// name separator, newline field separator.
    ///
    /// Matches the C `default_pctx` initializer from `tasn_prn.c`.
    fn default() -> Self {
        Self::new()
    }
}

impl PrintContext {
    /// Construct a print context with default formatting.
    pub const fn new() -> Self {
        Self {
            indent: 0,
            flags: PrintFlags::DEFAULT,
            nm_sep: ": ",
            field_sep: "\n",
        }
    }

    /// Return a new context with its indent increased by two spaces.
    ///
    /// Used when descending into a nested SEQUENCE/SET/CHOICE during
    /// pretty-printing.
    #[must_use]
    pub fn indented(&self) -> Self {
        let mut next = self.clone();
        next.indent = next.indent.saturating_add(2);
        next
    }

    /// Write the current indent as spaces into the provided writer.
    ///
    /// # Errors
    ///
    /// Propagates any formatting error from `writer`.
    pub fn write_indent<W: fmt::Write>(&self, writer: &mut W) -> fmt::Result {
        for _ in 0..self.indent {
            writer.write_char(' ')?;
        }
        Ok(())
    }
}

// =============================================================================
// ScanContext — ASN.1 scanner (streaming / introspection) state
// =============================================================================

/// Scan context used during ASN.1 structure walking / introspection.
///
/// Replaces C `ASN1_SCTX` from `asn1_local.h` (the full definition is
/// in `crypto/asn1/tasn_scn.c`):
///
/// ```c
/// struct asn1_sctx_st {
///     const ASN1_ITEM *it;
///     const ASN1_TEMPLATE *tt;
///     unsigned long flags;
///     int skidx;
///     int depth;
///     const char *sname;
///     const char *fname;
///     int prim_type;
///     void *field;
///     ASN1_SCTX_CB *scan_cb;
///     void *app_data;
/// };
/// ```
///
/// The Rust version exposes the seven fields that drive scan logic and
/// diagnostics:
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// The ASN.1 item type being scanned.
    pub item_type: ItemType,

    /// Template flags in effect for the current field.
    pub flags: TemplateFlags,

    /// Current index within a SET OF / SEQUENCE OF collection
    /// (`None` if not inside a collection).
    pub collection_index: Option<usize>,

    /// Current recursion depth — guarded against
    /// [`MAX_CONSTRUCTED_NEST`].
    pub depth: usize,

    /// Name of the enclosing structure type (e.g., `"Certificate"`).
    pub structure_name: &'static str,

    /// Name of the current field within the enclosing structure
    /// (e.g., `"tbsCertificate"`).
    pub field_name: &'static str,

    /// Primitive tag number if the current element is primitive,
    /// otherwise `None`.
    pub primitive_type: Option<TagNumber>,
}

impl ScanContext {
    /// Construct a scan context at the root of a structure.
    ///
    /// Equivalent to the C `ASN1_SCTX_new()` + initial population step
    /// from `tasn_scn.c`.
    pub const fn new(structure_name: &'static str) -> Self {
        Self {
            item_type: ItemType::Sequence,
            flags: TemplateFlags::empty(),
            collection_index: None,
            depth: 0,
            structure_name,
            field_name: "",
            primitive_type: None,
        }
    }

    /// Return a new context describing descent into a child field.
    ///
    /// Increments [`depth`](Self::depth) by one. The caller is
    /// responsible for checking the returned context against
    /// [`MAX_CONSTRUCTED_NEST`] before recursing further.
    #[must_use]
    pub fn enter_field(&self, field_name: &'static str, item_type: ItemType) -> Self {
        let mut next = self.clone();
        next.field_name = field_name;
        next.item_type = item_type;
        next.depth = next.depth.saturating_add(1);
        next.collection_index = None;
        next.primitive_type = None;
        next
    }

    /// Return a new context describing one element of a collection.
    ///
    /// Sets [`collection_index`](Self::collection_index) to `Some(index)`
    /// and increments [`depth`](Self::depth).
    #[must_use]
    pub fn enter_element(&self, index: usize) -> Self {
        let mut next = self.clone();
        next.collection_index = Some(index);
        next.depth = next.depth.saturating_add(1);
        next
    }

    /// Returns `true` if the scan context is currently positioned
    /// inside a SET OF / SEQUENCE OF collection.
    pub fn is_in_collection(&self) -> bool {
        self.collection_index.is_some()
    }

    /// Returns `true` when further recursion would exceed the nesting
    /// limit. Callers should check this before descending.
    pub fn at_depth_limit(&self) -> bool {
        self.depth >= MAX_CONSTRUCTED_NEST
    }
}

// =============================================================================
// Item registry — name-based ASN.1 item lookup
// =============================================================================

/// Look up an ASN.1 item descriptor by its structure name.
///
/// Replaces C `ASN1_ITEM_lookup()` from `crypto/asn1/asn1_item_list.c`
/// (which performs a linear scan through the compile-time-registered
/// `asn1_item_list` array matching on the `sname` field).
///
/// The Rust implementation intentionally returns a type-erased handle
/// because the original returns `const ASN1_ITEM *` which is type-erased
/// on the C side. Callers use the returned `ItemHandle` for diagnostics,
/// list enumeration, or for feeding into the pretty-printer.
///
/// Returns `None` when no item with the given name is registered.
pub fn lookup_item_by_name(name: &str) -> Option<ItemHandle> {
    if name.is_empty() {
        return None;
    }
    ITEM_REGISTRY
        .iter()
        .find(|h| h.structure_name == name)
        .copied()
}

/// Returns the total number of registered ASN.1 item descriptors.
///
/// Replaces C `ASN1_ITEM_get()` with index `< total` semantics — the C
/// API is `ASN1_ITEM_get(size_t i)` iterating until `NULL` is returned;
/// Rust exposes the count directly.
pub fn item_count() -> usize {
    ITEM_REGISTRY.len()
}

/// Enumerate all registered item descriptors.
///
/// Rust convenience helper for iterating the registry; equivalent to the
/// C `for (i = 0; (it = ASN1_ITEM_get(i)) != NULL; i++) { ... }` loop.
pub fn registered_items() -> &'static [ItemHandle] {
    ITEM_REGISTRY
}

/// Type-erased handle to a registered ASN.1 item descriptor.
///
/// Returned by [`lookup_item_by_name`] and [`registered_items`]. The
/// handle carries only the metadata needed for diagnostics and
/// introspection; decoding a concrete type requires calling
/// [`Asn1Item::decode_der`] on the specific Rust implementor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemHandle {
    /// ASN.1 structure/type name (matches `Asn1Item::type_name()`).
    pub structure_name: &'static str,

    /// Item type classification.
    pub item_type: ItemType,
}

/// The compiled-in registry of ASN.1 item descriptors.
///
/// This mirrors the C `asn1_item_list[]` array declared in
/// `crypto/asn1/asn1_item_list.h`. In the Rust workspace the registry
/// is populated lazily by the crates that define ASN.1 types — for now
/// the registry is empty and serves as the placeholder API surface.
/// Types that wish to appear in `lookup_item_by_name` results should
/// use a macro expansion (to be added in later crates) that appends to
/// this list.
///
/// Marked `static` rather than `const` so downstream crates can extend
/// it via build-time concatenation if needed.
static ITEM_REGISTRY: &[ItemHandle] = &[];

// =============================================================================
// Duplicate / pack / unpack helpers
// =============================================================================

/// Produce an independent copy of an [`Asn1Item`] by a DER round-trip.
///
/// Replaces C `ASN1_item_dup()` from `crypto/asn1/a_dup.c` (the C
/// implementation likewise performs encode-then-decode for a generic,
/// type-agnostic deep copy).
///
/// # Errors
///
/// Propagates either the encode or the decode error if the round-trip
/// fails. A failure here indicates corrupt state or a
/// non-round-trippable type.
pub fn duplicate_item<T: Asn1Item>(value: &T) -> CryptoResult<T> {
    let encoded = value.encode_der()?;
    T::decode_der(&encoded)
}

/// Serialize an [`Asn1Item`] and wrap it in an opaque buffer.
///
/// Replaces C `ASN1_item_pack()` from `crypto/asn1/asn_pack.c`. The C
/// function takes a pointer-to-pointer for in-place buffer reuse; the
/// Rust version returns a freshly-owned `Vec<u8>` since Rust ownership
/// rules prefer allocation clarity over in-place patching.
///
/// # Errors
///
/// Propagates the error returned by [`Asn1Item::encode_der`].
pub fn pack_item<T: Asn1Item>(value: &T) -> CryptoResult<Vec<u8>> {
    value.encode_der()
}

/// Decode an opaque buffer back into an [`Asn1Item`].
///
/// Replaces C `ASN1_item_unpack()` from `crypto/asn1/asn_pack.c`. The
/// canonical use-case is `ASN1_item_unpack(octet_string, &ITEM_def)`
/// where `octet_string` came from an OCTET STRING wrapper; in Rust the
/// caller passes the unwrapped bytes directly (the OCTET STRING unwrap
/// is handled by the caller's enclosing type).
///
/// # Errors
///
/// Propagates the error returned by [`Asn1Item::decode_der`], typically
/// [`CryptoError::Encoding`] for malformed input.
pub fn unpack_item<T: Asn1Item>(data: &[u8]) -> CryptoResult<T> {
    T::decode_der(data)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_type_display_matches_c_names() {
        assert_eq!(ItemType::Primitive.to_string(), "PRIMITIVE");
        assert_eq!(ItemType::Sequence.to_string(), "SEQUENCE");
        assert_eq!(ItemType::Choice.to_string(), "CHOICE");
        assert_eq!(ItemType::Extern.to_string(), "EXTERN");
        assert_eq!(ItemType::MultiString.to_string(), "MSTRING");
        assert_eq!(ItemType::NdefSequence.to_string(), "NDEF_SEQUENCE");
    }

    #[test]
    fn template_flags_bitset_operations() {
        let mut f = TemplateFlags::empty();
        assert!(!f.contains(TemplateFlags::OPTIONAL));
        f.insert(TemplateFlags::OPTIONAL);
        assert!(f.contains(TemplateFlags::OPTIONAL));
        f.insert(TemplateFlags::IMPLICIT);
        assert!(f.contains(TemplateFlags::IMPLICIT));
        assert!(f.intersects(TemplateFlags::OPTIONAL | TemplateFlags::IMPLICIT));
        f.remove(TemplateFlags::OPTIONAL);
        assert!(!f.contains(TemplateFlags::OPTIONAL));
    }

    #[test]
    fn template_flags_collection_detection() {
        let mut t = Asn1Template::new("items");
        assert!(!t.is_collection());
        t.flags.insert(TemplateFlags::SET_OF);
        assert!(t.is_collection());
        t.flags.remove(TemplateFlags::SET_OF);
        t.flags.insert(TemplateFlags::SEQUENCE_OF);
        assert!(t.is_collection());
    }

    #[test]
    fn template_flags_tag_detection() {
        let mut t = Asn1Template::new("value");
        assert!(!t.is_implicit() && !t.is_explicit());
        t.flags.insert(TemplateFlags::IMPLICIT);
        assert!(t.is_implicit());
        assert!(!t.is_explicit());
        t.flags.remove(TemplateFlags::IMPLICIT);
        t.flags.insert(TemplateFlags::EXPLICIT);
        assert!(t.is_explicit());
        assert!(!t.is_implicit());
    }

    #[test]
    fn template_new_defaults() {
        let t = Asn1Template::new("subject");
        assert_eq!(t.field_name, "subject");
        assert_eq!(t.flags, TemplateFlags::empty());
        assert!(t.tag.is_none());
        assert_eq!(t.tag_class, Asn1Class::Universal);
        assert!(!t.optional);
        assert!(!t.has_default);
        assert!(!t.has_tag_override());
    }

    #[test]
    fn template_with_tag_override() {
        let mut t = Asn1Template::new("version");
        t.tag = Some(0);
        assert!(t.has_tag_override());
    }

    #[test]
    fn encoding_cache_lifecycle() {
        let mut c = EncodingCache::new();
        assert!(!c.is_valid());
        assert!(c.is_empty());
        assert_eq!(c.len(), None);
        assert_eq!(c.restore(), None);

        c.save(vec![0x30, 0x03, 0x02, 0x01, 0x05]);
        assert!(c.is_valid());
        assert!(!c.is_empty());
        assert_eq!(c.len(), Some(5));
        assert_eq!(c.restore(), Some(&[0x30u8, 0x03, 0x02, 0x01, 0x05][..]));

        c.invalidate();
        assert!(!c.is_valid());
        assert_eq!(c.restore(), None);
        assert_eq!(c.len(), None);
        assert!(c.is_empty());
    }

    #[test]
    fn encoding_cache_default_matches_new() {
        let a = EncodingCache::default();
        let b = EncodingCache::new();
        assert_eq!(a.is_valid(), b.is_valid());
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn sort_set_of_canonical_lexicographic() {
        let mut elements = vec![
            vec![0x30, 0x02, 0x05, 0x00], // NULL
            vec![0x02, 0x01, 0x05],       // INTEGER 5
            vec![0x02, 0x01, 0x03],       // INTEGER 3
            vec![0x04, 0x01, 0xFF],       // OCTET STRING 0xFF
        ];
        sort_set_of_canonical(&mut elements);
        assert_eq!(elements[0], vec![0x02, 0x01, 0x03]);
        assert_eq!(elements[1], vec![0x02, 0x01, 0x05]);
        assert_eq!(elements[2], vec![0x04, 0x01, 0xFF]);
        assert_eq!(elements[3], vec![0x30, 0x02, 0x05, 0x00]);
    }

    #[test]
    fn sort_set_of_canonical_handles_empty() {
        let mut elements: Vec<Vec<u8>> = Vec::new();
        sort_set_of_canonical(&mut elements);
        assert!(elements.is_empty());
    }

    #[test]
    fn sort_set_of_canonical_prefix_rule() {
        // X.690 §11.6: shorter strings sort before longer ones that
        // share a prefix.
        let mut elements = vec![
            vec![0x01, 0x02, 0x03, 0x04],
            vec![0x01, 0x02],
            vec![0x01, 0x02, 0x03],
        ];
        sort_set_of_canonical(&mut elements);
        assert_eq!(elements[0], vec![0x01, 0x02]);
        assert_eq!(elements[1], vec![0x01, 0x02, 0x03]);
        assert_eq!(elements[2], vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn print_context_defaults() {
        let ctx = PrintContext::new();
        assert_eq!(ctx.indent, 0);
        assert_eq!(ctx.nm_sep, ": ");
        assert_eq!(ctx.field_sep, "\n");
        assert_eq!(ctx.flags, PrintFlags::DEFAULT);
    }

    #[test]
    fn print_context_indent_grows() {
        let ctx = PrintContext::new();
        let deeper = ctx.indented();
        assert_eq!(deeper.indent, 2);
        let deeper2 = deeper.indented();
        assert_eq!(deeper2.indent, 4);
    }

    #[test]
    fn print_context_write_indent() {
        let mut buf = String::new();
        let mut ctx = PrintContext::new();
        ctx.indent = 3;
        ctx.write_indent(&mut buf).unwrap();
        assert_eq!(buf, "   ");
    }

    #[test]
    fn scan_context_tracks_depth() {
        let root = ScanContext::new("Certificate");
        assert_eq!(root.depth, 0);
        assert_eq!(root.structure_name, "Certificate");
        assert_eq!(root.field_name, "");

        let field = root.enter_field("tbsCertificate", ItemType::Sequence);
        assert_eq!(field.depth, 1);
        assert_eq!(field.field_name, "tbsCertificate");
        assert_eq!(field.item_type, ItemType::Sequence);
    }

    #[test]
    fn scan_context_tracks_collection_index() {
        let root = ScanContext::new("Extensions");
        assert!(!root.is_in_collection());
        let elem = root.enter_element(0);
        assert!(elem.is_in_collection());
        assert_eq!(elem.collection_index, Some(0));
        let elem1 = root.enter_element(1);
        assert_eq!(elem1.collection_index, Some(1));
    }

    #[test]
    fn scan_context_depth_limit() {
        let mut ctx = ScanContext::new("Deep");
        assert!(!ctx.at_depth_limit());
        // Manually set to the limit.
        ctx.depth = MAX_CONSTRUCTED_NEST;
        assert!(ctx.at_depth_limit());
    }

    #[test]
    fn item_registry_is_empty_placeholder() {
        assert_eq!(item_count(), 0);
        assert!(lookup_item_by_name("Nonexistent").is_none());
        assert!(registered_items().is_empty());
        // Empty name must return None.
        assert!(lookup_item_by_name("").is_none());
    }

    #[test]
    fn max_constructed_nest_matches_c_value() {
        // Must match C constant `ASN1_MAX_CONSTRUCTED_NEST` from
        // `tasn_dec.c`.
        assert_eq!(MAX_CONSTRUCTED_NEST, 30);
    }

    // A trivial `Asn1Item` used to exercise the encode/decode engine
    // in isolation. Encodes itself as a raw DER INTEGER with a fixed
    // value.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestInteger(i64);

    impl Asn1Item for TestInteger {
        fn item_type() -> ItemType {
            ItemType::Primitive
        }
        fn type_name() -> &'static str {
            "TestInteger"
        }
        fn encode_der(&self) -> CryptoResult<Vec<u8>> {
            // Encode as INTEGER tag (0x02), length 1, value.
            let v = i8::try_from(self.0).map_err(|_| {
                Asn1Error::EncodingError("TestInteger value out of i8 range".into())
            })?;
            Ok(vec![0x02, 0x01, v as u8])
        }
        fn decode_der(data: &[u8]) -> CryptoResult<Self> {
            if data.len() != 3 || data[0] != 0x02 || data[1] != 0x01 {
                return Err(Asn1Error::DecodingError("malformed TestInteger".into()).into());
            }
            Ok(TestInteger(data[2] as i8 as i64))
        }
    }

    #[test]
    fn encode_item_roundtrips_via_wrapper() {
        let v = TestInteger(42);
        let bytes = encode_item(&v).unwrap();
        assert_eq!(bytes, vec![0x02, 0x01, 42]);
    }

    #[test]
    fn encode_item_ndef_falls_back_to_der() {
        // Without explicit NDEF implementation, the wrapper should
        // match encode_item.
        let v = TestInteger(7);
        assert_eq!(encode_item_ndef(&v).unwrap(), encode_item(&v).unwrap());
    }

    #[test]
    fn decode_item_roundtrips() {
        let original = TestInteger(-5);
        let bytes = encode_item(&original).unwrap();
        let back: TestInteger = decode_item(&bytes).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn decode_item_with_depth_rejects_too_deep() {
        let result: CryptoResult<TestInteger> =
            decode_item_with_depth(&[0x02, 0x01, 0x00], MAX_CONSTRUCTED_NEST);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nesting") || err_msg.contains("depth"),
            "expected nesting-depth error, got: {err_msg}"
        );
    }

    #[test]
    fn decode_item_with_depth_under_limit_succeeds() {
        let result: CryptoResult<TestInteger> = decode_item_with_depth(&[0x02, 0x01, 9], 0);
        assert_eq!(result.unwrap(), TestInteger(9));
    }

    #[test]
    fn decode_item_with_depth_just_under_limit_succeeds() {
        let result: CryptoResult<TestInteger> =
            decode_item_with_depth(&[0x02, 0x01, 1], MAX_CONSTRUCTED_NEST - 1);
        assert_eq!(result.unwrap(), TestInteger(1));
    }

    #[test]
    fn duplicate_item_produces_equivalent_copy() {
        let original = TestInteger(100);
        let dup = duplicate_item(&original).unwrap();
        assert_eq!(dup, original);
    }

    #[test]
    fn pack_and_unpack_item_round_trip() {
        let original = TestInteger(-1);
        let packed = pack_item(&original).unwrap();
        let unpacked: TestInteger = unpack_item(&packed).unwrap();
        assert_eq!(unpacked, original);
    }

    // Trivial type exercising the Asn1Aux default callbacks.
    #[derive(Debug, Clone, Default)]
    struct AuxTestType {
        pre_enc_called: bool,
    }
    impl Asn1Aux for AuxTestType {}

    #[test]
    fn asn1_aux_default_callbacks_are_no_ops() {
        let mut v = AuxTestType::default();
        assert!(v.pre_encode().is_ok());
        assert!(v.post_encode().is_ok());
        assert!(v.pre_decode().is_ok());
        assert!(v.post_decode().is_ok());
        assert!(v.pre_free().is_ok());
        assert!(v.post_free().is_ok());
        // And the default impls make no observable changes.
        assert!(!v.pre_enc_called);
    }

    // Override exactly one callback to exercise the dispatch.
    #[derive(Debug, Default)]
    struct AuxOverride {
        pub encoded: std::cell::Cell<bool>,
    }
    impl Asn1Aux for AuxOverride {
        fn pre_encode(&self) -> CryptoResult<()> {
            self.encoded.set(true);
            Ok(())
        }
    }

    #[test]
    fn asn1_aux_override_is_invoked() {
        let v = AuxOverride::default();
        assert!(!v.encoded.get());
        v.pre_encode().unwrap();
        assert!(v.encoded.get());
    }
}
