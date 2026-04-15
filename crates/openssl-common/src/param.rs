//! Typed parameter system replacing the C `OSSL_PARAM` mechanism.
//!
//! Provides compile-time type-checked parameter passing between the EVP layer
//! and provider implementations. This module replaces the dynamically-typed
//! `OSSL_PARAM` arrays used in OpenSSL C with a strongly-typed Rust equivalent.
//!
//! # C-to-Rust Mapping
//!
//! | C Concept | Rust Equivalent |
//! |-----------|-----------------|
//! | `OSSL_PARAM` array (null-terminated) | [`ParamSet`] (`HashMap`-backed, O(1) lookup) |
//! | `OSSL_PARAM_locate()` (linear scan) | [`ParamSet::get()`] (hash lookup) |
//! | `OSSL_PARAM_BLD` (stack builder) | [`ParamBuilder`] (fluent builder pattern) |
//! | `OSSL_PARAM_BLD_to_param()` | [`ParamBuilder::build()`] |
//! | `OSSL_PARAM_INTEGER` / `UNSIGNED_INTEGER` | [`ParamValue::Int32`], [`ParamValue::UInt32`], etc. |
//! | `OSSL_PARAM_REAL` | [`ParamValue::Real`] |
//! | `OSSL_PARAM_UTF8_STRING` | [`ParamValue::Utf8String`] |
//! | `OSSL_PARAM_OCTET_STRING` | [`ParamValue::OctetString`] |
//! | `ossl_param_construct_*` | [`ParamBuilder::push_*()`] |
//! | `params_from_text.c` text parsing | [`from_text()`] |
//! | `params_dup.c` duplication | [`ParamSet::duplicate()`] (leverages `Clone`) |
//!
//! # Design Principles
//!
//! - **Rule R5:** All accessors return `Option<T>` or `Result<T, E>`, never sentinel values.
//! - **Rule R6:** All numeric conversions use `TryFrom`/checked arithmetic, no bare `as` casts.
//! - **Rule R7:** `ParamSet` is owned (not shared). If shared in future, add `// LOCK-SCOPE:`.
//! - **Rule R8:** Zero `unsafe` code.
//! - **Rule R10:** Reachable via EVP fetch → provider → param passing.
//!
//! # Examples
//!
//! ```rust
//! use openssl_common::param::{ParamBuilder, ParamValue, FromParam};
//!
//! let params = ParamBuilder::new()
//!     .push_utf8("digest", "SHA256".to_string())
//!     .push_u32("key_length", 256)
//!     .push_octet("iv", vec![0u8; 16])
//!     .build();
//!
//! assert_eq!(params.get("digest"), Some(&ParamValue::Utf8String("SHA256".to_string())));
//! assert_eq!(params.len(), 3);
//! ```

use std::collections::HashMap;
use std::fmt;

use crate::error::CommonError;

// ---------------------------------------------------------------------------
// ParamValue — typed parameter value enum (replaces OSSL_PARAM type tags)
// ---------------------------------------------------------------------------

/// A typed parameter value, replacing the C `OSSL_PARAM` data-type + data-pointer pair.
///
/// Each variant maps to a specific `OSSL_PARAM` data type constant:
///
/// | Variant | C Type Tag |
/// |---------|-----------|
/// | `Int32` | `OSSL_PARAM_INTEGER` (data_size = 4) |
/// | `UInt32` | `OSSL_PARAM_UNSIGNED_INTEGER` (data_size = 4) |
/// | `Int64` | `OSSL_PARAM_INTEGER` (data_size = 8) |
/// | `UInt64` | `OSSL_PARAM_UNSIGNED_INTEGER` (data_size = 8) |
/// | `Real` | `OSSL_PARAM_REAL` |
/// | `Utf8String` | `OSSL_PARAM_UTF8_STRING` |
/// | `OctetString` | `OSSL_PARAM_OCTET_STRING` |
/// | `BigNum` | `OSSL_PARAM_UNSIGNED_INTEGER` (large data_size) |
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ParamValue {
    /// Signed 32-bit integer (maps to `OSSL_PARAM_INTEGER` with `data_size=4`).
    Int32(i32),
    /// Unsigned 32-bit integer (maps to `OSSL_PARAM_UNSIGNED_INTEGER` with `data_size=4`).
    UInt32(u32),
    /// Signed 64-bit integer (maps to `OSSL_PARAM_INTEGER` with `data_size=8`).
    Int64(i64),
    /// Unsigned 64-bit integer (maps to `OSSL_PARAM_UNSIGNED_INTEGER` with `data_size=8`).
    UInt64(u64),
    /// IEEE 754 double-precision floating-point (maps to `OSSL_PARAM_REAL`).
    Real(f64),
    /// UTF-8 string (maps to `OSSL_PARAM_UTF8_STRING`).
    Utf8String(String),
    /// Raw byte vector (maps to `OSSL_PARAM_OCTET_STRING`).
    OctetString(Vec<u8>),
    /// Big number as big-endian byte vector (maps to `OSSL_PARAM_UNSIGNED_INTEGER`
    /// with large `data_size`).
    BigNum(Vec<u8>),
}

impl ParamValue {
    /// Extracts an `i32` if this value is [`ParamValue::Int32`].
    ///
    /// Returns `None` for any other variant (Rule R5 — no sentinel values).
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::Int32(v) => Some(*v),
            _ => None,
        }
    }

    /// Extracts a `u32` if this value is [`ParamValue::UInt32`].
    ///
    /// Returns `None` for any other variant.
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::UInt32(v) => Some(*v),
            _ => None,
        }
    }

    /// Extracts an `i64` if this value is [`ParamValue::Int64`].
    ///
    /// Returns `None` for any other variant.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int64(v) => Some(*v),
            _ => None,
        }
    }

    /// Extracts a `u64` if this value is [`ParamValue::UInt64`].
    ///
    /// Returns `None` for any other variant.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::UInt64(v) => Some(*v),
            _ => None,
        }
    }

    /// Extracts an `f64` if this value is [`ParamValue::Real`].
    ///
    /// Returns `None` for any other variant.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Real(v) => Some(*v),
            _ => None,
        }
    }

    /// Extracts a string slice if this value is [`ParamValue::Utf8String`].
    ///
    /// Returns `None` for any other variant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Utf8String(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Extracts a byte slice if this value is [`ParamValue::OctetString`].
    ///
    /// Returns `None` for any other variant.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::OctetString(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Extracts a big-number byte slice if this value is [`ParamValue::BigNum`].
    ///
    /// The bytes are in big-endian order. Returns `None` for any other variant.
    pub fn as_bignum(&self) -> Option<&[u8]> {
        match self {
            Self::BigNum(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Returns a human-readable name describing this value's type.
    ///
    /// Useful for error messages and diagnostics output.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_common::param::ParamValue;
    /// assert_eq!(ParamValue::Int32(42).param_type_name(), "Int32");
    /// assert_eq!(ParamValue::Utf8String("hello".into()).param_type_name(), "Utf8String");
    /// ```
    pub fn param_type_name(&self) -> &'static str {
        match self {
            Self::Int32(_) => "Int32",
            Self::UInt32(_) => "UInt32",
            Self::Int64(_) => "Int64",
            Self::UInt64(_) => "UInt64",
            Self::Real(_) => "Real",
            Self::Utf8String(_) => "Utf8String",
            Self::OctetString(_) => "OctetString",
            Self::BigNum(_) => "BigNum",
        }
    }
}

impl fmt::Display for ParamValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int32(v) => write!(f, "{v}"),
            Self::UInt32(v) => write!(f, "{v}"),
            Self::Int64(v) => write!(f, "{v}"),
            Self::UInt64(v) => write!(f, "{v}"),
            Self::Real(v) => write!(f, "{v}"),
            Self::Utf8String(v) => write!(f, "{v}"),
            Self::OctetString(v) => write!(f, "[{} bytes]", v.len()),
            Self::BigNum(v) => write!(f, "BigNum[{} bytes]", v.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// ParamSet — typed parameter collection (replaces null-terminated OSSL_PARAM arrays)
// ---------------------------------------------------------------------------

/// A collection of named, typed parameters, replacing the C null-terminated
/// `OSSL_PARAM` array.
///
/// Backed by a `HashMap<String, ParamValue>` for O(1) key lookup,
/// compared to the C implementation's linear scan via `OSSL_PARAM_locate()`.
/// Keys are `String` internally (enabling `serde::Deserialize` support), but
/// the write API (`set()`) accepts `&'static str` to enforce compile-time
/// constant parameter names — matching the C convention where `OSSL_PARAM` key
/// names are always string literals.
///
/// # Ownership
///
/// `ParamSet` is an owned, non-shared value. If it needs to be shared across
/// threads in the future, wrap in `Arc<parking_lot::RwLock<ParamSet>>` and
/// annotate with `// LOCK-SCOPE: param set, <access pattern description>` (Rule R7).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ParamSet {
    /// The backing store mapping parameter names to values.
    params: HashMap<String, ParamValue>,
}

impl ParamSet {
    /// Creates an empty parameter set.
    ///
    /// Equivalent to constructing a zero-length `OSSL_PARAM` array in C.
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    /// Looks up a parameter by key, returning a reference to its value.
    ///
    /// Replaces `OSSL_PARAM_locate()` — O(1) hash lookup instead of linear scan.
    ///
    /// Returns `None` if the key is not present (Rule R5 — no sentinel values).
    pub fn get(&self, key: &str) -> Option<&ParamValue> {
        self.params.get(key)
    }

    /// Performs a type-safe extraction of a parameter by key.
    ///
    /// Combines key lookup with type conversion via the [`FromParam`] trait.
    ///
    /// # Errors
    ///
    /// - [`CommonError::ParamNotFound`] if the key is absent.
    /// - [`CommonError::ParamTypeMismatch`] if the value cannot be converted to `T`.
    pub fn get_typed<T: FromParam>(&self, key: &str) -> Result<T, CommonError> {
        let value = self
            .params
            .get(key)
            .ok_or_else(|| CommonError::ParamNotFound {
                key: key.to_string(),
            })?;
        T::from_param(value)
    }

    /// Sets (inserts or overwrites) a parameter.
    ///
    /// Accepts `&'static str` keys to enforce compile-time constant parameter
    /// names, matching the C convention where `OSSL_PARAM` key names are always
    /// string literals.
    pub fn set(&mut self, key: &'static str, value: ParamValue) {
        self.params.insert(key.to_owned(), value);
    }

    /// Returns `true` if the parameter set contains the given key.
    pub fn contains(&self, key: &str) -> bool {
        self.params.contains_key(key)
    }

    /// Removes a parameter by key, returning its value if present.
    ///
    /// Returns `None` if the key was not found (Rule R5).
    pub fn remove(&mut self, key: &str) -> Option<ParamValue> {
        self.params.remove(key)
    }

    /// Returns an iterator over all parameter keys as string slices.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.params.keys().map(String::as_str)
    }

    /// Returns the number of parameters in the set.
    pub fn len(&self) -> usize {
        self.params.len()
    }

    /// Returns `true` if the parameter set contains no entries.
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// Returns an iterator over `(key, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ParamValue)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Merges another parameter set into this one.
    ///
    /// Parameters from `other` overwrite any existing parameters with the same key.
    /// Parameters in `self` that are not in `other` are preserved.
    pub fn merge(&mut self, other: &ParamSet) {
        for (key, value) in &other.params {
            self.params.insert(key.clone(), value.clone());
        }
    }

    /// Creates an explicit deep clone of this parameter set.
    ///
    /// Equivalent to `ossl_param_dup()` from `crypto/params_dup.c`.
    /// Uses Rust's `Clone` implementation under the hood.
    #[must_use]
    pub fn duplicate(&self) -> ParamSet {
        self.clone()
    }
}

// ---------------------------------------------------------------------------
// ParamBuilder — fluent builder (replaces OSSL_PARAM_BLD)
// ---------------------------------------------------------------------------

/// A fluent builder for constructing [`ParamSet`] instances.
///
/// Replaces the C `OSSL_PARAM_BLD` API pattern where parameters are pushed
/// one-by-one and then converted into a flat `OSSL_PARAM` array via
/// `OSSL_PARAM_BLD_to_param()`.
///
/// # Examples
///
/// ```rust
/// use openssl_common::param::ParamBuilder;
///
/// let params = ParamBuilder::new()
///     .push_utf8("algorithm", "AES-256-GCM".to_string())
///     .push_u32("key_length", 256)
///     .push_octet("iv", vec![0u8; 12])
///     .build();
///
/// assert_eq!(params.len(), 3);
/// ```
#[derive(Debug, Default)]
pub struct ParamBuilder {
    /// Accumulated parameters in insertion order.
    params: Vec<(&'static str, ParamValue)>,
}

impl ParamBuilder {
    /// Creates a new, empty parameter builder.
    pub fn new() -> Self {
        Self { params: Vec::new() }
    }

    /// Pushes a signed 32-bit integer parameter.
    #[must_use]
    pub fn push_i32(mut self, key: &'static str, value: i32) -> Self {
        self.params.push((key, ParamValue::Int32(value)));
        self
    }

    /// Pushes an unsigned 32-bit integer parameter.
    #[must_use]
    pub fn push_u32(mut self, key: &'static str, value: u32) -> Self {
        self.params.push((key, ParamValue::UInt32(value)));
        self
    }

    /// Pushes a signed 64-bit integer parameter.
    #[must_use]
    pub fn push_i64(mut self, key: &'static str, value: i64) -> Self {
        self.params.push((key, ParamValue::Int64(value)));
        self
    }

    /// Pushes an unsigned 64-bit integer parameter.
    #[must_use]
    pub fn push_u64(mut self, key: &'static str, value: u64) -> Self {
        self.params.push((key, ParamValue::UInt64(value)));
        self
    }

    /// Pushes a floating-point parameter.
    #[must_use]
    pub fn push_f64(mut self, key: &'static str, value: f64) -> Self {
        self.params.push((key, ParamValue::Real(value)));
        self
    }

    /// Pushes a UTF-8 string parameter.
    #[must_use]
    pub fn push_utf8(mut self, key: &'static str, value: String) -> Self {
        self.params.push((key, ParamValue::Utf8String(value)));
        self
    }

    /// Pushes an octet-string (raw bytes) parameter.
    #[must_use]
    pub fn push_octet(mut self, key: &'static str, value: Vec<u8>) -> Self {
        self.params.push((key, ParamValue::OctetString(value)));
        self
    }

    /// Pushes a big-number parameter as a big-endian byte vector.
    #[must_use]
    pub fn push_bignum(mut self, key: &'static str, value: Vec<u8>) -> Self {
        self.params.push((key, ParamValue::BigNum(value)));
        self
    }

    /// Consumes the builder and produces a [`ParamSet`].
    ///
    /// If duplicate keys were pushed, the last value for each key wins
    /// (matching `HashMap::insert` semantics).
    ///
    /// Equivalent to `OSSL_PARAM_BLD_to_param()` in C.
    pub fn build(self) -> ParamSet {
        let mut map = HashMap::new();
        for (key, value) in self.params {
            map.insert(key.to_owned(), value);
        }
        ParamSet { params: map }
    }
}

// ---------------------------------------------------------------------------
// FromParam — type-safe extraction trait
// ---------------------------------------------------------------------------

/// Trait for extracting a typed value from a [`ParamValue`].
///
/// Implementations handle type checking and safe numeric conversion.
/// All narrowing conversions use `TryFrom` per Rule R6 — no bare `as` casts.
///
/// # Errors
///
/// Returns [`CommonError::ParamTypeMismatch`] when the `ParamValue` variant
/// does not match or cannot be safely converted to the target type.
pub trait FromParam: Sized {
    /// Attempts to extract `Self` from the given parameter value.
    fn from_param(value: &ParamValue) -> Result<Self, CommonError>;
}

impl FromParam for i32 {
    fn from_param(value: &ParamValue) -> Result<Self, CommonError> {
        match value {
            ParamValue::Int32(v) => Ok(*v),
            ParamValue::Int64(v) => i32::try_from(*v).map_err(|_| CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "Int32",
                actual: "Int64 (out of i32 range)",
            }),
            _ => Err(CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "Int32",
                actual: value.param_type_name(),
            }),
        }
    }
}

impl FromParam for u32 {
    fn from_param(value: &ParamValue) -> Result<Self, CommonError> {
        match value {
            ParamValue::UInt32(v) => Ok(*v),
            ParamValue::UInt64(v) => {
                u32::try_from(*v).map_err(|_| CommonError::ParamTypeMismatch {
                    key: String::new(),
                    expected: "UInt32",
                    actual: "UInt64 (out of u32 range)",
                })
            }
            _ => Err(CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "UInt32",
                actual: value.param_type_name(),
            }),
        }
    }
}

impl FromParam for i64 {
    fn from_param(value: &ParamValue) -> Result<Self, CommonError> {
        match value {
            ParamValue::Int64(v) => Ok(*v),
            ParamValue::Int32(v) => Ok(i64::from(*v)),
            _ => Err(CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "Int64",
                actual: value.param_type_name(),
            }),
        }
    }
}

impl FromParam for u64 {
    fn from_param(value: &ParamValue) -> Result<Self, CommonError> {
        match value {
            ParamValue::UInt64(v) => Ok(*v),
            ParamValue::UInt32(v) => Ok(u64::from(*v)),
            _ => Err(CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "UInt64",
                actual: value.param_type_name(),
            }),
        }
    }
}

impl FromParam for f64 {
    fn from_param(value: &ParamValue) -> Result<Self, CommonError> {
        match value {
            ParamValue::Real(v) => Ok(*v),
            _ => Err(CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "Real",
                actual: value.param_type_name(),
            }),
        }
    }
}

impl FromParam for String {
    fn from_param(value: &ParamValue) -> Result<Self, CommonError> {
        match value {
            ParamValue::Utf8String(v) => Ok(v.clone()),
            _ => Err(CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "Utf8String",
                actual: value.param_type_name(),
            }),
        }
    }
}

impl FromParam for Vec<u8> {
    fn from_param(value: &ParamValue) -> Result<Self, CommonError> {
        match value {
            ParamValue::OctetString(v) | ParamValue::BigNum(v) => Ok(v.clone()),
            _ => Err(CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "OctetString or BigNum",
                actual: value.param_type_name(),
            }),
        }
    }
}

impl FromParam for bool {
    /// Extracts a boolean from an [`ParamValue::Int32`].
    ///
    /// `0` maps to `false`, any nonzero value maps to `true`.
    /// This matches the C OpenSSL convention where boolean parameters are
    /// stored as integer 0/1 values.
    fn from_param(value: &ParamValue) -> Result<Self, CommonError> {
        match value {
            ParamValue::Int32(v) => Ok(*v != 0),
            ParamValue::UInt32(v) => Ok(*v != 0),
            _ => Err(CommonError::ParamTypeMismatch {
                key: String::new(),
                expected: "Int32 (boolean)",
                actual: value.param_type_name(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// from_text — text-to-ParamValue parser (replaces params_from_text.c)
// ---------------------------------------------------------------------------

/// Parses a string representation into a [`ParamValue`], associating it with
/// the given key.
///
/// Replaces `OSSL_PARAM_allocate_from_text()` from `crypto/params_from_text.c`.
///
/// # Parsing Strategy
///
/// The function attempts to parse the value string in the following order:
///
/// 1. **Hex bytes** — if the value starts with `"0x"` or `"0X"`, parse as hex-encoded
///    octet string.
/// 2. **Signed integer** — attempt `i64::from_str()`.
/// 3. **Unsigned integer** — attempt `u64::from_str()` (catches values > `i64::MAX`).
/// 4. **Floating-point** — attempt `f64::from_str()`.
/// 5. **UTF-8 string** — fallback: return the raw string as `Utf8String`.
///
/// All numeric parsing uses `str::parse::<T>()` — never bare `as` casts (Rule R6).
///
/// # Errors
///
/// Returns [`CommonError::InvalidArgument`] if hex decoding fails (odd-length
/// hex string or non-hex characters after the `0x` prefix).
///
/// # Examples
///
/// ```rust
/// use openssl_common::param::{from_text, ParamValue};
///
/// // Integer parsing
/// let v = from_text("count", "42").unwrap();
/// assert_eq!(v, ParamValue::Int64(42));
///
/// // Hex bytes
/// let v = from_text("iv", "0xdeadbeef").unwrap();
/// assert_eq!(v, ParamValue::OctetString(vec![0xde, 0xad, 0xbe, 0xef]));
///
/// // Fallback to string
/// let v = from_text("name", "SHA256").unwrap();
/// assert_eq!(v, ParamValue::Utf8String("SHA256".to_string()));
/// ```
pub fn from_text(_key: &'static str, value: &str) -> Result<ParamValue, CommonError> {
    // Step 1: Check for hex byte prefix
    if let Some(hex_str) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return decode_hex_bytes(hex_str);
    }

    // Step 2: Try signed integer (i64)
    if let Ok(v) = value.parse::<i64>() {
        return Ok(ParamValue::Int64(v));
    }

    // Step 3: Try unsigned integer (u64) — catches values > i64::MAX
    if let Ok(v) = value.parse::<u64>() {
        return Ok(ParamValue::UInt64(v));
    }

    // Step 4: Try floating-point (f64)
    // Only attempt if the value looks like a float (contains '.' or 'e'/'E')
    // to avoid misinterpreting plain words as NaN/Infinity
    if value.contains('.') || value.contains('e') || value.contains('E') {
        if let Ok(v) = value.parse::<f64>() {
            if v.is_finite() {
                return Ok(ParamValue::Real(v));
            }
        }
    }

    // Step 5: Fallback — treat as UTF-8 string
    Ok(ParamValue::Utf8String(value.to_string()))
}

/// Decodes a hexadecimal string (without the `0x` prefix) into an octet vector.
///
/// # Errors
///
/// Returns [`CommonError::InvalidArgument`] if:
/// - The hex string has odd length.
/// - The hex string contains non-hex characters.
fn decode_hex_bytes(hex: &str) -> Result<ParamValue, CommonError> {
    if hex.len() % 2 != 0 {
        return Err(CommonError::InvalidArgument(format!(
            "hex string has odd length: {}",
            hex.len()
        )));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi_val = hex_digit_value(hi).ok_or_else(|| {
            CommonError::InvalidArgument(format!("invalid hex character: '{hi}'"))
        })?;
        let lo_val = hex_digit_value(lo).ok_or_else(|| {
            CommonError::InvalidArgument(format!("invalid hex character: '{lo}'"))
        })?;
        bytes.push(hi_val << 4 | lo_val);
    }
    Ok(ParamValue::OctetString(bytes))
}

/// Converts a single hexadecimal character to its numeric value (0–15).
///
/// Returns `None` for non-hex characters.
/// Uses `char::to_digit(16)` and `u8::try_from()` per Rule R6 — no bare `as` casts.
fn hex_digit_value(c: char) -> Option<u8> {
    // `to_digit(16)` returns `Some(0..=15)` for valid hex chars, `None` otherwise.
    // `u8::try_from` is guaranteed to succeed for 0–15, but we avoid bare `as` casts.
    c.to_digit(16).and_then(|v| u8::try_from(v).ok())
}
