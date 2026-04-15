//! # Property Query and Match System
//!
//! Translates OpenSSL's `crypto/property/` subsystem (~2,800 lines of C across 7 files) into
//! idiomatic Rust. This module enables runtime algorithm selection based on property
//! query strings (e.g., `"fips=yes"`, `"provider=default"`).
//!
//! ## Architecture
//!
//! The property system has four layers:
//! 1. **String Interning** — maps property names/values to compact integer indices
//! 2. **Property Parsing** — parses definition and query strings into sorted lists
//! 3. **Method Store** — associates algorithm implementations with property definitions
//! 4. **Query Cache** — caches query results per algorithm for fast repeated lookups
//!
//! ## Source Mapping
//!
//! | Rust Type | C Source | C Lines |
//! |-----------|----------|---------|
//! | `PropertyIndex` | `OSSL_PROPERTY_IDX` in `property_local.h` | L14 |
//! | `PropertyOper` | `OSSL_PROPERTY_OPER` in `property_local.h` | L16-20 |
//! | `PropertyDefinition` | `ossl_property_definition_st` in `property_local.h` | L22-31 |
//! | `PropertyList` | `ossl_property_list_st` in `property_local.h` | L33-37 |
//! | `PropertyStringStore` | `PROPERTY_STRING_DATA` in `property_string.c` | L38-48 |
//! | `DefinitionCache` | `defn_cache` in `defn_cache.c` | full file |
//! | `MethodStore` | `ossl_method_store_st` in `property.c` | L94+ |
//! | `AlgorithmEntry` | `ALGORITHM` in `property.c` | L69-73 |
//!
//! ## Locking Strategy (Rule R7)
//!
//! The method store uses sharded `RwLock`s (`NUM_SHARDS`=4) for scalability, matching
//! the C implementation's `STORED_ALGORITHMS` sharding strategy per `property.c` L31.
//! Each lock carries a `// LOCK-SCOPE:` annotation documenting its purpose and
//! contention characteristics.

use std::collections::HashMap;
use std::fmt;

use parking_lot::RwLock;
use tracing::{debug, trace, warn};

use openssl_common::error::{CryptoError, CryptoResult};

// =============================================================================
// Constants
// =============================================================================

/// Number of shards for the method store, matching C `NUM_SHARDS` (property.c L31-33).
/// Determined through performance testing on Intel Xeon Gold 6248R CPU @ 3.00GHz.
/// 4 shards combined with `CACHE_SIZE` delivered the best performance for 16+
/// threads and close to best performance at below 16 threads.
const NUM_SHARDS: usize = 4;

/// Maximum number of cache entries across all shards, matching C `CACHE_SIZE`
/// (property.c L35-37).
const CACHE_SIZE: usize = 512;

/// Per-shard flush threshold, matching C `IMPL_CACHE_FLUSH_THRESHOLD`
/// (property.c L44).
const CACHE_FLUSH_THRESHOLD: usize = CACHE_SIZE / NUM_SHARDS;

// =============================================================================
// PropertyIndex — Interned string identifier
// =============================================================================

/// Interned property name or value index. Non-zero.
///
/// Replaces C `OSSL_PROPERTY_IDX` (`property_local.h` L14). Property names and
/// values are interned into a [`PropertyStringStore`] for O(1) comparison via
/// integer equality rather than string comparison.
///
/// A zero index is never valid — all indices start at 1, matching the C
/// convention where `0` means "not found" (Rule R5: we use `Option<PropertyIndex>`
/// instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PropertyIndex(u32);

impl PropertyIndex {
    /// Returns the raw underlying index value.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Reserved boolean property value index for "yes" / "true".
/// Matches C `OSSL_PROPERTY_TRUE` (`property_local.h` L39).
pub const PROPERTY_TRUE: PropertyIndex = PropertyIndex(1);

/// Reserved boolean property value index for "no" / "false".
/// Matches C `OSSL_PROPERTY_FALSE` (`property_local.h` L40).
pub const PROPERTY_FALSE: PropertyIndex = PropertyIndex(2);

// =============================================================================
// PropertyOper — comparison operator
// =============================================================================

/// Property comparison operator.
///
/// Replaces C `OSSL_PROPERTY_OPER` from `property_local.h` L16-20.
/// Used in both definition strings and query strings to specify how
/// a property value should be compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyOper {
    /// Equality test: `name=value`.
    Eq,
    /// Inequality test: `name!=value`.
    Ne,
    /// Override: used during property merge (query prefix `-name`).
    Override,
}

impl fmt::Display for PropertyOper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eq => f.write_str("="),
            Self::Ne => f.write_str("!="),
            Self::Override => f.write_str("-"),
        }
    }
}

// =============================================================================
// PropertyType — value type tag
// =============================================================================

/// Property value type tag.
///
/// Replaces C `OSSL_PROPERTY_TYPE` from `property_local.h`. Indicates
/// whether a property value is a string (interned), a number, or
/// unspecified (used for undefined values in queries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyType {
    /// An interned string value.
    String,
    /// A signed 64-bit integer value.
    Number,
    /// The value was not specified or could not be resolved.
    Unspecified,
}

impl fmt::Display for PropertyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => f.write_str("string"),
            Self::Number => f.write_str("number"),
            Self::Unspecified => f.write_str("unspecified"),
        }
    }
}

// =============================================================================
// PropertyValue — typed value union replacement
// =============================================================================

/// Typed property value — replaces the C union in `ossl_property_definition_st`.
///
/// In C, the value is a `union { int64_t int_val; OSSL_PROPERTY_IDX str_val; }`.
/// In Rust, we use a safe enum to avoid `unsafe` union access entirely (Rule R8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    /// A signed 64-bit integer value.
    Number(i64),
    /// An interned string value index.
    StringVal(PropertyIndex),
}

// =============================================================================
// PropertyDefinition — single property entry
// =============================================================================

/// A single property definition entry.
///
/// Replaces C `ossl_property_definition_st` from `property_local.h` L22-31.
/// Each definition pairs an interned property name with a typed value and
/// a comparison operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyDefinition {
    /// Interned property name index.
    pub name_idx: PropertyIndex,
    /// Property type (String, Number, Unspecified).
    pub prop_type: PropertyType,
    /// Comparison operator (Eq, Ne, Override).
    pub oper: PropertyOper,
    /// Whether this property is optional in queries (prefixed with '?').
    pub optional: bool,
    /// Property value.
    pub value: PropertyValue,
}

// =============================================================================
// PropertyList — sorted collection of definitions
// =============================================================================

/// A sorted list of property definitions.
///
/// Replaces C `ossl_property_list_st` from `property_local.h` L33-37.
/// The list is always sorted by `name_idx` to enable O(log n) binary search
/// during property matching and lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyList {
    /// Whether any property in the list is optional.
    pub has_optional: bool,
    /// Properties sorted by `name_idx` for binary search.
    pub properties: Vec<PropertyDefinition>,
}

impl PropertyList {
    /// Creates an empty property list with no optional properties.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            has_optional: false,
            properties: Vec::new(),
        }
    }
}

impl Default for PropertyList {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for PropertyList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, prop) in self.properties.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            if prop.optional {
                f.write_str("?")?;
            }
            if prop.oper == PropertyOper::Override {
                write!(f, "-{}", prop.name_idx.0)?;
            } else {
                write!(f, "{}", prop.name_idx.0)?;
                write!(f, "{}", prop.oper)?;
                match &prop.value {
                    PropertyValue::Number(n) => write!(f, "{n}")?,
                    PropertyValue::StringVal(idx) => write!(f, "{}", idx.0)?,
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// PropertyStringStore — String interning tables
// =============================================================================

/// Internal storage for the property string interning tables.
struct PropertyStringStoreInner {
    /// Map from name string to interned index.
    name_to_idx: HashMap<String, PropertyIndex>,
    /// Map from index back to name string.
    idx_to_name: Vec<String>,
    /// Map from value string to interned index.
    value_to_idx: HashMap<String, PropertyIndex>,
    /// Map from index back to value string.
    idx_to_value: Vec<String>,
    /// Next name index counter (starts at 1, 0 is invalid).
    next_name_idx: u32,
    /// Next value index counter (starts at 3, 1=TRUE, 2=FALSE are reserved).
    next_value_idx: u32,
}

/// Per-context string interning for property names and values.
///
/// Replaces C `PROPERTY_STRING_DATA` from `property_string.c` L38-48.
/// Provides efficient string→index and index→string lookup for property
/// names and values. Thread-safe via an internal [`RwLock`].
///
/// Pre-registers canonical property names ("provider", "version", "fips",
/// "output", "input", "structure") and boolean values ("yes" → `PROPERTY_TRUE`,
/// "no" → `PROPERTY_FALSE`) matching `ossl_property_parse_init()` in
/// `property_parse.c` L574-602.
pub struct PropertyStringStore {
    // LOCK-SCOPE: protects name/value interning tables — write during first-seen
    // name/value, read during all property operations. Low contention after
    // initialization since most names/values are interned during provider load.
    inner: RwLock<PropertyStringStoreInner>,
}

impl PropertyStringStore {
    /// Creates a new property string store pre-populated with canonical names.
    ///
    /// Pre-registers:
    /// - Names: "provider", "version", "fips", "output", "input", "structure"
    ///   (from `property_parse.c` `ossl_property_parse_init()` L576-583)
    /// - Values: "yes" → index 1 (`PROPERTY_TRUE`), "no" → index 2
    ///   (`PROPERTY_FALSE`) (from `property_parse.c` L595-596)
    #[must_use]
    pub fn new() -> Self {
        let mut inner = PropertyStringStoreInner {
            name_to_idx: HashMap::new(),
            idx_to_name: Vec::new(),
            value_to_idx: HashMap::new(),
            idx_to_value: Vec::new(),
            next_name_idx: 1,
            next_value_idx: 1,
        };

        // Pre-register canonical property names (property_parse.c L576-583)
        // Starting at index 1 with only 6 names, overflow is impossible.
        let predefined_names = [
            "provider",
            "version",
            "fips",
            "output",
            "input",
            "structure",
        ];
        for name in &predefined_names {
            let idx = PropertyIndex(inner.next_name_idx);
            inner.next_name_idx = inner.next_name_idx.saturating_add(1);
            inner.name_to_idx.insert((*name).to_string(), idx);
            inner.idx_to_name.push((*name).to_string());
        }

        // Pre-register boolean values: "yes" = PROPERTY_TRUE(1), "no" = PROPERTY_FALSE(2)
        // (property_parse.c L595-596)
        // Starting at index 1 with only 2 values, overflow is impossible.
        let yes_idx = PropertyIndex(inner.next_value_idx);
        debug_assert!(yes_idx == PROPERTY_TRUE);
        inner.next_value_idx = inner.next_value_idx.saturating_add(1);
        inner.value_to_idx.insert("yes".to_string(), yes_idx);
        inner.idx_to_value.push("yes".to_string());

        let no_idx = PropertyIndex(inner.next_value_idx);
        debug_assert!(no_idx == PROPERTY_FALSE);
        inner.next_value_idx = inner.next_value_idx.saturating_add(1);
        inner.value_to_idx.insert("no".to_string(), no_idx);
        inner.idx_to_value.push("no".to_string());

        debug!(
            "PropertyStringStore initialized with {} predefined names and 2 boolean values",
            predefined_names.len()
        );

        Self {
            inner: RwLock::new(inner),
        }
    }

    /// Interns a property name string, returning its unique index.
    ///
    /// Replaces C `ossl_property_name()` from `property_string.c`.
    /// If `create` is `true` and the name has not been seen before,
    /// a new index is allocated. If `create` is `false` and the name
    /// is unknown, returns `None` (Rule R5: Option instead of sentinel 0).
    pub fn intern_name(&self, name: &str, create: bool) -> Option<PropertyIndex> {
        let lower = name.to_lowercase();

        // Fast path: read lock for existing names
        {
            let guard = self.inner.read();
            if let Some(&idx) = guard.name_to_idx.get(&lower) {
                return Some(idx);
            }
            if !create {
                return None;
            }
        }

        // Slow path: write lock to insert new name
        let mut guard = self.inner.write();
        // Double-check after acquiring write lock
        if let Some(&idx) = guard.name_to_idx.get(&lower) {
            return Some(idx);
        }

        let idx = PropertyIndex(guard.next_name_idx);
        guard.next_name_idx = guard.next_name_idx.checked_add(1)?;
        guard.name_to_idx.insert(lower.clone(), idx);
        guard.idx_to_name.push(lower);
        trace!(name = %name, index = idx.0, "interned new property name");
        Some(idx)
    }

    /// Interns a property value string, returning its unique index.
    ///
    /// Replaces C `ossl_property_value()` from `property_string.c`.
    /// If `create` is `true` and the value has not been seen before,
    /// a new index is allocated. If `create` is `false` and the value
    /// is unknown, returns `None` (Rule R5: Option instead of sentinel 0).
    pub fn intern_value(&self, value: &str, create: bool) -> Option<PropertyIndex> {
        let lower = value.to_lowercase();

        // Fast path: read lock for existing values
        {
            let guard = self.inner.read();
            if let Some(&idx) = guard.value_to_idx.get(&lower) {
                return Some(idx);
            }
            if !create {
                return None;
            }
        }

        // Slow path: write lock to insert new value
        let mut guard = self.inner.write();
        // Double-check after acquiring write lock
        if let Some(&idx) = guard.value_to_idx.get(&lower) {
            return Some(idx);
        }

        let idx = PropertyIndex(guard.next_value_idx);
        guard.next_value_idx = guard.next_value_idx.checked_add(1)?;
        guard.value_to_idx.insert(lower.clone(), idx);
        guard.idx_to_value.push(lower);
        trace!(value = %value, index = idx.0, "interned new property value");
        Some(idx)
    }

    /// Resolves a property name index back to its string representation.
    ///
    /// Replaces C `ossl_property_name_str()` from `property_string.c`.
    /// Returns `None` if the index is not valid (Rule R5).
    #[must_use]
    pub fn name_str(&self, idx: PropertyIndex) -> Option<String> {
        let guard = self.inner.read();
        let array_idx = idx.0.checked_sub(1)? as usize;
        guard.idx_to_name.get(array_idx).cloned()
    }

    /// Resolves a property value index back to its string representation.
    ///
    /// Replaces C `ossl_property_value_str()` from `property_string.c`.
    /// Returns `None` if the index is not valid (Rule R5).
    #[must_use]
    pub fn value_str(&self, idx: PropertyIndex) -> Option<String> {
        let guard = self.inner.read();
        let array_idx = idx.0.checked_sub(1)? as usize;
        guard.idx_to_value.get(array_idx).cloned()
    }
}

impl Default for PropertyStringStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PropertyStringStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.read();
        f.debug_struct("PropertyStringStore")
            .field("names_count", &guard.name_to_idx.len())
            .field("values_count", &guard.value_to_idx.len())
            .finish()
    }
}

// =============================================================================
// Property Parsing — definition and query string parsers
// =============================================================================

/// Skips leading whitespace characters in the input slice.
fn skip_space(s: &str) -> &str {
    s.trim_start()
}

/// Attempts to consume a single character `ch` at the start of the string.
/// Returns `Some(rest)` with whitespace skipped if the character matched,
/// or `None` if the character did not match.
fn match_ch(s: &str, ch: char) -> Option<&str> {
    let trimmed = skip_space(s);
    if trimmed.starts_with(ch) {
        Some(skip_space(&trimmed[ch.len_utf8()..]))
    } else {
        None
    }
}

/// Attempts to consume a case-insensitive prefix string at the start.
/// Returns `Some(rest)` with whitespace skipped if the prefix matched,
/// or `None` if it did not.
fn match_str<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let trimmed = skip_space(s);
    if trimmed.len() >= prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(skip_space(&trimmed[prefix.len()..]))
    } else {
        None
    }
}

/// Parses a property name identifier from the input.
///
/// Property names consist of alphanumeric characters, underscores, and dots.
/// The first character must be alphabetic. Dots separate user-defined
/// namespace prefixes. The name is normalized to lowercase.
///
/// Returns `(remaining_input, parsed_name)` on success.
fn parse_name_str(s: &str) -> CryptoResult<(&str, String)> {
    let s = skip_space(s);
    let bytes = s.as_bytes();

    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return Err(CryptoError::Provider(format!(
            "property name must start with alphabetic character, got: '{}'",
            s.chars().next().unwrap_or('\0')
        )));
    }

    let mut i = 0;
    let mut name = String::with_capacity(32);

    loop {
        // Must start each segment with alpha
        if i >= bytes.len() || !bytes[i].is_ascii_alphabetic() {
            if name.is_empty() {
                return Err(CryptoError::Provider(format!(
                    "property name must start with alphabetic character near: '{}'",
                    &s[i..]
                )));
            }
            break;
        }

        // Consume alphanumeric and underscores
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            name.push(bytes[i].to_ascii_lowercase() as char);
            i += 1;
        }

        // Check for dot-separated namespace
        if i < bytes.len() && bytes[i] == b'.' {
            name.push('.');
            i += 1;
        } else {
            break;
        }
    }

    if name.len() > 99 {
        return Err(CryptoError::Provider(format!(
            "property name too long ({} chars, max 99): '{}'",
            name.len(),
            &name[..40]
        )));
    }

    let rest = skip_space(&s[i..]);
    Ok((rest, name))
}

/// Parses a decimal number from the input.
///
/// Uses checked arithmetic to detect overflow per Rule R6 (lossless numeric casts).
/// Returns `(remaining_input, parsed_value)`.
fn parse_decimal(s: &str) -> CryptoResult<(&str, i64)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return Err(CryptoError::Provider(format!(
            "expected decimal digit near: '{}'",
            &s[..s.len().min(20)]
        )));
    }

    let mut v: i64 = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        let digit = i64::from(bytes[i] - b'0');
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| {
                CryptoError::Common(openssl_common::error::CommonError::ArithmeticOverflow {
                    operation: "property number parse",
                })
            })?;
        i += 1;
    }

    // Verify termination: must end with whitespace, NUL equivalent (end), or comma
    if i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b',' && bytes[i] != b'\0' {
        return Err(CryptoError::Provider(format!(
            "unexpected character after decimal number near: '{}'",
            &s[i..s.len().min(i + 20)]
        )));
    }

    let rest = skip_space(&s[i..]);
    Ok((rest, v))
}

/// Parses a hexadecimal number (after the `0x` prefix has been consumed).
///
/// Uses checked arithmetic to detect overflow per Rule R6.
fn parse_hex(s: &str) -> CryptoResult<(&str, i64)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_hexdigit() {
        return Err(CryptoError::Provider(format!(
            "expected hexadecimal digit near: '{}'",
            &s[..s.len().min(20)]
        )));
    }

    let mut v: i64 = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
        let digit = if bytes[i].is_ascii_digit() {
            i64::from(bytes[i] - b'0')
        } else {
            i64::from(bytes[i].to_ascii_lowercase() - b'a' + 10)
        };
        v = v
            .checked_mul(16)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| {
                CryptoError::Common(openssl_common::error::CommonError::ArithmeticOverflow {
                    operation: "property hex number parse",
                })
            })?;
        i += 1;
    }

    if i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b',' && bytes[i] != b'\0' {
        return Err(CryptoError::Provider(format!(
            "unexpected character after hex number near: '{}'",
            &s[i..s.len().min(i + 20)]
        )));
    }

    let rest = skip_space(&s[i..]);
    Ok((rest, v))
}

/// Parses an octal number (after a leading `0` digit with more digits following).
///
/// Uses checked arithmetic to detect overflow per Rule R6.
fn parse_oct(s: &str) -> CryptoResult<(&str, i64)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() || bytes[0] == b'8' || bytes[0] == b'9' {
        return Err(CryptoError::Provider(format!(
            "expected octal digit near: '{}'",
            &s[..s.len().min(20)]
        )));
    }

    let mut v: i64 = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() && bytes[i] != b'8' && bytes[i] != b'9' {
        let digit = i64::from(bytes[i] - b'0');
        v = v
            .checked_mul(8)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| {
                CryptoError::Common(openssl_common::error::CommonError::ArithmeticOverflow {
                    operation: "property octal number parse",
                })
            })?;
        i += 1;
    }

    if i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b',' && bytes[i] != b'\0' {
        return Err(CryptoError::Provider(format!(
            "unexpected character after octal number near: '{}'",
            &s[i..s.len().min(i + 20)]
        )));
    }

    let rest = skip_space(&s[i..]);
    Ok((rest, v))
}

/// Parses a quoted string value (after the opening quote has been consumed).
///
/// The delimiter is the character that opened the string (single or double quote).
fn parse_quoted_string<'a>(
    store: &PropertyStringStore,
    s: &'a str,
    delim: char,
    create: bool,
) -> CryptoResult<(&'a str, PropertyValue)> {
    if let Some(end_pos) = s.find(delim) {
        let value_str = &s[..end_pos];
        if value_str.len() > 999 {
            return Err(CryptoError::Provider(format!(
                "property string value too long ({} chars, max 999)",
                value_str.len()
            )));
        }
        let idx = store.intern_value(value_str, create).ok_or_else(|| {
            CryptoError::Provider(format!("unknown property value: '{value_str}'"))
        })?;
        let rest = skip_space(&s[end_pos + delim.len_utf8()..]);
        Ok((rest, PropertyValue::StringVal(idx)))
    } else {
        Err(CryptoError::Provider(format!(
            "no matching string delimiter '{delim}' near: '{}'",
            &s[..s.len().min(40)]
        )))
    }
}

/// Parses an unquoted string value (e.g., `default`, `yes`, `no`).
fn parse_unquoted_string<'a>(
    store: &PropertyStringStore,
    s: &'a str,
    create: bool,
) -> CryptoResult<(&'a str, PropertyValue)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes[0] == b',' {
        return Err(CryptoError::Provider(
            "empty unquoted string value".to_string(),
        ));
    }

    let mut i = 0;
    let mut buf = String::with_capacity(64);
    while i < bytes.len()
        && bytes[i].is_ascii_graphic()
        && !bytes[i].is_ascii_whitespace()
        && bytes[i] != b','
    {
        buf.push(bytes[i].to_ascii_lowercase() as char);
        i += 1;
    }

    if buf.len() > 999 {
        return Err(CryptoError::Provider(format!(
            "property string value too long ({} chars, max 999)",
            buf.len()
        )));
    }

    let idx = store
        .intern_value(&buf, create)
        .ok_or_else(|| CryptoError::Provider(format!("unknown property value: '{buf}'")))?;

    let rest = skip_space(&s[i..]);
    Ok((rest, PropertyValue::StringVal(idx)))
}

/// Parses a property value from the input.
///
/// Handles: quoted strings, signed numbers, hex (0x), octal (0N), decimal,
/// and unquoted identifier strings. Mirrors `parse_value()` from
/// `property_parse.c` L256-285.
fn parse_value_impl<'a>(
    store: &PropertyStringStore,
    s: &'a str,
    create: bool,
) -> CryptoResult<(&'a str, PropertyType, PropertyValue)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(CryptoError::Provider(
            "unexpected end of input while parsing property value".to_string(),
        ));
    }

    match bytes[0] {
        b'"' | b'\'' => {
            let delim = bytes[0] as char;
            let (rest, val) = parse_quoted_string(store, &s[1..], delim, create)?;
            Ok((rest, PropertyType::String, val))
        }
        b'+' => {
            let (rest, n) = parse_decimal(&s[1..])?;
            Ok((rest, PropertyType::Number, PropertyValue::Number(n)))
        }
        b'-' => {
            let (rest, n) = parse_decimal(&s[1..])?;
            Ok((
                rest,
                PropertyType::Number,
                PropertyValue::Number(n.checked_neg().ok_or_else(|| {
                    CryptoError::Common(openssl_common::error::CommonError::ArithmeticOverflow {
                        operation: "property number negation",
                    })
                })?),
            ))
        }
        b'0' if bytes.len() > 1 && bytes[1] == b'x' => {
            let (rest, n) = parse_hex(&s[2..])?;
            Ok((rest, PropertyType::Number, PropertyValue::Number(n)))
        }
        b'0' if bytes.len() > 1 && bytes[1].is_ascii_digit() => {
            let (rest, n) = parse_oct(&s[1..])?;
            Ok((rest, PropertyType::Number, PropertyValue::Number(n)))
        }
        c if c.is_ascii_digit() => {
            let (rest, n) = parse_decimal(s)?;
            Ok((rest, PropertyType::Number, PropertyValue::Number(n)))
        }
        c if c.is_ascii_alphabetic() => {
            let (rest, val) = parse_unquoted_string(store, s, create)?;
            Ok((rest, PropertyType::String, val))
        }
        _ => Err(CryptoError::Provider(format!(
            "unexpected character '{}' while parsing property value near: '{}'",
            bytes[0] as char,
            &s[..s.len().min(20)]
        ))),
    }
}

/// Builds a sorted [`PropertyList`] from a vector of property definitions.
///
/// Sorts by `name_idx` for binary search, rejects duplicate property names,
/// and records the `has_optional` flag. Mirrors `stack_to_property_list()`
/// in `property_parse.c` L317-349.
fn build_sorted_list(mut defs: Vec<PropertyDefinition>) -> CryptoResult<PropertyList> {
    // Sort by name_idx for binary search (pd_compare in property_parse.c L309-315)
    defs.sort_by_key(|d| d.name_idx);

    // Check for duplicate names (property_parse.c L332-339)
    for window in defs.windows(2) {
        if window[0].name_idx == window[1].name_idx {
            return Err(CryptoError::Provider(format!(
                "duplicate property name index {} in property list",
                window[0].name_idx.0
            )));
        }
    }

    let has_optional = defs.iter().any(|d| d.optional);

    Ok(PropertyList {
        has_optional,
        properties: defs,
    })
}

/// Parses a property definition string into a sorted [`PropertyList`].
///
/// Definition strings are attached to provider implementations and consist of
/// comma-separated `name=value` pairs. A name alone is treated as a boolean
/// property with value `PROPERTY_TRUE`.
///
/// Replaces C `ossl_parse_property()` from `property_parse.c` L355-408.
///
/// # Examples (semantic)
///
/// - `"provider=default,fips=no"` → two definitions, both `Eq`
/// - `"fips"` → one definition: `fips = yes` (boolean shorthand)
/// - `""` → empty list (valid, no properties)
///
/// # Errors
///
/// Returns `Err` on malformed input such as missing names, invalid values,
/// duplicate property names, or identifier overflow.
pub fn parse_definition(store: &PropertyStringStore, defn: &str) -> CryptoResult<PropertyList> {
    let defn = defn.trim();
    if defn.is_empty() {
        debug!("parse_definition: empty definition string");
        return Ok(PropertyList::empty());
    }

    let mut defs = Vec::with_capacity(8);
    let mut remaining = skip_space(defn);

    while !remaining.is_empty() {
        // Parse property name
        let (rest, name) = parse_name_str(remaining)?;
        let name_idx = store.intern_name(&name, true).ok_or_else(|| {
            CryptoError::Provider(format!("failed to intern property name: '{name}'"))
        })?;

        // Check for = operator
        if let Some(after_eq) = match_ch(rest, '=') {
            // Parse value
            let (after_val, prop_type, value) = parse_value_impl(store, after_eq, true)?;
            defs.push(PropertyDefinition {
                name_idx,
                prop_type,
                oper: PropertyOper::Eq,
                optional: false,
                value,
            });
            remaining = after_val;
        } else {
            // Name alone = boolean true (property_parse.c L380-393)
            defs.push(PropertyDefinition {
                name_idx,
                prop_type: PropertyType::String,
                oper: PropertyOper::Eq,
                optional: false,
                value: PropertyValue::StringVal(PROPERTY_TRUE),
            });
            remaining = rest;
        }

        // Consume comma separator if present
        if let Some(after_comma) = match_ch(remaining, ',') {
            remaining = after_comma;
        } else {
            let trimmed = skip_space(remaining);
            if !trimmed.is_empty() {
                return Err(CryptoError::Provider(format!(
                    "unexpected character in definition near: '{}'",
                    &trimmed[..trimmed.len().min(20)]
                )));
            }
            break;
        }
    }

    let list = build_sorted_list(defs)?;
    debug!(
        count = list.properties.len(),
        "parse_definition: parsed property definition"
    );
    Ok(list)
}

/// Parses a property query string into a sorted [`PropertyList`].
///
/// Query strings are specified by API callers for algorithm selection. They
/// support additional syntax not present in definition strings:
/// - `?` prefix for optional properties (no hard-fail on mismatch)
/// - `-` prefix for override properties (used during merge)
/// - `!=` operator for inequality
/// - Missing value means "value is undefined" (`PropertyType::Unspecified`)
///
/// Replaces C `ossl_parse_query()` from `property_parse.c` L414-485.
///
/// # Examples (semantic)
///
/// - `"fips=yes"` → required equality check
/// - `"?provider=default"` → optional equality check
/// - `"-fips"` → override (used in merge)
/// - `"provider!=legacy"` → inequality check
///
/// # Errors
///
/// Returns `Err` on malformed input such as missing names, invalid values,
/// duplicate property names, or identifier overflow.
pub fn parse_query(store: &PropertyStringStore, query: &str) -> CryptoResult<PropertyList> {
    let query = query.trim();
    if query.is_empty() {
        debug!("parse_query: empty query string");
        return Ok(PropertyList::empty());
    }

    let mut defs = Vec::with_capacity(8);
    let mut remaining = skip_space(query);

    while !remaining.is_empty() {
        let mut optional = false;
        let mut oper = PropertyOper::Eq;

        // Check for override prefix '-' (property_parse.c L429-441)
        if let Some(after_minus) = match_ch(remaining, '-') {
            let (rest, name) = parse_name_str(after_minus)?;
            let name_idx = store.intern_name(&name, true).ok_or_else(|| {
                CryptoError::Provider(format!("failed to intern property name: '{name}'"))
            })?;
            defs.push(PropertyDefinition {
                name_idx,
                prop_type: PropertyType::Unspecified,
                oper: PropertyOper::Override,
                optional: false,
                value: PropertyValue::Number(0),
            });
            remaining = rest;
        } else {
            // Check for optional prefix '?' (property_parse.c L444-448)
            if let Some(after_qmark) = match_ch(remaining, '?') {
                optional = true;
                remaining = after_qmark;
            }

            // Parse property name
            let (rest, name) = parse_name_str(remaining)?;
            let name_idx = store.intern_name(&name, true).ok_or_else(|| {
                CryptoError::Provider(format!("failed to intern property name: '{name}'"))
            })?;

            // Check for != operator (property_parse.c L454-462)
            if let Some(after_ne) = match_str(rest, "!=") {
                oper = PropertyOper::Ne;
                let (after_val, prop_type, value) = parse_value_impl(store, after_ne, true)?;
                defs.push(PropertyDefinition {
                    name_idx,
                    prop_type,
                    oper,
                    optional,
                    value,
                });
                remaining = after_val;
            } else if let Some(after_eq) = match_ch(rest, '=') {
                // Equality with value
                let (after_val, prop_type, value) = parse_value_impl(store, after_eq, true)?;
                defs.push(PropertyDefinition {
                    name_idx,
                    prop_type,
                    oper,
                    optional,
                    value,
                });
                remaining = after_val;
            } else {
                // Name alone: value is undefined (property_parse.c L469-480)
                defs.push(PropertyDefinition {
                    name_idx,
                    prop_type: PropertyType::Unspecified,
                    oper,
                    optional,
                    value: PropertyValue::Number(0),
                });
                remaining = rest;
            }
        }

        // Consume comma separator if present
        if let Some(after_comma) = match_ch(remaining, ',') {
            remaining = after_comma;
        } else {
            let trimmed = skip_space(remaining);
            if !trimmed.is_empty() {
                return Err(CryptoError::Provider(format!(
                    "unexpected character in query near: '{}'",
                    &trimmed[..trimmed.len().min(20)]
                )));
            }
            break;
        }
    }

    let list = build_sorted_list(defs)?;
    debug!(
        count = list.properties.len(),
        "parse_query: parsed property query"
    );
    Ok(list)
}

// =============================================================================
// Property Matching — match_count, merge, list_to_string
// =============================================================================

/// Counts the number of matching properties between a query and a definition.
///
/// Returns `Some(count)` if all required properties match, where `count` is
/// the number of matched properties (including optional ones). Returns `None`
/// if any required (non-optional) property fails to match.
///
/// Replaces C `ossl_property_match_count()` from `property_parse.c` L490-542.
/// Uses the sorted order of both lists for efficient parallel traversal.
///
/// The matching algorithm mirrors the C implementation's logic:
/// - Override properties are skipped
/// - If query has a value (`Eq`/`Ne`), it must match the definition's value
/// - If query has no definition entry: for `String` type, compare against `FALSE`
/// - `Unspecified` query values match `Ne` only
/// - Optional properties that fail don't cause an overall mismatch
///
/// Rule R5: Returns `Option<usize>` instead of C's `-1` sentinel for "no match".
pub fn match_count(query: &PropertyList, defn: &PropertyList) -> Option<usize> {
    if query.properties.is_empty() {
        trace!("match_count: empty query, default match");
        return Some(0);
    }

    let mut matches: usize = 0;

    for q in &query.properties {
        // Skip override properties (not used in matching)
        if q.oper == PropertyOper::Override {
            trace!(
                name_idx = q.name_idx.0,
                "match_count: skipping override property"
            );
            continue;
        }

        // Binary search for matching name in definition
        let found = defn
            .properties
            .binary_search_by_key(&q.name_idx, |d| d.name_idx)
            .ok()
            .map(|i| &defn.properties[i]);

        if let Some(d) = found {
            // Definition found — check value match
            let matched = match q.prop_type {
                PropertyType::Unspecified => {
                    // Unspecified query value: NE always matches, EQ never matches
                    q.oper == PropertyOper::Ne
                }
                PropertyType::String | PropertyType::Number => {
                    let values_equal = q.value == d.value;
                    match q.oper {
                        PropertyOper::Eq => values_equal,
                        PropertyOper::Ne => !values_equal,
                        PropertyOper::Override => true,
                    }
                }
            };

            if matched {
                matches = matches.saturating_add(1);
            } else if !q.optional {
                trace!(
                    name_idx = q.name_idx.0,
                    "match_count: required property mismatch"
                );
                return None;
            }
        } else {
            // No definition entry for this query property
            // For string type: compare query against FALSE (property_parse.c L519-536)
            let matched = match q.prop_type {
                PropertyType::Unspecified => {
                    // Missing definition with unspecified value: NE matches
                    q.oper == PropertyOper::Ne
                }
                PropertyType::String => {
                    let query_is_false = q.value == PropertyValue::StringVal(PROPERTY_FALSE);
                    match q.oper {
                        PropertyOper::Eq => query_is_false,
                        PropertyOper::Ne => !query_is_false,
                        PropertyOper::Override => true,
                    }
                }
                PropertyType::Number => {
                    let query_is_zero = q.value == PropertyValue::Number(0);
                    match q.oper {
                        PropertyOper::Eq => query_is_zero,
                        PropertyOper::Ne => !query_is_zero,
                        PropertyOper::Override => true,
                    }
                }
            };

            if matched {
                matches = matches.saturating_add(1);
            } else if !q.optional {
                trace!(
                    name_idx = q.name_idx.0,
                    "match_count: missing required property"
                );
                return None;
            }
        }
    }

    trace!(count = matches, "match_count: computed match score");
    Some(matches)
}

/// Merges two property lists, with the first list taking precedence.
///
/// Replaces C `ossl_property_merge()` from `property_parse.c` L547-572.
/// Both input lists must be sorted by `name_idx`. The output is also sorted.
///
/// On name collision, the first list's definition wins (used for merging
/// global properties with per-algorithm definitions).
pub fn merge(first: &PropertyList, second: &PropertyList) -> PropertyList {
    let mut merged = Vec::with_capacity(first.properties.len() + second.properties.len());

    let mut i = 0;
    let mut j = 0;

    while i < first.properties.len() && j < second.properties.len() {
        let a = &first.properties[i];
        let b = &second.properties[j];

        match a.name_idx.cmp(&b.name_idx) {
            std::cmp::Ordering::Less => {
                // Skip override properties from the first list
                if a.oper != PropertyOper::Override {
                    merged.push(a.clone());
                }
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                merged.push(b.clone());
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                // First list wins on name collision
                if a.oper != PropertyOper::Override {
                    merged.push(a.clone());
                }
                i += 1;
                j += 1;
            }
        }
    }

    // Append remaining from first
    while i < first.properties.len() {
        let a = &first.properties[i];
        if a.oper != PropertyOper::Override {
            merged.push(a.clone());
        }
        i += 1;
    }

    // Append remaining from second
    while j < second.properties.len() {
        merged.push(second.properties[j].clone());
        j += 1;
    }

    let has_optional = merged.iter().any(|d| d.optional);

    PropertyList {
        has_optional,
        properties: merged,
    }
}

/// Serializes a property list back to its canonical string representation.
///
/// Replaces C `ossl_property_list_to_string()` from `property_parse.c` L616-666.
/// Uses the string store to resolve interned indices back to names/values.
pub fn list_to_string(list: &PropertyList, store: &PropertyStringStore) -> String {
    let mut out = String::with_capacity(list.properties.len() * 20);

    for (i, prop) in list.properties.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }

        if prop.optional {
            out.push('?');
        }

        let name = store
            .name_str(prop.name_idx)
            .unwrap_or_else(|| format!("#{}", prop.name_idx.0));

        if prop.oper == PropertyOper::Override {
            out.push('-');
            out.push_str(&name);
            continue;
        }

        out.push_str(&name);

        match prop.oper {
            PropertyOper::Eq => out.push('='),
            PropertyOper::Ne => out.push_str("!="),
            PropertyOper::Override => {} // handled above
        }

        match &prop.value {
            PropertyValue::Number(n) => {
                out.push_str(&n.to_string());
            }
            PropertyValue::StringVal(idx) => {
                let val = store
                    .value_str(*idx)
                    .unwrap_or_else(|| format!("#{}", idx.0));
                out.push_str(&val);
            }
        }
    }

    out
}

// =============================================================================
// Property Query Helpers — find_property, get_string_value, etc.
// =============================================================================

/// Finds a property in a sorted property list by name index.
///
/// Replaces C `ossl_property_find_property()` from `property_query.c` L28-42.
/// Uses binary search over the sorted list for O(log n) lookup.
/// Returns `None` if the property is not found (Rule R5).
pub fn find_property(list: &PropertyList, name_idx: PropertyIndex) -> Option<&PropertyDefinition> {
    let idx = list
        .properties
        .binary_search_by_key(&name_idx, |d| d.name_idx)
        .ok()?;
    trace!(
        name_idx = name_idx.0,
        "find_property: found at index {}",
        idx
    );
    Some(&list.properties[idx])
}

/// Retrieves the string value of a property definition.
///
/// Replaces C `ossl_property_get_string_value()` from `property_query.c` L52-59.
/// Returns `None` if the property is not a string type or the index cannot
/// be resolved (Rule R5).
pub fn get_string_value(defn: &PropertyDefinition, store: &PropertyStringStore) -> Option<String> {
    if defn.prop_type != PropertyType::String {
        return None;
    }
    match &defn.value {
        PropertyValue::StringVal(idx) => store.value_str(*idx),
        PropertyValue::Number(_) => None,
    }
}

/// Retrieves the numeric value of a property definition.
///
/// Replaces C `ossl_property_get_number_value()` from `property_query.c` L61-67.
/// Returns `None` if the property is not a number type (Rule R5).
pub fn get_number_value(defn: &PropertyDefinition) -> Option<i64> {
    if defn.prop_type != PropertyType::Number {
        return None;
    }
    match &defn.value {
        PropertyValue::Number(n) => Some(*n),
        PropertyValue::StringVal(_) => None,
    }
}

/// Checks whether a boolean-like property is considered "enabled" in a list.
///
/// Replaces C `ossl_property_is_enabled()` from `property_query.c` L69-81.
/// A property is enabled if:
/// - It exists and is not optional/override
/// - Its type is String
/// - `Eq` with value `PROPERTY_TRUE` → enabled
/// - `Ne` with value that is NOT `PROPERTY_TRUE` → enabled
///
/// Returns `false` if the property is not found or does not meet the criteria.
pub fn is_enabled(list: &PropertyList, name_idx: PropertyIndex) -> bool {
    let Some(defn) = find_property(list, name_idx) else {
        return false;
    };

    if defn.optional || defn.oper == PropertyOper::Override {
        return false;
    }

    if defn.prop_type != PropertyType::String {
        return false;
    }

    let is_true = defn.value == PropertyValue::StringVal(PROPERTY_TRUE);

    match defn.oper {
        PropertyOper::Eq => is_true,
        PropertyOper::Ne => !is_true,
        PropertyOper::Override => false,
    }
}

// =============================================================================
// DefinitionCache — cached parsed property definitions
// =============================================================================

/// Cache of parsed property definitions keyed by definition string.
///
/// Replaces C `defn_cache.c` per-libctx LHASH cache. Avoids re-parsing
/// the same definition string on every algorithm registration.
///
/// Thread-safe via an internal [`RwLock`]. The cache never evicts — property
/// definition strings are finite (bounded by the set of registered providers)
/// so unbounded growth is not a concern.
pub struct DefinitionCache {
    // LOCK-SCOPE: protects the parsed definition cache — write on first parse,
    // read on subsequent lookups. Very low contention after provider initialization
    // since the set of definition strings is finite.
    cache: RwLock<HashMap<String, PropertyList>>,
}

impl DefinitionCache {
    /// Creates a new empty definition cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Looks up a cached property list by definition string.
    ///
    /// Replaces C `ossl_prop_defn_get()` from `defn_cache.c` L46-63.
    /// Returns `None` on cache miss (Rule R5). The returned list is cloned
    /// since the caller may need to store or modify it independently.
    pub fn get(&self, defn: &str) -> Option<PropertyList> {
        let guard = self.cache.read();
        let result = guard.get(defn).cloned();
        if result.is_some() {
            trace!(defn = %defn, "definition cache hit");
        }
        result
    }

    /// Inserts a parsed property list into the cache.
    ///
    /// Replaces C `ossl_prop_defn_set()` from `defn_cache.c` L66-101.
    /// If an entry for the same definition string already exists, the
    /// existing entry is retained and the new one is ignored (matching
    /// the C double-check pattern).
    pub fn set(&self, defn: &str, list: PropertyList) {
        let mut guard = self.cache.write();
        // Only insert if not already cached (C double-check pattern)
        if !guard.contains_key(defn) {
            debug!(defn = %defn, count = list.properties.len(), "definition cache insert");
            guard.insert(defn.to_string(), list);
        }
    }
}

impl Default for DefinitionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DefinitionCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.cache.read();
        f.debug_struct("DefinitionCache")
            .field("entries", &guard.len())
            .finish()
    }
}

// =============================================================================
// MethodStore — sharded algorithm store with per-algorithm query cache
// =============================================================================

/// A registered algorithm implementation with its property definition.
///
/// Replaces C `IMPLEMENTATION` from `property.c` L52-56. Each implementation
/// is registered by a specific provider with a set of property definitions
/// describing its capabilities (e.g., `provider=default,fips=no`).
#[derive(Debug, Clone)]
pub struct MethodImplementation {
    /// Name of the provider that registered this implementation.
    pub provider_name: String,
    /// Property definitions describing this implementation's capabilities.
    pub properties: PropertyList,
    /// Opaque method handle — the actual algorithm implementation.
    pub method: MethodHandle,
}

/// Opaque handle to a fetched method.
///
/// Replaces C `METHOD` from `property.c` L46-50. In the C implementation,
/// this is a void pointer with `up_ref`/`free` callbacks. In Rust, we use
/// a simple wrapper with `Clone` semantics — the underlying method data
/// is managed by the provider system through shared ownership.
#[derive(Debug, Clone)]
pub struct MethodHandle {
    /// Opaque identifier for the method — used for equality checks.
    id: u64,
}

impl MethodHandle {
    /// Creates a new method handle with the given identifier.
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self { id }
    }

    /// Returns the method's identifier.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// Cached query result entry.
///
/// Replaces C `QUERY` struct from `property.c` L60-66. Stores the resolved
/// method — the query string itself serves as the `HashMap` key in
/// `AlgorithmEntry::query_cache`.
#[derive(Debug, Clone)]
struct CachedQuery {
    /// The resolved method handle.
    method: MethodImplementation,
}

/// Per-algorithm entry holding implementations and query cache.
///
/// Replaces C `ALGORITHM` from `property.c` L69-73. Each NID (algorithm
/// identifier) has a set of implementations from various providers and
/// an LRU-like query result cache. The NID itself is the `HashMap` key in
/// the shard, so it is not stored in the entry.
#[derive(Debug, Clone, Default)]
struct AlgorithmEntry {
    /// All registered implementations for this algorithm, from various providers.
    implementations: Vec<MethodImplementation>,
    /// Per-algorithm query result cache, keyed by canonical query string.
    query_cache: HashMap<String, CachedQuery>,
}

/// Per-shard storage for algorithms.
///
/// Each shard holds a subset of all algorithm entries, partitioned by
/// NID modulo `NUM_SHARDS`. This reduces lock contention compared to a
/// single global lock.
#[derive(Debug, Default)]
struct MethodStoreShard {
    /// Algorithm entries indexed by NID.
    algorithms: HashMap<u32, AlgorithmEntry>,
    /// Total number of cached queries in this shard.
    cache_nelem: usize,
    /// Whether a cache flush is needed.
    cache_need_flush: bool,
}

/// The method store — holds all registered algorithm implementations and query caches.
///
/// Replaces C `ossl_method_store_st` from `property.c` L94+. This is the
/// primary data structure used by the EVP fetch system to find the best
/// algorithm implementation matching a caller's property query.
///
/// ## Locking Strategy (Rule R7)
///
/// Uses sharded locking per Rule R7 for scalability, matching the C
/// implementation's `STORED_ALGORITHMS` sharding strategy (`NUM_SHARDS=4`,
/// `property.c` L31-33). Each shard has its own `RwLock`, so concurrent
/// fetches for algorithms in different shards never contend.
///
/// The `reserve_lock` is a separate coordination lock used during multi-provider
/// construction cycles (the `core_fetch.c` reserve/unreserve pattern).
///
/// The `global_properties` lock stores per-context global property overrides.
pub struct MethodStore {
    /// Sharded algorithm storage for concurrent access.
    // LOCK-SCOPE: per-shard RwLock — write during algorithm registration/cache flush,
    // read during fetch. Sharded into 4 partitions matching C NUM_SHARDS for lock
    // contention reduction. Shard index = nid & (NUM_SHARDS - 1).
    shards: [RwLock<MethodStoreShard>; NUM_SHARDS],

    /// Global store reservation lock for multi-provider construction cycles.
    // LOCK-SCOPE: reserve lock — held during multi-provider construction cycles
    // (core_fetch.c reserve/unreserve pattern). Write-locked during reserve, read
    // access is always available.
    reserve_lock: RwLock<()>,

    /// Global property overrides applied to all fetches.
    // LOCK-SCOPE: global properties — write during set_global_properties(), read
    // during every fetch(). Contention is minimal since global properties are
    // typically set once during initialization.
    global_properties: RwLock<Option<PropertyList>>,
}

impl MethodStore {
    /// Creates a new empty method store with `NUM_SHARDS` partitions.
    ///
    /// Replaces C `ossl_method_store_new()` from `property.c` L125-153.
    #[must_use]
    pub fn new() -> Self {
        debug!("MethodStore created with {} shards", NUM_SHARDS);
        Self {
            shards: [
                RwLock::new(MethodStoreShard::default()),
                RwLock::new(MethodStoreShard::default()),
                RwLock::new(MethodStoreShard::default()),
                RwLock::new(MethodStoreShard::default()),
            ],
            reserve_lock: RwLock::new(()),
            global_properties: RwLock::new(None),
        }
    }

    /// Computes the shard index for a given algorithm NID.
    ///
    /// Uses bitwise AND with `(NUM_SHARDS - 1)` for efficient modulo
    /// on power-of-two shard counts (matching C `stored_algs_shard` macro,
    /// `property.c` L104-105).
    fn shard_index(nid: u32) -> usize {
        (nid as usize) & (NUM_SHARDS - 1)
    }

    /// Registers an algorithm implementation with the method store.
    ///
    /// Replaces C `ossl_method_store_add()` from `property.c` L261-345.
    /// The implementation is associated with the given NID and its property
    /// definitions are used for subsequent query matching.
    ///
    /// Rejects duplicate registrations (same provider + identical property
    /// definitions) to prevent accidental double-registration.
    ///
    /// Flushes the per-algorithm query cache for the affected NID since
    /// a new implementation may change fetch results.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the NID is zero (invalid) or a duplicate is detected.
    pub fn add_implementation(
        &self,
        nid: u32,
        impl_entry: MethodImplementation,
    ) -> CryptoResult<()> {
        if nid == 0 {
            return Err(CryptoError::Provider(
                "cannot register implementation with NID 0".to_string(),
            ));
        }

        let shard_idx = Self::shard_index(nid);
        let mut shard = self.shards[shard_idx].write();

        // Ensure algorithm entry exists using the entry API
        let entry = shard.algorithms.entry(nid).or_default();

        // Check for duplicate provider + properties (property.c L308-320)
        for existing in &entry.implementations {
            if existing.provider_name == impl_entry.provider_name
                && existing.properties == impl_entry.properties
            {
                warn!(
                    nid = nid,
                    provider = %impl_entry.provider_name,
                    "duplicate implementation registration rejected"
                );
                return Err(CryptoError::Provider(format!(
                    "duplicate implementation for NID {} from provider '{}'",
                    nid, impl_entry.provider_name
                )));
            }
        }

        // Flush query cache for this algorithm (new impl may change results)
        let flushed = entry.query_cache.len();
        entry.query_cache.clear();

        let impl_count = entry.implementations.len() + 1;
        let provider = impl_entry.provider_name.clone();
        entry.implementations.push(impl_entry);

        // Update shard-level cache counter after releasing entry borrow
        shard.cache_nelem = shard.cache_nelem.saturating_sub(flushed);

        debug!(
            nid = nid,
            provider = %provider,
            props = impl_count,
            "registered algorithm implementation"
        );

        Ok(())
    }

    /// Fetches the best matching implementation for a given algorithm NID.
    ///
    /// Replaces C `ossl_method_store_fetch()` from `property.c` L700-800.
    /// The fetch algorithm:
    /// 1. Checks the per-algorithm query cache first
    /// 2. Merges the query with global properties (if any)
    /// 3. Scans all implementations, scoring each via `match_count()`
    /// 4. Returns the implementation with the highest match score
    /// 5. Caches the result for subsequent identical queries
    ///
    /// If `query` is `None`, returns the first registered implementation
    /// (matching the C behavior for NULL property query).
    ///
    /// Rule R5: Returns `Ok(None)` instead of a sentinel for "no match".
    ///
    /// # Errors
    ///
    /// Returns `Err` if the NID is zero (invalid).
    pub fn fetch(
        &self,
        nid: u32,
        query: &PropertyList,
        global_props: Option<&PropertyList>,
        store: &PropertyStringStore,
    ) -> CryptoResult<Option<MethodImplementation>> {
        if nid == 0 {
            return Err(CryptoError::Provider(
                "cannot fetch implementation with NID 0".to_string(),
            ));
        }

        let shard_idx = Self::shard_index(nid);
        let query_key = list_to_string(query, store);

        // Fast path: check cache under read lock
        {
            let shard = self.shards[shard_idx].read();
            if let Some(entry) = shard.algorithms.get(&nid) {
                if let Some(cached) = entry.query_cache.get(&query_key) {
                    trace!(nid = nid, query = %query_key, "method store cache hit");
                    return Ok(Some(cached.method.clone()));
                }
            } else {
                return Ok(None);
            }
        }

        // Slow path: scan implementations under read lock
        let shard = self.shards[shard_idx].read();
        let Some(entry) = shard.algorithms.get(&nid) else {
            return Ok(None);
        };

        // If query is empty, return first implementation (C behavior for NULL query)
        if query.properties.is_empty() {
            let result = entry.implementations.first().cloned();
            return Ok(result);
        }

        // Merge query with global properties if present
        let merged_query;
        let effective_query = if let Some(gp) = global_props {
            merged_query = merge(query, gp);
            &merged_query
        } else {
            query
        };

        // Scan implementations for best match
        let mut best: Option<&MethodImplementation> = None;
        let mut best_score: usize = 0;

        for imp in &entry.implementations {
            if let Some(score) = match_count(effective_query, &imp.properties) {
                if score > best_score || best.is_none() {
                    best_score = score;
                    best = Some(imp);
                }
            }
        }

        let result = best.cloned();

        // Drop the read lock before acquiring write lock for cache insert
        drop(shard);

        // Cache the result if found
        if let Some(ref method) = result {
            let mut shard = self.shards[shard_idx].write();

            // Stochastic cache eviction if cache is too full
            let need_eviction = shard.cache_nelem >= CACHE_FLUSH_THRESHOLD;
            if need_eviction {
                Self::evict_cache_entries_impl(&mut shard);
            }

            if let Some(entry) = shard.algorithms.get_mut(&nid) {
                if !entry.query_cache.contains_key(&query_key) {
                    entry.query_cache.insert(
                        query_key.clone(),
                        CachedQuery {
                            method: method.clone(),
                        },
                    );
                    shard.cache_nelem = shard.cache_nelem.saturating_add(1);
                    trace!(nid = nid, query = %query_key, "method store cache insert");
                }
            }
        }

        Ok(result)
    }

    /// Performs stochastic cache eviction within a shard.
    ///
    /// Mirrors the C implementation's xorshift PRNG-based eviction
    /// (property.c L668-694). Removes a fraction of cache entries
    /// to prevent unbounded growth.
    fn evict_cache_entries_impl(shard: &mut MethodStoreShard) {
        let target = shard.cache_nelem / 4;
        let mut evicted: usize = 0;

        for entry in shard.algorithms.values_mut() {
            if evicted >= target {
                break;
            }
            let to_remove = entry.query_cache.len() / 4;
            if to_remove > 0 {
                let keys_to_remove: Vec<String> =
                    entry.query_cache.keys().take(to_remove).cloned().collect();
                for key in keys_to_remove {
                    entry.query_cache.remove(&key);
                    evicted = evicted.saturating_add(1);
                }
            }
        }

        shard.cache_nelem = shard.cache_nelem.saturating_sub(evicted);
        shard.cache_need_flush = false;
        debug!(
            evicted = evicted,
            remaining = shard.cache_nelem,
            "cache eviction complete"
        );
    }

    /// Flushes all query caches across all shards.
    ///
    /// Replaces C `ossl_method_store_cache_flush_all()` from `property.c`.
    /// Called when a provider is loaded/unloaded or global properties change,
    /// invalidating all cached query results.
    pub fn flush_cache(&self) {
        for (i, shard_lock) in self.shards.iter().enumerate() {
            let mut shard = shard_lock.write();
            let mut flushed: usize = 0;
            for entry in shard.algorithms.values_mut() {
                flushed = flushed.saturating_add(entry.query_cache.len());
                entry.query_cache.clear();
            }
            shard.cache_nelem = 0;
            shard.cache_need_flush = false;
            trace!(shard = i, flushed = flushed, "shard cache flushed");
        }
        debug!("all method store caches flushed");
    }

    /// Removes all implementations from a specific provider.
    ///
    /// Called when a provider is unloaded. Removes all implementations
    /// registered by the named provider across all shards and flushes
    /// affected query caches.
    pub fn remove_by_provider(&self, provider_name: &str) {
        let mut total_removed: usize = 0;

        for (i, shard_lock) in self.shards.iter().enumerate() {
            let mut shard = shard_lock.write();
            let mut shard_removed: usize = 0;
            let mut cache_flushed: usize = 0;

            // First pass: remove implementations and track cache flush needs
            for entry in shard.algorithms.values_mut() {
                let before = entry.implementations.len();
                entry
                    .implementations
                    .retain(|imp| imp.provider_name != provider_name);
                let removed = before - entry.implementations.len();
                if removed > 0 {
                    shard_removed = shard_removed.saturating_add(removed);
                    // Flush cache for affected algorithms
                    cache_flushed = cache_flushed.saturating_add(entry.query_cache.len());
                    entry.query_cache.clear();
                }
            }

            // Update shard-level cache counter
            shard.cache_nelem = shard.cache_nelem.saturating_sub(cache_flushed);

            // Remove empty algorithm entries
            shard
                .algorithms
                .retain(|_, entry| !entry.implementations.is_empty());

            total_removed = total_removed.saturating_add(shard_removed);
            trace!(
                shard = i,
                removed = shard_removed,
                "removed provider implementations from shard"
            );
        }

        debug!(
            provider = %provider_name,
            removed = total_removed,
            "removed all implementations for provider"
        );
    }
}

impl Default for MethodStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MethodStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut total_algorithms = 0;
        let mut total_implementations = 0;
        let mut total_cache_entries = 0;

        for shard_lock in &self.shards {
            let shard = shard_lock.read();
            total_algorithms += shard.algorithms.len();
            for entry in shard.algorithms.values() {
                total_implementations += entry.implementations.len();
                total_cache_entries += entry.query_cache.len();
            }
        }

        // Check whether the reserve lock is currently held
        let reserve_active = self.reserve_lock.try_read().is_none();
        let has_global_props = self.global_properties.read().is_some();

        f.debug_struct("MethodStore")
            .field("shards", &NUM_SHARDS)
            .field("algorithms", &total_algorithms)
            .field("implementations", &total_implementations)
            .field("cache_entries", &total_cache_entries)
            .field("reserve_active", &reserve_active)
            .field("has_global_properties", &has_global_props)
            .finish()
    }
}

// =============================================================================
// Global Properties — per-context property overrides
// =============================================================================

/// Sets global property overrides on a method store.
///
/// Replaces C `ossl_method_store_set_global_properties()` from `property.c`.
/// Global properties are merged with per-query properties during every
/// `fetch()` call, allowing context-wide defaults (e.g., `"fips=yes"`
/// to force FIPS-only algorithm selection).
///
/// Setting global properties flushes all query caches since cached results
/// may no longer be valid.
///
/// # Errors
///
/// Returns `Err` if the property string cannot be parsed.
pub fn set_global_properties(
    method_store: &MethodStore,
    str_store: &PropertyStringStore,
    props: &str,
) -> CryptoResult<()> {
    let parsed = parse_definition(str_store, props)?;

    {
        let mut guard = method_store.global_properties.write();
        *guard = Some(parsed);
    }

    // Flush all caches since global properties affect all fetches
    method_store.flush_cache();

    debug!(props = %props, "global properties set");
    Ok(())
}

/// Gets the current global property overrides from a method store.
///
/// Replaces C access to the `OSSL_GLOBAL_PROPERTIES` structure.
/// Returns `None` if no global properties have been set (Rule R5).
#[must_use]
pub fn get_global_properties(method_store: &MethodStore) -> Option<PropertyList> {
    let guard = method_store.global_properties.read();
    guard.clone()
}

// =============================================================================
// Display implementations for key types
// =============================================================================

impl fmt::Display for PropertyDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.optional {
            f.write_str("?")?;
        }
        if self.oper == PropertyOper::Override {
            write!(f, "-#{}", self.name_idx.0)?;
        } else {
            write!(f, "#{}", self.name_idx.0)?;
            write!(f, "{}", self.oper)?;
            match &self.value {
                PropertyValue::Number(n) => write!(f, "{n}")?,
                PropertyValue::StringVal(idx) => write!(f, "#{}", idx.0)?,
            }
        }
        Ok(())
    }
}

impl fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::StringVal(idx) => write!(f, "#{}", idx.0),
        }
    }
}

impl fmt::Display for PropertyIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
