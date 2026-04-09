//! # Predefined (Built-in) Provider Registry
//!
//! Translates `crypto/provider_predefined.c` and `crypto/provider_local.h` into Rust.
//! Defines the list of providers that are built into the library and can be loaded
//! without external shared library files.
//!
//! ## Source Mapping
//!
//! | Rust Type | C Source | C Lines |
//! |-----------|----------|---------|
//! | `ProviderInfo` | `OSSL_PROVIDER_INFO` in `provider_local.h` L18-24 | 7 |
//! | `InfoPair` | `INFOPAIR` in `provider_local.h` L12-15 | 4 |
//! | `predefined_providers()` | `ossl_predefined_providers[]` in `provider_predefined.c` L20-32 | 12 |
//! | `ProviderKind` | `OSSL_provider_init_fn *init` pointers in `provider_predefined.c` L13-18 | 6 |
//!
//! ## Built-in Providers
//!
//! The C `ossl_predefined_providers[]` array (`provider_predefined.c` L20-32) registers:
//! - **default** — The default provider (most algorithms), fallback-capable
//! - **base** — Base provider (encoders/decoders only), not a fallback
//! - **null** — Null provider (no-op sentinel), not a fallback
//! - **legacy** — Legacy algorithms (MD2, DES, etc.), conditionally compiled (`STATIC_LEGACY`)
//! - **fips** — FIPS provider (FIPS module build only, `FIPS_MODULE`)
//!
//! In Rust, the init function pointers are replaced by [`ProviderKind`] enum variants,
//! which the provider loading system dispatches to the appropriate Rust provider crate.
//! This eliminates the need for `unsafe` function pointer calls entirely.
//!
//! ## Feature Flag Mapping
//!
//! | C Preprocessor | Rust Feature | Effect |
//! |----------------|-------------|--------|
//! | `FIPS_MODULE` | `fips_module` | Only the FIPS provider is predefined |
//! | `STATIC_LEGACY` | `static_legacy` | Include legacy provider in non-FIPS builds |
//!
//! ## Wiring (Rule R10)
//!
//! Reachable via: `ProviderStore::new()` → `predefined_providers()` → provider initialization path.
//! Also reachable via: `ProviderStore::activate_fallbacks()` → `predefined_providers()`.

use std::fmt;

// ---------------------------------------------------------------------------
// InfoPair — name-value parameter pair
// ---------------------------------------------------------------------------

/// A name-value parameter pair for provider configuration.
///
/// Replaces C `INFOPAIR` from `provider_local.h` L12-15:
/// ```c
/// typedef struct {
///     char *name;
///     char *value;
/// } INFOPAIR;
/// ```
///
/// Used to attach configuration parameters to a [`ProviderInfo`] entry.
/// For example, a provider loaded via config file may have parameters like
/// `("module", "/usr/lib/ossl-modules/fips.so")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoPair {
    /// Parameter name (e.g., `"module"`, `"activate"`)
    pub name: String,
    /// Parameter value (e.g., `"/usr/lib/ossl-modules/fips.so"`, `"1"`)
    pub value: String,
}

impl InfoPair {
    /// Creates a new `InfoPair` from the given name and value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use openssl_crypto::provider::predefined::InfoPair;
    /// let pair = InfoPair::new("module", "/usr/lib/ossl-modules/fips.so");
    /// assert_eq!(pair.name, "module");
    /// assert_eq!(pair.value, "/usr/lib/ossl-modules/fips.so");
    /// ```
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

impl fmt::Display for InfoPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

// ---------------------------------------------------------------------------
// ProviderKind — enum replacing C function pointers
// ---------------------------------------------------------------------------

/// Identifies which built-in provider implementation to load.
///
/// Replaces C `OSSL_provider_init_fn *init` function pointers from
/// `provider_predefined.c` L13-18. By using an enum instead of function
/// pointers, we avoid all `unsafe` code in the predefined provider registry.
///
/// The provider loading system matches on this enum to dispatch to the
/// appropriate Rust provider crate implementation.
///
/// ## Variant Mapping
///
/// | Variant | C Init Function | C Source |
/// |---------|----------------|----------|
/// | `Default` | `ossl_default_provider_init` | `provider_predefined.c` L13 |
/// | `Base` | `ossl_base_provider_init` | `provider_predefined.c` L14 |
/// | `Null` | `ossl_null_provider_init` | `provider_predefined.c` L15 |
/// | `Fips` | `ossl_fips_intern_provider_init` | `provider_predefined.c` L16 |
/// | `Legacy` | `ossl_legacy_provider_init` | `provider_predefined.c` L18 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    /// Default provider — most algorithms, implemented by `openssl-provider` crate.
    /// Replaces C `ossl_default_provider_init` (`provider_predefined.c` L13).
    Default,
    /// Base provider — encoders/decoders only.
    /// Replaces C `ossl_base_provider_init` (`provider_predefined.c` L14).
    Base,
    /// Null provider — no-op sentinel, provides no algorithms.
    /// Replaces C `ossl_null_provider_init` (`provider_predefined.c` L15).
    Null,
    /// Legacy provider — MD2, DES, and other deprecated algorithms.
    /// Replaces C `ossl_legacy_provider_init` (`provider_predefined.c` L18, `STATIC_LEGACY`).
    Legacy,
    /// FIPS provider — FIPS 140 certified algorithms only.
    /// Replaces C `ossl_fips_intern_provider_init` (`provider_predefined.c` L16).
    Fips,
}

impl ProviderKind {
    /// Returns the canonical string name for this provider kind.
    ///
    /// This matches the name field used in the C `ossl_predefined_providers[]`
    /// array entries and is used for display, logging, and lookup purposes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use openssl_crypto::provider::predefined::ProviderKind;
    /// assert_eq!(ProviderKind::Default.as_str(), "default");
    /// assert_eq!(ProviderKind::Fips.as_str(), "fips");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Base => "base",
            Self::Null => "null",
            Self::Legacy => "legacy",
            Self::Fips => "fips",
        }
    }

    /// Returns an iterator over all possible `ProviderKind` variants.
    ///
    /// Useful for exhaustive operations across all provider kinds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use openssl_crypto::provider::predefined::ProviderKind;
    /// let all_kinds: Vec<_> = ProviderKind::all().collect();
    /// assert_eq!(all_kinds.len(), 5);
    /// ```
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Default,
            Self::Base,
            Self::Null,
            Self::Legacy,
            Self::Fips,
        ]
        .into_iter()
    }

    /// Attempts to parse a provider kind from a canonical name string.
    ///
    /// Returns `None` if the name does not match any known provider kind.
    /// This is the inverse of [`ProviderKind::as_str()`].
    ///
    /// # Rule R5 (Nullability over Sentinels)
    ///
    /// Returns `Option<ProviderKind>` instead of a sentinel value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use openssl_crypto::provider::predefined::ProviderKind;
    /// assert_eq!(ProviderKind::from_name("default"), Some(ProviderKind::Default));
    /// assert_eq!(ProviderKind::from_name("unknown"), None);
    /// ```
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "default" => Some(Self::Default),
            "base" => Some(Self::Base),
            "null" => Some(Self::Null),
            "legacy" => Some(Self::Legacy),
            "fips" => Some(Self::Fips),
            _ => None,
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ProviderInfo — predefined provider metadata
// ---------------------------------------------------------------------------

/// Information about a predefined (built-in) provider.
///
/// Replaces C `OSSL_PROVIDER_INFO` from `provider_local.h` L18-24:
/// ```c
/// typedef struct {
///     char *name;
///     char *path;
///     OSSL_provider_init_fn *init;
///     STACK_OF(INFOPAIR) *parameters;
///     unsigned int is_fallback : 1;
/// } OSSL_PROVIDER_INFO;
/// ```
///
/// ## Design Decisions
///
/// - `path` uses `Option<String>` instead of a `NULL` pointer (Rule R5).
/// - `kind` uses [`ProviderKind`] enum instead of a function pointer (Rule R8).
/// - `parameters` uses `Vec<InfoPair>` instead of `STACK_OF(INFOPAIR)`.
/// - `is_fallback` uses `bool` instead of a bitfield.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Provider name (e.g., `"default"`, `"fips"`, `"legacy"`, `"base"`, `"null"`).
    ///
    /// This is the identifier used for provider lookup and display. It matches
    /// the name field in the C `ossl_predefined_providers[]` array.
    pub name: String,

    /// Optional filesystem path to shared library.
    ///
    /// `None` for built-in providers (all predefined providers have `path = None`).
    /// `Some(path)` for externally-loaded providers specified via configuration.
    ///
    /// Rule R5: Uses `Option<String>` instead of empty string or `NULL` sentinel.
    pub path: Option<String>,

    /// Which built-in provider implementation this maps to.
    ///
    /// Replaces the C `OSSL_provider_init_fn *init` function pointer.
    /// The provider loading system dispatches on this enum to select the
    /// appropriate Rust provider crate implementation.
    pub kind: ProviderKind,

    /// Configuration parameters (name-value pairs).
    ///
    /// Empty for predefined providers by default. Parameters are added via
    /// [`info_add_parameter()`] when providers are configured through config files.
    /// Replaces C `STACK_OF(INFOPAIR) *parameters`.
    pub parameters: Vec<InfoPair>,

    /// Whether this provider is a fallback.
    ///
    /// Fallback providers are loaded automatically if no other provider is
    /// explicitly loaded. In the C source, the default provider (non-FIPS build)
    /// and the FIPS provider (FIPS build) have `is_fallback = 1`.
    ///
    /// Replaces C `unsigned int is_fallback : 1;` (`provider_local.h` L23).
    pub is_fallback: bool,
}

impl ProviderInfo {
    /// Creates a new `ProviderInfo` with the given name and kind.
    ///
    /// All other fields are set to their defaults: no path, no parameters,
    /// and not a fallback. Use the builder-style setters to customize.
    ///
    /// # Examples
    ///
    /// ```
    /// # use openssl_crypto::provider::predefined::{ProviderInfo, ProviderKind};
    /// let info = ProviderInfo::new("custom", ProviderKind::Default);
    /// assert_eq!(info.name, "custom");
    /// assert_eq!(info.kind, ProviderKind::Default);
    /// assert!(!info.is_fallback);
    /// ```
    pub fn new(name: &str, kind: ProviderKind) -> Self {
        Self {
            name: name.to_string(),
            path: None,
            kind,
            parameters: Vec::new(),
            is_fallback: false,
        }
    }

    /// Sets the filesystem path for this provider info entry.
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    /// Sets the fallback flag for this provider info entry.
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_fallback(mut self, is_fallback: bool) -> Self {
        self.is_fallback = is_fallback;
        self
    }

    /// Adds a configuration parameter to this provider info entry.
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_parameter(mut self, name: &str, value: &str) -> Self {
        self.parameters.push(InfoPair::new(name, value));
        self
    }
}

impl fmt::Display for ProviderInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Provider(name={}, kind={}", self.name, self.kind)?;
        if let Some(ref path) = self.path {
            write!(f, ", path={path}")?;
        }
        if self.is_fallback {
            f.write_str(", fallback")?;
        }
        if !self.parameters.is_empty() {
            write!(f, ", params=[{}]", self.parameters.len())?;
        }
        f.write_str(")")
    }
}

// ---------------------------------------------------------------------------
// Predefined provider list
// ---------------------------------------------------------------------------

/// Returns the list of predefined (built-in) providers.
///
/// Replaces C `ossl_predefined_providers[]` from `provider_predefined.c` L20-32.
///
/// The list varies by build configuration:
/// - **Normal build** (`!fips_module`): default (fallback), base, null, and optionally legacy
/// - **FIPS module build** (`fips_module`): fips only (fallback)
///
/// ## Feature Flag Behavior
///
/// | Feature | Effect |
/// |---------|--------|
/// | `fips_module` | Only the FIPS provider is returned (with `is_fallback = true`) |
/// | `static_legacy` | Legacy provider is included in non-FIPS builds |
/// | Neither | Default (fallback), base, null providers are returned |
///
/// ## C Source Reference
///
/// ```c
/// // provider_predefined.c L20-32
/// const OSSL_PROVIDER_INFO ossl_predefined_providers[] = {
/// #ifdef FIPS_MODULE
///     { "fips", NULL, ossl_fips_intern_provider_init, NULL, 1 },
/// #else
///     { "default", NULL, ossl_default_provider_init, NULL, 1 },
/// #ifdef STATIC_LEGACY
///     { "legacy", NULL, ossl_legacy_provider_init, NULL, 0 },
/// #endif
///     { "base", NULL, ossl_base_provider_init, NULL, 0 },
///     { "null", NULL, ossl_null_provider_init, NULL, 0 },
/// #endif
///     { NULL, NULL, NULL, NULL, 0 }
/// };
/// ```
pub fn predefined_providers() -> Vec<ProviderInfo> {
    let mut providers = Vec::new();

    #[cfg(feature = "fips_module")]
    {
        // FIPS module build: only the FIPS provider is predefined.
        // C: { "fips", NULL, ossl_fips_intern_provider_init, NULL, 1 }
        // (provider_predefined.c L22)
        providers.push(ProviderInfo {
            name: "fips".to_string(),
            path: None,
            kind: ProviderKind::Fips,
            parameters: Vec::new(),
            is_fallback: true,
        });
    }

    #[cfg(not(feature = "fips_module"))]
    {
        // Normal build: default provider is the fallback.
        // C: { "default", NULL, ossl_default_provider_init, NULL, 1 }
        // (provider_predefined.c L24)
        providers.push(ProviderInfo {
            name: "default".to_string(),
            path: None,
            kind: ProviderKind::Default,
            parameters: Vec::new(),
            is_fallback: true, // C: is_fallback = 1 (provider_predefined.c L24)
        });

        // Legacy provider: only included when statically linked.
        // C: { "legacy", NULL, ossl_legacy_provider_init, NULL, 0 }
        // (provider_predefined.c L26, guarded by #ifdef STATIC_LEGACY)
        #[cfg(feature = "static_legacy")]
        {
            providers.push(ProviderInfo {
                name: "legacy".to_string(),
                path: None,
                kind: ProviderKind::Legacy,
                parameters: Vec::new(),
                is_fallback: false, // C: is_fallback = 0 (provider_predefined.c L26)
            });
        }

        // Base provider: encoders/decoders only, not a fallback.
        // C: { "base", NULL, ossl_base_provider_init, NULL, 0 }
        // (provider_predefined.c L28)
        providers.push(ProviderInfo {
            name: "base".to_string(),
            path: None,
            kind: ProviderKind::Base,
            parameters: Vec::new(),
            is_fallback: false, // C: is_fallback = 0 (provider_predefined.c L28)
        });

        // Null provider: no-op sentinel, not a fallback.
        // C: { "null", NULL, ossl_null_provider_init, NULL, 0 }
        // (provider_predefined.c L29)
        providers.push(ProviderInfo {
            name: "null".to_string(),
            path: None,
            kind: ProviderKind::Null,
            parameters: Vec::new(),
            is_fallback: false, // C: is_fallback = 0 (provider_predefined.c L29)
        });
    }

    providers
}

// ---------------------------------------------------------------------------
// Provider info management functions
// ---------------------------------------------------------------------------

/// Adds a configuration parameter to a [`ProviderInfo`] entry.
///
/// Replaces C `ossl_provider_info_add_parameter()` from `provider_local.h` L31-33:
/// ```c
/// int ossl_provider_info_add_parameter(OSSL_PROVIDER_INFO *provinfo,
///     const char *name, const char *value);
/// ```
///
/// This function appends a name-value pair to the provider's parameter list.
/// Parameters are used during provider initialization to pass configuration
/// values (e.g., module path, activation flags).
///
/// # Examples
///
/// ```
/// # use openssl_crypto::provider::predefined::{ProviderInfo, ProviderKind, info_add_parameter};
/// let mut info = ProviderInfo::new("fips", ProviderKind::Fips);
/// info_add_parameter(&mut info, "module", "/usr/lib/ossl-modules/fips.so");
/// info_add_parameter(&mut info, "activate", "1");
/// assert_eq!(info.parameters.len(), 2);
/// assert_eq!(info.parameters[0].name, "module");
/// assert_eq!(info.parameters[1].value, "1");
/// ```
pub fn info_add_parameter(info: &mut ProviderInfo, name: &str, value: &str) {
    info.parameters.push(InfoPair::new(name, value));
}

/// Looks up a predefined provider by name.
///
/// Searches the list returned by [`predefined_providers()`] for a provider
/// whose name matches the given string (case-sensitive comparison, matching
/// the C implementation's `strcmp()` behavior).
///
/// # Rule R5 (Nullability over Sentinels)
///
/// Returns `Option<ProviderInfo>` instead of a `NULL` pointer or error code.
///
/// # Examples
///
/// ```
/// # use openssl_crypto::provider::predefined::{find_by_name, ProviderKind};
/// let info = find_by_name("default");
/// assert!(info.is_some());
/// let info = info.unwrap();
/// assert_eq!(info.kind, ProviderKind::Default);
/// assert!(info.is_fallback);
///
/// assert!(find_by_name("nonexistent").is_none());
/// ```
#[must_use]
pub fn find_by_name(name: &str) -> Option<ProviderInfo> {
    predefined_providers().into_iter().find(|p| p.name == name)
}

/// Checks if a name corresponds to a predefined (built-in) provider.
///
/// This is a convenience function that returns `true` if the given name
/// matches any provider in the predefined list for the current build
/// configuration.
///
/// # Examples
///
/// ```
/// # use openssl_crypto::provider::predefined::is_predefined;
/// assert!(is_predefined("default"));
/// assert!(is_predefined("base"));
/// assert!(is_predefined("null"));
/// assert!(!is_predefined("custom"));
/// assert!(!is_predefined(""));
/// ```
#[must_use]
pub fn is_predefined(name: &str) -> bool {
    predefined_providers().iter().any(|p| p.name == name)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // InfoPair tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_info_pair_new() {
        let pair = InfoPair::new("module", "/usr/lib/fips.so");
        assert_eq!(pair.name, "module");
        assert_eq!(pair.value, "/usr/lib/fips.so");
    }

    #[test]
    fn test_info_pair_equality() {
        let a = InfoPair::new("key", "value");
        let b = InfoPair::new("key", "value");
        let c = InfoPair::new("key", "other");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_info_pair_clone() {
        let original = InfoPair::new("name", "val");
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_info_pair_display() {
        let pair = InfoPair::new("module", "/path/to/fips.so");
        assert_eq!(format!("{pair}"), "module=/path/to/fips.so");
    }

    #[test]
    fn test_info_pair_debug() {
        let pair = InfoPair::new("key", "val");
        let debug = format!("{pair:?}");
        assert!(debug.contains("InfoPair"));
        assert!(debug.contains("key"));
        assert!(debug.contains("val"));
    }

    // -----------------------------------------------------------------------
    // ProviderKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_kind_display() {
        assert_eq!(format!("{}", ProviderKind::Default), "default");
        assert_eq!(format!("{}", ProviderKind::Base), "base");
        assert_eq!(format!("{}", ProviderKind::Null), "null");
        assert_eq!(format!("{}", ProviderKind::Legacy), "legacy");
        assert_eq!(format!("{}", ProviderKind::Fips), "fips");
    }

    #[test]
    fn test_provider_kind_as_str() {
        assert_eq!(ProviderKind::Default.as_str(), "default");
        assert_eq!(ProviderKind::Base.as_str(), "base");
        assert_eq!(ProviderKind::Null.as_str(), "null");
        assert_eq!(ProviderKind::Legacy.as_str(), "legacy");
        assert_eq!(ProviderKind::Fips.as_str(), "fips");
    }

    #[test]
    fn test_provider_kind_from_name_valid() {
        assert_eq!(
            ProviderKind::from_name("default"),
            Some(ProviderKind::Default)
        );
        assert_eq!(ProviderKind::from_name("base"), Some(ProviderKind::Base));
        assert_eq!(ProviderKind::from_name("null"), Some(ProviderKind::Null));
        assert_eq!(
            ProviderKind::from_name("legacy"),
            Some(ProviderKind::Legacy)
        );
        assert_eq!(ProviderKind::from_name("fips"), Some(ProviderKind::Fips));
    }

    #[test]
    fn test_provider_kind_from_name_invalid() {
        assert_eq!(ProviderKind::from_name(""), None);
        assert_eq!(ProviderKind::from_name("unknown"), None);
        assert_eq!(ProviderKind::from_name("Default"), None); // Case-sensitive
        assert_eq!(ProviderKind::from_name("FIPS"), None);
    }

    #[test]
    fn test_provider_kind_all() {
        let all: Vec<_> = ProviderKind::all().collect();
        assert_eq!(all.len(), 5);
        assert!(all.contains(&ProviderKind::Default));
        assert!(all.contains(&ProviderKind::Base));
        assert!(all.contains(&ProviderKind::Null));
        assert!(all.contains(&ProviderKind::Legacy));
        assert!(all.contains(&ProviderKind::Fips));
    }

    #[test]
    fn test_provider_kind_copy() {
        let kind = ProviderKind::Default;
        let copied = kind;
        assert_eq!(kind, copied);
    }

    #[test]
    fn test_provider_kind_hash() {
        use std::collections::HashMap;
        let mut map: HashMap<ProviderKind, &str> = HashMap::new();
        map.insert(ProviderKind::Default, "default provider");
        map.insert(ProviderKind::Fips, "fips provider");
        assert_eq!(map.get(&ProviderKind::Default), Some(&"default provider"));
        assert_eq!(map.get(&ProviderKind::Fips), Some(&"fips provider"));
        assert_eq!(map.get(&ProviderKind::Null), None);
    }

    #[test]
    fn test_provider_kind_roundtrip() {
        // Verify as_str() and from_name() are inverses for all variants.
        for kind in ProviderKind::all() {
            let name = kind.as_str();
            let parsed = ProviderKind::from_name(name);
            assert_eq!(parsed, Some(kind), "roundtrip failed for {kind}");
        }
    }

    // -----------------------------------------------------------------------
    // ProviderInfo tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_info_new() {
        let info = ProviderInfo::new("test", ProviderKind::Default);
        assert_eq!(info.name, "test");
        assert_eq!(info.kind, ProviderKind::Default);
        assert!(info.path.is_none());
        assert!(info.parameters.is_empty());
        assert!(!info.is_fallback);
    }

    #[test]
    fn test_provider_info_with_path() {
        let info =
            ProviderInfo::new("custom", ProviderKind::Legacy).with_path("/usr/lib/custom.so");
        assert_eq!(info.path, Some("/usr/lib/custom.so".to_string()));
    }

    #[test]
    fn test_provider_info_with_fallback() {
        let info = ProviderInfo::new("default", ProviderKind::Default).with_fallback(true);
        assert!(info.is_fallback);
    }

    #[test]
    fn test_provider_info_with_parameter() {
        let info = ProviderInfo::new("fips", ProviderKind::Fips)
            .with_parameter("module", "/fips.so")
            .with_parameter("activate", "1");
        assert_eq!(info.parameters.len(), 2);
        assert_eq!(info.parameters[0].name, "module");
        assert_eq!(info.parameters[1].name, "activate");
    }

    #[test]
    fn test_provider_info_builder_chain() {
        let info = ProviderInfo::new("custom", ProviderKind::Default)
            .with_path("/custom.so")
            .with_fallback(true)
            .with_parameter("key", "value");
        assert_eq!(info.name, "custom");
        assert_eq!(info.path, Some("/custom.so".to_string()));
        assert!(info.is_fallback);
        assert_eq!(info.parameters.len(), 1);
    }

    #[test]
    fn test_provider_info_display_minimal() {
        let info = ProviderInfo::new("null", ProviderKind::Null);
        let display = format!("{info}");
        assert!(display.contains("null"));
        assert!(!display.contains("fallback"));
        assert!(!display.contains("path="));
        assert!(!display.contains("params="));
    }

    #[test]
    fn test_provider_info_display_full() {
        let info = ProviderInfo::new("fips", ProviderKind::Fips)
            .with_path("/fips.so")
            .with_fallback(true)
            .with_parameter("module", "/fips.so");
        let display = format!("{info}");
        assert!(display.contains("fips"));
        assert!(display.contains("path="));
        assert!(display.contains("fallback"));
        assert!(display.contains("params=[1]"));
    }

    // -----------------------------------------------------------------------
    // predefined_providers() tests
    // -----------------------------------------------------------------------

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_predefined_providers_normal_build() {
        let providers = predefined_providers();

        // In a normal build (no fips_module), we expect at least 3 providers:
        // default, base, null (and optionally legacy if static_legacy is set)
        assert!(
            providers.len() >= 3,
            "Expected at least 3 providers, got {}",
            providers.len()
        );

        // The default provider must be first and marked as fallback.
        // C: { "default", NULL, ossl_default_provider_init, NULL, 1 }
        assert_eq!(providers[0].name, "default");
        assert_eq!(providers[0].kind, ProviderKind::Default);
        assert!(providers[0].is_fallback);
        assert!(providers[0].path.is_none());
        assert!(providers[0].parameters.is_empty());

        // Verify base and null are present (order depends on static_legacy).
        let has_base = providers.iter().any(|p| p.name == "base");
        let has_null = providers.iter().any(|p| p.name == "null");
        assert!(has_base, "base provider missing");
        assert!(has_null, "null provider missing");

        // Verify base is not a fallback.
        let base = providers.iter().find(|p| p.name == "base");
        assert!(!base.map_or(true, |p| p.is_fallback));

        // Verify null is not a fallback.
        let null = providers.iter().find(|p| p.name == "null");
        assert!(!null.map_or(true, |p| p.is_fallback));
    }

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_predefined_default_is_only_fallback() {
        let providers = predefined_providers();
        let fallback_count = providers.iter().filter(|p| p.is_fallback).count();
        assert_eq!(
            fallback_count, 1,
            "Exactly one provider should be fallback, found {fallback_count}"
        );
        let fallback = providers.iter().find(|p| p.is_fallback);
        assert_eq!(fallback.map(|p| p.name.as_str()), Some("default"));
    }

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_predefined_all_paths_none() {
        // All predefined providers should have path = None (built-in, not loaded from disk).
        for provider in predefined_providers() {
            assert!(
                provider.path.is_none(),
                "Provider {} should have path = None",
                provider.name
            );
        }
    }

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_predefined_all_parameters_empty() {
        // All predefined providers should have empty parameters.
        for provider in predefined_providers() {
            assert!(
                provider.parameters.is_empty(),
                "Provider {} should have empty parameters",
                provider.name
            );
        }
    }

    // -----------------------------------------------------------------------
    // info_add_parameter() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_info_add_parameter_basic() {
        let mut info = ProviderInfo::new("test", ProviderKind::Default);
        info_add_parameter(&mut info, "key", "value");
        assert_eq!(info.parameters.len(), 1);
        assert_eq!(info.parameters[0].name, "key");
        assert_eq!(info.parameters[0].value, "value");
    }

    #[test]
    fn test_info_add_parameter_multiple() {
        let mut info = ProviderInfo::new("test", ProviderKind::Fips);
        info_add_parameter(&mut info, "module", "/fips.so");
        info_add_parameter(&mut info, "activate", "1");
        info_add_parameter(&mut info, "install-mac", "HMAC");
        assert_eq!(info.parameters.len(), 3);
        assert_eq!(info.parameters[0].name, "module");
        assert_eq!(info.parameters[1].name, "activate");
        assert_eq!(info.parameters[2].name, "install-mac");
    }

    #[test]
    fn test_info_add_parameter_empty_strings() {
        let mut info = ProviderInfo::new("test", ProviderKind::Null);
        info_add_parameter(&mut info, "", "");
        assert_eq!(info.parameters.len(), 1);
        assert_eq!(info.parameters[0].name, "");
        assert_eq!(info.parameters[0].value, "");
    }

    // -----------------------------------------------------------------------
    // find_by_name() tests
    // -----------------------------------------------------------------------

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_find_by_name_default() {
        let result = find_by_name("default");
        assert!(result.is_some());
        let info = result.expect("default provider should exist");
        assert_eq!(info.kind, ProviderKind::Default);
        assert!(info.is_fallback);
    }

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_find_by_name_base() {
        let result = find_by_name("base");
        assert!(result.is_some());
        let info = result.expect("base provider should exist");
        assert_eq!(info.kind, ProviderKind::Base);
        assert!(!info.is_fallback);
    }

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_find_by_name_null() {
        let result = find_by_name("null");
        assert!(result.is_some());
        let info = result.expect("null provider should exist");
        assert_eq!(info.kind, ProviderKind::Null);
        assert!(!info.is_fallback);
    }

    #[test]
    fn test_find_by_name_nonexistent() {
        assert!(find_by_name("nonexistent").is_none());
        assert!(find_by_name("").is_none());
        assert!(find_by_name("DEFAULT").is_none()); // Case-sensitive
    }

    // -----------------------------------------------------------------------
    // is_predefined() tests
    // -----------------------------------------------------------------------

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_is_predefined_known_names() {
        assert!(is_predefined("default"));
        assert!(is_predefined("base"));
        assert!(is_predefined("null"));
    }

    #[test]
    fn test_is_predefined_unknown_names() {
        assert!(!is_predefined("custom"));
        assert!(!is_predefined("nonexistent"));
        assert!(!is_predefined(""));
        assert!(!is_predefined("DEFAULT")); // Case-sensitive
        assert!(!is_predefined("Base"));
    }

    // -----------------------------------------------------------------------
    // Provider ordering tests (match C source order)
    // -----------------------------------------------------------------------

    #[cfg(not(feature = "fips_module"))]
    #[test]
    fn test_predefined_order_matches_c_source() {
        let providers = predefined_providers();
        // In C: default comes first (L24), then optionally legacy (L26),
        // then base (L28), then null (L29).
        assert_eq!(providers[0].name, "default", "default must be first");

        // Find base and null positions — they should be after default.
        let base_pos = providers.iter().position(|p| p.name == "base");
        let null_pos = providers.iter().position(|p| p.name == "null");
        assert!(base_pos.is_some(), "base must be present");
        assert!(null_pos.is_some(), "null must be present");

        // Base comes before null, matching C source order (L28 before L29).
        let base_pos = base_pos.expect("base position");
        let null_pos = null_pos.expect("null position");
        assert!(
            base_pos < null_pos,
            "base (pos {base_pos}) must come before null (pos {null_pos})"
        );
    }
}
