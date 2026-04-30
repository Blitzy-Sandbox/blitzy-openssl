// =============================================================================
// crates/openssl-provider/src/lib.rs
//
// Crate root for the openssl-provider crate — the Rust equivalent of OpenSSL's
// provider system (C `providers/` directory, ~78,409 LoC excluding FIPS).
//
// This module is the single entry point that:
//   1. Declares all submodules (`traits`, `dispatch`, the four built-in
//      providers, and the algorithm `implementations` hub).
//   2. Re-exports the most commonly used types so downstream crates can write
//      `use openssl_provider::Provider` rather than navigating sub-paths.
//   3. Provides a runtime-selectable [`BuiltinProviderKind`] enum for callers
//      that need to instantiate built-in providers by name.
//   4. Exposes a single high-level [`register_builtin_providers`] convenience
//      function used by [`openssl_crypto`](../openssl_crypto/index.html) library
//      initialization to register the canonical default + base + legacy set.
//
// The FIPS provider lives in a **separate crate** (`openssl-fips`) so that the
// FIPS module boundary required by the certified target can be enforced at the
// crate level — no symbol from outside `openssl-fips` may participate in the
// approved-services dispatch chain.
// =============================================================================

//! # openssl-provider
//!
//! Provider framework crate for the OpenSSL Rust workspace.  Translates the
//! C `OSSL_DISPATCH` function-pointer table dispatch architecture into Rust
//! trait-based dynamic dispatch using trait objects (`Box<dyn Provider>` and
//! algorithm-specific `Box<dyn DigestProvider>`-style traits).
//!
//! ## Architecture
//!
//! The provider system is the **sole** algorithm dispatch mechanism in
//! OpenSSL 4.0.  Applications access cryptographic primitives through the
//! high-level EVP API, which in turn fetches concrete implementations from
//! registered providers via the [`MethodStore`]:
//!
//! ```text
//! Application -> EVP API -> MethodStore -> Provider -> Algorithm Implementation
//!     (user)    (typed)    (registry)    (trait)      (`AlgorithmProvider`)
//! ```
//!
//! Each provider advertises a catalog of algorithms via
//! [`Provider::query_operation`].  Catalogs are flat lists of
//! [`AlgorithmDescriptor`] records keyed by name aliases, properties (such
//! as `"provider=default"` or `"fips=yes"`), and an opaque
//! `Box<dyn AlgorithmProvider>` instance carrying the actual logic.
//!
//! ## Built-in Providers
//!
//! - [`default`] — Standard non-FIPS catalog: digests (SHA-2/3, BLAKE2),
//!   ciphers (AES-GCM/CCM/CTR, ChaCha20-Poly1305, AES-XTS), MACs
//!   (HMAC, CMAC, GMAC, KMAC, Poly1305, `SipHash`), KDFs (HKDF, PBKDF2,
//!   Argon2, scrypt, KBKDF), signatures (RSA, DSA, ECDSA, Ed25519/Ed448,
//!   ML-DSA, SLH-DSA), KEMs (RSA-KEM, EC-KEM, ML-KEM), key
//!   management for every algorithm above, plus PKCS#12/PEM/DER
//!   encoders & decoders.
//! - [`legacy`] — Deprecated algorithms only available behind the `legacy`
//!   feature gate: MD2, MD4, MDC2, Whirlpool, Blowfish, CAST5, IDEA,
//!   SEED, RC2, RC4, RC5, single-DES, PBKDF1 and PVK KDF.  Tagged with
//!   `provider=legacy` so callers can select / exclude them by property.
//! - [`base`] — Foundational provider exposing encoder/decoder/store
//!   operations and the entropy seed-source RAND.  Does **not** implement
//!   any cryptographic algorithm itself.
//! - [`null`] — No-op sentinel provider that returns metadata but
//!   advertises zero algorithms.  Used as a placeholder when an
//!   `Option<Box<dyn Provider>>` slot must be populated without enabling
//!   any concrete dispatch.
//!
//! The FIPS provider is intentionally housed in a separate crate
//! (`openssl-fips`) for certification isolation.  The FIPS boundary is
//! enforced at the crate level — `openssl-provider` has no compile-time
//! dependency on `openssl-fips` and cannot accidentally export FIPS state.
//!
//! ## Key C → Rust Transformations
//!
//! | C construct                            | Rust replacement                                  |
//! |----------------------------------------|---------------------------------------------------|
//! | `OSSL_DISPATCH` function-pointer table | Trait objects (`Box<dyn DigestProvider>`, etc.)   |
//! | `OSSL_PARAM` parameter bag             | Typed [`openssl_common::param::ParamSet`] struct  |
//! | `OPENSSL_NO_*` compile-time guard      | Cargo `#[cfg(feature = "...")]` feature gate      |
//! | `OSSL_METHOD_STORE`                    | [`MethodStore`] with fine-grained `RwLock`s       |
//! | `OSSL_FUNC_provider_query_operation`   | [`Provider::query_operation`] returning `Option`  |
//! | `OSSL_FUNC_provider_teardown`          | [`Provider::teardown`] with `&mut self` semantics |
//! | Reference-counted `OSSL_PROVIDER`      | `Arc<dyn Provider>` ownership model               |
//! | `ossl_prov_is_running()` global        | Per-instance [`Provider::is_running`] method      |
//!
//! ## Design Principles (Refactor Rules R1–R10)
//!
//! - **Zero unsafe (Rule R8):** This crate contains zero `unsafe` code.
//!   The crate-level `#![deny(unsafe_code)]` attribute makes any
//!   accidental introduction a compile-time error.  All FFI surfaces
//!   live in `openssl-ffi`.
//! - **Synchronous only (AAP §0.4.4):** No async / `tokio` dependency.
//!   The provider system is fully synchronous; async behavior is layered
//!   on top by `openssl-ssl::quic`.
//! - **`Option<T>` over sentinels (Rule R5):** Missing values are
//!   represented as `None`; sentinel integers (`-1`, `0`) are not used to
//!   encode "absent".
//! - **Checked numeric casts (Rule R6):** The crate-level
//!   `#![deny(clippy::cast_possible_truncation)]` blocks bare narrowing
//!   `as` casts.  All conversions use `TryFrom::try_from` with explicit
//!   error handling.
//! - **Fine-grained locking (Rule R7):** [`MethodStore`] uses per-shard
//!   `RwLock`s so digest registration cannot block cipher fetches and
//!   vice versa.
//! - **Wired before done (Rule R10):** All built-in providers are
//!   reachable from [`openssl_crypto`] library initialization through
//!   [`register_builtin_providers`] and have integration tests asserting
//!   their algorithms can be fetched.
//!
//! ## Quick Start
//!
//! ```no_run
//! use openssl_provider::{
//!     register_builtin_providers, BuiltinProviderKind, MethodStore,
//! };
//!
//! // Create a fresh method store (typically owned by `OSSL_LIB_CTX`).
//! let store = MethodStore::new();
//!
//! // Register the canonical built-in provider set.
//! register_builtin_providers(&store);
//!
//! // Or instantiate individual built-in providers by name.
//! let kind = BuiltinProviderKind::from_name("default").unwrap();
//! let provider = kind.create();
//! assert_eq!(provider.info().name, "OpenSSL Default Provider");
//! ```

// =============================================================================
// Crate-level Lint Attributes
// =============================================================================
//
// These complement the workspace-level lints declared in the root `Cargo.toml`
// `[workspace.lints]` tables.  Declaring them here makes the policy explicit
// for anyone reading this file in isolation and guarantees the rules apply
// even if a future refactor changes the workspace inheritance setup.
//
// Rule R8: Zero unsafe in non-FFI crates.  Accidental `unsafe` is a hard
//          compile error here.  The `openssl-ffi` crate is the only place
//          unsafe is permitted (and even there each block must carry a
//          `// SAFETY:` comment).
#![deny(unsafe_code)]
//
// Rule R6: No bare narrowing casts.  `value as u8` is rejected by the
//          compiler — callers must use `u8::try_from(value)?` or
//          `value.clamp(...)` with an explicit reasoning trail.
#![deny(clippy::cast_possible_truncation)]
//
// Documentation coverage: every public item in this crate must have a `///`
// doc comment.  Missing-docs is `warn` (rather than `deny`) because some
// re-exports inherit docs from their upstream definitions.
#![warn(missing_docs)]
//
// Library-quality error handling: `unwrap` and `expect` indicate a panic path
// and are forbidden in this crate's library code.  Tests, examples, and
// `main()` functions may opt out with `#[allow(...)]` plus a justification
// comment.  These elevate the workspace-level `warn` to `deny` for the
// provider crate where panics would be especially harmful (panic in a
// provider implementation aborts the entire crypto operation chain).
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

// =============================================================================
// Module Declarations
// =============================================================================
//
// Submodules are declared in dependency order: foundational trait/dispatch
// modules first, then the four built-in provider implementations, then the
// algorithm implementations hub.

/// Provider trait definitions replacing C `OSSL_DISPATCH` function pointer
/// tables.
///
/// Defines the full trait hierarchy for every algorithm category: digest,
/// cipher, MAC, KDF, signature, KEM, key management, key exchange, RAND,
/// encoder/decoder, and store operations.  The base [`Provider`] trait
/// describes provider lifecycle; algorithm-specific traits describe a
/// single algorithm category's contract.
pub mod traits;

/// Method store and algorithm dispatch infrastructure.
///
/// Manages algorithm registration, lookup by name and property query,
/// caching, and provider-based algorithm fetch.  Translates the C
/// `crypto/core_fetch.c` and `crypto/core_algorithm.c` into Rust using
/// `parking_lot::RwLock` for per-operation shards (Rule R7 fine-grained
/// locking).
pub mod dispatch;

/// Default provider — the primary non-FIPS provider.
///
/// Supplies the standard algorithm catalog across all 12 operation
/// categories (digests, ciphers, MACs, KDFs, signatures, key exchange,
/// RAND, KEMs, asymmetric ciphers, key management, encoder/decoder,
/// store).  Replaces C `providers/defltprov.c` (~1,500 lines).
pub mod default;

/// Legacy provider — deprecated algorithm catalog.
///
/// Provides MD2, MD4, MDC2, Whirlpool, Blowfish, CAST5, IDEA, SEED,
/// RC2, RC4, RC5, single-DES, PBKDF1 and the PVK KDF.  Algorithms are
/// tagged with the `provider=legacy` property so callers can include
/// or exclude them via property query.  The entire module is gated
/// behind the `legacy` Cargo feature so security-conscious deployments
/// can drop the deprecated code paths from the binary entirely.
/// Replaces C `providers/legacyprov.c`.
#[cfg(feature = "legacy")]
pub mod legacy;

/// Base provider — encoder/decoder/store + seed-source RAND.
///
/// Limited surface focused on key serialization infrastructure: PKCS#8
/// and SubjectPublicKeyInfo encoders/decoders, OSSL_STORE file handler,
/// and the entropy seed source used by DRBGs.  Does **not** provide
/// cryptographic algorithms (no digests, ciphers, signatures, etc.).
/// Replaces C `providers/baseprov.c`.
pub mod base;

/// Null provider — no-op sentinel.
///
/// A minimal, ABI-valid provider that returns provider metadata (name,
/// version, status) via [`Provider::info`] but advertises zero
/// algorithms for every operation type — [`Provider::query_operation`]
/// always returns `None`.  Used as a placeholder when a valid
/// `Box<dyn Provider>` is required but no algorithm dispatch should
/// succeed.  Replaces C `providers/nullprov.c`.
pub mod null;

/// Algorithm implementation backends.
///
/// Hub module containing 11 feature-gated submodules — one per
/// algorithm category — that supply the actual algorithm logic.
/// Built-in providers reference this module to populate their
/// algorithm catalogs.  This module also exposes
/// `all_*_descriptors()` aggregation helpers used during provider
/// registration.
pub mod implementations;

// `tests/` is the integration-test root.  It is conditionally compiled
// only for `cargo test` runs; it is **not** part of the public API and
// must not appear in the documentation tree.
#[cfg(test)]
mod tests;

// =============================================================================
// Public Re-exports — Trait Hierarchy (from `traits` module)
// =============================================================================
//
// Re-exporting the trait hierarchy at the crate root lets downstream code
// write `use openssl_provider::Provider;` rather than the longer
// `use openssl_provider::traits::Provider;`.  Names are sorted
// alphabetically for predictable diff'ing.  Each re-export is documented
// in the upstream module — adding `///` doc comments here would duplicate
// content and risk drift.

pub use traits::AlgorithmDescriptor;
pub use traits::AlgorithmProvider;
pub use traits::CipherContext;
pub use traits::CipherProvider;
pub use traits::DecoderProvider;
pub use traits::DigestContext;
pub use traits::DigestProvider;
pub use traits::EncoderProvider;
pub use traits::KdfContext;
pub use traits::KdfProvider;
pub use traits::KemContext;
pub use traits::KemProvider;
pub use traits::KeyData;
pub use traits::KeyExchangeContext;
pub use traits::KeyExchangeProvider;
pub use traits::KeyMgmtProvider;
pub use traits::KeySelection;
pub use traits::MacContext;
pub use traits::MacProvider;
pub use traits::Provider;
pub use traits::ProviderInfo;
pub use traits::RandContext;
pub use traits::RandProvider;
pub use traits::SignatureContext;
pub use traits::SignatureProvider;
pub use traits::StoreContext;
pub use traits::StoreObject;
pub use traits::StoreProvider;

// =============================================================================
// Public Re-exports — Dispatch Infrastructure (from `dispatch` module)
// =============================================================================

pub use dispatch::AlgorithmCapability;
pub use dispatch::MethodKey;
pub use dispatch::MethodStore;

// =============================================================================
// Public Re-exports — Built-in Provider Implementations
// =============================================================================
//
// Each built-in provider is exported so callers can construct instances
// directly without going through [`BuiltinProviderKind::create`].  The
// legacy provider re-export is gated behind the same feature flag as the
// module declaration above.

pub use base::BaseProvider;
pub use default::DefaultProvider;
#[cfg(feature = "legacy")]
pub use legacy::LegacyProvider;
pub use null::NullProvider;

// =============================================================================
// BuiltinProviderKind — Runtime Provider Selection Enum
// =============================================================================

/// Identifier for the built-in providers shipped by this crate.
///
/// Used by [`openssl_crypto::context::LibContext`] and the CLI's
/// `openssl provider` subcommand to instantiate a built-in provider by
/// name without hard-coding the concrete provider type.
///
/// The variants form a closed set — third-party providers are loaded via
/// the [`Provider`] trait directly and do not appear in this enum.  The
/// [`BuiltinProviderKind::Legacy`] variant is gated behind the `legacy`
/// feature so that builds that drop legacy algorithms also drop the
/// corresponding selector.
///
/// ## Mapping
///
/// | Variant   | Crate path           | C source equivalent          |
/// |-----------|----------------------|------------------------------|
/// | `Default` | `default::DefaultProvider` | `providers/defltprov.c`  |
/// | `Legacy`  | `legacy::LegacyProvider`   | `providers/legacyprov.c` |
/// | `Base`    | `base::BaseProvider`       | `providers/baseprov.c`   |
/// | `Null`    | `null::NullProvider`       | `providers/nullprov.c`   |
///
/// ## Example
///
/// ```
/// use openssl_provider::BuiltinProviderKind;
///
/// let kind = BuiltinProviderKind::from_name("default").unwrap();
/// assert_eq!(kind, BuiltinProviderKind::Default);
/// assert_eq!(kind.name(), "default");
///
/// let provider = kind.create();
/// assert_eq!(provider.info().name, "OpenSSL Default Provider");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinProviderKind {
    /// Standard non-FIPS algorithm catalog.
    ///
    /// Mapped to [`DefaultProvider`].  This is the provider every fresh
    /// [`MethodStore`] starts with after [`register_builtin_providers`]
    /// has been called.
    Default,

    /// Deprecated algorithms (MD2, RC4, Blowfish, etc.).
    ///
    /// Mapped to [`LegacyProvider`].  Only present when the `legacy`
    /// Cargo feature is enabled — security-hardened builds that disable
    /// the feature will not see this variant.
    #[cfg(feature = "legacy")]
    Legacy,

    /// Encoder / decoder / store + seed-source RAND.
    ///
    /// Mapped to [`BaseProvider`].  Always available regardless of
    /// feature flags because key serialization is required by every
    /// realistic deployment.
    Base,

    /// No-op sentinel provider.
    ///
    /// Mapped to [`NullProvider`].  Useful for tests that need a valid
    /// `Box<dyn Provider>` handle without registering any algorithm.
    Null,
}

impl BuiltinProviderKind {
    /// Constructs a fresh provider instance corresponding to this kind.
    ///
    /// Returns a boxed trait object so the caller does not need to know
    /// the concrete type.  Each call instantiates a new provider — there
    /// is no shared global state, so providers can be created and
    /// dropped freely.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_provider::BuiltinProviderKind;
    ///
    /// let provider = BuiltinProviderKind::Default.create();
    /// assert!(provider.is_running());
    /// assert_eq!(provider.info().name, "OpenSSL Default Provider");
    /// ```
    #[must_use]
    pub fn create(&self) -> Box<dyn Provider> {
        match self {
            Self::Default => Box::new(DefaultProvider::new()),
            #[cfg(feature = "legacy")]
            Self::Legacy => Box::new(LegacyProvider::new()),
            Self::Base => Box::new(BaseProvider::new()),
            Self::Null => Box::new(NullProvider::new()),
        }
    }

    /// Looks up a built-in provider kind by name string.
    ///
    /// Both short canonical names (`"default"`, `"legacy"`, `"base"`,
    /// `"null"`) and the long form C-compatible names (`"OpenSSL
    /// Default Provider"`, etc.) are accepted so this method can be
    /// driven by user-facing configuration files.
    ///
    /// Returns [`None`] for unknown names — callers should fall back to
    /// dynamic provider loading or surface an error.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_provider::BuiltinProviderKind;
    ///
    /// assert_eq!(
    ///     BuiltinProviderKind::from_name("default"),
    ///     Some(BuiltinProviderKind::Default),
    /// );
    /// assert_eq!(
    ///     BuiltinProviderKind::from_name("OpenSSL Base Provider"),
    ///     Some(BuiltinProviderKind::Base),
    /// );
    /// assert_eq!(BuiltinProviderKind::from_name("nonexistent"), None);
    /// ```
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "default" | "OpenSSL Default Provider" => Some(Self::Default),
            #[cfg(feature = "legacy")]
            "legacy" | "OpenSSL Legacy Provider" => Some(Self::Legacy),
            "base" | "OpenSSL Base Provider" => Some(Self::Base),
            "null" | "OpenSSL Null Provider" => Some(Self::Null),
            _ => None,
        }
    }

    /// Returns the canonical short name string for this provider kind.
    ///
    /// The returned string is suitable for use in property queries,
    /// configuration files, and CLI output.  It matches the lowercase
    /// short identifier accepted by [`from_name`](Self::from_name).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_provider::BuiltinProviderKind;
    ///
    /// assert_eq!(BuiltinProviderKind::Default.name(), "default");
    /// assert_eq!(BuiltinProviderKind::Base.name(), "base");
    /// assert_eq!(BuiltinProviderKind::Null.name(), "null");
    /// ```
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Default => "default",
            #[cfg(feature = "legacy")]
            Self::Legacy => "legacy",
            Self::Base => "base",
            Self::Null => "null",
        }
    }
}

// =============================================================================
// register_builtin_providers — Bulk Registration Helper
// =============================================================================

/// Registers the canonical set of built-in providers with the supplied
/// [`MethodStore`].
///
/// This convenience function is invoked during library initialization
/// (typically from `openssl_crypto::context::LibContext::default`) to
/// populate a fresh method store with the providers every realistic
/// deployment needs:
///
/// 1. [`DefaultProvider`] — standard algorithm catalog
/// 2. [`BaseProvider`]    — encoder/decoder/store + seed-source RAND
/// 3. [`LegacyProvider`]  — only when the `legacy` Cargo feature is enabled
///
/// The [`NullProvider`] is intentionally **not** registered here — it has
/// no algorithms and would only add overhead to method-store lookups.
/// Callers that need the null provider should instantiate it directly
/// via [`BuiltinProviderKind::Null::create()`](BuiltinProviderKind::create).
///
/// Each registration is logged via `tracing::info!` to satisfy the AAP
/// §0.8.5 observability rule (ship structured logging with the initial
/// implementation, not as follow-up).
///
/// ## Algorithm Visibility
///
/// After this function returns, every algorithm advertised by the
/// registered providers is discoverable via
/// [`MethodStore::fetch`](dispatch::MethodStore::fetch) using its name
/// alias and an optional property query string (e.g.
/// `"provider=default,fips=no"`).  The internal cache is flushed by
/// [`MethodStore::register_provider`] so previously-cached negative
/// lookups do not mask the new algorithms.
///
/// ## Thread Safety
///
/// This function takes `&MethodStore` (not `&mut`) so it can be called
/// concurrently from multiple threads — though doing so is unusual,
/// since library initialization is typically single-threaded.  The
/// store's internal locking is described in [`MethodStore`].
///
/// # Examples
///
/// ```
/// use openssl_provider::{register_builtin_providers, MethodStore};
///
/// let store = MethodStore::new();
/// register_builtin_providers(&store);
///
/// // The default provider's SHA-256 implementation is now reachable.
/// // (Actual fetch syntax varies — see the `MethodStore::fetch` docs.)
/// ```
pub fn register_builtin_providers(store: &MethodStore) {
    // Default provider — always registered.
    tracing::info!(
        provider = "default",
        version = VERSION,
        "registering built-in default provider"
    );
    let default_provider = DefaultProvider::new();
    store.register_provider(&default_provider);

    // Base provider — always registered (encoder/decoder/store).
    tracing::info!(
        provider = "base",
        version = VERSION,
        "registering built-in base provider"
    );
    let base_provider = BaseProvider::new();
    store.register_provider(&base_provider);

    // Legacy provider — only when the `legacy` feature is enabled.
    #[cfg(feature = "legacy")]
    {
        tracing::info!(
            provider = "legacy",
            version = VERSION,
            "registering built-in legacy provider"
        );
        let legacy_provider = LegacyProvider::new();
        store.register_provider(&legacy_provider);
    }

    tracing::info!("built-in provider registration complete");
}

// =============================================================================
// Crate Version & Identity Constants
// =============================================================================

/// Crate version string, populated by Cargo at compile time.
///
/// Matches the `version` field in this crate's `Cargo.toml` and is used
/// in `tracing::info!` log lines emitted by [`register_builtin_providers`]
/// to correlate provider activity with crate versions.
///
/// # Examples
///
/// ```
/// use openssl_provider::VERSION;
///
/// assert!(!VERSION.is_empty());
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name string, populated by Cargo at compile time.
///
/// Always equal to `"openssl-provider"`.  Exposed so downstream tooling
/// can identify the crate without hard-coding the literal.
///
/// # Examples
///
/// ```
/// use openssl_provider::NAME;
///
/// assert_eq!(NAME, "openssl-provider");
/// ```
pub const NAME: &str = env!("CARGO_PKG_NAME");
