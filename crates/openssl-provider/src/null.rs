//! Null provider implementation for the OpenSSL Rust workspace.
//!
//! Implements the [`Provider`] trait returning metadata (name, version, status)
//! but advertising zero algorithms for all operation classes.
//! [`NullProvider::query_operation()`] always returns [`None`].
//!
//! The null provider is a minimal, ABI-valid provider used as a
//! sentinel/placeholder when a valid provider handle is needed but no
//! algorithm discovery should succeed.
//!
//! # Source Reference
//!
//! Replaces C `providers/nullprov.c` (78 lines) and references
//! `providers/prov_running.c` for the `is_running()` always-true behavior.
//!
//! # C-to-Rust Mapping
//!
//! | C Construct                         | Rust Equivalent                                |
//! |-------------------------------------|------------------------------------------------|
//! | `ossl_null_provider_init()`         | [`NullProvider::new()`]                        |
//! | `null_get_params()` (line 35)       | [`NullProvider::get_params()`]                 |
//! | `null_gettable_params()` (line 30)  | [`NullProvider::gettable_params()`] (default)  |
//! | `null_query()` (line 54)            | [`NullProvider::query_operation()`] → `None`   |
//! | `null_dispatch_table[]` (line 63)   | `impl Provider for NullProvider`               |
//! | `ossl_prov_is_running()` (always 1) | [`NullProvider::is_running()`] → `true`        |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `query_operation()` returns `Option<Vec<…>>`, not
//!   a null pointer.
//! - **R8 (Zero Unsafe):** This module contains zero `unsafe` blocks;
//!   `#![forbid(unsafe_code)]` is inherited from the crate root.
//! - **R9 (Warning-Free):** Every public item has a `///` doc comment;
//!   no `#[allow(unused)]` attributes.
//! - **R10 (Wiring):** Reachable via
//!   `openssl-crypto::provider::load_provider("null")` → `NullProvider`.

use std::fmt;

use crate::traits::{AlgorithmDescriptor, Provider, ProviderInfo};
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::types::OperationType;

// =============================================================================
// NullProvider — Zero-Algorithm Sentinel Provider
// =============================================================================

/// Null provider — implements the [`Provider`] trait but advertises no
/// algorithms for any operation class.
///
/// Used as a sentinel/placeholder when a valid provider handle is needed but
/// no algorithm discovery should succeed.  The defining characteristic is that
/// [`NullProvider::query_operation()`] **always returns [`None`]** regardless
/// of the operation type requested.
///
/// Replaces C `ossl_null_provider_init` and the associated
/// `null_dispatch_table[]` from `providers/nullprov.c`.
///
/// # Zero-Allocation
///
/// `NullProvider` is a unit struct with no internal state, no provider
/// context, and no cleanup needed.  Construction (`new()`) performs zero
/// heap allocations.
///
/// # Thread Safety
///
/// `NullProvider` is [`Send`] + [`Sync`] by construction (no interior
/// state) and can be freely shared across threads via `Arc<dyn Provider>`.
///
/// # Examples
///
/// ```
/// use openssl_provider::null::NullProvider;
/// use openssl_provider::traits::Provider;
/// use openssl_common::types::OperationType;
///
/// let provider = NullProvider::new();
///
/// // The null provider reports as running…
/// assert!(provider.is_running());
///
/// // …but advertises zero algorithms for every operation class.
/// assert!(provider.query_operation(OperationType::Digest).is_none());
/// assert!(provider.query_operation(OperationType::Cipher).is_none());
///
/// // Metadata is available.
/// let info = provider.info();
/// assert_eq!(info.name, "OpenSSL Null Provider");
/// assert!(info.status);
/// ```
#[derive(Clone)]
pub struct NullProvider;

// =============================================================================
// Construction and Standard Trait Implementations
// =============================================================================

impl NullProvider {
    /// Creates a new null provider instance.
    ///
    /// This is a zero-allocation operation — `NullProvider` is a unit struct
    /// with no internal state.  Replaces C `ossl_null_provider_init()` which
    /// sets `*out = null_dispatch_table` and assigns a dummy context.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_provider::null::NullProvider;
    ///
    /// let provider = NullProvider::new();
    /// ```
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullProvider {
    /// Returns the default null provider — delegates to [`NullProvider::new()`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NullProvider {
    /// Formats the provider as `"NullProvider"` for diagnostic output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NullProvider")
    }
}

impl fmt::Display for NullProvider {
    /// Formats the provider using its human-readable name:
    /// `"OpenSSL Null Provider"`.
    ///
    /// Matches the provider name string returned by [`NullProvider::info()`]
    /// and the C `null_get_params()` `OSSL_PROV_PARAM_NAME` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenSSL Null Provider")
    }
}

// =============================================================================
// Provider Trait Implementation
// =============================================================================

impl Provider for NullProvider {
    /// Returns provider metadata for the null provider.
    ///
    /// The returned [`ProviderInfo`] contains:
    /// - `name`: `"OpenSSL Null Provider"` (matches C `null_get_params` line 40)
    /// - `version`: The crate version from `Cargo.toml` (replaces C `OPENSSL_VERSION_STR`)
    /// - `build_info`: `"openssl-provider <version>"` (replaces C `OPENSSL_FULL_VERSION_STR`)
    /// - `status`: `true` (matches C `ossl_prov_is_running()` always returning 1)
    #[inline]
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "OpenSSL Null Provider",
            version: env!("CARGO_PKG_VERSION"),
            build_info: concat!("openssl-provider ", env!("CARGO_PKG_VERSION")),
            status: true,
        }
    }

    /// Queries available algorithms for the given operation type.
    ///
    /// **Always returns [`None`]** — this is the defining characteristic of
    /// the null provider.  No algorithms are advertised for any operation
    /// class, regardless of the `OperationType` requested.
    ///
    /// Replaces C `null_query()` (line 54–60 of `nullprov.c`) which returns
    /// `NULL` for all `operation_id` values and sets `*no_cache = 0`.
    ///
    /// # Rule R5
    ///
    /// Returns `Option<Vec<AlgorithmDescriptor>>` instead of a null pointer,
    /// using `None` to encode "no algorithms available".
    #[inline]
    fn query_operation(&self, _op: OperationType) -> Option<Vec<AlgorithmDescriptor>> {
        None
    }

    /// Returns the provider parameters as a typed [`ParamSet`].
    ///
    /// The returned parameter set contains the following keys, matching the
    /// C `null_get_params()` output from `nullprov.c` lines 35–51:
    ///
    /// | Key         | Value                                 | C Equivalent               |
    /// |-------------|---------------------------------------|----------------------------|
    /// | `"name"`    | `"OpenSSL Null Provider"`             | `OSSL_PROV_PARAM_NAME`     |
    /// | `"version"` | Crate version string                  | `OSSL_PROV_PARAM_VERSION`  |
    /// | `"buildinfo"` | `"openssl-provider <version>"`     | `OSSL_PROV_PARAM_BUILDINFO`|
    /// | `"status"`  | `1` (i32, provider is running)        | `OSSL_PROV_PARAM_STATUS`   |
    ///
    /// # Errors
    ///
    /// This implementation always succeeds — returns `Ok(ParamSet)`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let params = ParamBuilder::new()
            .push_utf8("name", "OpenSSL Null Provider".to_string())
            .push_utf8("version", env!("CARGO_PKG_VERSION").to_string())
            .push_utf8(
                "buildinfo",
                concat!("openssl-provider ", env!("CARGO_PKG_VERSION")).to_string(),
            )
            .push_i32("status", 1)
            .build();
        Ok(params)
    }

    /// Returns the list of gettable parameter keys.
    ///
    /// Returns `["name", "version", "buildinfo", "status"]`, matching the
    /// C `null_param_types[]` array from `nullprov.c` lines 22–28.
    ///
    /// This implementation explicitly overrides the default to document
    /// the exact parameter set available from the null provider.
    fn gettable_params(&self) -> Vec<&'static str> {
        vec!["name", "version", "buildinfo", "status"]
    }

    /// Returns whether this provider is in a running / healthy state.
    ///
    /// **Always returns `true`** — matches the C `ossl_prov_is_running()`
    /// from `providers/prov_running.c` which unconditionally returns `1`.
    ///
    /// The null provider has no error state and is always operational.
    #[inline]
    fn is_running(&self) -> bool {
        true
    }

    /// Performs provider teardown / cleanup.
    ///
    /// This is a no-op for the null provider — there is no internal state,
    /// no provider context, and no allocated resources to release.
    ///
    /// Uses the default trait implementation which returns `Ok(())`.
    /// Replaces the implicit no-op teardown in C (the null dispatch table
    /// does not register `OSSL_FUNC_PROVIDER_TEARDOWN`).
    fn teardown(&mut self) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Verifies that `NullProvider::info()` returns the correct metadata
    /// matching the C `null_get_params()` output.
    #[test]
    fn test_info_returns_correct_metadata() {
        let provider = NullProvider::new();
        let info = provider.info();

        assert_eq!(info.name, "OpenSSL Null Provider");
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            info.build_info,
            concat!("openssl-provider ", env!("CARGO_PKG_VERSION"))
        );
        assert!(info.status);
    }

    /// Verifies that `query_operation()` returns `None` for every single
    /// variant of [`OperationType`], matching the C `null_query()` behavior.
    #[test]
    fn test_query_operation_returns_none_for_all_types() {
        let provider = NullProvider::new();

        let all_ops = [
            OperationType::Digest,
            OperationType::Cipher,
            OperationType::Mac,
            OperationType::Kdf,
            OperationType::Rand,
            OperationType::KeyMgmt,
            OperationType::Signature,
            OperationType::AsymCipher,
            OperationType::Kem,
            OperationType::KeyExch,
            OperationType::EncoderDecoder,
            OperationType::Store,
            OperationType::SKeyMgmt,
        ];

        for op in all_ops {
            assert!(
                provider.query_operation(op).is_none(),
                "query_operation({:?}) should return None for NullProvider",
                op,
            );
        }
    }

    /// Verifies that `is_running()` always returns `true`, matching
    /// `ossl_prov_is_running()` from `prov_running.c`.
    #[test]
    fn test_is_running_always_true() {
        let provider = NullProvider::new();
        assert!(provider.is_running());
    }

    /// Verifies that `get_params()` returns a valid `ParamSet` with the
    /// four standard provider metadata keys.
    #[test]
    fn test_get_params_returns_correct_param_set() {
        let provider = NullProvider::new();
        let params = provider.get_params().expect("get_params should succeed");

        // Verify all four standard keys are present
        assert!(params.contains("name"));
        assert!(params.contains("version"));
        assert!(params.contains("buildinfo"));
        assert!(params.contains("status"));
        assert_eq!(params.len(), 4);

        // Verify values
        let name = params.get("name").expect("name param should exist");
        assert_eq!(name.as_str(), Some("OpenSSL Null Provider"));

        let version = params.get("version").expect("version param should exist");
        assert_eq!(version.as_str(), Some(env!("CARGO_PKG_VERSION")));

        let buildinfo = params
            .get("buildinfo")
            .expect("buildinfo param should exist");
        assert_eq!(
            buildinfo.as_str(),
            Some(concat!("openssl-provider ", env!("CARGO_PKG_VERSION")))
        );

        let status = params.get("status").expect("status param should exist");
        assert_eq!(status.as_i32(), Some(1));
    }

    /// Verifies that `gettable_params()` returns the standard four keys.
    #[test]
    fn test_gettable_params_returns_standard_keys() {
        let provider = NullProvider::new();
        let keys = provider.gettable_params();

        assert_eq!(keys.len(), 4);
        assert!(keys.contains(&"name"));
        assert!(keys.contains(&"version"));
        assert!(keys.contains(&"buildinfo"));
        assert!(keys.contains(&"status"));
    }

    /// Verifies that `teardown()` succeeds (no-op for null provider).
    #[test]
    fn test_teardown_succeeds() {
        let mut provider = NullProvider::new();
        assert!(provider.teardown().is_ok());
    }

    /// Verifies that `Default::default()` produces an equivalent provider.
    #[test]
    fn test_default_matches_new() {
        let from_new = NullProvider::new();
        let from_default = NullProvider::default();

        // Both should report identical info
        assert_eq!(from_new.info().name, from_default.info().name);
        assert_eq!(from_new.info().version, from_default.info().version);
        assert_eq!(from_new.is_running(), from_default.is_running());
    }

    /// Verifies that `Debug` formatting produces "NullProvider".
    #[test]
    fn test_debug_format() {
        let provider = NullProvider::new();
        assert_eq!(format!("{:?}", provider), "NullProvider");
    }

    /// Verifies that `Display` formatting produces "OpenSSL Null Provider".
    #[test]
    fn test_display_format() {
        let provider = NullProvider::new();
        assert_eq!(format!("{}", provider), "OpenSSL Null Provider");
    }

    /// Verifies that `NullProvider` implements `Clone` correctly.
    #[test]
    fn test_clone() {
        let provider = NullProvider::new();
        let cloned = provider.clone();

        assert_eq!(provider.info().name, cloned.info().name);
        assert_eq!(provider.is_running(), cloned.is_running());
    }

    /// Verifies that `NullProvider` is `Send` and `Sync`, enabling safe
    /// use across threads via `Arc<dyn Provider>`.
    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NullProvider>();
    }

    /// Verifies zero `unsafe` blocks by construction — this test validates
    /// the contract by checking that the provider works without any FFI.
    #[test]
    fn test_no_unsafe_usage() {
        // This test exists to document that NullProvider is 100% safe Rust.
        // The #![forbid(unsafe_code)] attribute at the crate level enforces this
        // at compile time.
        let provider = NullProvider::new();
        let _ = provider.info();
        let _ = provider.query_operation(OperationType::Digest);
        let _ = provider.get_params();
        let _ = provider.gettable_params();
        let _ = provider.is_running();
    }
}
