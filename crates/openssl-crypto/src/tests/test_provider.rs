//! Integration tests for the provider loading, dispatch, and property query system.
//!
//! These tests validate the public API surface of [`crate::provider`] — the
//! Rust equivalent of OpenSSL's provider dispatch subsystem rooted at
//! `crypto/provider_core.c`, `crypto/core_fetch.c`, and `crypto/property/`.
//! The suite is organised into seven phases mirroring the agent prompt's
//! work breakdown:
//!
//! * **Phase 2 — Provider Loading Tests** — verify [`load`], [`try_load`],
//!   [`unload`], and [`available`] end-to-end.  Reference: `test/provider_test.c`
//!   and `test/provider_internal_test.c`.
//! * **Phase 3 — Provider Activation Tests** — verify
//!   [`ProviderInstance::activate`] / [`ProviderInstance::deactivate`]
//!   reference-count semantics including safe double-activation and the
//!   "deactivate below zero" error path.  Reference:
//!   `test/provider_status_test.c`.
//! * **Phase 4 — Algorithm Fetch Tests** — verify algorithm descriptor
//!   registration/querying via [`ProviderInstance::register_algorithms`] and
//!   [`ProviderInstance::query_algorithms`], property-query filtering, and
//!   the operation-bit cache primitive used by the fetch-caching
//!   fast-path.  Reference: `test/provfetchtest.c` and
//!   `test/provider_pkey_test.c`.
//! * **Phase 5 — Property Query Tests** — verify
//!   [`parse_definition`], [`parse_query`], and [`match_count`] cover the
//!   canonical property-matching scenarios, including the positive, negative,
//!   and FIPS-selection cases.  Reference: `test/property_test.c`.
//! * **Phase 6 — Provider Fallback Tests** — verify
//!   [`ProviderStore::activate_fallbacks`] auto-loads the default fallback
//!   provider when no explicit provider has been requested.  Reference:
//!   `test/provider_fallback_test.c`.
//! * **Phase 7 — Provider Configuration Tests** — verify
//!   [`ProviderConfState::activate_from_config`] parses the documented
//!   `"activate = 1"` / `"activate = yes"` / `"activate = true"` syntax and
//!   is a no-op for unsupported values.  Reference:
//!   `test/prov_config_test.c`.
//! * **Phase 8 — `LibContext` Isolation Tests** — verify that distinct
//!   [`LibContext`] instances maintain independent `ProviderStoreData`
//!   registrations, and that a single context serves multiple fetches
//!   consistently.
//!
//! # Rules Compliance
//!
//! * **R5 — Nullability Over Sentinels:** [`load`], [`try_load`], [`unload`],
//!   [`ProviderInstance::activate`], [`ProviderInstance::deactivate`], and
//!   [`LibContext::ensure_provider_activated`] all return [`CryptoResult`].
//!   Tests inspect the `Result` directly and never compare against integer
//!   sentinels (no `== 0` / `== -1` checks).  [`ProviderStore::find`] and
//!   [`ProviderInstance::path`] return [`Option`] — tests use pattern
//!   matching, not `is_null()` analogues.
//! * **R7 — Concurrency Lock Granularity:** Each test creates its own
//!   [`PropertyStringStore`] and [`ProviderStore`] instance so assertions
//!   never cross the boundary between two coarse locks.  The Phase 8
//!   isolation tests exercise independent [`LibContext`] instances, each
//!   with its own fine-grained `parking_lot::RwLock<ProviderStoreData>`.
//!   LOCK-SCOPE: tests acquire short-lived read/write guards on the
//!   per-context provider store.
//! * **R8 — Zero Unsafe Outside FFI:** The `openssl-crypto` crate declares
//!   `#![forbid(unsafe_code)]` at its root (see `src/lib.rs`); these tests
//!   contain no `unsafe` blocks or `unsafe fn` declarations.
//! * **R10 — Wiring Before Done:** [`test_provider_load_default`],
//!   [`test_provider_fallback_to_default`], and [`test_provider_from_config`]
//!   together exercise the complete provider-activation wiring chain
//!   (create store → load/fallback/config → activated instance reachable
//!   via [`find`](ProviderStore::find) and [`available`]).
//!
//! # Gate 10 — Coverage
//!
//! These tests target 80% line coverage for the provider module.
//! `test_provider_fetch_digest`, `test_provider_fetch_cipher`,
//! `test_provider_fetch_with_propquery`, and `test_provider_fetch_caching`
//! together drive the algorithm-registration and operation-bit code paths;
//! the Phase 5 tests drive the property-query parsing paths.
//!
//! # Fixture Independence
//!
//! Every test in this module constructs its own fresh
//! [`PropertyStringStore`] and [`ProviderStore`], so tests never share
//! mutable state via globals.  Phase 8 tests explicitly compare two
//! independent [`LibContext`] instances produced by [`LibContext::new`],
//! which are guaranteed distinct (non-singleton) per
//! `crates/openssl-crypto/src/context.rs`.

// Test-only lint relaxations. Test code uses `expect`, `unwrap`, and explicit
// `assert!` to surface failures promptly. These lints are denied at the crate
// root per the workspace lint policy (see `crates/openssl-crypto/src/lib.rs`).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::too_many_lines
)]

use std::sync::Arc;

use crate::context::LibContext;
use crate::provider::property::{match_count, parse_definition, parse_query};
use crate::provider::*;
use crate::{CryptoError, CryptoResult};

// =============================================================================
// Helpers
// =============================================================================
//
// Every test in this module begins by constructing a fresh
// `PropertyStringStore` and `ProviderStore` tuple.  Factoring the
// construction into a helper keeps the tests below focused on the
// scenario-under-test while also documenting the canonical fixture
// layout in one place.

/// Creates a fresh `(PropertyStringStore, ProviderStore)` fixture.
///
/// The returned store is pre-populated with the predefined providers
/// (default, base, null, plus legacy when the `static_legacy` feature is
/// active) in their unactivated state, matching the behaviour of
/// [`ProviderStore::new`].  Callers are expected to activate providers
/// via [`load`], [`try_load`], or [`ProviderStore::activate_fallbacks`].
fn fresh_store() -> (Arc<PropertyStringStore>, ProviderStore) {
    let strings = Arc::new(PropertyStringStore::new());
    let store = ProviderStore::new(Arc::clone(&strings));
    (strings, store)
}

/// Constructs an [`AlgorithmDescriptor`] for a message-digest algorithm.
///
/// Used by the Phase 4 fetch tests to exercise the provider's algorithm
/// registration API without depending on any concrete digest
/// implementation.  The `names` argument follows the colon-separated
/// OpenSSL convention (e.g., `"SHA2-256:SHA-256:SHA256"`).
fn make_digest_descriptor(names: &str, properties: &str) -> AlgorithmDescriptor {
    AlgorithmDescriptor {
        names: names.to_string(),
        properties: properties.to_string(),
        operation_id: OperationId::Digest,
    }
}

/// Constructs an [`AlgorithmDescriptor`] for a cipher algorithm.
fn make_cipher_descriptor(names: &str, properties: &str) -> AlgorithmDescriptor {
    AlgorithmDescriptor {
        names: names.to_string(),
        properties: properties.to_string(),
        operation_id: OperationId::Cipher,
    }
}

// =============================================================================
// Phase 2 — Provider Loading Tests
// =============================================================================
//
// Reference: test/provider_test.c lines 210-260 (default provider smoke test),
//            test/provider_internal_test.c lines 40-100 (load/unload cycle).

/// Loads the predefined default provider and verifies it is activated and
/// reports the correct name.
///
/// Mirrors the C precondition that every test makes: `OSSL_PROVIDER_load(NULL,
/// "default")` must succeed and yield a provider whose name is `"default"`.
#[test]
fn test_provider_load_default() {
    let (_strings, store) = fresh_store();

    let provider: Arc<ProviderInstance> =
        load(&store, "default").expect("loading the default provider must succeed");

    assert_eq!(
        provider.name(),
        "default",
        "loaded provider must report name \"default\""
    );
    assert!(
        provider.is_activated(),
        "load() must activate the loaded provider"
    );
    assert!(
        provider.is_initialized(),
        "activation must also set the initialized flag on first activate"
    );
    assert_eq!(
        provider.kind(),
        ProviderKind::Default,
        "predefined default provider must report ProviderKind::Default"
    );
}

/// Loads the legacy provider via [`try_load`] with fallback-retention
/// enabled, verifying the same basic post-conditions as
/// [`test_provider_load_default`].
///
/// The legacy provider is only present in the predefined list when the
/// `static_legacy` feature is enabled.  When the feature is disabled,
/// `try_load` returns an error — the test accepts either outcome so it
/// remains useful across both build configurations.
#[test]
fn test_provider_load_legacy() {
    let (_strings, store) = fresh_store();

    match try_load(&store, "legacy") {
        Ok(provider) => {
            // When the legacy provider is compiled in, it must activate.
            assert_eq!(
                provider.name(),
                "legacy",
                "legacy provider must report name \"legacy\""
            );
            assert!(
                provider.is_activated(),
                "try_load() must activate the legacy provider"
            );
            assert_eq!(
                provider.kind(),
                ProviderKind::Legacy,
                "legacy provider must report ProviderKind::Legacy"
            );
            assert!(
                available(&store, "legacy"),
                "available() must report true after a successful try_load()"
            );
        }
        Err(err) => {
            // When the legacy provider is not compiled in, try_load() must
            // report a clear "not found" diagnostic.  try_load() — in
            // contrast to load() — never dynamically creates a dummy.
            let msg = format!("{err}");
            assert!(
                msg.contains("not found"),
                "try_load() for an absent provider must return a 'not found' error, got: {msg}"
            );
            assert!(matches!(err, CryptoError::Provider(_)));
        }
    }
}

/// Attempts to load a provider that is not present in the store via
/// [`try_load`] and verifies the error path (Rule R5).
///
/// `try_load` differs from `load` in that it refuses to create a dummy
/// provider for an unknown name — this is the "contract" caller used by
/// configuration code and the FFI that needs to distinguish "does not
/// exist" from "exists but failed to activate".
#[test]
fn test_provider_load_nonexistent_error() {
    let (_strings, store) = fresh_store();

    let result: CryptoResult<Arc<ProviderInstance>> = try_load(&store, "nonexistent-provider-xyz");

    assert!(
        result.is_err(),
        "try_load() for an unknown provider must return Err"
    );

    let err = result.expect_err("must contain an error");
    let msg = format!("{err}");
    assert!(
        msg.contains("not found"),
        "error message must mention 'not found', got: {msg}"
    );

    // R5: the error variant must be a Provider error, not a generic one.
    assert!(
        matches!(err, CryptoError::Provider(_)),
        "try_load() error must be CryptoError::Provider variant, got: {err:?}"
    );

    // A failed try_load() must NOT pollute the store.
    assert!(
        !available(&store, "nonexistent-provider-xyz"),
        "a failed try_load() must not leave the provider in the store"
    );
}

/// Exercises the [`available`] convenience function through its complete
/// state sequence: absent → loaded → unloaded.
#[test]
fn test_provider_is_available() {
    let (_strings, store) = fresh_store();

    // Before any explicit load/activate, the predefined "default" provider
    // is present in the store but not yet activated, so `available()`
    // reports false.
    assert!(
        !available(&store, "default"),
        "a freshly-created store must not report 'default' as available"
    );
    assert!(
        !available(&store, "base"),
        "a freshly-created store must not report 'base' as available"
    );

    // After load(), the provider becomes available.
    load(&store, "default").expect("failed to load default provider");
    assert!(
        available(&store, "default"),
        "available() must return true after load()"
    );

    // Loading a different provider does not affect the first.
    load(&store, "base").expect("failed to load base provider");
    assert!(
        available(&store, "default"),
        "available('default') must remain true after loading a sibling provider"
    );
    assert!(
        available(&store, "base"),
        "available('base') must become true once base is loaded"
    );

    // After unload(), the provider is no longer available.
    unload(&store, "default").expect("failed to unload default provider");
    assert!(
        !available(&store, "default"),
        "available() must return false after unload()"
    );

    // available() for a provider that was never registered must be false.
    assert!(
        !available(&store, "no-such-provider"),
        "available() for an unknown provider must return false"
    );
}

// =============================================================================
// Phase 3 — Provider Activation Tests
// =============================================================================
//
// Reference: test/provider_status_test.c lines 40-180 (activation lifecycle),
//            test/provider_internal_test.c lines 60-145 (activate/deactivate
//            reference counting).

/// Verifies the basic activate → deactivate lifecycle and the
/// "deactivate below zero" error path.
#[test]
fn test_provider_activate_deactivate() {
    let (_strings, store) = fresh_store();

    let provider = load(&store, "default").expect("failed to load default");
    assert!(provider.is_activated(), "load() must activate the provider");

    // After one deactivation the reference count falls to zero and the
    // activated flag clears.
    provider
        .deactivate()
        .expect("first deactivate must succeed");
    assert!(
        !provider.is_activated(),
        "is_activated() must return false once the reference count hits zero"
    );

    // The provider remains initialized — `is_initialized()` tracks
    // first-activation, not the current reference count.
    assert!(
        provider.is_initialized(),
        "is_initialized() must remain true after deactivation (sticky flag)"
    );

    // A second deactivate — with the count already at zero — must fail
    // with a clear diagnostic.  This is the Rule R5 conversion of the
    // C sentinel pattern.
    let second_result: CryptoResult<()> = provider.deactivate();
    assert!(
        second_result.is_err(),
        "deactivating below zero must return Err"
    );
    let err = second_result.expect_err("must contain an error");
    let msg = format!("{err}");
    assert!(
        msg.contains("not activated") && msg.contains("count=0"),
        "error must describe the 'not activated (count=0)' state, got: {msg}"
    );
    assert!(matches!(err, CryptoError::Provider(_)));
}

/// Verifies that calling [`ProviderInstance::activate`] twice increments
/// the activation reference count without clearing the activated flag.
///
/// This mirrors the semantics of `OSSL_PROVIDER_load` being called twice
/// on the same provider — activation is idempotent from the observer's
/// perspective but tracks reference counts so that matching `unload`
/// calls correctly deactivate only when the count reaches zero.
#[test]
fn test_provider_double_activate() {
    let (_strings, store) = fresh_store();

    // load() activates the provider once (count becomes 1).
    let provider = load(&store, "default").expect("load must succeed");
    assert!(provider.is_activated());

    // A second explicit activate() increments the count to 2 but leaves
    // the observable activated flag unchanged.
    provider
        .activate()
        .expect("second activate must succeed (count=2)");
    assert!(
        provider.is_activated(),
        "is_activated() must remain true through repeated activation"
    );

    // A third activation is also safe.
    provider
        .activate()
        .expect("third activate must succeed (count=3)");
    assert!(provider.is_activated());

    // Now we must call deactivate() three times before the flag clears.
    provider.deactivate().expect("first deactivate (count=3→2)");
    assert!(
        provider.is_activated(),
        "after one matching deactivate the provider must still be activated (count=2)"
    );

    provider
        .deactivate()
        .expect("second deactivate (count=2→1)");
    assert!(
        provider.is_activated(),
        "after two matching deactivates the provider must still be activated (count=1)"
    );

    provider.deactivate().expect("third deactivate (count=1→0)");
    assert!(
        !provider.is_activated(),
        "once the count reaches zero, is_activated() must return false"
    );

    // A fourth deactivate — count is now zero — must fail.
    let err = provider
        .deactivate()
        .expect_err("fourth deactivate must fail");
    assert!(matches!(err, CryptoError::Provider(_)));
}

/// Verifies that `ProviderStore::find` reports the correct initialization
/// and activation status after [`load`].
///
/// This is the Rust equivalent of `OSSL_PROVIDER_status(prov)` queries in
/// `test/provider_status_test.c`, exercised through the store API rather
/// than the direct `ProviderInstance` handle returned by `load`.
///
/// # Feature gating
///
/// This test is gated on `not(feature = "fips_module")` because under the
/// FIPS module build the `predefined_providers()` registry contains only
/// the `fips` provider — the `default` provider is excluded by design (see
/// `crypto/provider/predefined.rs::predefined_providers` and the C
/// reference `provider_predefined.c` lines 22–29 where the predefined
/// table is partitioned at compile time by `#ifdef FIPS_MODULE`).
/// Consequently, the `store.find("default")` call below would return
/// `None` and the subsequent `.expect("predefined 'default' must exist")`
/// would panic. The behaviour validated here — that `find()` reports the
/// correct status for the predefined `default` instance before and after
/// activation — applies only to non-FIPS builds; the FIPS build asserts
/// the equivalent invariant for the `fips` provider through the dedicated
/// FIPS-module test suite (`crates/openssl-fips/src/tests/`).
#[cfg(not(feature = "fips_module"))]
#[test]
fn test_provider_status_after_activate() {
    let (_strings, store) = fresh_store();

    // Before load(), find() returns the predefined unactivated instance.
    let before: Option<Arc<ProviderInstance>> = store.find("default");
    let before_provider = before.expect("predefined 'default' must exist in the store");
    assert_eq!(before_provider.name(), "default");
    assert!(
        !before_provider.is_initialized(),
        "before load(), the default provider must not be initialized"
    );
    assert!(
        !before_provider.is_activated(),
        "before load(), the default provider must not be activated"
    );

    // After load(), the same lookup must yield an activated provider.
    let loaded = load(&store, "default").expect("load must succeed");
    let after = store
        .find("default")
        .expect("default must still be findable after load");

    assert!(
        Arc::ptr_eq(&loaded, &after),
        "ProviderStore::find() must return the same Arc instance as load()"
    );
    assert!(
        after.is_initialized(),
        "after load(), the provider must be initialized"
    );
    assert!(
        after.is_activated(),
        "after load(), the provider must be activated"
    );
    assert_eq!(after.name(), "default");
    assert_eq!(after.kind(), ProviderKind::Default);
}

// =============================================================================
// Phase 4 — Algorithm Fetch Tests
// =============================================================================
//
// Reference: test/provfetchtest.c lines 150-260 (algorithm registration and
//            query), test/provider_pkey_test.c (property-filtered fetch).

/// Registers a single digest algorithm on the default provider and verifies
/// [`ProviderInstance::query_algorithms`] returns it.
#[test]
fn test_provider_fetch_digest() {
    let (_strings, store) = fresh_store();
    let provider = load(&store, "default").expect("failed to load default");

    // Before registration, no algorithms are available for the Digest
    // operation.
    let before = provider.query_algorithms(OperationId::Digest);
    assert!(
        before.is_empty(),
        "no algorithms should be registered before register_algorithms()"
    );

    // Register a single digest descriptor.
    let descriptor = make_digest_descriptor("SHA2-256:SHA-256:SHA256", "provider=default,fips=no");
    provider.register_algorithms(OperationId::Digest, vec![descriptor]);

    // After registration, query_algorithms() returns the descriptor.
    let after = provider.query_algorithms(OperationId::Digest);
    assert_eq!(
        after.len(),
        1,
        "exactly one digest algorithm must be registered"
    );
    assert_eq!(after[0].names, "SHA2-256:SHA-256:SHA256");
    assert_eq!(after[0].properties, "provider=default,fips=no");
    assert_eq!(after[0].operation_id, OperationId::Digest);

    // Querying a different operation must still return empty.
    let ciphers = provider.query_algorithms(OperationId::Cipher);
    assert!(
        ciphers.is_empty(),
        "Cipher operation must return no algorithms — only Digest was registered"
    );
}

/// Registers cipher algorithms on the default provider and verifies
/// [`ProviderInstance::query_algorithms`] returns them for the Cipher
/// operation.
#[test]
fn test_provider_fetch_cipher() {
    let (_strings, store) = fresh_store();
    let provider = load(&store, "default").expect("failed to load default");

    let descriptors = vec![
        make_cipher_descriptor("AES-256-GCM", "provider=default,fips=yes"),
        make_cipher_descriptor("AES-128-GCM", "provider=default,fips=yes"),
        make_cipher_descriptor("CHACHA20-POLY1305", "provider=default,fips=no"),
    ];
    provider.register_algorithms(OperationId::Cipher, descriptors);

    let registered = provider.query_algorithms(OperationId::Cipher);
    assert_eq!(
        registered.len(),
        3,
        "all three cipher descriptors must be retrievable"
    );

    // Every descriptor must carry the expected operation id.
    for d in &registered {
        assert_eq!(d.operation_id, OperationId::Cipher);
    }

    // Spot-check the registered names are present (order-insensitive).
    let names: Vec<&str> = registered.iter().map(|d| d.names.as_str()).collect();
    assert!(names.contains(&"AES-256-GCM"));
    assert!(names.contains(&"AES-128-GCM"));
    assert!(names.contains(&"CHACHA20-POLY1305"));
}

/// Verifies that property-query filtering via [`match_count`] correctly
/// selects algorithms tagged with matching property definitions.
///
/// This exercises the same logic that the EVP fetch fast-path uses when
/// the caller provides a `property_query` string such as
/// `"provider=default,fips=no"`.
#[test]
fn test_provider_fetch_with_propquery() {
    let (strings, store) = fresh_store();
    let provider = load(&store, "default").expect("failed to load default");

    // Register two digest descriptors with distinct property sets.
    let fips_approved = make_digest_descriptor("SHA2-256", "provider=default,fips=yes");
    let not_fips = make_digest_descriptor("MD5", "provider=default,fips=no");
    provider.register_algorithms(OperationId::Digest, vec![fips_approved, not_fips]);

    let registered = provider.query_algorithms(OperationId::Digest);
    assert_eq!(registered.len(), 2, "both digest descriptors must register");

    // Build the property lists once and reuse them across the scenarios
    // below.
    let sha2_defn = parse_definition(&strings, "provider=default,fips=yes")
        .expect("parse_definition for SHA2-256 defn must succeed");
    let md5_defn = parse_definition(&strings, "provider=default,fips=no")
        .expect("parse_definition for MD5 defn must succeed");

    // Query 1: "fips=yes" — selects SHA2-256, rejects MD5.
    let fips_query = parse_query(&strings, "fips=yes").expect("parse_query(fips=yes) must succeed");
    assert!(
        match_count(&fips_query, &sha2_defn).is_some(),
        "SHA2-256 must satisfy fips=yes"
    );
    assert!(
        match_count(&fips_query, &md5_defn).is_none(),
        "MD5 must NOT satisfy fips=yes (required mismatch → None)"
    );

    // Query 2: "provider=default" — selects both, since both advertise
    // provider=default.
    let provider_query = parse_query(&strings, "provider=default")
        .expect("parse_query(provider=default) must succeed");
    assert!(
        match_count(&provider_query, &sha2_defn).is_some(),
        "SHA2-256 must satisfy provider=default"
    );
    assert!(
        match_count(&provider_query, &md5_defn).is_some(),
        "MD5 must satisfy provider=default"
    );

    // Query 3: combined "provider=default,fips=no" — selects MD5 only.
    let combined_query = parse_query(&strings, "provider=default,fips=no")
        .expect("parse_query(combined) must succeed");
    assert!(
        match_count(&combined_query, &md5_defn).is_some(),
        "MD5 must match the combined query"
    );
    assert!(
        match_count(&combined_query, &sha2_defn).is_none(),
        "SHA2-256 must NOT match provider=default,fips=no"
    );
}

/// Verifies the operation-bit caching primitive used to short-circuit
/// repeated algorithm-enumeration work.
///
/// [`ProviderInstance::test_operation_bit`] reports `false` before any
/// query has run; [`ProviderInstance::set_operation_bit`] marks an
/// operation as enumerated; subsequent `test_operation_bit` calls report
/// `true`, enabling the caller (the EVP method-store construction path)
/// to skip a second enumeration.
#[test]
fn test_provider_fetch_caching() {
    let (_strings, store) = fresh_store();
    let provider = load(&store, "default").expect("failed to load default");

    // Initially, no operation bits are set — every operation looks
    // "needs enumeration".
    assert!(
        !provider.test_operation_bit(OperationId::Digest),
        "operation bit must start cleared for OperationId::Digest"
    );
    assert!(
        !provider.test_operation_bit(OperationId::Cipher),
        "operation bit must start cleared for OperationId::Cipher"
    );
    assert!(
        !provider.test_operation_bit(OperationId::Signature),
        "operation bit must start cleared for OperationId::Signature"
    );

    // Setting the bit for one operation must not affect the others.
    provider.set_operation_bit(OperationId::Digest);

    assert!(
        provider.test_operation_bit(OperationId::Digest),
        "after set_operation_bit(Digest) the bit must report true"
    );
    assert!(
        !provider.test_operation_bit(OperationId::Cipher),
        "set_operation_bit(Digest) must NOT set the Cipher bit"
    );
    assert!(
        !provider.test_operation_bit(OperationId::Signature),
        "set_operation_bit(Digest) must NOT set the Signature bit"
    );

    // Idempotence: setting the same bit twice keeps it set.
    provider.set_operation_bit(OperationId::Digest);
    assert!(
        provider.test_operation_bit(OperationId::Digest),
        "set_operation_bit() must be idempotent"
    );

    // Registering algorithms for an operation does not by itself set the
    // operation bit — set_operation_bit() is the caller's explicit
    // marker that enumeration has completed.  This assertion locks in
    // the decoupling that downstream callers rely on.
    let cipher_provider_name = provider.name().to_string();
    provider.register_algorithms(
        OperationId::Cipher,
        vec![make_cipher_descriptor("AES-256-GCM", "provider=default")],
    );
    assert!(
        !provider.test_operation_bit(OperationId::Cipher),
        "register_algorithms() must NOT toggle the operation bit by itself"
    );
    provider.set_operation_bit(OperationId::Cipher);
    assert!(
        provider.test_operation_bit(OperationId::Cipher),
        "explicit set_operation_bit(Cipher) must finally set the bit"
    );

    // Finally, after all the above, the provider name is still sane —
    // ensure the provider handle was not substituted behind the scenes.
    assert_eq!(provider.name(), cipher_provider_name);
}

// =============================================================================
// Phase 5 — Property Query Tests
// =============================================================================
//
// Reference: test/property_test.c lines 200-500 (parser_tests,
//            test_property_match, test_merge).

/// Parses a well-formed property definition and verifies the structural
/// invariants documented on [`parse_definition`].
#[test]
fn test_property_parse_valid() {
    let strings = PropertyStringStore::new();

    // Simple single-property definition.
    let list = parse_definition(&strings, "provider=default")
        .expect("parse_definition must accept 'provider=default'");
    assert_eq!(
        list.properties.len(),
        1,
        "a single-property definition must produce one entry"
    );
    assert!(
        !list.has_optional,
        "no '?' prefix in the input → has_optional must be false"
    );

    let entry = &list.properties[0];
    assert_eq!(entry.oper, PropertyOper::Eq);
    assert!(!entry.optional);
    assert_eq!(entry.prop_type, PropertyType::String);

    // The canonical pre-registered "provider" name has index 1.
    let provider_idx = strings
        .intern_name("provider", false)
        .expect("'provider' must be pre-interned");
    assert_eq!(entry.name_idx, provider_idx);

    // A multi-property definition round-trips into the same number of
    // entries.
    let multi = parse_definition(&strings, "provider=default,fips=yes,version=3")
        .expect("multi-property definition must parse");
    assert_eq!(
        multi.properties.len(),
        3,
        "three comma-separated properties must produce three entries"
    );

    // Name-alone is treated as boolean true (PROPERTY_TRUE).
    let boolean_true =
        parse_definition(&strings, "fips").expect("bareword must parse as PROPERTY_TRUE");
    assert_eq!(boolean_true.properties.len(), 1);
    assert_eq!(boolean_true.properties[0].oper, PropertyOper::Eq);
    match boolean_true.properties[0].value {
        PropertyValue::StringVal(idx) => {
            assert_eq!(idx, PROPERTY_TRUE, "bareword must resolve to PROPERTY_TRUE");
        }
        PropertyValue::Number(_) => {
            panic!("bareword must be stored as StringVal(PROPERTY_TRUE), not a Number")
        }
    }

    // Empty input is valid — it parses to an empty list.
    let empty =
        parse_definition(&strings, "").expect("empty definition must parse to an empty list");
    assert!(empty.properties.is_empty());

    // Malformed input must fail cleanly (Rule R5 — no 0-as-sentinel).
    let malformed = parse_definition(&strings, "!!!invalid!!!");
    assert!(malformed.is_err(), "malformed input must return Err");
}

/// Verifies that a property query with matching criteria yields
/// `Some(match_count)` from [`match_count`].
#[test]
fn test_property_match_positive() {
    let strings = PropertyStringStore::new();

    let defn = parse_definition(&strings, "provider=default,fips=no")
        .expect("parse_definition must succeed");

    // Query 1: empty query matches anything and returns Some(0).
    let empty_query = parse_query(&strings, "").expect("empty query must parse");
    assert_eq!(
        match_count(&empty_query, &defn),
        Some(0),
        "empty query is the universal match — count=0 by definition"
    );

    // Query 2: single-property positive match.
    let q1 = parse_query(&strings, "provider=default").expect("parse_query must succeed");
    assert_eq!(
        match_count(&q1, &defn),
        Some(1),
        "single-property positive match must return Some(1)"
    );

    // Query 3: two-property positive match.
    let q2 = parse_query(&strings, "provider=default,fips=no").expect("parse_query must succeed");
    assert_eq!(
        match_count(&q2, &defn),
        Some(2),
        "two-property positive match must return Some(2)"
    );
}

/// Verifies that a required-property mismatch yields `None` from
/// [`match_count`].
#[test]
fn test_property_match_negative() {
    let strings = PropertyStringStore::new();

    let defn = parse_definition(&strings, "provider=default,fips=no")
        .expect("parse_definition must succeed");

    // A required property that doesn't match must return None.
    let mismatch = parse_query(&strings, "provider=legacy").expect("parse_query must succeed");
    assert_eq!(
        match_count(&mismatch, &defn),
        None,
        "required-property mismatch must return None"
    );

    // Optional mismatch must NOT short-circuit the scan.
    let optional = parse_query(&strings, "?provider=legacy,fips=no")
        .expect("parse_query('?...') must succeed");
    let opt_result = match_count(&optional, &defn);
    assert!(
        opt_result.is_some(),
        "optional mismatch must fall through to the next property, yielding Some(_)"
    );
    // Only "fips=no" matches; the optional "provider=legacy" does not.
    assert_eq!(opt_result, Some(1));
}

/// Verifies the FIPS-selection semantic used by the EVP fetch path when
/// the caller requests `"fips=yes"` (and conversely, `"fips=no"`).
///
/// This is the scenario that drives the FIPS boundary per the AAP §0.7.3 —
/// a `"fips=yes"` query must select only FIPS-approved implementations.
#[test]
fn test_property_fips_query() {
    let strings = PropertyStringStore::new();

    let fips_defn = parse_definition(&strings, "provider=fips,fips=yes")
        .expect("parse_definition must succeed for fips defn");
    let default_defn = parse_definition(&strings, "provider=default,fips=no")
        .expect("parse_definition must succeed for default defn");
    let unlabelled_defn = parse_definition(&strings, "provider=default")
        .expect("parse_definition must succeed for unlabelled defn");

    let fips_yes = parse_query(&strings, "fips=yes").expect("parse_query fips=yes");
    let fips_no = parse_query(&strings, "fips=no").expect("parse_query fips=no");

    // "fips=yes" selects only fips-tagged providers.
    assert!(
        match_count(&fips_yes, &fips_defn).is_some(),
        "fips=yes query must match the fips provider"
    );
    assert!(
        match_count(&fips_yes, &default_defn).is_none(),
        "fips=yes query must NOT match the default (fips=no) provider"
    );
    assert!(
        match_count(&fips_yes, &unlabelled_defn).is_none(),
        "fips=yes query must NOT match a provider that omits fips — missing + yes → no match"
    );

    // "fips=no" selects providers that are explicitly fips=no AND also
    // providers that omit the property altogether (missing + value==FALSE
    // → matches, per property.rs:match_count()).
    assert!(
        match_count(&fips_no, &default_defn).is_some(),
        "fips=no must match explicitly-marked non-FIPS providers"
    );
    assert!(
        match_count(&fips_no, &unlabelled_defn).is_some(),
        "fips=no must match providers that omit the fips property (missing + FALSE → matches)"
    );
    assert!(
        match_count(&fips_no, &fips_defn).is_none(),
        "fips=no must NOT match the FIPS provider"
    );
}

// =============================================================================
// Phase 6 — Provider Fallback Tests
// =============================================================================
//
// Reference: test/provider_fallback_test.c lines 30-62 (implicit default
//            activation when no explicit provider was loaded).

/// Verifies that [`ProviderStore::activate_fallbacks`] auto-loads the
/// predefined fallback provider (the `default` provider) when the caller
/// has not explicitly loaded any provider.
///
/// Mirrors the C behaviour where `EVP_MD_fetch(NULL, ...)` succeeds even
/// when `OSSL_PROVIDER_load()` was never called — because the library
/// silently activates fallbacks on first use.
///
/// # Feature gating
///
/// This test is gated on `not(feature = "fips_module")` because the
/// fallback provider in the predefined registry differs by build profile:
/// non-FIPS builds register `default` as the fallback (see
/// `crypto/provider/predefined.rs::predefined_providers`, mirroring C
/// `provider_predefined.c` line 24), whereas the FIPS module build
/// registers `fips` as the sole predefined fallback (line 22 of the same
/// C file, gated by `#ifdef FIPS_MODULE`). The assertions below
/// (`available(&store, "default")`) therefore hold only for the non-FIPS
/// configuration. The FIPS-module fallback equivalent is exercised in
/// the dedicated FIPS test suite under `crates/openssl-fips/src/tests/`.
#[cfg(not(feature = "fips_module"))]
#[test]
fn test_provider_fallback_to_default() {
    let (_strings, store) = fresh_store();

    // Precondition: no provider is activated yet.
    assert!(
        !available(&store, "default"),
        "no provider should be activated before activate_fallbacks()"
    );
    assert!(!available(&store, "base"));
    assert!(!available(&store, "null"));

    // Activating fallbacks brings up the predefined fallback provider(s).
    store
        .activate_fallbacks()
        .expect("activate_fallbacks must succeed with a fresh store");

    // The `default` provider is flagged `is_fallback=true` in the
    // predefined list (see `provider/predefined.rs`) and must therefore
    // be activated.
    assert!(
        available(&store, "default"),
        "after activate_fallbacks(), 'default' (the fallback) must be available"
    );

    // The default provider's ProviderInstance must also report the
    // activated state through its own public accessor — the two views
    // (store.available vs. instance.is_activated) must agree.
    let instance = store
        .find("default")
        .expect("default instance must still be findable");
    assert!(
        instance.is_activated(),
        "ProviderInstance::is_activated() must agree with ProviderStore::available()"
    );
    assert!(
        instance.is_initialized(),
        "fallback activation must also set the initialized flag"
    );

    // activate_fallbacks() is idempotent — a second call is a no-op and
    // does not error or double-increment.
    store
        .activate_fallbacks()
        .expect("activate_fallbacks must be idempotent");
    assert!(
        available(&store, "default"),
        "default must remain available after a second activate_fallbacks() call"
    );
}

// =============================================================================
// Phase 7 — Provider Configuration Tests
// =============================================================================
//
// Reference: test/prov_config_test.c lines 40-100 (config-driven provider
//            activation).

/// Verifies that [`ProviderConfState::activate_from_config`] correctly
/// activates a provider when the config value is one of the documented
/// truthy spellings, and is a no-op for every other value.
#[test]
fn test_provider_from_config() {
    let (_strings, store) = fresh_store();
    let state = ProviderConfState::new();

    // A falsy config value (activate = 0) must NOT activate the
    // provider.  This is the "section exists but is disabled" case that
    // configuration files exercise when a sysadmin keeps a provider
    // pre-wired but toggled off.
    state
        .activate_from_config(&store, "default", "activate = 0")
        .expect("activate_from_config must succeed for falsy values (no-op)");
    assert!(
        !available(&store, "default"),
        "activate = 0 must be a no-op — provider must remain inactive"
    );

    // Another falsy value: "activate = no".
    state
        .activate_from_config(&store, "default", "activate = no")
        .expect("activate_from_config must succeed for 'no'");
    assert!(
        !available(&store, "default"),
        "activate = no must be a no-op"
    );

    // Another falsy value: "activate = false".
    state
        .activate_from_config(&store, "default", "activate = false")
        .expect("activate_from_config must succeed for 'false'");
    assert!(!available(&store, "default"));

    // The canonical truthy spelling documented in the `ProviderConfState`
    // Rustdoc: "activate = 1".
    state
        .activate_from_config(&store, "default", "activate = 1")
        .expect("activate_from_config must succeed for 'activate = 1'");
    assert!(
        available(&store, "default"),
        "activate = 1 must activate the default provider"
    );

    // Case-insensitive "yes" also activates.
    state
        .activate_from_config(&store, "base", "activate = YES")
        .expect("activate_from_config must succeed for 'YES'");
    assert!(
        available(&store, "base"),
        "activate = YES must activate the base provider (case-insensitive)"
    );

    // Case-insensitive "true" also activates.
    state
        .activate_from_config(&store, "null", "activate = True")
        .expect("activate_from_config must succeed for 'True'");
    assert!(
        available(&store, "null"),
        "activate = True must activate the null provider (case-insensitive)"
    );
}

// =============================================================================
// Phase 8 — `LibContext` Isolation Tests
// =============================================================================
//
// These tests exercise the per-`LibContext` `ProviderStoreData` (a
// separate HashMap-backed registry from the algorithm-dispatch
// `ProviderStore`) defined in `crates/openssl-crypto/src/context.rs`.

/// Verifies that two independent [`LibContext`] instances maintain
/// separate provider registrations — registering a provider in context A
/// must not make it visible in context B.
///
/// This is the Rust equivalent of the C invariant that
/// `OSSL_LIB_CTX_new()` returns a fresh context with its own provider
/// store, independent of the process-wide default context.
#[test]
fn test_provider_isolated_contexts() {
    let ctx1: Arc<LibContext> = LibContext::new();
    let ctx2: Arc<LibContext> = LibContext::new();

    // The two contexts must be distinct `Arc` instances.
    assert!(
        !Arc::ptr_eq(&ctx1, &ctx2),
        "LibContext::new() must return independent contexts"
    );

    // Register and activate "test-provider-a" in ctx1 only.
    {
        let mut store = ctx1.provider_store_mut();
        store.register("test-provider-a".to_string(), 100);
        assert!(
            store.activate("test-provider-a"),
            "activate() must return true for a just-registered provider"
        );
    }

    // ctx1 must now see the provider as activated.
    assert!(
        ctx1.provider_store().is_activated("test-provider-a"),
        "ctx1 must observe 'test-provider-a' as activated"
    );

    // ctx2 must NOT see the provider.
    assert!(
        !ctx2.provider_store().is_activated("test-provider-a"),
        "ctx2 must NOT observe 'test-provider-a' — it was registered on ctx1 only"
    );
    assert!(
        ctx2.provider_store().is_empty(),
        "ctx2 must start with an empty provider store"
    );

    // The public ensure_provider_activated() API (Rule R5 — returns
    // CryptoResult rather than a C-style sentinel) must report the
    // per-context view correctly.
    assert!(
        ctx1.ensure_provider_activated("test-provider-a").is_ok(),
        "ensure_provider_activated must succeed on ctx1"
    );
    let err = ctx2
        .ensure_provider_activated("test-provider-a")
        .expect_err("ensure_provider_activated must fail on ctx2");
    let msg = format!("{err}");
    assert!(
        msg.contains("not registered") || msg.contains("not activated"),
        "ctx2 error must describe the missing registration, got: {msg}"
    );
    assert!(matches!(err, CryptoError::Provider(_)));

    // Registering a different provider on ctx2 does not leak back to ctx1.
    {
        let mut store = ctx2.provider_store_mut();
        store.register("test-provider-b".to_string(), 50);
        assert!(store.activate("test-provider-b"));
    }
    assert!(ctx2.provider_store().is_activated("test-provider-b"));
    assert!(
        !ctx1.provider_store().is_activated("test-provider-b"),
        "ctx1 must NOT observe the provider registered on ctx2"
    );

    // Final cross-check: each context sees exactly one activated
    // provider, and the names do not overlap.
    let ctx1_names: Vec<String> = ctx1
        .provider_store()
        .activated_names()
        .map(ToString::to_string)
        .collect();
    let ctx2_names: Vec<String> = ctx2
        .provider_store()
        .activated_names()
        .map(ToString::to_string)
        .collect();
    assert_eq!(ctx1_names, vec!["test-provider-a".to_string()]);
    assert_eq!(ctx2_names, vec!["test-provider-b".to_string()]);
}

/// Verifies that a single [`LibContext`] yields the same provider-store
/// view across repeated accesses — i.e., multiple callers observe the
/// same registration state without requiring re-activation.
///
/// This is the "shared provider across fetches" pattern exercised by the
/// EVP fetch path, where repeated digest/cipher lookups within a single
/// context all consult the same underlying provider registry.
#[test]
fn test_provider_shared_across_fetches() {
    let ctx: Arc<LibContext> = LibContext::new();

    // Register and activate a single provider.
    {
        let mut store = ctx.provider_store_mut();
        store.register("shared-provider".to_string(), 200);
        assert!(store.activate("shared-provider"));
    }

    // Three successive reads on the same context must all see the
    // provider as activated — this is the invariant the EVP fetch path
    // relies on when it consults the provider store multiple times
    // per second under load.
    for fetch_idx in 0..3u32 {
        let store = ctx.provider_store();
        assert!(
            store.is_activated("shared-provider"),
            "fetch #{fetch_idx}: shared-provider must remain activated across repeated accesses"
        );
        assert_eq!(
            store.len(),
            1,
            "fetch #{fetch_idx}: exactly one provider registered"
        );
    }

    // Also verify through the public ensure_provider_activated() API
    // that the same consistency holds across repeated calls.
    for fetch_idx in 0..3u32 {
        ctx.ensure_provider_activated("shared-provider")
            .unwrap_or_else(|err| {
                panic!("ensure_provider_activated failed on fetch #{fetch_idx}: {err}")
            });
    }

    // Cloning the Arc<LibContext> gives another handle to the same
    // underlying context — the provider registration must be visible
    // via both handles.
    let ctx_clone: Arc<LibContext> = Arc::clone(&ctx);
    assert!(
        Arc::ptr_eq(&ctx, &ctx_clone),
        "Arc::clone must not create a new context"
    );
    assert!(
        ctx_clone.provider_store().is_activated("shared-provider"),
        "the cloned Arc must observe the shared provider as activated"
    );

    // Deactivation through one handle is visible through the other.
    {
        let mut store = ctx.provider_store_mut();
        assert!(
            store.deactivate("shared-provider"),
            "deactivate() must succeed for a registered provider"
        );
    }
    assert!(
        !ctx_clone.provider_store().is_activated("shared-provider"),
        "the cloned Arc must observe the deactivation"
    );

    // The provider is still *registered* — just no longer activated.
    assert_eq!(
        ctx.provider_store().len(),
        1,
        "deactivate() must not remove the registration"
    );
}
