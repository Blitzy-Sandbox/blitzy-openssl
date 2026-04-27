//! # Provider Framework Integration Tests
//!
//! Comprehensive test suite for the `openssl-provider` crate, verifying:
//!
//! - **Provider lifecycle:** Registration, activation, deactivation, teardown
//!   for all built-in providers (Default, Base, Legacy, Null).
//! - **Trait dispatch:** Verification that `query_operation()` returns correct
//!   algorithm descriptors for each provider and operation type.
//! - **Method store:** Algorithm registration, lookup by name/property, cache
//!   invalidation, concurrent access under [`parking_lot::RwLock`].
//! - **Algorithm correctness:** Known Answer Test vectors for provider-dispatched
//!   algorithms (digests, ciphers, MACs, KDFs).
//! - **Feature gates:** `#[cfg(feature = "legacy")]` correctly enables/disables
//!   legacy algorithms.
//! - **Parameter handling:** Typed parameter get/set via the Rust config struct
//!   pattern replacing C `OSSL_PARAM` dynamic parameter bags.
//! - **Callback pairing:** Registration-invocation tests per Rule R4.
//! - **Error paths:** Error types, propagation chains, and reason codes.
//! - **Concurrent access:** Thread-safe provider registry access per Rule R7.
//!
//! ## Source References
//!
//! These integration tests collectively exercise the Rust translations of:
//!
//! - `providers/defltprov.c` — Default provider (non-FIPS algorithm catalog)
//! - `providers/baseprov.c` — Base provider (encoder/decoder/store/RAND only)
//! - `providers/legacyprov.c` — Legacy provider (deprecated algorithms)
//! - `providers/nullprov.c` — Null provider (metadata-only sentinel)
//! - `providers/prov_running.c` — Provider running-state status function
//!
//! The C implementations export `OSSL_provider_init_fn` entry points that
//! register an `OSSL_DISPATCH` table; the Rust translation uses the
//! [`Provider`](crate::traits::Provider) trait and the
//! [`MethodStore`](crate::dispatch::MethodStore) registry to achieve the
//! same runtime-polymorphic algorithm dispatch with compile-time type safety.
//!
//! ## Test Organization
//!
//! | Module | Focus | Key Rules |
//! |--------|-------|-----------|
//! | `test_provider_lifecycle` | Create/register/query/teardown for all providers | R4, R7, R10 |
//! | `test_dispatch` | `MethodStore` operations, concurrent access | R4, R7, R10 |
//! | `test_default_provider` | Default provider algorithm catalog completeness | R10 |
//! | `test_legacy_provider` | Legacy provider with feature gate (`legacy`) | R10 |
//! | `test_base_provider` | Base provider encoder/decoder/store/RAND coverage | R10 |
//! | `test_null_provider` | Null provider metadata-only behaviour | R10 |
//! | `test_algorithm_correctness` | KAT vectors for dispatched algorithms | R10 |
//! | `cross_provider` | Cross-provider integration (multi-provider registration) | R7, R10 |
//!
//! ## Rules Enforced
//!
//! - **Rule R4 — Callback Registration-Invocation Pairing:** Every callback
//!   registration API has an integration test that registers a handler,
//!   triggers the event via normal execution, and asserts invocation with
//!   correct arguments.
//! - **Rule R7 — Concurrency Lock Granularity:** Concurrent access tests for
//!   shared state verify that [`MethodStore`](crate::dispatch::MethodStore)
//!   supports parallel fetch/register operations without deadlock or data
//!   corruption.
//! - **Rule R8 — Zero Unsafe Outside FFI:** No `unsafe` blocks appear in
//!   ANY test file in this module. The crate root enforces this with
//!   `#![forbid(unsafe_code)]`.
//! - **Rule R9 — Warning-Free Build:** Test code compiles warning-free under
//!   `RUSTFLAGS="-D warnings"`. Individual `#[allow(dead_code)]` attributes
//!   on shared test utilities carry explicit justification comments.
//! - **Rule R10 — Wiring Before Done:** Every provider module
//!   ([`default`](crate::default), [`base`](crate::base),
//!   [`null`](crate::null), [`legacy`](crate::legacy)) is reachable from
//!   the entry point via at least one integration test traversing the full
//!   provider → trait → dispatch → store path.
//!
//! ## Shared Test Utilities
//!
//! This module exposes three `pub(crate)` helper functions for use across
//! test submodules:
//!
//! - `create_test_store` — Construct a pre-populated
//!   [`MethodStore`](crate::dispatch::MethodStore) with the
//!   [`DefaultProvider`](crate::default::DefaultProvider) registered, ready
//!   for algorithm lookup tests without per-test boilerplate.
//! - `hex_encode` — Convert a byte slice into a lowercase hex string for
//!   Known Answer Test comparison.
//! - `hex_decode` — Parse a hex string into a byte vector for KAT input
//!   loading.
//!
//! These helpers are intentionally minimal and panic on invalid input —
//! acceptable in test code per AAP §0.8.6 ("No `unwrap()` or `expect()` in
//! library code — permitted in tests and CLI `main()`").

// =============================================================================
// Submodule Declarations
// =============================================================================
//
// The test submodule set is fixed and exhaustive: every built-in provider has
// a dedicated test module, and cross-cutting concerns (lifecycle, dispatch,
// algorithm correctness, cross-provider interop) have their own modules.
//
// Submodule visibility is private (`mod foo;` without `pub`) because these
// modules are compile-only test code — they are not part of the public API
// of this crate. They exist solely to be discovered by `cargo test` via the
// `#[cfg(test)] mod tests;` declaration in `lib.rs`.

// --- Per-provider test modules ---

/// Integration tests for the [`NullProvider`](crate::null::NullProvider).
///
/// Verifies metadata correctness, `query_operation()` returning `None` for
/// every [`OperationType`](openssl_common::OperationType), and full lifecycle
/// semantics (create → query → teardown). Exercises Rule R10 wiring
/// verification by routing through the
/// [`Provider`](crate::traits::Provider) trait including dynamic dispatch.
///
/// Source: `providers/nullprov.c` (80 LoC), `providers/prov_running.c`.
mod test_null_provider;

/// Integration tests for the [`BaseProvider`](crate::base::BaseProvider).
///
/// Verifies that the base provider exposes ONLY encoder, decoder, store, and
/// seed-source RAND operations — returning `None` for all cryptographic
/// algorithm operation types (digest, cipher, MAC, KDF, signature, KEM,
/// key management, key exchange). Exercises Rule R10 wiring verification.
///
/// Source: `providers/baseprov.c` (189 LoC).
mod test_base_provider;

/// Integration tests for the [`DefaultProvider`](crate::default::DefaultProvider).
///
/// Verifies that the default provider exposes algorithms for all 12 operation
/// categories (Digest, Cipher, MAC, KDF, RAND, KeyMgmt, Signature, AsymCipher,
/// KEM, KeyExchange, EncoderDecoder, Store) with correct metadata and the
/// `provider=default` property tag. Exercises Rule R10 wiring verification
/// by asserting full algorithm catalog completeness.
///
/// Source: `providers/defltprov.c` (840 LoC).
mod test_default_provider;

/// Feature-gated integration tests for the
/// [`LegacyProvider`](crate::legacy::LegacyProvider).
///
/// This module is compiled only when the `legacy` Cargo feature is enabled.
/// Verifies that the legacy provider exposes ONLY deprecated algorithms
/// (MD2/MD4/MDC2/Whirlpool/Blowfish/CAST5/IDEA/SEED/RC2/RC4/RC5/DES with
/// `provider=legacy` property tag) and does not duplicate default-provider
/// algorithms. Exercises Rule R10 wiring verification under the feature
/// flag.
///
/// Source: `providers/legacyprov.c` (326 LoC; C pattern: `#ifdef STATIC_LEGACY`).
#[cfg(feature = "legacy")]
mod test_legacy_provider;

// --- Cross-cutting test modules ---

/// Cross-cutting lifecycle tests spanning all built-in providers.
///
/// Exercises the full create → register → query → teardown path for
/// [`DefaultProvider`](crate::default::DefaultProvider),
/// [`BaseProvider`](crate::base::BaseProvider),
/// [`NullProvider`](crate::null::NullProvider), and (under the `legacy`
/// feature) [`LegacyProvider`](crate::legacy::LegacyProvider). Tests the
/// factory enum pattern and multi-provider registration in a single
/// [`MethodStore`](crate::dispatch::MethodStore). Exercises Rules R4
/// (callback registration), R7 (concurrent access), and R10 (wiring).
mod test_provider_lifecycle;

/// Integration tests for the [`MethodStore`](crate::dispatch::MethodStore)
/// and algorithm dispatch infrastructure.
///
/// Verifies:
/// - CRUD operations on the algorithm registry (register, fetch, remove).
/// - Property query matching (`provider=default`, `fips=yes`, wildcard).
/// - Cache behaviour (warm cache, cold cache, flush semantics).
/// - Concurrent access under the tri-locking scheme (Rule R7: separate locks
///   for cache, registry, and capabilities).
/// - Algorithm enumeration across operation types.
/// - The `register_provider()` coordinator pattern.
/// Exercises Rules R4, R7, and R10.
mod test_dispatch;

/// Known Answer Test (KAT) vectors for provider-dispatched algorithms.
///
/// Verifies digest (SHA-256, SHA-3-256), cipher (AES-GCM, AES-CBC), MAC
/// (HMAC-SHA-256), and KDF (HKDF, scrypt) correctness against published
/// NIST CAVP and RFC test vectors, routed through the full provider
/// dispatch path (provider → `query_operation()` → descriptor → factory →
/// context → `init`/`update`/`finalize`). Exercises Rule R10 by traversing
/// the complete algorithm resolution pipeline.
mod test_algorithm_correctness;

/// Cross-provider integration tests.
///
/// Verifies correct behaviour when multiple providers are registered in the
/// same [`MethodStore`](crate::dispatch::MethodStore): algorithm enumeration
/// composition, provider removal isolation, `get_params()` interoperability,
/// and provider metadata distinctness. These tests complement the
/// per-provider modules by focusing on multi-provider coordination.
mod cross_provider;

// =============================================================================
// Shared Test Utilities
// =============================================================================
//
// These helpers are `pub(crate)` so they are callable from any test submodule.
// Each carries `#[allow(dead_code)]` because not every submodule uses every
// helper — the individual per-provider modules (e.g. `test_null_provider`)
// typically operate on provider instances directly without needing a
// pre-populated store or hex utilities.
//
// Rule R9 compliance: these `#[allow(dead_code)]` attributes are scoped to
// individual items (not crate- or module-level) and each carries a
// justification comment. This is permitted per AAP §0.8.1 Rule R9
// ("Individual `#[allow]` must carry justification comment").

/// Creates a pre-populated [`MethodStore`](crate::dispatch::MethodStore) with
/// the [`DefaultProvider`](crate::default::DefaultProvider) registered.
///
/// This helper eliminates boilerplate in test submodules that need a
/// fully-populated algorithm registry to exercise
/// [`fetch`](crate::dispatch::MethodStore::fetch),
/// [`enumerate_algorithms`](crate::dispatch::MethodStore::enumerate_algorithms),
/// or property-based lookup. It is equivalent to writing:
///
/// ```ignore
/// let store = MethodStore::new();
/// let default = DefaultProvider::new();
/// store.register_provider(&default);
/// ```
///
/// The default provider is chosen because it registers algorithms across
/// every [`OperationType`](openssl_common::OperationType) category, giving
/// test code the broadest surface to exercise.
///
/// # Returns
///
/// A [`MethodStore`](crate::dispatch::MethodStore) containing the full
/// default-provider algorithm catalog. Additional providers can be
/// registered on top via
/// [`register_provider`](crate::dispatch::MethodStore::register_provider).
///
/// # Justification for `#[allow(dead_code)]`
///
/// Not every test submodule requires a pre-populated store — per-provider
/// modules (`test_null_provider`, `test_base_provider`) typically
/// instantiate providers directly and operate on them without indirection
/// through a store. Exposing this helper `pub(crate)` ensures it is
/// available as future tests are added without requiring each author to
/// re-derive the construction pattern.
#[allow(dead_code)]
pub(crate) fn create_test_store() -> crate::dispatch::MethodStore {
    let store = crate::dispatch::MethodStore::new();
    let default = crate::default::DefaultProvider::new();
    store.register_provider(&default);
    store
}

/// Encodes a byte slice as a lowercase hexadecimal string.
///
/// Each byte is formatted as exactly two lowercase hex digits (`0`-`9`,
/// `a`-`f`), producing an output length of `2 * bytes.len()`. No separators
/// are inserted; the result is suitable for direct comparison against
/// hex-encoded Known Answer Test vectors.
///
/// # Examples
///
/// ```ignore
/// use crate::tests::hex_encode;
///
/// assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
/// assert_eq!(hex_encode(&[]), "");
/// assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
/// ```
///
/// # Determinism
///
/// This function is deterministic and total — it never panics and never
/// allocates beyond the output string capacity (pre-sized to
/// `2 * bytes.len()`).
///
/// # Justification for `#[allow(dead_code)]`
///
/// KAT-oriented tests live primarily in
/// `test_algorithm_correctness`, which currently maintains a local copy
/// of this helper for ergonomic reasons (panic-on-error with distinct
/// wording vs. `unwrap`). Exposing a canonical workspace copy here
/// enables future test modules to share hex encoding without duplicating
/// logic.
#[allow(dead_code)]
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // `format!("{:02x}", b)` is equivalent and slightly more concise, but
        // the write! macro avoids allocating an intermediate String per byte.
        use std::fmt::Write;
        // Writing to a String via the Write trait is infallible in practice
        // (String's Write impl never errors); unwrap is permitted in tests.
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

/// Decodes a hexadecimal string into a byte vector.
///
/// Each pair of hex digits in `hex` is interpreted as one byte, producing a
/// `Vec<u8>` of length `hex.len() / 2`. Both lowercase (`a`-`f`) and
/// uppercase (`A`-`F`) hex digits are accepted.
///
/// # Panics
///
/// Panics if:
/// - `hex.len()` is odd (hex strings must have even length for byte pairing).
/// - Any character in `hex` is not a valid hex digit (`0`-`9`, `a`-`f`,
///   `A`-`F`).
///
/// Both failure modes indicate a malformed test vector — panicking is the
/// appropriate response in test code per AAP §0.8.6.
///
/// # Examples
///
/// ```ignore
/// use crate::tests::hex_decode;
///
/// assert_eq!(hex_decode("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(hex_decode("DEADBEEF"), vec![0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(hex_decode(""), vec![]);
/// ```
///
/// # Relationship to `hex_encode`
///
/// This function is the inverse of `hex_encode` for canonical inputs:
///
/// ```ignore
/// use crate::tests::{hex_encode, hex_decode};
///
/// let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
/// assert_eq!(hex_decode(&hex_encode(&bytes)), bytes);
/// ```
///
/// # Justification for `#[allow(dead_code)]`
///
/// Mirrors `hex_encode` — KAT tests typically carry a local copy for
/// historical reasons, but this canonical copy is exposed for future
/// test modules.
///
/// # Justification for `#[allow(clippy::panic)]`
///
/// This is a test utility whose inputs are compile-time constants embedded
/// in test source code (KAT vectors from NIST/RFC publications). A
/// malformed hex literal represents a test authoring error, not a runtime
/// condition — panicking with a diagnostic message is the correct behavior
/// because (a) returning `Result` would force every test site to call
/// `.unwrap()` and produce less informative failure messages, and (b) the
/// invariant that test vectors are well-formed hex is a developer
/// contract, not a user input. Rule R9 permits individual `#[allow]` with
/// justification, which this comment provides.
#[allow(dead_code)]
#[allow(clippy::panic)]
pub(crate) fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(
        hex.len() % 2 == 0,
        "hex_decode: input length {} is odd; hex strings must pair digits",
        hex.len()
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or_else(|_| {
                panic!("hex_decode: non-hex character at byte offset {i} in input '{hex}'")
            })
        })
        .collect()
}

// =============================================================================
// Unit Tests for Shared Helpers
// =============================================================================
//
// Self-tests for the test utilities above — this ensures the helpers
// themselves are correct, so test submodules can rely on them without
// secondary verification. These tests run in the same `cargo test` pass
// as the provider integration tests.

#[cfg(test)]
mod helper_self_tests {
    use super::{create_test_store, hex_decode, hex_encode};
    use openssl_common::OperationType;

    // ─── hex_encode ─────────────────────────────────────────────────────

    #[test]
    fn hex_encode_empty_input() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_single_byte_zero() {
        assert_eq!(hex_encode(&[0x00]), "00");
    }

    #[test]
    fn hex_encode_single_byte_max() {
        assert_eq!(hex_encode(&[0xff]), "ff");
    }

    #[test]
    fn hex_encode_known_pattern() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn hex_encode_all_lowercase_digits() {
        // Output must use only lowercase a-f.
        let encoded = hex_encode(&[0xab, 0xcd, 0xef]);
        assert_eq!(encoded, "abcdef");
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "hex_encode output must be lowercase"
        );
    }

    #[test]
    fn hex_encode_length_is_double_input() {
        // Output length is always exactly 2× input length.
        for n in 0usize..=32 {
            let input = vec![0x42u8; n];
            assert_eq!(hex_encode(&input).len(), n * 2);
        }
    }

    // ─── hex_decode ─────────────────────────────────────────────────────

    #[test]
    fn hex_decode_empty_input() {
        assert_eq!(hex_decode(""), Vec::<u8>::new());
    }

    #[test]
    fn hex_decode_known_pattern_lowercase() {
        assert_eq!(hex_decode("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_known_pattern_uppercase() {
        assert_eq!(hex_decode("DEADBEEF"), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_mixed_case() {
        assert_eq!(hex_decode("DeAdBeEf"), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_all_zero() {
        assert_eq!(hex_decode("0000"), vec![0x00, 0x00]);
    }

    #[test]
    fn hex_decode_all_ff() {
        assert_eq!(hex_decode("ffff"), vec![0xff, 0xff]);
    }

    #[test]
    #[should_panic(expected = "odd")]
    fn hex_decode_panics_on_odd_length() {
        let _ = hex_decode("abc");
    }

    #[test]
    #[should_panic(expected = "non-hex")]
    fn hex_decode_panics_on_invalid_character() {
        let _ = hex_decode("gg");
    }

    // ─── Round-trip property ─────────────────────────────────────────────

    #[test]
    fn encode_decode_round_trip() {
        // For any byte sequence, decode(encode(x)) == x.
        let cases: &[&[u8]] = &[
            &[],
            &[0x00],
            &[0xff],
            &[0xde, 0xad, 0xbe, 0xef],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            &[
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            ],
        ];
        for input in cases {
            let encoded = hex_encode(input);
            let decoded = hex_decode(&encoded);
            assert_eq!(
                decoded.as_slice(),
                *input,
                "round-trip failed for {input:?}"
            );
        }
    }

    #[test]
    fn decode_encode_round_trip_known_vectors() {
        // For canonical (lowercase) hex strings, encode(decode(s)) == s.
        let cases = [
            "",
            "00",
            "ff",
            "deadbeef",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        ];
        for input in cases {
            let decoded = hex_decode(input);
            let encoded = hex_encode(&decoded);
            assert_eq!(encoded, input, "encode(decode(\"{input}\")) did not match");
        }
    }

    // ─── create_test_store ──────────────────────────────────────────────

    #[test]
    fn create_test_store_returns_populated_store() {
        let store = create_test_store();

        // A populated store must have at least one digest algorithm
        // registered by the DefaultProvider (SHA-2 family).
        let digests = store.enumerate_algorithms(OperationType::Digest);
        assert!(
            !digests.is_empty(),
            "create_test_store() must produce a store with at least one digest algorithm"
        );
    }

    #[test]
    fn create_test_store_has_cipher_algorithms() {
        let store = create_test_store();

        // The DefaultProvider registers AES cipher algorithms.
        let ciphers = store.enumerate_algorithms(OperationType::Cipher);
        assert!(
            !ciphers.is_empty(),
            "create_test_store() must produce a store with at least one cipher algorithm"
        );
    }

    #[test]
    fn create_test_store_produces_independent_instances() {
        // Each call returns a fresh, independent store — mutations to one
        // must not affect another.
        let store_a = create_test_store();
        let store_b = create_test_store();

        store_a.flush_cache();
        // store_b should be unaffected — still have algorithms.
        let digests_b = store_b.enumerate_algorithms(OperationType::Digest);
        assert!(
            !digests_b.is_empty(),
            "independent store must retain algorithms after other store is modified"
        );
    }
}
