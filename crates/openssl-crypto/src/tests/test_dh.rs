//! Integration tests for the Diffie-Hellman (DH) key exchange module.
//!
//! This test module validates the public API of [`crate::dh`], covering:
//!
//! - **Named group parameter loading** — RFC 7919 FFDHE groups (2048–8192
//!   bit) and RFC 3526 MODP groups, verifying each yields coherent
//!   `(p, g, q)` triples.
//! - **Custom DH parameter generation** via [`crate::dh::generate_params`],
//!   covering success paths that route through the FFDHE named-group
//!   cache and error paths that reject out-of-range modulus sizes.
//! - **Key pair generation** via [`crate::dh::generate_key`], including
//!   verification that generated public keys are non-trivial per
//!   SP 800-56A Rev. 3 §5.6.2.3.1.
//! - **Shared secret computation** via [`crate::dh::compute_key`], with
//!   the canonical two-party Alice/Bob round-trip mirroring the C
//!   reference implementation in `test/dhtest.c`.
//! - **Parameter validation** via [`crate::dh::check_params`], including
//!   a typed-enum assertion for [`crate::dh::DhCheckResult`] that
//!   satisfies Rule R5 (nullability/typing over sentinels).
//! - **Property-based verification** of DH commutativity — for any random
//!   keypair pair, `g^(ab) mod p == g^(ba) mod p` must hold.
//!
//! # References
//!
//! - `test/dhtest.c` — C reference test (Alice/Bob exchange pattern)
//! - `crypto/dh/dh_key.c` — C implementation of `DH_generate_key` and
//!   `DH_compute_key`
//! - `crypto/dh/dh_check.c` — C implementation of `DH_check`
//! - `crypto/dh/dh_group_params.c` — RFC 7919 / RFC 3526 named-group
//!   parameter tables
//! - RFC 7919 (Negotiated FFDHE Parameters for TLS)
//! - NIST SP 800-56A Rev. 3 (Pair-Wise Key-Establishment Schemes)
//!
//! # Rule Compliance
//!
//! - **R5 (nullability over sentinels):** `check_params` returns a typed
//!   [`crate::dh::DhCheckResult`] enum — never an integer bitflag.
//! - **R6 (lossless numeric casts):** Narrowing casts in this test file
//!   use [`usize::try_from`]; no bare `as` casts for narrowing.
//! - **R8 (zero unsafe):** No `unsafe` blocks. Private key material is
//!   zeroed on drop via [`zeroize::ZeroizeOnDrop`] inside `DhPrivateKey`.

// Note on feature gating: this module is included by `tests/mod.rs` under
// `#[cfg(feature = "dh")]`, so a redundant inner `#![cfg(feature = "dh")]`
// here would trigger `clippy::duplicated_attributes`. The sibling test
// files (e.g., `test_hpke.rs`) follow the same convention.
//
// Test code legitimately uses `.expect()`, `.unwrap()`, and `panic!()` for
// assertion failures. The workspace lint configuration flags these as
// warnings; tests are explicitly allowed to suppress them with
// justification per the "Tests and CLI main() may #[allow] with
// justification" policy recorded in the workspace `Cargo.toml` lints
// table.
#![allow(clippy::expect_used)] // Tests call .expect() on known-good Results.
#![allow(clippy::unwrap_used)] // Tests call .unwrap() on values guaranteed to be Some/Ok.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive-match error arms.

use crate::bn::BigNum;
use crate::dh::*;
use openssl_common::{CryptoError, CryptoResult};
use proptest::prelude::*;

// =========================================================================
// Phase 2: Named Group Tests
//
// Verify that the RFC 7919 FFDHE groups and RFC 3526 MODP groups load
// correctly and produce parameter structures with the expected modulus
// bit length, non-trivial generator, and correctly-derived subgroup
// order `q`. Mirrors the parameter-setup portion of `test/dhtest.c`.
// =========================================================================

/// Verify that `from_named_group(Ffdhe2048)` yields RFC 7919-compliant
/// parameters with a 2048-bit modulus, a non-trivial generator, and a
/// properly-computed subgroup order `q = (p - 1) / 2`. Also runs
/// [`check_params`] as a belt-and-suspenders validation.
#[test]
fn test_dh_ffdhe2048_params() {
    let params: DhParams = from_named_group(DhNamedGroup::Ffdhe2048);

    // RFC 7919 §3.1: FFDHE2048 modulus is exactly 2048 bits.
    let p: &BigNum = params.p();
    assert_eq!(
        p.num_bits(),
        2048,
        "FFDHE2048 modulus p must be exactly 2048 bits"
    );
    assert!(!p.is_zero(), "FFDHE2048 modulus p must be non-zero");

    // RFC 7919 §2: all FFDHE groups use generator g = 2.
    let g: &BigNum = params.g();
    assert!(!g.is_zero(), "FFDHE2048 generator g must be non-zero");

    // For safe primes p = 2q + 1, the subgroup order q is pre-computed and
    // stored so that `check_params` and `compute_key` can validate peer
    // public keys against the prime-order subgroup.
    assert!(
        params.q().is_some(),
        "FFDHE2048 subgroup order q must be computed from (p-1)/2"
    );

    // Validate via the full parameter check — this exercises the prime
    // test and the generator-range check in `check_params`.
    let result = check_params(&params).expect("check_params must succeed on FFDHE2048");
    assert!(
        result.is_ok(),
        "FFDHE2048 named group must pass validation; got {result:?}"
    );
}

/// Verify that `from_named_group(Ffdhe3072)` yields a 3072-bit modulus
/// and passes validation.
#[test]
fn test_dh_ffdhe3072_params() {
    let params: DhParams = from_named_group(DhNamedGroup::Ffdhe3072);

    let p: &BigNum = params.p();
    assert_eq!(
        p.num_bits(),
        3072,
        "FFDHE3072 modulus p must be exactly 3072 bits"
    );
    assert!(!p.is_zero(), "FFDHE3072 modulus p must be non-zero");

    let g: &BigNum = params.g();
    assert!(!g.is_zero(), "FFDHE3072 generator g must be non-zero");

    assert!(
        params.q().is_some(),
        "FFDHE3072 subgroup order q must be computed"
    );

    let result = check_params(&params).expect("check_params must succeed on FFDHE3072");
    assert!(
        result.is_ok(),
        "FFDHE3072 named group must pass validation; got {result:?}"
    );
}

/// Verify that every variant of [`DhNamedGroup`] is constructible and
/// produces parameters whose modulus bit length matches the variant's
/// declared `bits()` size. Exercises the full named-group dispatch table
/// from `dh_group_params.c` — both the RFC 7919 FFDHE tier
/// (`Ffdhe2048` through `Ffdhe8192`) and the RFC 3526 MODP tier
/// (`ModP2048` through `ModP8192`).
#[test]
fn test_dh_named_group_enum() {
    // The complete set of 10 standard named groups.
    let all_groups: [DhNamedGroup; 10] = [
        DhNamedGroup::Ffdhe2048,
        DhNamedGroup::Ffdhe3072,
        DhNamedGroup::Ffdhe4096,
        DhNamedGroup::Ffdhe6144,
        DhNamedGroup::Ffdhe8192,
        DhNamedGroup::ModP2048,
        DhNamedGroup::ModP3072,
        DhNamedGroup::ModP4096,
        DhNamedGroup::ModP6144,
        DhNamedGroup::ModP8192,
    ];

    for group in all_groups {
        let params = from_named_group(group);

        // The modulus must match the variant's declared bit size exactly.
        assert_eq!(
            params.p().num_bits(),
            group.bits(),
            "group {group:?}: declared bits {} must match p modulus bits",
            group.bits()
        );

        // Generator is always non-zero (all standard named groups use
        // either g = 2 for FFDHE or g = 2 for most MODP groups).
        assert!(
            !params.g().is_zero(),
            "group {group:?}: generator must be non-zero"
        );

        // Every named group has a human-readable name.
        let name: &'static str = group.name();
        assert!(!name.is_empty(), "group {group:?}: name must be non-empty");
    }

    // Verify the Copy, Clone, and PartialEq derives on DhNamedGroup.
    let original = DhNamedGroup::Ffdhe2048;
    let copied: DhNamedGroup = original; // Copy (no move)
    assert_eq!(
        original, copied,
        "Copy + PartialEq must work on DhNamedGroup"
    );
    assert_ne!(
        DhNamedGroup::Ffdhe2048,
        DhNamedGroup::Ffdhe3072,
        "different variants must compare unequal"
    );

    // Verify the bit-size accessor returns the documented values.
    assert_eq!(DhNamedGroup::Ffdhe2048.bits(), 2048);
    assert_eq!(DhNamedGroup::Ffdhe3072.bits(), 3072);
    assert_eq!(DhNamedGroup::Ffdhe8192.bits(), 8192);
    assert_eq!(DhNamedGroup::ModP2048.bits(), 2048);
}

// =========================================================================
// Phase 3: Key Generation Tests
//
// Verify that DH key generation produces coherent, non-trivial keypairs.
// Mirrors the `DH_generate_key()` portion of `test/dhtest.c`.
// =========================================================================

/// Verify that `generate_key` on FFDHE2048 parameters produces a valid
/// keypair, and that all three [`DhKeyPair`] accessors (`private_key()`,
/// `public_key()`, `params()`) return coherent references. Exercises the
/// full key-generation path in `crypto/dh/dh_key.c`.
#[test]
fn test_dh_generate_key_from_named_group() {
    let params = from_named_group(DhNamedGroup::Ffdhe2048);
    let keypair: DhKeyPair = generate_key(&params).expect("key generation must succeed");

    // Public key accessor returns a reference to a valid public key.
    let public: &DhPublicKey = keypair.public_key();
    let pub_value: &BigNum = public.value();
    assert!(
        !pub_value.is_zero(),
        "generated public key must not be zero (rejects trivial keys per SP 800-56A §5.6.2.3.1)"
    );

    // Public key carries the parameter set used to generate it.
    assert_eq!(
        public.params().p().num_bits(),
        2048,
        "public key must carry FFDHE2048 parameters"
    );

    // Private key accessor returns a reference (values are redacted in
    // the `Debug` impl of `DhPrivateKey` to prevent accidental logging).
    let private: &DhPrivateKey = keypair.private_key();
    assert_eq!(
        private.params().p().num_bits(),
        2048,
        "private key must carry FFDHE2048 parameters"
    );

    // Params accessor on DhKeyPair delegates to the public key's params.
    let ref_params: &DhParams = keypair.params();
    assert_eq!(
        ref_params.p().num_bits(),
        2048,
        "keypair.params() must match public_key().params()"
    );
    assert!(!ref_params.g().is_zero());
}

/// Verify `generate_params` for a standard 2048-bit size (which routes
/// to the FFDHE2048 named group for efficiency, matching the C behavior
/// in `ossl_dh_get_named_group_uid_from_size()`) and for error cases:
/// too-small and too-large bit sizes. Validates that all error paths
/// return [`CryptoError::Key`] per Rule R5 (typed error variants over
/// sentinels).
#[test]
fn test_dh_generate_params_custom() {
    // --- Success case: 2048 bits ---
    // This is instant because it routes to the pre-validated FFDHE2048
    // named group rather than running safe-prime generation.
    let params: DhParams = generate_params(2048).expect("generate_params(2048) must succeed");
    assert_eq!(
        params.p().num_bits(),
        2048,
        "generated p must be exactly 2048 bits"
    );
    assert!(!params.g().is_zero(), "generated g must be non-zero");

    // --- Error case: below minimum modulus size (DH_MIN_MODULUS_BITS = 512) ---
    let too_small: CryptoResult<DhParams> = generate_params(256);
    assert!(
        too_small.is_err(),
        "generate_params(256) must reject bits below DH_MIN_MODULUS_BITS"
    );
    match too_small.expect_err("too-small must be an error") {
        CryptoError::Key(msg) => {
            // Per Rule R5: we verify the error is the typed `Key` variant,
            // not a string comparison on a generic error. The message is
            // inspected only for informative assertion failure output.
            assert!(
                msg.contains("too small") || msg.contains("minimum"),
                "error message should reference the size constraint; got: {msg}"
            );
        }
        other => panic!("expected CryptoError::Key for too-small bits, got {other:?}"),
    }

    // --- Error case: above maximum modulus size (DH_MAX_MODULUS_BITS = 32768) ---
    let too_large: CryptoResult<DhParams> = generate_params(65_536);
    assert!(
        too_large.is_err(),
        "generate_params(65536) must reject bits above DH_MAX_MODULUS_BITS"
    );
    match too_large.expect_err("too-large must be an error") {
        CryptoError::Key(msg) => {
            assert!(
                msg.contains("too large") || msg.contains("maximum"),
                "error message should reference the size constraint; got: {msg}"
            );
        }
        other => panic!("expected CryptoError::Key for too-large bits, got {other:?}"),
    }
}

/// Verify that a generated keypair's public key is a non-trivial value
/// (not zero, not one, and of substantial bit length relative to the
/// modulus). This guards against degenerate key generation per
/// SP 800-56A Rev. 3 §5.6.2.3.1, which mandates that public keys must
/// not equal 0, 1, or p-1.
#[test]
fn test_dh_keypair_public_key_not_zero() {
    let params = from_named_group(DhNamedGroup::Ffdhe2048);
    let keypair = generate_key(&params).expect("key generation must succeed");

    // Access the public key's BigNum value through the chain:
    // keypair -> public_key() -> value().
    let pub_value: &BigNum = keypair.public_key().value();

    // SP 800-56A: public key must not be zero (trivial key).
    assert!(!pub_value.is_zero(), "public key must not be zero");

    // With a uniformly-random private exponent over a 2048-bit modulus,
    // the resulting public key g^x mod p has bit length very close to
    // that of the modulus with overwhelming probability. A bit length
    // below half the modulus would indicate a critical RNG or modular-
    // exponentiation defect.
    let pub_bits = pub_value.num_bits();
    assert!(
        pub_bits > 1024,
        "public key bit length {pub_bits} is suspiciously small for 2048-bit modulus — \
         indicates potential RNG or modular-exponentiation defect"
    );

    // The public key must also be less than the modulus (by the definition
    // of modular exponentiation), so its bit count cannot exceed p's.
    assert!(
        pub_bits <= params.p().num_bits(),
        "public key bit length {pub_bits} must not exceed modulus bit length {}",
        params.p().num_bits()
    );
}

// =========================================================================
// Phase 4: Key Exchange Tests
//
// End-to-end DH shared-secret round-trip. Mirrors the `DH_compute_key()`
// symmetric-exchange portion of `test/dhtest.c` (the Alice/Bob pattern).
// =========================================================================

/// End-to-end DH shared-secret computation. Two parties (Alice and Bob)
/// each generate a keypair under the shared FFDHE2048 parameter set,
/// exchange public keys, and each computes the shared secret. The
/// commutativity of DH (`g^(ab) mod p == g^(ba) mod p`) requires both
/// parties to arrive at identical shared secrets. This test also
/// verifies that the shared secret is zero-padded to the byte length
/// of the modulus (256 bytes for FFDHE2048), per `DH_compute_key_padded`.
#[test]
fn test_dh_compute_shared_secret() {
    let params = from_named_group(DhNamedGroup::Ffdhe2048);

    // Alice and Bob independently generate keypairs under the same params.
    let alice: DhKeyPair = generate_key(&params).expect("Alice key generation");
    let bob: DhKeyPair = generate_key(&params).expect("Bob key generation");

    // Each side computes the shared secret using its own private key and
    // the peer's public key.
    let secret_alice: Vec<u8> = compute_key(alice.private_key(), bob.public_key(), &params)
        .expect("Alice compute_key must succeed");

    let secret_bob: Vec<u8> = compute_key(bob.private_key(), alice.public_key(), &params)
        .expect("Bob compute_key must succeed");

    // The fundamental commutativity property of DH.
    assert_eq!(
        secret_alice, secret_bob,
        "Alice and Bob shared secrets must match (DH commutativity)"
    );
    assert!(!secret_alice.is_empty(), "shared secret must not be empty");

    // Per SP 800-56A, the shared secret is zero-padded to the byte length
    // of `p` to prevent timing side-channels from variable-length secrets.
    // For FFDHE2048, `ceil(2048 / 8) = 256` bytes. Use `usize::try_from`
    // per Rule R6 — no bare `as` narrowing casts.
    let expected_len = usize::try_from((params.p().num_bits() + 7) / 8)
        .expect("modulus byte length fits in usize");
    assert_eq!(
        secret_alice.len(),
        expected_len,
        "shared secret must be zero-padded to modulus byte length"
    );
    assert_eq!(
        expected_len, 256,
        "FFDHE2048 shared-secret length must be 256 bytes"
    );
}

/// Verify that different peer public keys produce different shared
/// secrets. If Alice exchanges with Bob and, separately, with Charlie,
/// her two resulting shared secrets must differ — otherwise the DH
/// computation would have collapsed the keyspace, indicating a critical
/// defect. The probability of collision with uniformly-random private
/// exponents over a 2048-bit group is negligible (<< 2^-1024).
#[test]
fn test_dh_shared_secret_changes_with_different_keys() {
    let params = from_named_group(DhNamedGroup::Ffdhe2048);

    // Three independent keypairs under the same parameter set.
    let alice = generate_key(&params).expect("Alice keygen");
    let bob = generate_key(&params).expect("Bob keygen");
    let charlie = generate_key(&params).expect("Charlie keygen");

    // Alice computes shared secrets with Bob and with Charlie.
    let alice_bob =
        compute_key(alice.private_key(), bob.public_key(), &params).expect("compute Alice<>Bob");
    let alice_charlie = compute_key(alice.private_key(), charlie.public_key(), &params)
        .expect("compute Alice<>Charlie");

    // Her two shared secrets must differ.
    assert_ne!(
        alice_bob, alice_charlie,
        "shared secrets with different peers must differ"
    );

    // Both secrets must be the same length (modulus byte length), since
    // both were derived under the same parameter set.
    assert_eq!(
        alice_bob.len(),
        alice_charlie.len(),
        "both secrets must have the same (modulus-padded) length"
    );

    // Sanity check on length: FFDHE2048 → 256 bytes.
    let expected_len = usize::try_from((params.p().num_bits() + 7) / 8)
        .expect("modulus byte length fits in usize");
    assert_eq!(alice_bob.len(), expected_len);
}

// =========================================================================
// Phase 5: Parameter Validation Tests
//
// Verify that `check_params` accepts valid RFC 7919 parameters and that
// the `DhCheckResult` enum exposes its error variants as typed values
// (Rule R5). Mirrors the `DH_check()` bitflag portion of `test/dhtest.c`.
// =========================================================================

/// Verify that the RFC 7919 FFDHE named groups all pass `check_params`.
/// These groups are pre-validated safe primes, so validation is expected
/// to succeed without error and the typed result must equal
/// [`DhCheckResult::Ok`].
#[test]
fn test_dh_check_valid_params() {
    // --- FFDHE2048 ---
    let params_2048 = from_named_group(DhNamedGroup::Ffdhe2048);
    let result_2048: DhCheckResult =
        check_params(&params_2048).expect("check_params must succeed on FFDHE2048");
    assert!(
        result_2048.is_ok(),
        "FFDHE2048 must validate as Ok, got {result_2048:?}"
    );
    // PartialEq on DhCheckResult must allow direct variant comparison.
    assert_eq!(result_2048, DhCheckResult::Ok);

    // --- FFDHE3072 ---
    let params_3072 = from_named_group(DhNamedGroup::Ffdhe3072);
    let result_3072 = check_params(&params_3072).expect("check_params on FFDHE3072");
    assert!(
        result_3072.is_ok(),
        "FFDHE3072 must validate as Ok, got {result_3072:?}"
    );
    assert_eq!(result_3072, DhCheckResult::Ok);

    // --- FFDHE4096 ---
    let params_4096 = from_named_group(DhNamedGroup::Ffdhe4096);
    let result_4096 = check_params(&params_4096).expect("check_params on FFDHE4096");
    assert!(
        result_4096.is_ok(),
        "FFDHE4096 must validate as Ok, got {result_4096:?}"
    );
    assert_eq!(result_4096, DhCheckResult::Ok);

    // --- MODP2048 ---
    let params_modp = from_named_group(DhNamedGroup::ModP2048);
    let result_modp = check_params(&params_modp).expect("check_params on ModP2048");
    assert!(
        result_modp.is_ok(),
        "ModP2048 must validate as Ok, got {result_modp:?}"
    );
}

/// Verify that [`DhCheckResult`] is a typed enum (per Rule R5 — no
/// integer bitflag sentinels). Every variant must be explicitly
/// constructible, `is_ok()` must return `true` only for the
/// [`DhCheckResult::Ok`] variant, and the derived `PartialEq` must
/// distinguish all variants.
///
/// This directly mirrors the C `DH_check()` bitflag constants
/// (`DH_CHECK_P_NOT_PRIME`, `DH_MODULUS_TOO_SMALL`, `DH_UNABLE_TO_CHECK_GENERATOR`,
/// etc.) as reconstituted into a type-safe Rust enum.
#[test]
fn test_dh_check_result_enum() {
    // Pair each variant with its expected `is_ok()` result. All error
    // variants must return `false`; only `Ok` returns `true`.
    let variants_and_expected: &[(DhCheckResult, bool)] = &[
        (DhCheckResult::Ok, true),
        (DhCheckResult::PNotPrime, false),
        (DhCheckResult::NotSuitableGenerator, false),
        (DhCheckResult::ModulusTooSmall, false),
        (DhCheckResult::ModulusTooLarge, false),
        (DhCheckResult::QNotPrime, false),
        (DhCheckResult::InvalidQ, false),
    ];

    for (variant, expected_is_ok) in variants_and_expected {
        assert_eq!(
            variant.is_ok(),
            *expected_is_ok,
            "{variant:?}.is_ok() expectation mismatch"
        );

        // Every variant must be Debug-formattable (exercises the Debug
        // derive and the Display impl's underlying implementation).
        let debug_repr = format!("{variant:?}");
        assert!(
            !debug_repr.is_empty(),
            "{variant:?}: Debug output must be non-empty"
        );

        // Every variant must also be Display-formattable.
        let display_repr = format!("{variant}");
        assert!(
            !display_repr.is_empty(),
            "{variant:?}: Display output must be non-empty"
        );
    }

    // PartialEq: variants must compare equal only to themselves.
    assert_eq!(DhCheckResult::Ok, DhCheckResult::Ok);
    assert_ne!(DhCheckResult::Ok, DhCheckResult::PNotPrime);
    assert_ne!(DhCheckResult::PNotPrime, DhCheckResult::ModulusTooSmall);
    assert_ne!(DhCheckResult::QNotPrime, DhCheckResult::InvalidQ);
    assert_ne!(
        DhCheckResult::ModulusTooSmall,
        DhCheckResult::ModulusTooLarge
    );

    // Clone derive must produce an identical value.
    let cloned = DhCheckResult::NotSuitableGenerator.clone();
    assert_eq!(cloned, DhCheckResult::NotSuitableGenerator);
}

// =========================================================================
// Phase 6: Property-Based Tests
//
// Proptest-driven verification of the fundamental DH commutativity
// property over randomly-sampled keypairs.
// =========================================================================

proptest! {
    // Use a low case count because each iteration performs two full key
    // generations plus two modular exponentiations over a 2048-bit
    // modulus. Each iteration takes roughly 200 ms on a modern x86_64
    // host; the default of 256 cases would take ~50 seconds, which is
    // prohibitive for the standard test suite. Four cases provide
    // sufficient signal for property violations while keeping runtime
    // under one second.
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 4,
        .. ProptestConfig::default()
    })]

    /// **DH commutativity property.**
    ///
    /// For any two keypairs `(a, A = g^a mod p)` and `(b, B = g^b mod p)`
    /// generated under the same parameter set, the shared secret computed
    /// as `compute_key(a_priv, B_pub, params)` must equal the shared
    /// secret computed as `compute_key(b_priv, A_pub, params)`, regardless
    /// of which side initiates. This verifies the fundamental algebraic
    /// identity `g^(ab) mod p == g^(ba) mod p` for randomly-sampled
    /// private exponents.
    ///
    /// The `seed` parameter drives proptest's iteration counter and
    /// satisfies the schema's `any::<u64>()` generator requirement.
    /// The actual random key material for each iteration is sourced from
    /// the operating system's secure RNG (inside `generate_key`), which
    /// is independent of proptest's seed — this ensures the test
    /// exercises truly different keypairs on each run.
    #[test]
    fn prop_dh_key_exchange_consistent(seed in any::<u64>()) {
        // Acknowledge the proptest-generated seed. Its purpose is to
        // drive iteration distinctness, not to seed key generation —
        // key material comes from the OS RNG.
        let _ = seed;

        let params = from_named_group(DhNamedGroup::Ffdhe2048);

        let alice = generate_key(&params).expect("alice keygen");
        let bob = generate_key(&params).expect("bob keygen");

        // Alice's view of the shared secret.
        let secret_a = compute_key(
            alice.private_key(),
            bob.public_key(),
            &params,
        ).expect("alice compute");

        // Bob's view of the shared secret.
        let secret_b = compute_key(
            bob.private_key(),
            alice.public_key(),
            &params,
        ).expect("bob compute");

        // The commutativity invariant — the property under test.
        prop_assert_eq!(secret_a, secret_b);
    }
}
