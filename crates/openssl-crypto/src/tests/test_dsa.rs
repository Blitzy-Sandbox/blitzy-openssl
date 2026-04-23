//! Integration tests for the Digital Signature Algorithm (DSA) module.
//!
//! This test module validates the public API of [`crate::dsa`] against the
//! FIPS 186-4 specification and the behavioral contract established by the
//! C reference implementation in `crypto/dsa/`. Tests are organized into
//! four phases mirroring the C reference test structure in `test/dsatest.c`
//! and `test/dsa_no_digest_size_test.c`:
//!
//! | Phase | Focus                         | C Reference                        |
//! |-------|-------------------------------|------------------------------------|
//! | 2     | Parameter generation (p,q,g)  | `test/dsatest.c::dsatest_default_`  |
//! | 3     | Key pair generation           | `crypto/dsa/dsa_key.c`             |
//! | 4     | Sign / verify roundtrips      | `crypto/dsa/dsa_sign.c`, `dsa_vrf.c` |
//! | 5     | Edge cases & typed return     | `test/dsa_no_digest_size_test.c`   |
//!
//! # Rule Compliance
//!
//! - **R5 (nullability / typing over sentinels):** [`crate::dsa::verify`]
//!   returns [`crate::CryptoResult`]`<`[`bool`]`>` rather than a C-style
//!   integer sentinel. The dedicated test [`test_dsa_verify_returns_result_bool`]
//!   statically binds the return type to prove this contract.
//! - **R6 (lossless numeric casts):** Narrowing from [`u32`] bit-counts or
//!   [`usize`] byte-counts uses `try_from` where narrowing might occur; no
//!   bare `as` casts are used for narrowing conversions in this file.
//! - **R8 (zero unsafe outside FFI):** This file contains zero `unsafe`
//!   blocks. Private-key material in [`crate::dsa::DsaPrivateKey`] is
//!   zeroed on drop via the `zeroize::ZeroizeOnDrop` derive inside the
//!   `dsa` module — tests never need to manage the boundary manually.
//!
//! # References
//!
//! - `test/dsatest.c` — Upstream C reference test for DSA parameter and
//!   signature generation.
//! - `test/dsa_no_digest_size_test.c` — Upstream C reference for the
//!   FIPS 186-4 §C.2.1 digest-truncation rule.
//! - `crypto/dsa/dsa_sign.c` — Reference signing implementation.
//! - `crypto/dsa/dsa_vrf.c` — Reference verification implementation.
//! - FIPS PUB 186-4 §4 (Digital Signature Algorithm).

// -----------------------------------------------------------------------------
// Feature gating
// -----------------------------------------------------------------------------
// NOTE: This module is included by `tests/mod.rs` under
// `#[cfg(feature = "dsa")]`, so adding a redundant inner
// `#![cfg(feature = "dsa")]` here would trigger the
// `clippy::duplicated_attributes` lint. The sibling test files
// (e.g., `test_dh.rs`, `test_rand.rs`) follow the same convention.
//
// -----------------------------------------------------------------------------
// Module-level lint overrides for test code.
// -----------------------------------------------------------------------------
// Justification: The workspace crate-root configuration in `lib.rs` sets
//   #![deny(clippy::unwrap_used)]
//   #![deny(clippy::expect_used)]
// because library code must always propagate errors with `?`. Test code,
// however, legitimately uses `.unwrap()` / `.expect()` / `panic!()` for
// failing-assertion semantics — a Rust-idiomatic testing pattern. The
// workspace lints table in `Cargo.toml` records that tests are explicitly
// allowed to suppress these lints with a justification comment, matching
// the convention used in all real test modules (`test_dh.rs`,
// `test_rand.rs`, `test_hpke.rs`, `test_mac.rs`, etc.).
#![allow(clippy::unwrap_used)] // Tests call .unwrap() on known-good Results.
#![allow(clippy::expect_used)] // Tests use .expect() with descriptive messages.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive-match error arms.

use crate::bn::{arithmetic, montgomery, BigNum};
use crate::dsa::*;
use openssl_common::{CryptoError, CryptoResult};

// =============================================================================
// Test Helpers
// =============================================================================
//
// DSA parameter generation is an expensive operation — generating 2048-bit
// parameters with a 256-bit subprime can take several seconds of CPU time.
// For tests that merely need *a* valid parameter set (not a size-specific
// one), we use 1024-bit parameters which generate in a fraction of a
// second.

/// Generate a fresh 1024-bit DSA parameter set for use in key-generation
/// and sign/verify tests. 1024-bit parameters have a 160-bit subprime and
/// a 20-byte signature, making them fast enough for the sign/verify test
/// loop.
fn gen_params_1024() -> DsaParams {
    generate_params(1024).expect("1024-bit DSA parameter generation must succeed")
}

/// Generate a fresh 1024-bit DSA keypair for use in signing and
/// verification tests. Delegates to [`gen_params_1024`] for the parameter
/// set and then to [`crate::dsa::generate_key`] for the keypair.
fn gen_keypair_1024() -> DsaKeyPair {
    let params = gen_params_1024();
    generate_key(&params).expect("DSA key generation must succeed on valid parameters")
}

// =============================================================================
// Phase 2: Parameter Generation Tests
// =============================================================================
//
// Verify that DSA parameter generation produces coherent (p, q, g) triples
// matching FIPS 186-4 §4.1 invariants. Mirrors `test/dsatest.c::dsatest_default_`
// parameter-setup logic (C reference uses a fixed seed for determinism;
// our implementation uses fresh entropy per invocation).

/// Verify that `generate_params(1024)` yields a 1024-bit prime modulus `p`,
/// a non-zero subprime `q`, and a non-zero generator `g`. Matches the
/// `L = 1024, N = 160` parameter pair from FIPS 186-4 Table 1.
#[test]
fn test_dsa_generate_params_1024() {
    let params = gen_params_1024();

    // FIPS 186-4 Table 1: L = 1024 → p is exactly 1024 bits.
    let p: &BigNum = params.p();
    assert!(!p.is_zero(), "generated DSA prime p must be non-zero");
    assert_eq!(
        p.num_bits(),
        1024,
        "1024-bit generation must produce a 1024-bit prime p"
    );

    // FIPS 186-4 Table 1: for L = 1024, N ∈ {160}. The `select_subprime_bits`
    // function in the `dsa` module pairs L = 1024 with N = 160.
    let q: &BigNum = params.q();
    assert!(!q.is_zero(), "generated DSA subprime q must be non-zero");
    assert_eq!(
        q.num_bits(),
        160,
        "1024-bit DSA params must produce a 160-bit subprime per FIPS 186-4 Table 1"
    );

    // Generator g must be in the open range (1, p). The `DsaParams::new`
    // validator enforces this, so a successfully-generated parameter set
    // is guaranteed to satisfy the constraint. Belt-and-suspenders check:
    let g: &BigNum = params.g();
    assert!(!g.is_zero(), "generated DSA generator g must be non-zero");
    assert!(!g.is_one(), "generated DSA generator g must not equal one");
    assert!(
        g < p,
        "generated DSA generator g must be strictly less than p"
    );
}

/// Verify that `generate_params(2048)` yields a 2048-bit prime modulus `p`
/// and a subprime `q` matching one of the FIPS 186-4 permitted sizes for
/// L = 2048: N ∈ {224, 256}.
///
/// This test is marked `#[ignore]` because 2048-bit parameter generation
/// can take many seconds of CPU time and is not required for routine
/// development iteration. It is exercised explicitly by the nightly CI
/// pipeline via `cargo test -- --ignored` to validate the slower code
/// path without slowing down the default workflow. This matches the
/// approach used by the C reference test `test/dsatest.c`, which
/// similarly conditions its 2048-bit suite on a longer timeout.
#[test]
#[ignore = "2048-bit DSA parameter generation is CPU-intensive; run with --ignored"]
fn test_dsa_generate_params_2048() {
    let params = generate_params(2048).expect("2048-bit DSA parameter generation must succeed");

    // FIPS 186-4 Table 1: L = 2048 → p is exactly 2048 bits.
    let p: &BigNum = params.p();
    assert!(!p.is_zero(), "generated DSA prime p must be non-zero");
    assert_eq!(
        p.num_bits(),
        2048,
        "2048-bit generation must produce a 2048-bit prime p"
    );

    // FIPS 186-4 Table 1: for L = 2048, N ∈ {224, 256}. Both are acceptable.
    let q: &BigNum = params.q();
    assert!(!q.is_zero(), "generated DSA subprime q must be non-zero");
    let q_bits = q.num_bits();
    assert!(
        q_bits == 224 || q_bits == 256,
        "2048-bit DSA params must produce a 224- or 256-bit subprime (got {q_bits} bits) per FIPS 186-4 Table 1"
    );

    let g: &BigNum = params.g();
    assert!(!g.is_zero(), "generated DSA generator g must be non-zero");
    assert!(!g.is_one(), "generated DSA generator g must not equal one");
    assert!(
        g < p,
        "generated DSA generator g must be strictly less than p"
    );
}

/// Verify the core FIPS 186-4 §4.1 invariant: the subprime `q` must
/// divide `(p - 1)` exactly. This is the algebraic precondition for the
/// existence of a subgroup of order `q` in `(Z/pZ)*`, which is what
/// makes DSA sound.
///
/// The arithmetic performed is:
///
/// ```text
///   Let r = (p - 1) mod q
///   Assert r == 0
/// ```
///
/// This directly validates the C invariant in `crypto/dsa/dsa_gen.c`.
#[test]
fn test_dsa_params_q_divides_p_minus_1() {
    let params = gen_params_1024();

    // Compute p - 1 using the public `arithmetic::sub` helper (infallible
    // for arbitrary-precision BigInt-backed operands). Using the free
    // function rather than the `Sub` operator impl keeps the dependency
    // chain flat and explicit.
    let p_minus_1: BigNum = arithmetic::sub(params.p(), &BigNum::one());
    assert!(
        !p_minus_1.is_zero(),
        "p - 1 must be non-zero for any valid DSA prime p > 1"
    );

    // Divide (p - 1) by q using `div_rem`, which returns (quotient, remainder).
    // If q divides (p - 1) exactly — as FIPS 186-4 §4.1 requires — the
    // remainder is zero.
    let (quotient, remainder) =
        arithmetic::div_rem(&p_minus_1, params.q()).expect("div_rem by non-zero q must succeed");

    assert!(
        remainder.is_zero(),
        "FIPS 186-4 §4.1: q must divide (p - 1); remainder was {remainder}"
    );

    // Sanity: the quotient must also be non-zero (p - 1 ≥ q).
    assert!(
        !quotient.is_zero(),
        "(p - 1) / q must be non-zero; p and q structurally impossible otherwise"
    );
}

// =============================================================================
// Phase 3: Key Generation Tests
// =============================================================================
//
// Verify that key generation from a valid parameter set yields a
// mathematically coherent (private_key, public_key) pair where
// y = g^x mod p. Mirrors `crypto/dsa/dsa_key.c::dsa_keygen`.

/// Verify that `generate_key` on valid 1024-bit parameters produces a
/// keypair where all three accessors (`private_key()`, `public_key()`,
/// `params()`) return coherent references, and the private/public key
/// values themselves are non-zero.
#[test]
fn test_dsa_generate_key() {
    let params = gen_params_1024();
    let keypair: DsaKeyPair =
        generate_key(&params).expect("DSA key generation must succeed on valid parameters");

    // Private key accessor returns a reference to a valid private scalar
    // `x` in the range [1, q-1]. The private scalar itself is wrapped in
    // a `zeroize` guard for secure erasure on drop (see R8 compliance).
    let private: &DsaPrivateKey = keypair.private_key();
    let x: &BigNum = private.value();
    assert!(
        !x.is_zero(),
        "generated DSA private key x must be non-zero (1 ≤ x ≤ q-1)"
    );
    assert!(
        x < params.q(),
        "generated DSA private key x must satisfy x < q"
    );

    // Public key accessor returns a reference to the corresponding public
    // value `y = g^x mod p`, which must also be non-zero and less than p.
    let public: &DsaPublicKey = keypair.public_key();
    let y: &BigNum = public.value();
    assert!(
        !y.is_zero(),
        "generated DSA public key y must be non-zero (rejects y = 0 per SP 800-89)"
    );
    assert!(
        !y.is_one(),
        "generated DSA public key y must not equal one (rejects y = 1 per SP 800-89)"
    );
    assert!(y < params.p(), "generated DSA public key y must satisfy y < p");

    // Params accessor on DsaKeyPair must return the same parameter set
    // used at generation time (by-value equality).
    let ref_params: &DsaParams = keypair.params();
    assert_eq!(
        ref_params.p(),
        params.p(),
        "keypair.params().p() must equal the input parameter p"
    );
    assert_eq!(
        ref_params.q(),
        params.q(),
        "keypair.params().q() must equal the input parameter q"
    );
    assert_eq!(
        ref_params.g(),
        params.g(),
        "keypair.params().g() must equal the input parameter g"
    );

    // The parameter set carried by the private key must also match.
    assert_eq!(
        private.params().p(),
        params.p(),
        "private_key.params().p() must equal the original parameter p"
    );
    // And the public key's parameter set must likewise match.
    assert_eq!(
        public.params().p(),
        params.p(),
        "public_key.params().p() must equal the original parameter p"
    );
}

/// Verify the mathematical relationship between the private and public
/// components of a DSA keypair: `y = g^x mod p`.
///
/// This test extracts `x` from the private key, `(p, g)` from the
/// parameter set, and independently computes `y_computed = g^x mod p`
/// using the public [`montgomery::mod_exp`] primitive. It then asserts
/// that `y_computed` equals the `y` stored in the generated public key,
/// proving that key generation is internally consistent.
///
/// This mirrors the relationship validated by OpenSSL's C function
/// `DSA_check_key_pair` (defined in `crypto/dsa/dsa_check.c`).
#[test]
fn test_dsa_public_key_derivable() {
    let keypair = gen_keypair_1024();

    // Extract references to all the components needed for the derivation.
    let x: &BigNum = keypair.private_key().value();
    let params: &DsaParams = keypair.params();
    let p: &BigNum = params.p();
    let g: &BigNum = params.g();
    let y_stored: &BigNum = keypair.public_key().value();

    // Independently recompute y = g^x mod p using the modular
    // exponentiation primitive. This MUST match the stored public key.
    let y_computed: BigNum = montgomery::mod_exp(g, x, p)
        .expect("modular exponentiation g^x mod p must succeed for valid DSA params");

    // BigNum derives `PartialEq`, so we can use `assert_eq!` directly.
    // If this assertion fails, either key generation is broken or the
    // modular-exponentiation primitive disagrees with the one used
    // internally by `generate_key` — both are defects.
    assert_eq!(
        &y_computed, y_stored,
        "DSA public key y must equal g^x mod p (FIPS 186-4 §4.1 keygen invariant)"
    );
}

// =============================================================================
// Phase 4: Sign / Verify Tests
// =============================================================================
//
// Verify the DSA signing and verification contract. The signing function
// follows the recipe in `crypto/dsa/dsa_sign.c::DSA_do_sign` (generate
// per-message nonce k, compute r = (g^k mod p) mod q, compute s = k^-1
// (m + xr) mod q). Verification follows `crypto/dsa/dsa_vrf.c`.

/// The canonical sign/verify roundtrip: generate a keypair, sign a
/// digest with the private key, and verify the signature with the
/// corresponding public key. The verification must return `Ok(true)`.
///
/// This is the core contract of DSA — if this test fails, DSA is
/// fundamentally broken.
#[test]
fn test_dsa_sign_verify_roundtrip() {
    let keypair = gen_keypair_1024();

    // Use a 20-byte SHA-1-sized digest; 1024-bit DSA with N = 160 accepts
    // digests up to 20 bytes without truncation per FIPS 186-4 §C.2.1.
    let digest: [u8; 20] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];

    // Sign the digest with the private key. The signature is a `Vec<u8>`
    // containing the fixed-size r‖s encoding (40 bytes for 1024-bit DSA).
    let signature: Vec<u8> =
        sign(keypair.private_key(), &digest).expect("DSA signing must succeed on a valid digest");

    // Signature length must be exactly 2 × q_byte_len. For N = 160 bits
    // → 20 bytes → total 40 bytes. This is the fixed-size r‖s encoding.
    assert_eq!(
        signature.len(),
        40,
        "1024-bit DSA signature must be exactly 2 × 20 = 40 bytes"
    );

    // Verify the signature with the public key — MUST return Ok(true).
    let result: CryptoResult<bool> = verify(keypair.public_key(), &digest, &signature);
    let verified: bool = result.expect("verification of a legitimate signature must not error");
    assert!(
        verified,
        "DSA sign/verify roundtrip must succeed: valid signature must verify as true"
    );
}

/// Verify that a signature produced by one keypair does NOT verify under
/// a different keypair's public key. The verification function MUST
/// return `Ok(false)` (not `Err`) in this case — a cryptographic
/// "signature is well-formed but does not match the claimed signer"
/// outcome, not an error condition.
#[test]
fn test_dsa_verify_wrong_key_fails() {
    // Generate two independent keypairs sharing the same parameter set.
    // Sharing parameters is the realistic threat model: an attacker
    // cannot swap parameters, only keys.
    let params = gen_params_1024();
    let keypair_signer = generate_key(&params).expect("signer keypair generation must succeed");
    let keypair_other = generate_key(&params).expect("other keypair generation must succeed");

    // Sanity: the two public keys must differ (collision probability is
    // astronomically low for a 160-bit subgroup).
    assert_ne!(
        keypair_signer.public_key().value(),
        keypair_other.public_key().value(),
        "two independently-generated DSA keys must produce distinct public keys"
    );

    let digest: [u8; 20] = [0xAB; 20];
    let signature = sign(keypair_signer.private_key(), &digest)
        .expect("signing with the signer's private key must succeed");

    // Verify with the WRONG public key. The signature is well-formed
    // (r and s are in range), so `from_bytes` will parse it — but the
    // final comparison `v == r` will fail, returning Ok(false).
    let result = verify(keypair_other.public_key(), &digest, &signature);
    match result {
        Ok(false) => {
            // Expected: well-formed but invalid signature → false.
        }
        Ok(true) => {
            panic!("signature verified under wrong public key — DSA soundness broken");
        }
        Err(e) => {
            panic!(
                "wrong-key verification must return Ok(false), not an error; got Err({e:?})"
            );
        }
    }
}

/// Verify that a tampered signature (one bit flipped) fails to verify
/// under the original keypair's public key. Because we flip a bit
/// inside the `r` or `s` portion without changing the overall length,
/// the signature remains *structurally valid* — `DsaSignature::from_bytes`
/// parses it successfully — but the mathematical verification step
/// fails, returning `Ok(false)`.
#[test]
fn test_dsa_verify_tampered_signature_fails() {
    let keypair = gen_keypair_1024();
    let digest: [u8; 20] = [0xCD; 20];

    let mut signature = sign(keypair.private_key(), &digest).expect("signing must succeed");
    assert_eq!(
        signature.len(),
        40,
        "1024-bit DSA signature must be 40 bytes"
    );

    // Flip the LEAST-SIGNIFICANT BIT of the last byte of `r` (index 19).
    // This keeps the signature the same length and, with overwhelming
    // probability, keeps `r` inside the legal range (1 ≤ r < q), so
    // `from_bytes` will still parse successfully. The mathematical
    // `v == r` comparison inside `verify` will then fail.
    //
    // We specifically avoid flipping the high bit of r, which could
    // push r ≥ q on a boundary value and cause `verify` to return
    // Ok(false) via the early `r >= q` reject rather than the main
    // equality mismatch — both are acceptable observations, but we
    // want the main path exercised.
    signature[19] ^= 0x01;

    let result = verify(keypair.public_key(), &digest, &signature);
    match result {
        // Both outcomes are acceptable negative-verification signals:
        //   Ok(false):                         bit-flip produced an in-range r
        //                                      but the mathematical check v == r
        //                                      failed (main path).
        //   Err(CryptoError::Verification(_)): bit-flip pushed r out of the
        //                                      legal range [1, q), caught at
        //                                      `from_bytes` parse time.
        Ok(false) | Err(CryptoError::Verification(_)) => {
            // Expected: signature rejected as invalid or malformed.
        }
        Ok(true) => {
            panic!("tampered signature verified as valid — DSA soundness broken");
        }
        Err(e) => {
            panic!(
                "tampered signature must return Ok(false) or Err(Verification), got Err({e:?})"
            );
        }
    }
}

/// Verify that modifying the digest after signing causes verification
/// to fail. This exercises a different path than tampering with the
/// signature itself: the signature is structurally intact, but the
/// `m` input to `v = ((g^u1 * y^u2) mod p) mod q` differs from what
/// the signer saw, so `v != r` and the result is `Ok(false)`.
#[test]
fn test_dsa_verify_tampered_digest_fails() {
    let keypair = gen_keypair_1024();
    let original_digest: [u8; 20] = [0xEF; 20];

    let signature = sign(keypair.private_key(), &original_digest).expect("signing must succeed");

    // Construct a modified digest that differs in exactly one byte.
    // Any change to the digest must cause verification to fail with
    // overwhelming probability.
    let mut modified_digest = original_digest;
    modified_digest[10] ^= 0xFF;
    assert_ne!(
        modified_digest, original_digest,
        "modified digest must differ from original"
    );

    let result = verify(keypair.public_key(), &modified_digest, &signature);
    match result {
        Ok(false) => {
            // Expected: digest differs → m differs → v != r → false.
        }
        Ok(true) => {
            panic!(
                "signature verified against modified digest — DSA soundness or integrity broken"
            );
        }
        Err(e) => {
            panic!(
                "tampered-digest verification must return Ok(false), got Err({e:?})"
            );
        }
    }
}

/// End-to-end verification against a freshly-generated "known" vector.
/// Because DSA parameter generation and signing both consume fresh
/// entropy, we cannot hard-code a static `(params, key, digest,
/// signature)` vector and expect byte-for-byte reproducibility
/// (signatures are non-deterministic in FIPS 186-4 DSA). What we CAN
/// hard-code is the digest and then verify that the signature produced
/// by our signer is accepted by our verifier — a self-consistency
/// check against a known-content input, mirroring the pattern used in
/// `test/dsatest.c` for the signature-equality section.
#[test]
fn test_dsa_sign_with_known_vector() {
    let keypair = gen_keypair_1024();

    // Known test vector: the 20-byte SHA-1 digest of the ASCII string
    // "The quick brown fox jumps over the lazy dog". This is the classic
    // pangram used in many cryptographic test suites — deterministic,
    // well-documented, and easy to cross-reference.
    //
    //   SHA-1("The quick brown fox jumps over the lazy dog")
    //     = 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
    //
    // See: https://en.wikipedia.org/wiki/SHA-1#Example_hashes
    let known_digest: [u8; 20] = [
        0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7,
        0x39, 0x1b, 0x93, 0xeb, 0x12,
    ];

    // Sign the known digest with the private key.
    let signature = sign(keypair.private_key(), &known_digest)
        .expect("signing of a well-known test digest must succeed");
    assert_eq!(
        signature.len(),
        40,
        "1024-bit DSA signature must be 40 bytes (r‖s, 20 bytes each)"
    );

    // Verify the signature on the SAME digest with the public key.
    let ok = verify(keypair.public_key(), &known_digest, &signature)
        .expect("verification of a known-vector signature must not error");
    assert!(
        ok,
        "DSA signature on known-vector digest must verify as true (full roundtrip)"
    );

    // Additionally, re-sign the same digest and verify that two
    // independent signatures on the same message both verify. This
    // exercises the non-determinism guarantee of FIPS 186-4 DSA:
    // each invocation uses a fresh per-message secret k, so sig1 ≠ sig2
    // with overwhelming probability, yet both are valid.
    let signature2 = sign(keypair.private_key(), &known_digest)
        .expect("second signing of the same digest must succeed");
    assert_ne!(
        signature, signature2,
        "DSA signatures are non-deterministic (fresh k per sign) — two sigs on same digest must differ"
    );
    let ok2 = verify(keypair.public_key(), &known_digest, &signature2)
        .expect("verification of second signature must not error");
    assert!(
        ok2,
        "second DSA signature on same digest must also verify as true"
    );
}

// =============================================================================
// Phase 5: Edge Cases
// =============================================================================
//
// Verify corner-case behaviors that are easy to get wrong. These tests
// are the first line of defense against regressions in input validation
// and typed-return-value contracts.

/// Verify that signing an empty digest is permitted and produces a
/// well-formed signature (length = 2 × `q_byte_len`) that verifies under
/// the corresponding public key.
///
/// FIPS 186-4 does not require a minimum digest length; the only
/// requirement is that the integer `m` fit into `N` bits after truncation
/// per §C.2.1. An empty digest yields `m = 0`, which is a valid (if
/// unusual) input. Applications should of course never sign an empty
/// digest in practice — but the primitive MUST handle it without panic
/// or overflow, and the result MUST round-trip through `verify`.
///
/// This directly mirrors `test/dsa_no_digest_size_test.c`, which verifies
/// that DSA signing tolerates arbitrary digest lengths.
#[test]
fn test_dsa_sign_empty_digest() {
    let keypair = gen_keypair_1024();

    // Sign the empty digest. This must either succeed (the correct
    // FIPS-compatible behavior) or return a structured CryptoError —
    // NEVER panic or return a malformed signature.
    let result: CryptoResult<Vec<u8>> = sign(keypair.private_key(), &[]);
    match result {
        Ok(signature) => {
            // If signing succeeded, the signature must be the standard
            // fixed size and must verify under the same key on the same
            // empty digest.
            assert_eq!(
                signature.len(),
                40,
                "1024-bit DSA signature on empty digest must still be 40 bytes (r‖s)"
            );
            let verified = verify(keypair.public_key(), &[], &signature)
                .expect("verification of empty-digest signature must not error");
            assert!(
                verified,
                "DSA sign/verify roundtrip on empty digest must succeed (m = 0 is a valid input)"
            );
        }
        Err(e) => {
            // An implementation that chooses to reject empty digests
            // MUST do so via a structured error, not a panic. We do not
            // mandate which outcome — either is spec-compliant — but
            // we DO mandate that the error be well-formed.
            //
            // If we ever observe this branch in CI, it means the
            // implementation deliberately rejects empty digests; we
            // just verify that the rejection is structured.
            let msg = format!("{e}");
            assert!(
                !msg.is_empty(),
                "CryptoError on empty-digest rejection must have a human-readable message"
            );
        }
    }
}

/// Verify **Rule R5 compliance**: [`crate::dsa::verify`] returns a
/// [`crate::CryptoResult`]`<`[`bool`]`>` — a typed, three-state
/// outcome (Ok(true) / Ok(false) / Err(...)) — not a C-style integer
/// sentinel where 1 = success, 0 = invalid, -1 = error.
///
/// The C API (`DSA_do_verify` in `crypto/dsa/dsa_vrf.c`) returns `int`
/// with the overloaded semantics `1 = valid, 0 = invalid, -1 = error`.
/// This encoding conflates the "invalid signature" and "error during
/// verification" cases and is a well-known source of security bugs
/// (callers often check `== 1` and mistakenly treat -1 as "invalid").
/// Rule R5 demands that the Rust rewrite use a sum type instead.
///
/// This test does the minimum to prove the contract statically:
///   1. Assign the return value of `verify` to a binding with a
///      *syntactically-explicit* [`CryptoResult<bool>`] type annotation.
///   2. Exercise all three arms: Ok(true), Ok(false), and the existence
///      of an Err variant via pattern matching.
///
/// Compilation alone is the proof for (1); runtime assertions prove (2).
#[test]
fn test_dsa_verify_returns_result_bool() {
    let keypair = gen_keypair_1024();
    let digest: [u8; 20] = [0x42; 20];
    let signature = sign(keypair.private_key(), &digest).expect("signing must succeed");

    // ---- Arm 1: Ok(true) ----------------------------------------------
    // The explicit type annotation is the static proof of R5 compliance.
    // If `verify` ever changed to return `i32` or `u8`, this line would
    // fail to compile.
    let ok_result: CryptoResult<bool> = verify(keypair.public_key(), &digest, &signature);
    match ok_result {
        Ok(true) => {
            // Expected: valid signature verifies as `Ok(true)`.
        }
        Ok(false) => panic!("valid DSA signature must verify as Ok(true)"),
        Err(e) => panic!("valid DSA signature verification must not error; got Err({e:?})"),
    }

    // ---- Arm 2: Ok(false) ---------------------------------------------
    // A bit-flipped signature must return Ok(false), not Err, because
    // the signature parses structurally but fails the mathematical
    // check. This proves the Ok(false) arm is reachable.
    let mut tampered = signature.clone();
    tampered[19] ^= 0x01; // flip the LSB of r's last byte
    let invalid_result: CryptoResult<bool> = verify(keypair.public_key(), &digest, &tampered);
    match invalid_result {
        // Both outcomes are acceptable negative-verification signals, each
        // via a distinct code path:
        //   Ok(false):                         the tampered r lay inside
        //                                      [1, q) and parsed correctly,
        //                                      but the mathematical check
        //                                      v == r failed.
        //   Err(CryptoError::Verification(_)): boundary bit-flips may push r
        //                                      out of [1, q), caught by the
        //                                      length/range check at parse
        //                                      time via a TYPED error variant.
        Ok(false) | Err(CryptoError::Verification(_)) => {
            // Expected: tampered signature is rejected.
        }
        Ok(true) => panic!("tampered signature must not verify as true"),
        Err(e) => panic!(
            "tampered signature must return Ok(false) or Err(CryptoError::Verification); got Err({e:?})"
        ),
    }

    // ---- Arm 3: Err ----------------------------------------------------
    // A signature of the WRONG LENGTH (neither 40 nor 2×q_byte_len for any
    // supported q-size) must return `Err(CryptoError::Verification(_))`
    // from `DsaSignature::from_bytes`. This is the third state distinct
    // from Ok(true) and Ok(false), proving that R5's three-state contract
    // is genuinely three-state.
    //
    // We use an odd length (3 bytes) that cannot match any of the valid
    // DSA signature encodings (40, 56, 64 bytes for N = 160, 224, 256).
    let malformed_sig = vec![0u8, 0u8, 0u8];
    let err_result: CryptoResult<bool> = verify(keypair.public_key(), &digest, &malformed_sig);
    match err_result {
        Err(CryptoError::Verification(msg)) => {
            // Expected: structurally-malformed signature → typed error.
            assert!(
                !msg.is_empty(),
                "CryptoError::Verification payload must include a diagnostic message"
            );
        }
        Err(e) => panic!(
            "malformed-length signature must return CryptoError::Verification, got Err({e:?})"
        ),
        Ok(v) => panic!(
            "malformed-length signature must not parse as a valid verification outcome; got Ok({v})"
        ),
    }
}
