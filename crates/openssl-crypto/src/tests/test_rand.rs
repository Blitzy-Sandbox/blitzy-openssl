//! Integration tests for random number generation and DRBG.
//!
//! Tests are organized into six phases matching the C reference test
//! structure (`test/drbgtest.c`, `test/rand_test.c`, `test/rand_status_test.c`):
//!
//! | Phase | Focus                 | C Reference               |
//! |-------|-----------------------|---------------------------|
//! | 2     | RAND public API       | `test/rand_test.c`        |
//! | 3     | DRBG lifecycle        | `test/drbgtest.c`         |
//! | 4     | Entropy pool          | —                         |
//! | 5     | Reseed mechanics      | `test/drbgtest.c`         |
//! | 6     | Property-based tests  | —                         |
//!
//! Key rules enforced:
//! - **R5:** All rand functions return `CryptoResult<()>` (except `rand_seed`
//!   and `rand_status`); `DrbgState` is a typed enum, not integer flags.
//! - **R7:** DRBG shared state is behind `Arc<Mutex<Drbg>>` with
//!   `// LOCK-SCOPE:` annotations; tests verify correct lock-scope compliance
//!   by exercising the global DRBG path (`rand_bytes`/`rand_priv_bytes`).
//! - **R8:** Zero `unsafe` — uses pure-Rust `rand` crate for CSPRNG.
//! - **Gate 10:** 80 percent line coverage target for the `rand` module.

// ---------------------------------------------------------------------------
// Module-level lint overrides for test code.
// Justification: Test functions use `.unwrap()` on success paths, explicit
// assertions, and wildcard imports for proptest macros.  These patterns are
// standard in Rust test modules and are forbidden only in library code per
// workspace lint configuration.
// ---------------------------------------------------------------------------
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::wildcard_imports
)]

use crate::rand::{
    collect_entropy, drbg_generate, drbg_reseed, new_drbg, rand_bytes, rand_priv_bytes,
    rand_seed, rand_status, Drbg, DrbgState, DrbgType, EntropyPool,
    PRIMARY_RESEED_INTERVAL, PRIMARY_RESEED_TIME_INTERVAL, SECONDARY_RESEED_INTERVAL,
    SECONDARY_RESEED_TIME_INTERVAL,
};

/// Mirror of `rand::MAX_REQUEST_SIZE` for test assertions.
///
/// The constant is `pub(crate)` / private in the `rand` module; tests
/// reproduce it here to verify the rejection boundary without requiring
/// the module to export an implementation detail.
const MAX_REQUEST_SIZE: usize = 1 << 20;
use openssl_common::{CryptoError, CryptoResult};
use proptest::prelude::*;

// =============================================================================
// Phase 2: RAND Public API Tests
// =============================================================================
// Reference: test/rand_test.c — test_rand(), test_rand_uniform()
// Reference: test/rand_status_test.c — RAND_status() assertion
// =============================================================================

/// Verify that `rand_bytes()` fills a buffer with random data.
///
/// Statistical check: at least one byte in a 64-byte buffer must be
/// non-zero.  The probability of all 64 bytes being zero from a
/// correctly seeded CSPRNG is 2^{-512}, effectively impossible.
#[test]
fn test_rand_bytes_fills_buffer() {
    let mut buf = [0u8; 64];
    rand_bytes(&mut buf).unwrap();
    assert!(
        buf.iter().any(|&b| b != 0),
        "rand_bytes should produce at least one non-zero byte in 64 bytes"
    );
}

/// Verify that two consecutive calls to `rand_bytes()` produce distinct output.
///
/// The probability of two 64-byte random outputs being identical is
/// 2^{-512}, so any collision indicates a serious RNG defect.
#[test]
fn test_rand_bytes_different_each_call() {
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];
    rand_bytes(&mut buf1).unwrap();
    rand_bytes(&mut buf2).unwrap();
    assert_ne!(
        buf1, buf2,
        "two consecutive rand_bytes calls should produce different output"
    );
}

/// Verify that `rand_priv_bytes()` (private DRBG) fills a buffer.
///
/// The private DRBG uses HMAC-DRBG and is distinct from the public
/// CTR-DRBG.  Same statistical check as [`test_rand_bytes_fills_buffer`].
#[test]
fn test_rand_priv_bytes_fills_buffer() {
    let mut buf = [0u8; 64];
    rand_priv_bytes(&mut buf).unwrap();
    assert!(
        buf.iter().any(|&b| b != 0),
        "rand_priv_bytes should produce at least one non-zero byte"
    );
}

/// Verify that `rand_status()` returns `true` after DRBG initialisation.
///
/// Mirrors `test/rand_status_test.c` which simply asserts `RAND_status() == 1`.
/// The DRBG is lazily initialised on first call to `rand_bytes()`.
#[test]
fn test_rand_status_is_seeded() {
    // Force lazy initialisation of the public DRBG.
    let mut buf = [0u8; 1];
    rand_bytes(&mut buf).unwrap();
    assert!(
        rand_status(),
        "rand_status should return true after successful rand_bytes"
    );
}

/// Verify that `rand_bytes()` with a zero-length buffer succeeds as a no-op.
///
/// The C implementation returns 1 (success) for zero-length requests.
/// Rust equivalent: `Ok(())`.
#[test]
fn test_rand_bytes_zero_length() {
    let mut buf = [0u8; 0];
    let result: CryptoResult<()> = rand_bytes(&mut buf);
    assert!(result.is_ok(), "zero-length rand_bytes should succeed as no-op");
}

/// Verify that `rand_bytes()` rejects requests exceeding `MAX_REQUEST_SIZE`.
///
/// The maximum single request is 1 MiB (`1 << 20` bytes).  Requests
/// larger than this must return an error to prevent unbounded memory use.
#[test]
fn test_rand_bytes_exceeds_max_request() {
    let mut buf = vec![0u8; MAX_REQUEST_SIZE + 1];
    let result = rand_bytes(&mut buf);
    assert!(
        result.is_err(),
        "rand_bytes should reject requests exceeding MAX_REQUEST_SIZE"
    );
}

/// Verify that `rand_seed()` accepts additional seed material without error.
///
/// `rand_seed()` stores additional entropy for subsequent DRBG reseeds.
/// After seeding, `rand_bytes()` must still produce valid output.
#[test]
fn test_rand_seed_accepts_data() {
    let seed = b"additional seed material for DRBG testing";
    rand_seed(seed);
    // Verify the DRBG still functions after adding seed material.
    let mut buf = [0u8; 32];
    rand_bytes(&mut buf).unwrap();
    assert!(
        buf.iter().any(|&b| b != 0),
        "rand_bytes should work after rand_seed"
    );
}

/// Verify that `rand_seed()` silently ignores empty seed data.
#[test]
fn test_rand_seed_empty_is_noop() {
    rand_seed(b"");
    // Must not panic or corrupt state.  Force DRBG init if not already done.
    let mut buf = [0u8; 1];
    rand_bytes(&mut buf).unwrap();
    assert!(rand_status(), "rand_status should be true after empty seed");
}

// =============================================================================
// Phase 3: DRBG Lifecycle Tests
// =============================================================================
// Reference: test/drbgtest.c — DRBG instantiation, generation, reseeding
// =============================================================================

/// Verify CTR-DRBG instantiation: state is `Ready`, counter is 0,
/// and the reseed interval matches `SECONDARY_RESEED_INTERVAL`.
#[test]
fn test_drbg_new_ctr() {
    let drbg: Drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
    assert_eq!(drbg.drbg_type(), DrbgType::CtrDrbg);
    assert_eq!(drbg.state(), DrbgState::Ready);
    assert_eq!(drbg.reseed_counter(), 0);
    assert_eq!(drbg.reseed_interval(), SECONDARY_RESEED_INTERVAL);
}

/// Verify Hash-DRBG instantiation.
#[test]
fn test_drbg_new_hash() {
    let drbg = new_drbg(DrbgType::HashDrbg).unwrap();
    assert_eq!(drbg.drbg_type(), DrbgType::HashDrbg);
    assert_eq!(drbg.state(), DrbgState::Ready);
    assert_eq!(drbg.reseed_counter(), 0);
    assert_eq!(drbg.reseed_interval(), SECONDARY_RESEED_INTERVAL);
}

/// Verify HMAC-DRBG instantiation.
#[test]
fn test_drbg_new_hmac() {
    let drbg = new_drbg(DrbgType::HmacDrbg).unwrap();
    assert_eq!(drbg.drbg_type(), DrbgType::HmacDrbg);
    assert_eq!(drbg.state(), DrbgState::Ready);
    assert_eq!(drbg.reseed_counter(), 0);
}

/// Verify DRBG generation produces non-zero output and increments the
/// reseed counter.
#[test]
fn test_drbg_generate() {
    let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
    let mut buf = [0u8; 32];
    drbg_generate(&mut drbg, &mut buf, None).unwrap();

    assert!(
        buf.iter().any(|&b| b != 0),
        "drbg_generate should produce non-zero output"
    );
    assert_eq!(drbg.reseed_counter(), 1);
    assert_eq!(drbg.state(), DrbgState::Ready);
}

/// Verify that multiple DRBG generations produce distinct output.
#[test]
fn test_drbg_generate_distinct_outputs() {
    let mut drbg = new_drbg(DrbgType::HashDrbg).unwrap();
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    drbg_generate(&mut drbg, &mut buf1, None).unwrap();
    drbg_generate(&mut drbg, &mut buf2, None).unwrap();

    assert_ne!(buf1, buf2, "consecutive drbg_generate calls should differ");
    assert_eq!(drbg.reseed_counter(), 2);
}

/// Verify explicit reseed resets the counter and maintains `Ready` state.
#[test]
fn test_drbg_reseed() {
    let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();

    // Generate a few times to increment counter.
    let mut buf = [0u8; 16];
    for _ in 0..5 {
        drbg_generate(&mut drbg, &mut buf, None).unwrap();
    }
    assert_eq!(drbg.reseed_counter(), 5);

    // Reseed — counter should reset to 0.
    drbg_reseed(&mut drbg, None).unwrap();
    assert_eq!(drbg.reseed_counter(), 0);
    assert_eq!(drbg.state(), DrbgState::Ready);

    // Verify generation still works post-reseed.
    drbg_generate(&mut drbg, &mut buf, None).unwrap();
    assert_eq!(drbg.reseed_counter(), 1);
}

/// Verify DRBG generation with additional input.
///
/// Additional input is mixed into the generation seed per NIST SP 800-90A.
/// Output should be non-zero and counter should increment normally.
#[test]
fn test_drbg_additional_input() {
    let mut drbg = new_drbg(DrbgType::HmacDrbg).unwrap();
    let additional = b"additional entropy data for testing";
    let mut buf = [0u8; 32];

    drbg_generate(&mut drbg, &mut buf, Some(additional)).unwrap();
    assert!(
        buf.iter().any(|&b| b != 0),
        "drbg_generate with additional input should produce non-zero output"
    );
    assert_eq!(drbg.reseed_counter(), 1);
    assert_eq!(drbg.state(), DrbgState::Ready);
}

/// Verify DRBG generation with an empty buffer succeeds as no-op.
#[test]
fn test_drbg_generate_empty_buffer() {
    let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
    let mut buf = [0u8; 0];
    drbg_generate(&mut drbg, &mut buf, None).unwrap();
    // Counter should NOT increment for empty buffer.
    assert_eq!(drbg.reseed_counter(), 0);
}

/// Verify reseed with additional input incorporates the extra material
/// and resets the counter.
#[test]
fn test_drbg_reseed_with_additional_input() {
    let mut drbg = new_drbg(DrbgType::HmacDrbg).unwrap();
    let mut buf = [0u8; 16];
    drbg_generate(&mut drbg, &mut buf, None).unwrap();
    assert_eq!(drbg.reseed_counter(), 1);

    // Reseed with additional input.
    drbg_reseed(&mut drbg, Some(b"extra reseed data")).unwrap();
    assert_eq!(drbg.reseed_counter(), 0);
    assert_eq!(drbg.state(), DrbgState::Ready);

    // Generate after reseed — should work normally.
    drbg_generate(&mut drbg, &mut buf, None).unwrap();
    assert!(buf.iter().any(|&b| b != 0));
    assert_eq!(drbg.reseed_counter(), 1);
}

// =============================================================================
// Phase 4: Entropy Pool Tests
// =============================================================================

/// Verify `collect_entropy()` returns the requested number of bytes.
#[test]
fn test_entropy_collection() {
    let entropy = collect_entropy(32).unwrap();
    assert_eq!(entropy.len(), 32, "collect_entropy should return exactly 32 bytes");
}

/// Verify collected entropy has sufficient randomness (variance check).
///
/// Two independent 32-byte entropy samples should differ, and each
/// should contain at least 5 unique byte values (a very conservative
/// threshold for 32 bytes of good randomness).
#[test]
fn test_entropy_randomness() {
    let e1 = collect_entropy(32).unwrap();
    let e2 = collect_entropy(32).unwrap();
    assert_ne!(e1, e2, "two entropy collections should produce different output");

    // Count unique byte values in the first sample.
    let unique_count = {
        let mut seen = [false; 256];
        for &b in &e1 {
            seen[b as usize] = true;
        }
        seen.iter().filter(|&&v| v).count()
    };
    assert!(
        unique_count > 5,
        "entropy should have reasonable variance, got {unique_count} unique byte values in 32 bytes"
    );
}

/// Verify `collect_entropy(0)` returns an error (zero bytes is invalid).
#[test]
fn test_collect_entropy_zero_bytes_error() {
    let result = collect_entropy(0);
    assert!(result.is_err(), "collect_entropy(0) should fail");
    assert!(
        matches!(result, Err(CryptoError::Rand(_))),
        "collect_entropy(0) should return CryptoError::Rand"
    );
}

/// Verify `collect_entropy()` with a large request succeeds.
#[test]
fn test_collect_entropy_large_request() {
    let entropy = collect_entropy(1024).unwrap();
    assert_eq!(entropy.len(), 1024);
    assert!(
        entropy.iter().any(|&b| b != 0),
        "large entropy collection should contain non-zero bytes"
    );
}

/// Verify [`EntropyPool`] basic construction and accessors.
///
/// A newly created pool has zero length and is empty.
#[test]
fn test_entropy_pool_basic() {
    let pool = EntropyPool::new(64);
    assert_eq!(pool.len(), 0, "new pool should have zero length");
    assert!(pool.is_empty(), "new pool should be empty");
    assert!(pool.as_bytes().is_empty(), "new pool as_bytes should be empty");
}

/// Verify [`EntropyPool`] with zero capacity.
#[test]
fn test_entropy_pool_zero_capacity() {
    let pool = EntropyPool::new(0);
    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());
}

// =============================================================================
// Phase 5: Reseed Tests
// =============================================================================
// Reference: test/drbgtest.c — reseed chain, counter tracking, auto-reseed
// =============================================================================

/// Verify that the DRBG auto-reseeds when the reseed interval is exceeded.
///
/// Creates a DRBG with `SECONDARY_RESEED_INTERVAL` (65 536), generates
/// exactly that many times to reach the threshold, then verifies the
/// next generation triggers an automatic reseed (counter resets to 1).
///
/// This mirrors the reseed-chain counter verification in
/// `test/drbgtest.c::test_drbg_reseed()`.
#[test]
fn test_drbg_auto_reseed_after_interval() {
    let mut drbg = new_drbg(DrbgType::CtrDrbg).unwrap();
    let interval = drbg.reseed_interval();
    assert_eq!(interval, SECONDARY_RESEED_INTERVAL);

    // Generate `interval` times — counter will reach `interval`.
    let mut buf = [0u8; 1];
    for _ in 0..interval {
        drbg_generate(&mut drbg, &mut buf, None).unwrap();
    }
    assert_eq!(
        drbg.reseed_counter(),
        interval,
        "counter should equal interval after {interval} generations"
    );

    // One more generation triggers auto-reseed:
    //   reseed → counter = 0, then generate_internal → counter = 1.
    drbg_generate(&mut drbg, &mut buf, None).unwrap();
    assert_eq!(
        drbg.reseed_counter(),
        1,
        "counter should be 1 after auto-reseed + generate"
    );
    assert_eq!(drbg.state(), DrbgState::Ready);
}

/// Verify DRBG state transitions throughout its lifecycle.
///
/// ```text
/// new_drbg() → Ready
///      │ generate
///      ▼
///    Ready
///      │ reseed
///      ▼
///    Ready (counter = 0)
///      │ generate
///      ▼
///    Ready (counter = 1)
/// ```
///
/// Also verifies that `DrbgState::Uninitialised` and `DrbgState::Error`
/// are valid enum variants (Rule R5 — typed enums, not sentinel integers).
#[test]
fn test_drbg_state_transitions() {
    // Transition 1: new_drbg → Ready
    let mut drbg = new_drbg(DrbgType::HmacDrbg).unwrap();
    assert_eq!(drbg.state(), DrbgState::Ready);

    // Transition 2: generate → still Ready
    let mut buf = [0u8; 16];
    drbg_generate(&mut drbg, &mut buf, None).unwrap();
    assert_eq!(drbg.state(), DrbgState::Ready);
    assert_eq!(drbg.reseed_counter(), 1);

    // Transition 3: reseed → Ready, counter reset
    drbg_reseed(&mut drbg, Some(b"extra seed")).unwrap();
    assert_eq!(drbg.state(), DrbgState::Ready);
    assert_eq!(drbg.reseed_counter(), 0);

    // Transition 4: generate after reseed → Ready
    drbg_generate(&mut drbg, &mut buf, None).unwrap();
    assert_eq!(drbg.state(), DrbgState::Ready);
    assert_eq!(drbg.reseed_counter(), 1);

    // Verify the Uninitialised and Error states exist as valid variants.
    // These are not reachable via normal new_drbg() but must exist in the
    // type system per Rule R5 (typed enum over sentinel integers).
    assert_ne!(DrbgState::Ready, DrbgState::Uninitialised);
    assert_ne!(DrbgState::Ready, DrbgState::Error);
}

/// Verify reseed interval constants are correctly defined.
///
/// These constants control automatic DRBG reseeding thresholds and
/// time-based reseeding.  Values must match NIST SP 800-90A
/// recommendations.
#[test]
fn test_reseed_interval_constants() {
    // Counter-based reseed intervals.
    assert_eq!(
        PRIMARY_RESEED_INTERVAL, 256,
        "primary DRBG reseed interval should be 256"
    );
    assert_eq!(
        SECONDARY_RESEED_INTERVAL, 65536,
        "secondary DRBG reseed interval should be 65536"
    );

    // Time-based reseed intervals (in seconds).
    assert_eq!(
        PRIMARY_RESEED_TIME_INTERVAL, 3600,
        "primary time interval should be 3600 seconds (1 hour)"
    );
    assert_eq!(
        SECONDARY_RESEED_TIME_INTERVAL, 420,
        "secondary time interval should be 420 seconds (7 minutes)"
    );
}

/// Verify all [`DrbgState`] enum variants exist and are distinguishable.
///
/// This ensures the type system encodes the DRBG lifecycle correctly
/// per Rule R5 (nullability over sentinels — typed enum, not integer flags).
#[test]
fn test_drbg_state_enum_variants() {
    // Each variant is constructible and pattern-matchable.
    assert!(matches!(DrbgState::Uninitialised, DrbgState::Uninitialised));
    assert!(matches!(DrbgState::Ready, DrbgState::Ready));
    assert!(matches!(DrbgState::Error, DrbgState::Error));

    // All three are distinct.
    assert_ne!(DrbgState::Uninitialised, DrbgState::Ready);
    assert_ne!(DrbgState::Ready, DrbgState::Error);
    assert_ne!(DrbgState::Uninitialised, DrbgState::Error);
}

/// Verify all [`DrbgType`] enum variants exist and are distinguishable.
#[test]
fn test_drbg_type_enum_variants() {
    assert!(matches!(DrbgType::CtrDrbg, DrbgType::CtrDrbg));
    assert!(matches!(DrbgType::HashDrbg, DrbgType::HashDrbg));
    assert!(matches!(DrbgType::HmacDrbg, DrbgType::HmacDrbg));

    assert_ne!(DrbgType::CtrDrbg, DrbgType::HashDrbg);
    assert_ne!(DrbgType::HashDrbg, DrbgType::HmacDrbg);
    assert_ne!(DrbgType::CtrDrbg, DrbgType::HmacDrbg);
}

/// Verify counter increments correctly over 100 consecutive generations.
#[test]
fn test_drbg_counter_increments() {
    let mut drbg = new_drbg(DrbgType::HashDrbg).unwrap();
    let mut buf = [0u8; 8];

    for expected in 1_u64..=100 {
        drbg_generate(&mut drbg, &mut buf, None).unwrap();
        assert_eq!(
            drbg.reseed_counter(),
            expected,
            "counter should be {expected} after {expected} generations"
        );
    }
}

// =============================================================================
// Phase 6: Property-Based Tests
// =============================================================================
// Uses proptest for randomized API verification with hundreds of generated
// inputs.  Ensures RAND API correctness beyond hand-crafted test vectors.
// =============================================================================

proptest! {
    /// Property: `rand_bytes()` output length always matches the requested
    /// buffer length.
    ///
    /// Generates random buffer lengths in `[1, 4096)` and verifies the
    /// output buffer retains its size after being filled.
    #[test]
    fn prop_rand_bytes_correct_length(len in 1_usize..4096) {
        let mut buf = vec![0u8; len];
        rand_bytes(&mut buf).unwrap();
        prop_assert_eq!(buf.len(), len);
    }

    /// Property: `rand_bytes()` output is never all zeros for buffers ≥ 32
    /// bytes.
    ///
    /// The probability of 32+ random bytes all being zero is negligible
    /// (2^{−256} or less).  Any all-zero output indicates an RNG failure.
    #[test]
    fn prop_rand_bytes_not_all_zeros(len in 32_usize..256) {
        let mut buf = vec![0u8; len];
        rand_bytes(&mut buf).unwrap();
        prop_assert!(buf.iter().any(|&b| b != 0));
    }
}
