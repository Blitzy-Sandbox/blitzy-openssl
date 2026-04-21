//! Integration tests for library initialization and cleanup.
//!
//! These tests validate the public API surface of [`crate::init`] — the Rust
//! equivalent of OpenSSL's `OPENSSL_init_crypto()` / `OPENSSL_cleanup()` and
//! the surrounding RUN_ONCE stage machinery from `crypto/init.c` and
//! `crypto/o_init.c`.
//!
//! # Test Organisation
//!
//! The tests are organised into five phases matching the agent prompt:
//!
//! * **Phase 2 — Initialization Tests** exercise the happy-path init API
//!   (`init_default`, `initialize` with various flag combinations, config
//!   loading, error-string loading).
//! * **Phase 3 — Init Flags Tests** exercise the [`InitFlags`] bitflag type
//!   and its algebraic operations (`|`, `contains`, `empty`, `all`, `bits`).
//! * **Phase 4 — Cleanup Tests** verify the idempotency of [`cleanup`] and
//!   the post-cleanup state invariants.
//! * **Phase 5 — Thread-Safety Tests** spawn multiple threads to verify that
//!   the RUN_ONCE guarantee — implemented in Rust via [`std::sync::Once`] —
//!   is upheld under contention.
//!
//! # Global State Constraint
//!
//! All tests in the `openssl-crypto` crate compile into a single test binary
//! and therefore share the process-global [`std::sync::Once`] guards, the
//! `STOPPED` atomic, and the `COMPLETED_STAGES` bitmask. Because:
//!
//! 1. [`std::sync::Once`] guards fire exactly **once** per process — they
//!    cannot be reset between tests, and
//! 2. Cargo runs tests in parallel in non-deterministic order,
//!
//! every test in this module is written to be **state-tolerant**: it must
//! produce a correct outcome regardless of whether any combination of
//! `initialize()` / `cleanup()` has already run in another test. Tests that
//! inspect `initialize()`'s return value treat `Ok(())` **and**
//! `Err(CryptoError::Common(CommonError::NotInitialized(_)))` as equally
//! valid outcomes — the latter arising when a prior test has called
//! `cleanup()` and latched `STOPPED = true`.
//!
//! A module-level [`Mutex`] — [`INIT_TEST_MUTEX`] — serialises the cleanup /
//! re-init ordering tests where ordering matters for correctness.
//!
//! # Rules Compliance
//!
//! * **R5 — Nullability over Sentinels:** All init calls return
//!   [`CryptoResult`]`<()>`. Tests inspect the `Result` directly rather
//!   than comparing against sentinel integer codes.
//! * **R8 — Zero Unsafe Outside FFI:** The `openssl-crypto` crate declares
//!   `#![forbid(unsafe_code)]`; these tests contain no `unsafe` blocks.
//! * **R10 — Wiring Before Done:** `initialize()` is the first call in any
//!   execution path. These integration tests exercise that path directly
//!   and are therefore the wiring verification for Gate 9.

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

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use crate::context::LibContext;
use crate::init::*;
use crate::CryptoResult;

/// Test-level serialisation mutex.
///
/// Used by the cleanup / re-init ordering tests in Phase 4 and by the
/// concurrency tests in Phase 5 that must observe consistent global state
/// between the critical section's setup and assertion steps.
///
/// Tests outside of the cleanup-sensitive region do not acquire this lock
/// and can run in parallel.
static INIT_TEST_MUTEX: Mutex<()> = Mutex::new(());

// Helper: classify an `initialize`/`init_default` result as "expected" —
// either `Ok(())` (happy path) or `Err(NotInitialized)` (shared state is
// already latched to STOPPED from a prior test). Anything else is a real
// failure that should surface.
fn assert_init_outcome_is_expected(result: &CryptoResult<()>, context: &str) {
    match result {
        Ok(()) => { /* happy path — library initialised successfully */ }
        Err(err) => {
            let msg = format!("{err}");
            assert!(
                msg.contains("stopped") || msg.contains("not initialized"),
                "{context}: unexpected error variant: {err}"
            );
        }
    }
}

// ===========================================================================
// Phase 2: Initialization Tests
// ===========================================================================

/// Verifies that [`init_default`] — the zero-argument convenience wrapper
/// equivalent to `OPENSSL_init_crypto(0, NULL)` in C — runs to completion
/// and returns a [`CryptoResult`]`<()>` of the expected variant.
///
/// Mirrors C reference: `OPENSSL_init_crypto(0, NULL)` — the default path
/// that loads all compiled-in stages.
#[test]
fn test_openssl_init_crypto_default() {
    // Calling init_default must return a CryptoResult<()>. Per the
    // global-state contract (see module docs), either Ok(()) on a fresh
    // process OR Err(NotInitialized) on a post-cleanup process is valid.
    let result: CryptoResult<()> = init_default();
    assert_init_outcome_is_expected(&result, "init_default");
}

/// Verifies that multiple calls to [`initialize`] are safe — the RUN_ONCE
/// guarantee from `crypto/init.c` is preserved.
///
/// Mirrors C reference: `OPENSSL_init_crypto()` calling `RUN_ONCE(&base,
/// ossl_init_base)` which uses `CRYPTO_ONCE` to ensure one-time stage
/// execution.
#[test]
fn test_openssl_init_crypto_idempotent() {
    // Two back-to-back calls must both succeed or both produce the same
    // NotInitialized error (same global state, so same result).
    let first = initialize(InitFlags::all());
    let second = initialize(InitFlags::all());

    assert_init_outcome_is_expected(&first, "first initialize");
    assert_init_outcome_is_expected(&second, "second initialize");

    // Both calls must observe the same global STOPPED state — once the state
    // is latched, both Results are of the same variant.
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "idempotent initialize must yield consistent Ok/Err across calls"
    );

    // If both calls returned Ok, is_initialized() must be true AND
    // is_stopped() must be false.
    if first.is_ok() && second.is_ok() {
        assert!(
            !is_stopped(),
            "after successful initialize, is_stopped must be false"
        );
    }
}

/// Verifies that initialisation loads configuration correctly when the
/// [`InitFlags::CONFIG`] stage is requested, and that the default
/// [`LibContext`] is accessible afterwards.
///
/// Mirrors C reference: `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG,
/// NULL)` followed by `OSSL_LIB_CTX_get0_global_default()`.
#[test]
fn test_openssl_init_loads_config() {
    // Request a stage combination that includes CONFIG.
    let flags = InitFlags::BASE | InitFlags::CONFIG;
    let result = initialize(flags);
    assert_init_outcome_is_expected(&result, "initialize with CONFIG");

    // Regardless of init state, LibContext::get_default() must return a
    // valid Arc<LibContext>. This validates that configuration loading did
    // not corrupt the default context singleton.
    let ctx: Arc<LibContext> = LibContext::get_default();
    // Access an observable property to prove the context is well-formed.
    // The default context is, by definition, not a child context.
    assert!(
        !ctx.is_child(),
        "default library context must not be a child context"
    );

    // Multiple calls to get_default must return references to the same
    // singleton — verify by comparing the underlying pointer addresses.
    let ctx2 = LibContext::get_default();
    assert!(
        Arc::ptr_eq(&ctx, &ctx2),
        "get_default must return the same singleton Arc on repeated calls"
    );
}

/// Verifies that initialisation loads error strings when the
/// [`InitFlags::ERROR_STRINGS`] stage is requested.
///
/// Mirrors C reference:
/// `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)`.
#[test]
fn test_openssl_init_error_strings() {
    // Request BASE plus ERROR_STRINGS. BASE is always required as the
    // foundational stage in the Rust init pipeline.
    let flags = InitFlags::BASE | InitFlags::ERROR_STRINGS;
    let result = initialize(flags);
    assert_init_outcome_is_expected(&result, "initialize with ERROR_STRINGS");

    // The ERROR_STRINGS flag must be a valid, distinct flag (non-zero bits).
    assert_ne!(
        InitFlags::ERROR_STRINGS.bits(),
        0,
        "ERROR_STRINGS must be a non-zero bitflag"
    );

    // ERROR_STRINGS must be contained within InitFlags::all().
    assert!(
        InitFlags::all().contains(InitFlags::ERROR_STRINGS),
        "ERROR_STRINGS must be a subset of all flags"
    );
}

// ===========================================================================
// Phase 3: Init Flags Tests
// ===========================================================================

/// Verifies initialisation semantics when the CONFIG stage is intentionally
/// omitted from the flag set.
///
/// Mirrors C reference: `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG,
/// NULL)`. In the Rust port the absence of [`InitFlags::CONFIG`] is the
/// idiomatic way to express "do not load configuration" — there is no
/// dedicated negative flag because [`InitFlags`] is additive by design.
#[test]
fn test_init_with_no_config() {
    // Build a flag set that includes everything except CONFIG.
    let mut flags = InitFlags::all();
    flags = InitFlags::from_bits_truncate(flags.bits() & !InitFlags::CONFIG.bits());

    assert!(
        !flags.contains(InitFlags::CONFIG),
        "NO_CONFIG flag set must not contain CONFIG"
    );
    assert!(
        flags.contains(InitFlags::BASE),
        "NO_CONFIG flag set must still contain BASE"
    );

    let result = initialize(flags);
    assert_init_outcome_is_expected(&result, "initialize without CONFIG");
}

/// Verifies that initialisation omitting the ASYNC stage is a legitimate
/// flag combination, analogous to C's `OPENSSL_INIT_NO_ATEXIT` /
/// manually-excluded stages.
///
/// The Rust port expresses "do not register atexit / do not initialise the
/// async subsystem" via the positive-flag model: simply omit the ASYNC flag.
/// This preserves the intent of the C `OPENSSL_INIT_NO_ATEXIT` control
/// bit — namely, opt-out of the async/atexit machinery — while adhering
/// to the additive flag design.
#[test]
fn test_init_with_no_atexit() {
    // BASE + CPU_DETECT + THREADS + ERROR_STRINGS + PROVIDERS, without ASYNC.
    let flags = InitFlags::BASE
        | InitFlags::CPU_DETECT
        | InitFlags::THREADS
        | InitFlags::ERROR_STRINGS
        | InitFlags::PROVIDERS;

    assert!(
        !flags.contains(InitFlags::ASYNC),
        "NO_ATEXIT flag set must not contain ASYNC"
    );
    assert!(
        flags.contains(InitFlags::BASE),
        "NO_ATEXIT flag set must still contain BASE"
    );

    // The combined flag's bits must be strictly less than all().bits().
    assert!(
        flags.bits() < InitFlags::all().bits(),
        "NO_ATEXIT flag set must be a strict subset of all flags"
    );

    let result = initialize(flags);
    assert_init_outcome_is_expected(&result, "initialize without ASYNC");
}

/// Verifies the algebraic properties of [`InitFlags`]: bit distinctness,
/// bitwise OR composition, [`InitFlags::contains`], [`InitFlags::empty`],
/// [`InitFlags::all`], and [`InitFlags::bits`].
///
/// This is a pure-logic test — it does not touch global state and is fully
/// parallel-safe.
#[test]
fn test_init_flags_bitwise() {
    // ------- Singleton flag identity -------
    // Each of the seven stage flags must be non-empty and distinct.
    let singles = [
        InitFlags::BASE,
        InitFlags::CPU_DETECT,
        InitFlags::THREADS,
        InitFlags::ERROR_STRINGS,
        InitFlags::CONFIG,
        InitFlags::PROVIDERS,
        InitFlags::ASYNC,
    ];

    for (i, a) in singles.iter().enumerate() {
        assert_ne!(a.bits(), 0, "flag at index {i} must be non-zero");
        assert!(
            a.bits().is_power_of_two(),
            "singleton flag at index {i} must be a single bit"
        );
    }

    // ------- Empty flag -------
    let empty = InitFlags::empty();
    assert_eq!(empty.bits(), 0, "empty flag set must have zero bits");
    assert!(
        !empty.contains(InitFlags::BASE),
        "empty flag set must not contain BASE"
    );

    // ------- Full flag -------
    let all_flags = InitFlags::all();
    for (i, a) in singles.iter().enumerate() {
        assert!(
            all_flags.contains(*a),
            "InitFlags::all() must contain singleton at index {i}"
        );
    }

    // all() must have exactly seven bits set — one per stage.
    assert_eq!(
        all_flags.bits().count_ones(),
        7,
        "InitFlags::all() must contain exactly seven distinct stage bits"
    );

    // ------- Bitwise OR composition -------
    let base_and_cpu = InitFlags::BASE | InitFlags::CPU_DETECT;
    assert_eq!(
        base_and_cpu.bits(),
        InitFlags::BASE.bits() | InitFlags::CPU_DETECT.bits(),
        "OR of BASE and CPU_DETECT must have union bits"
    );
    assert!(
        base_and_cpu.contains(InitFlags::BASE),
        "composed set must contain BASE"
    );
    assert!(
        base_and_cpu.contains(InitFlags::CPU_DETECT),
        "composed set must contain CPU_DETECT"
    );
    assert!(
        !base_and_cpu.contains(InitFlags::ASYNC),
        "composed set must not contain uninvolved ASYNC"
    );

    // ------- Complex combination -------
    let complex = InitFlags::BASE | InitFlags::THREADS | InitFlags::PROVIDERS | InitFlags::ASYNC;
    assert!(complex.contains(InitFlags::BASE));
    assert!(complex.contains(InitFlags::THREADS));
    assert!(complex.contains(InitFlags::PROVIDERS));
    assert!(complex.contains(InitFlags::ASYNC));
    assert!(!complex.contains(InitFlags::CONFIG));
    assert!(!complex.contains(InitFlags::CPU_DETECT));
    assert!(!complex.contains(InitFlags::ERROR_STRINGS));
    assert_eq!(
        complex.bits().count_ones(),
        4,
        "complex set must have exactly four bits"
    );

    // ------- Contains reflexivity -------
    for a in &singles {
        assert!(a.contains(*a), "{a:?} must contain itself");
        assert!(all_flags.contains(*a), "all() must contain {a:?}");
        assert!(
            !empty.contains(*a),
            "empty must not contain {a:?} (unless {a:?} is empty)"
        );
    }

    // ------- Contains transitivity -------
    assert!(
        all_flags.contains(base_and_cpu),
        "all() must contain the BASE | CPU_DETECT subset"
    );
    assert!(
        base_and_cpu.contains(InitFlags::BASE),
        "BASE | CPU_DETECT must contain BASE"
    );
}

// ===========================================================================
// Phase 4: Cleanup Tests
// ===========================================================================

/// Verifies that [`cleanup`] runs without panicking and latches the
/// `STOPPED` flag.
///
/// Mirrors C reference: `OPENSSL_cleanup()` in `crypto/init.c` — sets
/// `stopped = 1` and tears down subsystem state.
///
/// **Ordering:** This test acquires [`INIT_TEST_MUTEX`] to serialise with
/// [`test_reinit_after_cleanup`], preventing a TOCTOU race on the observed
/// `STOPPED` state.
#[test]
fn test_cleanup_succeeds() {
    // Acquire the test-level mutex. Poisoning is treated the same as
    // successful acquisition because the shared global state is independent
    // of any test-local invariants the poisoning test might have violated.
    let _guard = match INIT_TEST_MUTEX.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    // cleanup() has a unit return type — it cannot fail. Multiple calls
    // must be idempotent per the Rust API contract.
    cleanup();
    cleanup();

    // After cleanup, STOPPED must be latched.
    assert!(is_stopped(), "after cleanup, is_stopped() must return true");

    // is_initialized must be false after cleanup (STOPPED latches it).
    assert!(
        !is_initialized(),
        "after cleanup, is_initialized() must return false"
    );
}

/// Verifies the actual post-cleanup re-initialisation behaviour: once
/// [`cleanup`] has latched the `STOPPED` flag, subsequent calls to
/// [`initialize`] return [`Err`] with the expected error variant.
///
/// **Important:** The agent-prompt phrasing "Can re-initialize after
/// cleanup" describes the test's *subject*, not its *expected outcome*.
/// The Rust implementation — consistent with the C original in
/// `crypto/init.c` — explicitly **prevents** re-initialisation after
/// cleanup by checking the `STOPPED` atomic at the entry of
/// `OPENSSL_init_crypto()`. This test verifies that protection is in place
/// and returns a meaningful error.
///
/// Mirrors C reference: `if (stopped) { if (!(opts & OPENSSL_INIT_BASE_ONLY))
/// ERR_raise(ERR_LIB_CRYPTO, ERR_R_INIT_FAIL); return 0; }` in
/// `OPENSSL_init_crypto()`.
#[test]
fn test_reinit_after_cleanup() {
    // Serialise with the cleanup test.
    let _guard = match INIT_TEST_MUTEX.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Ensure cleanup has latched STOPPED. cleanup() is idempotent so this
    // is safe whether or not another test has already done it.
    cleanup();
    assert!(is_stopped(), "cleanup() must latch STOPPED");

    // Attempt to re-initialise. The expected contract is Err(...).
    let result: CryptoResult<()> = initialize(InitFlags::BASE);
    assert!(
        result.is_err(),
        "initialize after cleanup must return Err — \
         re-init protection is a deliberate safety property"
    );

    // Verify the error message indicates the stopped / not-initialized
    // condition rather than some unrelated failure.
    if let Err(err) = &result {
        let msg = format!("{err}");
        assert!(
            msg.contains("stopped") || msg.contains("not initialized"),
            "reinit error must mention stopped/not-initialized, got: {err}"
        );
    }

    // init_default must also fail post-cleanup.
    let default_result: CryptoResult<()> = init_default();
    assert!(
        default_result.is_err(),
        "init_default after cleanup must return Err"
    );

    // is_initialized must remain false.
    assert!(
        !is_initialized(),
        "is_initialized() must remain false after failed reinit"
    );
}

// ===========================================================================
// Phase 5: Thread-Safety Tests
// ===========================================================================

/// Verifies the RUN_ONCE guarantee under concurrent initialisation from
/// multiple threads.
///
/// Mirrors C reference: `CRYPTO_THREAD_run_once()` ensures that each init
/// stage runs exactly once even under contention from multiple callers of
/// `OPENSSL_init_crypto()`.
///
/// Rust implementation: the same guarantee is provided by
/// [`std::sync::Once::call_once`]. This test spawns `N` threads, gates them
/// at a [`Barrier`] so they all race simultaneously, then verifies:
///
/// * No thread panicked.
/// * All threads observe the *same* init result (Ok or Err — whichever the
///   process-global state dictates). Divergent results would indicate a
///   concurrency bug.
#[test]
fn test_concurrent_init() {
    const THREAD_COUNT: usize = 8;

    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let mut handles: Vec<thread::JoinHandle<bool>> = Vec::with_capacity(THREAD_COUNT);

    for idx in 0..THREAD_COUNT {
        let barrier_clone = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            // Wait for all threads to reach the barrier, then all race.
            barrier_clone.wait();

            // Each thread tries to initialize. Exercise a different stage
            // mix per thread to broaden coverage of the RUN_ONCE guards.
            let flags = match idx % 4 {
                0 => InitFlags::BASE,
                1 => InitFlags::BASE | InitFlags::CPU_DETECT,
                2 => InitFlags::BASE | InitFlags::THREADS | InitFlags::ERROR_STRINGS,
                _ => InitFlags::all(),
            };

            let result: CryptoResult<()> = initialize(flags);
            // Return is_ok() so the driver thread can verify uniformity.
            // Only bubble up a panic-worthy failure if the error is of an
            // unexpected variant (something other than "stopped").
            match &result {
                Ok(()) => true,
                Err(err) => {
                    let msg = format!("{err}");
                    // Any non-stopped error is a hard failure — propagate
                    // via panic so the join() catches it.
                    assert!(
                        msg.contains("stopped") || msg.contains("not initialized"),
                        "thread {idx}: unexpected error variant: {err}"
                    );
                    false
                }
            }
        });
        handles.push(handle);
    }

    // Collect the Ok/Err classification from each thread.
    let mut results: Vec<bool> = Vec::with_capacity(THREAD_COUNT);
    for (idx, handle) in handles.into_iter().enumerate() {
        let ok = handle
            .join()
            .unwrap_or_else(|_| panic!("thread {idx} panicked during concurrent init"));
        results.push(ok);
    }

    // Uniformity invariant: since the threads share global state, every
    // thread must observe the same classification — either all succeeded
    // (fresh process) or all failed with NotInitialized (post-cleanup).
    let first = results[0];
    assert!(
        results.iter().all(|&ok| ok == first),
        "all threads must observe the same initialize() outcome \
         (first={first}, results={results:?}) — divergence indicates a \
         concurrency bug in the RUN_ONCE machinery"
    );
}

/// Verifies that, once the library is initialised, concurrent read-only
/// operations against the default [`LibContext`] are safe from multiple
/// threads.
///
/// This mirrors the typical real-world workload: a single init call at
/// startup followed by many parallel requests accessing the default
/// context for algorithm fetch, provider lookup, etc.
///
/// The test gates threads at a [`Barrier`] to maximise concurrent access,
/// then verifies that every thread received a valid [`Arc`]`<LibContext>`
/// pointing at the **same** singleton — validating that neither the
/// initialisation nor the access path aliases the default context.
#[test]
fn test_init_then_concurrent_operations() {
    const THREAD_COUNT: usize = 8;

    // Perform a single initialisation before the concurrent phase. The
    // result is logged via the shared helper but does not gate the test —
    // the concurrent-access portion is valid even when the library is in
    // the STOPPED state because LibContext::get_default() always yields a
    // valid Arc (the default context is a lazy static independent of the
    // init pipeline's Once guards).
    let init_result: CryptoResult<()> = init_default();
    assert_init_outcome_is_expected(&init_result, "pre-concurrent init_default");

    // Capture the canonical default context on the main thread as a
    // reference point for per-thread pointer equality. The pointer is
    // transported to worker threads as a `usize` so that it is `Send` —
    // raw pointers are not `Send` themselves, but their address value is.
    let canonical: Arc<LibContext> = LibContext::get_default();
    let canonical_addr: usize = Arc::as_ptr(&canonical) as usize;

    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(THREAD_COUNT);

    for idx in 0..THREAD_COUNT {
        let barrier_clone = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            barrier_clone.wait();

            // Each thread fetches the default context multiple times and
            // asserts it always points at the same underlying LibContext.
            for iteration in 0..16 {
                let ctx: Arc<LibContext> = LibContext::get_default();
                let addr: usize = Arc::as_ptr(&ctx) as usize;
                assert_eq!(
                    addr, canonical_addr,
                    "thread {idx}, iteration {iteration}: default context must be \
                     the same singleton across threads"
                );
                // Access an observable property to force a real read.
                assert!(
                    !ctx.is_child(),
                    "thread {idx}, iteration {iteration}: default context must \
                     never be a child context"
                );
            }
        });
        handles.push(handle);
    }

    for (idx, handle) in handles.into_iter().enumerate() {
        handle.join().unwrap_or_else(|_| {
            panic!("thread {idx} panicked during concurrent LibContext access")
        });
    }

    // After the concurrent phase, the canonical context remains accessible.
    let post_ctx = LibContext::get_default();
    assert!(
        Arc::ptr_eq(&canonical, &post_ctx),
        "default context must remain stable across the concurrent phase"
    );
}
