//! Integration tests for threading primitives and concurrency safety.
//!
//! These tests exercise the public API surface of [`crate::thread`], focusing on
//! correctness under concurrent access, lock semantics, one-time initialization
//! guarantees, and atomic operation wrappers. The test design follows patterns
//! from the original C test suite (`threadstest.c`, `threadpool_test.c`)
//! translated into idiomatic Rust with `std::thread` and `std::sync::Barrier`.
//!
//! # Test Phases
//!
//! 1. **`CryptoLock`** — read/write access, concurrent readers, write exclusion,
//!    try operations, and name-based debugging support.
//! 2. **`CryptoOnce`** — single-execution guarantee, concurrent invocation safety,
//!    and `is_completed` state tracking.
//! 3. **Stress Tests** — high-contention read/write workloads, atomic counters,
//!    and deadlock-freedom validation.
//! 4. **Atomic Operations** — `atomic_load_u64`, `atomic_store_u64`, `atomic_add_u64`
//!    correctness including wrapping behavior.
//!
//! # Key Rules
//!
//! - **R7:** Tests verify lock behavior matches `LOCK-SCOPE` annotations — each lock
//!   protects exactly the data it wraps, with fine-grained access patterns.
//! - **R5:** `try_read()`/`try_write()` return `Option`, not sentinel values.
//! - **R8:** Zero `unsafe` — `parking_lot` is fully safe Rust.

// Test-specific lint relaxations (workspace config: "Tests and CLI main() may
// #[allow] with justification"):
// - expect_used/unwrap_used: test assertions use expect/unwrap for clear failure messages
// - panic: intentional panic closures test CryptoOnce idempotency
// - doc_markdown: test doc comments reference C identifiers without backticks
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::uninlined_format_args
)]

use crate::thread::{
    atomic_add_u64, atomic_load_u64, atomic_store_u64, CryptoLock, CryptoOnce,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// =============================================================================
// Phase 2: CryptoLock Tests (reference: test/threadstest.c)
// =============================================================================

/// Verifies basic write-then-read semantics on `CryptoLock`.
///
/// Creates a lock protecting a `Vec<u8>`, writes data into it, then reads
/// back and asserts the data matches — validating the fundamental read/write
/// contract. Multiple read-write-verify cycles confirm lock state persistence.
#[test]
fn test_crypto_lock_read_write() {
    let lock = CryptoLock::new(vec![1_u8, 2, 3, 4, 5], "rw_test_lock");

    // Verify initial data via read lock.
    {
        let guard = lock.read();
        assert_eq!(*guard, vec![1, 2, 3, 4, 5]);
    }

    // Mutate data via write lock — append elements.
    {
        let mut guard = lock.write();
        guard.push(6);
        guard.push(7);
    }

    // Verify mutation is visible through a new read lock.
    {
        let guard = lock.read();
        assert_eq!(guard.len(), 7);
        assert_eq!(*guard, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    // Overwrite entire contents.
    {
        let mut guard = lock.write();
        guard.clear();
        guard.extend_from_slice(&[10, 20, 30]);
    }

    // Final read verification.
    {
        let guard = lock.read();
        assert_eq!(*guard, vec![10, 20, 30]);
    }
}

/// Verifies that multiple reader threads can hold the lock simultaneously.
///
/// Inspired by the C `threadstest.c` rw_torture reader pattern, this spawns
/// 16 threads that all acquire read locks concurrently. Since `parking_lot::RwLock`
/// allows concurrent readers, all threads complete without blocking each other.
/// A `Barrier` ensures maximum concurrent read contention.
#[test]
fn test_crypto_lock_concurrent_reads() {
    let data = vec![42_i64; 100];
    let lock = Arc::new(CryptoLock::new(data, "concurrent_reads"));
    let num_threads = 16;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for _ in 0..num_threads {
        let lock_clone = Arc::clone(&lock);
        let barrier_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            // Synchronize all threads to maximize concurrent read contention.
            barrier_clone.wait();
            let guard = lock_clone.read();
            assert_eq!(guard.len(), 100);
            for &val in guard.iter() {
                assert_eq!(val, 42_i64);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("reader thread should not panic");
    }
}

/// Verifies that a write lock provides exclusive access, blocking readers
/// until released.
///
/// A writer thread acquires the lock, signals that it holds it, holds it
/// briefly while writing, then releases. The main thread's subsequent read
/// must see the written value, proving the writer had exclusive access.
#[test]
fn test_crypto_lock_write_exclusion() {
    let lock = Arc::new(CryptoLock::new(0_u64, "write_exclusion"));
    let write_started = Arc::new(AtomicBool::new(false));
    let write_finished = Arc::new(AtomicBool::new(false));

    let lock_clone = Arc::clone(&lock);
    let ws = Arc::clone(&write_started);
    let wf = Arc::clone(&write_finished);

    // Writer thread: acquire write lock, signal, hold briefly, write, release.
    let writer = thread::spawn(move || {
        let mut guard = lock_clone.write();
        ws.store(true, Ordering::SeqCst);
        // Hold the lock to ensure the reader must wait for us.
        thread::sleep(std::time::Duration::from_millis(50));
        *guard = 999;
        drop(guard);
        wf.store(true, Ordering::SeqCst);
    });

    // Spin until writer has acquired the lock.
    while !write_started.load(Ordering::SeqCst) {
        thread::yield_now();
    }

    // By the time the reader acquires the read guard, the writer must have
    // released the lock (since `parking_lot::RwLock` blocks readers while
    // a writer holds the lock). Therefore, we should see the written value.
    let guard = lock.read();
    assert!(
        write_finished.load(Ordering::SeqCst),
        "Writer should have finished before reader acquired lock"
    );
    assert_eq!(*guard, 999, "Reader should see the value written under exclusive lock");
    drop(guard);

    writer.join().expect("writer thread should not panic");
}

/// Verifies that `CryptoLock` carries a debugging name accessible via `.name()`.
///
/// The name is a `&'static str` set at construction time and is intended for
/// diagnostics, logging, and `LOCK-SCOPE` annotation matching (rule R7).
#[test]
fn test_crypto_lock_name() {
    let lock_a = CryptoLock::new((), "provider_store_lock");
    assert_eq!(lock_a.name(), "provider_store_lock");

    let lock_b = CryptoLock::new(String::from("data"), "session_cache");
    assert_eq!(lock_b.name(), "session_cache");

    // Name is available regardless of the inner type.
    let lock_c: CryptoLock<Vec<u8>> = CryptoLock::new(Vec::new(), "bio_filter_chain");
    assert_eq!(lock_c.name(), "bio_filter_chain");

    // Empty name is valid (though not recommended).
    let lock_d = CryptoLock::new(0_u32, "");
    assert_eq!(lock_d.name(), "");
}

/// Verifies that `try_read()` returns `Option` (rule R5, not sentinel) and
/// that multiple `try_read` guards can coexist (readers don't block readers).
/// Also verifies `try_write()` succeeds when the lock is free.
#[test]
fn test_crypto_lock_try_read() {
    let lock = CryptoLock::new(vec![1, 2, 3], "try_read_test");

    // try_read should succeed when no writer holds the lock.
    let guard1 = lock.try_read();
    assert!(guard1.is_some(), "try_read should succeed when lock is free");
    let guard1 = guard1.unwrap();
    assert_eq!(*guard1, vec![1, 2, 3]);

    // Multiple concurrent try_reads should also succeed (readers don't block readers).
    let guard2 = lock.try_read();
    assert!(
        guard2.is_some(),
        "try_read should succeed while another read guard is held"
    );
    let guard2 = guard2.unwrap();
    assert_eq!(*guard2, vec![1, 2, 3]);

    // Both guards can coexist — drop them.
    drop(guard1);
    drop(guard2);

    // try_write should succeed when the lock is entirely free.
    let write_guard = lock.try_write();
    assert!(
        write_guard.is_some(),
        "try_write should succeed when lock is free"
    );
    let mut write_guard = write_guard.unwrap();
    write_guard.push(4);
    drop(write_guard);

    // Verify the write took effect.
    let guard = lock.try_read();
    assert!(guard.is_some());
    assert_eq!(*guard.unwrap(), vec![1, 2, 3, 4]);
}

// =============================================================================
// Phase 3: CryptoOnce Tests
// =============================================================================

/// Verifies that `CryptoOnce::call_once` runs the closure exactly once,
/// even when called multiple times sequentially.
#[test]
fn test_crypto_once_executes_once() {
    let once = CryptoOnce::new();
    let counter = Arc::new(AtomicU64::new(0));

    // First call should execute the closure.
    let c1 = Arc::clone(&counter);
    once.call_once(move || {
        c1.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // Second call should be a no-op — closure not invoked again.
    let c2 = Arc::clone(&counter);
    once.call_once(move || {
        c2.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // Third call — still no-op, even with a different closure body.
    let c3 = Arc::clone(&counter);
    once.call_once(move || {
        c3.fetch_add(100, Ordering::SeqCst);
    });
    assert_eq!(counter.load(Ordering::SeqCst), 1, "call_once must execute exactly once");
}

/// Verifies that concurrent calls to `CryptoOnce::call_once` from many threads
/// result in exactly one execution. Uses a `Barrier` to synchronize thread
/// starts for maximum concurrent contention.
///
/// Inspired by the multi-threaded once-init pattern from `threads_common.c`.
#[test]
fn test_crypto_once_concurrent_calls() {
    let once = Arc::new(CryptoOnce::new());
    let counter = Arc::new(AtomicU64::new(0));
    let num_threads = 20;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for _ in 0..num_threads {
        let o = Arc::clone(&once);
        let c = Arc::clone(&counter);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            // All threads wait at the barrier, then race to call_once.
            b.wait();
            o.call_once(|| {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }));
    }

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    // Exactly one thread should have executed the closure.
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "call_once should execute exactly once across {} threads",
        num_threads
    );
    assert!(
        once.is_completed(),
        "is_completed should be true after concurrent call_once"
    );
}

/// Verifies the `is_completed` state transitions of `CryptoOnce`.
///
/// Before `call_once`: `false`. After `call_once`: `true`. Repeated calls
/// do not revert the state.
#[test]
fn test_crypto_once_is_completed() {
    let once = CryptoOnce::new();

    // Before any call, is_completed should be false.
    assert!(
        !once.is_completed(),
        "is_completed should be false before call_once"
    );

    // After call_once, is_completed transitions to true.
    once.call_once(|| {
        // Intentional no-op closure — we're testing the completion state.
    });
    assert!(
        once.is_completed(),
        "is_completed should be true after call_once"
    );

    // Repeated calls don't change the completed state.
    once.call_once(|| {
        panic!("this closure should never execute");
    });
    assert!(
        once.is_completed(),
        "is_completed should remain true after repeated call_once"
    );
}

// =============================================================================
// Phase 4: Multi-Threaded Stress Tests (reference: test/threadstest.c _torture_rw)
// =============================================================================

/// Stress test: 10 threads performing interleaved read and write operations
/// on shared data protected by `CryptoLock`.
///
/// Inspired by the `_torture_rw` test in `test/threadstest.c` which spawns
/// 2 readers + 2 writers for ~4 seconds. This Rust version uses 5 reader
/// threads and 5 writer threads with a barrier for synchronized start.
/// Writers increment a counter; readers verify values are within bounds.
#[test]
fn test_concurrent_lock_operations() {
    let lock = Arc::new(CryptoLock::new(0_u64, "stress_rw"));
    let num_readers = 5;
    let num_writers = 5;
    let total_threads = num_readers + num_writers;
    let barrier = Arc::new(Barrier::new(total_threads));
    let iterations_per_thread = 100;
    let mut handles = Vec::with_capacity(total_threads);

    // Spawn writer threads: each increments the counter once per iteration.
    for _ in 0..num_writers {
        let lock_clone = Arc::clone(&lock);
        let barrier_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier_clone.wait();
            for _ in 0..iterations_per_thread {
                let mut guard = lock_clone.write();
                *guard += 1;
                // Explicit drop to release lock promptly, reducing contention.
                drop(guard);
            }
        }));
    }

    // Spawn reader threads: each reads the counter and verifies it's within bounds.
    let max_value = (num_writers * iterations_per_thread) as u64;
    for _ in 0..num_readers {
        let lock_clone = Arc::clone(&lock);
        let barrier_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier_clone.wait();
            for _ in 0..iterations_per_thread {
                let guard = lock_clone.read();
                // The value must always be in [0, max_value].
                assert!(
                    *guard <= max_value,
                    "Read value {} exceeds maximum expected {}",
                    *guard,
                    max_value
                );
            }
        }));
    }

    for handle in handles {
        handle.join().expect("stress test thread should not panic");
    }

    // Final value should be exactly num_writers * iterations_per_thread.
    let final_value = *lock.read();
    assert_eq!(
        final_value,
        (num_writers * iterations_per_thread) as u64,
        "Final counter should equal total writer increments"
    );
}

/// Stress test: multiple threads atomically incrementing a shared counter
/// using `CryptoLock<u64>` with write locks.
///
/// Verifies no increments are lost under contention, analogous to the
/// `CRYPTO_atomic_add` torture tests in `test/threadstest.c`.
#[test]
fn test_thread_safe_increment() {
    let lock = Arc::new(CryptoLock::new(0_u64, "safe_increment"));
    let completed = Arc::new(AtomicU64::new(0));
    let num_threads: usize = 8;
    let increments_per_thread: usize = 500;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for _ in 0..num_threads {
        let lock_clone = Arc::clone(&lock);
        let barrier_clone = Arc::clone(&barrier);
        let completed_clone = Arc::clone(&completed);
        handles.push(thread::spawn(move || {
            barrier_clone.wait();
            for _ in 0..increments_per_thread {
                let mut guard = lock_clone.write();
                *guard += 1;
            }
            // Track thread completion — Relaxed ordering is sufficient since
            // we join all threads before reading (join provides happens-before).
            completed_clone.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for handle in handles {
        handle.join().expect("increment thread should not panic");
    }

    // After join, all stores are visible.
    assert_eq!(
        completed.load(Ordering::Relaxed),
        num_threads as u64,
        "All threads should have completed"
    );

    let expected = (num_threads * increments_per_thread) as u64;
    let actual = *lock.read();
    assert_eq!(
        actual, expected,
        "Expected {} total increments, got {}",
        expected, actual
    );
}

/// Verifies that heavy concurrent access to `CryptoLock` does not cause
/// deadlock. This test must complete within a bounded time (the test
/// framework enforces a timeout via the Rust test harness).
///
/// Pattern: 12 threads alternating between read and write operations
/// with barrier synchronization for maximum contention. Even-indexed
/// threads read-then-write; odd-indexed threads write-then-read.
#[test]
fn test_lock_contention_no_deadlock() {
    let lock = Arc::new(CryptoLock::new(Vec::<u64>::new(), "deadlock_test"));
    let num_threads: usize = 12;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for thread_id in 0..num_threads {
        let lock_clone = Arc::clone(&lock);
        let barrier_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier_clone.wait();
            for i in 0..50_u64 {
                if thread_id % 2 == 0 {
                    // Even threads: read, then write.
                    {
                        let guard = lock_clone.read();
                        // Just read the length — the read guard itself is the test.
                        let _ = guard.len();
                    }
                    {
                        let mut guard = lock_clone.write();
                        guard.push(i + (thread_id as u64 * 1000));
                    }
                } else {
                    // Odd threads: write, then read.
                    {
                        let mut guard = lock_clone.write();
                        guard.push(i + (thread_id as u64 * 1000));
                    }
                    {
                        let guard = lock_clone.read();
                        assert!(!guard.is_empty(), "Should have at least one entry");
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.join().expect("contention thread should not panic");
    }

    // Verify all entries are present — each of 12 threads pushes 50 entries.
    let guard = lock.read();
    let expected_entries = num_threads * 50;
    assert_eq!(
        guard.len(),
        expected_entries,
        "Expected {} entries, got {}",
        expected_entries,
        guard.len()
    );
}

// =============================================================================
// Phase 5: Atomic Operations
// =============================================================================

/// Verifies `atomic_load_u64` and `atomic_store_u64` correctness.
///
/// Tests basic load/store round-trip, boundary values (0, `u64::MAX`),
/// and sequential store-then-load patterns. These functions wrap
/// `AtomicU64::load/store` with `Ordering::SeqCst`, matching the
/// `CRYPTO_atomic_load`/`CRYPTO_atomic_store` C equivalents.
#[test]
fn test_atomic_load_store_u64() {
    let val = AtomicU64::new(0);

    // Initial load returns the construction value.
    assert_eq!(atomic_load_u64(&val), 0);

    // Store and verify round-trip.
    atomic_store_u64(&val, 42);
    assert_eq!(atomic_load_u64(&val), 42);

    // Boundary: store u64::MAX.
    atomic_store_u64(&val, u64::MAX);
    assert_eq!(atomic_load_u64(&val), u64::MAX);

    // Store zero again.
    atomic_store_u64(&val, 0);
    assert_eq!(atomic_load_u64(&val), 0);

    // Sequential stores — each overwrite is visible immediately.
    for i in 1..=10_u64 {
        atomic_store_u64(&val, i * 100);
        assert_eq!(atomic_load_u64(&val), i * 100);
    }

    // Final value is the last store.
    assert_eq!(atomic_load_u64(&val), 1000);
}

/// Verifies `atomic_add_u64` returns the **post-addition** value (matching
/// C `__atomic_add_fetch` semantics) and handles wrapping at `u64::MAX`.
///
/// This function is the Rust equivalent of `CRYPTO_atomic_add` from
/// `crypto/threads_pthread.c`, which uses either GCC builtins or a
/// mutex-protected fallback.
#[test]
fn test_atomic_add_u64() {
    let val = AtomicU64::new(0);

    // Basic increment: 0 + 10 = 10 (post-add).
    let result = atomic_add_u64(&val, 10);
    assert_eq!(result, 10, "Post-add value should be 10");
    assert_eq!(atomic_load_u64(&val), 10);

    // Second increment: 10 + 5 = 15 (post-add).
    let result = atomic_add_u64(&val, 5);
    assert_eq!(result, 15, "Post-add value should be 15");
    assert_eq!(atomic_load_u64(&val), 15);

    // Adding zero is a no-op — value unchanged, returns current.
    let result = atomic_add_u64(&val, 0);
    assert_eq!(result, 15, "Adding zero should not change value");

    // Wrapping behavior at u64::MAX: MAX + 1 wraps to 0.
    let val2 = AtomicU64::new(u64::MAX);
    let result = atomic_add_u64(&val2, 1);
    assert_eq!(result, 0, "Should wrap to 0 at u64::MAX + 1");
    assert_eq!(atomic_load_u64(&val2), 0);

    // Wrapping with larger delta: (MAX - 4) + 10 = 5.
    let val3 = AtomicU64::new(u64::MAX - 4);
    let result = atomic_add_u64(&val3, 10);
    assert_eq!(result, 5, "Should wrap correctly: (MAX-4) + 10 = 5");
    assert_eq!(atomic_load_u64(&val3), 5);
}
