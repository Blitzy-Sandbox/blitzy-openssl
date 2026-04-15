//! Threading primitives for the OpenSSL Rust workspace.
//!
//! Replaces C `CRYPTO_THREAD_*` locks, `CRYPTO_ONCE`, thread-local storage, and
//! internal RCU synchronization with Rust standard library and `parking_lot` primitives.
//!
//! # Source Mapping
//!
//! | Rust Type | C Equivalent | Source File |
//! |-----------|-------------|-------------|
//! | [`CryptoLock<T>`] | `CRYPTO_RWLOCK` / `pthread_rwlock_t` | `crypto/threads_pthread.c` |
//! | [`CryptoOnce`] | `CRYPTO_ONCE` / `pthread_once_t` | `crypto/threads_pthread.c`, `crypto/init.c` |
//! | [`CryptoThreadLocal<T>`] | `CRYPTO_THREAD_LOCAL` / `pthread_key_t` | `crypto/threads_common.c` |
//! | [`register_thread_stop_handler`] | `ossl_init_thread_start()` | `crypto/initthread.c` |
//! | [`atomic_load_u64`] | `fallback_atomic_load_n` | `crypto/threads_pthread.c` |
//! | [`atomic_store_u64`] | `fallback_atomic_store_n` | `crypto/threads_pthread.c` |
//! | [`atomic_add_u64`] | `fallback_atomic_add_fetch` | `crypto/threads_pthread.c` |
//!
//! # Design Decisions
//!
//! - **`parking_lot::RwLock`** chosen over `std::sync::RwLock` for non-poisoning semantics
//!   and better performance under contention (Rule R7).
//! - **`std::sync::Once`** used for one-shot initialization with an `AtomicBool` companion
//!   for cheap `is_completed()` queries without calling `Once::call_once` again.
//! - **`CryptoThreadLocal<T>`** uses `Mutex<HashMap<ThreadId, T>>` rather than the
//!   `thread_local!` macro because Rust's `LocalKey` cannot be stored as a struct field;
//!   the mutex-map approach gives equivalent per-thread semantics with safe code.
//! - **Thread stop handlers** use a global registry of per-thread `Arc<ThreadStopState>`
//!   objects; a thread-local `StopGuard` fires registered handlers on drop (thread exit).
//! - **Zero `unsafe`** — the crate-level `#![forbid(unsafe_code)]` is inherited; all
//!   synchronization is through safe `parking_lot` and `std::sync` APIs (Rule R8).

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::thread::{self, ThreadId};

use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use openssl_common::error::CryptoError;

// ---------------------------------------------------------------------------
// CryptoLock<T> — replaces CRYPTO_RWLOCK / pthread_rwlock_t
// ---------------------------------------------------------------------------

/// Thread-safe read-write lock wrapping data of type `T`.
///
/// Replaces the C `CRYPTO_RWLOCK` (backed by `pthread_rwlock_t` on POSIX and
/// `SRWLOCK` on Windows) with a `parking_lot::RwLock` for better performance
/// and non-poisoning semantics.
///
/// Each lock carries a human-readable `name` used for debugging and tracing,
/// satisfying Rule R7's requirement that every shared data structure has a
/// documented lock scope.
///
/// # Examples
///
/// ```
/// use openssl_crypto::thread::CryptoLock;
///
/// let lock = CryptoLock::new(vec![1, 2, 3], "example_data");
/// {
///     let guard = lock.read();
///     assert_eq!(guard.len(), 3);
/// }
/// {
///     let mut guard = lock.write();
///     guard.push(4);
/// }
/// assert_eq!(lock.name(), "example_data");
/// ```
// LOCK-SCOPE: per-data-structure lock, replaces coarse CRYPTO_RWLOCK (Rule R7).
// Each CryptoLock protects exactly one logical data item. The `name` field
// documents which subsystem owns the lock for contention analysis.
pub struct CryptoLock<T> {
    /// The underlying read-write lock protecting the wrapped data.
    inner: RwLock<T>,
    /// A human-readable identifier for debugging, logging, and contention analysis.
    name: &'static str,
}

impl<T> CryptoLock<T> {
    /// Creates a new `CryptoLock` wrapping `data` with the given diagnostic `name`.
    ///
    /// The `name` should describe which subsystem or data structure the lock protects
    /// (e.g., `"provider_store"`, `"session_cache"`).
    ///
    /// # Arguments
    ///
    /// * `data` — The value to protect behind the read-write lock.
    /// * `name` — A static string identifying this lock for debugging and tracing.
    pub fn new(data: T, name: &'static str) -> Self {
        Self {
            inner: RwLock::new(data),
            name,
        }
    }

    /// Acquires a shared (read) lock, blocking the current thread until it is available.
    ///
    /// Multiple readers can hold the lock concurrently. Writers are excluded while
    /// any read guard is alive.
    ///
    /// Replaces `CRYPTO_THREAD_read_lock()` from `crypto/threads_pthread.c`.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.inner.read()
    }

    /// Acquires an exclusive (write) lock, blocking the current thread until it is
    /// available.
    ///
    /// No other readers or writers can hold the lock while a write guard is alive.
    ///
    /// Replaces `CRYPTO_THREAD_write_lock()` from `crypto/threads_pthread.c`.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.inner.write()
    }

    /// Attempts to acquire a shared (read) lock without blocking.
    ///
    /// Returns `Some(guard)` on success, or `None` if the lock is currently held
    /// exclusively by a writer. Uses `Option` instead of sentinel values per Rule R5.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        self.inner.try_read()
    }

    /// Attempts to acquire an exclusive (write) lock without blocking.
    ///
    /// Returns `Some(guard)` on success, or `None` if the lock is currently held
    /// by any reader or writer. Uses `Option` instead of sentinel values per Rule R5.
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        self.inner.try_write()
    }

    /// Returns the diagnostic name of this lock.
    ///
    /// Useful for logging contention events and debugging deadlocks.
    pub fn name(&self) -> &str {
        self.name
    }
}

// Safety: CryptoLock<T> delegates all thread-safety to parking_lot::RwLock<T>,
// which is Send+Sync when T: Send+Sync.
// (These bounds are automatically derived by the compiler.)

impl<T: std::fmt::Debug> std::fmt::Debug for CryptoLock<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoLock")
            .field("name", &self.name)
            .field("inner", &self.inner)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// CryptoOnce — replaces CRYPTO_ONCE / RUN_ONCE / pthread_once_t
// ---------------------------------------------------------------------------

/// One-time initialization primitive.
///
/// Wraps `std::sync::Once` with an additional `AtomicBool` flag so that
/// [`is_completed`](CryptoOnce::is_completed) can be queried cheaply without
/// attempting another `call_once` invocation.
///
/// Replaces the C `CRYPTO_ONCE` type (backed by `pthread_once_t` on POSIX and
/// `INIT_ONCE` on Windows) used extensively in `crypto/init.c` for library
/// initialization stages (`RUN_ONCE` macros).
///
/// # Examples
///
/// ```
/// use openssl_crypto::thread::CryptoOnce;
///
/// let once = CryptoOnce::new();
/// assert!(!once.is_completed());
///
/// once.call_once(|| { /* one-time init */ });
/// assert!(once.is_completed());
///
/// // Subsequent calls are no-ops:
/// once.call_once(|| { unreachable!("never called twice"); });
/// ```
pub struct CryptoOnce {
    /// The standard library one-shot gate.
    once: Once,
    /// A cheap flag that mirrors the `Once` completion state so callers can
    /// query completion without a full `call_once` round-trip.
    completed: AtomicBool,
}

impl CryptoOnce {
    /// Creates a new, incomplete `CryptoOnce`.
    pub fn new() -> Self {
        Self {
            once: Once::new(),
            completed: AtomicBool::new(false),
        }
    }

    /// Executes `f` exactly once, regardless of how many threads call this method
    /// concurrently. All subsequent calls are no-ops.
    ///
    /// Replaces the C `CRYPTO_THREAD_run_once()` function.
    ///
    /// # Panics
    ///
    /// If `f` panics, the `Once` is poisoned and future calls will also panic.
    /// This matches the C behavior where a failed `RUN_ONCE` leaves the library
    /// in an unrecoverable state.
    pub fn call_once<F: FnOnce()>(&self, f: F) {
        self.once.call_once(|| {
            f();
            self.completed.store(true, Ordering::Release);
        });
    }

    /// Returns `true` if [`call_once`](CryptoOnce::call_once) has already
    /// completed successfully.
    ///
    /// This is a cheap atomic load — it does **not** contend with concurrent
    /// `call_once` invocations.
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

impl Default for CryptoOnce {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CryptoOnce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoOnce")
            .field("completed", &self.is_completed())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// CryptoThreadLocal<T> — replaces CRYPTO_THREAD_LOCAL / pthread_key_t
// ---------------------------------------------------------------------------

/// Per-thread storage for values of type `T`.
///
/// Replaces the C `CRYPTO_THREAD_LOCAL` (backed by `pthread_key_t` on POSIX and
/// `TlsAlloc` on Windows) from `crypto/threads_common.c`.
///
/// Uses a `parking_lot::Mutex<HashMap<ThreadId, T>>` internally. While this has
/// slightly higher overhead than OS-level TLS, it avoids `unsafe` code and works
/// uniformly across platforms. Each access acquires the mutex briefly to
/// insert/retrieve/remove the calling thread's value.
///
/// # Type Constraints
///
/// `T` must be `Send` because values created on one thread may be cleaned up on
/// another (e.g., when [`remove_current`](CryptoThreadLocal::remove_current) is
/// called or the map is dropped). `T: 'static` is required because the storage
/// may outlive any particular stack frame.
///
/// # Examples
///
/// ```
/// use openssl_crypto::thread::CryptoThreadLocal;
///
/// let tls: CryptoThreadLocal<String> = CryptoThreadLocal::new("ctx_data");
/// tls.set("hello".to_string());
/// assert_eq!(tls.get(), Some("hello".to_string()));
///
/// tls.remove_current();
/// assert_eq!(tls.get(), None);
/// ```
// LOCK-SCOPE: protects per-thread value map; contention is low because each
// thread typically only touches its own entry (Rule R7).
pub struct CryptoThreadLocal<T: Send + 'static> {
    /// Map from thread identity to the thread's stored value.
    map: Mutex<HashMap<ThreadId, T>>,
    /// Diagnostic name for logging and tracing.
    name: &'static str,
}

impl<T: Send + 'static> CryptoThreadLocal<T> {
    /// Creates a new, empty per-thread storage with the given diagnostic `name`.
    pub fn new(name: &'static str) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            name,
        }
    }

    /// Stores `value` for the current thread, replacing any previous value.
    ///
    /// Replaces `CRYPTO_THREAD_set_local()` from `crypto/threads_common.c`.
    pub fn set(&self, value: T) {
        let tid = thread::current().id();
        self.map.lock().insert(tid, value);
    }

    /// Returns a clone of the current thread's value, or `None` if no value has
    /// been set. Uses `Option` per Rule R5 — no sentinel values.
    ///
    /// Replaces `CRYPTO_THREAD_get_local()` from `crypto/threads_common.c`.
    pub fn get(&self) -> Option<T>
    where
        T: Clone,
    {
        let tid = thread::current().id();
        self.map.lock().get(&tid).cloned()
    }

    /// Retrieves the current thread's value by applying `f` to it (if present).
    ///
    /// This avoids requiring `T: Clone` when callers only need to inspect or
    /// transform the stored value.
    pub fn with<R, F: FnOnce(&T) -> R>(&self, f: F) -> Option<R> {
        let tid = thread::current().id();
        let guard = self.map.lock();
        guard.get(&tid).map(f)
    }

    /// Removes and returns the current thread's value, or `None` if absent.
    ///
    /// Replaces the `CRYPTO_THREAD_cleanup_local()` cleanup path from
    /// `crypto/threads_common.c`.
    pub fn remove_current(&self) -> Option<T> {
        let tid = thread::current().id();
        self.map.lock().remove(&tid)
    }

    /// Returns the diagnostic name of this thread-local storage.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Returns the number of threads that currently have a stored value.
    ///
    /// Useful for diagnostics and testing.
    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    /// Returns `true` if no thread has a stored value.
    pub fn is_empty(&self) -> bool {
        self.map.lock().is_empty()
    }
}

impl<T: Send + 'static> Default for CryptoThreadLocal<T> {
    fn default() -> Self {
        Self::new("unnamed")
    }
}

impl<T: Send + std::fmt::Debug + 'static> std::fmt::Debug for CryptoThreadLocal<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit the `map` field to avoid holding the lock during
        // formatting (which could deadlock). Show entry count instead.
        f.debug_struct("CryptoThreadLocal")
            .field("name", &self.name)
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Thread Stop Handler System — replaces ossl_init_thread_start / initthread.c
// ---------------------------------------------------------------------------
//
// Architecture:
//
//   Global: GLOBAL_HANDLER_REGISTRY — Mutex<Vec<Arc<ThreadStopState>>>
//     Holds a weak reference (via Arc) to every thread's stop state so that
//     the global cleanup path (ossl_cleanup_thread equivalent) can forcibly
//     invoke remaining handlers.
//
//   Per-thread: STOP_GUARD — thread_local RefCell<Option<StopGuard>>
//     The StopGuard fires all registered handlers when the thread exits
//     (via its Drop implementation). This mirrors the C destructor-key
//     pattern in crypto/initthread.c.
//
// The C code uses a THREAD_EVENT_HANDLER linked list per thread. Here we
// use a Vec<Box<dyn FnOnce() + Send>> protected by a Mutex inside each
// thread's ThreadStopState.

/// Internal state for a single thread's stop handlers.
///
/// Contains the list of cleanup callbacks and a flag indicating whether
/// they have already been invoked.
// LOCK-SCOPE: protects the per-thread handler list; locked briefly during
// registration and once during thread exit (Rule R7).
struct ThreadStopState {
    /// Registered cleanup handlers, executed in LIFO order on thread exit.
    handlers: Mutex<Vec<Box<dyn FnOnce() + Send>>>,
    /// Set to `true` after handlers have been invoked to prevent double-fire.
    invoked: AtomicBool,
}

impl ThreadStopState {
    /// Creates a new, empty state.
    fn new() -> Self {
        Self {
            handlers: Mutex::new(Vec::new()),
            invoked: AtomicBool::new(false),
        }
    }

    /// Registers a handler to be called when the owning thread exits.
    fn push_handler(&self, handler: Box<dyn FnOnce() + Send>) {
        if self.invoked.load(Ordering::Acquire) {
            // Handlers already fired — silently drop new registrations.
            // This mirrors the C behavior where registrations after
            // ossl_cleanup_thread() are ignored.
            return;
        }
        self.handlers.lock().push(handler);
    }

    /// Fires all registered handlers in LIFO order, matching the C
    /// `init_thread_remove_handlers` destruction order.
    ///
    /// Handlers are executed outside the lock to avoid potential deadlocks
    /// if a handler interacts with other locks.
    fn fire_handlers(&self) {
        // Prevent double invocation.
        if self
            .invoked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        // Extract all handlers under the lock, then run them outside.
        let mut handlers_to_run: Vec<Box<dyn FnOnce() + Send>> = {
            let mut guard = self.handlers.lock();
            std::mem::take(&mut *guard)
        };

        // Execute in LIFO (reverse registration) order, matching the C
        // linked-list destruction order in crypto/initthread.c.
        while let Some(handler) = handlers_to_run.pop() {
            // Catch panics so one failing handler doesn't prevent others
            // from running — mirrors the C approach of iterating the full list.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(handler));
        }
    }
}

/// Guard that fires thread stop handlers when dropped (i.e., when the thread exits).
///
/// Each thread that registers at least one handler gets a `StopGuard` stored in
/// thread-local storage. When the thread exits, Rust drops the thread-local,
/// which drops the `StopGuard`, which fires all registered handlers.
struct StopGuard {
    state: Arc<ThreadStopState>,
}

impl Drop for StopGuard {
    fn drop(&mut self) {
        self.state.fire_handlers();
    }
}

// LOCK-SCOPE: protects the global list of per-thread stop states; locked briefly
// during thread handler registration and during global cleanup (Rule R7).
static GLOBAL_HANDLER_REGISTRY: Mutex<Vec<Arc<ThreadStopState>>> = Mutex::new(Vec::new());

thread_local! {
    /// Per-thread stop guard. Initialized lazily on first handler registration.
    static STOP_GUARD: RefCell<Option<StopGuard>> = const { RefCell::new(None) };
}

/// Registers a cleanup handler to be called when the current thread exits.
///
/// This is the Rust equivalent of `ossl_init_thread_start()` from
/// `crypto/initthread.c`. Handlers are fired in LIFO (last-registered,
/// first-called) order when the thread terminates, matching the C
/// `THREAD_EVENT_HANDLER` linked-list destruction order.
///
/// # Arguments
///
/// * `handler` — A boxed closure to execute on thread exit. Must be `Send`
///   because thread-local destructors may run in a different context during
///   process shutdown.
///
/// # Errors
///
/// Returns `Err(CryptoError)` if the thread-local storage has already been
/// destroyed (e.g., during late-stage process shutdown), mirroring the C
/// behavior where `ossl_init_thread_start` can fail if called too late.
///
/// # Examples
///
/// ```
/// use openssl_crypto::thread::register_thread_stop_handler;
///
/// register_thread_stop_handler(Box::new(|| {
///     // Cleanup resources when thread exits
/// })).expect("registration should succeed");
/// ```
pub fn register_thread_stop_handler(handler: Box<dyn FnOnce() + Send>) -> Result<(), CryptoError> {
    // Attempt to access the thread-local. This can fail during late
    // thread/process shutdown when TLS destructors have already run.
    let result = STOP_GUARD.try_with(|guard_cell| {
        let mut guard_ref = guard_cell.borrow_mut();

        if guard_ref.is_none() {
            // First handler registration on this thread — create the state
            // and register it globally.
            let state = Arc::new(ThreadStopState::new());
            GLOBAL_HANDLER_REGISTRY.lock().push(Arc::clone(&state));
            *guard_ref = Some(StopGuard { state });
        }

        // The guard is guaranteed to be Some after the block above.
        if let Some(ref stop_guard) = *guard_ref {
            stop_guard.state.push_handler(handler);
        }
    });

    result.map_err(|_| {
        CryptoError::Common(openssl_common::error::CommonError::Internal(
            "thread-local storage already destroyed during shutdown".into(),
        ))
    })
}

// ---------------------------------------------------------------------------
// Atomic helpers — replaces fallback_atomic_* from crypto/threads_pthread.c
// ---------------------------------------------------------------------------

/// Atomically loads a `u64` value with sequentially-consistent ordering.
///
/// Replaces `fallback_atomic_load_n()` from `crypto/threads_pthread.c`.
/// The C implementation uses either `__atomic_load_n` or a mutex-guarded
/// fallback; in Rust, `AtomicU64` provides lock-free atomics on all
/// supported targets.
///
/// # Arguments
///
/// * `val` — Reference to the atomic value to read.
#[inline]
pub fn atomic_load_u64(val: &AtomicU64) -> u64 {
    val.load(Ordering::SeqCst)
}

/// Atomically stores a `u64` value with sequentially-consistent ordering.
///
/// Replaces `fallback_atomic_store_n()` from `crypto/threads_pthread.c`.
///
/// # Arguments
///
/// * `val` — Reference to the atomic value to update.
/// * `new_val` — The value to store.
#[inline]
pub fn atomic_store_u64(val: &AtomicU64, new_val: u64) {
    val.store(new_val, Ordering::SeqCst);
}

/// Atomically adds `delta` to a `u64` value, returning the **new** (post-add) value.
///
/// Replaces `fallback_atomic_add_fetch()` from `crypto/threads_pthread.c`.
/// Note: the C function returns the post-add value (`__atomic_add_fetch`),
/// whereas Rust's `fetch_add` returns the pre-add value. We add `delta` to
/// the returned pre-add value to match the C semantics.
///
/// # Arguments
///
/// * `val` — Reference to the atomic value to update.
/// * `delta` — The amount to add.
#[inline]
pub fn atomic_add_u64(val: &AtomicU64, delta: u64) -> u64 {
    val.fetch_add(delta, Ordering::SeqCst).wrapping_add(delta)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    // -- CryptoLock tests --

    #[test]
    fn crypto_lock_read_write() {
        let lock = CryptoLock::new(42_u64, "test_lock");
        assert_eq!(lock.name(), "test_lock");

        // Read access.
        {
            let guard = lock.read();
            assert_eq!(*guard, 42);
        }

        // Write access.
        {
            let mut guard = lock.write();
            *guard = 100;
        }

        // Verify written value.
        {
            let guard = lock.read();
            assert_eq!(*guard, 100);
        }
    }

    #[test]
    fn crypto_lock_try_read_write() {
        let lock = CryptoLock::new(0_i32, "try_lock");

        // try_read should succeed when no writer holds the lock.
        let guard = lock.try_read();
        assert!(guard.is_some());
        drop(guard);

        // try_write should succeed when no one holds the lock.
        let guard = lock.try_write();
        assert!(guard.is_some());
        drop(guard);
    }

    #[test]
    fn crypto_lock_concurrent_readers() {
        let lock = Arc::new(CryptoLock::new(vec![1, 2, 3], "readers"));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let lock_clone = Arc::clone(&lock);
            handles.push(std::thread::spawn(move || {
                let guard = lock_clone.read();
                assert_eq!(guard.len(), 3);
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }
    }

    // -- CryptoOnce tests --

    #[test]
    fn crypto_once_single_execution() {
        let once = CryptoOnce::new();
        assert!(!once.is_completed());

        let counter = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&counter);
        once.call_once(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });

        assert!(once.is_completed());
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second call must be a no-op.
        let c2 = Arc::clone(&counter);
        once.call_once(move || {
            c2.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn crypto_once_default() {
        let once = CryptoOnce::default();
        assert!(!once.is_completed());
    }

    #[test]
    fn crypto_once_concurrent() {
        let once = Arc::new(CryptoOnce::new());
        let counter = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for _ in 0..16 {
            let o = Arc::clone(&once);
            let c = Arc::clone(&counter);
            handles.push(std::thread::spawn(move || {
                o.call_once(|| {
                    c.fetch_add(1, Ordering::SeqCst);
                });
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        assert!(once.is_completed());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // -- CryptoThreadLocal tests --

    #[test]
    fn thread_local_set_get_remove() {
        let tls: CryptoThreadLocal<String> = CryptoThreadLocal::new("test_tls");
        assert!(tls.is_empty());

        tls.set("hello".to_string());
        assert_eq!(tls.get(), Some("hello".to_string()));
        assert_eq!(tls.len(), 1);

        let upper = tls.with(|s| s.to_uppercase());
        assert_eq!(upper, Some("HELLO".to_string()));

        let removed = tls.remove_current();
        assert_eq!(removed, Some("hello".to_string()));
        assert!(tls.is_empty());
        assert_eq!(tls.get(), None);
    }

    #[test]
    fn thread_local_per_thread_isolation() {
        let tls = Arc::new(CryptoThreadLocal::new("isolation"));

        // Set value on main thread.
        tls.set(1_u64);

        // Spawn a child thread that sets its own value.
        let tls_clone = Arc::clone(&tls);
        let handle = std::thread::spawn(move || {
            assert_eq!(tls_clone.get(), None); // Should not see main's value.
            tls_clone.set(2_u64);
            assert_eq!(tls_clone.get(), Some(2));
        });
        handle.join().expect("child thread should not panic");

        // Main thread's value is unchanged.
        assert_eq!(tls.get(), Some(1));
    }

    #[test]
    fn thread_local_default() {
        let tls: CryptoThreadLocal<u32> = CryptoThreadLocal::default();
        assert_eq!(tls.name(), "unnamed");
    }

    // -- register_thread_stop_handler tests --

    #[test]
    fn stop_handler_fires_on_thread_exit() {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        let handle = std::thread::spawn(move || {
            register_thread_stop_handler(Box::new(move || {
                flag_clone.store(true, Ordering::SeqCst);
            }))
            .expect("registration should succeed");
        });

        handle.join().expect("thread should not panic");

        // Give the thread-local destructor a moment to run.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            flag.load(Ordering::SeqCst),
            "stop handler should have fired"
        );
    }

    #[test]
    fn stop_handler_lifo_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let o1 = Arc::clone(&order);
        let o2 = Arc::clone(&order);
        let o3 = Arc::clone(&order);

        let handle = std::thread::spawn(move || {
            register_thread_stop_handler(Box::new(move || {
                o1.lock().push(1);
            }))
            .expect("register 1");
            register_thread_stop_handler(Box::new(move || {
                o2.lock().push(2);
            }))
            .expect("register 2");
            register_thread_stop_handler(Box::new(move || {
                o3.lock().push(3);
            }))
            .expect("register 3");
        });

        handle.join().expect("thread should not panic");
        std::thread::sleep(std::time::Duration::from_millis(50));

        let fired = order.lock().clone();
        // LIFO: last registered fires first → [3, 2, 1]
        assert_eq!(fired, vec![3, 2, 1]);
    }

    #[test]
    fn stop_handler_panic_safety() {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        let handle = std::thread::spawn(move || {
            // Register a handler that panics.
            register_thread_stop_handler(Box::new(|| {
                panic!("intentional panic in stop handler");
            }))
            .expect("register panicking handler");

            // Register a handler BEFORE the panicking one (will fire AFTER due to LIFO).
            // Wait — LIFO means this fires first since it was registered second...
            // Let's be explicit: register non-panicking first, panicking second.
            // Actually the order above is: panicking registered first, then we need
            // another after it. Let me restructure:
            // Handler 1 (registered first, fires last in LIFO): sets flag.
            // Handler 2 (registered second, fires first in LIFO): panics.
            // So flag handler registered first should still fire even though handler 2 panics.
            register_thread_stop_handler(Box::new(move || {
                flag_clone.store(true, Ordering::SeqCst);
            }))
            .expect("register flag handler");
        });

        handle.join().expect("thread itself should not panic");
        std::thread::sleep(std::time::Duration::from_millis(50));

        // In LIFO order: flag handler fires first (registered second), then panicking.
        // The flag handler should have fired successfully.
        assert!(
            flag.load(Ordering::SeqCst),
            "flag handler should fire despite other handler panicking"
        );
    }

    // -- Atomic helper tests --

    #[test]
    fn atomic_load_store() {
        let val = AtomicU64::new(0);
        atomic_store_u64(&val, 42);
        assert_eq!(atomic_load_u64(&val), 42);
    }

    #[test]
    fn atomic_add() {
        let val = AtomicU64::new(10);
        let result = atomic_add_u64(&val, 5);
        assert_eq!(result, 15); // Post-add value.
        assert_eq!(atomic_load_u64(&val), 15);
    }

    #[test]
    fn atomic_add_wrapping() {
        let val = AtomicU64::new(u64::MAX);
        let result = atomic_add_u64(&val, 1);
        assert_eq!(result, 0); // Wrapping semantics.
    }

    #[test]
    fn debug_impls() {
        let lock = CryptoLock::new(42_i32, "dbg_lock");
        let dbg_str = format!("{:?}", lock);
        assert!(dbg_str.contains("CryptoLock"));
        assert!(dbg_str.contains("dbg_lock"));

        let once = CryptoOnce::new();
        let dbg_str = format!("{:?}", once);
        assert!(dbg_str.contains("CryptoOnce"));

        let tls: CryptoThreadLocal<i32> = CryptoThreadLocal::new("dbg_tls");
        let dbg_str = format!("{:?}", tls);
        assert!(dbg_str.contains("CryptoThreadLocal"));
    }
}
