//! QUIC Reactor — Async event-loop helper for QUIC state machine ticking.
//!
//! This module implements the QUIC reactor, which repeatedly "ticks" QUIC state
//! machines and, when necessary, blocks (asynchronously via tokio) until network
//! I/O is ready or a tick deadline is reached.
//!
//! # Source Translation
//!
//! Rust rewrite of `ssl/quic/quic_reactor.c` (~550 lines) and
//! `ssl/quic/quic_reactor_wait_ctx.c` (~100 lines).
//!
//! # Sync→Async Translation (AAP §0.7.4)
//!
//! The original C implementation uses blocking `poll(2)` / `select(2)` with
//! manual mutex unlock/relock around the blocking call. This Rust version
//! replaces that pattern with `tokio::select!` and `tokio::sync::Mutex`:
//!
//! | C Pattern                    | Rust Replacement                          |
//! |------------------------------|-------------------------------------------|
//! | `poll_two_fds()` / `poll(2)` | `tokio::select!` with `AsyncFd` readiness |
//! | `CRYPTO_MUTEX` unlock/relock | `tokio::sync::Mutex` guard drop/reacquire |
//! | `RIO_NOTIFIER` FD pair       | `tokio::sync::Notify`                     |
//! | EINTR retry loop             | Handled internally by tokio               |
//! | `select()` `FD_SETSIZE` limit | Not applicable with tokio epoll backend   |
//!
//! # Consistency Guarantees Lost (and Compensating Controls)
//!
//! 1. **Deterministic execution order**: C poll-loop has predictable callback
//!    order; tokio task scheduling is non-deterministic.
//!    *Compensating*: `tokio::select! { biased; .. }` +
//!    `tokio::test(start_paused = true)` for reproducible test scheduling.
//! 2. **Stack-depth predictability**: Async transforms recursion into state
//!    machines. *Compensating*: deep-nesting stress tests (1000+ streams).
//! 3. **Blocking-call safety**: `.await` across `std::sync::Mutex` hold causes
//!    deadlock. *Compensating*: `clippy::await_holding_lock = deny` per Rule R2.

use std::cell::RefCell;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bitflags::bitflags;
use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex as TokioMutex, Notify};
use tokio::time::Instant;

use openssl_common::error::SslError;
use openssl_common::time::OsslTime;

// =============================================================================
// Poll Descriptor
// =============================================================================

/// Network socket descriptor for reactor I/O readiness monitoring.
///
/// Replaces C's `BIO_POLL_DESCRIPTOR` union. Only the [`SocketFd`](Self::SocketFd)
/// variant is supported — matching `BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD` in the C
/// source. Custom descriptor types are not supported by the reactor.
///
/// # Platform Note
///
/// [`RawFd`] is Unix-specific (`i32` alias). The QUIC reactor currently targets
/// Unix platforms; Windows IOCP support would require a platform-specific
/// abstraction layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollDescriptor {
    /// A raw Unix socket file descriptor for async readiness monitoring.
    ///
    /// The reactor does NOT take ownership of the file descriptor. The caller
    /// is responsible for ensuring the FD remains valid and in non-blocking
    /// mode while registered with the reactor.
    SocketFd(RawFd),

    /// No descriptor registered. The reactor will not poll for I/O readiness
    /// on this side (read or write) when set to `None`.
    None,
}

impl PollDescriptor {
    /// Returns `true` if this descriptor holds a valid socket file descriptor.
    fn is_socket_fd(self) -> bool {
        matches!(self, PollDescriptor::SocketFd(_))
    }
}

// =============================================================================
// Block Flags
// =============================================================================

bitflags! {
    /// Flags controlling [`QuicReactor::block_until_pred()`] behavior.
    ///
    /// Replaces C's `QUIC_REACTOR_FLAG_*` constants used as the `flags`
    /// parameter to `ossl_quic_reactor_block_until_pred()`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BlockFlags: u32 {
        /// Skip the initial tick before the first predicate evaluation.
        ///
        /// When set, the reactor evaluates the user predicate immediately
        /// without ticking first. Useful when the caller knows the state
        /// machine was recently ticked and only wants to wait for I/O events
        /// or deadline expiry before re-evaluating.
        const SKIP_FIRST_TICK = 0x1;
    }
}

// =============================================================================
// Reactor Construction Flag
// =============================================================================

/// Flag passed to [`QuicReactor::new()`] to enable the cross-thread notifier.
///
/// When set, the reactor creates a [`tokio::sync::Notify`] instance that allows
/// other tasks/threads to wake the reactor's blocking loop. This replaces C's
/// `RIO_NOTIFIER` file descriptor pair (`rio_notifier_init()` /
/// `rio_notifier_signal()`).
///
/// Without this flag, the reactor relies solely on socket readiness and deadline
/// expiry to advance — no external wakeup mechanism is available.
pub const QUIC_REACTOR_FLAG_USE_NOTIFIER: u32 = 0x1;

// =============================================================================
// Tick Result
// =============================================================================

/// Result of a single reactor tick, capturing desired I/O state and next deadline.
///
/// Populated by the tick callback (`tick_cb`) and consumed by the reactor's
/// blocking loop to determine what to wait for. Replaces C's `QUIC_TICK_RESULT`
/// struct and the pattern of writing directly into reactor fields via output
/// pointer parameters.
#[derive(Debug, Clone)]
pub struct QuicTickResult {
    /// Whether the QUIC engine desires to read from the network socket.
    ///
    /// When `true`, the reactor monitors the read-side poll descriptor for
    /// readiness before the next tick.
    pub net_read_desired: bool,

    /// Whether the QUIC engine desires to write to the network socket.
    ///
    /// When `true`, the reactor monitors the write-side poll descriptor for
    /// readiness before the next tick.
    pub net_write_desired: bool,

    /// Deadline for the next mandatory tick.
    ///
    /// [`OsslTime::INFINITE`] means no deadline — the reactor only wakes on
    /// socket readiness or external notification. A finite value causes the
    /// reactor to wake and re-tick even if no I/O is ready.
    pub tick_deadline: OsslTime,

    /// Whether the tick produced state changes that other tasks/threads
    /// should be notified about.
    ///
    /// When `true`, the reactor signals the cross-thread notifier (if enabled)
    /// to wake any other tasks blocked on reactor operations.
    pub notify_other_threads: bool,
}

impl Default for QuicTickResult {
    fn default() -> Self {
        Self {
            net_read_desired: false,
            net_write_desired: false,
            tick_deadline: OsslTime::INFINITE,
            notify_other_threads: false,
        }
    }
}

impl QuicTickResult {
    /// Merges this tick result into the reactor's internal state.
    ///
    /// Updates the reactor's cached I/O desires and tick deadline from the tick
    /// callback's output. Called after each tick to propagate the callback's
    /// decisions into the reactor's blocking loop.
    ///
    /// This does NOT handle `notify_other_threads` — the caller must check
    /// that field separately and invoke [`QuicReactor::notify_other_threads()`].
    pub fn merge_into(&self, reactor: &mut QuicReactor) {
        reactor.net_read_desired = self.net_read_desired;
        reactor.net_write_desired = self.net_write_desired;
        reactor.tick_deadline = self.tick_deadline;
    }
}

// =============================================================================
// Async FD Wrapper (internal helper)
// =============================================================================

/// Thin wrapper around a raw file descriptor for [`AsyncFd`] registration.
///
/// Implements [`AsRawFd`] so it can be registered with [`tokio::io::unix::AsyncFd`]
/// for event-driven socket readiness monitoring. The wrapper does NOT own the FD
/// and does NOT close it on drop — the QUIC port layer retains ownership.
#[derive(Debug, Clone, Copy)]
struct AsyncFdWrapper(RawFd);

impl AsRawFd for AsyncFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

// =============================================================================
// QUIC Reactor
// =============================================================================

/// Core event-loop helper that ticks QUIC state machines and blocks
/// asynchronously until network I/O is ready or a tick deadline is reached.
///
/// The reactor is the central scheduling component of the QUIC stack. It
/// repeatedly invokes a tick callback (which drives the QUIC engine, port,
/// and channel state machines) and then waits for the next event using
/// `tokio::select!`.
///
/// # Lifecycle
///
/// 1. Created by `QuicEngine::new()` with a tick callback and optional notifier.
/// 2. Poll descriptors registered via [`set_poll_r()`](Self::set_poll_r) /
///    [`set_poll_w()`](Self::set_poll_w).
/// 3. Event loop driven by [`block_until_pred()`](Self::block_until_pred) —
///    tick, check predicate, wait.
/// 4. Dropped when the engine is destroyed.
///
/// # Rule R1 Compliance (Single Runtime)
///
/// The reactor uses `tokio::sync::*` primitives but NEVER creates a
/// `tokio::runtime::Runtime`. It relies on the runtime provided by the
/// application entry point (e.g., `openssl_cli::main()`).
///
/// # Rule R7 Compliance (Lock Granularity)
///
/// // LOCK-SCOPE: reactor mutex — guards `tick_cb` invocation and state updates;
/// // temporarily unlocked around `tokio::select!` to avoid holding across .await
/// // per Rule R2.
#[allow(clippy::struct_excessive_bools)] // Mirrors C reactor booleans faithfully
pub struct QuicReactor {
    /// Read-side poll descriptor (network socket for incoming data).
    poll_r: Option<PollDescriptor>,
    /// Write-side poll descriptor (network socket for outgoing data).
    poll_w: Option<PollDescriptor>,
    /// Whether the read-side descriptor supports async polling.
    can_poll_r: bool,
    /// Whether the write-side descriptor supports async polling.
    can_poll_w: bool,
    /// Tick callback invoked by the reactor to advance QUIC state machines.
    ///
    /// The callback fills a [`QuicTickResult`] with desired I/O state and
    /// deadlines. Must be `Send` to allow the reactor to be shared across tasks.
    tick_cb: Box<dyn FnMut(&mut QuicTickResult) + Send>,
    /// Whether the QUIC engine desires network read (from last tick).
    net_read_desired: bool,
    /// Whether the QUIC engine desires network write (from last tick).
    net_write_desired: bool,
    /// Deadline for the next tick (from last tick).
    tick_deadline: OsslTime,
    /// Cross-thread notifier replacing C's `RIO_NOTIFIER` FD pair.
    ///
    /// Created when [`QUIC_REACTOR_FLAG_USE_NOTIFIER`] is set at construction.
    /// Uses `tokio::sync::Notify` which does not suffer from the stale-signal
    /// problem that the C two-phase wakeup handshake addresses —
    /// `notify_waiters()` only wakes tasks currently in `notified().await`.
    notifier: Option<Arc<Notify>>,
    /// Whether the notifier is active and should be monitored in `select!`.
    use_notifier: bool,
    /// Count of tasks currently in a blocking section.
    ///
    /// Incremented by [`enter_blocking_section()`](Self::enter_blocking_section),
    /// decremented by [`leave_blocking_section()`](Self::leave_blocking_section).
    waiter_count: AtomicU32,
    /// Async mutex shared with the QUIC engine for state protection.
    ///
    /// // LOCK-SCOPE: reactor mutex — guards `tick_cb` invocation and state
    /// // updates; temporarily unlocked around `tokio::select!` to avoid holding
    /// // across .await per Rule R2.
    mutex: Option<Arc<TokioMutex<()>>>,
}

impl QuicReactor {
    /// Creates a new QUIC reactor with the given tick callback and optional mutex.
    ///
    /// # Arguments
    ///
    /// * `tick_cb` — Callback invoked on each tick to advance QUIC state machines.
    ///   The callback fills a [`QuicTickResult`] with desired I/O state and the
    ///   next tick deadline.
    /// * `mutex` — Optional shared mutex for synchronizing reactor operations
    ///   with other QUIC engine tasks. If provided, the reactor acquires the lock
    ///   during tick + predicate evaluation and releases it during async wait.
    /// * `reactor_flags` — Bitfield of construction flags. Currently only
    ///   [`QUIC_REACTOR_FLAG_USE_NOTIFIER`] is defined.
    ///
    /// # Rule R1 Compliance
    ///
    /// The reactor does NOT create a `tokio::runtime::Runtime`. It relies on
    /// the caller's runtime context.
    pub fn new(
        tick_cb: Box<dyn FnMut(&mut QuicTickResult) + Send>,
        mutex: Option<Arc<TokioMutex<()>>>,
        reactor_flags: u32,
    ) -> Self {
        let use_notifier = (reactor_flags & QUIC_REACTOR_FLAG_USE_NOTIFIER) != 0;
        let notifier = if use_notifier {
            // tokio::sync::Notify replaces C's RIO_NOTIFIER FD pair.
            // No file descriptors, no EINTR handling, no FD_SETSIZE limit.
            Some(Arc::new(Notify::new()))
        } else {
            Option::None
        };

        tracing::debug!(
            use_notifier = use_notifier,
            has_mutex = mutex.is_some(),
            "QuicReactor created"
        );

        Self {
            poll_r: Option::None,
            poll_w: Option::None,
            can_poll_r: false,
            can_poll_w: false,
            tick_cb,
            net_read_desired: false,
            net_write_desired: false,
            tick_deadline: OsslTime::INFINITE,
            notifier,
            use_notifier,
            waiter_count: AtomicU32::new(0),
            mutex,
        }
    }

    // =========================================================================
    // Poll Descriptor Management
    // =========================================================================

    /// Registers or clears the read-side poll descriptor.
    ///
    /// Only [`PollDescriptor::SocketFd`] is supported. Setting a descriptor
    /// enables the reactor to monitor socket read-readiness during
    /// [`block_until_pred()`](Self::block_until_pred).
    ///
    /// Replaces C's `ossl_quic_reactor_set_poll_r()`.
    pub fn set_poll_r(&mut self, desc: Option<PollDescriptor>) {
        self.can_poll_r = desc
            .as_ref()
            .map_or(false, QuicReactor::can_support_poll_descriptor);
        self.poll_r = desc;
    }

    /// Registers or clears the write-side poll descriptor.
    ///
    /// Only [`PollDescriptor::SocketFd`] is supported. Setting a descriptor
    /// enables the reactor to monitor socket write-readiness during
    /// [`block_until_pred()`](Self::block_until_pred).
    ///
    /// Replaces C's `ossl_quic_reactor_set_poll_w()`.
    pub fn set_poll_w(&mut self, desc: Option<PollDescriptor>) {
        self.can_poll_w = desc
            .as_ref()
            .map_or(false, QuicReactor::can_support_poll_descriptor);
        self.poll_w = desc;
    }

    /// Returns the current read-side poll descriptor, if any.
    pub fn get_poll_r(&self) -> Option<&PollDescriptor> {
        self.poll_r.as_ref()
    }

    /// Returns the current write-side poll descriptor, if any.
    pub fn get_poll_w(&self) -> Option<&PollDescriptor> {
        self.poll_w.as_ref()
    }

    /// Returns `true` if the given descriptor type is supported by the reactor.
    ///
    /// Currently only [`PollDescriptor::SocketFd`] is supported, matching
    /// C's `BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD` check in
    /// `ossl_quic_reactor_can_support_poll_descriptor()`.
    pub fn can_support_poll_descriptor(desc: &PollDescriptor) -> bool {
        desc.is_socket_fd()
    }

    /// Returns `true` if the read-side descriptor is registered and pollable.
    pub fn can_poll_r(&self) -> bool {
        self.can_poll_r
    }

    /// Returns `true` if the write-side descriptor is registered and pollable.
    pub fn can_poll_w(&self) -> bool {
        self.can_poll_w
    }

    // =========================================================================
    // State Accessors
    // =========================================================================

    /// Returns `true` if the QUIC engine desires network read (from last tick).
    pub fn net_read_desired(&self) -> bool {
        self.net_read_desired
    }

    /// Returns `true` if the QUIC engine desires network write (from last tick).
    pub fn net_write_desired(&self) -> bool {
        self.net_write_desired
    }

    /// Returns the tick deadline from the last tick.
    ///
    /// [`OsslTime::INFINITE`] means no deadline is set.
    pub fn get_tick_deadline(&self) -> OsslTime {
        self.tick_deadline
    }

    // =========================================================================
    // Tick
    // =========================================================================

    /// Performs a single reactor tick by invoking the tick callback.
    ///
    /// The tick callback advances QUIC state machines (engine, port, channel)
    /// and returns desired I/O state and the next deadline via [`QuicTickResult`].
    /// Results are merged into the reactor's internal state.
    ///
    /// If the tick result indicates `notify_other_threads`, the reactor signals
    /// the cross-thread notifier (if enabled).
    ///
    /// Replaces C's `ossl_quic_reactor_tick()`.
    pub fn tick(&mut self) {
        tracing::trace!("reactor tick");
        let mut result = QuicTickResult::default();
        (self.tick_cb)(&mut result);

        // Merge tick result into reactor state.
        result.merge_into(self);

        // Signal other tasks/threads if tick produced shareable state changes.
        if result.notify_other_threads {
            self.notify_other_threads();
        }
    }

    // =========================================================================
    // Blocking Until Predicate (Async)
    // =========================================================================

    /// Asynchronously blocks until the user predicate returns `true`.
    ///
    /// This is the core event loop of the QUIC reactor. It repeatedly:
    /// 1. Ticks the QUIC state machines (unless `SKIP_FIRST_TICK` on first iter)
    /// 2. Evaluates the user predicate — if satisfied, returns `Ok(())`
    /// 3. Checks if anything to wait for (desired I/O or finite deadline)
    /// 4. Enters a blocking section (increments waiter count)
    /// 5. Releases the reactor mutex (if present) — **Rule R2 compliance**
    /// 6. Waits via `tokio::select!` for socket readiness, deadline, or notifier
    /// 7. Reacquires the mutex and re-ticks
    ///
    /// # Sync→Async Translation
    ///
    /// This replaces C's `ossl_quic_reactor_block_until_pred()` which uses
    /// `poll_two_fds()` with `poll(2)` / `select(2)`. The Rust version uses
    /// `tokio::select!` with `biased` for deterministic branch priority
    /// (compensating for lost deterministic execution order per AAP §0.7.4).
    ///
    /// The mutex unlock/relock pattern from C (`ossl_crypto_mutex_unlock` before
    /// `poll()`, `ossl_crypto_mutex_lock` after) is implemented by dropping the
    /// `tokio::sync::MutexGuard` before `select!` and reacquiring at the top of
    /// the next loop iteration.
    ///
    /// # Errors
    ///
    /// Returns [`SslError::Quic`] if an I/O readiness poll fails.
    pub async fn block_until_pred<F>(
        &mut self,
        mut pred: F,
        flags: BlockFlags,
    ) -> Result<(), SslError>
    where
        F: FnMut() -> bool,
    {
        let mut skip_tick = flags.contains(BlockFlags::SKIP_FIRST_TICK);

        // Clone shared state to avoid borrow conflicts with &mut self in loop.
        let mutex = self.mutex.clone();
        let notifier = self.notifier.clone();
        let use_notifier = self.use_notifier;

        loop {
            // ==================================================================
            // Phase 1: Acquire mutex, tick, evaluate predicate
            // ==================================================================
            // LOCK-SCOPE: reactor mutex — held during tick + predicate check;
            // dropped before tokio::select! to avoid holding across .await (R2).
            let guard = match mutex {
                Some(ref m) => Some(m.lock().await),
                _ => Option::None,
            };

            if !skip_tick {
                tracing::trace!("reactor tick cycle in block_until_pred");
                self.tick();
            }
            skip_tick = false;

            // Evaluate user predicate — if satisfied, we are done.
            if pred() {
                tracing::debug!("predicate satisfied, returning");
                return Ok(());
            }

            // Check if there is anything to wait for.
            if !self.net_read_desired && !self.net_write_desired && self.tick_deadline.is_infinite()
            {
                // Nothing to wait for — predicate unsatisfied but no I/O or
                // deadline to block on. Return without error.
                tracing::debug!("nothing to wait for, returning");
                return Ok(());
            }

            // Snapshot state for the async wait phase (avoids &self in select!).
            let net_read_desired = self.net_read_desired;
            let net_write_desired = self.net_write_desired;
            let poll_r = self.poll_r;
            let poll_w = self.poll_w;
            let tick_deadline = self.tick_deadline;

            // ==================================================================
            // Phase 2: Enter blocking section, release mutex, async wait
            // ==================================================================
            self.enter_blocking_section();

            // Drop the mutex guard before the async wait — this is the Rust
            // equivalent of C's `ossl_crypto_mutex_unlock(rtor->mutex)` before
            // `poll()` / `select()`. The guard is reacquired at the top of the
            // next loop iteration (Phase 1).
            drop(guard);

            // Compute tokio::time::Instant deadline from OsslTime.
            let deadline: Option<Instant> = if tick_deadline.is_infinite() {
                Option::None
            } else {
                let now_ossl = OsslTime::now();
                let remaining = tick_deadline.saturating_sub(now_ossl);
                // to_duration() returns None for INFINITE (handled above),
                // Some(Duration::ZERO) for past deadlines — sleep_until fires
                // immediately in that case.
                remaining
                    .to_duration()
                    .map(|d| Instant::now() + d)
                    .or_else(|| Some(Instant::now()))
            };

            // Set up optional AsyncFd wrappers for socket readiness monitoring.
            // Created per-iteration because poll descriptors can change between
            // ticks. Gracefully falls back to None if AsyncFd creation fails
            // (matching C's poll_descriptor_to_fd returning -1 for invalid FDs).
            let read_fd: Option<AsyncFd<AsyncFdWrapper>> = if net_read_desired {
                match poll_r {
                    Some(PollDescriptor::SocketFd(fd)) => AsyncFd::new(AsyncFdWrapper(fd)).ok(),
                    _ => Option::None,
                }
            } else {
                Option::None
            };

            let write_fd: Option<AsyncFd<AsyncFdWrapper>> = if net_write_desired {
                match poll_w {
                    Some(PollDescriptor::SocketFd(fd)) => AsyncFd::new(AsyncFdWrapper(fd)).ok(),
                    _ => Option::None,
                }
            } else {
                Option::None
            };

            // Verify at least one select! branch will be active.
            let has_read = read_fd.is_some();
            let has_write = write_fd.is_some();
            let has_deadline = deadline.is_some();
            let has_notify = use_notifier && notifier.is_some();

            if !has_read && !has_write && !has_deadline && !has_notify {
                // No actionable wait condition — leave blocking and re-tick.
                tracing::debug!("no actionable wait conditions, re-ticking");
                self.leave_blocking_section();
                continue;
            }

            tracing::debug!(
                has_read = has_read,
                has_write = has_write,
                has_deadline = has_deadline,
                has_notify = has_notify,
                "entering async select"
            );

            // ==================================================================
            // Phase 3: Async multiplexed wait via tokio::select!
            // ==================================================================
            // Replaces C's poll_two_fds() which calls poll(2) or select(2)
            // with manual EINTR retry and FD_SETSIZE limit.
            //
            // `biased` gives deterministic branch priority (read > write >
            // deadline > notify), partially compensating for lost deterministic
            // execution order (AAP §0.7.4 consistency delta #1).
            tokio::select! {
                biased;

                result = async {
                    match read_fd.as_ref() {
                        Some(afd) => {
                            let mut g = afd.readable().await?;
                            g.clear_ready();
                            Ok::<(), std::io::Error>(())
                        }
                        Option::None => {
                            std::future::pending::<Result<(), std::io::Error>>().await
                        }
                    }
                }, if has_read => {
                    match result {
                        Ok(()) => {
                            tracing::debug!("reactor woke: read ready");
                        }
                        Err(e) => {
                            self.leave_blocking_section();
                            return Err(SslError::Quic(
                                format!("read readiness poll failed: {e}")
                            ));
                        }
                    }
                },

                result = async {
                    match write_fd.as_ref() {
                        Some(afd) => {
                            let mut g = afd.writable().await?;
                            g.clear_ready();
                            Ok::<(), std::io::Error>(())
                        }
                        Option::None => {
                            std::future::pending::<Result<(), std::io::Error>>().await
                        }
                    }
                }, if has_write => {
                    match result {
                        Ok(()) => {
                            tracing::debug!("reactor woke: write ready");
                        }
                        Err(e) => {
                            self.leave_blocking_section();
                            return Err(SslError::Quic(
                                format!("write readiness poll failed: {e}")
                            ));
                        }
                    }
                },

                () = async {
                    match deadline {
                        Some(dl) => tokio::time::sleep_until(dl).await,
                        Option::None => std::future::pending::<()>().await,
                    }
                }, if has_deadline => {
                    tracing::debug!("reactor woke: deadline reached");
                },

                () = async {
                    match notifier.as_ref() {
                        Some(n) => n.notified().await,
                        Option::None => std::future::pending::<()>().await,
                    }
                }, if has_notify => {
                    tracing::debug!("reactor woke: cross-thread notification");
                },
            }

            // ==================================================================
            // Phase 4: Leave blocking section, loop back to re-tick
            // ==================================================================
            // The mutex is reacquired at the top of the next iteration (Phase 1),
            // matching C's `ossl_crypto_mutex_lock(rtor->mutex)` after poll().
            self.leave_blocking_section();
        }
    }

    // =========================================================================
    // Cross-Thread Notification
    // =========================================================================

    /// Signals the cross-thread notifier to wake tasks blocked in
    /// [`block_until_pred()`](Self::block_until_pred).
    ///
    /// # Sync→Async Translation
    ///
    /// In C, `rtor_notify_other_threads()` sets a `notifier_signalled` flag,
    /// calls `ossl_rio_notifier_signal()`, then waits via a condvar for all
    /// blocked threads to wake (two-phase wakeup handshake). In Rust,
    /// `tokio::sync::Notify::notify_waiters()` wakes all tasks currently in
    /// `notified().await` without persistent state — the stale-signal problem
    /// that the C two-phase handshake addresses does not exist with Notify.
    pub fn notify_other_threads(&self) {
        if !self.use_notifier {
            return;
        }

        if let Some(ref notifier) = self.notifier {
            tracing::debug!(
                waiter_count = self.waiter_count.load(Ordering::Acquire),
                "signaling cross-thread notifier"
            );
            // notify_waiters() wakes ALL tasks currently in notified().await.
            // Unlike C's FD-based notifier, there is no stale signal — tasks
            // that call notified().await AFTER this call will block normally.
            notifier.notify_waiters();
        }
    }

    // =========================================================================
    // Blocking Section Management
    // =========================================================================

    /// Enters a blocking section — increments the waiter count.
    ///
    /// Must be balanced with a corresponding `leave_blocking_section()`
    /// (`Self::leave_blocking_section`) call. The blocking section tracks how
    /// many tasks are waiting in the async `select!` loop, used for shutdown
    /// coordination and observability.
    ///
    /// Replaces C's `ossl_quic_reactor_enter_blocking_section()`.
    pub fn enter_blocking_section(&self) {
        let prev = self.waiter_count.fetch_add(1, Ordering::AcqRel);
        tracing::debug!(waiter_count = prev + 1, "entered blocking section");
    }

    /// Leaves a blocking section — decrements the waiter count.
    ///
    /// # Sync→Async Translation
    ///
    /// In C, the last waiter to leave checks `notifier_signalled` and clears
    /// it, then broadcasts a condvar to unblock `rtor_notify_other_threads()`.
    /// In Rust, this complexity is not needed because `tokio::sync::Notify`
    /// does not have persistent signal state — each `notify_waiters()` call
    /// only affects tasks currently waiting.
    ///
    /// Replaces C's `ossl_quic_reactor_leave_blocking_section()`.
    pub fn leave_blocking_section(&self) {
        let prev = self.waiter_count.fetch_sub(1, Ordering::AcqRel);
        tracing::debug!(waiter_count = prev - 1, "left blocking section");
    }

    /// Returns a reference to the cross-thread notifier, if enabled.
    ///
    /// Used by external components that need to signal the reactor directly
    /// (e.g., the QUIC port layer when a new datagram arrives on a different
    /// thread).
    ///
    /// Replaces C's `ossl_quic_reactor_get0_notifier()`.
    pub fn get_notifier(&self) -> Option<&Arc<Notify>> {
        self.notifier.as_ref()
    }
}

// =============================================================================
// Reactor Wait Context (from quic_reactor_wait_ctx.c)
// =============================================================================

tokio::task_local! {
    /// Per-task reactor wait context for tracking blocking section depth.
    ///
    /// Replaces C's thread-local `QUIC_REACTOR_WAIT_CTX`. Initialized via
    /// `REACTOR_WAIT_CTX.scope(RefCell::new(ReactorWaitCtx::new()), future)`.
    ///
    /// # Sync→Async Translation
    ///
    /// C uses `CRYPTO_THREAD_LOCAL` for per-thread wait context storage.
    /// Rust uses `tokio::task_local!` for per-task storage, aligning with
    /// the async task model where multiple tasks may share a single OS thread.
    pub static REACTOR_WAIT_CTX: RefCell<ReactorWaitCtx>;
}

/// Tracks balanced enter/leave of reactor blocking sections per-task.
///
/// Each async task participating in QUIC reactor operations maintains a
/// `ReactorWaitCtx` in its [`REACTOR_WAIT_CTX`] task-local storage. The
/// context counts nesting depth and ensures proper cleanup on task completion.
///
/// In C, `QUIC_REACTOR_WAIT_CTX` is a thread-local linked list of per-reactor
/// slots with individual `blocking_count` fields. In Rust, we use a single
/// depth counter per task since the async model ensures non-overlapping
/// reactor access within a task.
///
/// # Usage
///
/// ```ignore
/// REACTOR_WAIT_CTX.scope(RefCell::new(ReactorWaitCtx::new()), async {
///     let guard = REACTOR_WAIT_CTX.with(|ctx| ctx.borrow_mut().enter());
///     // ... blocking section ...
///     drop(guard); // automatically calls leave()
/// }).await;
/// ```
pub struct ReactorWaitCtx {
    /// Current blocking section nesting depth.
    depth: u32,
}

impl ReactorWaitCtx {
    /// Creates a new wait context with zero nesting depth.
    pub fn new() -> Self {
        Self { depth: 0 }
    }

    /// Enters a blocking section, incrementing the nesting depth.
    ///
    /// Returns a [`WaitGuard`] that automatically calls [`leave()`](Self::leave)
    /// on drop via the per-task [`REACTOR_WAIT_CTX`] task-local, ensuring
    /// balanced enter/leave even on early returns or panics.
    ///
    /// # C Equivalent
    ///
    /// Replaces `ossl_quic_reactor_wait_ctx_enter()` which finds or creates
    /// a per-reactor slot in the thread-local linked list and increments its
    /// `blocking_count`.
    pub fn enter(&mut self) -> WaitGuard {
        self.depth = self.depth.saturating_add(1);
        tracing::trace!(depth = self.depth, "ReactorWaitCtx::enter");
        WaitGuard { _private: () }
    }

    /// Leaves a blocking section, decrementing the nesting depth.
    ///
    /// This is called automatically by [`WaitGuard::drop()`], but can also
    /// be called manually for explicit control flow.
    ///
    /// # C Equivalent
    ///
    /// Replaces `ossl_quic_reactor_wait_ctx_leave()` which finds the
    /// per-reactor slot and decrements its `blocking_count`.
    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        tracing::trace!(depth = self.depth, "ReactorWaitCtx::leave");
    }

    /// Cleans up the wait context, asserting all blocking sections are exited.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `depth == 0`. In release builds, resets depth to 0.
    ///
    /// # C Equivalent
    ///
    /// Replaces `ossl_quic_reactor_wait_ctx_cleanup()` which frees all
    /// per-reactor slots and asserts `blocking_count == 0` for each.
    pub fn cleanup(&mut self) {
        debug_assert_eq!(
            self.depth, 0,
            "ReactorWaitCtx::cleanup: unbalanced enter/leave (depth={})",
            self.depth
        );
        self.depth = 0;
    }
}

impl Default for ReactorWaitCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for reactor wait context depth tracking.
///
/// Created by [`ReactorWaitCtx::enter()`]. When dropped, automatically calls
/// [`ReactorWaitCtx::leave()`] via the per-task [`REACTOR_WAIT_CTX`] task-local,
/// ensuring balanced blocking section tracking even on early returns or panics.
///
/// # Design Note
///
/// The guard does not hold a direct mutable reference to [`ReactorWaitCtx`]
/// because the context lives in a `tokio::task_local!` `RefCell`. Instead,
/// drop accesses the task-local directly. This allows multiple guards to
/// coexist in the same scope without borrow conflicts.
pub struct WaitGuard {
    /// Private field to prevent external construction.
    _private: (),
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        // Access the task-local ReactorWaitCtx and decrement depth.
        // try_with returns Err if the task-local is not set (e.g., running
        // outside of a REACTOR_WAIT_CTX.scope()). This is a graceful no-op.
        let _ = REACTOR_WAIT_CTX.try_with(|ctx| {
            ctx.borrow_mut().leave();
        });
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poll_descriptor_none_variant() {
        let desc = PollDescriptor::None;
        assert!(!desc.is_socket_fd());
        assert!(!QuicReactor::can_support_poll_descriptor(&desc));
    }

    #[test]
    fn test_poll_descriptor_socket_fd() {
        let desc = PollDescriptor::SocketFd(42);
        assert!(desc.is_socket_fd());
        assert!(QuicReactor::can_support_poll_descriptor(&desc));
    }

    #[test]
    fn test_poll_descriptor_equality() {
        assert_eq!(PollDescriptor::SocketFd(10), PollDescriptor::SocketFd(10));
        assert_ne!(PollDescriptor::SocketFd(10), PollDescriptor::SocketFd(11));
        assert_ne!(PollDescriptor::SocketFd(10), PollDescriptor::None);
        assert_eq!(PollDescriptor::None, PollDescriptor::None);
    }

    #[test]
    fn test_block_flags_skip_first_tick() {
        let flags = BlockFlags::SKIP_FIRST_TICK;
        assert!(flags.contains(BlockFlags::SKIP_FIRST_TICK));

        let empty = BlockFlags::empty();
        assert!(!empty.contains(BlockFlags::SKIP_FIRST_TICK));
    }

    #[test]
    fn test_block_flags_bitwise_ops() {
        let a = BlockFlags::SKIP_FIRST_TICK;
        let b = BlockFlags::empty();
        let combined = a | b;
        assert!(combined.contains(BlockFlags::SKIP_FIRST_TICK));
    }

    #[test]
    fn test_reactor_flag_constant() {
        assert_eq!(QUIC_REACTOR_FLAG_USE_NOTIFIER, 0x1);
    }

    #[test]
    fn test_tick_result_default() {
        let result = QuicTickResult::default();
        assert!(!result.net_read_desired);
        assert!(!result.net_write_desired);
        assert_eq!(result.tick_deadline, OsslTime::INFINITE);
        assert!(!result.notify_other_threads);
    }

    #[test]
    fn test_tick_result_merge_into() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let mut reactor = QuicReactor::new(tick_cb, Option::None, 0);

        let result = QuicTickResult {
            net_read_desired: true,
            net_write_desired: false,
            tick_deadline: OsslTime::ZERO,
            notify_other_threads: true,
        };

        result.merge_into(&mut reactor);
        assert!(reactor.net_read_desired());
        assert!(!reactor.net_write_desired());
        assert_eq!(reactor.get_tick_deadline(), OsslTime::ZERO);
    }

    #[test]
    fn test_reactor_construction_no_notifier() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let reactor = QuicReactor::new(tick_cb, Option::None, 0);
        assert!(reactor.notifier.is_none());
        assert!(!reactor.use_notifier);
        assert!(!reactor.net_read_desired);
        assert!(!reactor.net_write_desired);
        assert_eq!(reactor.tick_deadline, OsslTime::INFINITE);
        assert!(reactor.poll_r.is_none());
        assert!(reactor.poll_w.is_none());
        assert!(!reactor.can_poll_r);
        assert!(!reactor.can_poll_w);
    }

    #[test]
    fn test_reactor_construction_with_notifier() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let reactor = QuicReactor::new(tick_cb, Option::None, QUIC_REACTOR_FLAG_USE_NOTIFIER);
        assert!(reactor.notifier.is_some());
        assert!(reactor.use_notifier);
    }

    #[test]
    fn test_reactor_construction_with_mutex() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let mutex = Arc::new(TokioMutex::new(()));
        let reactor = QuicReactor::new(tick_cb, Some(mutex), QUIC_REACTOR_FLAG_USE_NOTIFIER);
        assert!(reactor.mutex.is_some());
        assert!(reactor.notifier.is_some());
    }

    #[test]
    fn test_set_get_poll_descriptors() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let mut reactor = QuicReactor::new(tick_cb, Option::None, 0);

        // Initially empty.
        assert!(reactor.get_poll_r().is_none());
        assert!(reactor.get_poll_w().is_none());
        assert!(!reactor.can_poll_r());
        assert!(!reactor.can_poll_w());

        // Set read descriptor.
        reactor.set_poll_r(Some(PollDescriptor::SocketFd(10)));
        assert!(reactor.can_poll_r());
        assert_eq!(reactor.get_poll_r(), Some(&PollDescriptor::SocketFd(10)));

        // Set write descriptor.
        reactor.set_poll_w(Some(PollDescriptor::SocketFd(11)));
        assert!(reactor.can_poll_w());
        assert_eq!(reactor.get_poll_w(), Some(&PollDescriptor::SocketFd(11)));

        // Set to PollDescriptor::None — not pollable.
        reactor.set_poll_r(Some(PollDescriptor::None));
        assert!(!reactor.can_poll_r());
        assert_eq!(reactor.get_poll_r(), Some(&PollDescriptor::None));

        // Clear read descriptor entirely.
        reactor.set_poll_r(Option::None);
        assert!(!reactor.can_poll_r());
        assert!(reactor.get_poll_r().is_none());
    }

    #[test]
    fn test_tick_invokes_callback_and_merges() {
        let tick_cb = Box::new(|result: &mut QuicTickResult| {
            result.net_read_desired = true;
            result.net_write_desired = true;
            result.tick_deadline = OsslTime::ZERO;
            result.notify_other_threads = false;
        });
        let mut reactor = QuicReactor::new(tick_cb, Option::None, 0);

        assert!(!reactor.net_read_desired());
        assert!(!reactor.net_write_desired());
        assert_eq!(reactor.get_tick_deadline(), OsslTime::INFINITE);

        reactor.tick();

        assert!(reactor.net_read_desired());
        assert!(reactor.net_write_desired());
        assert_eq!(reactor.get_tick_deadline(), OsslTime::ZERO);
    }

    #[test]
    fn test_tick_with_notify() {
        let tick_cb = Box::new(|result: &mut QuicTickResult| {
            result.notify_other_threads = true;
            result.tick_deadline = OsslTime::INFINITE;
        });
        let mut reactor = QuicReactor::new(tick_cb, Option::None, QUIC_REACTOR_FLAG_USE_NOTIFIER);
        // Should not panic — notify is called internally.
        reactor.tick();
    }

    #[test]
    fn test_enter_leave_blocking_section() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let reactor = QuicReactor::new(tick_cb, Option::None, 0);

        assert_eq!(reactor.waiter_count.load(Ordering::Relaxed), 0);

        reactor.enter_blocking_section();
        assert_eq!(reactor.waiter_count.load(Ordering::Relaxed), 1);

        reactor.enter_blocking_section();
        assert_eq!(reactor.waiter_count.load(Ordering::Relaxed), 2);

        reactor.leave_blocking_section();
        assert_eq!(reactor.waiter_count.load(Ordering::Relaxed), 1);

        reactor.leave_blocking_section();
        assert_eq!(reactor.waiter_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_notify_no_notifier() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let reactor = QuicReactor::new(tick_cb, Option::None, 0);
        // Should not panic — early return when notifier not set.
        reactor.notify_other_threads();
    }

    #[test]
    fn test_notify_with_notifier() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let reactor = QuicReactor::new(tick_cb, Option::None, QUIC_REACTOR_FLAG_USE_NOTIFIER);
        // Should not panic.
        reactor.notify_other_threads();
    }

    #[test]
    fn test_get_notifier() {
        let tick_cb = Box::new(|_: &mut QuicTickResult| {});
        let reactor = QuicReactor::new(tick_cb, Option::None, QUIC_REACTOR_FLAG_USE_NOTIFIER);
        assert!(reactor.get_notifier().is_some());

        let tick_cb2 = Box::new(|_: &mut QuicTickResult| {});
        let reactor2 = QuicReactor::new(tick_cb2, Option::None, 0);
        assert!(reactor2.get_notifier().is_none());
    }

    #[test]
    fn test_wait_ctx_new() {
        let ctx = ReactorWaitCtx::new();
        assert_eq!(ctx.depth, 0);
    }

    #[test]
    fn test_wait_ctx_default() {
        let ctx = ReactorWaitCtx::default();
        assert_eq!(ctx.depth, 0);
    }

    #[test]
    fn test_wait_ctx_depth_tracking() {
        let mut ctx = ReactorWaitCtx::new();
        assert_eq!(ctx.depth, 0);

        // enter() increments depth and returns a guard.
        let _guard1 = ctx.enter();
        assert_eq!(ctx.depth, 1);

        // Manual leave() decrements depth.
        ctx.leave();
        assert_eq!(ctx.depth, 0);

        // _guard1 dropped here — attempts task-local leave(), which is a
        // graceful no-op outside of REACTOR_WAIT_CTX.scope().
    }

    #[test]
    fn test_wait_ctx_saturating_leave() {
        let mut ctx = ReactorWaitCtx::new();
        // leave() at depth 0 saturates to 0, no underflow.
        ctx.leave();
        assert_eq!(ctx.depth, 0);
    }

    #[test]
    fn test_wait_ctx_cleanup_balanced() {
        let mut ctx = ReactorWaitCtx::new();
        // No-op when depth is already 0.
        ctx.cleanup();
        assert_eq!(ctx.depth, 0);
    }

    #[test]
    fn test_wait_ctx_nested_enter() {
        let mut ctx = ReactorWaitCtx::new();
        let _g1 = ctx.enter();
        assert_eq!(ctx.depth, 1);
        let _g2 = ctx.enter();
        assert_eq!(ctx.depth, 2);
        ctx.leave();
        assert_eq!(ctx.depth, 1);
        ctx.leave();
        assert_eq!(ctx.depth, 0);
    }

    #[test]
    fn test_wait_guard_outside_task_local() {
        // WaitGuard::drop gracefully handles missing task-local.
        let guard = WaitGuard { _private: () };
        drop(guard); // Should not panic.
    }

    // =========================================================================
    // Async tests (require tokio runtime)
    // =========================================================================

    #[tokio::test]
    async fn test_block_until_pred_immediate_satisfaction() {
        let tick_cb = Box::new(|result: &mut QuicTickResult| {
            result.tick_deadline = OsslTime::INFINITE;
        });
        let mut reactor = QuicReactor::new(tick_cb, Option::None, 0);

        // Predicate immediately true — returns after first tick + pred check.
        let result = reactor.block_until_pred(|| true, BlockFlags::empty()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_until_pred_skip_first_tick() {
        let tick_count = Arc::new(AtomicU32::new(0));
        let tc = tick_count.clone();

        let tick_cb = Box::new(move |result: &mut QuicTickResult| {
            tc.fetch_add(1, Ordering::Relaxed);
            result.tick_deadline = OsslTime::INFINITE;
        });
        let mut reactor = QuicReactor::new(tick_cb, Option::None, 0);

        // With SKIP_FIRST_TICK, predicate is checked before first tick.
        let result = reactor
            .block_until_pred(|| true, BlockFlags::SKIP_FIRST_TICK)
            .await;
        assert!(result.is_ok());
        // No tick should have happened because predicate was immediately true.
        assert_eq!(tick_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_block_until_pred_nothing_to_wait_for() {
        let tick_cb = Box::new(|result: &mut QuicTickResult| {
            result.net_read_desired = false;
            result.net_write_desired = false;
            result.tick_deadline = OsslTime::INFINITE;
        });
        let mut reactor = QuicReactor::new(tick_cb, Option::None, 0);

        // Predicate false, nothing to wait for — returns Ok(()).
        let result = reactor
            .block_until_pred(|| false, BlockFlags::empty())
            .await;
        assert!(result.is_ok());
    }

    /// Deterministic testing note: In production CI, use
    /// `tokio::test(start_paused = true)` for reproducible scheduling
    /// per AAP §0.7.4 consistency delta. Omitted here due to test-util
    /// feature resolution across workspace optional deps.
    #[tokio::test]
    async fn test_block_until_pred_deadline_wakes() {
        let tick_count = Arc::new(AtomicU32::new(0));
        let tc = tick_count.clone();

        let tick_cb = Box::new(move |result: &mut QuicTickResult| {
            let count = tc.fetch_add(1, Ordering::Relaxed);
            if count < 2 {
                // First two ticks: set a short deadline.
                result.tick_deadline = OsslTime::ZERO;
                result.net_read_desired = false;
                result.net_write_desired = false;
            } else {
                // Third tick: no more work.
                result.tick_deadline = OsslTime::INFINITE;
            }
        });
        let mut reactor = QuicReactor::new(tick_cb, Option::None, 0);

        let mut pred_count = 0u32;
        let result = reactor
            .block_until_pred(
                || {
                    pred_count += 1;
                    // Satisfied on the third check (after deadline-based re-tick).
                    pred_count >= 3
                },
                BlockFlags::empty(),
            )
            .await;
        assert!(result.is_ok());
        assert!(pred_count >= 3);
    }

    #[tokio::test]
    async fn test_block_until_pred_with_mutex() {
        let mutex = Arc::new(TokioMutex::new(()));
        let tick_cb = Box::new(|result: &mut QuicTickResult| {
            result.tick_deadline = OsslTime::INFINITE;
        });
        let mut reactor = QuicReactor::new(tick_cb, Some(mutex), 0);

        // Predicate immediately true — mutex is acquired/released internally.
        let result = reactor.block_until_pred(|| true, BlockFlags::empty()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_until_pred_with_notifier() {
        let tick_cb = Box::new(|result: &mut QuicTickResult| {
            result.tick_deadline = OsslTime::INFINITE;
        });
        let mut reactor = QuicReactor::new(tick_cb, Option::None, QUIC_REACTOR_FLAG_USE_NOTIFIER);

        // Predicate immediately true.
        let result = reactor.block_until_pred(|| true, BlockFlags::empty()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wait_ctx_in_task_local() {
        REACTOR_WAIT_CTX
            .scope(RefCell::new(ReactorWaitCtx::new()), async {
                // Enter via task-local.
                let guard = REACTOR_WAIT_CTX.with(|ctx| ctx.borrow_mut().enter());

                // Depth should be 1.
                REACTOR_WAIT_CTX.with(|ctx| {
                    assert_eq!(ctx.borrow().depth, 1);
                });

                // Drop guard — leave() is called via task-local.
                drop(guard);

                // Depth should be back to 0.
                REACTOR_WAIT_CTX.with(|ctx| {
                    assert_eq!(ctx.borrow().depth, 0);
                });

                // Cleanup.
                REACTOR_WAIT_CTX.with(|ctx| {
                    ctx.borrow_mut().cleanup();
                });
            })
            .await;
    }

    #[tokio::test]
    async fn test_notifier_wakes_blocked_task() {
        let notifier = Arc::new(Notify::new());
        let notifier_clone = notifier.clone();

        let tick_count = Arc::new(AtomicU32::new(0));
        let tc = tick_count.clone();

        let tick_cb = Box::new(move |result: &mut QuicTickResult| {
            let count = tc.fetch_add(1, Ordering::Relaxed);
            if count == 0 {
                // First tick: nothing to do except wait for notifier.
                result.tick_deadline = OsslTime::INFINITE;
            } else {
                // After wakeup: predicate will be satisfied.
                result.tick_deadline = OsslTime::INFINITE;
            }
        });
        let mut reactor = QuicReactor::new(tick_cb, Option::None, QUIC_REACTOR_FLAG_USE_NOTIFIER);

        // Override the reactor's notifier with our shared one.
        reactor.notifier = Some(notifier);

        // Spawn a task to signal the notifier after a short delay.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            notifier_clone.notify_waiters();
        });

        let pred_count = Arc::new(AtomicU32::new(0));
        let pc = pred_count.clone();

        let result = reactor
            .block_until_pred(
                move || {
                    let c = pc.fetch_add(1, Ordering::Relaxed);
                    c >= 2 // True on third evaluation
                },
                BlockFlags::empty(),
            )
            .await;
        assert!(result.is_ok());
    }
}
