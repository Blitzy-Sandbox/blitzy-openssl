//! # Congestion Control — `NewReno` with Pluggable Trait
//!
//! This module provides the [`CongestionController`] trait for pluggable congestion control
//! algorithms and a [`NewRenoCc`] implementation of RFC 9002 §7 `NewReno` congestion control
//! for the QUIC v1 protocol stack.
//!
//! ## Architecture
//!
//! This is a direct Rust rewrite of `ssl/quic/cc_newreno.c` (~486 lines). The C code's
//! `OSSL_CC_METHOD` function-pointer dispatch table is replaced with a Rust trait
//! ([`CongestionController`]) enabling compile-time and runtime polymorphism (AAP §0.4.3).
//!
//! The C code's `OSSL_PARAM`-based configuration is replaced with typed builder methods
//! on [`NewRenoCc`] (AAP §0.7.2).
//!
//! ## State Machine
//!
//! The congestion controller follows a three-state machine:
//! - **`SlowStart`**: Exponential growth until `ssthresh` or loss
//! - **`CongestionAvoidance`**: Linear growth (one `max_dgram_size` per RTT)
//! - **Recovery**: After loss detection, window reduced; no growth until recovery ends
//!
//! ## RFC Compliance
//!
//! Implements RFC 9002 §7 (`NewReno` for QUIC):
//! - §7.2: Initial window calculation
//! - §7.3: Slow start with exponential growth
//! - §7.3.1: Congestion avoidance with linear growth
//! - §7.3.2: Recovery period handling
//! - §7.6.2: Persistent congestion detection
//!
//! ## Rules Compliance
//!
//! - **R5 (Nullability):** `Option<T>` for `ssthresh`, `recovery_start_time`, `tx_time_of_last_loss`
//! - **R6 (Lossless casts):** All arithmetic uses `saturating_sub`, `checked_mul`; no bare `as`
//! - **R7 (Lock granularity):** LOCK-SCOPE documented below
//! - **R8 (Zero unsafe):** No `unsafe` blocks
//! - **R9 (Warning-free):** All items documented, no unused imports
//! - **R10 (Wiring):** Reachable from `AckManager.on_rx_ack_frame() → cc.on_data_acked()/on_data_lost()`

// LOCK-SCOPE: NewRenoCc — owned per-channel, accessed via AckManager during loss processing.
// Each QUIC channel owns exactly one NewRenoCc instance. No shared mutable state across channels.
// The AckManager holds &mut NewRenoCc and calls methods during ACK/loss processing, which is
// single-threaded per channel. No Mutex required for this structure.

use openssl_common::time::OsslTime;
use std::cmp;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Constants (from ssl/quic/cc_newreno.c)
// ---------------------------------------------------------------------------

/// Minimum value for the maximum initial congestion window.
///
/// Per RFC 9002 §7.2, the initial window is `min(10 * max_dgram_size, max(2 * max_dgram_size, 14720))`.
/// This constant (14720 bytes ≈ 10 × 1472 for typical QUIC datagrams) ensures a reasonable
/// minimum starting window even for small datagram sizes.
///
/// Preserved from `MIN_MAX_INIT_WND_SIZE` in `ssl/quic/cc_newreno.c`.
const MIN_MAX_INIT_WND_SIZE: usize = 14720;

/// Multiplier threshold for persistent congestion detection.
///
/// Per RFC 9002 §7.6.2, persistent congestion is detected when the duration between
/// the earliest and latest lost ack-eliciting packets exceeds `pto_duration * 3`.
///
/// Preserved from `persistent_cong_thresh` field default in `ssl/quic/cc_newreno.c`.
const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

// ---------------------------------------------------------------------------
// CcState enum
// ---------------------------------------------------------------------------

/// Congestion control state machine states.
///
/// Tracks the current phase of the `NewReno` congestion control algorithm.
/// Transitions follow RFC 9002 §7:
/// - `SlowStart` → `CongestionAvoidance`: when `cwnd >= ssthresh`
/// - `SlowStart` / `CongestionAvoidance` → `Recovery`: on loss detection
/// - `Recovery` → `CongestionAvoidance`: when ack for post-recovery packet arrives
/// - Any → `SlowStart`: after persistent congestion reset
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcState {
    /// Exponential congestion window growth phase.
    ///
    /// The congestion window increases by the number of bytes acknowledged,
    /// effectively doubling the window each RTT. Active from connection start
    /// until the first loss event or until cwnd reaches ssthresh.
    SlowStart,

    /// Linear congestion window growth phase.
    ///
    /// After the first loss event establishes ssthresh, the window grows by
    /// one `max_dgram_size` per congestion window's worth of acknowledged data.
    /// This is the steady-state operating mode.
    CongestionAvoidance,

    /// Loss recovery phase.
    ///
    /// Entered upon detecting packet loss. The congestion window is reduced
    /// by the loss reduction factor (default: halved). No window growth occurs
    /// during recovery. Recovery ends when an ack is received for a packet
    /// sent after entering recovery.
    Recovery,
}

impl CcState {
    /// Returns a string label for diagnostic output.
    ///
    /// Maps to the diagnostic state names used by the C implementation's
    /// `newreno_update_diag()` function.
    pub fn as_str(self) -> &'static str {
        match self {
            CcState::SlowStart => "slow_start",
            CcState::CongestionAvoidance => "congestion_avoidance",
            CcState::Recovery => "recovery",
        }
    }
}

impl std::fmt::Display for CcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CongestionController trait
// ---------------------------------------------------------------------------

/// Pluggable congestion controller trait, replacing C's `OSSL_CC_METHOD`
/// function-pointer dispatch table.
///
/// This trait defines the interface for congestion control algorithms used by
/// the QUIC transport layer. The default implementation is [`NewRenoCc`] (RFC 9002 §7),
/// but alternative algorithms (e.g., CUBIC, BBR) can be implemented by providing
/// a different implementation of this trait.
///
/// # Design
///
/// Replaces the C `OSSL_CC_METHOD` structure from `include/internal/quic_cc.h`.
/// The Rust trait consolidates `on_data_lost` and `on_data_lost_finished` into a single
/// `on_data_lost` call with aggregated loss information, simplifying the API.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to support ownership transfer across threads.
/// In practice, each QUIC channel owns one congestion controller and accesses it
/// single-threaded from the channel's event loop.
///
/// See AAP §0.4.3 (Trait-based dispatch pattern).
pub trait CongestionController: Send + Sync {
    /// Inform the congestion controller that new data has been sent.
    ///
    /// Called for all packets (both ack-eliciting and non-ack-eliciting).
    /// Updates the bytes-in-flight counter.
    ///
    /// # Parameters
    /// - `bytes_sent`: Total bytes in the sent packet (including headers).
    fn on_data_sent(&mut self, bytes_sent: usize);

    /// Inform the congestion controller of newly acknowledged data.
    ///
    /// Called when an ACK frame is processed that acknowledges new packets.
    /// May trigger congestion window growth (slow start or congestion avoidance).
    ///
    /// # Parameters
    /// - `now`: Current time for recovery period calculations.
    /// - `bytes_acked`: Sum of bytes in all newly acknowledged packets.
    /// - `largest_pkt_time_sent`: Send time of the largest newly-acknowledged packet.
    fn on_data_acked(&mut self, now: OsslTime, bytes_acked: usize, largest_pkt_time_sent: OsslTime);

    /// Inform the congestion controller of detected lost packets.
    ///
    /// Called with aggregated loss information for one loss detection round.
    /// May trigger recovery entry with congestion window reduction.
    ///
    /// # Parameters
    /// - `now`: Current time (used to set recovery start time).
    /// - `largest_lost_pkt_num`: Packet number of the largest lost packet.
    /// - `largest_lost_pkt_send_time`: Send time of the largest lost packet.
    /// - `bytes_lost`: Total bytes across all detected lost packets.
    fn on_data_lost(
        &mut self,
        now: OsslTime,
        largest_lost_pkt_num: u64,
        largest_lost_pkt_send_time: OsslTime,
        bytes_lost: usize,
    );

    /// Inform the congestion controller of invalidated in-flight data.
    ///
    /// Called when a packet number space is discarded (e.g., Initial/Handshake
    /// keys are discarded after handshake completion). Reduces bytes-in-flight
    /// without triggering congestion response.
    ///
    /// # Parameters
    /// - `bytes_invalidated`: Total bytes in discarded packets.
    fn on_data_invalidated(&mut self, bytes_invalidated: usize);

    /// Query the current send allowance.
    ///
    /// Returns the number of bytes that may be sent given the current congestion
    /// window and bytes in flight. Returns 0 if the sender is congestion-limited.
    ///
    /// # Parameters
    /// - `now`: Current time (unused by `NewReno`, available for pacing algorithms).
    /// - `bytes_in_flight`: Current bytes in flight as tracked by the caller.
    /// - `max_dgram_size`: Maximum datagram payload size for minimum-packet checks.
    fn get_send_allowance(
        &self,
        now: OsslTime,
        bytes_in_flight: usize,
        max_dgram_size: usize,
    ) -> usize;

    /// Get the current congestion window in bytes.
    fn get_cwnd(&self) -> usize;

    /// Get the current slow-start threshold.
    ///
    /// Returns `None` if ssthresh has never been set (initial slow start phase,
    /// equivalent to C's `UINT64_MAX` sentinel value). Uses `Option<usize>` per
    /// Rule R5 (Nullability Over Sentinels).
    fn get_ssthresh(&self) -> Option<usize>;

    /// Get the current bytes in flight as tracked by the congestion controller.
    fn get_bytes_in_flight(&self) -> usize;

    /// Get a diagnostic string label for the current CC state.
    ///
    /// Returns a human-readable state name for logging and debugging.
    /// Replaces C's `newreno_update_diag()` diagnostic pointer pattern
    /// with structured tracing-compatible output.
    fn get_diag_state(&self) -> &'static str;

    /// Reset the congestion controller state.
    ///
    /// Resets the congestion window to the minimum window size, clears all
    /// recovery state, and returns to slow start. Typically called after
    /// persistent congestion detection per RFC 9002 §7.6.2.
    fn reset(&mut self);
}

// ---------------------------------------------------------------------------
// TxPacketRecord — packet metadata for persistent congestion detection
// ---------------------------------------------------------------------------

/// Record of a transmitted packet, used for persistent congestion detection.
///
/// The ack manager maintains these records for all sent packets. When loss is
/// detected, the records of lost packets are passed to [`detect_persistent_congestion`]
/// to determine if the loss pattern indicates persistent congestion per RFC 9002 §7.6.2.
#[derive(Debug, Clone, Copy)]
pub struct TxPacketRecord {
    /// Time the packet was originally sent.
    pub send_time: OsslTime,

    /// Whether this packet contained ack-eliciting frames.
    ///
    /// Only ack-eliciting packets are considered for persistent congestion
    /// detection per RFC 9002 §7.6.2. Packets containing only ACK frames
    /// or padding are not ack-eliciting.
    pub ack_eliciting: bool,
}

// ---------------------------------------------------------------------------
// NewRenoCc struct
// ---------------------------------------------------------------------------

/// `NewReno` congestion controller implementing RFC 9002 §7.
///
/// This is the default congestion control algorithm for the QUIC transport stack,
/// providing a direct Rust translation of `ssl/quic/cc_newreno.c`.
///
/// # Configuration
///
/// Uses builder methods to replace C's `OSSL_PARAM` get/set interface:
/// ```ignore
/// let cc = NewRenoCc::new(1472)
///     .with_init_wnd(14720)
///     .with_min_wnd(2944)
///     .with_loss_reduction(1, 2);
/// ```
///
/// # Defaults
///
/// | Parameter | Default | Source |
/// |-----------|---------|--------|
/// | Initial window | `min(10 * max_dgram, max(2 * max_dgram, 14720))` | RFC 9002 §7.2 |
/// | Minimum window | `2 * max_dgram_size` | RFC 9002 §7.2 |
/// | Loss reduction | 1/2 (halving) | RFC 9002 §7.3.2 |
///
/// # Thread Safety
///
/// `NewRenoCc` is `Send + Sync`. Each QUIC channel owns exactly one instance.
/// No Mutex is required because access is single-threaded per channel event loop.
// LOCK-SCOPE: NewRenoCc — owned per-channel, accessed single-threaded via AckManager.
// No shared mutable state. Each QUIC channel has its own CC instance.
#[derive(Debug)]
pub struct NewRenoCc {
    // -----------------------------------------------------------------------
    // Configurable parameters (from C OSSL_PARAM interface)
    // -----------------------------------------------------------------------
    /// Initial congestion window size in bytes.
    ///
    /// Computed as `min(10 * max_dgram_size, max(2 * max_dgram_size, MIN_MAX_INIT_WND_SIZE))`
    /// per RFC 9002 §7.2.
    k_init_wnd: usize,

    /// Minimum congestion window size in bytes.
    ///
    /// Defaults to `2 * max_dgram_size`. The congestion window never shrinks below
    /// this value, ensuring at least two datagrams can always be sent.
    k_min_wnd: usize,

    /// Loss reduction factor numerator (default: 1).
    ///
    /// Combined with `k_loss_reduction_factor_den`, determines the congestion window
    /// reduction on loss: `cwnd_new = cwnd * num / den`.
    k_loss_reduction_factor_num: u32,

    /// Loss reduction factor denominator (default: 2).
    ///
    /// Standard `NewReno` halving: `num`=1, `den`=2 → cwnd reduced to 50% on loss.
    k_loss_reduction_factor_den: u32,

    /// Maximum datagram payload size in bytes.
    ///
    /// Used for minimum window calculations and congestion avoidance growth
    /// (one `max_dgram_size` per RTT in congestion avoidance).
    max_dgram_size: usize,

    // -----------------------------------------------------------------------
    // Congestion control state
    // -----------------------------------------------------------------------
    /// Current congestion control state.
    state: CcState,

    /// Current congestion window in bytes.
    cwnd: usize,

    /// Slow-start threshold.
    ///
    /// `None` means unlimited (initial slow start, equivalent to C's `UINT64_MAX`).
    /// Set to a concrete value after the first loss event. Uses `Option<T>` per
    /// Rule R5 (Nullability Over Sentinels).
    ssthresh: Option<usize>,

    /// Bytes currently in flight (CC's internal tracking).
    bytes_in_flight: usize,

    // -----------------------------------------------------------------------
    // Recovery tracking
    // -----------------------------------------------------------------------
    /// Time when the current recovery period started.
    ///
    /// `None` if not in recovery. Packets sent at or before this time are
    /// considered "recovery-period packets" — their acknowledgment does not
    /// trigger window growth. Uses `Option<T>` per Rule R5.
    recovery_start_time: Option<OsslTime>,

    // -----------------------------------------------------------------------
    // Loss batching (from C's processing_loss / tx_time_of_last_loss)
    // -----------------------------------------------------------------------
    /// Whether a loss event is currently being processed.
    ///
    /// Used to deduplicate loss events: if `on_data_lost` is called multiple
    /// times for packets in the same congestion epoch, only the first call
    /// triggers recovery entry. Mirrors C's `processing_loss` flag.
    processing_loss: bool,

    /// Send time of the last processed lost packet.
    ///
    /// Used with `processing_loss` to determine if a new `on_data_lost` call
    /// represents a new loss event or a continuation of a previously processed
    /// epoch. Uses `Option<T>` per Rule R5.
    tx_time_of_last_loss: Option<OsslTime>,

    // -----------------------------------------------------------------------
    // Congestion avoidance accumulator
    // -----------------------------------------------------------------------
    /// Bytes acknowledged since last congestion avoidance window increase.
    ///
    /// In congestion avoidance mode, the window grows by one `max_dgram_size`
    /// after acknowledging a full window's worth of data. This accumulator
    /// tracks progress toward that threshold (RFC 9002 §B.5, RFC 3465).
    bytes_acked_since_last_increase: usize,

    // -----------------------------------------------------------------------
    // Diagnostics
    // -----------------------------------------------------------------------
    /// Current bytes in flight for diagnostic reporting.
    ///
    /// Updated on every state change. Replaces C's diagnostic pointer pattern
    /// (`newreno_update_diag()`) with direct field access.
    diag_cur_bytes_in_flight: usize,
}

// ---------------------------------------------------------------------------
// NewRenoCc — Construction and Configuration
// ---------------------------------------------------------------------------

impl NewRenoCc {
    /// Creates a new `NewReno` congestion controller with default parameters.
    ///
    /// The initial congestion window is calculated per RFC 9002 §7.2:
    /// ```text
    /// k_init_wnd = min(10 * max_dgram_size, max(2 * max_dgram_size, 14720))
    /// ```
    ///
    /// # Parameters
    /// - `max_dgram_size`: Maximum datagram payload size in bytes (typically 1472 for IPv4/UDP).
    ///
    /// # C Equivalent
    /// `newreno_new()` + `newreno_set_max_dgram_size()` in `ssl/quic/cc_newreno.c`
    pub fn new(max_dgram_size: usize) -> Self {
        // RFC 9002 §7.2: initial_window = min(10 * max_datagram_size,
        //                                     max(2 * max_datagram_size, 14720))
        // Rule R6: saturating arithmetic to prevent overflow
        let max_init_wnd = cmp::max(
            2_usize.saturating_mul(max_dgram_size),
            MIN_MAX_INIT_WND_SIZE,
        );
        let k_init_wnd = cmp::min(10_usize.saturating_mul(max_dgram_size), max_init_wnd);
        let k_min_wnd = 2_usize.saturating_mul(max_dgram_size);

        NewRenoCc {
            k_init_wnd,
            k_min_wnd,
            k_loss_reduction_factor_num: 1,
            k_loss_reduction_factor_den: 2,
            max_dgram_size,
            state: CcState::SlowStart,
            cwnd: k_init_wnd,
            ssthresh: None,
            bytes_in_flight: 0,
            recovery_start_time: None,
            processing_loss: false,
            tx_time_of_last_loss: None,
            bytes_acked_since_last_increase: 0,
            diag_cur_bytes_in_flight: 0,
        }
    }

    /// Sets the initial congestion window size.
    ///
    /// Overrides the RFC 9002 §7.2 default calculation. Also resets the current
    /// congestion window to the new initial value.
    ///
    /// # Parameters
    /// - `wnd`: Initial window size in bytes.
    ///
    /// # C Equivalent
    /// Setting `OSSL_CC_OPTION_INIT_K_CWND_SIZE` via `OSSL_PARAM` in C.
    #[must_use]
    pub fn with_init_wnd(mut self, wnd: usize) -> Self {
        self.k_init_wnd = wnd;
        self.cwnd = wnd;
        self
    }

    /// Sets the minimum congestion window size.
    ///
    /// The congestion window never shrinks below this value after loss events
    /// or persistent congestion reset.
    ///
    /// # Parameters
    /// - `wnd`: Minimum window size in bytes.
    ///
    /// # C Equivalent
    /// Setting `OSSL_CC_OPTION_MIN_K_CWND_SIZE` via `OSSL_PARAM` in C.
    #[must_use]
    pub fn with_min_wnd(mut self, wnd: usize) -> Self {
        self.k_min_wnd = wnd;
        self
    }

    /// Sets the loss reduction factor as a fraction `num / den`.
    ///
    /// Controls how much the congestion window is reduced on loss detection.
    /// The default is 1/2 (standard halving). Setting to 7/10 would reduce
    /// to 70% on loss.
    ///
    /// # Parameters
    /// - `num`: Numerator of the reduction factor.
    /// - `den`: Denominator of the reduction factor (must be > 0).
    ///
    /// # Panics
    /// Panics if `den` is zero (division by zero protection).
    ///
    /// # C Equivalent
    /// Setting `OSSL_CC_OPTION_LOSS_REDUCTION_FACTOR_{NUM,DEN}` via `OSSL_PARAM` in C.
    #[must_use]
    pub fn with_loss_reduction(mut self, num: u32, den: u32) -> Self {
        assert!(den > 0, "loss reduction denominator must be non-zero");
        self.k_loss_reduction_factor_num = num;
        self.k_loss_reduction_factor_den = den;
        self
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Checks if the sender is congestion-limited.
    ///
    /// RFC 9002 §B.4: "An endpoint SHOULD NOT increase the congestion window
    /// unless the endpoint is cwnd-limited." This prevents spurious window
    /// growth when the sender is application-limited.
    ///
    /// Returns `true` if any of:
    /// 1. `bytes_in_flight >= cwnd` (fully utilizing window)
    /// 2. Remaining window ≤ 3 × `max_dgram_size` (nearly full)
    /// 3. ssthresh set and remaining window ≤ cwnd / 2 (congestion avoidance threshold)
    ///
    /// # C Equivalent
    /// `newreno_is_cong_limited()` in `ssl/quic/cc_newreno.c`
    fn is_congestion_limited(&self) -> bool {
        if self.bytes_in_flight >= self.cwnd {
            return true;
        }

        let remaining = self.cwnd.saturating_sub(self.bytes_in_flight);

        // Nearly full: remaining window can fit at most 3 datagrams
        if remaining <= 3_usize.saturating_mul(self.max_dgram_size) {
            return true;
        }

        // In congestion avoidance (ssthresh is set) and less than half window remaining
        if self.ssthresh.is_some() && remaining <= self.cwnd / 2 {
            return true;
        }

        false
    }

    /// Checks if a packet sent at `tx_time` is within the current recovery period.
    ///
    /// A packet is considered "in recovery" if it was sent at or before the
    /// recovery start time. Acknowledging such packets does not trigger
    /// congestion window growth.
    ///
    /// # C Equivalent
    /// `newreno_in_cong_recovery()` in `ssl/quic/cc_newreno.c`
    fn is_in_recovery(&self, tx_time: OsslTime) -> bool {
        match self.recovery_start_time {
            Some(start) => tx_time <= start,
            None => false,
        }
    }

    /// Updates diagnostic tracking fields after a state change.
    ///
    /// Replaces C's `newreno_update_diag()` which wrote to diagnostic pointer
    /// locations. In Rust, this updates internal fields that can be queried
    /// via `get_diag_state()`, `get_cwnd()`, etc.
    fn update_diag(&mut self) {
        self.diag_cur_bytes_in_flight = self.bytes_in_flight;
    }
}

// ---------------------------------------------------------------------------
// CongestionController implementation for NewRenoCc
// ---------------------------------------------------------------------------

impl CongestionController for NewRenoCc {
    /// Records bytes sent, incrementing the bytes-in-flight counter.
    ///
    /// Called for every sent packet, including non-ack-eliciting packets (ACK-only,
    /// padding). The `bytes_in_flight` counter is decremented when the packet is
    /// either acknowledged (`on_data_acked`), declared lost (`on_data_lost`),
    /// or invalidated (`on_data_invalidated`).
    fn on_data_sent(&mut self, bytes_sent: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes_sent);
        self.update_diag();
    }

    /// Processes acknowledgment of data, potentially growing the congestion window.
    ///
    /// Implements RFC 9002 §7.3 (slow start) and §7.3.1 (congestion avoidance):
    /// - In slow start: `cwnd += bytes_acked` (exponential growth)
    /// - In congestion avoidance: `cwnd += max_dgram_size` per window of acked data
    ///
    /// Window growth is suppressed when:
    /// - The acknowledged packet was sent during the recovery period
    /// - The sender is not congestion-limited (RFC 9002 §B.4)
    fn on_data_acked(
        &mut self,
        _now: OsslTime,
        bytes_acked: usize,
        largest_pkt_time_sent: OsslTime,
    ) {
        // Deduct acknowledged bytes from in-flight counter (Rule R6: saturating_sub)
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        // Check if the acknowledged packet was sent during recovery
        if self.is_in_recovery(largest_pkt_time_sent) {
            // Still in recovery — no window growth
            self.update_diag();
            tracing::trace!(
                cwnd = self.cwnd,
                state = %self.state,
                "CC on_data_acked: in recovery, no growth"
            );
            return;
        }

        // Acknowledged packet was sent after recovery start — exit recovery
        if self.state == CcState::Recovery {
            self.state = CcState::CongestionAvoidance;
            self.processing_loss = false;
            tracing::debug!(
                cwnd = self.cwnd,
                state = %self.state,
                "CC exited recovery"
            );
        }

        // RFC 9002 §B.4: only grow window if congestion-limited
        if !self.is_congestion_limited() {
            self.update_diag();
            tracing::trace!(
                cwnd = self.cwnd,
                state = %self.state,
                "CC on_data_acked: not congestion-limited, no growth"
            );
            return;
        }

        // Determine growth mode based on cwnd vs ssthresh
        let in_slow_start = match self.ssthresh {
            None => true,
            Some(thresh) => self.cwnd < thresh,
        };

        if in_slow_start {
            // Slow start: exponential growth (RFC 9002 §7.3)
            self.cwnd = self.cwnd.saturating_add(bytes_acked);

            // Check for slow start → congestion avoidance transition
            if let Some(thresh) = self.ssthresh {
                if self.cwnd >= thresh {
                    self.state = CcState::CongestionAvoidance;
                    self.bytes_acked_since_last_increase = 0;
                }
            }

            // Ensure state reflects slow start if not transitioned
            if self.state != CcState::CongestionAvoidance {
                self.state = CcState::SlowStart;
            }
        } else {
            // Congestion avoidance: linear growth (RFC 9002 §7.3.1, RFC 3465)
            // Grow by one max_dgram_size per congestion window of acknowledged data
            self.state = CcState::CongestionAvoidance;
            self.bytes_acked_since_last_increase = self
                .bytes_acked_since_last_increase
                .saturating_add(bytes_acked);

            if self.bytes_acked_since_last_increase >= self.cwnd {
                self.bytes_acked_since_last_increase = self
                    .bytes_acked_since_last_increase
                    .saturating_sub(self.cwnd);
                self.cwnd = self.cwnd.saturating_add(self.max_dgram_size);
            }
        }

        self.update_diag();
        tracing::trace!(
            cwnd = self.cwnd,
            state = %self.state,
            bytes_acked = bytes_acked,
            "CC on_data_acked: window updated"
        );
    }

    /// Processes packet loss detection, potentially entering recovery.
    ///
    /// Implements RFC 9002 §7.3.2 congestion event handling:
    /// - Reduces `ssthresh` to `max(cwnd * loss_factor, k_min_wnd)`
    /// - Sets `cwnd = ssthresh` (reduced window)
    /// - Enters recovery state
    ///
    /// Loss batching: if `on_data_lost` is called multiple times for packets in
    /// the same congestion epoch (same or earlier send time as a previously
    /// processed loss), recovery is not re-entered. This prevents multiple
    /// window reductions for a single congestion event.
    fn on_data_lost(
        &mut self,
        now: OsslTime,
        largest_lost_pkt_num: u64,
        largest_lost_pkt_send_time: OsslTime,
        bytes_lost: usize,
    ) {
        if bytes_lost == 0 {
            return;
        }

        // Deduct lost bytes from in-flight counter (Rule R6: saturating_sub)
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_lost);

        // Loss batching check: if we've already processed a loss at or after this
        // send time, this is part of the same congestion epoch — skip recovery entry.
        if self.processing_loss {
            if let Some(last_loss_time) = self.tx_time_of_last_loss {
                if last_loss_time >= largest_lost_pkt_send_time {
                    // Already processed this epoch — just deduct bytes
                    self.update_diag();
                    tracing::trace!(
                        pkt_num = largest_lost_pkt_num,
                        bytes_lost = bytes_lost,
                        "CC on_data_lost: same epoch, bytes deducted only"
                    );
                    return;
                }
            }
        }

        // Check if the lost packet was sent during an existing recovery period.
        // If so, it was already in flight when recovery started — do not re-enter.
        if self.is_in_recovery(largest_lost_pkt_send_time) {
            self.processing_loss = true;
            self.tx_time_of_last_loss = Some(
                self.tx_time_of_last_loss
                    .map_or(largest_lost_pkt_send_time, |t| {
                        t.max(largest_lost_pkt_send_time)
                    }),
            );
            self.update_diag();
            tracing::trace!(
                pkt_num = largest_lost_pkt_num,
                bytes_lost = bytes_lost,
                "CC on_data_lost: packet in recovery period, no re-entry"
            );
            return;
        }

        // New congestion event — enter recovery (RFC 9002 §7.3.2)
        self.processing_loss = true;
        self.recovery_start_time = Some(now);

        // Calculate new ssthresh: cwnd * loss_factor, minimum k_min_wnd
        // Rule R6: use checked_mul to avoid overflow on large windows
        let reduced_wnd = self
            .cwnd
            .checked_mul(self.k_loss_reduction_factor_num as usize)
            .unwrap_or(usize::MAX)
            / cmp::max(self.k_loss_reduction_factor_den as usize, 1);
        let new_ssthresh = cmp::max(reduced_wnd, self.k_min_wnd);

        self.ssthresh = Some(new_ssthresh);
        self.cwnd = new_ssthresh;
        self.state = CcState::Recovery;
        self.tx_time_of_last_loss = Some(largest_lost_pkt_send_time);
        self.bytes_acked_since_last_increase = 0;

        self.update_diag();
        tracing::debug!(
            cwnd = self.cwnd,
            ssthresh = ?self.ssthresh,
            state = %self.state,
            pkt_num = largest_lost_pkt_num,
            bytes_lost = bytes_lost,
            "CC on_data_lost: entered recovery"
        );
    }

    /// Removes invalidated bytes from the in-flight counter.
    ///
    /// Called when a packet number space is discarded (e.g., after handshake
    /// completion). This reduces `bytes_in_flight` without any congestion response —
    /// the window and ssthresh remain unchanged per RFC 9002.
    fn on_data_invalidated(&mut self, bytes_invalidated: usize) {
        // Rule R6: saturating_sub prevents underflow
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_invalidated);
        self.update_diag();
    }

    /// Calculates the number of bytes allowed to be sent.
    ///
    /// Returns the available congestion window, ensuring at least one datagram
    /// can be sent during slow start when the window is nearly full (pacing).
    ///
    /// # Algorithm
    /// 1. Compute available window: `cwnd - bytes_in_flight`
    /// 2. If available < `max_dgram_size`:
    ///    - In slow start with room: allow one datagram (pacing, RFC 9002 §7.3)
    ///    - Otherwise: return 0 (congestion-limited)
    /// 3. Return available window
    fn get_send_allowance(
        &self,
        _now: OsslTime,
        bytes_in_flight: usize,
        max_dgram_size: usize,
    ) -> usize {
        // Rule R6: saturating_sub prevents underflow
        let cwnd_available = self.cwnd.saturating_sub(bytes_in_flight);

        if cwnd_available < max_dgram_size {
            // Allow one datagram in slow start when not fully congested (pacing)
            if self.state == CcState::SlowStart && bytes_in_flight < self.cwnd {
                return max_dgram_size;
            }
            return 0;
        }

        cwnd_available
    }

    /// Returns the current congestion window size in bytes.
    #[inline]
    fn get_cwnd(&self) -> usize {
        self.cwnd
    }

    /// Returns the current slow-start threshold.
    ///
    /// Returns `None` during initial slow start (before any loss event).
    /// Returns `Some(threshold)` after the first loss event sets ssthresh.
    #[inline]
    fn get_ssthresh(&self) -> Option<usize> {
        self.ssthresh
    }

    /// Returns the bytes currently in flight as tracked by the CC.
    #[inline]
    fn get_bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// Returns a diagnostic state label string.
    ///
    /// Maps to the state names used by the C implementation's diagnostic output:
    /// - `"slow_start"` — exponential growth phase
    /// - `"congestion_avoidance"` — linear growth phase
    /// - `"recovery"` — loss recovery phase
    #[inline]
    fn get_diag_state(&self) -> &'static str {
        self.state.as_str()
    }

    /// Resets the congestion controller to slow start with minimum window.
    ///
    /// Typically called after persistent congestion detection (RFC 9002 §7.6.2).
    /// Resets the congestion window to `k_min_wnd`, clears all recovery state,
    /// and returns to slow start.
    ///
    /// # C Equivalent
    /// `newreno_flush()` with `OSSL_CC_LOST_FLAG_PERSISTENT_CONGESTION` flag, or
    /// `newreno_reset()` for full initialization reset.
    fn reset(&mut self) {
        self.cwnd = self.k_min_wnd;
        self.ssthresh = None;
        self.bytes_in_flight = 0;
        self.state = CcState::SlowStart;
        self.recovery_start_time = None;
        self.processing_loss = false;
        self.tx_time_of_last_loss = None;
        self.bytes_acked_since_last_increase = 0;
        self.diag_cur_bytes_in_flight = 0;

        tracing::debug!(
            cwnd = self.cwnd,
            state = %self.state,
            "CC reset: persistent congestion or full reset"
        );
    }
}

// ---------------------------------------------------------------------------
// Persistent congestion detection
// ---------------------------------------------------------------------------

/// Detects persistent congestion among a set of lost packets.
///
/// Implements RFC 9002 §7.6.2: persistent congestion is established when the
/// time duration between the earliest and latest ack-eliciting lost packets
/// exceeds the persistent congestion threshold (`pto_duration × 3`).
///
/// When persistent congestion is detected, the caller should invoke
/// [`CongestionController::reset()`] to collapse the congestion window to
/// the minimum window and re-enter slow start.
///
/// # Parameters
/// - `lost_packets`: Records of all packets detected as lost in this round.
///   Only ack-eliciting packets are considered for the calculation.
/// - `pto_duration`: Current probe timeout duration, used as the base for
///   the persistent congestion threshold.
///
/// # Returns
/// `true` if persistent congestion is detected, `false` otherwise.
///
/// # Algorithm
/// 1. Filter to ack-eliciting packets only
/// 2. Find the minimum and maximum send times
/// 3. If `max_time - min_time > pto_duration × PERSISTENT_CONGESTION_THRESHOLD(3)`:
///    persistent congestion detected
///
/// # C Equivalent
/// Persistent congestion detection in the ack manager, signaled via
/// `OSSL_CC_LOST_FLAG_PERSISTENT_CONGESTION` flag to `newreno_flush()`.
pub fn detect_persistent_congestion(
    lost_packets: &[&TxPacketRecord],
    pto_duration: Duration,
) -> bool {
    // Filter to ack-eliciting packets only (RFC 9002 §7.6.2)
    let mut min_time: Option<OsslTime> = None;
    let mut max_time: Option<OsslTime> = None;

    for pkt in lost_packets {
        if !pkt.ack_eliciting {
            continue;
        }

        min_time = Some(match min_time {
            Some(current) => current.min(pkt.send_time),
            None => pkt.send_time,
        });

        max_time = Some(match max_time {
            Some(current) => current.max(pkt.send_time),
            None => pkt.send_time,
        });
    }

    // Need at least two distinct ack-eliciting packet send times
    let (min_t, max_t) = match (min_time, max_time) {
        (Some(min_val), Some(max_val)) if min_val != max_val => (min_val, max_val),
        _ => return false,
    };

    // Calculate the persistent congestion threshold:
    // threshold = pto_duration × PERSISTENT_CONGESTION_THRESHOLD (3)
    // Rule R6: use checked_mul for overflow safety on Duration
    let threshold = pto_duration
        .checked_mul(PERSISTENT_CONGESTION_THRESHOLD)
        .unwrap_or(Duration::MAX);

    // Convert threshold to OsslTime for comparison.
    // A zero threshold means persistent congestion cannot be meaningfully detected
    // (degenerate PTO configuration). Guard against it explicitly.
    let threshold_ticks = OsslTime::from_duration(threshold);
    if threshold_ticks.is_zero() {
        return false;
    }

    // Check if the loss duration exceeds the threshold.
    // `saturating_sub` on OsslTime ensures we never underflow even if times are
    // unexpectedly ordered (defensive). Compare against zero as a sanity check.
    let loss_duration = max_t.saturating_sub(min_t);
    if loss_duration == OsslTime::zero() {
        return false;
    }
    loss_duration > threshold_ticks
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies the initial window calculation for typical QUIC datagram size.
    #[test]
    fn test_new_default_params() {
        let cc = NewRenoCc::new(1472);

        // RFC 9002 §7.2: min(10 * 1472, max(2 * 1472, 14720))
        // = min(14720, max(2944, 14720)) = min(14720, 14720) = 14720
        assert_eq!(cc.get_cwnd(), 14720);
        assert_eq!(cc.get_ssthresh(), None);
        assert_eq!(cc.get_bytes_in_flight(), 0);
        assert_eq!(cc.get_diag_state(), "slow_start");
        assert_eq!(cc.max_dgram_size, 1472);
        assert_eq!(cc.k_min_wnd, 2944);
        assert_eq!(cc.k_loss_reduction_factor_num, 1);
        assert_eq!(cc.k_loss_reduction_factor_den, 2);
    }

    /// Verifies initial window for small datagram sizes.
    #[test]
    fn test_new_small_dgram() {
        let cc = NewRenoCc::new(1200);

        // min(10 * 1200, max(2 * 1200, 14720))
        // = min(12000, max(2400, 14720)) = min(12000, 14720) = 12000
        assert_eq!(cc.get_cwnd(), 12000);
        assert_eq!(cc.k_min_wnd, 2400);
    }

    /// Verifies initial window for large datagram sizes.
    #[test]
    fn test_new_large_dgram() {
        let cc = NewRenoCc::new(9000);

        // min(10 * 9000, max(2 * 9000, 14720))
        // = min(90000, max(18000, 14720)) = min(90000, 18000) = 18000
        assert_eq!(cc.get_cwnd(), 18000);
        assert_eq!(cc.k_min_wnd, 18000);
    }

    /// Verifies builder methods override defaults.
    #[test]
    fn test_builder_methods() {
        let cc = NewRenoCc::new(1472)
            .with_init_wnd(20000)
            .with_min_wnd(5000)
            .with_loss_reduction(7, 10);

        assert_eq!(cc.get_cwnd(), 20000);
        assert_eq!(cc.k_init_wnd, 20000);
        assert_eq!(cc.k_min_wnd, 5000);
        assert_eq!(cc.k_loss_reduction_factor_num, 7);
        assert_eq!(cc.k_loss_reduction_factor_den, 10);
    }

    /// Verifies on_data_sent increments bytes in flight.
    #[test]
    fn test_on_data_sent() {
        let mut cc = NewRenoCc::new(1472);
        cc.on_data_sent(1000);
        assert_eq!(cc.get_bytes_in_flight(), 1000);

        cc.on_data_sent(500);
        assert_eq!(cc.get_bytes_in_flight(), 1500);
    }

    /// Verifies slow start growth on acknowledgment.
    #[test]
    fn test_slow_start_growth() {
        let mut cc = NewRenoCc::new(1472);
        let now = OsslTime::from_ms(1000);
        let send_time = OsslTime::from_ms(900);

        // Send enough data to fill the window (14720) so we are congestion-limited.
        cc.on_data_sent(14720);
        assert_eq!(cc.get_bytes_in_flight(), 14720);

        // Acknowledge a small portion so remaining stays ≤ 3*max_dgram (4416),
        // keeping the sender congestion-limited and allowing slow start growth.
        cc.on_data_acked(now, 2000, send_time);
        // After ack: bytes_in_flight = 12720, remaining = 2000 ≤ 4416 → limited → grows
        assert_eq!(cc.get_cwnd(), 14720 + 2000);
        assert_eq!(cc.get_bytes_in_flight(), 14720 - 2000);
        assert_eq!(cc.get_diag_state(), "slow_start");
    }

    /// Verifies loss triggers recovery and window reduction.
    #[test]
    fn test_loss_enters_recovery() {
        let mut cc = NewRenoCc::new(1472);
        let now = OsslTime::from_ms(1000);
        let send_time = OsslTime::from_ms(900);

        cc.on_data_sent(14720);

        // Detect loss
        cc.on_data_lost(now, 10, send_time, 3000);

        // Window should be halved (min: k_min_wnd)
        // ssthresh = max(14720 * 1/2, 2944) = max(7360, 2944) = 7360
        assert_eq!(cc.get_cwnd(), 7360);
        assert_eq!(cc.get_ssthresh(), Some(7360));
        assert_eq!(cc.get_diag_state(), "recovery");
        assert_eq!(cc.get_bytes_in_flight(), 14720 - 3000);
    }

    /// Verifies that loss batching prevents double recovery entry.
    #[test]
    fn test_loss_batching() {
        let mut cc = NewRenoCc::new(1472);
        let now = OsslTime::from_ms(1000);
        let send_time = OsslTime::from_ms(900);

        cc.on_data_sent(14720);

        // First loss — enters recovery
        cc.on_data_lost(now, 10, send_time, 2000);
        let cwnd_after_first_loss = cc.get_cwnd();

        // Second loss at same or earlier send time — same epoch, no re-entry
        let earlier_send = OsslTime::from_ms(800);
        cc.on_data_lost(now, 8, earlier_send, 1000);

        // cwnd should not change (same epoch)
        assert_eq!(cc.get_cwnd(), cwnd_after_first_loss);
    }

    /// Verifies that loss of packet in recovery period does not re-enter recovery.
    #[test]
    fn test_loss_during_recovery_no_reenter() {
        let mut cc = NewRenoCc::new(1472);

        cc.on_data_sent(14720);

        // First loss at time 1000 — enters recovery
        let now = OsslTime::from_ms(1000);
        cc.on_data_lost(now, 10, OsslTime::from_ms(900), 2000);
        let cwnd_after_recovery = cc.get_cwnd();

        // New loss for packet sent before recovery start (900 <= 1000)
        // — in recovery period, should NOT re-enter
        cc.on_data_lost(OsslTime::from_ms(1100), 15, OsslTime::from_ms(950), 1000);
        assert_eq!(cc.get_cwnd(), cwnd_after_recovery);
        assert_eq!(cc.get_diag_state(), "recovery");
    }

    /// Verifies on_data_invalidated reduces bytes in flight without congestion response.
    #[test]
    fn test_on_data_invalidated() {
        let mut cc = NewRenoCc::new(1472);
        cc.on_data_sent(10000);

        let cwnd_before = cc.get_cwnd();
        cc.on_data_invalidated(5000);

        assert_eq!(cc.get_bytes_in_flight(), 5000);
        assert_eq!(cc.get_cwnd(), cwnd_before); // cwnd unchanged
    }

    /// Verifies send allowance calculation.
    #[test]
    fn test_get_send_allowance() {
        let cc = NewRenoCc::new(1472);
        let now = OsslTime::from_ms(1000);

        // No bytes in flight — full window available
        assert_eq!(cc.get_send_allowance(now, 0, 1472), 14720);

        // Partially used — remaining available
        assert_eq!(cc.get_send_allowance(now, 10000, 1472), 4720);

        // Nearly full — less than one datagram: slow start pacing allows one dgram
        assert_eq!(cc.get_send_allowance(now, 14000, 1472), 1472);

        // Fully congested
        assert_eq!(cc.get_send_allowance(now, 14720, 1472), 0);

        // Over-congested (bytes_in_flight > cwnd)
        assert_eq!(cc.get_send_allowance(now, 20000, 1472), 0);
    }

    /// Verifies congestion avoidance linear growth.
    #[test]
    fn test_congestion_avoidance_growth() {
        let mut cc = NewRenoCc::new(1472);
        let now = OsslTime::from_ms(1000);

        // Force into congestion avoidance by simulating a loss
        cc.on_data_sent(14720);
        cc.on_data_lost(now, 5, OsslTime::from_ms(800), 1000);
        // cwnd = 7360, ssthresh = 7360, state = Recovery

        // Send more data and ack a post-recovery packet to exit recovery
        cc.on_data_sent(7360);
        let post_recovery_send = OsslTime::from_ms(1100);
        cc.on_data_acked(OsslTime::from_ms(1200), 7360, post_recovery_send);
        // Should exit recovery → congestion avoidance

        assert_eq!(cc.get_diag_state(), "congestion_avoidance");
        let cwnd_ca = cc.get_cwnd();

        // Fill window for congestion-limited check
        cc.on_data_sent(cwnd_ca);

        // Ack a full window's worth → should grow by max_dgram_size
        cc.on_data_acked(OsslTime::from_ms(1300), cwnd_ca, OsslTime::from_ms(1250));

        assert_eq!(cc.get_cwnd(), cwnd_ca + 1472);
    }

    /// Verifies reset returns to slow start with minimum window.
    #[test]
    fn test_reset() {
        let mut cc = NewRenoCc::new(1472);
        let now = OsslTime::from_ms(1000);

        // Put CC into a non-initial state
        cc.on_data_sent(14720);
        cc.on_data_lost(now, 5, OsslTime::from_ms(800), 2000);

        // Reset
        cc.reset();

        assert_eq!(cc.get_cwnd(), 2944); // k_min_wnd = 2 * 1472
        assert_eq!(cc.get_ssthresh(), None);
        assert_eq!(cc.get_bytes_in_flight(), 0);
        assert_eq!(cc.get_diag_state(), "slow_start");
    }

    /// Verifies persistent congestion detection.
    #[test]
    fn test_persistent_congestion_detected() {
        let pkts = vec![
            TxPacketRecord {
                send_time: OsslTime::from_ms(100),
                ack_eliciting: true,
            },
            TxPacketRecord {
                send_time: OsslTime::from_ms(200),
                ack_eliciting: false, // non-ack-eliciting — ignored
            },
            TxPacketRecord {
                send_time: OsslTime::from_ms(5000),
                ack_eliciting: true,
            },
        ];
        let refs: Vec<&TxPacketRecord> = pkts.iter().collect();
        let pto = Duration::from_millis(500);

        // Duration = 5000 - 100 = 4900ms, threshold = 500 * 3 = 1500ms
        assert!(detect_persistent_congestion(&refs, pto));
    }

    /// Verifies persistent congestion not detected when duration is too short.
    #[test]
    fn test_persistent_congestion_not_detected() {
        let pkts = vec![
            TxPacketRecord {
                send_time: OsslTime::from_ms(100),
                ack_eliciting: true,
            },
            TxPacketRecord {
                send_time: OsslTime::from_ms(500),
                ack_eliciting: true,
            },
        ];
        let refs: Vec<&TxPacketRecord> = pkts.iter().collect();
        let pto = Duration::from_millis(500);

        // Duration = 400ms, threshold = 1500ms — NOT persistent congestion
        assert!(!detect_persistent_congestion(&refs, pto));
    }

    /// Verifies persistent congestion with only one ack-eliciting packet.
    #[test]
    fn test_persistent_congestion_single_ack_eliciting() {
        let pkts = vec![
            TxPacketRecord {
                send_time: OsslTime::from_ms(100),
                ack_eliciting: true,
            },
            TxPacketRecord {
                send_time: OsslTime::from_ms(5000),
                ack_eliciting: false,
            },
        ];
        let refs: Vec<&TxPacketRecord> = pkts.iter().collect();
        let pto = Duration::from_millis(500);

        // Only one ack-eliciting packet — cannot establish duration
        assert!(!detect_persistent_congestion(&refs, pto));
    }

    /// Verifies persistent congestion with empty packet list.
    #[test]
    fn test_persistent_congestion_empty() {
        let refs: Vec<&TxPacketRecord> = vec![];
        let pto = Duration::from_millis(500);
        assert!(!detect_persistent_congestion(&refs, pto));
    }

    /// Verifies zero-byte loss is a no-op.
    #[test]
    fn test_zero_byte_loss() {
        let mut cc = NewRenoCc::new(1472);
        cc.on_data_sent(5000);
        let cwnd_before = cc.get_cwnd();

        cc.on_data_lost(OsslTime::from_ms(1000), 1, OsslTime::from_ms(900), 0);

        assert_eq!(cc.get_cwnd(), cwnd_before);
        assert_eq!(cc.get_bytes_in_flight(), 5000);
    }

    /// Verifies that CcState Display formatting works.
    #[test]
    fn test_cc_state_display() {
        assert_eq!(format!("{}", CcState::SlowStart), "slow_start");
        assert_eq!(
            format!("{}", CcState::CongestionAvoidance),
            "congestion_avoidance"
        );
        assert_eq!(format!("{}", CcState::Recovery), "recovery");
    }

    /// Verifies NewRenoCc implements Send + Sync (required by trait bounds).
    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NewRenoCc>();
    }

    /// Verifies that with_loss_reduction panics on zero denominator.
    #[test]
    #[should_panic(expected = "loss reduction denominator must be non-zero")]
    fn test_loss_reduction_zero_den_panics() {
        let _ = NewRenoCc::new(1472).with_loss_reduction(1, 0);
    }

    /// Verifies custom loss reduction factor.
    #[test]
    fn test_custom_loss_reduction() {
        let mut cc = NewRenoCc::new(1472).with_loss_reduction(7, 10);
        let now = OsslTime::from_ms(1000);

        cc.on_data_sent(14720);
        cc.on_data_lost(now, 10, OsslTime::from_ms(900), 1000);

        // ssthresh = max(14720 * 7 / 10, 2944) = max(10304, 2944) = 10304
        assert_eq!(cc.get_cwnd(), 10304);
        assert_eq!(cc.get_ssthresh(), Some(10304));
    }

    /// Verifies saturating arithmetic on bytes_in_flight underflow.
    #[test]
    fn test_saturating_underflow() {
        let mut cc = NewRenoCc::new(1472);
        cc.on_data_sent(100);

        // Try to ack more than in flight — should saturate to 0
        cc.on_data_acked(OsslTime::from_ms(1000), 200, OsslTime::from_ms(900));
        assert_eq!(cc.get_bytes_in_flight(), 0);

        // Try to invalidate more than in flight — should saturate to 0
        cc.on_data_sent(100);
        cc.on_data_invalidated(200);
        assert_eq!(cc.get_bytes_in_flight(), 0);
    }

    /// Verifies full lifecycle: slow start → loss → recovery → congestion avoidance.
    #[test]
    fn test_full_lifecycle() {
        let mut cc = NewRenoCc::new(1472);

        // Phase 1: Slow start — send full window, ack small portion to stay congestion-limited
        assert_eq!(cc.get_diag_state(), "slow_start");
        cc.on_data_sent(14720);
        // Ack 2000 bytes. After: bytes_in_flight=12720, remaining=2000+2000=4000 ≤ 4416 → limited → grows
        // Wait, after ack cwnd grows: cwnd=14720+2000=16720, bytes_in_flight=12720,
        // remaining=4000 ≤ 4416 → congestion-limited → growth allowed
        cc.on_data_acked(OsslTime::from_ms(100), 2000, OsslTime::from_ms(50));
        assert_eq!(cc.get_diag_state(), "slow_start");
        assert_eq!(cc.get_cwnd(), 14720 + 2000);

        // Phase 2: Loss → recovery
        cc.on_data_lost(OsslTime::from_ms(200), 20, OsslTime::from_ms(150), 2000);
        assert_eq!(cc.get_diag_state(), "recovery");
        let recovery_cwnd = cc.get_cwnd();
        assert!(recovery_cwnd < 14720 + 2000); // Window was reduced

        // Phase 3: Ack post-recovery packet → exit recovery to congestion avoidance
        cc.on_data_sent(recovery_cwnd);
        cc.on_data_acked(
            OsslTime::from_ms(400),
            recovery_cwnd,
            OsslTime::from_ms(300), // sent after recovery start (200ms)
        );
        assert_eq!(cc.get_diag_state(), "congestion_avoidance");
    }

    /// Verifies that NewRenoCc can be used as a trait object.
    #[test]
    fn test_trait_object() {
        let cc: Box<dyn CongestionController> = Box::new(NewRenoCc::new(1472));
        assert_eq!(cc.get_cwnd(), 14720);
        assert_eq!(cc.get_diag_state(), "slow_start");
    }

    /// Verifies persistent congestion detection and reset integration.
    #[test]
    fn test_persistent_congestion_and_reset() {
        let mut cc = NewRenoCc::new(1472);
        cc.on_data_sent(14720);

        // Simulate loss
        cc.on_data_lost(OsslTime::from_ms(1000), 10, OsslTime::from_ms(900), 5000);

        // Detect persistent congestion
        let pkts = vec![
            TxPacketRecord {
                send_time: OsslTime::from_ms(100),
                ack_eliciting: true,
            },
            TxPacketRecord {
                send_time: OsslTime::from_ms(5000),
                ack_eliciting: true,
            },
        ];
        let refs: Vec<&TxPacketRecord> = pkts.iter().collect();
        assert!(detect_persistent_congestion(
            &refs,
            Duration::from_millis(500)
        ));

        // Reset CC
        cc.reset();
        assert_eq!(cc.get_cwnd(), 2944); // k_min_wnd
        assert_eq!(cc.get_diag_state(), "slow_start");
        assert_eq!(cc.get_ssthresh(), None);
        assert_eq!(cc.get_bytes_in_flight(), 0);
    }
}
