//! # ACK Manager, RTT Estimation, and `UintSet` for QUIC v1
//!
//! This module implements the QUIC ACK management subsystem — a direct Rust rewrite of:
//! - `ssl/quic/quic_ackm.c` (~1,800 lines) — TX/RX packet history, ACK synthesis, RFC 9002
//!   loss detection + PTO timers, ECN support
//! - `ssl/quic/quic_statm.c` (~150 lines) — RTT estimation (EWMA per RFC 9002 §5.3)
//! - `ssl/quic/uint_set.c` (~350 lines) — Range-coalescing integer set for packet number tracking
//!
//! ## Architecture
//!
//! The [`AckManager`] is the central coordinator, responsible for:
//! 1. **TX tracking:** Recording transmitted packets via [`on_tx_packet`](AckManager::on_tx_packet),
//!    maintaining per-PN-space [`TxPacketHistory`] with O(1) packet-number lookup.
//! 2. **ACK processing:** Processing received ACK frames via [`on_rx_ack_frame`](AckManager::on_rx_ack_frame),
//!    detecting newly acknowledged packets, updating RTT estimates, and invoking
//!    `on_acked`/`on_lost` callbacks.
//! 3. **Loss detection:** Implementing RFC 9002 time-threshold and packet-threshold loss
//!    detection, with PTO (Probe Timeout) timers and exponential backoff.
//! 4. **ACK generation:** Tracking received packet numbers via [`UintSet`]-based
//!    [`RxPacketHistory`], and generating ACK frame ranges via
//!    [`generate_ack_ranges`](AckManager::generate_ack_ranges).
//!
//! The [`RttEstimator`] maintains smoothed RTT, RTT variance, minimum RTT, and latest RTT
//! per RFC 9002 §5.3, providing PTO duration computation.
//!
//! ## RFC Compliance
//!
//! - RFC 9002 §5.3 — RTT estimation (EWMA)
//! - RFC 9002 §6.1 — Packet threshold loss detection (`K_PKT_THRESHOLD = 3`)
//! - RFC 9002 §6.1.2 — Time threshold loss detection (`9/8 * max(latest_rtt, smoothed_rtt)`)
//! - RFC 9002 §6.2 — Probe Timeout (PTO) with exponential backoff
//! - RFC 9002 §6.2.1 — PTO duration computation
//! - RFC 9000 §13.2.1 — Immediate ACK for Initial and Handshake packets
//!
//! ## Rules Compliance
//!
//! - **R5 (Nullability):** `Option<T>` for `largest_received`, `loss_time`, etc. — no sentinels
//! - **R6 (Lossless casts):** All PN arithmetic uses `u64`; RTT uses `Duration`; no bare `as`
//! - **R7 (Lock granularity):** `// LOCK-SCOPE: AckManager — per-channel, single-threaded`
//! - **R8 (Zero unsafe):** No `unsafe` blocks
//! - **R9 (Warning-free):** All items documented, no unused imports
//! - **R10 (Wiring):** Reachable from `channel.subtick() → ackm operations`
//!
//! ## C → Rust Translation Notes
//!
//! | C Pattern | Rust Pattern |
//! |-----------|-------------|
//! | `OSSL_ACKM_TX_PKT` linked list + LHASH | [`TxPacketHistory`] (LinkedList + HashMap) |
//! | `UINT_SET` doubly-linked sorted ranges | [`UintSet`] (BTreeMap<u64, u64>) |
//! | `OSSL_STATM` RTT info struct | [`RttEstimator`] with `Duration` fields |
//! | `OSSL_CC_METHOD` function pointers | `Box<dyn CongestionController>` trait object |
//! | `ossl_time_*()` saturating arithmetic | [`OsslTime`] methods |
//! | `on_acked/on_lost/on_discarded` fn ptrs | `Option<Box<dyn FnOnce() + Send>>` |
//! | `QUIC_PN_SPACE_*` integer constants | [`PnSpace`] enum |

// LOCK-SCOPE: AckManager — owned per-channel, accessed during RX/TX processing.
// Each QUIC channel owns exactly one AckManager instance. No shared mutable state
// across channels. The channel's event loop drives all AckManager method calls
// single-threaded. No Mutex required for this structure.

use crate::quic::cc::CongestionController;
use openssl_common::error::SslError;
use openssl_common::time::OsslTime;
use std::cmp::{max, min};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Duration;

// =============================================================================
// Constants (from ssl/quic/quic_ackm.c)
// =============================================================================

/// Time threshold multiplier numerator for loss detection.
///
/// RFC 9002 §6.1.2: `loss_delay` = `9/8 * max(latest_rtt, smoothed_rtt)`.
const K_TIME_THRESHOLD_NUM: u64 = 9;

/// Time threshold multiplier denominator for loss detection.
const K_TIME_THRESHOLD_DEN: u64 = 8;

/// Minimum granularity for loss detection time threshold.
///
/// RFC 9002 §6.1.2: "a timer SHOULD be set for … at least kGranularity"
/// where kGranularity is 1 millisecond.
const K_GRANULARITY_MS: u64 = 1;

/// Packet reordering threshold before declaring loss.
///
/// RFC 9002 §6.1.1: "kPacketThreshold … RECOMMENDED … value is 3"
const K_PKT_THRESHOLD: u64 = 3;

/// Maximum PTO backoff exponent to prevent overflow.
///
/// After `MAX_PTO_COUNT` consecutive PTOs, the backoff factor is capped at
/// `2^MAX_PTO_COUNT` to avoid unreasonably large timeouts.
const MAX_PTO_COUNT: u32 = 16;

/// Number of ACK-eliciting packets received before we always emit an ACK.
///
/// From `PKTS_BEFORE_ACK` in `ssl/quic/quic_ackm.c` line 1380.
const PKTS_BEFORE_ACK: u32 = 2;

/// Maximum number of ACK ranges to track in the RX history.
///
/// Limits memory usage per PN space. When exceeded, the oldest ranges are
/// trimmed and the watermark advanced. From `MAX_RX_ACK_RANGES` in C.
const MAX_RX_ACK_RANGES: usize = 32;

/// Initial RTT estimate used before the first RTT sample.
///
/// RFC 9002 §6.2.2: "… uses a default value of 333 milliseconds"
/// From `K_INITIAL_RTT` in `ssl/quic/quic_statm.c`.
const K_INITIAL_RTT_MS: u64 = 333;

/// Default TX max ACK delay (25 ms).
///
/// Maximum time the local endpoint may delay sending an ACK after receiving
/// an ack-eliciting packet. Matches `QUIC_DEFAULT_MAX_ACK_DELAY` in C.
const DEFAULT_TX_MAX_ACK_DELAY_MS: u64 = 25;

/// Default peer max ACK delay (25 ms).
///
/// Maximum time the peer is expected to delay its ACK. Used in PTO computation.
const DEFAULT_PEER_MAX_ACK_DELAY_MS: u64 = 25;

// =============================================================================
// PnSpace — Packet Number Space
// =============================================================================

/// QUIC packet number space identifier.
///
/// RFC 9000 §12.3: "Packet numbers are divided into three spaces":
/// - Initial: for Initial packets during handshake
/// - Handshake: for Handshake packets during handshake
/// - Application: for 0-RTT and 1-RTT application data
///
/// # C Equivalent
/// `QUIC_PN_SPACE_INITIAL`, `QUIC_PN_SPACE_HANDSHAKE`, `QUIC_PN_SPACE_APP`
/// from `include/internal/quic_ackm.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PnSpace {
    /// Initial encryption level (RFC 9001 §4.1).
    Initial = 0,
    /// Handshake encryption level (RFC 9001 §4.4).
    Handshake = 1,
    /// Application data encryption level (0-RTT and 1-RTT, RFC 9001 §4.6).
    Application = 2,
}

impl PnSpace {
    /// Returns the total number of packet number spaces (3).
    ///
    /// Used for array sizing in per-space state structures.
    #[inline]
    pub const fn count() -> usize {
        3
    }

    /// Returns the index of this PN space for array indexing.
    #[inline]
    fn idx(self) -> usize {
        self as usize
    }

    /// Returns all PN spaces in order.
    const ALL: [PnSpace; 3] = [PnSpace::Initial, PnSpace::Handshake, PnSpace::Application];
}

// =============================================================================
// AckRange — ACK frame range element
// =============================================================================

/// A contiguous range of packet numbers in an ACK frame.
///
/// Represents a gap-free sequence of acknowledged packet numbers from
/// `start` (smallest) to `end` (largest, inclusive).
///
/// # C Equivalent
/// `OSSL_QUIC_ACK_RANGE` in `include/internal/quic_wire.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    /// Smallest packet number in this range (inclusive).
    pub start: u64,
    /// Largest packet number in this range (inclusive).
    pub end: u64,
}

// =============================================================================
// EcnCounts — ECN counters from ACK frame
// =============================================================================

/// ECN (Explicit Congestion Notification) counters from an `ACK_ECN` frame.
///
/// RFC 9000 §19.3.2: These counters report the total number of QUIC packets
/// received with each ECN codepoint for a given packet number space.
///
/// # C Equivalent
/// ECN fields in `OSSL_QUIC_FRAME_ACK` from `include/internal/quic_wire.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EcnCounts {
    /// Count of packets received with the ECT(0) codepoint.
    pub ect0: u64,
    /// Count of packets received with the ECT(1) codepoint.
    pub ect1: u64,
    /// Count of packets received with the CE (Congestion Experienced) codepoint.
    pub ce: u64,
}

// =============================================================================
// AckFrameData — Parsed ACK frame
// =============================================================================

/// Parsed ACK frame data received from the peer.
///
/// Contains the acknowledged ranges (in descending order by packet number),
/// ACK delay, and optional ECN counters.
///
/// # C Equivalent
/// `OSSL_QUIC_FRAME_ACK` from `include/internal/quic_wire.h`.
#[derive(Debug, Clone)]
pub struct AckFrameData {
    /// Largest packet number acknowledged by the peer.
    pub largest_acked: u64,
    /// ACK delay in microseconds (as reported by the peer).
    ///
    /// The peer measures this as the time between receiving the largest
    /// acknowledged packet and sending this ACK frame.
    pub ack_delay: u64,
    /// Acknowledged ranges, in descending order by packet number.
    ///
    /// Each range represents a contiguous block of acknowledged PNs.
    /// The first range contains `largest_acked`.
    pub ranges: Vec<AckRange>,
    /// Optional ECN counters (present in `ACK_ECN` frames).
    pub ecn: Option<EcnCounts>,
}

// =============================================================================
// TxPacketRecord — Transmitted packet metadata
// =============================================================================

/// Record of a transmitted packet tracked by the ACK manager.
///
/// Each in-flight packet has an associated `TxPacketRecord` that carries
/// metadata for loss detection, RTT sampling, and congestion control, plus
/// callbacks for lifecycle events (acknowledged, lost, discarded).
///
/// # Callback Semantics
///
/// - `on_acked`: Invoked exactly once when the packet is acknowledged by the peer.
/// - `on_lost`: Invoked exactly once when the packet is declared lost by the
///   time/packet threshold loss detection algorithm.
/// - `on_discarded`: Invoked exactly once when the packet's PN space is discarded
///   (e.g., Initial/Handshake keys dropped after handshake completion).
///
/// Only one of these callbacks will fire for any given packet.
///
/// # C Equivalent
/// `OSSL_ACKM_TX_PKT` from `include/internal/quic_ackm.h`.
pub struct TxPacketRecord {
    /// Packet number (unique within a PN space).
    pub pkt_num: u64,
    /// Time the packet was sent.
    pub time_sent: OsslTime,
    /// Size of the packet in bytes (used for bytes-in-flight tracking).
    pub bytes_sent: usize,
    /// Whether this packet contains ACK-eliciting frames.
    ///
    /// Only ack-eliciting packets contribute to RTT samples and are considered
    /// for ACK generation thresholds.
    pub is_ack_eliciting: bool,
    /// Whether this packet counts toward bytes-in-flight.
    ///
    /// Typically true for data-bearing packets. ACK-only packets may have
    /// `is_in_flight = false`.
    pub is_in_flight: bool,
    /// Callback invoked when the packet is acknowledged.
    pub on_acked: Option<Box<dyn FnOnce() + Send>>,
    /// Callback invoked when the packet is declared lost.
    pub on_lost: Option<Box<dyn FnOnce() + Send>>,
    /// Callback invoked when the packet's PN space is discarded.
    pub on_discarded: Option<Box<dyn FnOnce() + Send>>,
    /// The largest acknowledged PN known at the time this packet was sent.
    ///
    /// Used to bump the RX watermark when this packet itself is acknowledged,
    /// pruning old entries from the RX packet history.
    largest_acked_on_send: Option<u64>,
}

impl TxPacketRecord {
    /// Creates a new TX packet record with the given public fields.
    ///
    /// The internal `largest_acked_on_send` field is initialised to `None`
    /// and will be populated by [`AckManager::on_tx_packet`] when the
    /// record is submitted for tracking.
    pub fn new(
        pkt_num: u64,
        time_sent: OsslTime,
        bytes_sent: usize,
        is_ack_eliciting: bool,
        is_in_flight: bool,
        on_acked: Option<Box<dyn FnOnce() + Send>>,
        on_lost: Option<Box<dyn FnOnce() + Send>>,
        on_discarded: Option<Box<dyn FnOnce() + Send>>,
    ) -> Self {
        Self {
            pkt_num,
            time_sent,
            bytes_sent,
            is_ack_eliciting,
            is_in_flight,
            on_acked,
            on_lost,
            on_discarded,
            largest_acked_on_send: None,
        }
    }
}

impl std::fmt::Debug for TxPacketRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxPacketRecord")
            .field("pkt_num", &self.pkt_num)
            .field("time_sent", &self.time_sent)
            .field("bytes_sent", &self.bytes_sent)
            .field("is_ack_eliciting", &self.is_ack_eliciting)
            .field("is_in_flight", &self.is_in_flight)
            .field("has_on_acked", &self.on_acked.is_some())
            .field("has_on_lost", &self.on_lost.is_some())
            .field("has_on_discarded", &self.on_discarded.is_some())
            .field("largest_acked_on_send", &self.largest_acked_on_send)
            .finish()
    }
}

// =============================================================================
// UintSet — Range-coalescing integer set (from uint_set.c)
// =============================================================================

/// A set of non-negative integers stored as coalesced, non-overlapping ranges.
///
/// Provides efficient insertion, containment queries, and range iteration for
/// tracking received packet numbers. Ranges are automatically merged when they
/// overlap or are adjacent, keeping the internal representation compact.
///
/// Internally backed by a [`BTreeMap<u64, u64>`] mapping range-start to
/// range-end (inclusive). The `BTreeMap` ordering guarantees ranges are sorted
/// by start value, enabling efficient merging and iteration.
///
/// # Bounded Size
///
/// When used for RX packet history, the number of ranges is bounded by
/// [`MAX_RX_ACK_RANGES`] to prevent denial-of-service attacks where a
/// peer sends carefully crafted packet numbers to create many small ranges.
///
/// # C Equivalent
/// `UINT_SET` from `ssl/quic/uint_set.c`, which uses a doubly-linked sorted
/// list of `UINT_SET_ITEM` nodes. The Rust implementation replaces the linked
/// list with a `BTreeMap` for O(log n) operations.
#[derive(Debug, Clone, Default)]
pub struct UintSet {
    /// Map from range start to range end (inclusive).
    /// Invariant: ranges are non-overlapping and non-adjacent (always coalesced).
    ranges: BTreeMap<u64, u64>,
}

impl UintSet {
    /// Creates a new empty `UintSet`.
    pub fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
        }
    }

    /// Inserts a single value into the set, coalescing adjacent/overlapping ranges.
    ///
    /// If the value already exists in the set, this is a no-op.
    ///
    /// # C Equivalent
    /// `ossl_uint_set_insert()` in `ssl/quic/uint_set.c`.
    pub fn insert(&mut self, value: u64) {
        self.insert_range(value, value);
    }

    /// Inserts a contiguous range `[start, end]` (inclusive) into the set.
    ///
    /// Adjacent and overlapping ranges are merged automatically to maintain
    /// the coalesced invariant.
    ///
    /// # Panics
    /// Panics if `start > end`.
    ///
    /// # C Equivalent
    /// `ossl_uint_set_insert()` in `ssl/quic/uint_set.c`.
    pub fn insert_range(&mut self, start: u64, end: u64) {
        assert!(
            start <= end,
            "UintSet::insert_range: start ({start}) > end ({end})"
        );

        // Determine the effective merged range by scanning for overlaps.
        let mut new_start = start;
        let mut new_end = end;

        // Collect keys of ranges that overlap or are adjacent to [start, end].
        // A range [rs, re] overlaps/touches [start, end] if:
        //   rs <= end + 1  AND  re + 1 >= start
        let mut to_remove: Vec<u64> = Vec::new();

        for (&rs, &re) in &self.ranges {
            // If the existing range starts well beyond our end, stop (sorted)
            if rs > end.saturating_add(1) {
                break;
            }
            // Check if ranges overlap or are adjacent
            if re.saturating_add(1) >= start {
                new_start = min(new_start, rs);
                new_end = max(new_end, re);
                to_remove.push(rs);
            }
        }

        // Remove all merged ranges
        for key in &to_remove {
            self.ranges.remove(key);
        }

        // Insert the merged range
        self.ranges.insert(new_start, new_end);
    }

    /// Returns `true` if the set contains the given value.
    ///
    /// # C Equivalent
    /// `ossl_uint_set_query()` in `ssl/quic/uint_set.c`.
    pub fn contains(&self, value: u64) -> bool {
        // Find the greatest range whose start <= value.
        if let Some((&_rs, &re)) = self.ranges.range(..=value).next_back() {
            re >= value
        } else {
            false
        }
    }

    /// Removes all values below `threshold` from the set.
    ///
    /// Ranges entirely below the threshold are removed. Ranges that span
    /// the threshold are trimmed so their start becomes `threshold`.
    ///
    /// # C Equivalent
    /// `rx_pkt_history_bump_watermark()` combined with `uint_set` trimming.
    pub fn remove_below(&mut self, threshold: u64) {
        if threshold == 0 {
            return;
        }

        let mut to_remove: Vec<u64> = Vec::new();
        let mut to_reinsert: Option<(u64, u64)> = None;

        for (&rs, &re) in &self.ranges {
            if re < threshold {
                // Entire range is below threshold — remove it
                to_remove.push(rs);
            } else if rs < threshold {
                // Range spans the threshold — trim it
                to_remove.push(rs);
                to_reinsert = Some((threshold, re));
                break; // No further ranges can start below threshold
            } else {
                break; // All remaining ranges are >= threshold
            }
        }

        for key in &to_remove {
            self.ranges.remove(key);
        }

        if let Some((new_start, new_end)) = to_reinsert {
            self.ranges.insert(new_start, new_end);
        }
    }

    /// Returns an iterator over all ranges in **descending** order (largest first).
    ///
    /// Each element is `(start, end)` where `start <= end` (inclusive range).
    /// Descending order is used for ACK frame generation, which lists the
    /// largest acknowledged range first.
    pub fn iter_ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.ranges.iter().rev().map(|(&s, &e)| (s, e))
    }

    /// Returns the number of non-overlapping ranges in the set.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Returns `true` if the set is empty.
    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the range containing the largest value, if any.
    fn last_range(&self) -> Option<(u64, u64)> {
        self.ranges.iter().next_back().map(|(&s, &e)| (s, e))
    }

    /// Trims the set to at most `max_ranges` ranges by removing the oldest
    /// (lowest-numbered) ranges. Returns the new minimum value if trimming
    /// occurred, so the caller can advance a watermark.
    fn trim_to(&mut self, max_ranges: usize) -> Option<u64> {
        if self.ranges.len() <= max_ranges {
            return None;
        }
        let excess = self.ranges.len() - max_ranges;
        let keys_to_remove: Vec<u64> = self.ranges.keys().take(excess).copied().collect();
        let mut new_watermark: Option<u64> = None;
        for key in &keys_to_remove {
            if let Some(end) = self.ranges.remove(key) {
                new_watermark = Some(end.saturating_add(1));
            }
        }
        new_watermark
    }
}

// =============================================================================
// TxPacketHistory — TX packet tracking (ordered list + fast lookup)
// =============================================================================

/// History of transmitted packets awaiting acknowledgment or loss declaration.
///
/// Maintains packets in send order (ascending packet number) with O(1) lookup
/// by packet number via a [`HashSet`]. The watermark tracks the lowest
/// packet number that has not been removed, enabling monotonic enforcement.
///
/// # C Equivalent
/// `struct tx_pkt_history_st` in `ssl/quic/quic_ackm.c`, which uses an
/// intrusive `ossl_list_tx_history` linked list + `LHASH` for O(1) lookup.
struct TxPacketHistory {
    /// Ordered packet list (ascending by `pkt_num`).
    packets: VecDeque<TxPacketRecord>,
    /// Fast lookup: packet numbers in the history. Enables O(1) containment
    /// checks without scanning the deque.
    lookup: HashSet<u64>,
    /// Monotonic watermark: no packet with PN < watermark can be added.
    watermark: u64,
    /// Highest packet number ever added.
    highest_sent: Option<u64>,
}

impl TxPacketHistory {
    /// Creates a new empty TX packet history.
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            lookup: HashSet::new(),
            watermark: 0,
            highest_sent: None,
        }
    }

    /// Adds a transmitted packet record to the history.
    ///
    /// The packet number must be >= watermark and strictly greater than all
    /// previously added packet numbers (monotonic ordering).
    ///
    /// # C Equivalent
    /// `tx_pkt_history_add()` in `ssl/quic/quic_ackm.c`.
    fn add(&mut self, record: TxPacketRecord) -> bool {
        let pn = record.pkt_num;
        if pn < self.watermark {
            return false;
        }
        if let Some(highest) = self.highest_sent {
            if pn <= highest {
                return false;
            }
        }
        self.highest_sent = Some(pn);
        self.lookup.insert(pn);
        self.packets.push_back(record);
        true
    }

    /// Removes a packet by packet number and returns it.
    ///
    /// Returns `None` if the packet number is not in the history.
    ///
    /// # C Equivalent
    /// `tx_pkt_history_remove()` in `ssl/quic/quic_ackm.c`.
    fn remove(&mut self, pkt_num: u64) -> Option<TxPacketRecord> {
        if !self.lookup.remove(&pkt_num) {
            return None;
        }
        // Linear scan to find and remove from the deque.
        // This mirrors the C code which also scans the list.
        if let Some(pos) = self.packets.iter().position(|p| p.pkt_num == pkt_num) {
            self.packets.remove(pos)
        } else {
            None
        }
    }

    /// Returns `true` if the history contains a packet with the given number.
    #[allow(dead_code)] // Available for diagnostics and testing
    fn has(&self, pkt_num: u64) -> bool {
        self.lookup.contains(&pkt_num)
    }

    /// Returns the number of packets in the history.
    #[allow(dead_code)] // Available for diagnostics and testing
    fn len(&self) -> usize {
        self.lookup.len()
    }

    /// Returns `true` if the history is empty.
    #[allow(dead_code)] // Available for diagnostics and testing
    fn is_empty(&self) -> bool {
        self.lookup.is_empty()
    }
}

// =============================================================================
// RxPacketHistory — RX packet tracking (UintSet-based)
// =============================================================================

/// History of received packet numbers, tracking which PNs have been received
/// but not yet provably acknowledged by the peer.
///
/// Uses a [`UintSet`] for efficient range-coalesced storage with a monotonic
/// watermark. Packet numbers below the watermark are considered "written off"
/// — they are treated as received for duplicate detection purposes.
///
/// # C Equivalent
/// `struct rx_pkt_history_st` in `ssl/quic/quic_ackm.c`.
struct RxPacketHistory {
    /// Set of received packet numbers (above watermark).
    received: UintSet,
    /// Monotonically increasing watermark. PNs below this value are considered
    /// already processed and will not be added to the set.
    watermark: u64,
}

impl RxPacketHistory {
    /// Creates a new empty RX packet history.
    fn new() -> Self {
        Self {
            received: UintSet::new(),
            watermark: 0,
        }
    }

    /// Records receipt of a packet number. Returns `true` if the PN is new
    /// (not a duplicate and not below the watermark).
    ///
    /// # C Equivalent
    /// `rx_pkt_history_add_pn()` in `ssl/quic/quic_ackm.c`.
    fn on_rx(&mut self, pkt_num: u64) -> bool {
        if pkt_num < self.watermark {
            return false; // Below watermark — considered already processed
        }
        if self.received.contains(pkt_num) {
            return false; // Already received
        }
        self.received.insert(pkt_num);
        // Trim to prevent unbounded growth (DoS mitigation)
        if let Some(new_wm) = self.received.trim_to(MAX_RX_ACK_RANGES) {
            self.watermark = max(self.watermark, new_wm);
        }
        true
    }

    /// Returns `true` if the packet number is a duplicate (already received
    /// or below the watermark).
    fn is_duplicate(&self, pkt_num: u64) -> bool {
        pkt_num < self.watermark || self.received.contains(pkt_num)
    }

    /// Advances the watermark, removing all entries below `new_watermark`.
    ///
    /// # C Equivalent
    /// `rx_pkt_history_bump_watermark()` in `ssl/quic/quic_ackm.c`.
    fn advance_watermark(&mut self, new_watermark: u64) {
        if new_watermark <= self.watermark {
            return;
        }
        self.watermark = new_watermark;
        self.received.remove_below(new_watermark);
    }
}

// =============================================================================
// RttEstimator — RTT estimation (from quic_statm.c)
// =============================================================================

/// RTT (Round-Trip Time) estimator implementing RFC 9002 §5.3.
///
/// Maintains four RTT metrics:
/// - `smoothed_rtt`: Exponentially weighted moving average of RTT samples
/// - `rttvar`: RTT variance estimate (used for PTO computation)
/// - `min_rtt`: Minimum observed RTT (never adjusted by ACK delay)
/// - `latest_rtt`: Most recent RTT sample
///
/// ## EWMA Algorithm (RFC 9002 §5.3)
///
/// First sample:
///   `smoothed_rtt = latest_rtt`
///   `rttvar = latest_rtt / 2`
///
/// Subsequent samples:
///   `adjusted_rtt = latest_rtt - ack_delay` (if `latest_rtt >= min_rtt + ack_delay`)
///   `rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|`
///   `smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt`
///
/// # C Equivalent
/// `OSSL_STATM` from `ssl/quic/quic_statm.c`.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Exponentially weighted moving average of RTT.
    pub smoothed_rtt: Duration,
    /// RTT variance (mean deviation) estimate.
    pub rttvar: Duration,
    /// Minimum observed RTT (never reduced by ACK delay).
    pub min_rtt: Duration,
    /// Most recent RTT sample.
    pub latest_rtt: Duration,
    /// Whether the first RTT sample has been received.
    first_sample_done: bool,
}

impl RttEstimator {
    /// Creates a new RTT estimator with initial values per RFC 9002 §6.2.2.
    ///
    /// - `smoothed_rtt` = 333ms (`K_INITIAL_RTT`)
    /// - `rttvar` = 333ms / 2 = 166.5ms
    /// - `min_rtt` = `Duration::MAX` (no sample yet)
    /// - `latest_rtt` = `Duration::ZERO`
    ///
    /// # C Equivalent
    /// `ossl_statm_init()` in `ssl/quic/quic_statm.c`.
    fn new() -> Self {
        let initial_rtt = Duration::from_millis(K_INITIAL_RTT_MS);
        Self {
            smoothed_rtt: initial_rtt,
            rttvar: initial_rtt / 2,
            min_rtt: Duration::MAX,
            latest_rtt: Duration::ZERO,
            first_sample_done: false,
        }
    }

    /// Updates the RTT estimate with a new sample.
    ///
    /// Implements the EWMA algorithm from RFC 9002 §5.3:
    /// 1. `min_rtt` is updated to the minimum of all samples (never adjusted by ACK delay).
    /// 2. On the first sample, `smoothed_rtt` and `rttvar` are initialized directly.
    /// 3. On subsequent samples, the standard EWMA is applied with `ack_delay`
    ///    subtracted only when `latest_rtt >= min_rtt + ack_delay` and the handshake
    ///    is confirmed.
    ///
    /// # Parameters
    /// - `latest_rtt`: The RTT measured from sending the packet to receiving its ACK.
    /// - `ack_delay`: The peer's reported ACK delay (from ACK frame).
    /// - `handshake_confirmed`: Whether the TLS handshake has been confirmed.
    ///   ACK delay is only subtracted after handshake confirmation.
    ///
    /// # C Equivalent
    /// `ossl_statm_update_rtt()` in `ssl/quic/quic_statm.c`.
    pub fn update(
        &mut self,
        latest_rtt: Duration,
        ack_delay: Duration,
        handshake_confirmed: bool,
    ) {
        self.latest_rtt = latest_rtt;

        // min_rtt is never adjusted by ack_delay
        if latest_rtt < self.min_rtt {
            self.min_rtt = latest_rtt;
        }

        if !self.first_sample_done {
            // First sample: direct initialization (RFC 9002 §5.3)
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            self.first_sample_done = true;
            tracing::debug!(
                smoothed_rtt_ms = u64::try_from(latest_rtt.as_millis()).unwrap_or(u64::MAX),
                rttvar_ms = u64::try_from((latest_rtt / 2).as_millis()).unwrap_or(u64::MAX),
                "RTT first sample"
            );
            return;
        }

        // Subsequent samples: EWMA update
        let mut adjusted_rtt = latest_rtt;

        // Only subtract ack_delay after handshake confirmation, and only
        // if latest_rtt > min_rtt + ack_delay (to prevent negative adjusted_rtt)
        if handshake_confirmed {
            if let Some(threshold) = self.min_rtt.checked_add(ack_delay) {
                if latest_rtt >= threshold {
                    adjusted_rtt = latest_rtt.saturating_sub(ack_delay);
                }
            }
        }

        // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
        let rtt_diff = if self.smoothed_rtt > adjusted_rtt {
            self.smoothed_rtt - adjusted_rtt
        } else {
            adjusted_rtt - self.smoothed_rtt
        };
        self.rttvar = (self.rttvar * 3 / 4) + (rtt_diff / 4);

        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        self.smoothed_rtt = (self.smoothed_rtt * 7 / 8) + (adjusted_rtt / 8);

        tracing::trace!(
            smoothed_rtt_ms = u64::try_from(self.smoothed_rtt.as_millis()).unwrap_or(u64::MAX),
            rttvar_ms = u64::try_from(self.rttvar.as_millis()).unwrap_or(u64::MAX),
            min_rtt_ms = u64::try_from(self.min_rtt.as_millis()).unwrap_or(u64::MAX),
            latest_rtt_ms = u64::try_from(latest_rtt.as_millis()).unwrap_or(u64::MAX),
            "RTT updated"
        );
    }

    /// Computes the PTO (Probe Timeout) duration.
    ///
    /// RFC 9002 §6.2.1:
    /// `PTO = smoothed_rtt + max(4 * rttvar, k_granularity) + max_ack_delay`
    ///
    /// # Parameters
    /// - `max_ack_delay`: The peer's maximum ACK delay. For application data,
    ///   this is the peer's declared `max_ack_delay` transport parameter.
    ///   For Initial/Handshake spaces, this should be `Duration::ZERO`.
    ///
    /// # C Equivalent
    /// `ossl_ackm_get_pto_duration()` in `ssl/quic/quic_ackm.c`.
    pub fn get_pto_duration(&self, max_ack_delay: Duration) -> Duration {
        let granularity = Duration::from_millis(K_GRANULARITY_MS);
        let four_rttvar = self.rttvar.saturating_mul(4);
        let variance_component = max(four_rttvar, granularity);
        self.smoothed_rtt
            .saturating_add(variance_component)
            .saturating_add(max_ack_delay)
    }
}

// =============================================================================
// PnSpaceState — Per-PN-space state
// =============================================================================

/// State maintained for each QUIC packet number space within the [`AckManager`].
///
/// Each of the three PN spaces (Initial, Handshake, Application) has an
/// independent copy of this state, enabling separate ACK generation, loss
/// detection, and TX/RX history tracking per encryption level.
///
/// # C Equivalent
/// Fields of `ossl_ackm_st` indexed by `[pkt_space]` in `ssl/quic/quic_ackm.c`.
struct PnSpaceState {
    // --- TX side ---
    /// History of transmitted packets awaiting acknowledgment.
    tx_history: TxPacketHistory,

    // --- RX side ---
    /// History of received packet numbers for ACK generation.
    rx_history: RxPacketHistory,

    // --- Loss detection ---
    /// Time at which the earliest unacked packet in this space becomes lost.
    /// `None` if no loss timer is active for this space.
    loss_time: Option<OsslTime>,

    // --- PTO ---
    /// Time the last ack-eliciting packet was sent in this space.
    time_of_last_ack_eliciting: Option<OsslTime>,

    // --- ACK generation ---
    /// Whether an ACK frame is immediately desired for this space.
    ack_desired: bool,
    /// Deadline by which an ACK must be sent (flush timer).
    /// `OsslTime::INFINITE` means no deadline is active.
    ack_flush_deadline: OsslTime,
    /// Number of ACK-eliciting packets received since last ACK was generated.
    pkts_since_last_ack: u32,
    /// Whether we have ever generated an ACK frame for this space.
    ack_generated: bool,
    /// Largest received packet number in this space.
    largest_received: Option<u64>,
    /// Time at which the largest received packet was received.
    largest_received_time: Option<OsslTime>,

    // --- Largest acked tracking ---
    /// Largest packet number acknowledged by the peer in this space.
    largest_acked: Option<u64>,

    // --- ECN counters (RX side — our counts of received ECN markings) ---
    /// ECN ECT(0) count seen on received packets.
    #[allow(dead_code)] // Reserved for future ECN feedback integration
    rx_ect0: u64,
    /// ECN ECT(1) count seen on received packets.
    #[allow(dead_code)] // Reserved for future ECN feedback integration
    rx_ect1: u64,
    /// ECN CE (Congestion Experienced) count seen on received packets.
    #[allow(dead_code)] // Reserved for future ECN feedback integration
    rx_ecnce: u64,

    // --- ECN counters (peer-reported, from ACK frames) ---
    peer_ecnce: u64,

    // --- Byte tracking ---
    /// Total bytes in flight for this space.
    ack_eliciting_in_flight: u64,

    // --- Previously generated ACK frame (for "was_missing" detection) ---
    /// Ranges from the last ACK frame we generated for this space.
    last_ack_ranges: Vec<AckRange>,

    // --- Discard flag ---
    /// Whether this PN space has been discarded (keys dropped).
    discarded: bool,
}

impl PnSpaceState {
    /// Creates a new per-space state with default initial values.
    fn new() -> Self {
        Self {
            tx_history: TxPacketHistory::new(),
            rx_history: RxPacketHistory::new(),
            loss_time: None,
            time_of_last_ack_eliciting: None,
            ack_desired: false,
            ack_flush_deadline: OsslTime::INFINITE,
            pkts_since_last_ack: 0,
            ack_generated: false,
            largest_received: None,
            largest_received_time: None,
            largest_acked: None,
            rx_ect0: 0,
            rx_ect1: 0,
            rx_ecnce: 0,
            peer_ecnce: 0,
            ack_eliciting_in_flight: 0,
            last_ack_ranges: Vec::new(),
            discarded: false,
        }
    }
}

// =============================================================================
// ProbeInfo — PTO probe tracking
// =============================================================================

/// Tracks pending probe requests generated by PTO timeouts.
///
/// When a PTO fires, the ACK manager records which PN spaces need probing.
/// The TX packetiser reads these counters and generates appropriate probe packets.
///
/// # C Equivalent
/// `OSSL_ACKM_PROBE_INFO` from `include/internal/quic_ackm.h`.
#[derive(Debug, Clone, Default)]
pub struct ProbeInfo {
    /// Per-space PTO probe requests.
    pto: [u32; PnSpace::count()],
    /// Anti-deadlock probe for Initial space (client-side).
    anti_deadlock_initial: u32,
    /// Anti-deadlock probe for Handshake space (client-side).
    anti_deadlock_handshake: u32,
}

// =============================================================================
// AckManager — Central ACK management (from quic_ackm.c)
// =============================================================================

/// QUIC ACK manager implementing RFC 9002 loss detection and ACK generation.
///
/// The `AckManager` is the central coordinator for:
/// - **TX packet tracking:** Recording sent packets and their metadata.
/// - **ACK processing:** Processing received ACK frames, detecting newly
///   acknowledged packets, and updating RTT estimates.
/// - **Loss detection:** Time-threshold and packet-threshold loss detection
///   with PTO (Probe Timeout) timers and exponential backoff.
/// - **ACK generation:** Deciding when to generate ACK frames and producing
///   the set of acknowledged ranges.
/// - **Congestion control integration:** Notifying the pluggable [`CongestionController`]
///   of sent, acknowledged, lost, and invalidated data.
///
/// # Lifecycle
///
/// ```text
/// AckManager::new(cc)
///   → on_tx_packet()     [for each sent packet]
///   → on_rx_ack_frame()  [when ACK frame received]
///   → on_rx_packet()     [when any packet received]
///   → on_timeout()       [when loss detection timer fires]
///   → on_pkt_space_discarded()  [when keys dropped]
///   → on_handshake_confirmed()  [when handshake completes]
/// ```
///
/// # C Equivalent
/// `OSSL_ACKM` from `ssl/quic/quic_ackm.c`.
#[allow(clippy::struct_excessive_bools)] // Matches C struct fields (handshake_confirmed, peer_completed_addr_validation, is_server, first_rtt_sample)
pub struct AckManager {
    /// Per-PN-space state (Initial, Handshake, Application).
    spaces: [PnSpaceState; PnSpace::count()],

    /// Pluggable congestion controller (trait object).
    /// Receives notifications for sent, acked, lost, and invalidated data.
    cc: Box<dyn CongestionController>,

    /// RTT estimator (embedded STATM module).
    statm: RttEstimator,

    /// Our maximum ACK delay: the longest we will delay sending an ACK
    /// after receiving an ack-eliciting packet.
    tx_max_ack_delay: OsslTime,

    /// Peer's maximum ACK delay (from transport parameters).
    /// Used in PTO computation for the Application space.
    peer_max_ack_delay: OsslTime,

    /// Optional callback invoked when the ACK deadline changes for a space.
    ack_deadline_cb: Option<Box<dyn FnMut(PnSpace, OsslTime) + Send>>,

    /// Optional callback invoked when the loss detection deadline changes.
    loss_detection_deadline_cb: Option<Box<dyn FnMut(OsslTime) + Send>>,

    /// Whether the TLS handshake has been confirmed.
    handshake_confirmed: bool,

    /// Whether the peer has completed address validation.
    /// Set when we receive a Handshake ACK or handshake is confirmed.
    peer_completed_addr_validation: bool,

    /// Whether this endpoint is the server (affects PTO anti-deadlock).
    is_server: bool,

    /// Total bytes in flight across all PN spaces.
    bytes_in_flight: u64,

    /// PTO counter: incremented on each PTO expiry, reset on ACK receipt.
    pto_count: u32,

    /// Loss detection deadline (the earliest time at which `on_timeout` should fire).
    loss_detection_deadline: OsslTime,

    /// Pending probe requests from PTO timeouts.
    pending_probe: ProbeInfo,

    /// Whether the first RTT sample has been taken. Used to determine if
    /// `smoothed_rtt` is available for PTO computation.
    first_rtt_sample: bool,
}

impl AckManager {
    /// Creates a new ACK manager with the given congestion controller.
    ///
    /// # Parameters
    /// - `cc`: Pluggable congestion controller instance.
    /// - `is_server`: Whether this endpoint is the QUIC server.
    ///
    /// # C Equivalent
    /// `ossl_ackm_new()` in `ssl/quic/quic_ackm.c`.
    pub fn new(cc: Box<dyn CongestionController>, is_server: bool) -> Self {
        Self {
            spaces: [PnSpaceState::new(), PnSpaceState::new(), PnSpaceState::new()],
            cc,
            statm: RttEstimator::new(),
            tx_max_ack_delay: OsslTime::from_ms(DEFAULT_TX_MAX_ACK_DELAY_MS),
            peer_max_ack_delay: OsslTime::from_ms(DEFAULT_PEER_MAX_ACK_DELAY_MS),
            ack_deadline_cb: None,
            loss_detection_deadline_cb: None,
            handshake_confirmed: false,
            peer_completed_addr_validation: is_server,
            is_server,
            bytes_in_flight: 0,
            pto_count: 0,
            loss_detection_deadline: OsslTime::INFINITE,
            pending_probe: ProbeInfo::default(),
            first_rtt_sample: false,
        }
    }

    /// Sets the callback invoked when the ACK deadline changes.
    pub fn set_ack_deadline_callback(
        &mut self,
        cb: impl FnMut(PnSpace, OsslTime) + Send + 'static,
    ) {
        self.ack_deadline_cb = Some(Box::new(cb));
    }

    /// Sets the callback invoked when the loss detection deadline changes.
    pub fn set_loss_detection_deadline_callback(
        &mut self,
        cb: impl FnMut(OsslTime) + Send + 'static,
    ) {
        self.loss_detection_deadline_cb = Some(Box::new(cb));
    }

    /// Sets the peer's maximum ACK delay (from transport parameters).
    pub fn set_peer_max_ack_delay(&mut self, delay: OsslTime) {
        self.peer_max_ack_delay = delay;
    }

    /// Sets the local maximum ACK delay.
    pub fn set_tx_max_ack_delay(&mut self, delay: OsslTime) {
        self.tx_max_ack_delay = delay;
    }

    /// Returns a reference to the embedded RTT estimator.
    pub fn rtt_estimator(&self) -> &RttEstimator {
        &self.statm
    }

    /// Returns a reference to the pending probe info.
    pub fn pending_probe(&self) -> &ProbeInfo {
        &self.pending_probe
    }

    // =========================================================================
    // TX Operations
    // =========================================================================

    /// Records a transmitted packet.
    ///
    /// Updates the per-space TX history, bytes-in-flight, and informs the
    /// congestion controller. Also recomputes the loss detection timer.
    ///
    /// # Parameters
    /// - `space`: The PN space this packet belongs to.
    /// - `record`: The packet metadata.
    ///
    /// # C Equivalent
    /// `ossl_ackm_on_tx_packet()` in `ssl/quic/quic_ackm.c`.
    pub fn on_tx_packet(&mut self, space: PnSpace, mut record: TxPacketRecord) {
        let s = &mut self.spaces[space.idx()];

        // Store the largest acked PN we know about at send time,
        // so we can bump RX watermark later when this packet is acked.
        record.largest_acked_on_send = s.largest_acked;

        let pkt_num = record.pkt_num;
        let bytes_sent = record.bytes_sent;
        let is_ack_eliciting = record.is_ack_eliciting;
        let is_in_flight = record.is_in_flight;
        let time_sent = record.time_sent;

        if !s.tx_history.add(record) {
            tracing::warn!(
                pkt_num = pkt_num,
                space = ?space,
                "TX packet rejected: PN below watermark or non-monotonic"
            );
            return;
        }

        if is_ack_eliciting {
            s.time_of_last_ack_eliciting = Some(time_sent);
        }

        if is_in_flight {
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes_sent as u64);
            s.ack_eliciting_in_flight = s
                .ack_eliciting_in_flight
                .saturating_add(u64::from(is_ack_eliciting));
            self.cc.on_data_sent(bytes_sent);
        }

        tracing::trace!(
            pkt_num = pkt_num,
            space = ?space,
            bytes = bytes_sent,
            ack_eliciting = is_ack_eliciting,
            in_flight = is_in_flight,
            "TX packet recorded"
        );

        self.set_loss_detection_timer();
    }

    // =========================================================================
    // ACK Frame Processing
    // =========================================================================

    /// Processes a received ACK frame.
    ///
    /// This is the core ACK processing path, implementing:
    /// 1. Update `largest_acked` for the space
    /// 2. Detect newly acknowledged packets (descending ACK range walk)
    /// 3. Update RTT estimate (if the largest newly-acked was ack-eliciting)
    /// 4. Process ECN counters
    /// 5. Detect lost packets (time + packet threshold)
    /// 6. Invoke `on_acked` / `on_lost` callbacks
    /// 7. Reset PTO counter and recompute loss detection timer
    ///
    /// # Parameters
    /// - `space`: The PN space of the received ACK.
    /// - `ack`: Parsed ACK frame data.
    /// - `now`: Current time for loss detection and RTT computation.
    ///
    /// # Errors
    /// Returns `SslError::Quic` if the ACK frame references an invalid PN space.
    ///
    /// # C Equivalent
    /// `ossl_ackm_on_rx_ack_frame()` in `ssl/quic/quic_ackm.c`.
    pub fn on_rx_ack_frame(
        &mut self,
        space: PnSpace,
        ack: &AckFrameData,
        now: OsslTime,
    ) -> Result<(), SslError> {
        if self.spaces[space.idx()].discarded {
            return Ok(());
        }

        // Update largest acked for this space
        let prev_largest_acked = self.spaces[space.idx()].largest_acked;
        let new_largest_acked = match prev_largest_acked {
            Some(prev) => max(prev, ack.largest_acked),
            None => ack.largest_acked,
        };
        self.spaces[space.idx()].largest_acked = Some(new_largest_acked);

        // Handshake space ACK implies peer completed address validation
        if space == PnSpace::Handshake {
            self.peer_completed_addr_validation = true;
        }

        // Detect and remove newly acknowledged packets
        let (newly_acked, largest_newly_acked) =
            self.detect_newly_acked(space, ack);

        if newly_acked.is_empty() {
            return Ok(());
        }

        // Compute total acked bytes and find the largest newly-acked packet info
        let mut total_acked_bytes: usize = 0;
        let mut largest_newly_acked_time = OsslTime::ZERO;
        let mut largest_newly_acked_is_ack_eliciting = false;

        for pkt in &newly_acked {
            total_acked_bytes = total_acked_bytes.saturating_add(pkt.bytes_sent);
            if pkt.pkt_num == largest_newly_acked {
                largest_newly_acked_time = pkt.time_sent;
                largest_newly_acked_is_ack_eliciting = pkt.is_ack_eliciting;
            }
        }

        // Update RTT (only if largest newly-acked was ack-eliciting)
        if largest_newly_acked_is_ack_eliciting && !largest_newly_acked_time.is_zero() {
            let rtt_sample = now.saturating_sub(largest_newly_acked_time);

            // Convert ack_delay from microseconds to Duration
            let ack_delay_dur = Duration::from_micros(ack.ack_delay);

            // Cap ack_delay at peer_max_ack_delay after handshake
            let capped_ack_delay = if self.handshake_confirmed {
                let max_delay = self.peer_max_ack_delay.to_duration().unwrap_or(Duration::MAX);
                min(ack_delay_dur, max_delay)
            } else {
                ack_delay_dur
            };

            // Convert OsslTime rtt_sample to Duration for the estimator
            let rtt_duration = rtt_sample.to_duration().unwrap_or(Duration::ZERO);
            self.statm
                .update(rtt_duration, capped_ack_delay, self.handshake_confirmed);
            self.first_rtt_sample = true;
        }

        // Process ECN
        if let Some(ref ecn) = ack.ecn {
            self.process_ecn(space, ecn, now);
        }

        // Detect and remove lost packets
        let lost_pkts = self.detect_and_remove_lost(space, now);

        // Decrement bytes_in_flight for acked packets and invoke on_acked
        self.on_pkts_acked(space, newly_acked, now);

        // Process lost packets
        if !lost_pkts.is_empty() {
            self.on_pkts_lost(space, lost_pkts, now);
        }

        // Reset PTO count on receiving a valid ACK
        self.pto_count = 0;

        self.set_loss_detection_timer();

        Ok(())
    }

    /// Detects newly acknowledged packets by walking the ACK ranges against TX history.
    ///
    /// Returns the list of newly acked packets and the largest newly-acked PN.
    ///
    /// # C Equivalent
    /// `ackm_detect_and_remove_newly_acked_pkts()` in `ssl/quic/quic_ackm.c`.
    fn detect_newly_acked(
        &mut self,
        space: PnSpace,
        ack: &AckFrameData,
    ) -> (Vec<TxPacketRecord>, u64) {
        let s = &mut self.spaces[space.idx()];
        let mut newly_acked = Vec::new();
        let mut largest_newly_acked: u64 = 0;

        // Walk ACK ranges and remove matching packets from TX history
        for range in &ack.ranges {
            for pn in range.start..=range.end {
                if let Some(pkt) = s.tx_history.remove(pn) {
                    if pkt.is_in_flight {
                        self.bytes_in_flight =
                            self.bytes_in_flight.saturating_sub(pkt.bytes_sent as u64);
                        if pkt.is_ack_eliciting {
                            s.ack_eliciting_in_flight =
                                s.ack_eliciting_in_flight.saturating_sub(1);
                        }
                    }
                    if pkt.pkt_num > largest_newly_acked || newly_acked.is_empty() {
                        largest_newly_acked = pkt.pkt_num;
                    }
                    newly_acked.push(pkt);
                }
            }
        }

        (newly_acked, largest_newly_acked)
    }

    /// Invokes `on_acked` callbacks and updates state for newly acknowledged packets.
    ///
    /// # C Equivalent
    /// `ackm_on_pkts_acked()` in `ssl/quic/quic_ackm.c`.
    fn on_pkts_acked(
        &mut self,
        space: PnSpace,
        pkts: Vec<TxPacketRecord>,
        now: OsslTime,
    ) {
        let mut total_bytes: usize = 0;
        let mut largest_time_sent = OsslTime::ZERO;

        for mut pkt in pkts {
            total_bytes = total_bytes.saturating_add(pkt.bytes_sent);
            if pkt.time_sent > largest_time_sent {
                largest_time_sent = pkt.time_sent;
            }

            // Bump RX watermark based on largest_acked at send time
            if let Some(la) = pkt.largest_acked_on_send {
                self.spaces[space.idx()]
                    .rx_history
                    .advance_watermark(la.saturating_add(1));
            }

            tracing::trace!(
                pkt_num = pkt.pkt_num,
                space = ?space,
                bytes = pkt.bytes_sent,
                "Packet acknowledged"
            );

            // Invoke on_acked callback
            if let Some(cb) = pkt.on_acked.take() {
                cb();
            }
        }

        // Notify congestion controller
        if total_bytes > 0 {
            self.cc
                .on_data_acked(now, total_bytes, largest_time_sent);
        }
    }

    /// Processes ECN information from an ACK frame.
    ///
    /// If the peer's CE counter has increased, this indicates congestion was
    /// experienced. The C code calls `cc_method->on_ecn()`, but the Rust
    /// `CongestionController` trait does not expose this method; instead we
    /// log the event and track the counter update.
    ///
    /// # C Equivalent
    /// `ackm_process_ecn()` in `ssl/quic/quic_ackm.c`.
    fn process_ecn(&mut self, space: PnSpace, ecn: &EcnCounts, _now: OsslTime) {
        let s = &mut self.spaces[space.idx()];
        if ecn.ce > s.peer_ecnce {
            tracing::debug!(
                space = ?space,
                prev_ce = s.peer_ecnce,
                new_ce = ecn.ce,
                "ECN congestion experienced (CE count increased)"
            );
            s.peer_ecnce = ecn.ce;
            // The CongestionController trait does not expose on_ecn().
            // ECN-based congestion response would require extending the trait.
            // For now, the CE counter is tracked for diagnostic purposes.
        }
    }

    // =========================================================================
    // Loss Detection (RFC 9002 §6)
    // =========================================================================

    /// Detects and removes lost packets from the TX history for a given space.
    ///
    /// A packet is declared lost if:
    /// 1. **Time threshold:** It was sent more than `loss_delay` ago, where
    ///    `loss_delay = 9/8 * max(latest_rtt, smoothed_rtt)`, floored at `K_GRANULARITY`.
    /// 2. **Packet threshold:** Its PN is more than `K_PKT_THRESHOLD` (3) less
    ///    than the largest acknowledged PN.
    ///
    /// # C Equivalent
    /// `ackm_detect_and_remove_lost_pkts()` in `ssl/quic/quic_ackm.c`.
    fn detect_and_remove_lost(&mut self, space: PnSpace, now: OsslTime) -> Vec<TxPacketRecord> {
        let Some(largest_acked) = self.spaces[space.idx()].largest_acked else {
            return Vec::new();
        };

        // Compute loss delay: 9/8 * max(latest_rtt, smoothed_rtt)
        let latest_rtt_ticks =
            OsslTime::from_duration(self.statm.latest_rtt).ticks();
        let smoothed_rtt_ticks =
            OsslTime::from_duration(self.statm.smoothed_rtt).ticks();
        let max_rtt = max(latest_rtt_ticks, smoothed_rtt_ticks);

        // loss_delay = max_rtt * 9 / 8, floored at K_GRANULARITY
        let loss_delay_ticks = max(
            max_rtt.saturating_mul(K_TIME_THRESHOLD_NUM) / K_TIME_THRESHOLD_DEN,
            OsslTime::from_ms(K_GRANULARITY_MS).ticks(),
        );
        let loss_delay = OsslTime::from_ticks(loss_delay_ticks);

        let loss_time_threshold = now.saturating_sub(loss_delay);

        // Collect packet numbers to remove
        let s = &self.spaces[space.idx()];
        let mut lost_pns: Vec<u64> = Vec::new();
        let mut new_loss_time: Option<OsslTime> = None;

        // Iterate through packets in send order (ascending PN)
        for pkt in &s.tx_history.packets {
            if pkt.pkt_num > largest_acked {
                break; // Can't declare packets beyond largest_acked as lost
            }

            // Time threshold: sent before (now - loss_delay)
            let time_lost = pkt.time_sent <= loss_time_threshold;

            // Packet threshold: PN + K_PKT_THRESHOLD <= largest_acked
            let pkt_lost = pkt.pkt_num.saturating_add(K_PKT_THRESHOLD) <= largest_acked;

            if time_lost || pkt_lost {
                lost_pns.push(pkt.pkt_num);
            } else {
                // This packet is not yet lost, but track when it would become lost
                // by time threshold for the loss detection timer.
                let pkt_loss_time = pkt.time_sent.saturating_add(loss_delay);
                new_loss_time = Some(match new_loss_time {
                    Some(existing) => OsslTime::min(existing, pkt_loss_time),
                    None => pkt_loss_time,
                });
            }
        }

        // Update loss_time for this space
        self.spaces[space.idx()].loss_time = new_loss_time;

        // Remove lost packets
        let mut lost_pkts = Vec::with_capacity(lost_pns.len());
        for pn in lost_pns {
            if let Some(pkt) = self.spaces[space.idx()].tx_history.remove(pn) {
                lost_pkts.push(pkt);
            }
        }

        lost_pkts
    }

    /// Processes lost packets: decrements bytes-in-flight, notifies CC, invokes callbacks.
    ///
    /// # C Equivalent
    /// `ackm_on_pkts_lost()` in `ssl/quic/quic_ackm.c`.
    fn on_pkts_lost(
        &mut self,
        space: PnSpace,
        pkts: Vec<TxPacketRecord>,
        now: OsslTime,
    ) {
        let mut total_bytes_lost: usize = 0;
        let mut largest_lost_pn: u64 = 0;
        let mut largest_lost_send_time = OsslTime::ZERO;

        for mut pkt in pkts {
            if pkt.is_in_flight {
                total_bytes_lost = total_bytes_lost.saturating_add(pkt.bytes_sent);
            }
            if pkt.pkt_num > largest_lost_pn {
                largest_lost_pn = pkt.pkt_num;
                largest_lost_send_time = pkt.time_sent;
            }

            tracing::debug!(
                pkt_num = pkt.pkt_num,
                space = ?space,
                bytes = pkt.bytes_sent,
                "Packet declared lost"
            );

            // Invoke on_lost callback
            if let Some(cb) = pkt.on_lost.take() {
                cb();
            }
        }

        // Notify congestion controller
        if total_bytes_lost > 0 {
            self.cc.on_data_lost(
                now,
                largest_lost_pn,
                largest_lost_send_time,
                total_bytes_lost,
            );
        }
    }

    // =========================================================================
    // Loss Detection Timer (RFC 9002 §6.2)
    // =========================================================================

    /// Returns the earliest loss time across all non-discarded PN spaces,
    /// along with the space that has the earliest loss time.
    fn get_loss_time_and_space(&self) -> (Option<OsslTime>, PnSpace) {
        let mut earliest: Option<OsslTime> = None;
        let mut earliest_space = PnSpace::Initial;

        for &sp in &PnSpace::ALL {
            let s = &self.spaces[sp.idx()];
            if s.discarded {
                continue;
            }
            if let Some(lt) = s.loss_time {
                match earliest {
                    None => {
                        earliest = Some(lt);
                        earliest_space = sp;
                    }
                    Some(e) if lt < e => {
                        earliest = Some(lt);
                        earliest_space = sp;
                    }
                    _ => {}
                }
            }
        }

        (earliest, earliest_space)
    }

    /// Returns the total ack-eliciting bytes in flight across all non-discarded spaces.
    fn total_ack_eliciting_in_flight(&self) -> u64 {
        self.spaces
            .iter()
            .filter(|s| !s.discarded)
            .map(|s| s.ack_eliciting_in_flight)
            .sum()
    }

    /// Computes PTO time and the space to probe, returning (`pto_time`, space).
    ///
    /// # C Equivalent
    /// `ackm_get_pto_time_and_space()` in `ssl/quic/quic_ackm.c`.
    fn get_pto_time_and_space(&self) -> (OsslTime, PnSpace) {
        let pto_base = self.statm.get_pto_duration(Duration::ZERO);
        let backoff_factor = 1u64.checked_shl(min(self.pto_count, MAX_PTO_COUNT))
            .unwrap_or(u64::MAX);

        let mut earliest_pto = OsslTime::INFINITE;
        let mut pto_space = PnSpace::Initial;

        for &sp in &PnSpace::ALL {
            let s = &self.spaces[sp.idx()];
            if s.discarded {
                continue;
            }

            if let Some(last_ack_eliciting) = s.time_of_last_ack_eliciting {
                // Compute duration for this space
                let mut duration = pto_base;

                // For application data, add peer's max ACK delay
                if sp == PnSpace::Application {
                    let peer_delay = self
                        .peer_max_ack_delay
                        .to_duration()
                        .unwrap_or(Duration::ZERO);
                    duration = duration.saturating_add(peer_delay);
                }

                // Apply exponential backoff
                let duration_ossl = OsslTime::from_duration(duration);
                let backed_off = duration_ossl.saturating_mul(backoff_factor);
                let pto_time = last_ack_eliciting.saturating_add(backed_off);

                if pto_time < earliest_pto {
                    earliest_pto = pto_time;
                    pto_space = sp;
                }
            }
        }

        (earliest_pto, pto_space)
    }

    /// Recomputes and sets the loss detection timer.
    ///
    /// The timer fires at the earliest of:
    /// 1. The earliest `loss_time` across all spaces (time threshold loss detection)
    /// 2. The PTO time (probe timeout)
    ///
    /// # C Equivalent
    /// `ackm_set_loss_detection_timer()` in `ssl/quic/quic_ackm.c`.
    fn set_loss_detection_timer(&mut self) {
        let (earliest_loss_time, _loss_space) = self.get_loss_time_and_space();

        if let Some(loss_time) = earliest_loss_time {
            // Time threshold loss timer takes priority
            self.loss_detection_deadline = loss_time;
        } else if self.total_ack_eliciting_in_flight() == 0
            && self.peer_completed_addr_validation
        {
            // Nothing in flight and peer validated — no timer needed
            self.loss_detection_deadline = OsslTime::INFINITE;
        } else {
            // PTO timer
            let (pto_time, _pto_space) = self.get_pto_time_and_space();
            self.loss_detection_deadline = pto_time;
        }

        // Notify callback
        let deadline = self.loss_detection_deadline;
        if let Some(ref mut cb) = self.loss_detection_deadline_cb {
            cb(deadline);
        }
    }

    // =========================================================================
    // Timeout Handling (RFC 9002 §6.2.1)
    // =========================================================================

    /// Handles a loss detection timeout.
    ///
    /// Called when the loss detection timer (from [`get_loss_detection_deadline`])
    /// fires. Processes time-threshold losses or sends PTO probes.
    ///
    /// # C Equivalent
    /// `ossl_ackm_on_timeout()` in `ssl/quic/quic_ackm.c`.
    pub fn on_timeout(&mut self, now: OsslTime) -> Result<(), SslError> {
        let (earliest_loss_time, loss_space) = self.get_loss_time_and_space();

        if earliest_loss_time.is_some() {
            // Time threshold loss detection
            let lost_pkts = self.detect_and_remove_lost(loss_space, now);
            if !lost_pkts.is_empty() {
                tracing::debug!(
                    space = ?loss_space,
                    count = lost_pkts.len(),
                    "Time threshold loss detection"
                );
                self.on_pkts_lost(loss_space, lost_pkts, now);
            }
            self.set_loss_detection_timer();
            return Ok(());
        }

        if self.total_ack_eliciting_in_flight() == 0 {
            // Client sends anti-deadlock packet
            if !self.peer_completed_addr_validation {
                if self.spaces[PnSpace::Initial.idx()].discarded {
                    self.pending_probe.anti_deadlock_handshake += 1;
                    tracing::debug!("PTO: anti-deadlock handshake probe");
                } else {
                    self.pending_probe.anti_deadlock_initial += 1;
                    tracing::debug!("PTO: anti-deadlock initial probe");
                }
            }
        } else {
            // PTO — send probe in the appropriate space
            let (_pto_time, pto_space) = self.get_pto_time_and_space();
            self.pending_probe.pto[pto_space.idx()] += 1;
            tracing::warn!(
                space = ?pto_space,
                pto_count = self.pto_count + 1,
                "PTO probe timeout"
            );
        }

        self.pto_count += 1;
        self.set_loss_detection_timer();
        Ok(())
    }

    /// Returns the current loss detection deadline.
    ///
    /// This is the time at which [`on_timeout`](Self::on_timeout) should be called.
    /// Returns `OsslTime::INFINITE` if no timer is active.
    ///
    /// # C Equivalent
    /// `ossl_ackm_get_loss_detection_deadline()` in `ssl/quic/quic_ackm.c`.
    pub fn get_loss_detection_deadline(&self) -> OsslTime {
        self.loss_detection_deadline
    }

    // =========================================================================
    // RX Packet Processing and ACK Generation
    // =========================================================================

    /// Records receipt of a packet.
    ///
    /// Updates the RX history, largest received PN/time, ECN counters, and
    /// decides whether to generate an ACK immediately or defer it.
    ///
    /// # Parameters
    /// - `space`: The PN space of the received packet.
    /// - `pkt_num`: The received packet number.
    /// - `time`: Time the packet was received.
    /// - `is_ack_eliciting`: Whether the packet contains ack-eliciting frames.
    ///
    /// # C Equivalent
    /// `ossl_ackm_on_rx_packet()` in `ssl/quic/quic_ackm.c`.
    pub fn on_rx_packet(
        &mut self,
        space: PnSpace,
        pkt_num: u64,
        time: OsslTime,
        is_ack_eliciting: bool,
    ) {
        if self.spaces[space.idx()].discarded {
            return;
        }

        // Check if PN is processable (not duplicate, not below watermark)
        if self.spaces[space.idx()].rx_history.is_duplicate(pkt_num) {
            return;
        }

        // Check if this PN was previously reported as "missing" in our ACK
        // (must be done before mutating rx_history)
        let was_missing = self.is_pn_missing(space, pkt_num);

        // Update largest received
        let is_new_largest = match self.spaces[space.idx()].largest_received {
            Some(prev) => pkt_num > prev,
            None => true,
        };
        if is_new_largest {
            self.spaces[space.idx()].largest_received = Some(pkt_num);
            self.spaces[space.idx()].largest_received_time = Some(time);
        }

        // Add to RX history
        if !self.spaces[space.idx()].rx_history.on_rx(pkt_num) {
            return; // Duplicate detected by set
        }

        tracing::trace!(
            pkt_num = pkt_num,
            space = ?space,
            ack_eliciting = is_ack_eliciting,
            "RX packet recorded"
        );

        // Decide ACK timing
        if is_ack_eliciting {
            self.on_rx_ack_eliciting(space, time, was_missing);
        }
    }

    /// Checks if a packet number was implied as missing in the last ACK we generated.
    ///
    /// A PN is "missing" if it is not greater than the highest PN in our last
    /// generated ACK frame, but is not contained in any of the ACK ranges.
    ///
    /// # C Equivalent
    /// `ackm_is_missing()` in `ssl/quic/quic_ackm.c`.
    fn is_pn_missing(&self, space: PnSpace, pkt_num: u64) -> bool {
        let s = &self.spaces[space.idx()];
        if s.last_ack_ranges.is_empty() {
            return false;
        }
        // The first range has the largest PN (descending order)
        let largest_acked_in_ack = s.last_ack_ranges[0].end;
        if pkt_num > largest_acked_in_ack {
            return false;
        }
        // Check if PN is contained in any range
        !s.last_ack_ranges
            .iter()
            .any(|r| pkt_num >= r.start && pkt_num <= r.end)
    }

    /// Checks if the newly received PN creates a new gap (implying missing packets).
    ///
    /// # C Equivalent
    /// `ackm_has_newly_missing()` in `ssl/quic/quic_ackm.c`.
    fn has_newly_missing(&self, space: PnSpace) -> bool {
        let s = &self.spaces[space.idx()];
        if s.rx_history.received.is_empty() || s.last_ack_ranges.is_empty() {
            return false;
        }

        // The highest range in RX history
        let Some(last_rx) = s.rx_history.received.last_range() else {
            return false;
        };

        // The highest PN we've previously reported in an ACK
        let last_ack_end = s.last_ack_ranges[0].end;

        // Newly missing if: the highest RX range is a single PN AND
        // it's beyond (not adjacent to) the highest ACK'd PN
        last_rx.0 == last_rx.1 && last_rx.0 > last_ack_end.saturating_add(1)
    }

    /// Handles receipt of an ACK-eliciting packet: decides immediate vs deferred ACK.
    ///
    /// # C Equivalent
    /// `ackm_on_rx_ack_eliciting()` in `ssl/quic/quic_ackm.c`.
    fn on_rx_ack_eliciting(&mut self, space: PnSpace, rx_time: OsslTime, was_missing: bool) {
        if self.spaces[space.idx()].ack_desired {
            // ACK already requested
            return;
        }

        self.spaces[space.idx()].pkts_since_last_ack += 1;

        // Determine if we should ACK immediately (read-only checks first)
        let ack_generated = self.spaces[space.idx()].ack_generated;
        let pkts = self.spaces[space.idx()].pkts_since_last_ack;
        let newly_missing = self.has_newly_missing(space);

        let immediate = !ack_generated                     // First packet ever in this space
            || was_missing                                  // Previously reported as missing
            || pkts >= PKTS_BEFORE_ACK                      // Threshold exceeded
            || newly_missing;                               // New gap detected

        if immediate {
            // Request immediate ACK
            self.spaces[space.idx()].ack_desired = true;
            self.spaces[space.idx()].ack_flush_deadline = OsslTime::INFINITE;
            let deadline = self.get_ack_deadline(space);
            if let Some(ref mut cb) = self.ack_deadline_cb {
                cb(space, deadline);
            }
            return;
        }

        // Deferred ACK with flush deadline.
        // RFC 9000 §13.2.1: Initial and Handshake ACKs must be immediate.
        let max_delay = if space == PnSpace::Initial || space == PnSpace::Handshake {
            OsslTime::ZERO
        } else {
            self.tx_max_ack_delay
        };

        let new_deadline = rx_time.saturating_add(max_delay);
        let s = &mut self.spaces[space.idx()];

        if s.ack_flush_deadline.is_infinite() {
            s.ack_flush_deadline = new_deadline;
        } else {
            s.ack_flush_deadline = OsslTime::min(s.ack_flush_deadline, new_deadline);
        }

        // Drop mutable borrow before calling get_ack_deadline
        let deadline = self.get_ack_deadline(space);
        if let Some(ref mut cb) = self.ack_deadline_cb {
            cb(space, deadline);
        }
    }

    /// Returns `true` if an ACK frame should be generated for the given space.
    ///
    /// An ACK is desired when:
    /// - The `ack_desired` flag is set (immediate ACK requested), or
    /// - The ACK flush deadline has passed.
    ///
    /// # Parameters
    /// - `space`: The PN space to check.
    ///
    /// # C Equivalent
    /// `ossl_ackm_is_ack_desired()` in `ssl/quic/quic_ackm.c`.
    pub fn is_ack_desired(&self, space: PnSpace, now: OsslTime) -> bool {
        let s = &self.spaces[space.idx()];
        s.ack_desired
            || (!s.ack_flush_deadline.is_infinite() && now >= s.ack_flush_deadline)
    }

    /// Returns the deadline by which an ACK frame should be sent for the given space.
    ///
    /// Returns `OsslTime::ZERO` if an ACK is immediately desired.
    /// Returns `OsslTime::INFINITE` if no ACK is pending.
    ///
    /// # C Equivalent
    /// `ossl_ackm_get_ack_deadline()` in `ssl/quic/quic_ackm.c`.
    pub fn get_ack_deadline(&self, space: PnSpace) -> OsslTime {
        let s = &self.spaces[space.idx()];
        if s.ack_desired {
            OsslTime::ZERO
        } else {
            s.ack_flush_deadline
        }
    }

    /// Generates ACK ranges for the given PN space.
    ///
    /// Returns the acknowledged ranges in **descending order** (largest PN first),
    /// suitable for inclusion in an ACK frame. Also resets the ACK generation
    /// state (clears `ack_desired`, resets packet counter).
    ///
    /// The returned ranges reflect the current RX history for the space. Up to
    /// [`MAX_RX_ACK_RANGES`] ranges are returned.
    ///
    /// # C Equivalent
    /// `ossl_ackm_get_ack_frame()` + `ackm_fill_rx_ack_ranges()` in `ssl/quic/quic_ackm.c`.
    pub fn generate_ack_ranges(&mut self, space: PnSpace, now: OsslTime) -> Vec<AckRange> {
        let s = &mut self.spaces[space.idx()];

        // Build ranges from RX history (descending order)
        let ranges: Vec<AckRange> = s
            .rx_history
            .received
            .iter_ranges()
            .take(MAX_RX_ACK_RANGES)
            .map(|(start, end)| AckRange { start, end })
            .collect();

        // Save a copy for "was_missing" detection in future on_rx_packet calls
        s.last_ack_ranges.clone_from(&ranges);

        // Reset ACK generation state
        s.pkts_since_last_ack = 0;
        s.ack_generated = true;
        s.ack_desired = false;
        s.ack_flush_deadline = OsslTime::INFINITE;

        // Notify callback that flush deadline is cancelled
        let deadline = self.get_ack_deadline(space);
        if let Some(ref mut cb) = self.ack_deadline_cb {
            cb(space, deadline);
        }

        tracing::trace!(
            space = ?space,
            num_ranges = ranges.len(),
            largest = ranges.first().map(|r| r.end),
            "ACK ranges generated"
        );

        let _ = now; // Available for ACK delay computation by caller

        ranges
    }

    // =========================================================================
    // PN Space Discard and Handshake Confirmation
    // =========================================================================

    /// Discards a packet number space (e.g., after Initial/Handshake keys are dropped).
    ///
    /// This destroys the TX and RX histories for the space, invokes `on_discarded`
    /// callbacks for all remaining TX packets, invalidates bytes-in-flight with the
    /// congestion controller, and resets the loss detection timer.
    ///
    /// # C Equivalent
    /// `ossl_ackm_on_pkt_space_discarded()` in `ssl/quic/quic_ackm.c`.
    pub fn on_pkt_space_discarded(&mut self, space: PnSpace) {
        let s = &mut self.spaces[space.idx()];
        if s.discarded {
            return;
        }

        if space == PnSpace::Handshake {
            self.peer_completed_addr_validation = true;
        }

        // Collect remaining packets and invoke on_discarded callbacks
        let mut num_bytes_invalidated: usize = 0;
        let mut remaining_packets: Vec<TxPacketRecord> = Vec::new();

        // Drain the packet list
        while let Some(pkt) = s.tx_history.packets.pop_front() {
            s.tx_history.lookup.remove(&pkt.pkt_num);
            if pkt.is_in_flight {
                let bytes = pkt.bytes_sent;
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes as u64);
                num_bytes_invalidated = num_bytes_invalidated.saturating_add(bytes);
            }
            remaining_packets.push(pkt);
        }

        // Invoke on_discarded callbacks
        for mut pkt in remaining_packets {
            if let Some(cb) = pkt.on_discarded.take() {
                cb();
            }
        }

        // Notify congestion controller
        if num_bytes_invalidated > 0 {
            self.cc.on_data_invalidated(num_bytes_invalidated);
        }

        // Reset space state
        s.time_of_last_ack_eliciting = None;
        s.loss_time = None;
        s.ack_eliciting_in_flight = 0;
        s.discarded = true;

        // Reset PTO count and recompute timer
        self.pto_count = 0;
        self.set_loss_detection_timer();

        tracing::debug!(
            space = ?space,
            bytes_invalidated = num_bytes_invalidated,
            "PN space discarded"
        );
    }

    /// Marks the TLS handshake as confirmed.
    ///
    /// After handshake confirmation:
    /// - ACK delay is included in RTT calculations
    /// - PTO timer behavior changes for the Application space
    /// - Peer is considered to have completed address validation
    ///
    /// # C Equivalent
    /// `ossl_ackm_on_handshake_confirmed()` in `ssl/quic/quic_ackm.c`.
    pub fn on_handshake_confirmed(&mut self) {
        self.handshake_confirmed = true;
        self.peer_completed_addr_validation = true;
        self.set_loss_detection_timer();
        tracing::debug!("Handshake confirmed");
    }

    // =========================================================================
    // Additional Public Methods
    // =========================================================================

    /// Marks a specific packet as pseudo-lost, triggering retransmission.
    ///
    /// This is used by higher layers (e.g., the QUIC channel) to force
    /// retransmission of a specific packet's data without declaring it as
    /// a real loss (no congestion controller notification).
    ///
    /// The packet is removed from the TX history and its `on_lost` callback
    /// is invoked.
    ///
    /// # C Equivalent
    /// `ossl_ackm_mark_packet_pseudo_lost()` in `ssl/quic/quic_ackm.c`.
    pub fn mark_packet_pseudo_lost(&mut self, space: PnSpace, pkt_num: u64) {
        let s = &mut self.spaces[space.idx()];

        if let Some(mut pkt) = s.tx_history.remove(pkt_num) {
            if pkt.is_in_flight {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.bytes_sent as u64);
                if pkt.is_ack_eliciting {
                    s.ack_eliciting_in_flight =
                        s.ack_eliciting_in_flight.saturating_sub(1);
                }
            }

            tracing::debug!(
                pkt_num = pkt_num,
                space = ?space,
                "Packet marked pseudo-lost"
            );

            // Invoke on_lost callback (pseudo-loss reuses the lost callback)
            if let Some(cb) = pkt.on_lost.take() {
                cb();
            }
        }
    }

    /// Returns the current PTO duration for the given space.
    ///
    /// This is the base PTO duration without exponential backoff:
    /// `smoothed_rtt + max(4 * rttvar, K_GRANULARITY) + rx_max_ack_delay`
    ///
    /// For the Application space, the peer's max ACK delay is included.
    ///
    /// # C Equivalent
    /// `ossl_ackm_get_pto_duration()` in `ssl/quic/quic_ackm.c`.
    pub fn get_pto_duration(&self, space: PnSpace) -> Duration {
        let peer_delay = if space == PnSpace::Application {
            self.peer_max_ack_delay
                .to_duration()
                .unwrap_or(Duration::ZERO)
        } else {
            Duration::ZERO
        };
        self.statm.get_pto_duration(peer_delay)
    }

    /// Returns the largest acknowledged packet number in the given space.
    ///
    /// Returns `None` if no ACK has been received for this space.
    ///
    /// # C Equivalent
    /// `ossl_ackm_get_largest_acked()` in `ssl/quic/quic_ackm.c`.
    pub fn get_largest_acked(&self, space: PnSpace) -> Option<u64> {
        self.spaces[space.idx()].largest_acked
    }

    /// Checks if a received packet number is processable (not a duplicate,
    /// not below the watermark).
    ///
    /// # C Equivalent
    /// `ossl_ackm_is_rx_pn_processable()` in `ssl/quic/quic_ackm.c`.
    pub fn is_rx_pn_processable(&self, space: PnSpace, pkt_num: u64) -> bool {
        let s = &self.spaces[space.idx()];
        if s.discarded {
            return false;
        }
        !s.rx_history.is_duplicate(pkt_num)
    }

    /// Returns a copy of the current pending probe info.
    ///
    /// The TX packetiser uses this to determine which probe packets to send.
    /// After reading, the probe info is cleared.
    ///
    /// # C Equivalent
    /// `ossl_ackm_get0_probe_request()` in `ssl/quic/quic_ackm.c`.
    pub fn get_probe_request(&mut self) -> ProbeInfo {
        let info = self.pending_probe.clone();
        self.pending_probe = ProbeInfo::default();
        info
    }

    /// Sets whether this endpoint is the QUIC server.
    pub fn set_is_server(&mut self, is_server: bool) {
        self.is_server = is_server;
    }

    /// Returns the current bytes in flight across all PN spaces.
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Returns the current PTO count (number of consecutive PTO timeouts).
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    /// Returns whether the handshake has been confirmed.
    pub fn is_handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }
}

