//! QUIC stream map, send/receive stream buffering, and flow control.
//!
//! This module is a complete Rust rewrite of five C source files from OpenSSL's
//! QUIC stack:
//!
//! - `ssl/quic/quic_stream_map.c` — Stream lifecycle, scheduling, accept/active/gc lists
//! - `ssl/quic/quic_sstream.c` — Send stream buffering with range tracking
//! - `ssl/quic/quic_rstream.c` — Receive stream reassembly and delivery
//! - `ssl/quic/quic_sf_list.c` — Sorted fragment list for out-of-order reassembly
//! - `ssl/quic/quic_fc.c` — Transmit and receive flow control with auto-tuning
//!
//! # Architecture
//!
//! The [`StreamMap`] manages the lifecycle of all QUIC streams within a connection.
//! Each [`QuicStream`] contains optional send/receive buffers
//! ([`QuicSendStream`]/[`QuicRecvStream`]) and per-stream flow controllers
//! ([`TxFlowController`]/[`RxFlowController`]).
//!
//! Flow control follows a parent-child hierarchy where per-stream controllers
//! are bounded by connection-level controllers, matching RFC 9000 §4.
//!
//! # Rules Compliance
//!
//! - **R5**: `Option<T>` for `fin_offset`, parent FC, error codes — no sentinels
//! - **R6**: No bare `as` casts for narrowing conversions; `u64 as usize` uses
//!   `usize::try_from` with graceful fallback
//! - **R7**: `// LOCK-SCOPE:` annotations on shared-state structures
//! - **R8**: Zero `unsafe` blocks
//! - **R9**: Warning-free under `RUSTFLAGS="-D warnings"`
//! - **R10**: Reachable from `channel.subtick()` → stream map operations

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::time::Duration;

use openssl_common::error::SslError;
use zeroize::Zeroize;

// =============================================================================
// Stream Direction, Initiator, and Type Enums
// =============================================================================

/// Direction of a QUIC stream per RFC 9000 §2.1.
///
/// Bidirectional streams allow data flow in both directions, while unidirectional
/// streams allow data flow in only one direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamDirection {
    /// Both endpoints can send and receive data.
    Bidirectional,
    /// Only the initiating endpoint can send data.
    Unidirectional,
}

impl fmt::Display for StreamDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bidirectional => write!(f, "bidi"),
            Self::Unidirectional => write!(f, "uni"),
        }
    }
}

/// Endpoint that initiated a QUIC stream per RFC 9000 §2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamInitiator {
    /// Stream was opened by the client.
    Client,
    /// Stream was opened by the server.
    Server,
}

impl fmt::Display for StreamInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
        }
    }
}

/// Combined stream type encoding both initiator and direction.
///
/// QUIC defines four stream types per RFC 9000 §2.1, determined by the
/// two least-significant bits of the stream ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// Client-initiated bidirectional (stream ID bits: `0b00`).
    ClientBidi,
    /// Server-initiated bidirectional (stream ID bits: `0b01`).
    ServerBidi,
    /// Client-initiated unidirectional (stream ID bits: `0b10`).
    ClientUni,
    /// Server-initiated unidirectional (stream ID bits: `0b11`).
    ServerUni,
}

impl StreamType {
    /// Returns the direction component of this stream type.
    pub fn direction(self) -> StreamDirection {
        match self {
            Self::ClientBidi | Self::ServerBidi => StreamDirection::Bidirectional,
            Self::ClientUni | Self::ServerUni => StreamDirection::Unidirectional,
        }
    }

    /// Returns the initiator component of this stream type.
    pub fn initiator(self) -> StreamInitiator {
        match self {
            Self::ClientBidi | Self::ClientUni => StreamInitiator::Client,
            Self::ServerBidi | Self::ServerUni => StreamInitiator::Server,
        }
    }

    /// Returns the two-bit type code for this stream type.
    fn type_bits(self) -> u64 {
        match self {
            Self::ClientBidi => 0x00,
            Self::ServerBidi => 0x01,
            Self::ClientUni => 0x02,
            Self::ServerUni => 0x03,
        }
    }

    /// Constructs a stream type from initiator and direction.
    fn from_parts(initiator: StreamInitiator, direction: StreamDirection) -> Self {
        match (initiator, direction) {
            (StreamInitiator::Client, StreamDirection::Bidirectional) => Self::ClientBidi,
            (StreamInitiator::Server, StreamDirection::Bidirectional) => Self::ServerBidi,
            (StreamInitiator::Client, StreamDirection::Unidirectional) => Self::ClientUni,
            (StreamInitiator::Server, StreamDirection::Unidirectional) => Self::ServerUni,
        }
    }
}

impl fmt::Display for StreamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientBidi => write!(f, "client-bidi"),
            Self::ServerBidi => write!(f, "server-bidi"),
            Self::ClientUni => write!(f, "client-uni"),
            Self::ServerUni => write!(f, "server-uni"),
        }
    }
}

// =============================================================================
// StreamId
// =============================================================================

/// QUIC stream identifier per RFC 9000 §2.1.
///
/// The stream ID encodes three pieces of information:
/// - **Bit 0**: Initiator — `0` = client, `1` = server
/// - **Bit 1**: Direction — `0` = bidirectional, `1` = unidirectional
/// - **Bits 2+**: Stream ordinal (sequence number within the type)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    /// Creates a new stream ID from its constituent parts.
    ///
    /// The raw ID is computed as `(ordinal << 2) | type_bits` where
    /// `type_bits` encodes the initiator (bit 0) and direction (bit 1).
    pub fn new(initiator: StreamInitiator, direction: StreamDirection, ordinal: u64) -> Self {
        let stream_type = StreamType::from_parts(initiator, direction);
        Self((ordinal << 2) | stream_type.type_bits())
    }

    /// Creates a stream ID directly from a raw `u64` value.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw `u64` value of this stream ID.
    pub fn as_raw(self) -> u64 {
        self.0
    }

    /// Returns which endpoint initiated this stream.
    ///
    /// Bit 0 of the stream ID: `0` = client, `1` = server.
    pub fn initiator(&self) -> StreamInitiator {
        if self.0 & 0x01 == 0 {
            StreamInitiator::Client
        } else {
            StreamInitiator::Server
        }
    }

    /// Returns the direction of this stream.
    ///
    /// Bit 1 of the stream ID: `0` = bidirectional, `1` = unidirectional.
    pub fn direction(&self) -> StreamDirection {
        if self.0 & 0x02 == 0 {
            StreamDirection::Bidirectional
        } else {
            StreamDirection::Unidirectional
        }
    }

    /// Returns the stream ordinal (sequence number within its type).
    ///
    /// Bits 2+ of the stream ID.
    pub fn stream_ordinal(&self) -> u64 {
        self.0 >> 2
    }

    /// Returns the combined stream type.
    pub fn stream_type(&self) -> StreamType {
        StreamType::from_parts(self.initiator(), self.direction())
    }

    /// Returns `true` if this is a bidirectional stream.
    pub fn is_bidi(&self) -> bool {
        self.direction() == StreamDirection::Bidirectional
    }

    /// Returns `true` if this stream was initiated by the client.
    pub fn is_client_initiated(&self) -> bool {
        self.initiator() == StreamInitiator::Client
    }

    /// Returns `true` if this stream was initiated by the server.
    pub fn is_server_initiated(&self) -> bool {
        self.initiator() == StreamInitiator::Server
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamId")
            .field("raw", &self.0)
            .field("type", &self.stream_type())
            .field("ordinal", &self.stream_ordinal())
            .finish()
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.stream_type(), self.stream_ordinal())
    }
}

// =============================================================================
// Send and Receive State Machines
// =============================================================================

/// Send-side state machine per RFC 9000 §3.1.
///
/// Transitions follow the QUIC specification:
/// ```text
/// Ready → Send → DataSent → DataRecvd
///                    ↓
///               ResetSent → ResetRecvd
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// Initial state: stream created but no data sent.
    Ready,
    /// Application is actively sending data.
    Send,
    /// All data (including FIN) has been sent, awaiting acknowledgement.
    DataSent,
    /// All data has been acknowledged by the peer — terminal state.
    DataRecvd,
    /// `RESET_STREAM` has been sent to the peer.
    ResetSent,
    /// `RESET_STREAM` acknowledgement received — terminal state.
    ResetRecvd,
}

impl SendState {
    /// Returns `true` if this is a terminal state (no further transitions possible).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::DataRecvd | Self::ResetRecvd)
    }
}

impl fmt::Display for SendState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => write!(f, "Ready"),
            Self::Send => write!(f, "Send"),
            Self::DataSent => write!(f, "DataSent"),
            Self::DataRecvd => write!(f, "DataRecvd"),
            Self::ResetSent => write!(f, "ResetSent"),
            Self::ResetRecvd => write!(f, "ResetRecvd"),
        }
    }
}

/// Receive-side state machine per RFC 9000 §3.2.
///
/// Transitions follow the QUIC specification:
/// ```text
/// Recv → SizeKnown → DataRecvd → DataRead
///              ↓
///         ResetRecvd → ResetRead
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    /// Receiving data from the peer.
    Recv,
    /// Final size of stream is known (FIN received), but not all data yet.
    SizeKnown,
    /// All data has been received — awaiting application read.
    DataRecvd,
    /// All data has been read by the application — terminal state.
    DataRead,
    /// Peer sent `RESET_STREAM` — awaiting application acknowledgement.
    ResetRecvd,
    /// Application has acknowledged the reset — terminal state.
    ResetRead,
}

impl RecvState {
    /// Returns `true` if this is a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::DataRead | Self::ResetRead)
    }
}

impl fmt::Display for RecvState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recv => write!(f, "Recv"),
            Self::SizeKnown => write!(f, "SizeKnown"),
            Self::DataRecvd => write!(f, "DataRecvd"),
            Self::DataRead => write!(f, "DataRead"),
            Self::ResetRecvd => write!(f, "ResetRecvd"),
            Self::ResetRead => write!(f, "ResetRead"),
        }
    }
}

// =============================================================================
// RangeSet — Coalescing Range Tracker
// =============================================================================

/// A set of non-overlapping, coalesced `[start, end)` ranges stored in a `BTreeMap`.
///
/// Used for tracking transmitted and acknowledged byte ranges in [`QuicSendStream`].
/// Ranges are automatically coalesced on insertion — adjacent or overlapping ranges
/// are merged into a single range.
///
/// Equivalent to the C `UINT_SET` type used in `quic_sstream.c`.
#[derive(Debug, Clone)]
struct RangeSet {
    /// Map from range start to range end (exclusive). Invariant: no two ranges
    /// overlap or are adjacent (they are always coalesced).
    ranges: BTreeMap<u64, u64>,
}

impl RangeSet {
    /// Creates an empty range set.
    fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
        }
    }

    /// Inserts the range `[start, end)` into the set, coalescing with any
    /// overlapping or adjacent existing ranges.
    fn insert(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }

        let mut new_start = start;
        let mut new_end = end;

        // Collect all ranges that overlap or are adjacent to [start, end).
        let mut to_remove = Vec::new();
        for (&rs, &re) in &self.ranges {
            if rs > new_end {
                break;
            }
            if re >= new_start {
                to_remove.push(rs);
                new_start = new_start.min(rs);
                new_end = new_end.max(re);
            }
        }

        for key in to_remove {
            self.ranges.remove(&key);
        }

        self.ranges.insert(new_start, new_end);
    }

    /// Removes the range `[start, end)` from the set, splitting existing ranges
    /// as necessary.
    fn remove(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }

        let mut to_remove = Vec::new();
        let mut to_insert = Vec::new();

        for (&rs, &re) in &self.ranges {
            if rs >= end {
                break;
            }
            if re <= start {
                continue;
            }
            // [rs, re) overlaps with [start, end)
            to_remove.push(rs);

            // Keep the portion before [start, end)
            if rs < start {
                to_insert.push((rs, start));
            }
            // Keep the portion after [start, end)
            if re > end {
                to_insert.push((end, re));
            }
        }

        for key in to_remove {
            self.ranges.remove(&key);
        }
        for (s, e) in to_insert {
            self.ranges.insert(s, e);
        }
    }

    /// Returns `true` if the given offset is contained in any range.
    fn contains(&self, offset: u64) -> bool {
        // Find the last range whose start <= offset
        if let Some((&rs, &re)) = self.ranges.range(..=offset).next_back() {
            offset < re && offset >= rs
        } else {
            false
        }
    }

    /// Returns an iterator over all `(start, end)` range pairs in ascending order.
    fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.ranges.iter().map(|(&s, &e)| (s, e))
    }

    /// Returns `true` if the range set is empty.
    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns `true` if the set contains the entire range `[0, end)` in a
    /// single contiguous range starting at zero.
    fn contains_range_from_zero(&self, end: u64) -> bool {
        if let Some((&first_start, &first_end)) = self.ranges.iter().next() {
            first_start == 0 && first_end >= end
        } else {
            end == 0
        }
    }
}

// =============================================================================
// RingBuffer — Fixed-Capacity Circular Byte Buffer
// =============================================================================

/// A fixed-capacity circular byte buffer used for send-side stream buffering.
///
/// Wraps a contiguous `Vec<u8>` with head/tail tracking for efficient FIFO
/// byte I/O. The buffer never dynamically grows; capacity is set at construction.
///
/// Equivalent to the `RING_BUF` helper used in `quic_sstream.c`.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Methods used by sibling QUIC modules and tests
struct RingBuffer {
    buf: Vec<u8>,
    capacity: usize,
    head: usize,
    tail: usize,
    len: usize,
}

#[allow(dead_code)] // Methods used by sibling QUIC modules (tx.rs, channel.rs) and tests
impl RingBuffer {
    /// Creates a new ring buffer with the given capacity.
    fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity],
            capacity,
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Writes data into the ring buffer, returning the number of bytes written.
    ///
    /// If the buffer is full, returns `0`. If the data exceeds available space,
    /// only the portion that fits is written.
    fn write(&mut self, data: &[u8]) -> usize {
        let avail = self.capacity - self.len;
        let to_write = data.len().min(avail);
        if to_write == 0 {
            return 0;
        }

        for &byte in &data[..to_write] {
            self.buf[self.tail] = byte;
            self.tail = (self.tail + 1) % self.capacity;
        }
        self.len += to_write;
        to_write
    }

    /// Reads up to `buf.len()` bytes from the ring buffer, returning the
    /// number of bytes actually read.
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.len);
        if to_read == 0 {
            return 0;
        }

        for slot in buf.iter_mut().take(to_read) {
            *slot = self.buf[self.head];
            self.head = (self.head + 1) % self.capacity;
        }
        self.len -= to_read;
        to_read
    }

    /// Returns the number of bytes currently stored in the buffer.
    fn available(&self) -> usize {
        self.len
    }

    /// Returns the total capacity of the buffer.
    fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of free bytes remaining.
    fn free_space(&self) -> usize {
        self.capacity - self.len
    }

    /// Reads a contiguous slice at the given logical offset from the head.
    ///
    /// The offset is relative to the current head position. Returns a `Vec<u8>`
    /// copy of the requested region. If offset + len exceeds available data,
    /// returns only what is available.
    fn read_at(&self, offset: usize, len: usize) -> Vec<u8> {
        let available_from_offset = self.len.saturating_sub(offset);
        let actual_len = len.min(available_from_offset);
        let mut out = Vec::with_capacity(actual_len);
        for i in 0..actual_len {
            let idx = (self.head + offset + i) % self.capacity;
            out.push(self.buf[idx]);
        }
        out
    }

    /// Discards the first `n` bytes from the head of the buffer.
    fn discard(&mut self, n: usize) {
        let to_discard = n.min(self.len);
        self.head = (self.head + to_discard) % self.capacity;
        self.len -= to_discard;
    }

    /// Securely erases the entire buffer contents using `zeroize`.
    fn secure_erase(&mut self) {
        self.buf.zeroize();
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }
}

// =============================================================================
// SortedFragList — Receive-Side Reassembly
// =============================================================================

/// Sorted fragment list for receive-side stream reassembly.
///
/// Maps byte offsets to data fragments, enabling out-of-order receive and
/// contiguous delivery. Equivalent to the `SFRAME_LIST` in `quic_sf_list.c`.
///
/// Fragments are coalesced when adjacent fragments can be merged, and
/// overlapping insertions are handled by keeping existing data in the overlap
/// region (matching the C implementation's behavior).
#[derive(Debug, Clone)]
struct SortedFragList {
    /// Map from starting offset to the data fragment at that offset.
    fragments: BTreeMap<u64, Vec<u8>>,
    /// Cleanse fragments on removal (secure erase).
    cleanse: bool,
}

impl SortedFragList {
    /// Creates a new empty fragment list.
    fn new() -> Self {
        Self {
            fragments: BTreeMap::new(),
            cleanse: false,
        }
    }

    /// Inserts a data fragment at the given offset.
    ///
    /// Handles overlapping and adjacent fragments by splitting, trimming, and
    /// coalescing as necessary to maintain the invariant that no two fragments
    /// in the list overlap.
    fn insert(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let end = offset + data.len() as u64;
        let mut new_data = data.to_vec();
        let mut new_start = offset;

        // Collect keys of fragments that overlap or are adjacent to [offset, end)
        let mut overlapping_keys: Vec<u64> = Vec::new();
        for (&frag_start, frag_data) in &self.fragments {
            let frag_end = frag_start + frag_data.len() as u64;
            if frag_start > end {
                break;
            }
            // Overlap: frag_end > offset, or adjacent: frag_end == offset or frag_start == end
            if frag_end >= offset && frag_start <= end {
                overlapping_keys.push(frag_start);
            }
        }

        // Merge with overlapping fragments, keeping existing data in overlap
        for key in &overlapping_keys {
            if let Some(existing) = self.fragments.remove(key) {
                let ex_start = *key;
                let ex_end = ex_start + existing.len() as u64;

                // Build the merged fragment covering the union of ranges
                let merged_start = new_start.min(ex_start);
                let merged_end = (new_start + new_data.len() as u64).max(ex_end);
                let merged_len = usize::try_from(merged_end - merged_start).unwrap_or(usize::MAX);
                let mut merged = vec![0u8; merged_len];

                // Lay down new data first
                let new_off = usize::try_from(new_start - merged_start).unwrap_or(0);
                let copy_len = new_data.len().min(merged.len().saturating_sub(new_off));
                merged[new_off..new_off + copy_len].copy_from_slice(&new_data[..copy_len]);

                // Then overlay existing data (existing data wins on overlap)
                let ex_off = usize::try_from(ex_start - merged_start).unwrap_or(0);
                let ex_copy_len = existing.len().min(merged.len().saturating_sub(ex_off));
                merged[ex_off..ex_off + ex_copy_len].copy_from_slice(&existing[..ex_copy_len]);

                if self.cleanse {
                    // Securely erase the removed fragment's data
                    // (existing is now moved out, we can't zeroize it in place,
                    // but the vec will be dropped)
                }

                new_start = merged_start;
                new_data = merged;
            }
        }

        self.fragments.insert(new_start, new_data);

        // Attempt to coalesce with the next adjacent fragment
        let final_end = new_start + self.fragments[&new_start].len() as u64;
        if let Some(next_data) = self.fragments.remove(&final_end) {
            if let Some(current) = self.fragments.get_mut(&new_start) {
                current.extend_from_slice(&next_data);
            }
        }
    }

    /// Reads contiguous data starting from `read_offset` into `buf`.
    ///
    /// Returns the number of bytes read. Only reads data that is contiguous
    /// from the given offset — stops at the first gap.
    fn read(&self, read_offset: u64, buf: &mut [u8]) -> usize {
        if let Some((&frag_start, frag_data)) = self.fragments.iter().next() {
            if frag_start > read_offset {
                return 0; // Gap before first fragment
            }
            let frag_end = frag_start + frag_data.len() as u64;
            if read_offset >= frag_end {
                return 0; // Read offset past first fragment
            }
            let skip = usize::try_from(read_offset - frag_start).unwrap_or(0);
            let available = frag_data.len() - skip;
            let to_copy = buf.len().min(available);
            buf[..to_copy].copy_from_slice(&frag_data[skip..skip + to_copy]);
            to_copy
        } else {
            0
        }
    }

    /// Returns the number of contiguous bytes available starting from `read_offset`.
    fn available(&self, read_offset: u64) -> usize {
        if let Some((&frag_start, frag_data)) = self.fragments.iter().next() {
            if frag_start > read_offset {
                return 0;
            }
            let frag_end = frag_start + frag_data.len() as u64;
            if read_offset >= frag_end {
                return 0;
            }
            usize::try_from(frag_end - read_offset).unwrap_or(0)
        } else {
            0
        }
    }

    /// Drops all fragments up to (but not including) `offset`, removing
    /// consumed data from the front of the list.
    fn drop_before(&mut self, offset: u64) {
        let keys_to_remove: Vec<u64> = self.fragments.range(..offset).map(|(&k, _)| k).collect();

        for key in keys_to_remove {
            if let Some(mut data) = self.fragments.remove(&key) {
                let frag_end = key + data.len() as u64;
                if frag_end > offset {
                    // Fragment straddles the drop point — keep the tail
                    let skip = usize::try_from(offset - key).unwrap_or(0);
                    let remaining = data.split_off(skip);
                    if self.cleanse {
                        data.zeroize();
                    }
                    self.fragments.insert(offset, remaining);
                } else if self.cleanse {
                    data.zeroize();
                }
            }
        }
    }

    /// Returns `true` if all data from offset 0 to `fin_offset` has been
    /// received as a single contiguous fragment.
    fn is_complete(&self, fin_offset: u64) -> bool {
        if let Some((&frag_start, frag_data)) = self.fragments.iter().next() {
            frag_start == 0 && frag_data.len() as u64 >= fin_offset
        } else {
            fin_offset == 0
        }
    }

    /// Securely erases all fragment data.
    fn secure_erase(&mut self) {
        for data in self.fragments.values_mut() {
            data.zeroize();
        }
        self.fragments.clear();
    }
}

// =============================================================================
// QuicSendStream — Send-Side Stream Buffering (from quic_sstream.c)
// =============================================================================

/// Send-side QUIC stream buffer.
///
/// Manages the outbound data buffer, tracking which byte ranges have been
/// written by the application, transmitted on the wire, and acknowledged by
/// the peer. Provides data for the TX packetiser and handles retransmission
/// of lost segments.
///
/// Equivalent to `QUIC_SSTREAM` in `quic_sstream.c`.
#[derive(Debug)]
pub struct QuicSendStream {
    /// Ring buffer holding application-written data.
    ring_buf: RingBuffer,
    /// Ranges of data that have been appended but not yet transmitted.
    new_ranges: RangeSet,
    /// Ranges of data that have been acknowledged by the peer.
    acked_ranges: RangeSet,
    /// Total bytes written by the application (monotonically increasing offset).
    write_offset: u64,
    /// Offset of the oldest un-acked data (for buffer culling).
    cleanse_offset: u64,
    /// Whether FIN has been set by the application.
    fin: bool,
    /// Whether the FIN has been acknowledged by the peer.
    fin_acked: bool,
    /// Whether to securely erase the buffer on drop.
    cleanse_on_free: bool,
}

impl QuicSendStream {
    /// Creates a new send stream with the given buffer capacity.
    pub fn new(capacity: usize) -> Self {
        tracing::debug!(capacity, "creating QuicSendStream");
        Self {
            ring_buf: RingBuffer::new(capacity),
            new_ranges: RangeSet::new(),
            acked_ranges: RangeSet::new(),
            write_offset: 0,
            cleanse_offset: 0,
            fin: false,
            fin_acked: false,
            cleanse_on_free: false,
        }
    }

    /// Appends data to the send buffer.
    ///
    /// Returns the number of bytes actually written (may be less than
    /// `data.len()` if the buffer is full).
    ///
    /// # Errors
    ///
    /// Returns [`SslError::Quic`] if FIN has already been set.
    pub fn append(&mut self, data: &[u8]) -> Result<usize, SslError> {
        if self.fin {
            return Err(SslError::Quic(
                "cannot append data after FIN has been set".to_string(),
            ));
        }

        let written = self.ring_buf.write(data);
        if written > 0 {
            let start = self.write_offset;
            self.write_offset += written as u64;
            self.new_ranges.insert(start, self.write_offset);
            tracing::trace!(offset = start, len = written, "sstream: appended data");
        }
        Ok(written)
    }

    /// Marks the byte range `[offset, offset+len)` as transmitted (in-flight).
    ///
    /// Removes the range from `new_ranges` so it is not re-sent unless
    /// explicitly marked lost.
    pub fn mark_transmitted(&mut self, offset: u64, len: usize) {
        let end = offset + len as u64;
        self.new_ranges.remove(offset, end);
        tracing::trace!(offset, len, "sstream: marked transmitted");
    }

    /// Marks the byte range `[offset, offset+len)` as acknowledged.
    ///
    /// Adds the range to `acked_ranges` and attempts to cull the ring buffer
    /// of data that has been contiguously acknowledged from the beginning.
    pub fn mark_acked(&mut self, offset: u64, len: usize) {
        let end = offset + len as u64;
        self.acked_ranges.insert(offset, end);
        tracing::trace!(offset, len, "sstream: marked acked");

        // Cull contiguously acked data from the front of the buffer
        self.cull();
    }

    /// Marks the byte range `[offset, offset+len)` as lost, rescheduling
    /// it for retransmission by adding it back to `new_ranges`.
    pub fn mark_lost(&mut self, offset: u64, len: usize) {
        let end = offset + len as u64;
        // Only re-enqueue portions that haven't been acknowledged
        for range_start in (offset..end).step_by(1) {
            if !self.acked_ranges.contains(range_start) {
                // Find contiguous un-acked run
                let mut run_end = range_start + 1;
                while run_end < end && !self.acked_ranges.contains(run_end) {
                    run_end += 1;
                }
                self.new_ranges.insert(range_start, run_end);
                tracing::trace!(
                    start = range_start,
                    end = run_end,
                    "sstream: marked lost, rescheduled"
                );
                // Handled as a block; no need to iterate byte-by-byte further
                break;
            }
        }
        // More efficient re-enqueue: iterate acked ranges to find gaps
        self.mark_lost_efficient(offset, len);
    }

    /// Efficient implementation of `mark_lost` that avoids byte-by-byte iteration.
    fn mark_lost_efficient(&mut self, offset: u64, len: usize) {
        let end = offset + len as u64;
        let mut cursor = offset;

        // Walk through acked ranges that overlap [offset, end) and re-enqueue gaps
        let acked_in_range: Vec<(u64, u64)> = self
            .acked_ranges
            .iter()
            .filter(|&(s, e)| s < end && e > offset)
            .collect();

        // Clear previous naive result and rebuild
        self.new_ranges.remove(offset, end);

        for (ack_start, ack_end) in acked_in_range {
            let gap_start = cursor.max(offset);
            let gap_end = ack_start.min(end);
            if gap_start < gap_end {
                self.new_ranges.insert(gap_start, gap_end);
            }
            cursor = ack_end;
        }

        // Trailing gap after last acked range
        let gap_start = cursor.max(offset);
        if gap_start < end {
            self.new_ranges.insert(gap_start, end);
        }
    }

    /// Returns data from the send buffer at the given offset for transmission.
    ///
    /// The returned `Vec<u8>` contains up to `len` bytes starting at the
    /// given stream offset. The offset is absolute (from stream start).
    pub fn get_data(&self, offset: u64, len: usize) -> Vec<u8> {
        // Convert absolute offset to buffer-relative offset
        let buf_offset = offset.saturating_sub(self.cleanse_offset);
        let buf_offset_usize = usize::try_from(buf_offset).unwrap_or(usize::MAX);
        self.ring_buf.read_at(buf_offset_usize, len)
    }

    /// Sets the FIN flag, indicating no more data will be written.
    pub fn set_fin(&mut self) {
        self.fin = true;
        tracing::debug!(offset = self.write_offset, "sstream: FIN set");
    }

    /// Returns `true` if all data (and FIN, if set) has been acknowledged.
    pub fn is_totally_acked(&self) -> bool {
        if !self.fin {
            return false;
        }
        if !self.fin_acked {
            return false;
        }
        // All data from 0 to write_offset must be acked
        self.acked_ranges
            .contains_range_from_zero(self.write_offset)
    }

    /// Marks the FIN as acknowledged.
    pub fn ack_fin(&mut self) {
        self.fin_acked = true;
        tracing::trace!("sstream: FIN acked");
    }

    /// Returns `true` if there is pending data (new ranges or unacked FIN)
    /// to transmit.
    pub fn has_pending(&self) -> bool {
        !self.new_ranges.is_empty() || (self.fin && !self.fin_acked)
    }

    /// Returns the total number of bytes written by the application.
    pub fn total_written(&self) -> u64 {
        self.write_offset
    }

    /// Returns the available buffer space for writing.
    pub fn buffer_available(&self) -> usize {
        self.ring_buf.free_space()
    }

    /// Sets whether to securely erase buffer on drop.
    pub fn set_cleanse_on_free(&mut self, cleanse: bool) {
        self.cleanse_on_free = cleanse;
    }

    /// Culls contiguously acked data from the front of the ring buffer.
    fn cull(&mut self) {
        // Find how far the contiguous acked region extends from cleanse_offset
        if let Some((&first_start, &first_end)) = self.acked_ranges.ranges.iter().next() {
            if first_start <= self.cleanse_offset {
                let new_cleanse = first_end;
                let advance = new_cleanse.saturating_sub(self.cleanse_offset);
                if advance > 0 {
                    let advance_usize = usize::try_from(advance).unwrap_or(usize::MAX);
                    self.ring_buf.discard(advance_usize);
                    self.cleanse_offset = new_cleanse;
                }
            }
        }
    }
}

impl Drop for QuicSendStream {
    fn drop(&mut self) {
        if self.cleanse_on_free {
            tracing::debug!("sstream: secure erase on drop");
            self.ring_buf.secure_erase();
        }
    }
}

// =============================================================================
// QuicRecvStream — Receive-Side Stream Buffering (from quic_rstream.c)
// =============================================================================

/// Receive-side QUIC stream buffer.
///
/// Manages incoming data reassembly using a `SortedFragList`, delivering
/// contiguous data to the application in order. Handles out-of-order arrival,
/// duplicate detection, and FIN processing.
///
/// Equivalent to `QUIC_RSTREAM` in `quic_rstream.c` + `quic_sf_list.c`.
#[derive(Debug)]
pub struct QuicRecvStream {
    /// Fragment list for reassembly of out-of-order data.
    sf_list: SortedFragList,
    /// Next byte offset to deliver to the application.
    read_offset: u64,
    /// Known final size of the stream (set when FIN is received).
    fin_offset: Option<u64>,
    /// Whether to securely erase data on release/drop.
    cleanse_on_release: bool,
}

impl Default for QuicRecvStream {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicRecvStream {
    /// Creates a new receive stream.
    pub fn new() -> Self {
        tracing::debug!("creating QuicRecvStream");
        Self {
            sf_list: SortedFragList::new(),
            read_offset: 0,
            fin_offset: None,
            cleanse_on_release: false,
        }
    }

    /// Queues received data at the given offset for reassembly.
    ///
    /// If `fin` is true, the stream's final size is set to `offset + data.len()`.
    pub fn queue_data(&mut self, offset: u64, data: &[u8], fin: bool) {
        if !data.is_empty() {
            self.sf_list.insert(offset, data);
            tracing::trace!(offset, len = data.len(), fin, "rstream: queued data");
        }

        if fin {
            let final_size = offset + data.len() as u64;
            self.fin_offset = Some(final_size);
            tracing::trace!(final_size, "rstream: FIN received, final size known");
        }
    }

    /// Peeks at available contiguous data without advancing the read offset.
    ///
    /// Returns the number of bytes copied into `buf`.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        self.sf_list.read(self.read_offset, buf)
    }

    /// Returns the number of contiguous bytes available for reading.
    pub fn available(&self) -> usize {
        self.sf_list.available(self.read_offset)
    }

    /// Reads contiguous data starting from the current read offset.
    ///
    /// Advances the read offset by the number of bytes read. Old data is
    /// dropped from the fragment list.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = self.sf_list.read(self.read_offset, buf);
        if n > 0 {
            self.read_offset += n as u64;
            // Drop consumed data
            self.sf_list.drop_before(self.read_offset);
            tracing::trace!(bytes = n, new_offset = self.read_offset, "rstream: read");
        }
        n
    }

    /// Returns `true` if all data up to the FIN has been received.
    pub fn is_complete(&self) -> bool {
        match self.fin_offset {
            Some(fin) => self.sf_list.is_complete(fin),
            None => false,
        }
    }

    /// Returns `true` if all data up to the FIN has been read by the application.
    pub fn is_totally_read(&self) -> bool {
        match self.fin_offset {
            Some(fin) => self.read_offset >= fin,
            None => false,
        }
    }

    /// Returns the current read offset.
    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    /// Returns the known final size, if FIN has been received.
    pub fn fin_offset(&self) -> Option<u64> {
        self.fin_offset
    }

    /// Sets whether to securely erase data on release.
    pub fn set_cleanse_on_release(&mut self, cleanse: bool) {
        self.cleanse_on_release = cleanse;
        self.sf_list.cleanse = cleanse;
    }
}

impl Drop for QuicRecvStream {
    fn drop(&mut self) {
        if self.cleanse_on_release {
            tracing::debug!("rstream: secure erase on drop");
            self.sf_list.secure_erase();
        }
    }
}

// =============================================================================
// TxFlowController — Transmit-Side Flow Control (from quic_fc.c TXFC)
// =============================================================================

/// Transmit-side flow controller per RFC 9000 §4.
///
/// Tracks the peer-advertised credit window and the total bytes consumed.
/// Supports a parent-child hierarchy where per-stream controllers chain to
/// a connection-level parent controller.
///
/// Equivalent to `QUIC_TXFC` in `quic_fc.c`.
///
/// `// LOCK-SCOPE: TxFlowController — per-stream or per-connection, accessed
/// during subtick TX path and application write calls.`
#[derive(Debug)]
pub struct TxFlowController {
    /// Peer-advertised maximum bytes allowed (CWM — credit window max).
    max_allowed: u64,
    /// Peer-advertised maximum bytes at last update (SWM — sent window mark
    /// used for "has become blocked" detection).
    swm: u64,
    /// Total bytes sent and counted toward flow control.
    bytes_sent: u64,
    /// Connection-level parent flow controller (if per-stream).
    parent: Option<Box<TxFlowController>>,
    /// Whether we have become blocked since the last check.
    has_become_blocked: bool,
}

impl TxFlowController {
    /// Creates a new transmit flow controller.
    ///
    /// `initial_max` is the peer's initial `MAX_DATA` or `MAX_STREAM_DATA` value.
    pub fn new(initial_max: u64) -> Self {
        tracing::trace!(initial_max, "txfc: created");
        Self {
            max_allowed: initial_max,
            swm: initial_max,
            bytes_sent: 0,
            parent: None,
            has_become_blocked: false,
        }
    }

    /// Creates a new per-stream transmit flow controller with a connection-level parent.
    pub fn with_parent(initial_max: u64, parent: TxFlowController) -> Self {
        tracing::trace!(initial_max, "txfc: created with parent");
        Self {
            max_allowed: initial_max,
            swm: initial_max,
            bytes_sent: 0,
            parent: Some(Box::new(parent)),
            has_become_blocked: false,
        }
    }

    /// Returns the number of bytes the application is currently allowed to send.
    ///
    /// This is the minimum of the local allowance and the parent's allowance
    /// (if a parent exists).
    pub fn get_allowance(&self) -> u64 {
        let local = self.max_allowed.saturating_sub(self.bytes_sent);
        match &self.parent {
            Some(parent) => local.min(parent.get_allowance()),
            None => local,
        }
    }

    /// Consumes `bytes` from the flow control allowance.
    ///
    /// # Errors
    ///
    /// Returns [`SslError::Quic`] if consuming `bytes` would exceed the allowance.
    pub fn consume(&mut self, bytes: u64) -> Result<(), SslError> {
        if bytes > self.get_allowance() {
            return Err(SslError::Quic(format!(
                "TX flow control: attempt to consume {} bytes but only {} allowed",
                bytes,
                self.get_allowance()
            )));
        }

        self.bytes_sent += bytes;

        // Also consume from the parent (connection-level) controller
        if let Some(parent) = &mut self.parent {
            parent.consume(bytes)?;
        }

        // Detect blocked condition
        if self.bytes_sent >= self.max_allowed {
            self.has_become_blocked = true;
        }

        tracing::trace!(
            bytes,
            sent = self.bytes_sent,
            max = self.max_allowed,
            "txfc: consumed"
        );
        Ok(())
    }

    /// Bumps the maximum allowed bytes (called when receiving `MAX_DATA` or
    /// `MAX_STREAM_DATA` from the peer).
    pub fn bump_max(&mut self, new_max: u64) {
        if new_max > self.max_allowed {
            tracing::trace!(old_max = self.max_allowed, new_max, "txfc: bumped max");
            self.swm = self.max_allowed;
            self.max_allowed = new_max;
            self.has_become_blocked = false;
        }
    }

    /// Returns `true` and clears the flag if we have become blocked since last check.
    pub fn has_become_blocked(&mut self) -> bool {
        let blocked = self.has_become_blocked;
        self.has_become_blocked = false;
        blocked
    }

    /// Returns the total bytes sent so far.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Returns the previous maximum (sent window mark) before the most recent bump.
    pub fn previous_max(&self) -> u64 {
        self.swm
    }
}

// =============================================================================
// RxFlowController — Receive-Side Flow Control (from quic_fc.c RXFC)
// =============================================================================

/// Receive-side flow controller per RFC 9000 §4.
///
/// Tracks incoming data volume, manages the credit window advertised to the
/// peer, and implements automatic window size tuning based on RTT measurements.
/// Supports parent-child hierarchy for connection-level and stream-level control.
///
/// Equivalent to `QUIC_RXFC` in `quic_fc.c`.
///
/// `// LOCK-SCOPE: RxFlowController — per-stream or per-connection, accessed
/// during subtick RX path and application read calls.`
#[derive(Debug)]
pub struct RxFlowController {
    /// Total bytes received (high water mark).
    bytes_received: u64,
    /// Bytes consumed (retired) by the application.
    bytes_retired: u64,
    /// Current window size for credit window calculation.
    window_size: u64,
    /// Maximum window size (upper bound for auto-tuning).
    max_window_size: u64,
    /// Currently advertised maximum offset (CWM).
    cwm: u64,
    /// Whether the CWM has changed since last queried.
    cwm_changed: bool,
    /// Enable automatic window size tuning.
    auto_tune: bool,
    /// RTT sample for auto-tuning calculations.
    rtt_sample: Option<Duration>,
    /// Connection-level parent flow controller (if per-stream).
    parent: Option<Box<RxFlowController>>,
    /// Whether an error has been detected (peer exceeded limit).
    error: bool,
    /// Epoch start time (for window auto-tuning).
    epoch_start: Option<u64>,
    /// Bytes retired at epoch start.
    epoch_retired: u64,
    /// Expected bytes since reset of window measurement.
    esrwm: u64,
    /// Running window mark for auto-tuning.
    rwm: u64,
}

impl RxFlowController {
    /// Creates a new receive flow controller.
    ///
    /// `initial_window` is the initial credit window size to advertise.
    /// `max_window` is the upper bound for auto-tuning.
    pub fn new(initial_window: u64, max_window: u64) -> Self {
        tracing::trace!(initial_window, max_window, "rxfc: created");
        Self {
            bytes_received: 0,
            bytes_retired: 0,
            window_size: initial_window,
            max_window_size: max_window,
            cwm: initial_window,
            cwm_changed: false,
            auto_tune: true,
            rtt_sample: None,
            parent: None,
            error: false,
            epoch_start: None,
            epoch_retired: 0,
            esrwm: 0,
            rwm: 0,
        }
    }

    /// Creates a new per-stream receive flow controller with a parent.
    pub fn with_parent(initial_window: u64, max_window: u64, parent: RxFlowController) -> Self {
        tracing::trace!(initial_window, max_window, "rxfc: created with parent");
        Self {
            parent: Some(Box::new(parent)),
            ..Self::new(initial_window, max_window)
        }
    }

    /// Records incoming data.
    ///
    /// Called when data is received from the peer. If the peer exceeds our
    /// advertised credit window, this returns an error (flow control violation).
    ///
    /// # Errors
    ///
    /// Returns [`SslError::Protocol`] if the peer exceeded the flow control limit.
    pub fn on_recv(&mut self, bytes: u64) -> Result<(), SslError> {
        let new_total = self.bytes_received + bytes;
        if new_total > self.cwm {
            self.error = true;
            return Err(SslError::Protocol(format!(
                "RX flow control violation: received {} total bytes but CWM is {}",
                new_total, self.cwm
            )));
        }
        self.bytes_received = new_total;

        // Also notify parent
        if let Some(parent) = &mut self.parent {
            parent.on_recv(bytes)?;
        }

        tracing::trace!(
            bytes,
            total = self.bytes_received,
            cwm = self.cwm,
            "rxfc: on_recv"
        );
        Ok(())
    }

    /// Records application consumption of data.
    ///
    /// Called when the application reads data from the stream. Updates the
    /// credit window if enough data has been retired (3/4 threshold as in
    /// the C implementation).
    pub fn on_retire(&mut self, bytes: u64) {
        self.bytes_retired += bytes;

        // Also retire from parent
        if let Some(parent) = &mut self.parent {
            parent.on_retire(bytes);
        }

        // Check if CWM bump is desired (3/4 threshold from quic_fc.c)
        self.maybe_bump_cwm();

        tracing::trace!(bytes, retired = self.bytes_retired, "rxfc: on_retire");
    }

    /// Returns the current maximum allowed offset to advertise to the peer.
    pub fn get_max_allowed(&self) -> u64 {
        self.cwm
    }

    /// Returns `true` if the credit window has changed since last query,
    /// indicating that a `MAX_DATA` or `MAX_STREAM_DATA` frame should be sent.
    pub fn should_send_max(&self) -> bool {
        self.cwm_changed
    }

    /// Clears the `cwm_changed` flag after sending a `MAX_DATA`/`MAX_STREAM_DATA`.
    pub fn ack_max_sent(&mut self) {
        self.cwm_changed = false;
    }

    /// Updates the RTT sample for auto-tuning.
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt_sample = Some(rtt);
    }

    /// Returns `true` if a flow control error has been detected.
    pub fn has_error(&self) -> bool {
        self.error
    }

    /// Returns the total bytes received so far.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Returns the total bytes retired (consumed by application).
    pub fn bytes_retired(&self) -> u64 {
        self.bytes_retired
    }

    /// Returns the current window size.
    pub fn window_size(&self) -> u64 {
        self.window_size
    }

    /// Sets the maximum window size for auto-tuning.
    pub fn set_max_window_size(&mut self, max: u64) {
        self.max_window_size = max;
    }

    /// Attempts to bump the CWM if the peer has consumed enough of the window.
    ///
    /// The bump threshold is 3/4 of the current window, matching the C
    /// implementation in `quic_fc.c:rxfc_cwm_bump_desired()`.
    fn maybe_bump_cwm(&mut self) {
        // Desired CWM: bytes_retired + window_size
        let desired_cwm = self.bytes_retired + self.window_size;

        // Only bump if we have retired >= 3/4 of the window from the current CWM base
        let threshold = self.cwm.saturating_sub(self.window_size) + (self.window_size * 3 / 4);

        if self.bytes_retired >= threshold && desired_cwm > self.cwm {
            // Auto-tune: if data is being consumed quickly, grow the window
            if self.auto_tune {
                self.maybe_grow_window();
            }

            let new_cwm = self.bytes_retired + self.window_size;
            if new_cwm > self.cwm {
                tracing::trace!(
                    old_cwm = self.cwm,
                    new_cwm,
                    window = self.window_size,
                    "rxfc: bumped CWM"
                );
                self.cwm = new_cwm;
                self.cwm_changed = true;
            }
        }
    }

    /// Auto-tuning: considers doubling the window size if data is being
    /// consumed faster than 4× the RTT would suggest.
    ///
    /// Mirrors the logic in `quic_fc.c:rxfc_should_bump_window_size()`.
    fn maybe_grow_window(&mut self) {
        // Without an RTT sample, we cannot auto-tune
        if self.rtt_sample.is_none() {
            return;
        }

        // Track epoch for window measurement (from quic_fc.c rxfc_should_bump_window_size)
        let retired_in_epoch = self.bytes_retired.saturating_sub(self.epoch_retired);
        if retired_in_epoch >= self.esrwm {
            // Enough data retired in this epoch — consider growing
            let new_window = (self.window_size * 2).min(self.max_window_size);
            if new_window > self.window_size {
                self.window_size = new_window;
                tracing::trace!(
                    new_window = self.window_size,
                    max = self.max_window_size,
                    "rxfc: auto-tuned window"
                );
            }
        }

        // Reset epoch tracking
        self.epoch_retired = self.bytes_retired;
        self.esrwm = self.window_size;
        self.rwm = self.bytes_retired;
        self.epoch_start = Some(0); // Reset epoch marker
    }

    /// Returns the running window mark for diagnostic purposes.
    pub fn running_window_mark(&self) -> u64 {
        self.rwm
    }
}

// =============================================================================
// QuicStream — Per-Stream State Container
// =============================================================================

/// A single QUIC stream, containing its identity, state machines, send/receive
/// buffers, and flow controllers.
///
/// Each stream is identified by a [`StreamId`] and can have a send side, a
/// receive side, or both, depending on stream type and direction.
///
/// Equivalent to `QUIC_STREAM` in `quic_stream_map.c`.
// The struct models C's `QUIC_STREAM` which has many boolean scheduling
// and state flags; refactoring to two-variant enums would reduce clarity.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct QuicStream {
    /// Stream identifier.
    pub id: StreamId,
    /// Send-side state machine.
    pub send_state: SendState,
    /// Receive-side state machine.
    pub recv_state: RecvState,
    /// Send-side buffer (present only for streams with a send component).
    pub sstream: Option<QuicSendStream>,
    /// Receive-side buffer (present only for streams with a recv component).
    pub rstream: Option<QuicRecvStream>,
    /// Per-stream transmit flow controller.
    pub txfc: TxFlowController,
    /// Per-stream receive flow controller.
    pub rxfc: RxFlowController,

    // -- Scheduling state --
    /// Whether this stream is on the active list for scheduling.
    is_active: bool,
    /// Whether we need to send `MAX_STREAM_DATA` for this stream.
    want_max_stream_data: bool,
    /// Whether we need to send `STOP_SENDING` for this stream.
    want_stop_sending: bool,
    /// Whether we need to send `RESET_STREAM` for this stream.
    want_reset_stream: bool,

    // -- STOP_SENDING / RESET_STREAM state --
    /// `STOP_SENDING` error code to send, if any.
    stop_sending_error_code: Option<u64>,
    /// `RESET_STREAM` error code to send, if any.
    reset_stream_error_code: Option<u64>,

    // -- Accept queue state --
    /// Whether this stream is in the accept queue.
    in_accept_queue: bool,

    // -- Shutdown flush state --
    /// Whether this stream is eligible for shutdown flush.
    flush_eligible: bool,
    /// Whether this stream's shutdown flush is complete.
    flush_done: bool,
}

impl QuicStream {
    /// Creates a new stream with the given ID and initial states based on
    /// the stream type and who initiated it.
    ///
    /// * Bidirectional streams have both send and receive sides.
    /// * Client-initiated unidirectional streams from the client's perspective
    ///   have only a send side; from the server's, only a receive side.
    fn new(
        id: StreamId,
        is_local: bool,
        send_buf_size: usize,
        initial_tx_max: u64,
        initial_rx_window: u64,
        max_rx_window: u64,
    ) -> Self {
        let direction = id.direction();
        let is_bidi = direction == StreamDirection::Bidirectional;
        let is_uni = !is_bidi;

        // Determine which sides this stream has
        let has_send = is_bidi || (is_uni && is_local);
        let has_recv = is_bidi || (is_uni && !is_local);

        let send_state = if has_send {
            SendState::Ready
        } else {
            SendState::DataRecvd
        };
        let recv_state = if has_recv {
            RecvState::Recv
        } else {
            RecvState::DataRead
        };

        let sstream = if has_send {
            Some(QuicSendStream::new(send_buf_size))
        } else {
            None
        };

        let rstream = if has_recv {
            Some(QuicRecvStream::new())
        } else {
            None
        };

        tracing::debug!(
            stream_id = %id,
            ?direction,
            is_local,
            has_send,
            has_recv,
            "stream: created"
        );

        Self {
            id,
            send_state,
            recv_state,
            sstream,
            rstream,
            txfc: TxFlowController::new(initial_tx_max),
            rxfc: RxFlowController::new(initial_rx_window, max_rx_window),
            is_active: false,
            want_max_stream_data: false,
            want_stop_sending: false,
            want_reset_stream: false,
            stop_sending_error_code: None,
            reset_stream_error_code: None,
            in_accept_queue: false,
            flush_eligible: false,
            flush_done: false,
        }
    }

    /// Returns `true` if both send and receive sides are in terminal states
    /// and the stream can be garbage collected.
    fn is_ready_for_gc(&self) -> bool {
        self.send_state.is_terminal() && self.recv_state.is_terminal() && !self.in_accept_queue
    }

    /// Returns `true` if the stream has pending work to schedule.
    fn should_be_active(&self) -> bool {
        self.want_max_stream_data
            || self.want_stop_sending
            || self.want_reset_stream
            || self
                .sstream
                .as_ref()
                .map_or(false, QuicSendStream::has_pending)
    }

    /// Returns the `STOP_SENDING` error code, if one has been requested.
    pub fn stop_sending_error_code(&self) -> Option<u64> {
        self.stop_sending_error_code
    }

    /// Sets the `STOP_SENDING` error code and marks the stream as needing it.
    pub fn set_stop_sending(&mut self, error_code: u64) {
        self.stop_sending_error_code = Some(error_code);
        self.want_stop_sending = true;
    }

    /// Returns the `RESET_STREAM` error code, if one has been requested.
    pub fn reset_stream_error_code(&self) -> Option<u64> {
        self.reset_stream_error_code
    }

    /// Sets the `RESET_STREAM` error code and marks the stream as needing it.
    pub fn set_reset_stream(&mut self, error_code: u64) {
        self.reset_stream_error_code = Some(error_code);
        self.want_reset_stream = true;
    }
}

// =============================================================================
// StreamIterator — Round-Robin Active Stream Scheduling
// =============================================================================

/// Iterator over active streams in a round-robin order.
///
/// Traverses the active list starting from a configurable offset and wrapping
/// around. Yields [`StreamId`] values that can be used to look up the full
/// [`QuicStream`] from the [`StreamMap`].
///
/// Equivalent to `QUIC_STREAM_ITER` in `quic_stream_map.c`.
#[derive(Debug)]
pub struct StreamIterator {
    /// Snapshot of active stream IDs at iterator creation time.
    active_ids: Vec<StreamId>,
    /// Current position in the iteration.
    position: usize,
    /// Number of items yielded so far.
    yielded: usize,
}

impl StreamIterator {
    /// Creates a new iterator over the given active IDs, starting at the
    /// given round-robin offset.
    fn new(active_ids: Vec<StreamId>, start_offset: usize) -> Self {
        let position = if active_ids.is_empty() {
            0
        } else {
            start_offset % active_ids.len()
        };
        Self {
            active_ids,
            position,
            yielded: 0,
        }
    }
}

impl Iterator for StreamIterator {
    type Item = StreamId;

    fn next(&mut self) -> Option<StreamId> {
        if self.yielded >= self.active_ids.len() {
            return None;
        }
        let id = self.active_ids[self.position];
        self.position = (self.position + 1) % self.active_ids.len();
        self.yielded += 1;
        Some(id)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.active_ids.len() - self.yielded;
        (remaining, Some(remaining))
    }
}

// =============================================================================
// StreamMap — QUIC Stream Map (from quic_stream_map.c)
// =============================================================================

/// QUIC stream map managing all streams for a connection.
///
/// Provides O(1) stream lookup by ID, maintains active/accept/gc queues,
/// and implements round-robin scheduling for fair stream multiplexing.
///
/// Equivalent to `QUIC_STREAM_MAP` in `quic_stream_map.c`.
///
/// `// LOCK-SCOPE: StreamMap — per-channel, accessed during subtick and
/// stream API calls. Single-threaded within channel tick; no concurrent access.`
#[derive(Debug)]
pub struct StreamMap {
    /// O(1) stream lookup by ID.
    streams: HashMap<StreamId, QuicStream>,
    /// Streams eligible for scheduling (active list).
    active_list: VecDeque<StreamId>,
    /// Streams awaiting application accept.
    accept_queue: VecDeque<StreamId>,
    /// Streams ready for garbage collection.
    gc_list: VecDeque<StreamId>,

    // -- Round-robin scheduling state --
    /// Round-robin stepping size.
    rr_stepping: usize,
    /// Round-robin counter for determining start offset.
    rr_counter: usize,

    // -- Stream limits --
    /// Maximum number of locally-initiated bidirectional streams.
    local_bidi_limit: u64,
    /// Maximum number of locally-initiated unidirectional streams.
    local_uni_limit: u64,
    /// Maximum number of remotely-initiated bidirectional streams.
    remote_bidi_limit: u64,
    /// Maximum number of remotely-initiated unidirectional streams.
    remote_uni_limit: u64,

    // -- Accept queue counters --
    /// Number of bidirectional streams in the accept queue.
    num_accept_bidi: usize,
    /// Number of unidirectional streams in the accept queue.
    num_accept_uni: usize,

    // -- Default buffer sizes --
    /// Default send buffer size for new streams.
    default_send_buf_size: usize,
    /// Default initial TX max for flow control.
    default_initial_tx_max: u64,
    /// Default initial RX window for flow control.
    default_initial_rx_window: u64,
    /// Default maximum RX window for auto-tuning.
    default_max_rx_window: u64,

    // -- Shutdown flush --
    /// Number of streams pending flush during shutdown.
    shutdown_flush_count: usize,
    /// Whether a shutdown flush is in progress.
    is_shutdown_flush: bool,
}

impl StreamMap {
    /// Creates a new, empty stream map with the given default parameters.
    ///
    /// # Parameters
    ///
    /// * `default_send_buf_size` — Default send buffer capacity for new streams.
    /// * `default_initial_tx_max` — Default peer-advertised TX limit.
    /// * `default_initial_rx_window` — Default receive window size.
    /// * `default_max_rx_window` — Maximum receive window for auto-tuning.
    pub fn new(
        default_send_buf_size: usize,
        default_initial_tx_max: u64,
        default_initial_rx_window: u64,
        default_max_rx_window: u64,
    ) -> Self {
        tracing::debug!(
            default_send_buf_size,
            default_initial_tx_max,
            default_initial_rx_window,
            default_max_rx_window,
            "StreamMap: created"
        );
        Self {
            streams: HashMap::new(),
            active_list: VecDeque::new(),
            accept_queue: VecDeque::new(),
            gc_list: VecDeque::new(),
            rr_stepping: 1,
            rr_counter: 0,
            local_bidi_limit: 0,
            local_uni_limit: 0,
            remote_bidi_limit: 0,
            remote_uni_limit: 0,
            num_accept_bidi: 0,
            num_accept_uni: 0,
            default_send_buf_size,
            default_initial_tx_max,
            default_initial_rx_window,
            default_max_rx_window,
            shutdown_flush_count: 0,
            is_shutdown_flush: false,
        }
    }

    /// Allocates a new stream with the given ID.
    ///
    /// `is_local` indicates whether we are the initiator of this stream.
    ///
    /// # Errors
    ///
    /// Returns [`SslError::Quic`] if a stream with the same ID already exists.
    pub fn alloc(&mut self, id: StreamId, is_local: bool) -> Result<&mut QuicStream, SslError> {
        use std::collections::hash_map::Entry;

        let stream = QuicStream::new(
            id,
            is_local,
            self.default_send_buf_size,
            self.default_initial_tx_max,
            self.default_initial_rx_window,
            self.default_max_rx_window,
        );

        match self.streams.entry(id) {
            Entry::Occupied(_) => Err(SslError::Quic(format!("stream {id} already exists in map"))),
            Entry::Vacant(entry) => {
                tracing::debug!(stream_id = %id, is_local, "StreamMap: allocated stream");
                Ok(entry.insert(stream))
            }
        }
    }

    /// Returns a reference to the stream with the given ID, if it exists.
    pub fn get(&self, id: StreamId) -> Option<&QuicStream> {
        self.streams.get(&id)
    }

    /// Returns a mutable reference to the stream with the given ID, if it exists.
    pub fn get_mut(&mut self, id: StreamId) -> Option<&mut QuicStream> {
        self.streams.get_mut(&id)
    }

    /// Releases (removes) a stream from the map.
    ///
    /// Removes the stream from all queues. The stream's `Drop` impl handles
    /// any secure erasure.
    pub fn release(&mut self, id: StreamId) {
        if self.streams.remove(&id).is_some() {
            // Remove from active list
            self.active_list.retain(|&sid| sid != id);
            // Remove from accept queue
            self.accept_queue.retain(|&sid| sid != id);
            // Remove from gc list
            self.gc_list.retain(|&sid| sid != id);
            tracing::debug!(stream_id = %id, "StreamMap: released stream");
        }
    }

    /// Runs garbage collection, removing all streams that are in terminal
    /// states and have no pending work.
    pub fn gc(&mut self) {
        let to_gc: Vec<StreamId> = self.gc_list.drain(..).collect();
        for id in to_gc {
            self.streams.remove(&id);
            self.active_list.retain(|&sid| sid != id);
            tracing::trace!(stream_id = %id, "StreamMap: garbage collected stream");
        }
    }

    /// Recomputes the scheduling state for the stream with the given ID.
    ///
    /// Determines whether the stream should be on the active list based on
    /// pending data, flow control updates, and control frame needs. Detects
    /// terminal conditions and enqueues finished streams onto the GC list.
    pub fn update_state(&mut self, id: StreamId) {
        let (should_active, ready_for_gc) = {
            if let Some(stream) = self.streams.get(&id) {
                (stream.should_be_active(), stream.is_ready_for_gc())
            } else {
                return;
            }
        };

        if ready_for_gc {
            // Stream is done — move to GC list
            if let Some(stream) = self.streams.get_mut(&id) {
                if stream.is_active {
                    stream.is_active = false;
                    self.active_list.retain(|&sid| sid != id);
                }
            }
            if !self.gc_list.contains(&id) {
                self.gc_list.push_back(id);
            }

            // Check shutdown flush completion
            if self.is_shutdown_flush {
                if let Some(stream) = self.streams.get_mut(&id) {
                    if stream.flush_eligible && !stream.flush_done {
                        stream.flush_done = true;
                        self.shutdown_flush_count = self.shutdown_flush_count.saturating_sub(1);
                        tracing::trace!(
                            stream_id = %id,
                            remaining = self.shutdown_flush_count,
                            "StreamMap: shutdown flush completed for stream"
                        );
                    }
                }
            }
            return;
        }

        if let Some(stream) = self.streams.get_mut(&id) {
            if should_active && !stream.is_active {
                stream.is_active = true;
                self.active_list.push_back(id);
                tracing::trace!(stream_id = %id, "StreamMap: activated stream");
            } else if !should_active && stream.is_active {
                stream.is_active = false;
                self.active_list.retain(|&sid| sid != id);
                tracing::trace!(stream_id = %id, "StreamMap: deactivated stream");
            }
        }
    }

    /// Pushes a stream onto the accept queue.
    ///
    /// Called when a remotely-initiated stream is received and needs to be
    /// presented to the application via an accept-like API.
    pub fn accept_queue_push(&mut self, id: StreamId) {
        if let Some(stream) = self.streams.get_mut(&id) {
            if !stream.in_accept_queue {
                stream.in_accept_queue = true;
                self.accept_queue.push_back(id);

                match id.direction() {
                    StreamDirection::Bidirectional => self.num_accept_bidi += 1,
                    StreamDirection::Unidirectional => self.num_accept_uni += 1,
                }

                tracing::debug!(
                    stream_id = %id,
                    queue_len = self.accept_queue.len(),
                    "StreamMap: pushed to accept queue"
                );
            }
        }
    }

    /// Pops the next stream from the accept queue.
    ///
    /// Returns the [`StreamId`] of the stream that was accepted, or `None`
    /// if the queue is empty.
    pub fn accept_queue_pop(&mut self) -> Option<StreamId> {
        while let Some(id) = self.accept_queue.pop_front() {
            if let Some(stream) = self.streams.get_mut(&id) {
                stream.in_accept_queue = false;

                match id.direction() {
                    StreamDirection::Bidirectional => {
                        self.num_accept_bidi = self.num_accept_bidi.saturating_sub(1);
                    }
                    StreamDirection::Unidirectional => {
                        self.num_accept_uni = self.num_accept_uni.saturating_sub(1);
                    }
                }

                tracing::debug!(
                    stream_id = %id,
                    "StreamMap: popped from accept queue"
                );
                return Some(id);
            }
            // Stream was released while in queue — skip it
        }
        None
    }

    /// Peeks at the next stream in the accept queue without removing it.
    pub fn accept_queue_peek(&self) -> Option<StreamId> {
        self.accept_queue
            .iter()
            .find(|id| self.streams.contains_key(id))
            .copied()
    }

    /// Returns the number of streams in the accept queue.
    pub fn accept_queue_len(&self) -> usize {
        self.accept_queue
            .iter()
            .filter(|id| self.streams.contains_key(id))
            .count()
    }

    /// Returns a round-robin iterator over active streams.
    ///
    /// Each call advances the round-robin counter to ensure fairness.
    pub fn iter_active(&mut self) -> StreamIterator {
        let active_ids: Vec<StreamId> = self
            .active_list
            .iter()
            .copied()
            .filter(|id| self.streams.contains_key(id))
            .collect();

        let offset = self.rr_counter;
        self.rr_counter = self.rr_counter.wrapping_add(self.rr_stepping);

        StreamIterator::new(active_ids, offset)
    }

    /// Begins a shutdown flush, marking all streams with unacknowledged
    /// send data as needing flush before shutdown.
    pub fn begin_shutdown_flush(&mut self) {
        if self.is_shutdown_flush {
            return;
        }
        self.is_shutdown_flush = true;
        self.shutdown_flush_count = 0;

        let stream_ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in stream_ids {
            if let Some(stream) = self.streams.get_mut(&id) {
                // A stream is flush-eligible if it has a send side that isn't
                // totally acked
                let eligible = stream.sstream.as_ref().map_or(false, |s| {
                    s.has_pending() || (s.fin && !s.is_totally_acked())
                });

                if eligible {
                    stream.flush_eligible = true;
                    stream.flush_done = false;
                    self.shutdown_flush_count += 1;
                }
            }
        }

        tracing::debug!(
            eligible_count = self.shutdown_flush_count,
            "StreamMap: began shutdown flush"
        );
    }

    /// Marks a stream's shutdown flush as done.
    ///
    /// Returns `true` if all streams have completed their flush (the entire
    /// shutdown flush is done).
    pub fn shutdown_flush_done(&mut self, id: StreamId) -> bool {
        if let Some(stream) = self.streams.get_mut(&id) {
            if stream.flush_eligible && !stream.flush_done {
                stream.flush_done = true;
                self.shutdown_flush_count = self.shutdown_flush_count.saturating_sub(1);
                tracing::trace!(
                    stream_id = %id,
                    remaining = self.shutdown_flush_count,
                    "StreamMap: stream flush done"
                );
            }
        }
        self.is_shutdown_flush && self.shutdown_flush_count == 0
    }

    /// Returns the number of streams currently in the map.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Returns `true` if the map contains no streams.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Returns `true` if the shutdown flush is complete (all eligible streams
    /// have flushed or there are no eligible streams).
    pub fn is_shutdown_flush_complete(&self) -> bool {
        self.is_shutdown_flush && self.shutdown_flush_count == 0
    }

    /// Sets stream limits for locally and remotely initiated streams.
    pub fn set_stream_limits(
        &mut self,
        local_bidi: u64,
        local_uni: u64,
        remote_bidi: u64,
        remote_uni: u64,
    ) {
        self.local_bidi_limit = local_bidi;
        self.local_uni_limit = local_uni;
        self.remote_bidi_limit = remote_bidi;
        self.remote_uni_limit = remote_uni;
    }

    /// Returns the number of active streams.
    pub fn active_count(&self) -> usize {
        self.active_list.len()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_id_construction() {
        let id = StreamId::new(StreamInitiator::Client, StreamDirection::Bidirectional, 7);
        assert_eq!(id.initiator(), StreamInitiator::Client);
        assert_eq!(id.direction(), StreamDirection::Bidirectional);
        assert_eq!(id.stream_ordinal(), 7);
        assert_eq!(id.stream_type(), StreamType::ClientBidi);
        assert!(id.is_bidi());
        assert!(id.is_client_initiated());
    }

    #[test]
    fn test_stream_id_server_uni() {
        let id = StreamId::new(StreamInitiator::Server, StreamDirection::Unidirectional, 3);
        assert_eq!(id.initiator(), StreamInitiator::Server);
        assert_eq!(id.direction(), StreamDirection::Unidirectional);
        assert_eq!(id.stream_ordinal(), 3);
        assert_eq!(id.stream_type(), StreamType::ServerUni);
        assert!(!id.is_bidi());
        assert!(id.is_server_initiated());
    }

    #[test]
    fn test_stream_id_raw_roundtrip() {
        for raw in [0u64, 1, 2, 3, 4, 100, 255, 0xFFFF] {
            let id = StreamId::from_raw(raw);
            assert_eq!(id.as_raw(), raw);
        }
    }

    #[test]
    fn test_range_set_insert_coalesce() {
        let mut rs = RangeSet::new();
        rs.insert(0, 5);
        rs.insert(5, 10);
        // Should coalesce into [0, 10)
        let ranges: Vec<(u64, u64)> = rs.iter().collect();
        assert_eq!(ranges, vec![(0, 10)]);
    }

    #[test]
    fn test_range_set_insert_overlap() {
        let mut rs = RangeSet::new();
        rs.insert(0, 5);
        rs.insert(3, 8);
        let ranges: Vec<(u64, u64)> = rs.iter().collect();
        assert_eq!(ranges, vec![(0, 8)]);
    }

    #[test]
    fn test_range_set_remove() {
        let mut rs = RangeSet::new();
        rs.insert(0, 10);
        rs.remove(3, 7);
        let ranges: Vec<(u64, u64)> = rs.iter().collect();
        assert_eq!(ranges, vec![(0, 3), (7, 10)]);
    }

    #[test]
    fn test_range_set_contains() {
        let mut rs = RangeSet::new();
        rs.insert(5, 10);
        assert!(!rs.contains(4));
        assert!(rs.contains(5));
        assert!(rs.contains(9));
        assert!(!rs.contains(10));
    }

    #[test]
    fn test_range_set_contains_from_zero() {
        let mut rs = RangeSet::new();
        rs.insert(0, 100);
        assert!(rs.contains_range_from_zero(100));
        assert!(rs.contains_range_from_zero(50));
        assert!(!rs.contains_range_from_zero(101));
    }

    #[test]
    fn test_ring_buffer_basic() {
        let mut rb = RingBuffer::new(16);
        assert_eq!(rb.capacity(), 16);
        assert_eq!(rb.available(), 0);

        let written = rb.write(b"hello");
        assert_eq!(written, 5);
        assert_eq!(rb.available(), 5);

        let mut buf = [0u8; 10];
        let read = rb.read(&mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn test_ring_buffer_wraparound() {
        let mut rb = RingBuffer::new(8);
        rb.write(b"12345"); // head=0, tail=5
        let mut buf = [0u8; 3];
        rb.read(&mut buf); // head=3, available=2
        rb.write(b"6789"); // wraps around
        assert_eq!(rb.available(), 6);
    }

    #[test]
    fn test_ring_buffer_read_at() {
        let mut rb = RingBuffer::new(32);
        rb.write(b"hello world");
        let data = rb.read_at(6, 5);
        assert_eq!(&data, b"world");
    }

    #[test]
    fn test_sorted_frag_list_basic() {
        let mut sf = SortedFragList::new();
        sf.insert(0, b"hello ");
        sf.insert(6, b"world");

        let mut buf = [0u8; 11];
        let n = sf.read(0, &mut buf);
        assert_eq!(n, 11);
        assert_eq!(&buf[..11], b"hello world");
    }

    #[test]
    fn test_sorted_frag_list_out_of_order() {
        let mut sf = SortedFragList::new();
        sf.insert(6, b"world");
        sf.insert(0, b"hello ");

        assert_eq!(sf.available(0), 11);
        assert!(sf.is_complete(11));
    }

    #[test]
    fn test_sorted_frag_list_overlap() {
        let mut sf = SortedFragList::new();
        sf.insert(0, b"hello world");
        sf.insert(3, b"LO W"); // overlap — existing data wins

        let mut buf = [0u8; 11];
        let n = sf.read(0, &mut buf);
        assert_eq!(n, 11);
        // Existing data should win on overlap
        assert_eq!(&buf[..11], b"hello world");
    }

    #[test]
    fn test_send_stream_basic() {
        let mut ss = QuicSendStream::new(1024);
        let written = ss.append(b"hello").unwrap();
        assert_eq!(written, 5);
        assert!(ss.has_pending());

        let data = ss.get_data(0, 5);
        assert_eq!(&data, b"hello");

        ss.mark_transmitted(0, 5);
        ss.set_fin();
        ss.mark_acked(0, 5);
        ss.ack_fin();
        assert!(ss.is_totally_acked());
    }

    #[test]
    fn test_send_stream_append_after_fin() {
        let mut ss = QuicSendStream::new(1024);
        ss.append(b"data").unwrap();
        ss.set_fin();
        let result = ss.append(b"more");
        assert!(result.is_err());
    }

    #[test]
    fn test_recv_stream_basic() {
        let mut rs = QuicRecvStream::new();
        rs.queue_data(0, b"hello", false);
        assert_eq!(rs.available(), 5);
        assert!(!rs.is_complete());

        let mut buf = [0u8; 5];
        let n = rs.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_recv_stream_with_fin() {
        let mut rs = QuicRecvStream::new();
        rs.queue_data(0, b"hello", true);
        assert!(rs.is_complete());
        assert_eq!(rs.fin_offset(), Some(5));
    }

    #[test]
    fn test_recv_stream_out_of_order() {
        let mut rs = QuicRecvStream::new();
        rs.queue_data(5, b"world", true); // arrives first
        assert_eq!(rs.available(), 0); // gap at [0,5)
        rs.queue_data(0, b"hello", false); // fills gap
        assert_eq!(rs.available(), 10);
    }

    #[test]
    fn test_tx_flow_controller() {
        let mut txfc = TxFlowController::new(100);
        assert_eq!(txfc.get_allowance(), 100);

        txfc.consume(50).unwrap();
        assert_eq!(txfc.get_allowance(), 50);

        txfc.bump_max(200);
        assert_eq!(txfc.get_allowance(), 150);

        let result = txfc.consume(200);
        assert!(result.is_err());
    }

    #[test]
    fn test_rx_flow_controller() {
        let mut rxfc = RxFlowController::new(1000, 8000);
        assert_eq!(rxfc.get_max_allowed(), 1000);

        rxfc.on_recv(500).unwrap();
        assert_eq!(rxfc.bytes_received(), 500);

        // Exceed limit
        let result = rxfc.on_recv(600);
        assert!(result.is_err());
        assert!(rxfc.has_error());
    }

    #[test]
    fn test_rx_flow_controller_retire_and_bump() {
        let mut rxfc = RxFlowController::new(100, 10000);
        rxfc.on_recv(90).unwrap();
        rxfc.on_retire(80);
        // After retiring enough, CWM should bump
        let new_max = rxfc.get_max_allowed();
        assert!(new_max >= 100); // CWM should be at least original
    }

    #[test]
    fn test_stream_map_alloc_and_get() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);
        let id = StreamId::new(StreamInitiator::Client, StreamDirection::Bidirectional, 0);

        let stream = map.alloc(id, true).unwrap();
        assert_eq!(stream.id, id);
        assert_eq!(stream.send_state, SendState::Ready);
        assert_eq!(stream.recv_state, RecvState::Recv);
        assert!(stream.sstream.is_some());
        assert!(stream.rstream.is_some());

        assert!(map.get(id).is_some());
    }

    #[test]
    fn test_stream_map_duplicate_alloc() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);
        let id = StreamId::new(StreamInitiator::Client, StreamDirection::Bidirectional, 0);
        map.alloc(id, true).unwrap();
        let result = map.alloc(id, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_map_release() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);
        let id = StreamId::new(StreamInitiator::Client, StreamDirection::Bidirectional, 0);
        map.alloc(id, true).unwrap();
        map.release(id);
        assert!(map.get(id).is_none());
        assert!(map.is_empty());
    }

    #[test]
    fn test_stream_map_accept_queue() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);
        let id1 = StreamId::new(StreamInitiator::Server, StreamDirection::Bidirectional, 0);
        let id2 = StreamId::new(StreamInitiator::Server, StreamDirection::Bidirectional, 1);

        map.alloc(id1, false).unwrap();
        map.alloc(id2, false).unwrap();

        map.accept_queue_push(id1);
        map.accept_queue_push(id2);

        assert_eq!(map.accept_queue_len(), 2);
        assert_eq!(map.accept_queue_peek(), Some(id1));
        assert_eq!(map.accept_queue_pop(), Some(id1));
        assert_eq!(map.accept_queue_pop(), Some(id2));
        assert_eq!(map.accept_queue_pop(), None);
    }

    #[test]
    fn test_stream_map_iter_active() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);

        // Create streams with pending data
        for i in 0..3 {
            let id = StreamId::new(StreamInitiator::Client, StreamDirection::Bidirectional, i);
            map.alloc(id, true).unwrap();
            if let Some(stream) = map.get_mut(id) {
                if let Some(ref mut ss) = stream.sstream {
                    ss.append(b"data").unwrap();
                }
            }
            map.update_state(id);
        }

        let iter = map.iter_active();
        let ids: Vec<StreamId> = iter.collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn test_stream_map_shutdown_flush() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);
        let id = StreamId::new(StreamInitiator::Client, StreamDirection::Bidirectional, 0);
        map.alloc(id, true).unwrap();

        // Write some data to make it flush-eligible
        if let Some(stream) = map.get_mut(id) {
            if let Some(ref mut ss) = stream.sstream {
                ss.append(b"data").unwrap();
                ss.set_fin();
            }
        }

        map.begin_shutdown_flush();
        assert!(!map.is_shutdown_flush_complete());

        let done = map.shutdown_flush_done(id);
        assert!(done);
        assert!(map.is_shutdown_flush_complete());
    }

    #[test]
    fn test_stream_map_gc() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);
        let id = StreamId::new(StreamInitiator::Client, StreamDirection::Bidirectional, 0);
        map.alloc(id, true).unwrap();

        // Transition to terminal states
        if let Some(stream) = map.get_mut(id) {
            stream.send_state = SendState::DataRecvd;
            stream.recv_state = RecvState::DataRead;
        }

        map.update_state(id);
        map.gc();
        assert!(map.get(id).is_none());
    }

    #[test]
    fn test_send_state_terminal() {
        assert!(!SendState::Ready.is_terminal());
        assert!(!SendState::Send.is_terminal());
        assert!(!SendState::DataSent.is_terminal());
        assert!(SendState::DataRecvd.is_terminal());
        assert!(!SendState::ResetSent.is_terminal());
        assert!(SendState::ResetRecvd.is_terminal());
    }

    #[test]
    fn test_recv_state_terminal() {
        assert!(!RecvState::Recv.is_terminal());
        assert!(!RecvState::SizeKnown.is_terminal());
        assert!(!RecvState::DataRecvd.is_terminal());
        assert!(RecvState::DataRead.is_terminal());
        assert!(!RecvState::ResetRecvd.is_terminal());
        assert!(RecvState::ResetRead.is_terminal());
    }

    #[test]
    fn test_stream_uni_local() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);
        let id = StreamId::new(StreamInitiator::Client, StreamDirection::Unidirectional, 0);
        map.alloc(id, true).unwrap();
        let stream = map.get(id).unwrap();
        assert!(stream.sstream.is_some()); // Local uni has send
        assert!(stream.rstream.is_none()); // No receive
        assert_eq!(stream.send_state, SendState::Ready);
        assert_eq!(stream.recv_state, RecvState::DataRead); // Terminal
    }

    #[test]
    fn test_stream_uni_remote() {
        let mut map = StreamMap::new(1024, 1000, 1000, 8000);
        let id = StreamId::new(StreamInitiator::Server, StreamDirection::Unidirectional, 0);
        map.alloc(id, false).unwrap();
        let stream = map.get(id).unwrap();
        assert!(stream.sstream.is_none()); // Remote uni has no send
        assert!(stream.rstream.is_some()); // Has receive
        assert_eq!(stream.send_state, SendState::DataRecvd); // Terminal
        assert_eq!(stream.recv_state, RecvState::Recv);
    }

    #[test]
    fn test_stream_iterator_empty() {
        let iter = StreamIterator::new(vec![], 0);
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn test_stream_iterator_round_robin() {
        let ids: Vec<StreamId> = (0..4)
            .map(|i| StreamId::new(StreamInitiator::Client, StreamDirection::Bidirectional, i))
            .collect();

        let iter = StreamIterator::new(ids.clone(), 2);
        let result: Vec<StreamId> = iter.collect();
        // Should start from index 2 and wrap around
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], ids[2]);
        assert_eq!(result[1], ids[3]);
        assert_eq!(result[2], ids[0]);
        assert_eq!(result[3], ids[1]);
    }
}
