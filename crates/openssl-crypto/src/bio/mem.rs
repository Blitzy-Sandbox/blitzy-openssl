//! In-memory BIO implementations for the OpenSSL Rust workspace.
//!
//! Provides memory-backed I/O abstractions for buffering, testing, and
//! in-process communication. Translates C memory BIOs from `bss_mem.c`
//! and `bss_bio.c` into safe Rust types.
//!
//! ## Types
//!
//! - [`MemBio`] — Growable memory buffer (replaces `BIO_s_mem()` / `BIO_new_mem_buf()`)
//! - [`SecureMemBio`] — Secure memory buffer with zeroing on drop (replaces `BIO_s_secmem()`)
//! - [`BioPairEnd`] — One half of a bidirectional in-process stream pair
//!   (replaces `BIO_new_bio_pair()`)
//! - [`new_bio_pair`] — Create a connected pair of [`BioPairEnd`] instances
//!
//! ## Design
//!
//! Uses `bytes::BytesMut` for efficient zero-copy buffer management in
//! [`MemBio`] and [`BioPairEnd`]. Memory BIOs support both growable
//! read-write and fixed read-only modes. [`SecureMemBio`] uses
//! [`SecureVec`] to guarantee automatic zeroing of sensitive data on
//! drop, matching C `BIO_s_secmem()` semantics.
//!
//! ## Empty-buffer read semantics (replaces C `bio->num` sentinel)
//!
//! When the buffer is empty:
//! - With `eof_on_empty = true` → [`Read::read`] returns `Ok(0)` (EOF)
//! - With `eof_on_empty = false` → [`Read::read`] returns
//!   `Err(io::ErrorKind::WouldBlock)` (caller should retry)
//!
//! Read-write [`MemBio`] defaults to `eof_on_empty = false` (retry semantics),
//! read-only [`MemBio`] created via [`MemBio::from_slice`] defaults to `true`
//! (EOF semantics). Read-write behavior mirrors C `BIO_set_mem_eof_return(bio, 0)`
//! which sets `bio->num = 0` (retry).
//!
//! ## Safety
//!
//! This module contains ZERO `unsafe` blocks. All buffer operations use
//! safe `bytes::BytesMut` APIs and the [`SecureVec`] wrapper which itself
//! derives `ZeroizeOnDrop` from the `zeroize` crate.

use std::cmp::min;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use zeroize::Zeroize;

use openssl_common::mem::SecureVec;
use openssl_common::{CryptoError, CryptoResult};

use super::{Bio, BioStats, BioType};

// ---------------------------------------------------------------------------
// MemBio — replaces C BIO_s_mem() / BIO_new_mem_buf() from bss_mem.c
// ---------------------------------------------------------------------------

/// Growable in-memory BIO backed by [`bytes::BytesMut`].
///
/// Replaces C `BIO_s_mem()` and `BIO_new_mem_buf()` from `crypto/bio/bss_mem.c`.
///
/// Supports two modes:
/// - **Read-write mode** (default, via [`MemBio::new`] or [`MemBio::with_capacity`]):
///   Data written via [`Write::write`] is appended to the end of the buffer.
///   Data read via [`Read::read`] is consumed from the front in O(1) via
///   [`BytesMut::split_to`]. The buffer grows automatically as needed.
///
/// - **Read-only mode** (via [`MemBio::from_slice`]): The buffer is
///   initialised from an external slice and [`Write::write`] is rejected
///   with [`io::ErrorKind::PermissionDenied`]. [`MemBio::reset`] restores
///   the buffer to its original contents.
///
/// The empty-buffer read behaviour is controlled by [`MemBio::set_eof_on_empty`]:
/// see the module-level documentation for details.
///
/// Uses [`bytes::BytesMut`] for zero-copy buffer management with O(1) front
/// consumption via [`BytesMut::split_to`], replacing C `BUF_MEM` move operations.
#[derive(Debug)]
pub struct MemBio {
    /// Unread portion of the buffer. After each successful read, `split_to(n)`
    /// is called to discard the first `n` bytes in O(1), leaving only the
    /// unread tail.
    buf: BytesMut,
    /// Snapshot of original data for read-only reset.
    ///
    /// `Some(bytes)` in read-only mode — [`MemBio::reset`] will copy these
    /// bytes back into `buf` to restore the read position to the start.
    /// `None` in read-write mode — [`MemBio::reset`] clears `buf` instead.
    ///
    /// Storing [`bytes::Bytes`] (not `Vec<u8>`) gives cheap O(1) cloning
    /// via reference counting when reset is called.
    original: Option<Bytes>,
    /// `true` if this BIO rejects [`Write::write`] calls with
    /// [`io::ErrorKind::PermissionDenied`]. Set by [`MemBio::from_slice`].
    /// Replaces C `BIO_FLAGS_MEM_RDONLY` flag (typed bool per rule R5).
    read_only: bool,
    /// Empty-buffer read behaviour flag.
    /// - `true`  → [`Read::read`] returns `Ok(0)` (EOF) when buffer is empty
    /// - `false` → [`Read::read`] returns `Err(WouldBlock)` when buffer is empty
    ///
    /// Replaces C `bio->num` sentinel (typed bool per rule R5, replacing
    /// the integer encoding `0 = retry`, non-zero = EOF-return-value).
    eof_on_empty: bool,
    /// I/O byte counters required by the [`Bio`] trait.
    stats: BioStats,
}

impl MemBio {
    /// Creates an empty read-write memory BIO.
    ///
    /// Equivalent to C `BIO_new(BIO_s_mem())`. The returned BIO grows its
    /// internal buffer on each [`Write::write`] and returns
    /// [`io::ErrorKind::WouldBlock`] from [`Read::read`] when the buffer is
    /// empty (matching C `bio->num = 0` retry behaviour — the default for
    /// newly-constructed mem BIOs in C).
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            original: None,
            read_only: false,
            // Read-write mem BIOs in C default to `bio->num = 0` meaning
            // "return retry on empty read". Rule R5: encode as typed bool.
            eof_on_empty: false,
            stats: BioStats::new(),
        }
    }

    /// Creates an empty read-write memory BIO with at least `capacity` bytes
    /// of pre-allocated internal storage.
    ///
    /// No C equivalent exists (C uses lazy growth via `BUF_MEM_grow`), but
    /// matching capacity hints are idiomatic in Rust and avoid early
    /// reallocations for known-size workloads.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
            original: None,
            read_only: false,
            eof_on_empty: false,
            stats: BioStats::new(),
        }
    }

    /// Creates a read-only memory BIO from an external byte slice.
    ///
    /// Replaces C `BIO_new_mem_buf(data, len)` from `bss_mem.c` lines 382-395.
    /// The supplied data is copied into an internally-owned [`BytesMut`]
    /// (the C implementation casts away `const` and aliases the caller's
    /// memory — Rust copies for safety, per rule R8).
    ///
    /// The returned BIO:
    /// - Rejects [`Write::write`] with [`io::ErrorKind::PermissionDenied`]
    /// - Returns `Ok(0)` (EOF) from [`Read::read`] when exhausted
    ///   (matching C `BIO_FLAGS_MEM_RDONLY` + default `bio->num` behaviour)
    /// - Supports [`MemBio::reset`] which restores the read position to the
    ///   start of the original data (C `BIO_CTRL_RESET` on read-only mem BIO)
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        let original = Bytes::copy_from_slice(data);
        Self {
            buf: BytesMut::from(data),
            original: Some(original),
            read_only: true,
            // Read-only mem BIOs return EOF (length 0) on exhausted read —
            // this is the normal consumer contract.
            eof_on_empty: true,
            stats: BioStats::new(),
        }
    }

    /// Controls the [`Read::read`] return value when the buffer is empty.
    ///
    /// - `true`  → return `Ok(0)` (EOF)
    /// - `false` → return [`io::ErrorKind::WouldBlock`] (caller should retry)
    ///
    /// Replaces C `BIO_set_mem_eof_return(bio, value)` from `bss_mem.c`,
    /// which stores `value` in `bio->num`. Rule R5: encoded as typed bool
    /// rather than an integer sentinel, since only two behaviours are
    /// semantically meaningful in the Rust [`Read`] model.
    pub fn set_eof_on_empty(&mut self, eof: bool) {
        self.eof_on_empty = eof;
    }

    /// Returns the number of unread bytes currently buffered.
    ///
    /// Replaces C `BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL)` on mem BIO.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.remaining()
    }

    /// Returns `true` if no unread bytes are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.buf.has_remaining()
    }

    /// Returns `true` if this BIO was constructed from a read-only slice.
    ///
    /// Replaces reading C `BIO_FLAGS_MEM_RDONLY` from `bio->flags`.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Returns a view of the unread buffer contents without consuming them.
    ///
    /// Equivalent to C `BIO_get_mem_data(bio, &ptr)` from `bss_mem.c`. The
    /// returned slice is invalidated by subsequent [`Read::read`],
    /// [`Write::write`], [`MemBio::reset`], or [`MemBio::into_bytes`] calls.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.chunk()
    }

    /// Alias for [`MemBio::as_bytes`], matching the C `BIO_get_mem_data` name.
    #[must_use]
    pub fn get_data(&self) -> &[u8] {
        self.as_bytes()
    }

    /// Resets the BIO.
    ///
    /// Replaces C `BIO_ctrl(bio, BIO_CTRL_RESET, ...)` from `bss_mem.c`:
    /// - **Read-write mode**: clears the buffer to length 0
    /// - **Read-only mode**: restores the buffer to its original contents
    ///   so that subsequent reads see the data from the start
    ///
    /// Also resets the [`BioStats`] byte counters.
    pub fn reset(&mut self) {
        match &self.original {
            // Read-only: rewind by re-copying from the preserved original.
            // `Bytes::clone()` is O(1) (reference counted), so this is cheap.
            Some(orig) => {
                self.buf.clear();
                self.buf.extend_from_slice(&orig[..]);
            }
            // Read-write: discard all buffered data.
            None => {
                self.buf.clear();
            }
        }
        self.stats.reset();
    }

    /// Consumes this BIO and returns the underlying unread buffer.
    ///
    /// Useful for handing off the accumulated write-side data to another
    /// consumer (e.g. after encoding a certificate into the BIO, the
    /// resulting DER bytes can be extracted without copying).
    #[must_use]
    pub fn into_bytes(self) -> BytesMut {
        self.buf
    }
}

impl Default for MemBio {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for MemBio {
    /// Constructs a read-write [`MemBio`] containing the given bytes.
    ///
    /// This is distinct from [`MemBio::from_slice`] which creates a
    /// read-only BIO. Use this when the consumer needs to both read the
    /// initial data and append more bytes.
    fn from(data: Vec<u8>) -> Self {
        Self {
            buf: BytesMut::from(&data[..]),
            original: None,
            read_only: false,
            eof_on_empty: false,
            stats: BioStats::new(),
        }
    }
}

impl From<&[u8]> for MemBio {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

impl Read for MemBio {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if !self.buf.has_remaining() {
            if self.eof_on_empty {
                return Ok(0);
            }
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = min(dst.len(), self.buf.remaining());
        if n == 0 {
            // Caller requested a zero-byte read — valid per std::io::Read contract.
            return Ok(0);
        }
        dst[..n].copy_from_slice(&self.buf[..n]);
        // Zero-copy front-consumption per AAP: split_to advances the internal
        // cursor in O(1); the returned BytesMut is immediately dropped.
        let _consumed = self.buf.split_to(n);
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for MemBio {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "write to read-only MemBio",
            ));
        }
        self.buf.put_slice(src);
        self.stats.record_write(src.len());
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Bio for MemBio {
    fn bio_type(&self) -> BioType {
        BioType::Memory
    }

    fn pending(&self) -> usize {
        self.buf.remaining()
    }

    fn eof(&self) -> bool {
        self.eof_on_empty && !self.buf.has_remaining()
    }

    fn reset(&mut self) -> CryptoResult<()> {
        MemBio::reset(self);
        Ok(())
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "memory buffer"
    }
}

// ---------------------------------------------------------------------------
// SecureMemBio — replaces C BIO_s_secmem() from bss_mem.c
// ---------------------------------------------------------------------------

/// Secure in-memory BIO with zero-on-drop guarantee.
///
/// Replaces C `BIO_s_secmem()` from `crypto/bio/bss_mem.c` (lines 358-373).
/// Semantically identical to [`MemBio`] but uses [`SecureVec`] as the
/// backing buffer so that:
///
/// 1. All buffered data is zeroed when the BIO is dropped (automatic via
///    [`SecureVec`]'s `ZeroizeOnDrop` derive)
/// 2. Data consumed by [`Read::read`] is explicitly zeroed before the
///    read position advances, providing forward secrecy for intermediate
///    key-material buffers (matches C `OPENSSL_cleanse()` call in
///    `mem_read()` for secmem BIOs at `bss_mem.c` line ~125)
///
/// Designed for holding sensitive data such as raw key material, PMS,
/// session tickets, and intermediate PEM buffers containing private keys.
#[derive(Debug)]
pub struct SecureMemBio {
    /// Secure buffer. Derives `ZeroizeOnDrop` so that the full buffer is
    /// zeroed when this BIO is dropped.
    buf: SecureVec,
    /// Current read offset within `buf`. Data from index `0..read_pos`
    /// has already been consumed (and zeroed).
    read_pos: usize,
    /// Read-only flag (matches [`MemBio::read_only`]).
    read_only: bool,
    /// EOF-on-empty flag (matches [`MemBio::eof_on_empty`]).
    eof_on_empty: bool,
    /// I/O byte counters required by the [`Bio`] trait.
    stats: BioStats,
}

impl SecureMemBio {
    /// Creates an empty read-write secure memory BIO.
    ///
    /// Equivalent to C `BIO_new(BIO_s_secmem())`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // SecureVec::new takes a capacity argument; 0 = lazy allocation.
            buf: SecureVec::new(0),
            read_pos: 0,
            read_only: false,
            eof_on_empty: false,
            stats: BioStats::new(),
        }
    }

    /// Creates an empty read-write secure memory BIO with at least
    /// `capacity` bytes of pre-allocated secure storage.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: SecureVec::new(capacity),
            read_pos: 0,
            read_only: false,
            eof_on_empty: false,
            stats: BioStats::new(),
        }
    }

    /// Creates a read-only secure memory BIO from an external byte slice.
    ///
    /// The supplied data is copied into an internally-owned [`SecureVec`].
    /// On drop, the copy is zeroed — the caller's original slice is
    /// unchanged (the caller is responsible for its own security handling).
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            buf: SecureVec::from_slice(data),
            read_pos: 0,
            read_only: true,
            eof_on_empty: true,
            stats: BioStats::new(),
        }
    }

    /// Returns the number of unread bytes currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len().saturating_sub(self.read_pos)
    }

    /// Returns `true` if no unread bytes are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Resets the BIO.
    ///
    /// - **Read-write mode**: securely zeroes and clears the buffer
    /// - **Read-only mode**: rewinds the read position to 0 (the buffer
    ///   contents are untouched, matching C `BIO_CTRL_RESET` semantics on
    ///   read-only mem BIO)
    ///
    /// Also resets the [`BioStats`] byte counters.
    pub fn reset(&mut self) {
        if self.read_only {
            // Rewind without clearing — the original data remains available
            // for subsequent reads. SecureVec's ZeroizeOnDrop still applies
            // when the BIO is dropped.
            self.read_pos = 0;
        } else {
            // `SecureVec::clear()` zeroizes data before setting length to 0.
            self.buf.clear();
            self.read_pos = 0;
        }
        self.stats.reset();
    }

    /// Returns a view of the unread buffer contents without consuming them.
    ///
    /// The returned slice is invalidated by subsequent [`Read::read`],
    /// [`Write::write`], or [`SecureMemBio::reset`] calls.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf.as_bytes()[self.read_pos..]
    }
}

impl Default for SecureMemBio {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for SecureMemBio {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let available = self.buf.len().saturating_sub(self.read_pos);
        if available == 0 {
            if self.eof_on_empty {
                return Ok(0);
            }
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = min(dst.len(), available);
        if n == 0 {
            return Ok(0);
        }

        // SecureVec::as_bytes() returns &[u8] of full buffer; slice from read_pos.
        let end = self.read_pos.saturating_add(n);
        dst[..n].copy_from_slice(&self.buf.as_bytes()[self.read_pos..end]);

        // Forward secrecy: zeroize the just-consumed range before advancing —
        // but only for read-write BIOs where the data is truly consumed.
        // For read-only BIOs we preserve the data so that `reset()` can rewind
        // the read position and allow the buffer to be consumed again, matching
        // C `BIO_CTRL_RESET` semantics on a `BIO_new_mem_buf()` BIO.
        //
        // The unconditional zeroization still happens when the SecureMemBio is
        // dropped because `SecureVec` derives `ZeroizeOnDrop`; the only thing
        // skipped here is the mid-lifetime zeroization for the read-only path.
        // Matches C `OPENSSL_cleanse(readp->data, ret)` call in secmem path
        // of `mem_read()` at `bss_mem.c` line ~125. `Zeroize::zeroize()` is
        // dispatched on the mutable slice returned by `SecureVec::as_bytes_mut()`.
        if !self.read_only {
            self.buf.as_bytes_mut()[self.read_pos..end].zeroize();
        }

        self.read_pos = end;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for SecureMemBio {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "write to read-only SecureMemBio",
            ));
        }
        self.buf.extend_from_slice(src);
        self.stats.record_write(src.len());
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Bio for SecureMemBio {
    fn bio_type(&self) -> BioType {
        BioType::Memory
    }

    fn pending(&self) -> usize {
        self.len()
    }

    fn eof(&self) -> bool {
        self.eof_on_empty && self.is_empty()
    }

    fn reset(&mut self) -> CryptoResult<()> {
        SecureMemBio::reset(self);
        Ok(())
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "secure memory buffer"
    }
}

// ---------------------------------------------------------------------------
// BioPairEnd — replaces C BIO_new_bio_pair() from bss_bio.c
// ---------------------------------------------------------------------------

/// Default buffer size for a [`BioPairEnd`] (17 KiB = one TLS record).
///
/// Matches the C `BIO_new_bio_pair()` default from `bss_bio.c` line 48:
/// `#define DEFAULT_BIO_SIZE  (17 * 1024)`.
const DEFAULT_BIO_PAIR_SIZE: usize = 17 * 1024;

/// Shared buffer state between two [`BioPairEnd`] instances.
///
/// Holds the backing [`BytesMut`] plus a close-flag. Accessed under the
/// mutex owned by the relevant [`BioPairEnd`].
///
/// The `max_size` field enforces the application-configured back-pressure
/// ceiling: [`Write::write`] on the producing end rejects data once
/// `data.len() >= max_size`, mirroring C's fixed-size circular buffer in
/// `bss_bio.c` that returns `BIO_should_retry` when full.
#[derive(Debug)]
struct BioPairBuffer {
    /// Pending payload waiting to be consumed by the peer reader.
    /// Grows via [`Write::write`] and shrinks via [`Read::read`]
    /// (using [`BytesMut::split_to`] for O(1) front consumption).
    data: BytesMut,
    /// Maximum permissible `data.len()`. Writes exceeding this cap receive
    /// [`io::ErrorKind::WouldBlock`] (partial writes up to the cap are
    /// permitted). Replaces C `bio->size` field from `struct bio_bio_st`.
    max_size: usize,
    /// Half-close flag. Set by [`BioPairEnd::close_write`] on the producing
    /// end; once set and `data` drains to empty, the peer reader sees EOF
    /// (`Ok(0)`). Replaces C `bio->closed` field.
    closed: bool,
}

impl BioPairBuffer {
    fn new(max_size: usize) -> Self {
        Self {
            data: BytesMut::new(),
            max_size,
            closed: false,
        }
    }
}

/// One half of a bidirectional in-process BIO pair.
///
/// Replaces C `BIO_new_bio_pair()` from `crypto/bio/bss_bio.c` (805 lines).
/// Two [`BioPairEnd`] instances returned from [`new_bio_pair`] are
/// cross-wired so that:
///
/// - Data written to end A via [`Write::write`] becomes readable from
///   end B via [`Read::read`]
/// - Data written to end B becomes readable from end A
///
/// The pair uses two independent shared buffers (one per direction), each
/// with its own byte ceiling enforced at write time, mirroring the C
/// implementation's dual ring buffers.
///
/// ## Synchronisation
///
/// Each direction's buffer is protected by an [`Arc<Mutex<BioPairBuffer>>`]
/// — this allows the two [`BioPairEnd`] instances to be moved to different
/// threads without data races. The [`Bio`] trait requires only `Send`
/// (not `Sync`), so a single [`BioPairEnd`] itself is not shared across
/// threads — only the underlying buffers via [`Arc`].
///
/// // LOCK-SCOPE: one lock per pair direction (not one coarse lock for both).
/// // Each `Mutex` protects the `BytesMut` ring buffer + close flag for a
/// // single direction (producer → peer reader). The two directions are
/// // independent: a thread writing to end A (`tx` lock) does not block a
/// // thread reading from end A (`rx` lock held by peer writer). Rule R7
/// // justification: contention is inherently direction-specific (a write,
/// // then its peer read on the same direction) — splitting the lock matches
/// // the access pattern.
///
/// ## Half-close (EOF)
///
/// Calling [`BioPairEnd::close_write`] on the producing end flags the
/// corresponding direction as closed. Once the peer reader drains any
/// remaining buffered bytes, [`Read::read`] returns `Ok(0)` (EOF) instead
/// of [`io::ErrorKind::WouldBlock`]. Replaces C's half-close via
/// `BIO_shutdown_wr()` at `bss_bio.c` line ~480.
#[derive(Debug)]
pub struct BioPairEnd {
    /// Buffer this end writes to. The peer [`BioPairEnd`] reads from this
    /// same buffer. Incoming writes check `self.tx.lock().data.len()` against
    /// `self.tx.lock().max_size` for back-pressure.
    tx: Arc<Mutex<BioPairBuffer>>,
    /// Buffer the peer writes to; this end consumes from it via [`Read::read`].
    rx: Arc<Mutex<BioPairBuffer>>,
    /// Configured maximum size for *this* end's transmit buffer — used by
    /// [`BioPairEnd::buffer_size`] to report the configured capacity to
    /// callers (matches C `BIO_ctrl(bio, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL)`
    /// from `bss_bio.c` line ~640).
    configured_size: usize,
    /// I/O byte counters required by the [`Bio`] trait.
    stats: BioStats,
}

impl BioPairEnd {
    /// Returns the number of bytes available for reading from this end.
    ///
    /// Replaces C `BIO_ctrl_pending(bio)` on bio-pair BIOs.
    #[must_use]
    pub fn pending(&self) -> usize {
        // Rule R8: Mutex::lock() poison is mapped to 0 (empty) — returning
        // a sentinel error would break the Bio trait contract. Poisoning
        // only happens if a holder thread panicked, which is already a
        // bug in the caller's code.
        match self.rx.lock() {
            Ok(guard) => guard.data.remaining(),
            Err(poisoned) => poisoned.into_inner().data.remaining(),
        }
    }

    /// Returns the number of bytes currently buffered for the peer to read.
    ///
    /// Reports the fill level of *this* end's transmit buffer — i.e., bytes
    /// that this end has [`Write::write`]-n but that the peer has not yet
    /// [`Read::read`]. Replaces C `BIO_wpending(bio)`.
    #[must_use]
    pub fn wpending(&self) -> usize {
        match self.tx.lock() {
            Ok(guard) => guard.data.remaining(),
            Err(poisoned) => poisoned.into_inner().data.remaining(),
        }
    }

    /// Closes the write side of this end.
    ///
    /// After this call:
    /// - [`Write::write`] on this end returns [`io::ErrorKind::BrokenPipe`]
    /// - The peer's [`Read::read`] returns `Ok(0)` (EOF) once buffered
    ///   data is drained
    ///
    /// Replaces C `BIO_shutdown_wr(bio)` from `bss_bio.c` line ~480. This
    /// implements a half-close: the opposite direction (peer writes → this
    /// end reads) remains open and must be closed separately by calling
    /// `close_write` on the peer.
    pub fn close_write(&mut self) {
        let mut guard = match self.tx.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.closed = true;
    }

    /// Returns `true` if [`BioPairEnd::close_write`] was called on this end.
    #[must_use]
    pub fn is_write_closed(&self) -> bool {
        match self.tx.lock() {
            Ok(guard) => guard.closed,
            Err(poisoned) => poisoned.into_inner().closed,
        }
    }

    /// Returns the configured maximum buffer size for this end's transmit
    /// direction.
    ///
    /// Replaces C `BIO_ctrl(bio, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL)` from
    /// `bss_bio.c` line ~640. The returned value is the ceiling on pending
    /// bytes before [`Write::write`] returns a partial or `WouldBlock` result.
    #[must_use]
    pub fn buffer_size(&self) -> usize {
        self.configured_size
    }
}

impl Read for BioPairEnd {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        // Acquire rx lock: this end reads from the buffer the peer writes to.
        let mut guard = self
            .rx
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "BIO pair rx lock poisoned"))?;

        if !guard.data.has_remaining() {
            if guard.closed {
                // Peer has half-closed and drained — EOF.
                // Note: `closed` on the rx side is set by the PEER calling
                // close_write() on its own end. From this end's perspective,
                // the peer has shut down its write side.
                return Ok(0);
            }
            // No data and peer has not closed — caller should retry.
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        let n = min(dst.len(), guard.data.remaining());
        if n == 0 {
            return Ok(0);
        }
        dst[..n].copy_from_slice(&guard.data[..n]);
        // Zero-copy front consumption via split_to (see MemBio::read comments).
        let _consumed = guard.data.split_to(n);

        // Drop the lock before mutating stats — although stats is owned by
        // self, not guarded, keeping locks minimal is good practice.
        drop(guard);

        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for BioPairEnd {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        // Acquire tx lock: this end writes to the buffer the peer reads from.
        let mut guard = self
            .tx
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "BIO pair tx lock poisoned"))?;

        if guard.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "BIO pair write side closed",
            ));
        }

        let used = guard.data.remaining();
        let capacity = guard.max_size;
        let free = capacity.saturating_sub(used);
        if free == 0 {
            // Buffer full and not closed — caller should retry after the
            // peer reads some data.
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        // Partial writes are permitted per the std::io::Write contract when
        // the destination cannot accept all requested bytes (matches C
        // `BIO_write` behaviour on bio-pair when buffer is partially full).
        let n = min(src.len(), free);
        if n == 0 {
            return Ok(0);
        }
        guard.data.put_slice(&src[..n]);

        drop(guard);

        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Bio-pair is in-process memory transport — nothing to flush.
        Ok(())
    }
}

impl Bio for BioPairEnd {
    fn bio_type(&self) -> BioType {
        BioType::BioPair
    }

    fn pending(&self) -> usize {
        BioPairEnd::pending(self)
    }

    fn wpending(&self) -> usize {
        BioPairEnd::wpending(self)
    }

    fn eof(&self) -> bool {
        // EOF iff peer closed its write side AND our receive buffer drained.
        match self.rx.lock() {
            Ok(guard) => guard.closed && !guard.data.has_remaining(),
            Err(poisoned) => {
                let g = poisoned.into_inner();
                g.closed && !g.data.has_remaining()
            }
        }
    }

    fn reset(&mut self) -> CryptoResult<()> {
        // C `BIO_CTRL_RESET` on bio-pair clears BOTH direction buffers
        // (bss_bio.c line ~250). Acquire both locks in a consistent order
        // — pointer address ordering — to prevent deadlock if both ends
        // reset concurrently.
        let tx_ptr = Arc::as_ptr(&self.tx);
        let rx_ptr = Arc::as_ptr(&self.rx);
        let (first, second) = match tx_ptr.cmp(&rx_ptr) {
            std::cmp::Ordering::Less => (&self.tx, &self.rx),
            std::cmp::Ordering::Greater => (&self.rx, &self.tx),
            std::cmp::Ordering::Equal => {
                // Equal pointers would imply a self-pair (impossible via
                // new_bio_pair) — but handle defensively by locking only one.
                let mut g = first_or_err(&self.tx)?;
                g.data.clear();
                g.closed = false;
                self.stats.reset();
                return Ok(());
            }
        };

        let mut g1 = first_or_err(first)?;
        let mut g2 = first_or_err(second)?;

        g1.data.clear();
        g1.closed = false;
        g2.data.clear();
        g2.closed = false;

        drop(g2);
        drop(g1);

        self.stats.reset();
        Ok(())
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "BIO pair"
    }
}

/// Helper that locks an [`Arc<Mutex<BioPairBuffer>>`] and converts poison
/// errors into a [`CryptoError`] suitable for the [`Bio::reset`] contract.
fn first_or_err(
    m: &Arc<Mutex<BioPairBuffer>>,
) -> CryptoResult<std::sync::MutexGuard<'_, BioPairBuffer>> {
    m.lock().map_err(|_| {
        CryptoError::Io(io::Error::new(
            io::ErrorKind::Other,
            "BIO pair lock poisoned during reset",
        ))
    })
}

/// Creates a connected pair of [`BioPairEnd`] instances.
///
/// Replaces C `BIO_new_bio_pair(bio1, size1, bio2, size2)` from
/// `crypto/bio/bss_bio.c` line ~760. Returns `(end_a, end_b)` such that:
///
/// - Data written to `end_a` via [`Write::write`] is readable from `end_b`
///   via [`Read::read`]
/// - Data written to `end_b` is readable from `end_a`
///
/// Buffer size parameters:
/// - `buf_size_a_to_b`: maximum bytes buffered in the `a → b` direction
///   (i.e., the size of `end_a`'s transmit buffer and `end_b`'s receive
///   buffer). A value of `0` selects the default (17 KiB — one TLS record).
/// - `buf_size_b_to_a`: same, for the reverse direction.
///
/// Back-pressure: writes that would exceed the configured buffer size
/// return partial writes (up to the remaining free space) or
/// [`io::ErrorKind::WouldBlock`] if the buffer is already full — matching
/// C's `BIO_should_retry(bio)` semantics.
///
/// ## Example
///
/// ```ignore
/// use std::io::{Read, Write};
/// use openssl_crypto::bio::new_bio_pair;
///
/// let (mut a, mut b) = new_bio_pair(0, 0); // default buffer sizes
/// a.write_all(b"hello").unwrap();
/// let mut got = [0u8; 5];
/// b.read_exact(&mut got).unwrap();
/// assert_eq!(&got, b"hello");
/// ```
#[must_use]
pub fn new_bio_pair(buf_size_a_to_b: usize, buf_size_b_to_a: usize) -> (BioPairEnd, BioPairEnd) {
    let size_ab = if buf_size_a_to_b == 0 {
        DEFAULT_BIO_PAIR_SIZE
    } else {
        buf_size_a_to_b
    };
    let size_ba = if buf_size_b_to_a == 0 {
        DEFAULT_BIO_PAIR_SIZE
    } else {
        buf_size_b_to_a
    };

    // ab_buf: carries data from A (writer) to B (reader).
    let ab_buf = Arc::new(Mutex::new(BioPairBuffer::new(size_ab)));
    // ba_buf: carries data from B (writer) to A (reader).
    let ba_buf = Arc::new(Mutex::new(BioPairBuffer::new(size_ba)));

    // End A: writes to ab_buf, reads from ba_buf.
    let end_a = BioPairEnd {
        tx: Arc::clone(&ab_buf),
        rx: Arc::clone(&ba_buf),
        configured_size: size_ab,
        stats: BioStats::new(),
    };
    // End B: writes to ba_buf, reads from ab_buf.
    let end_b = BioPairEnd {
        tx: Arc::clone(&ba_buf),
        rx: Arc::clone(&ab_buf),
        configured_size: size_ba,
        stats: BioStats::new(),
    };

    (end_a, end_b)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use .unwrap() on values guaranteed to be Some/Ok.
#[allow(clippy::expect_used)] // Tests use .expect() to unwrap known-good Results.
#[allow(clippy::panic)] // Tests use panic!() in exhaustive match arms for error variants.
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};

    // ----- MemBio tests -----

    #[test]
    fn mem_bio_new_is_empty_and_read_write() {
        let mem = MemBio::new();
        assert!(mem.is_empty());
        assert_eq!(mem.len(), 0);
        assert!(!mem.is_read_only());
        assert_eq!(mem.bio_type(), BioType::Memory);
    }

    #[test]
    fn mem_bio_with_capacity_reports_empty() {
        let mem = MemBio::with_capacity(1024);
        assert!(mem.is_empty());
        assert_eq!(mem.len(), 0);
        assert!(!mem.is_read_only());
    }

    #[test]
    fn mem_bio_write_then_read_round_trip() {
        let mut mem = MemBio::new();
        let wrote = mem.write(b"hello world").unwrap();
        assert_eq!(wrote, 11);
        assert_eq!(mem.len(), 11);

        let mut out = [0u8; 11];
        let got = mem.read(&mut out).unwrap();
        assert_eq!(got, 11);
        assert_eq!(&out, b"hello world");
        assert!(mem.is_empty());
    }

    #[test]
    fn mem_bio_partial_read_preserves_unread() {
        let mut mem = MemBio::new();
        mem.write_all(b"abcdefghij").unwrap();

        let mut first = [0u8; 4];
        assert_eq!(mem.read(&mut first).unwrap(), 4);
        assert_eq!(&first, b"abcd");
        assert_eq!(mem.len(), 6);
        assert_eq!(mem.as_bytes(), b"efghij");

        let mut second = [0u8; 10];
        assert_eq!(mem.read(&mut second).unwrap(), 6);
        assert_eq!(&second[..6], b"efghij");
    }

    #[test]
    fn mem_bio_empty_read_returns_would_block_by_default() {
        let mut mem = MemBio::new();
        let mut buf = [0u8; 8];
        let err = mem.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn mem_bio_empty_read_returns_eof_when_configured() {
        let mut mem = MemBio::new();
        mem.set_eof_on_empty(true);
        let mut buf = [0u8; 8];
        let n = mem.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn mem_bio_from_slice_is_read_only_and_eof_on_empty() {
        let mut mem = MemBio::from_slice(b"readonly data");
        assert!(mem.is_read_only());
        assert_eq!(mem.len(), 13);

        let mut out = [0u8; 13];
        assert_eq!(mem.read(&mut out).unwrap(), 13);
        assert_eq!(&out, b"readonly data");

        // Empty read: EOF (default for from_slice).
        let mut more = [0u8; 4];
        assert_eq!(mem.read(&mut more).unwrap(), 0);
    }

    #[test]
    fn mem_bio_write_to_read_only_rejected() {
        let mut mem = MemBio::from_slice(b"fixed");
        let err = mem.write(b"bad").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn mem_bio_reset_read_write_clears_buffer() {
        let mut mem = MemBio::new();
        mem.write_all(b"discard me").unwrap();
        assert_eq!(mem.len(), 10);
        mem.reset();
        assert!(mem.is_empty());
        assert_eq!(mem.stats().bytes_read(), 0);
        assert_eq!(mem.stats().bytes_written(), 0);
    }

    #[test]
    fn mem_bio_reset_read_only_rewinds_to_start() {
        let mut mem = MemBio::from_slice(b"twice");
        let mut out = [0u8; 5];
        assert_eq!(mem.read(&mut out).unwrap(), 5);
        assert!(mem.is_empty());

        mem.reset();
        assert_eq!(mem.len(), 5);
        let mut again = [0u8; 5];
        assert_eq!(mem.read(&mut again).unwrap(), 5);
        assert_eq!(&again, b"twice");
    }

    #[test]
    fn mem_bio_as_bytes_and_get_data_consistent() {
        let mut mem = MemBio::new();
        mem.write_all(b"peek").unwrap();
        assert_eq!(mem.as_bytes(), b"peek");
        assert_eq!(mem.get_data(), b"peek");
        assert_eq!(mem.len(), 4); // not consumed
    }

    #[test]
    fn mem_bio_into_bytes_returns_unread() {
        let mut mem = MemBio::new();
        mem.write_all(b"keep").unwrap();
        let mut consumed = [0u8; 1];
        mem.read_exact(&mut consumed).unwrap();
        let tail = mem.into_bytes();
        assert_eq!(&tail[..], b"eep");
    }

    #[test]
    fn mem_bio_from_vec_is_read_write() {
        let mut mem: MemBio = vec![1u8, 2, 3].into();
        assert!(!mem.is_read_only());
        mem.write_all(&[4, 5]).unwrap();
        assert_eq!(mem.as_bytes(), &[1u8, 2, 3, 4, 5]);
    }

    #[test]
    fn mem_bio_from_ref_slice_is_read_only() {
        let data: &[u8] = b"borrowed";
        let mem: MemBio = data.into();
        assert!(mem.is_read_only());
    }

    #[test]
    fn mem_bio_default_is_new() {
        let mem = MemBio::default();
        assert!(mem.is_empty());
        assert!(!mem.is_read_only());
    }

    #[test]
    fn mem_bio_bio_trait_reset_and_eof() {
        let mut mem = MemBio::from_slice(b"abc");
        assert!(!mem.eof());
        let mut out = [0u8; 3];
        mem.read_exact(&mut out).unwrap();
        assert!(mem.eof());
        <MemBio as Bio>::reset(&mut mem).unwrap();
        assert!(!mem.eof());
    }

    #[test]
    fn mem_bio_method_name() {
        let mem = MemBio::new();
        assert_eq!(<MemBio as Bio>::method_name(&mem), "memory buffer");
    }

    #[test]
    fn mem_bio_stats_update_on_io() {
        let mut mem = MemBio::new();
        mem.write_all(b"xyz").unwrap();
        assert_eq!(mem.stats().bytes_written(), 3);
        let mut out = [0u8; 3];
        mem.read_exact(&mut out).unwrap();
        assert_eq!(mem.stats().bytes_read(), 3);
    }

    // ----- SecureMemBio tests -----

    #[test]
    fn secure_mem_bio_new_is_empty() {
        let smb = SecureMemBio::new();
        assert!(smb.is_empty());
        assert_eq!(smb.len(), 0);
    }

    #[test]
    fn secure_mem_bio_with_capacity_is_empty() {
        let smb = SecureMemBio::with_capacity(256);
        assert!(smb.is_empty());
    }

    #[test]
    fn secure_mem_bio_write_then_read_round_trip() {
        let mut smb = SecureMemBio::new();
        smb.write_all(b"secret material").unwrap();
        assert_eq!(smb.len(), 15);

        let mut out = [0u8; 15];
        smb.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"secret material");
        assert!(smb.is_empty());
    }

    #[test]
    fn secure_mem_bio_from_slice_is_read_only() {
        let mut smb = SecureMemBio::from_slice(b"key!");
        let mut out = [0u8; 4];
        smb.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"key!");

        // Write to read-only rejected.
        let err = smb.write(b"x").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn secure_mem_bio_empty_read_would_block_by_default() {
        let mut smb = SecureMemBio::new();
        let mut buf = [0u8; 4];
        let err = smb.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn secure_mem_bio_from_slice_empty_read_is_eof() {
        let mut smb = SecureMemBio::from_slice(b"ro");
        let mut out = [0u8; 2];
        smb.read_exact(&mut out).unwrap();
        let mut more = [0u8; 1];
        assert_eq!(smb.read(&mut more).unwrap(), 0);
    }

    #[test]
    fn secure_mem_bio_reset_read_write_clears() {
        let mut smb = SecureMemBio::new();
        smb.write_all(b"tmp").unwrap();
        smb.reset();
        assert!(smb.is_empty());
    }

    #[test]
    fn secure_mem_bio_reset_read_only_rewinds() {
        let mut smb = SecureMemBio::from_slice(b"again");
        let mut out = [0u8; 5];
        smb.read_exact(&mut out).unwrap();
        smb.reset();
        assert_eq!(smb.len(), 5);
        let mut again = [0u8; 5];
        smb.read_exact(&mut again).unwrap();
        assert_eq!(&again, b"again");
    }

    #[test]
    fn secure_mem_bio_as_bytes_matches_unread() {
        let mut smb = SecureMemBio::new();
        smb.write_all(b"abcdef").unwrap();
        assert_eq!(smb.as_bytes(), b"abcdef");
        let mut out = [0u8; 2];
        smb.read_exact(&mut out).unwrap();
        assert_eq!(smb.as_bytes(), b"cdef");
    }

    #[test]
    fn secure_mem_bio_bio_trait_members_work() {
        let mut smb = SecureMemBio::from_slice(b"x");
        assert_eq!(smb.bio_type(), BioType::Memory);
        assert_eq!(smb.pending(), 1);
        assert_eq!(
            <SecureMemBio as Bio>::method_name(&smb),
            "secure memory buffer"
        );
        assert!(!smb.eof());
        let mut out = [0u8; 1];
        smb.read_exact(&mut out).unwrap();
        assert!(smb.eof());
        <SecureMemBio as Bio>::reset(&mut smb).unwrap();
    }

    // ----- BioPairEnd tests -----

    #[test]
    fn bio_pair_defaults_to_17kib() {
        let (a, b) = new_bio_pair(0, 0);
        assert_eq!(a.buffer_size(), 17 * 1024);
        assert_eq!(b.buffer_size(), 17 * 1024);
    }

    #[test]
    fn bio_pair_custom_sizes() {
        let (a, b) = new_bio_pair(256, 512);
        assert_eq!(a.buffer_size(), 256);
        assert_eq!(b.buffer_size(), 512);
    }

    #[test]
    fn bio_pair_a_to_b_flow() {
        let (mut a, mut b) = new_bio_pair(64, 64);
        assert_eq!(b.pending(), 0);

        a.write_all(b"ping").unwrap();
        assert_eq!(b.pending(), 4);
        assert_eq!(a.wpending(), 4);

        let mut out = [0u8; 4];
        b.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"ping");
        assert_eq!(b.pending(), 0);
        assert_eq!(a.wpending(), 0);
    }

    #[test]
    fn bio_pair_b_to_a_flow() {
        let (mut a, mut b) = new_bio_pair(64, 64);
        b.write_all(b"pong").unwrap();
        let mut out = [0u8; 4];
        a.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"pong");
    }

    #[test]
    fn bio_pair_empty_read_is_would_block() {
        let (mut a, _b) = new_bio_pair(64, 64);
        let mut buf = [0u8; 4];
        let err = a.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn bio_pair_full_buffer_write_returns_would_block() {
        let (mut a, _b) = new_bio_pair(4, 4);
        // Fill the a → b direction exactly.
        a.write_all(&[0u8; 4]).unwrap();
        // Next write sees full buffer.
        let err = a.write(b"x").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn bio_pair_partial_write_permitted_when_buffer_almost_full() {
        let (mut a, mut b) = new_bio_pair(4, 4);
        a.write_all(&[1u8, 2]).unwrap();
        // Free space is 2 — writing 4 accepts only 2.
        let n = a.write(&[3u8, 4, 5, 6]).unwrap();
        assert_eq!(n, 2);
        let mut out = [0u8; 4];
        b.read_exact(&mut out).unwrap();
        assert_eq!(&out, &[1u8, 2, 3, 4]);
    }

    #[test]
    fn bio_pair_close_write_propagates_eof_to_peer() {
        let (mut a, mut b) = new_bio_pair(64, 64);
        a.write_all(b"last").unwrap();
        a.close_write();
        assert!(a.is_write_closed());

        // Peer can still read buffered data.
        let mut out = [0u8; 4];
        b.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"last");

        // Subsequent read sees EOF.
        let mut more = [0u8; 1];
        assert_eq!(b.read(&mut more).unwrap(), 0);
        assert!(b.eof());
    }

    #[test]
    fn bio_pair_write_to_closed_side_returns_broken_pipe() {
        let (mut a, _b) = new_bio_pair(64, 64);
        a.close_write();
        let err = a.write(b"nope").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    }

    #[test]
    fn bio_pair_reset_clears_both_directions() {
        let (mut a, mut b) = new_bio_pair(64, 64);
        a.write_all(b"alpha").unwrap();
        b.write_all(b"beta").unwrap();
        assert_eq!(a.pending(), 4);
        assert_eq!(b.pending(), 5);

        <BioPairEnd as Bio>::reset(&mut a).unwrap();
        assert_eq!(a.pending(), 0);
        assert_eq!(b.pending(), 0);
    }

    #[test]
    fn bio_pair_reset_reopens_write_side() {
        let (mut a, _b) = new_bio_pair(64, 64);
        a.close_write();
        assert!(a.is_write_closed());
        <BioPairEnd as Bio>::reset(&mut a).unwrap();
        assert!(!a.is_write_closed());
    }

    #[test]
    fn bio_pair_bio_type_and_method_name() {
        let (a, _b) = new_bio_pair(64, 64);
        assert_eq!(a.bio_type(), BioType::BioPair);
        assert_eq!(<BioPairEnd as Bio>::method_name(&a), "BIO pair");
    }

    #[test]
    fn bio_pair_independent_directions() {
        // Filling a→b should not block b→a writes.
        let (mut a, mut b) = new_bio_pair(4, 4);
        a.write_all(&[0u8; 4]).unwrap();
        // b → a still has full capacity.
        let n = b.write(&[9u8; 4]).unwrap();
        assert_eq!(n, 4);
    }

    #[test]
    fn bio_pair_stats_update_on_io() {
        let (mut a, mut b) = new_bio_pair(64, 64);
        a.write_all(b"01234").unwrap();
        assert_eq!(a.stats().bytes_written(), 5);
        let mut out = [0u8; 5];
        b.read_exact(&mut out).unwrap();
        assert_eq!(b.stats().bytes_read(), 5);
    }

    // ----- Integration: thread-safety of BioPairEnd -----

    #[test]
    fn bio_pair_send_across_threads() {
        use std::thread;
        let (mut a, mut b) = new_bio_pair(1024, 1024);

        let writer = thread::spawn(move || {
            for i in 0..16u8 {
                let buf = [i; 32];
                a.write_all(&buf).unwrap();
            }
            a.close_write();
        });

        let reader = thread::spawn(move || {
            let mut total = 0usize;
            let mut buf = [0u8; 128];
            loop {
                match b.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => total = total.saturating_add(n),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::yield_now();
                    }
                    Err(e) => panic!("read error: {e:?}"),
                }
            }
            total
        });

        writer.join().unwrap();
        let total = reader.join().unwrap();
        assert_eq!(total, 16 * 32);
    }
}
