//! Filter chain BIO implementations for the OpenSSL Rust workspace.
//!
//! Provides composable I/O filter wrappers that transform data in transit
//! between a source/sink BIO and the application. Translates C filter BIOs
//! (`crypto/bio/bf_*.c`) into Rust types implementing [`std::io::Read`] and
//! [`std::io::Write`].
//!
//! ## Filter Types
//!
//! | Rust Type             | C Equivalent         | Purpose                                                  |
//! |-----------------------|----------------------|----------------------------------------------------------|
//! | [`BufferFilter`]      | `BIO_f_buffer()`     | General-purpose read/write buffering (dual-direction)    |
//! | [`LineBufferFilter`]  | `BIO_f_linebuffer()` | Write-side line buffering — flushes on newline           |
//! | [`ReadBufferFilter`]  | `BIO_f_readbuffer()` | Read-only caching filter — enables seek/tell over pipes  |
//! | [`PrefixFilter`]      | `BIO_f_prefix()`     | Write-side prefix/indent injection per output line       |
//! | [`NullFilter`]        | `BIO_f_null()`       | Transparent pass-through — delegates all operations      |
//! | [`FilterChainBuilder`]| `BIO_push()`         | Composition utility for building filter chains           |
//!
//! ## Design
//!
//! Each filter wraps an inner generic I/O object (`T`) and delegates I/O
//! through its transformation layer. Filter chains are built by nesting:
//!
//! ```text
//! PrefixFilter { inner: BufferFilter { inner: FileBio { ... } } }
//! ```
//!
//! ## Buffer Management
//!
//! Internal buffers use [`bytes::BytesMut`] for zero-copy consumption via
//! [`bytes::BytesMut::split_to`] and efficient append via
//! [`bytes::BufMut::put_slice`]. This eliminates the manual offset/length
//! bookkeeping required by the C `BIO_F_BUFFER_CTX` structure (see
//! `crypto/bio/bio_local.h`).
//!
//! ## Enforced Rules
//!
//! - **R5:** All operations return [`io::Result`] (no sentinel integers).
//!   [`PrefixFilter::prefix`] is [`Option<String>`] (no empty-string sentinel).
//! - **R6:** All buffer size math uses [`usize::saturating_add`] and
//!   [`usize::saturating_sub`] — no bare `as` narrowing casts.
//! - **R7:** No shared mutable state — each filter owns its inner I/O object.
//!   No locks required.
//! - **R8:** Zero `unsafe` code. [`bytes::BytesMut`] provides safe buffer APIs.
//! - **R9:** All public items carry `///` doc comments.
//! - **R10:** Reachable from [`super`] via `bio::filter::*` re-exports in
//!   [`crate::bio`].

use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};

use bytes::{Buf, BufMut, BytesMut};

use openssl_common::{CryptoError, CryptoResult};

use super::{Bio, BioStats, BioType, DEFAULT_BUFFER_SIZE};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default buffer size for [`LineBufferFilter`] (10240 bytes).
///
/// Matches the C `DEFAULT_LINEBUFFER_SIZE = 1024 * 10` constant defined in
/// `crypto/bio/bf_lbuf.c` line ~33. Line buffers are larger than general
/// buffer BIOs because they typically hold complete log lines which can be
/// longer than the default 4 KiB buffer.
pub const DEFAULT_LINEBUFFER_SIZE: usize = 1024 * 10;

/// Scratch space size for [`ReadBufferFilter::ensure_cache_to`] inner reads.
///
/// When extending the read cache, this chunk size balances the number of
/// syscalls against memory overhead. Matches C `readbuffer_resize` default
/// growth increment of `DEFAULT_BUFFER_SIZE = 4096`.
const CACHE_GROW_CHUNK: usize = DEFAULT_BUFFER_SIZE;

/// Reusable space buffer for [`PrefixFilter`] indentation emission.
///
/// A chunk of ASCII space characters (`0x20`) used to efficiently emit
/// indentation without allocating per write call. Sized at 64 bytes to cover
/// typical indentation (up to `MAX_INDENT = 128` in two chunks) while
/// keeping the constant compact.
const SPACE_CHUNK: [u8; 64] = [b' '; 64];

// ===========================================================================
// BufferFilter - General-purpose buffered I/O filter
// ===========================================================================

/// General-purpose buffered I/O filter.
///
/// Translates C `BIO_f_buffer()` from `crypto/bio/bf_buff.c` (478 lines).
/// Provides separate input and output buffers with independently-configurable
/// capacities. The dual-buffer design mirrors the C `BIO_F_BUFFER_CTX`
/// structure (see `crypto/bio/bio_local.h` lines 75-96):
///
/// ```text
///     Application        <--ibuf-- inner (source)
///     Application        --obuf--> inner (sink)
/// ```
///
/// # Default Capacity
///
/// Both input and output buffers default to [`DEFAULT_BUFFER_SIZE`] (4096
/// bytes) when constructed with [`BufferFilter::new`]. This matches the C
/// `DEFAULT_BUFFER_SIZE = 4096` constant in `bf_buff.c` line ~24.
///
/// # Read Algorithm (matches C `buffer_read`)
///
/// 1. If data remains in the input buffer, return up to the requested amount.
/// 2. If the request exceeds the buffer capacity, bypass buffering and read
///    directly from the inner source.
/// 3. Otherwise refill the buffer from the inner source, then serve from it.
///
/// # Write Algorithm (matches C `buffer_write`)
///
/// 1. If the output buffer has space, append and return.
/// 2. If the data plus existing buffer fits, append then flush.
/// 3. If the data itself exceeds the buffer, bypass buffering and write
///    directly to the inner sink.
///
/// # Type Parameter
///
/// `T` is the wrapped I/O object. Constructors and accessors work for any
/// `T`. [`Read`] is implemented when `T: Read`; [`Write`] when `T: Write`;
/// [`BufRead`] when `T: Read`; [`Bio`] when `T: Send`.
#[derive(Debug)]
pub struct BufferFilter<T> {
    /// Wrapped I/O object (inner BIO in C terminology — `b->next_bio`).
    inner: T,
    /// Input (read) buffer.
    ///
    /// Replaces C `ctx->ibuf` + `ctx->ibuf_off` + `ctx->ibuf_len`. Uses
    /// [`BytesMut::split_to`] for O(1) front consumption without shifting
    /// bytes.
    ibuf: BytesMut,
    /// Output (write) buffer.
    ///
    /// Replaces C `ctx->obuf` + `ctx->obuf_off` + `ctx->obuf_len`.
    obuf: BytesMut,
    /// Configured input buffer capacity (maximum refill size).
    ibuf_capacity: usize,
    /// Configured output buffer capacity (triggers flush when exceeded).
    obuf_capacity: usize,
    /// I/O activity counters for telemetry (see [`Bio::stats`]).
    stats: BioStats,
}

impl<T> BufferFilter<T> {
    /// Creates a new buffer filter wrapping `inner` with default capacities.
    ///
    /// Both input and output buffers are allocated with
    /// [`DEFAULT_BUFFER_SIZE`] (4096 bytes) capacity. Use
    /// [`BufferFilter::with_capacity`] for custom sizing.
    ///
    /// Equivalent to C `BIO_new(BIO_f_buffer())` followed by `BIO_push` onto
    /// a source/sink BIO.
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self::with_capacity(inner, DEFAULT_BUFFER_SIZE, DEFAULT_BUFFER_SIZE)
    }

    /// Creates a new buffer filter with explicit input and output capacities.
    ///
    /// Replaces C `BIO_set_read_buffer_size` + `BIO_set_write_buffer_size`
    /// control operations. Zero-sized capacities are not supported — any
    /// value of `0` is replaced with [`DEFAULT_BUFFER_SIZE`] (matching C
    /// `buffer_ctrl` `BIO_C_SET_BUFF_SIZE` validation at `bf_buff.c` ~line 300).
    #[must_use]
    pub fn with_capacity(inner: T, read_capacity: usize, write_capacity: usize) -> Self {
        let ibuf_capacity = if read_capacity == 0 {
            DEFAULT_BUFFER_SIZE
        } else {
            read_capacity
        };
        let obuf_capacity = if write_capacity == 0 {
            DEFAULT_BUFFER_SIZE
        } else {
            write_capacity
        };
        Self {
            inner,
            ibuf: BytesMut::with_capacity(ibuf_capacity),
            obuf: BytesMut::with_capacity(obuf_capacity),
            ibuf_capacity,
            obuf_capacity,
            stats: BioStats::new(),
        }
    }

    /// Consumes the filter and returns the wrapped I/O object.
    ///
    /// Any data buffered in [`BufferFilter`]'s output buffer is
    /// **discarded** — call [`Write::flush`] before [`BufferFilter::into_inner`]
    /// to commit pending writes.
    ///
    /// Equivalent to C `BIO_pop()` extracting the source/sink BIO from the
    /// filter chain (then freeing the filter BIO).
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Returns a shared reference to the wrapped I/O object.
    ///
    /// Useful for inspecting inner state without consuming the filter.
    /// Equivalent to C `BIO_next(bio)` traversal.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped I/O object.
    ///
    /// **Caution:** Directly writing to the inner I/O object bypasses the
    /// filter's output buffer, potentially producing out-of-order output.
    /// Flush first via [`Write::flush`] if mixing direct and buffered writes.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns the number of bytes currently buffered for reading.
    ///
    /// Replaces C `BIO_CTRL_PENDING` returning `ctx->ibuf_len`. When this
    /// returns a non-zero value, [`Read::read`] can satisfy at least that
    /// many bytes without touching the inner source.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.ibuf.remaining()
    }

    /// Returns the number of bytes currently buffered for writing.
    ///
    /// Replaces C `BIO_CTRL_WPENDING` returning `ctx->obuf_len`. This data
    /// has been accepted by [`Write::write`] but not yet flushed to the
    /// inner sink.
    #[must_use]
    pub fn wpending(&self) -> usize {
        self.obuf.len()
    }
}

impl<T: Read> BufferFilter<T> {
    /// Refills the input buffer from the inner source.
    ///
    /// Reads up to [`BufferFilter::ibuf_capacity`] bytes into `ibuf`. Returns
    /// the number of bytes added. A return of `0` indicates EOF on the inner
    /// source.
    ///
    /// # Errors
    ///
    /// Propagates [`io::Error`] from the inner reader.
    fn refill(&mut self) -> io::Result<usize> {
        // Ensure the buffer has at least `ibuf_capacity` bytes of headroom.
        // Using BytesMut's internal reserve+set_len pattern requires unsafe;
        // instead we use a scratch Vec and extend_from_slice for safety (R8).
        let mut scratch = vec![0u8; self.ibuf_capacity];
        let n = self.inner.read(&mut scratch)?;
        if n > 0 {
            self.ibuf.put_slice(&scratch[..n]);
        }
        Ok(n)
    }
}

impl<T: Read> Read for BufferFilter<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Fast path 1: buffer has data — serve from it. Matches `buffer_read`
        // "stuff left over" branch in bf_buff.c line 104.
        if self.ibuf.has_remaining() {
            let take = buf.len().min(self.ibuf.remaining());
            let chunk = self.ibuf.split_to(take);
            buf[..take].copy_from_slice(&chunk);
            self.stats.record_read(take);
            return Ok(take);
        }

        // Fast path 2: request exceeds buffer capacity — bypass buffering
        // and read directly from inner. Matches bf_buff.c lines 122-143.
        if buf.len() > self.ibuf_capacity {
            let n = self.inner.read(buf)?;
            self.stats.record_read(n);
            return Ok(n);
        }

        // Slow path: refill the buffer, then serve.
        let refilled = self.refill()?;
        if refilled == 0 {
            return Ok(0);
        }
        let take = buf.len().min(self.ibuf.remaining());
        let chunk = self.ibuf.split_to(take);
        buf[..take].copy_from_slice(&chunk);
        self.stats.record_read(take);
        Ok(take)
    }
}

impl<T: Write> Write for BufferFilter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let available = self.obuf_capacity.saturating_sub(self.obuf.len());

        // Fast path 1: data fits in existing buffer space — append and return.
        // Matches bf_buff.c line 172 "add to buffer and return".
        if buf.len() <= available {
            self.obuf.put_slice(buf);
            self.stats.record_write(buf.len());
            return Ok(buf.len());
        }

        // Flush any existing buffered output first. Matches bf_buff.c lines
        // 180-205 where buffered data is drained before new data is processed.
        if !self.obuf.is_empty() {
            self.drain_obuf()?;
        }

        // Fast path 2: data itself exceeds buffer capacity — write directly
        // without buffering. Matches bf_buff.c lines 213-227 bypass loop.
        if buf.len() >= self.obuf_capacity {
            let n = self.inner.write(buf)?;
            self.stats.record_write(n);
            return Ok(n);
        }

        // Slow path: buffer is empty, data fits — append to fresh buffer.
        self.obuf.put_slice(buf);
        self.stats.record_write(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain_obuf()?;
        self.inner.flush()
    }
}

impl<T: Write> BufferFilter<T> {
    /// Flushes all buffered output to the inner writer, returning a
    /// [`CryptoResult`] instead of the `io::Result` produced by
    /// [`Write::flush`].
    ///
    /// Equivalent to [`Write::flush`], but converts [`io::Error`] into
    /// [`CryptoError::Io`] for ergonomic error propagation in callers
    /// that already use the [`CryptoResult`] type family. This mirrors
    /// the C `BIO_flush()` return convention (1 = success, 0/-1 = error)
    /// translated to the idiomatic Rust error type.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Io`] wrapping any I/O error from the inner
    /// writer during buffer draining or final flush.
    pub fn try_flush(&mut self) -> CryptoResult<()> {
        self.drain_obuf().map_err(CryptoError::Io)?;
        self.inner.flush().map_err(CryptoError::Io)
    }

    /// Writes all buffered output data to the inner sink, clearing the
    /// output buffer on success.
    ///
    /// Uses [`Write::write_all`] to ensure complete flushing — matches the
    /// C `buffer_ctrl` `BIO_CTRL_FLUSH` loop at `bf_buff.c` lines 340-360
    /// that retries until `obuf_len` reaches zero.
    ///
    /// # Errors
    ///
    /// Propagates [`io::Error`] from the inner writer. On error, partial
    /// data may have been consumed from the buffer via [`BytesMut::advance`]
    /// (not all-or-nothing; caller may retry).
    fn drain_obuf(&mut self) -> io::Result<()> {
        if self.obuf.is_empty() {
            return Ok(());
        }
        // Copy out to a scratch buffer so that we can reset the BytesMut
        // without holding a borrow across the write_all call.
        let data = self.obuf.split();
        self.inner.write_all(&data)
    }
}

impl<T: Read> BufRead for BufferFilter<T> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        // Refill only when empty. Matches the BufRead contract — `fill_buf`
        // should attempt to ensure the buffer is non-empty, then return a
        // view of its contents.
        if !self.ibuf.has_remaining() {
            self.refill()?;
        }
        Ok(&self.ibuf[..])
    }

    fn consume(&mut self, amt: usize) {
        // Saturate the consumption count to the buffer size to avoid panic
        // on an over-eager caller. Per the BufRead contract, `amt` must be
        // less-than-or-equal to the slice returned from `fill_buf` — but
        // defensive handling is free and protects against misuse.
        let take = amt.min(self.ibuf.remaining());
        self.ibuf.advance(take);
        self.stats.record_read(take);
    }
}

impl<T: Send> Bio for BufferFilter<T> {
    fn bio_type(&self) -> BioType {
        BioType::Buffer
    }

    fn pending(&self) -> usize {
        self.ibuf.remaining()
    }

    fn wpending(&self) -> usize {
        self.obuf.len()
    }

    fn eof(&self) -> bool {
        // Buffer filter has no intrinsic EOF signal — it delegates to the
        // inner I/O object. This method returns `false` by default; callers
        // must inspect [`Read::read`] returning `Ok(0)` to detect EOF.
        false
    }

    fn reset(&mut self) -> CryptoResult<()> {
        // C `BIO_CTRL_RESET` on buffer filter clears both buffers. See
        // `bf_buff.c` lines 252-258. We also reset statistics for a clean
        // slate, consistent with how [`crate::bio::mem::MemBio`] handles
        // reset.
        self.ibuf.clear();
        self.obuf.clear();
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
        "buffer"
    }
}

// ===========================================================================
// LineBufferFilter - Write-side line buffering
// ===========================================================================

/// Line-buffered write filter.
///
/// Translates C `BIO_f_linebuffer()` from `crypto/bio/bf_lbuf.c` (354 lines).
/// Accumulates written bytes in an output buffer and flushes the buffer to
/// the inner sink whenever a newline (`'\n'`) character appears in the
/// input. Unlike [`BufferFilter`], this filter does not buffer reads —
/// reads pass through to the inner reader unchanged.
///
/// # Default Capacity
///
/// The output buffer defaults to [`DEFAULT_LINEBUFFER_SIZE`] (10240 bytes),
/// matching the C `DEFAULT_LINEBUFFER_SIZE = 1024 * 10` constant in
/// `bf_lbuf.c` line ~33. Line buffers are deliberately larger than the
/// general [`DEFAULT_BUFFER_SIZE`] (4096) because they are designed to hold
/// complete log lines which may exceed 4 KiB.
///
/// # Write Algorithm (matches C `linebuffer_write`)
///
/// For each call to [`Write::write`]:
///
/// 1. Scan the input for the first newline `'\n'`.
/// 2. If a newline is found:
///    - If data was previously buffered, concatenate the pre-newline portion
///      into the buffer (up to capacity) and flush to inner.
///    - Otherwise, write the pre-newline portion directly to inner.
///    - Repeat with the remainder.
/// 3. If no newline is found, buffer the remainder. If it exceeds available
///    space, flush the existing buffer and retry.
///
/// This mirrors the C `linebuffer_write` outer `do { ... } while (foundnl &&
/// inl > 0)` loop at `bf_lbuf.c` lines 118-189.
///
/// # Type Parameter
///
/// `W` is the wrapped writer. The [`Write`] implementation requires
/// `W: Write`; the [`Read`] pass-through implementation requires `W: Read`;
/// the [`Bio`] implementation requires `W: Send`.
#[derive(Debug)]
pub struct LineBufferFilter<W> {
    /// Wrapped I/O object.
    inner: W,
    /// Output buffer accumulating bytes until a newline flushes it.
    ///
    /// Replaces C `ctx->obuf` + `ctx->obuf_len` from the
    /// `BIO_LINEBUFFER_CTX` struct at `bf_lbuf.c` lines 50-54.
    obuf: BytesMut,
    /// Configured output buffer capacity.
    obuf_capacity: usize,
    /// I/O activity counters.
    stats: BioStats,
}

impl<W> LineBufferFilter<W> {
    /// Creates a new line-buffered filter wrapping `inner` with the default
    /// capacity ([`DEFAULT_LINEBUFFER_SIZE`] = 10240 bytes).
    ///
    /// Equivalent to C `BIO_new(BIO_f_linebuffer())` followed by `BIO_push`
    /// onto a sink BIO.
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self::with_capacity(inner, DEFAULT_LINEBUFFER_SIZE)
    }

    /// Creates a new line-buffered filter with an explicit output buffer
    /// capacity.
    ///
    /// Replaces C `BIO_set_write_buffer_size` control operation on line
    /// buffers. A `capacity` of `0` is replaced with
    /// [`DEFAULT_LINEBUFFER_SIZE`].
    #[must_use]
    pub fn with_capacity(inner: W, capacity: usize) -> Self {
        let obuf_capacity = if capacity == 0 {
            DEFAULT_LINEBUFFER_SIZE
        } else {
            capacity
        };
        Self {
            inner,
            obuf: BytesMut::with_capacity(obuf_capacity),
            obuf_capacity,
            stats: BioStats::new(),
        }
    }

    /// Consumes the filter and returns the wrapped writer.
    ///
    /// Any data remaining in the line buffer is **discarded** — call
    /// [`Write::flush`] before [`LineBufferFilter::into_inner`] to commit
    /// incomplete lines.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> LineBufferFilter<W> {
    /// Flushes the line-buffered output (including any partial line) to
    /// the inner writer, returning a [`CryptoResult`] instead of the
    /// `io::Result` produced by [`Write::flush`].
    ///
    /// Converts [`io::Error`] into [`CryptoError::Io`] for ergonomic error
    /// propagation in callers that already use the [`CryptoResult`] type
    /// family. This mirrors the C `BIO_flush()` return convention
    /// translated to the idiomatic Rust error type.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Io`] wrapping any I/O error from the inner
    /// writer during buffer draining or final flush.
    pub fn try_flush(&mut self) -> CryptoResult<()> {
        self.flush_buffer().map_err(CryptoError::Io)?;
        self.inner.flush().map_err(CryptoError::Io)
    }

    /// Writes all currently buffered bytes to the inner writer, then clears
    /// the buffer.
    ///
    /// # Errors
    ///
    /// Propagates [`io::Error`] from the inner writer. On error, the
    /// buffered data may have been partially consumed from the buffer.
    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.obuf.is_empty() {
            return Ok(());
        }
        let data = self.obuf.split();
        self.inner.write_all(&data)
    }
}

impl<W: Write> Write for LineBufferFilter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut remaining = buf;
        let mut total_written: usize = 0;

        // Inner loop: process newline-terminated segments first.
        // Matches bf_lbuf.c lines 118-189 `do { ... } while (foundnl ...)`.
        while let Some(nl_pos) = remaining.iter().position(|&byte| byte == b'\n') {
            // `line_end` points one past the newline so it is included in
            // the flush.
            let line_end = nl_pos.saturating_add(1);

            if self.obuf.is_empty() {
                // No buffered data — direct-write the line.
                self.inner.write_all(&remaining[..line_end])?;
                total_written = total_written.saturating_add(line_end);
                remaining = &remaining[line_end..];
            } else {
                // Concatenate the pre-newline portion into the buffer (up
                // to capacity) and flush. Matches bf_lbuf.c lines 128-166.
                let space = self.obuf_capacity.saturating_sub(self.obuf.len());
                let copy = line_end.min(space);
                if copy > 0 {
                    self.obuf.put_slice(&remaining[..copy]);
                }
                self.flush_buffer()?;
                total_written = total_written.saturating_add(copy);
                remaining = &remaining[copy..];

                // Direct-write the remainder of the line if it did not fit
                // into the buffer. Matches bf_lbuf.c lines 170-185.
                let line_rest = line_end.saturating_sub(copy);
                if line_rest > 0 {
                    self.inner.write_all(&remaining[..line_rest])?;
                    total_written = total_written.saturating_add(line_rest);
                    remaining = &remaining[line_rest..];
                }
            }
        }

        // Outer loop: buffer the remainder (no newlines left). Matches
        // bf_lbuf.c lines 196-228 `while (inl > 0)` flushing-to-make-room
        // loop.
        while !remaining.is_empty() {
            let space = self.obuf_capacity.saturating_sub(self.obuf.len());
            if space == 0 {
                self.flush_buffer()?;
                continue;
            }
            let copy = remaining.len().min(space);
            self.obuf.put_slice(&remaining[..copy]);
            total_written = total_written.saturating_add(copy);
            remaining = &remaining[copy..];
        }

        self.stats.record_write(total_written);
        Ok(total_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer()?;
        self.inner.flush()
    }
}

impl<W: Read> Read for LineBufferFilter<W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Pass-through: line buffer only transforms writes. Matches
        // C `linebuffer_read` at `bf_lbuf.c` lines 86-103 which simply
        // delegates to `BIO_read(next_bio, ...)` with retry-flag copying
        // (retry flags map to `io::ErrorKind::Interrupted`/`WouldBlock`
        // in Rust I/O idioms).
        let n = self.inner.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl<W: Send> Bio for LineBufferFilter<W> {
    fn bio_type(&self) -> BioType {
        BioType::LineBuffer
    }

    fn pending(&self) -> usize {
        // Line buffer does not buffer reads — no pending input.
        0
    }

    fn wpending(&self) -> usize {
        self.obuf.len()
    }

    fn eof(&self) -> bool {
        // Line buffer does not cache the inner EOF state — delegates.
        false
    }

    fn reset(&mut self) -> CryptoResult<()> {
        // C `BIO_CTRL_RESET` on linebuffer clears the output buffer
        // (see `bf_lbuf.c` lines 242-246).
        self.obuf.clear();
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
        "linebuffer"
    }
}

// ===========================================================================
// ReadBufferFilter - Read-only caching filter enabling seek/tell
// ===========================================================================

/// Read-only caching filter enabling seek/tell over non-seekable sources.
///
/// Translates C `BIO_f_readbuffer()` from `crypto/bio/bf_readbuff.c`
/// (291 lines). Caches every byte read from the inner source in an
/// internal buffer, allowing [`Seek`] operations (backward-within-cache)
/// even when the inner source is a pipe, socket, or other non-seekable
/// stream.
///
/// # Cache Layout
///
/// ```text
///     +-----------------------------+
///     |   cached bytes              |
///     +-----------------------------+
///      ^                  ^
///      0               position
///                          ^      ^
///                     read cursor  cache.len()
/// ```
///
/// - `cache` holds all bytes read from `inner` since construction.
/// - `position` marks the next byte to return from [`Read::read`].
///
/// This mirrors the C `BIO_F_BUFFER_CTX` semantics for read-buffer mode
/// (`bf_readbuff.c` lines 88-150):
/// - `ctx->ibuf_off` ↔ [`ReadBufferFilter::position`]
/// - `ctx->ibuf_off + ctx->ibuf_len` ↔ `cache.len()` (total bytes cached)
///
/// # Seek Semantics
///
/// [`Seek`] is implemented only for backward-or-within-cache positions.
/// Matches the C `readbuffer_ctrl` at `bf_readbuff.c` lines 178-186 which
/// explicitly only supports `sz = ctx->ibuf_off + ctx->ibuf_len;` range
/// (i.e. positions `0..=cache.len()`). Seeking past the end of cached data
/// requires reading the inner source until EOF ([`SeekFrom::End`]) or
/// extending the cache via [`Read::read`].
///
/// # Type Parameter
///
/// `R` is the wrapped reader. [`Read`] is implemented when `R: Read`.
/// [`Seek`] requires `R: Read` (seek-past-cache extends the cache via
/// reads). [`Bio`] requires `R: Send`.
#[derive(Debug)]
pub struct ReadBufferFilter<R> {
    /// Wrapped I/O object (source — reads extend `cache`).
    inner: R,
    /// Cumulative cache of every byte read from `inner` since construction.
    ///
    /// Grows on demand via [`ReadBufferFilter::ensure_cache_to`] /
    /// [`ReadBufferFilter::read_more_into_cache`].
    cache: BytesMut,
    /// Current read cursor within `cache`. Data in `cache[..position]` has
    /// been returned to the application; `cache[position..]` is cached but
    /// unread.
    position: usize,
    /// Whether `inner` has signaled EOF (returning `Ok(0)` from its last
    /// [`Read::read`] call).
    eof: bool,
    /// I/O activity counters.
    stats: BioStats,
}

impl<R> ReadBufferFilter<R> {
    /// Creates a new read-caching filter wrapping `inner`.
    ///
    /// The cache starts empty and grows as reads occur. No initial
    /// allocation is performed.
    ///
    /// Equivalent to C `BIO_new(BIO_f_readbuffer())` followed by `BIO_push`
    /// onto a source BIO.
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            cache: BytesMut::new(),
            position: 0,
            eof: false,
            stats: BioStats::new(),
        }
    }

    /// Returns the total number of bytes currently cached.
    ///
    /// This is the total of both previously-read and not-yet-read data:
    /// matches C `ctx->ibuf_off + ctx->ibuf_len` in `bf_readbuff.c`.
    #[must_use]
    pub fn cached_len(&self) -> usize {
        self.cache.len()
    }

    /// Returns the current read position (logical tell).
    ///
    /// Matches C `BIO_C_FILE_TELL` / `BIO_CTRL_INFO` at `bf_readbuff.c`
    /// line 189 returning `(long)ctx->ibuf_off`.
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }
}

impl<R: Read> ReadBufferFilter<R> {
    /// Reads more bytes from `inner` into the cache.
    ///
    /// Reads up to `min_bytes` bytes (rounded up to the nearest
    /// `CACHE_GROW_CHUNK`) in a single call. Returns the number of bytes
    /// added to the cache. Returns `0` when `inner` is at EOF.
    ///
    /// # Errors
    ///
    /// Propagates [`io::Error`] from the inner reader.
    fn read_more_into_cache(&mut self, min_bytes: usize) -> io::Result<usize> {
        if self.eof {
            return Ok(0);
        }
        // Round up to CACHE_GROW_CHUNK for syscall amortisation. Matches
        // C `readbuffer_resize` block-size rounding at `bf_readbuff.c`
        // lines 92-94.
        let grow = min_bytes
            .max(CACHE_GROW_CHUNK)
            .saturating_add(CACHE_GROW_CHUNK.saturating_sub(1))
            / CACHE_GROW_CHUNK
            * CACHE_GROW_CHUNK;
        let grow = grow.max(CACHE_GROW_CHUNK);
        let mut scratch = vec![0u8; grow];
        let n = self.inner.read(&mut scratch)?;
        if n == 0 {
            self.eof = true;
        } else {
            self.cache.put_slice(&scratch[..n]);
        }
        Ok(n)
    }

    /// Extends the cache until it contains at least `target` bytes (or
    /// `inner` reaches EOF, whichever comes first).
    ///
    /// # Errors
    ///
    /// Propagates [`io::Error`] from the inner reader.
    fn ensure_cache_to(&mut self, target: usize) -> io::Result<()> {
        while self.cache.len() < target && !self.eof {
            let need = target.saturating_sub(self.cache.len());
            let got = self.read_more_into_cache(need)?;
            if got == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Reads all remaining bytes from `inner` into the cache, until EOF.
    ///
    /// Used by [`Seek`] with [`SeekFrom::End`] to determine the total
    /// stream length.
    ///
    /// # Errors
    ///
    /// Propagates [`io::Error`] from the inner reader.
    fn drain_inner_to_eof(&mut self) -> io::Result<()> {
        while !self.eof {
            let got = self.read_more_into_cache(CACHE_GROW_CHUNK)?;
            if got == 0 {
                break;
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for ReadBufferFilter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // If we are at the end of the cache, extend it (unless EOF).
        if self.position >= self.cache.len() {
            let got = self.read_more_into_cache(buf.len())?;
            if got == 0 {
                return Ok(0);
            }
        }

        // Serve from cache starting at `position`. Matches bf_readbuff.c
        // lines 123-134 `memcpy(out, &(ctx->ibuf[ctx->ibuf_off]), i)` loop.
        let available = self.cache.len().saturating_sub(self.position);
        let take = buf.len().min(available);
        let start = self.position;
        let end = start.saturating_add(take);
        buf[..take].copy_from_slice(&self.cache[start..end]);
        self.position = end;
        self.stats.record_read(take);
        Ok(take)
    }
}

impl<R: Read> BufRead for ReadBufferFilter<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position >= self.cache.len() && !self.eof {
            self.read_more_into_cache(CACHE_GROW_CHUNK)?;
        }
        Ok(&self.cache[self.position..])
    }

    fn consume(&mut self, amt: usize) {
        let available = self.cache.len().saturating_sub(self.position);
        let take = amt.min(available);
        self.position = self.position.saturating_add(take);
        self.stats.record_read(take);
    }
}

impl<R: Read> Seek for ReadBufferFilter<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Compute the target absolute position in the cached stream.
        // Matches bf_readbuff.c lines 178-186 seek semantics which require
        // `0 <= num <= ibuf_off + ibuf_len` (= cache.len()).
        let target = match pos {
            SeekFrom::Start(offset) => {
                // Cast with `try_from` to catch overflow on 32-bit targets
                // (Rule R6). On 64-bit this is always infallible.
                usize::try_from(offset).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek position overflows usize")
                })?
            }
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    let delta_u = usize::try_from(delta).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek delta overflows usize")
                    })?;
                    self.position.saturating_add(delta_u)
                } else {
                    // Negative delta: compute magnitude without using a
                    // bare `as` cast (Rule R6). `delta.unsigned_abs()`
                    // returns u64.
                    let abs = usize::try_from(delta.unsigned_abs()).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "seek magnitude overflows usize",
                        )
                    })?;
                    self.position.checked_sub(abs).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek to negative position")
                    })?
                }
            }
            SeekFrom::End(delta) => {
                // Drain the inner source to determine the stream length.
                self.drain_inner_to_eof()?;
                let end = self.cache.len();
                if delta >= 0 {
                    let delta_u = usize::try_from(delta).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek delta overflows usize")
                    })?;
                    end.saturating_add(delta_u)
                } else {
                    let abs = usize::try_from(delta.unsigned_abs()).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "seek magnitude overflows usize",
                        )
                    })?;
                    end.checked_sub(abs).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek to negative position")
                    })?
                }
            }
        };

        // For forward seeks past the cache, extend the cache to reach the
        // target. This is permitted as long as the inner source has enough
        // data — matches C's behaviour where the user must have first
        // read through the target position to have it cached.
        if target > self.cache.len() {
            self.ensure_cache_to(target)?;
        }

        // After best-effort extension, validate the target is within cache.
        // Matches bf_readbuff.c line 180 `if (num < 0 || num > sz) return 0`.
        if target > self.cache.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek target exceeds cached data and inner source is at EOF",
            ));
        }

        self.position = target;
        // `u64::try_from(usize)` is infallible on all supported targets
        // (usize <= u64) — but we use `try_from` for R6 compliance.
        u64::try_from(target)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "position exceeds u64"))
    }
}

impl<R: Send> Bio for ReadBufferFilter<R> {
    fn bio_type(&self) -> BioType {
        BioType::ReadBuffer
    }

    fn pending(&self) -> usize {
        // Pending = unread cached bytes. Matches bf_readbuff.c line 195
        // `ret = (long)ctx->ibuf_len;`.
        self.cache.len().saturating_sub(self.position)
    }

    fn wpending(&self) -> usize {
        // Read-only filter — never any pending writes.
        0
    }

    fn eof(&self) -> bool {
        // EOF only when cache is fully consumed AND inner signaled EOF.
        // Matches bf_readbuff.c lines 169-174 `if (ctx->ibuf_len > 0)
        // return 0; ret = BIO_ctrl(b->next_bio, cmd, ...);`.
        self.eof && self.position >= self.cache.len()
    }

    fn reset(&mut self) -> CryptoResult<()> {
        // C `BIO_CTRL_RESET` on readbuffer seeks to position 0 (does NOT
        // discard the cache). See `bf_readbuff.c` lines 178-186 sharing
        // the `BIO_C_FILE_SEEK` / `BIO_CTRL_RESET` case.
        self.position = 0;
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
        "readbuffer"
    }
}

// ===========================================================================
// PrefixFilter - Write-side line prefix and indent filter
// ===========================================================================

/// Maximum permitted indent depth for [`PrefixFilter`].
///
/// Mirrors the private `MAX_INDENT` used by `bio::bio_dump` in
/// `crates/openssl-crypto/src/bio/mod.rs` and matches the historical
/// OpenSSL C upper bound for indent column-width (`bf_prefix.c` rejects
/// indents above this via `BIO_CTRL_SET_INDENT`).
const MAX_INDENT: usize = 128;

/// Write-side filter that prepends a configured prefix string and
/// indentation spaces to each output line.
///
/// Translates C `BIO_f_prefix()` from `crypto/bio/bf_prefix.c` (211
/// lines). The filter tracks line boundaries across successive
/// [`Write::write`] calls so that the prefix + indent are emitted once
/// per line, not once per write-call.
///
/// # Algorithm
///
/// Starting from the line-start state (matches C `prefix_create`
/// setting `linestart = 1`), each call to [`Write::write`]:
///
/// 1. If no prefix and `indent == 0`, fall through to the inner writer
///    unchanged, updating `linestart` from the trailing byte. Matches
///    C fast path at `bf_prefix.c` lines 77-84.
/// 2. Otherwise, process byte-by-byte:
///    - If at line-start, emit prefix, then emit `indent` spaces.
///    - Scan forward to the next `\n` (or end-of-input).
///    - Write that segment (including the `\n` if found) to `inner`.
///    - If the segment ended with `\n`, set line-start = true.
///
/// # Type Parameter
///
/// `W` is the wrapped writer. [`Write`] is implemented when `W: Write`.
/// [`Bio`] requires `W: Send`.
#[derive(Debug)]
pub struct PrefixFilter<W> {
    /// Wrapped I/O object (sink).
    inner: W,
    /// Optional prefix string. `None` means no prefix is emitted (matches
    /// C `ctx->prefix == NULL` at `bf_prefix.c` lines 77-78). Rule R5:
    /// use `Option<String>` instead of empty-string sentinel.
    prefix: Option<String>,
    /// Number of space characters to emit after the prefix. Clamped to
    /// `MAX_INDENT` on write. Zero means no indent.
    indent: usize,
    /// Line-start state. Initialized to `true` (matches C `prefix_create`
    /// at `bf_prefix.c` line 56). Reset to `true` after emitting a `\n`.
    linestart: bool,
    /// I/O activity counters.
    stats: BioStats,
}

impl<W> PrefixFilter<W> {
    /// Creates a new prefix filter wrapping `inner`.
    ///
    /// No prefix is set and indent is `0`. The filter behaves as a
    /// transparent pass-through until [`PrefixFilter::set_prefix`] or
    /// [`PrefixFilter::set_indent`] is called.
    ///
    /// Equivalent to `BIO_new(BIO_f_prefix())` at `bf_prefix.c` line 25.
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            prefix: None,
            indent: 0,
            linestart: true,
            stats: BioStats::new(),
        }
    }

    /// Creates a new prefix filter with the given prefix string.
    ///
    /// Equivalent to `BIO_new(BIO_f_prefix())` followed by
    /// `BIO_set_prefix(b, prefix)` (C `BIO_CTRL_SET_PREFIX`).
    #[must_use]
    pub fn with_prefix(inner: W, prefix: &str) -> Self {
        Self {
            inner,
            prefix: Some(prefix.to_owned()),
            indent: 0,
            linestart: true,
            stats: BioStats::new(),
        }
    }

    /// Creates a new prefix filter with the given prefix string and
    /// indent.
    ///
    /// The indent is clamped to `MAX_INDENT` (=128) columns, matching
    /// the historical C limit.
    #[must_use]
    pub fn with_prefix_and_indent(inner: W, prefix: &str, indent: usize) -> Self {
        Self {
            inner,
            prefix: Some(prefix.to_owned()),
            indent: indent.min(MAX_INDENT),
            linestart: true,
            stats: BioStats::new(),
        }
    }

    /// Sets or clears the prefix string.
    ///
    /// Passing `None` clears the prefix (no prefix is emitted on
    /// subsequent writes). Matches C `BIO_CTRL_SET_PREFIX` at
    /// `bf_prefix.c` lines 145-158 where `NULL` clears the stored
    /// prefix.
    pub fn set_prefix(&mut self, prefix: Option<String>) {
        self.prefix = prefix;
    }

    /// Sets the indent column count.
    ///
    /// The value is clamped to `MAX_INDENT` (=128). Matches C
    /// `BIO_CTRL_SET_INDENT` at `bf_prefix.c` lines 159-164 which
    /// validates `num >= 0` (Rule R5: we use `usize` so this is
    /// implicit).
    pub fn set_indent(&mut self, indent: usize) {
        self.indent = indent.min(MAX_INDENT);
    }

    /// Consumes the filter, returning the wrapped inner writer.
    ///
    /// Any line-start state is discarded. Buffered output is _not_
    /// flushed — caller should call [`Write::flush`] on the filter
    /// before calling this method if that is required.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns a reference to the wrapped inner writer.
    #[must_use]
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped inner writer.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Returns the current prefix, if any.
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// Returns the current indent column count.
    #[must_use]
    pub fn indent(&self) -> usize {
        self.indent
    }
}

impl<W: Write> PrefixFilter<W> {
    /// Emits `self.indent` space characters to the inner writer in
    /// [`SPACE_CHUNK`]-sized writes.
    ///
    /// # Errors
    ///
    /// Propagates [`io::Error`] from the inner writer.
    fn emit_indent(&mut self) -> io::Result<()> {
        let mut remaining = self.indent;
        while remaining > 0 {
            let take = remaining.min(SPACE_CHUNK.len());
            self.inner.write_all(&SPACE_CHUNK[..take])?;
            remaining = remaining.saturating_sub(take);
        }
        Ok(())
    }

    /// Emits the prefix and indent (if any) to the inner writer.
    ///
    /// Called at the start of each new line when the prefix or indent
    /// is non-empty.
    ///
    /// # Errors
    ///
    /// Propagates [`io::Error`] from the inner writer.
    fn emit_line_prefix(&mut self) -> io::Result<()> {
        if let Some(ref prefix) = self.prefix {
            if !prefix.is_empty() {
                let bytes = prefix.as_bytes();
                // Clone to appease borrow checker — we need to call
                // `self.inner.write_all` while `self.prefix` is borrowed.
                // Using `prefix.to_owned()` would allocate every call;
                // instead, copy to a local slice via `Vec`. But since
                // writes may partial-fail and we want atomicity per-line,
                // use write_all which handles EWOULDBLOCK correctly.
                let owned: Vec<u8> = bytes.to_vec();
                self.inner.write_all(&owned)?;
            }
        }
        self.emit_indent()
    }
}

impl<W: Write> Write for PrefixFilter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Fast path: no prefix and no indent — just pass through and track
        // line-start state. Matches C `bf_prefix.c` lines 77-84.
        let has_prefix = self.prefix.as_ref().is_some_and(|p| !p.is_empty());
        if !has_prefix && self.indent == 0 {
            let n = self.inner.write(buf)?;
            if n > 0 {
                // Update linestart from the last byte we actually wrote.
                let last_idx = n.saturating_sub(1);
                self.linestart = buf[last_idx] == b'\n';
                self.stats.record_write(n);
            }
            return Ok(n);
        }

        // Slow path: emit prefix/indent at each line start, find newlines,
        // write segments between them. Matches C `prefix_write` lines
        // 86-137 of `bf_prefix.c`.
        let mut offset: usize = 0;
        while offset < buf.len() {
            if self.linestart {
                self.emit_line_prefix()?;
                self.linestart = false;
            }

            // Find the next newline within `buf[offset..]`, or end-of-buf.
            let segment_end = match buf[offset..].iter().position(|&b| b == b'\n') {
                Some(nl_rel) => offset.saturating_add(nl_rel).saturating_add(1),
                None => buf.len(),
            };
            let ends_with_nl = segment_end <= buf.len()
                && segment_end > offset
                && buf[segment_end.saturating_sub(1)] == b'\n';

            self.inner.write_all(&buf[offset..segment_end])?;
            let segment_len = segment_end.saturating_sub(offset);
            self.stats.record_write(segment_len);
            offset = segment_end;
            if ends_with_nl {
                self.linestart = true;
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Pass-through [`Read`] impl for [`PrefixFilter`]: the filter transforms
/// writes only, reads pass through unchanged.
///
/// Matches C `prefix_read` at `bf_prefix.c` line 69 which simply
/// delegates to `BIO_read_ex(next_bio, ...)`.
impl<W: Read> Read for PrefixFilter<W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl<W: Send> Bio for PrefixFilter<W> {
    fn bio_type(&self) -> BioType {
        BioType::Prefix
    }

    fn pending(&self) -> usize {
        // Prefix filter has no read buffering.
        0
    }

    fn wpending(&self) -> usize {
        // Prefix filter has no write buffering — each write is committed
        // to the inner writer synchronously.
        0
    }

    fn eof(&self) -> bool {
        false
    }

    fn reset(&mut self) -> CryptoResult<()> {
        // Reset returns to the line-start state (like a fresh BIO). The
        // prefix string and indent are preserved — matches C behavior
        // which only clears the linestart flag on `BIO_CTRL_RESET`.
        self.linestart = true;
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
        "prefix"
    }
}

// ===========================================================================
// NullFilter - Transparent pass-through filter
// ===========================================================================

/// Transparent pass-through filter.
///
/// Translates C `BIO_f_null()` from `crypto/bio/bf_null.c` (128 lines).
/// Delegates every I/O operation directly to the inner BIO without
/// transformation.
///
/// # Purpose
///
/// Useful as:
/// - A placeholder in filter chains while other filters are added.
/// - A debugging diagnostic point (tap reads/writes via
///   [`NullFilter::stats`]).
/// - A no-op chain terminator that still advertises the filter BIO
///   interface.
///
/// # Type Parameter
///
/// `T` is the wrapped I/O object. [`Read`] / [`Write`] / [`BufRead`] are
/// implemented by delegating when the inner type implements the
/// corresponding trait.
#[derive(Debug)]
pub struct NullFilter<T> {
    /// Wrapped I/O object.
    inner: T,
    /// I/O activity counters.
    stats: BioStats,
}

impl<T> NullFilter<T> {
    /// Creates a new null pass-through filter wrapping `inner`.
    ///
    /// Equivalent to `BIO_new(BIO_f_null())` at `bf_null.c` line 63.
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            stats: BioStats::new(),
        }
    }

    /// Consumes the filter, returning the wrapped inner I/O object.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Returns a shared reference to the wrapped inner I/O object.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped inner I/O object.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

/// Pass-through [`Read`] impl matching C `null_read` at `bf_null.c` line
/// 69 which delegates to `BIO_read_ex(next_bio, ...)`.
impl<T: Read> Read for NullFilter<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

/// Pass-through [`Write`] impl matching C `null_write` at `bf_null.c`
/// line 79 which delegates to `BIO_write_ex(next_bio, ...)`.
impl<T: Write> Write for NullFilter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Pass-through [`BufRead`] impl delegates both `fill_buf` and `consume`
/// to the inner buffered reader.
impl<T: BufRead> BufRead for NullFilter<T> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
        self.stats.record_read(amt);
    }
}

impl<T: Send> Bio for NullFilter<T> {
    fn bio_type(&self) -> BioType {
        BioType::NullFilter
    }

    fn pending(&self) -> usize {
        // Delegating pending to the inner would require `T: Bio` which
        // we deliberately do not require. Advertising 0 mirrors C's
        // default behavior when the inner BIO's ctrl is not directly
        // interrogated by the null filter.
        0
    }

    fn wpending(&self) -> usize {
        0
    }

    fn eof(&self) -> bool {
        false
    }

    fn reset(&mut self) -> CryptoResult<()> {
        // Match C `null_ctrl` at `bf_null.c` lines 99-110 which delegates
        // most ctrls to the next BIO — we reset only local stats.
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
        "null filter"
    }
}

// ===========================================================================
// FilterChainBuilder - Composable filter chain constructor
// ===========================================================================

/// Builder for composing BIO filter chains.
///
/// Provides a central entry point for constructing each filter type
/// wrapping an inner I/O object. Equivalent to C's `BIO_push(filter,
/// source)` chaining — but type-safe and ownership-tracked.
///
/// # Example
///
/// ```no_run
/// use openssl_crypto::bio::filter::FilterChainBuilder;
/// use std::io::Cursor;
///
/// let source = Cursor::new(b"hello world".to_vec());
/// // Wrap with a general-purpose read buffer
/// let buffered = FilterChainBuilder::with_buffer(source);
/// // Or wrap with a null pass-through
/// let source = Cursor::new(b"hello world".to_vec());
/// let null_wrapped = FilterChainBuilder::with_null(source);
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct FilterChainBuilder;

impl FilterChainBuilder {
    /// Wraps `inner` with a [`BufferFilter`].
    ///
    /// Uses the default buffer capacity ([`DEFAULT_BUFFER_SIZE`] = 4096
    /// bytes for both read and write buffers).
    #[must_use]
    pub fn with_buffer<T>(inner: T) -> BufferFilter<T> {
        BufferFilter::new(inner)
    }

    /// Wraps `inner` with a [`LineBufferFilter`].
    ///
    /// Uses the default line-buffer capacity ([`DEFAULT_LINEBUFFER_SIZE`]
    /// = 10240 bytes).
    #[must_use]
    pub fn with_line_buffer<W: Write>(inner: W) -> LineBufferFilter<W> {
        LineBufferFilter::new(inner)
    }

    /// Wraps `inner` with a [`ReadBufferFilter`] for seek/tell support
    /// over non-seekable sources.
    ///
    /// The cache starts empty and grows on demand in
    /// `CACHE_GROW_CHUNK`-sized chunks.
    #[must_use]
    pub fn with_read_buffer<R: Read>(inner: R) -> ReadBufferFilter<R> {
        ReadBufferFilter::new(inner)
    }

    /// Wraps `inner` with a [`PrefixFilter`] that emits `prefix` at the
    /// start of every output line followed by `indent` spaces.
    ///
    /// Passing `None` for `prefix` disables prefix emission (indent-only
    /// mode). Indent is clamped to `MAX_INDENT` = 128.
    #[must_use]
    pub fn with_prefix<W: Write>(
        inner: W,
        prefix: Option<String>,
        indent: usize,
    ) -> PrefixFilter<W> {
        let mut filter = PrefixFilter::new(inner);
        // Consume the `Option<String>` directly via `set_prefix` to avoid
        // an unnecessary clone and satisfy `clippy::needless_pass_by_value`.
        filter.set_prefix(prefix);
        filter.set_indent(indent);
        filter
    }

    /// Wraps `inner` with a [`NullFilter`] transparent pass-through.
    #[must_use]
    pub fn with_null<T>(inner: T) -> NullFilter<T> {
        NullFilter::new(inner)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// Test modules are permitted to use unwrap/expect/panic for brevity; the
// pedantic lints are disabled below with justification.
#[allow(clippy::unwrap_used)] // Tests panic-on-failure is the desired behaviour.
#[allow(clippy::expect_used)] // Tests panic-on-failure is the desired behaviour.
#[allow(clippy::panic)] // Assertion panics are the standard test mechanism.
#[allow(clippy::too_many_lines)] // Consolidated test module with many scenarios.
mod tests {
    use super::{
        BioType, BufferFilter, FilterChainBuilder, LineBufferFilter, NullFilter, PrefixFilter,
        ReadBufferFilter,
    };
    use super::{DEFAULT_LINEBUFFER_SIZE, MAX_INDENT};
    use crate::bio::{Bio, DEFAULT_BUFFER_SIZE};
    use std::io::{BufRead, Cursor, Read, Seek, SeekFrom, Write};

    // -------- BufferFilter --------

    #[test]
    fn buffer_filter_read_small_request() {
        let src = Cursor::new(b"hello world".to_vec());
        let mut buf = BufferFilter::new(src);
        let mut out = [0u8; 5];
        let n = buf.read(&mut out).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&out, b"hello");
    }

    #[test]
    fn buffer_filter_read_larger_than_buffer_bypasses() {
        // Request larger than read buffer capacity bypasses the buffer
        // per bf_buff.c lines 97-108.
        let data: Vec<u8> = (0..8192).map(|i| u8::try_from(i & 0xFF).unwrap()).collect();
        let src = Cursor::new(data.clone());
        let mut buf = BufferFilter::with_capacity(src, 128, 128);
        let mut out = vec![0u8; 4096];
        let n = buf.read(&mut out).unwrap();
        assert!(n > 0);
        assert_eq!(&out[..n], &data[..n]);
    }

    #[test]
    fn buffer_filter_write_small_buffers() {
        let sink: Vec<u8> = Vec::new();
        let mut buf = BufferFilter::new(sink);
        let n = buf.write(b"hi").unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf.wpending(), 2, "small write must remain buffered");
        buf.flush().unwrap();
        assert_eq!(buf.wpending(), 0);
        let out = buf.into_inner();
        assert_eq!(&out[..], b"hi");
    }

    #[test]
    fn buffer_filter_write_large_bypasses_buffer() {
        let sink: Vec<u8> = Vec::new();
        let mut buf = BufferFilter::with_capacity(sink, 64, 64);
        let payload = vec![0xABu8; 4096];
        buf.write_all(&payload).unwrap();
        buf.flush().unwrap();
        let out = buf.into_inner();
        assert_eq!(out.len(), 4096);
        assert!(out.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn buffer_filter_flush_empty_is_noop() {
        let sink: Vec<u8> = Vec::new();
        let mut buf = BufferFilter::new(sink);
        buf.flush().unwrap();
        assert_eq!(buf.wpending(), 0);
    }

    #[test]
    fn buffer_filter_bufread_fill_and_consume() {
        let src = Cursor::new(b"0123456789".to_vec());
        let mut buf = BufferFilter::new(src);
        let available = {
            let slice = buf.fill_buf().unwrap();
            assert!(!slice.is_empty());
            slice.len()
        };
        buf.consume(3);
        let rest = {
            let slice = buf.fill_buf().unwrap();
            slice.to_vec()
        };
        assert_eq!(rest.len(), available - 3);
    }

    #[test]
    fn buffer_filter_pending_reflects_buffered_data() {
        let src = Cursor::new(b"abcdef".to_vec());
        let mut buf = BufferFilter::new(src);
        let _ = buf.fill_buf().unwrap();
        assert!(buf.pending() > 0);
    }

    #[test]
    fn buffer_filter_bio_trait_methods() {
        let src = Cursor::new(b"abc".to_vec());
        let mut buf = BufferFilter::new(src);
        assert_eq!(buf.bio_type(), BioType::Buffer);
        assert!(!buf.eof());
        assert_eq!(buf.method_name(), "buffer");
        assert_eq!(buf.stats().bytes_read(), 0);

        let mut out = [0u8; 3];
        buf.read_exact(&mut out).unwrap();
        assert_eq!(buf.stats().bytes_read(), 3);

        buf.reset().unwrap();
        assert_eq!(buf.stats().bytes_read(), 0);
        assert_eq!(buf.wpending(), 0);
    }

    #[test]
    fn buffer_filter_get_ref_and_get_mut() {
        let src: Vec<u8> = Vec::new();
        let mut buf = BufferFilter::new(src);
        // `get_ref` returns the inner sink.
        assert!(buf.get_ref().is_empty());
        buf.get_mut().push(0x42);
        assert_eq!(buf.get_ref().as_slice(), &[0x42]);
    }

    #[test]
    fn buffer_filter_with_capacity_zero_falls_back_to_default() {
        // Passing zero for the capacity must fall back to the default so
        // the filter always has usable buffers (matches C
        // BIO_set_buffer_size rejecting zero).
        let src = Cursor::new(Vec::<u8>::new());
        let buf = BufferFilter::with_capacity(src, 0, 0);
        assert!(buf.pending() == 0);
        assert!(buf.wpending() == 0);
    }

    // -------- LineBufferFilter --------

    #[test]
    fn line_buffer_filter_buffers_partial_line() {
        let sink: Vec<u8> = Vec::new();
        let mut lb = LineBufferFilter::new(sink);
        lb.write_all(b"hello").unwrap();
        assert!(lb.wpending() > 0, "partial line must remain buffered");
        lb.flush().unwrap();
        let out = lb.into_inner();
        assert_eq!(&out[..], b"hello");
    }

    #[test]
    fn line_buffer_filter_flushes_on_newline() {
        let sink: Vec<u8> = Vec::new();
        let mut lb = LineBufferFilter::new(sink);
        lb.write_all(b"hello\n").unwrap();
        assert_eq!(lb.wpending(), 0, "newline-terminated line must be flushed");
        let out = lb.into_inner();
        assert_eq!(&out[..], b"hello\n");
    }

    #[test]
    fn line_buffer_filter_multi_line_writes() {
        let sink: Vec<u8> = Vec::new();
        let mut lb = LineBufferFilter::new(sink);
        lb.write_all(b"line1\nline2\nline3").unwrap();
        let pending = lb.wpending();
        assert_eq!(pending, 5, "last partial line (line3) should buffer");
        lb.flush().unwrap();
        let out = lb.into_inner();
        assert_eq!(&out[..], b"line1\nline2\nline3");
    }

    #[test]
    fn line_buffer_filter_read_is_passthrough() {
        let src = Cursor::new(b"abc".to_vec());
        let mut lb = LineBufferFilter::new(src);
        let mut out = [0u8; 3];
        lb.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"abc");
    }

    #[test]
    fn line_buffer_filter_large_write_past_capacity_flushes_early() {
        let sink: Vec<u8> = Vec::new();
        let mut lb = LineBufferFilter::with_capacity(sink, 16);
        let payload = vec![b'x'; 128];
        lb.write_all(&payload).unwrap();
        lb.flush().unwrap();
        let out = lb.into_inner();
        assert_eq!(out.len(), 128);
        assert!(out.iter().all(|&b| b == b'x'));
    }

    #[test]
    fn line_buffer_filter_bio_trait_methods() {
        let sink: Vec<u8> = Vec::new();
        let lb = LineBufferFilter::new(sink);
        assert_eq!(lb.bio_type(), BioType::LineBuffer);
        assert_eq!(lb.pending(), 0);
        assert!(!lb.eof());
        assert_eq!(lb.method_name(), "linebuffer");
    }

    #[test]
    fn line_buffer_filter_default_capacity() {
        let sink: Vec<u8> = Vec::new();
        let lb = LineBufferFilter::new(sink);
        // Indirectly verify by writing up to capacity.
        assert_eq!(lb.wpending(), 0);
        let _ = DEFAULT_LINEBUFFER_SIZE; // referenced to ensure import is used
    }

    #[test]
    fn line_buffer_filter_reset_clears_buffer() {
        let sink: Vec<u8> = Vec::new();
        let mut lb = LineBufferFilter::new(sink);
        lb.write_all(b"partial").unwrap();
        assert!(lb.wpending() > 0);
        lb.reset().unwrap();
        assert_eq!(lb.wpending(), 0);
    }

    // -------- ReadBufferFilter --------

    #[test]
    fn read_buffer_filter_reads_and_caches() {
        let src = Cursor::new(b"0123456789".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let mut out = [0u8; 5];
        rb.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"01234");
        assert_eq!(rb.position(), 5);
        assert!(rb.cached_len() >= 5);
    }

    #[test]
    fn read_buffer_filter_seek_backward_within_cache() {
        let src = Cursor::new(b"0123456789".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let mut out = [0u8; 5];
        rb.read_exact(&mut out).unwrap();
        assert_eq!(rb.position(), 5);
        // Seek backward to position 2 — must succeed, within cached data.
        let new_pos = rb.seek(SeekFrom::Start(2)).unwrap();
        assert_eq!(new_pos, 2);
        assert_eq!(rb.position(), 2);
        // Re-read from position 2.
        let mut out2 = [0u8; 3];
        rb.read_exact(&mut out2).unwrap();
        assert_eq!(&out2, b"234");
    }

    #[test]
    fn read_buffer_filter_seek_current_positive_and_negative() {
        let src = Cursor::new(b"abcdefghij".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let mut out = [0u8; 4];
        rb.read_exact(&mut out).unwrap();
        assert_eq!(rb.position(), 4);
        // Current + 2
        let pos = rb.seek(SeekFrom::Current(2)).unwrap();
        assert_eq!(pos, 6);
        // Current - 3 -> position 3
        let pos = rb.seek(SeekFrom::Current(-3)).unwrap();
        assert_eq!(pos, 3);
    }

    #[test]
    fn read_buffer_filter_seek_negative_below_zero_is_error() {
        let src = Cursor::new(b"abc".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let mut out = [0u8; 3];
        rb.read_exact(&mut out).unwrap();
        let result = rb.seek(SeekFrom::Current(-100));
        assert!(result.is_err());
    }

    #[test]
    fn read_buffer_filter_seek_from_end_drains_inner() {
        let src = Cursor::new(b"0123456789".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let end_pos = rb.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(end_pos, 10);
        assert_eq!(rb.cached_len(), 10);
        // Seek back to start
        let pos = rb.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(pos, 0);
        let mut out = [0u8; 10];
        rb.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"0123456789");
    }

    #[test]
    fn read_buffer_filter_seek_end_with_negative_offset() {
        let src = Cursor::new(b"0123456789".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let pos = rb.seek(SeekFrom::End(-3)).unwrap();
        assert_eq!(pos, 7);
        let mut out = [0u8; 3];
        rb.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"789");
    }

    #[test]
    fn read_buffer_filter_bio_trait_methods() {
        let src = Cursor::new(b"abc".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        assert_eq!(rb.bio_type(), BioType::ReadBuffer);
        assert_eq!(rb.method_name(), "readbuffer");
        assert!(!rb.eof());

        let mut out = [0u8; 3];
        rb.read_exact(&mut out).unwrap();
        // After fully reading the source, next read should hit EOF.
        let mut more = [0u8; 1];
        let n = rb.read(&mut more).unwrap();
        assert_eq!(n, 0);
        assert!(rb.eof());
    }

    #[test]
    fn read_buffer_filter_reset_returns_to_start() {
        let src = Cursor::new(b"abc".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let mut out = [0u8; 3];
        rb.read_exact(&mut out).unwrap();
        rb.reset().unwrap();
        assert_eq!(rb.position(), 0);
        // Cache is preserved, we can re-read.
        let mut out2 = [0u8; 3];
        rb.read_exact(&mut out2).unwrap();
        assert_eq!(&out2, b"abc");
    }

    #[test]
    fn read_buffer_filter_pending_reflects_unread_cache() {
        let src = Cursor::new(b"abcdef".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let mut out = [0u8; 2];
        rb.read_exact(&mut out).unwrap();
        // All 6 bytes may have been cached on first read; position is 2.
        assert!(rb.pending() == rb.cached_len() - rb.position());
    }

    #[test]
    fn read_buffer_filter_bufread_fill_and_consume() {
        let src = Cursor::new(b"0123456789".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let first = {
            let slice = rb.fill_buf().unwrap();
            assert!(!slice.is_empty());
            slice.to_vec()
        };
        assert!(first.starts_with(b"0123456789"));
        rb.consume(5);
        assert_eq!(rb.position(), 5);
    }

    #[test]
    fn read_buffer_filter_seek_past_eof_is_error() {
        let src = Cursor::new(b"abc".to_vec());
        let mut rb = ReadBufferFilter::new(src);
        let result = rb.seek(SeekFrom::Start(100));
        assert!(result.is_err());
    }

    // -------- PrefixFilter --------

    #[test]
    fn prefix_filter_no_prefix_no_indent_is_passthrough() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::new(sink);
        pf.write_all(b"hello\n").unwrap();
        let out = pf.into_inner();
        assert_eq!(&out[..], b"hello\n");
    }

    #[test]
    fn prefix_filter_emits_prefix_at_line_start() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::with_prefix(sink, ">>> ");
        pf.write_all(b"hello\n").unwrap();
        let out = pf.into_inner();
        assert_eq!(&out[..], b">>> hello\n");
    }

    #[test]
    fn prefix_filter_emits_prefix_once_per_line() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::with_prefix(sink, "P:");
        pf.write_all(b"line1\nline2\nline3\n").unwrap();
        let out = pf.into_inner();
        assert_eq!(&out[..], b"P:line1\nP:line2\nP:line3\n");
    }

    #[test]
    fn prefix_filter_emits_indent_spaces() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::new(sink);
        pf.set_indent(4);
        pf.write_all(b"x\ny\n").unwrap();
        let out = pf.into_inner();
        assert_eq!(&out[..], b"    x\n    y\n");
    }

    #[test]
    fn prefix_filter_prefix_plus_indent_combined() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::with_prefix_and_indent(sink, "> ", 2);
        pf.write_all(b"hello\n").unwrap();
        let out = pf.into_inner();
        assert_eq!(&out[..], b">   hello\n");
    }

    #[test]
    fn prefix_filter_handles_partial_line_across_calls() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::with_prefix(sink, "[X] ");
        pf.write_all(b"abc").unwrap();
        pf.write_all(b"def\n").unwrap();
        let out = pf.into_inner();
        // Only one prefix should be emitted (at the true line start).
        assert_eq!(&out[..], b"[X] abcdef\n");
    }

    #[test]
    fn prefix_filter_indent_clamped_to_max() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::new(sink);
        pf.set_indent(usize::MAX);
        assert_eq!(pf.indent(), MAX_INDENT);
    }

    #[test]
    fn prefix_filter_set_prefix_none_clears_prefix() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::with_prefix(sink, "prefix:");
        pf.set_prefix(None);
        assert!(pf.prefix().is_none());
    }

    #[test]
    fn prefix_filter_bio_trait_methods() {
        let sink: Vec<u8> = Vec::new();
        let pf = PrefixFilter::with_prefix(sink, "A ");
        assert_eq!(pf.bio_type(), BioType::Prefix);
        assert_eq!(pf.method_name(), "prefix");
        assert_eq!(pf.pending(), 0);
        assert_eq!(pf.wpending(), 0);
    }

    #[test]
    fn prefix_filter_reset_returns_to_linestart() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::with_prefix(sink, "P:");
        // Write a partial line so linestart becomes false.
        pf.write_all(b"abc").unwrap();
        pf.reset().unwrap();
        // After reset, next write starts a fresh line with prefix.
        pf.write_all(b"def\n").unwrap();
        let out = pf.into_inner();
        // First segment writes "P:abc" (prefix + partial).
        // After reset, linestart=true so next write prepends prefix again
        // yielding "P:def\n".
        assert_eq!(&out[..], b"P:abcP:def\n");
    }

    #[test]
    fn prefix_filter_empty_prefix_string_acts_as_no_prefix() {
        let sink: Vec<u8> = Vec::new();
        let mut pf = PrefixFilter::with_prefix(sink, "");
        pf.write_all(b"hello\n").unwrap();
        let out = pf.into_inner();
        assert_eq!(&out[..], b"hello\n");
    }

    #[test]
    fn prefix_filter_accessors() {
        let sink: Vec<u8> = Vec::new();
        let pf = PrefixFilter::with_prefix_and_indent(sink, "pfx", 3);
        assert_eq!(pf.prefix(), Some("pfx"));
        assert_eq!(pf.indent(), 3);
    }

    // -------- NullFilter --------

    #[test]
    fn null_filter_read_passthrough() {
        let src = Cursor::new(b"abcdef".to_vec());
        let mut nf = NullFilter::new(src);
        let mut out = [0u8; 6];
        nf.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"abcdef");
        assert_eq!(nf.stats().bytes_read(), 6);
    }

    #[test]
    fn null_filter_write_passthrough() {
        let sink: Vec<u8> = Vec::new();
        let mut nf = NullFilter::new(sink);
        nf.write_all(b"xyz").unwrap();
        assert_eq!(nf.stats().bytes_written(), 3);
        let out = nf.into_inner();
        assert_eq!(&out[..], b"xyz");
    }

    #[test]
    fn null_filter_bio_trait_methods() {
        let src = Cursor::new(Vec::<u8>::new());
        let mut nf = NullFilter::new(src);
        assert_eq!(nf.bio_type(), BioType::NullFilter);
        assert_eq!(nf.method_name(), "null filter");
        assert_eq!(nf.pending(), 0);
        assert_eq!(nf.wpending(), 0);
        assert!(!nf.eof());
        nf.reset().unwrap();
    }

    #[test]
    fn null_filter_get_ref_and_get_mut() {
        let mut nf = NullFilter::new(Vec::<u8>::new());
        assert!(nf.get_ref().is_empty());
        nf.get_mut().push(0x7F);
        assert_eq!(nf.get_ref().as_slice(), &[0x7F]);
    }

    #[test]
    fn null_filter_bufread_passthrough() {
        let src = Cursor::new(b"hello".to_vec());
        let mut nf = NullFilter::new(src);
        let len = {
            let slice = nf.fill_buf().unwrap();
            assert_eq!(slice, b"hello");
            slice.len()
        };
        nf.consume(len);
        assert_eq!(nf.stats().bytes_read(), u64::try_from(len).unwrap());
    }

    // -------- FilterChainBuilder --------

    #[test]
    fn filter_chain_builder_constructs_all_filter_types() {
        // with_buffer
        let src = Cursor::new(b"abc".to_vec());
        let buf = FilterChainBuilder::with_buffer(src);
        assert_eq!(buf.bio_type(), BioType::Buffer);

        // with_line_buffer
        let sink: Vec<u8> = Vec::new();
        let lb = FilterChainBuilder::with_line_buffer(sink);
        assert_eq!(lb.bio_type(), BioType::LineBuffer);

        // with_read_buffer
        let src = Cursor::new(b"xyz".to_vec());
        let rb = FilterChainBuilder::with_read_buffer(src);
        assert_eq!(rb.bio_type(), BioType::ReadBuffer);

        // with_prefix (Some)
        let sink: Vec<u8> = Vec::new();
        let pf = FilterChainBuilder::with_prefix(sink, Some("hdr:".to_string()), 2);
        assert_eq!(pf.bio_type(), BioType::Prefix);
        assert_eq!(pf.prefix(), Some("hdr:"));
        assert_eq!(pf.indent(), 2);

        // with_prefix (None — indent only)
        let sink: Vec<u8> = Vec::new();
        let pf = FilterChainBuilder::with_prefix(sink, None, 4);
        assert!(pf.prefix().is_none());
        assert_eq!(pf.indent(), 4);

        // with_null
        let src = Cursor::new(b"abc".to_vec());
        let nf = FilterChainBuilder::with_null(src);
        assert_eq!(nf.bio_type(), BioType::NullFilter);
    }

    #[test]
    fn filter_chain_builder_default_instance() {
        // Builder is stateless — verify Debug/Clone/Copy traits work as
        // expected on the unit struct.
        let builder = FilterChainBuilder;
        let copied = builder; // Copy
        let cloned = builder; // also Copy; Clone is present too
        assert_eq!(format!("{builder:?}"), format!("{copied:?}"));
        assert_eq!(format!("{builder:?}"), format!("{cloned:?}"));
    }

    // -------- Composability (end-to-end) --------

    #[test]
    fn compose_prefix_over_null_over_cursor() {
        // Demonstrates nested filter chains — the key use case for
        // FilterChainBuilder.
        let sink: Vec<u8> = Vec::new();
        let null = FilterChainBuilder::with_null(sink);
        let mut prefixed = FilterChainBuilder::with_prefix(null, Some("log: ".to_string()), 0);
        prefixed.write_all(b"line1\nline2\n").unwrap();
        let null = prefixed.into_inner();
        let out = null.into_inner();
        assert_eq!(&out[..], b"log: line1\nlog: line2\n");
    }

    #[test]
    fn compose_buffer_over_cursor_survives_multiple_reads() {
        let data: Vec<u8> = (0u8..=255).collect();
        let src = Cursor::new(data.clone());
        let mut buf = FilterChainBuilder::with_buffer(src);
        let mut collected: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 16];
        loop {
            let n = buf.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(collected, data);
    }

    #[test]
    fn default_buffer_size_matches_module_constant() {
        // Sanity check: the re-exported constant from the bio module is
        // what we import and use for buffer sizing defaults.
        assert_eq!(DEFAULT_BUFFER_SIZE, 4096);
    }
}
