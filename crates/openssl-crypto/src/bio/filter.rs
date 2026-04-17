//! Filter chain BIO implementations (buffering, line-buffering, prefix, null).
//!
//! Stub module — full implementation provided by dedicated agent.

use std::io::{self, Read, Write};
use super::{Bio, BioType, BioStats};


/// Buffering filter BIO wrapping an inner `Read + Write`, replacing C `BIO_f_buffer()`.
///
/// Adds input and output buffering to reduce system call overhead.
#[derive(Debug)]
pub struct BufferFilter<T: Read + Write> {
    inner: T,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_end: usize,
    write_buf: Vec<u8>,
    capacity: usize,
    stats: BioStats,
}

impl<T: Read + Write> BufferFilter<T> {
    /// Creates a new buffer filter with default capacity.
    pub fn new(inner: T) -> Self {
        Self::with_capacity(super::DEFAULT_BUFFER_SIZE, inner)
    }

    /// Creates a new buffer filter with the specified capacity.
    pub fn with_capacity(capacity: usize, inner: T) -> Self {
        Self {
            inner,
            read_buf: vec![0u8; capacity],
            read_pos: 0,
            read_end: 0,
            write_buf: Vec::with_capacity(capacity),
            capacity,
            stats: BioStats::new(),
        }
    }

    /// Consumes the filter and returns the inner I/O object.
    pub fn into_inner(mut self) -> T {
        // Best-effort flush before unwrapping
        let _ = self.flush();
        self.inner
    }

    /// Returns a reference to the inner I/O object.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the inner I/O object.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns the number of buffered readable bytes.
    pub fn pending(&self) -> usize {
        self.read_end.saturating_sub(self.read_pos)
    }

    /// Returns the number of buffered writable bytes (not yet flushed).
    pub fn wpending(&self) -> usize {
        self.write_buf.len()
    }
}

impl<T: Read + Write> Read for BufferFilter<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If internal buffer is empty, refill it
        if self.read_pos >= self.read_end {
            self.read_pos = 0;
            self.read_end = self.inner.read(&mut self.read_buf)?;
            if self.read_end == 0 {
                return Ok(0);
            }
        }
        let available = &self.read_buf[self.read_pos..self.read_end];
        let n = std::cmp::min(buf.len(), available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.read_pos = self.read_pos.saturating_add(n);
        self.stats.record_read(n);
        Ok(n)
    }
}

impl<T: Read + Write> Write for BufferFilter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // If adding to write buf would exceed capacity, flush first
        if self.write_buf.len().saturating_add(buf.len()) > self.capacity {
            self.flush()?;
        }
        // If still too large, write directly to inner
        if buf.len() > self.capacity {
            let n = self.inner.write(buf)?;
            self.stats.record_write(n);
            return Ok(n);
        }
        self.write_buf.extend_from_slice(buf);
        self.stats.record_write(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.write_buf.is_empty() {
            self.inner.write_all(&self.write_buf)?;
            self.write_buf.clear();
        }
        self.inner.flush()
    }
}

impl<T: Read + Write + Send> Bio for BufferFilter<T> {
    fn bio_type(&self) -> BioType {
        BioType::Buffer
    }

    fn pending(&self) -> usize {
        BufferFilter::pending(self)
    }

    fn wpending(&self) -> usize {
        BufferFilter::wpending(self)
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

/// Line-buffering filter — flushes on newline, replacing C `BIO_f_linebuffer()`.
#[derive(Debug)]
pub struct LineBufferFilter<T: Read + Write> {
    inner: T,
    write_buf: Vec<u8>,
    capacity: usize,
    stats: BioStats,
}

impl<T: Read + Write> LineBufferFilter<T> {
    /// Creates a new line buffer filter with default capacity.
    pub fn new(inner: T) -> Self {
        Self::with_capacity(super::DEFAULT_BUFFER_SIZE, inner)
    }

    /// Creates a new line buffer filter with specified capacity.
    pub fn with_capacity(capacity: usize, inner: T) -> Self {
        Self {
            inner,
            write_buf: Vec::with_capacity(capacity),
            capacity,
            stats: BioStats::new(),
        }
    }

    /// Consumes the filter and returns the inner I/O object.
    pub fn into_inner(mut self) -> T {
        let _ = self.flush();
        self.inner
    }
}

impl<T: Read + Write> Read for LineBufferFilter<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl<T: Read + Write> Write for LineBufferFilter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.extend_from_slice(buf);
        self.stats.record_write(buf.len());

        // Flush on newline
        if let Some(nl_pos) = self.write_buf.iter().rposition(|&b| b == b'\n') {
            let to_flush = self.write_buf[..=nl_pos].to_vec();
            self.inner.write_all(&to_flush)?;
            self.write_buf.drain(..=nl_pos);
        }

        // Also flush if buffer exceeds capacity
        if self.write_buf.len() >= self.capacity {
            self.inner.write_all(&self.write_buf)?;
            self.write_buf.clear();
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.write_buf.is_empty() {
            self.inner.write_all(&self.write_buf)?;
            self.write_buf.clear();
        }
        self.inner.flush()
    }
}

impl<T: Read + Write + Send> Bio for LineBufferFilter<T> {
    fn bio_type(&self) -> BioType {
        BioType::LineBuffer
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

/// Prefix filter — prepends a string prefix to each line of output.
#[derive(Debug)]
pub struct PrefixFilter<T: Read + Write> {
    inner: T,
    prefix: String,
    indent: usize,
    at_line_start: bool,
    stats: BioStats,
}

impl<T: Read + Write> PrefixFilter<T> {
    /// Creates a new prefix filter with no prefix.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            prefix: String::new(),
            indent: 0,
            at_line_start: true,
            stats: BioStats::new(),
        }
    }

    /// Creates a new prefix filter with the specified prefix string.
    pub fn with_prefix(inner: T, prefix: &str) -> Self {
        Self {
            inner,
            prefix: prefix.to_string(),
            indent: 0,
            at_line_start: true,
            stats: BioStats::new(),
        }
    }

    /// Sets the prefix string.
    pub fn set_prefix(&mut self, prefix: &str) {
        self.prefix = prefix.to_string();
    }

    /// Sets an indentation level (number of spaces before prefix).
    pub fn set_indent(&mut self, indent: usize) {
        self.indent = indent;
    }

    /// Consumes the filter and returns the inner I/O object.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Read + Write> Read for PrefixFilter<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl<T: Read + Write> Write for PrefixFilter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        for &b in buf {
            if self.at_line_start {
                // Write indent spaces
                for _ in 0..self.indent {
                    self.inner.write_all(b" ")?;
                }
                // Write prefix
                if !self.prefix.is_empty() {
                    self.inner.write_all(self.prefix.as_bytes())?;
                }
                self.at_line_start = false;
            }
            self.inner.write_all(&[b])?;
            written += 1;
            if b == b'\n' {
                self.at_line_start = true;
            }
        }
        self.stats.record_write(written);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T: Read + Write + Send> Bio for PrefixFilter<T> {
    fn bio_type(&self) -> BioType {
        BioType::Prefix
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

/// Null filter — passes through all data unchanged, replacing C `BIO_f_null()`.
#[derive(Debug)]
pub struct NullFilter<T: Read + Write> {
    inner: T,
    stats: BioStats,
}

impl<T: Read + Write> NullFilter<T> {
    /// Creates a new null filter wrapping an inner I/O object.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            stats: BioStats::new(),
        }
    }

    /// Consumes the filter and returns the inner I/O object.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Returns a reference to the inner I/O object.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the inner I/O object.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Read + Write> Read for NullFilter<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl<T: Read + Write> Write for NullFilter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T: Read + Write + Send> Bio for NullFilter<T> {
    fn bio_type(&self) -> BioType {
        BioType::NullFilter
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

/// Read-buffering filter — caches read data for re-reading.
#[derive(Debug)]
pub struct ReadBufferFilter<T: Read> {
    inner: T,
    cache: Vec<u8>,
    position: usize,
    stats: BioStats,
}

impl<T: Read> ReadBufferFilter<T> {
    /// Creates a new read buffer filter.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            cache: Vec::new(),
            position: 0,
            stats: BioStats::new(),
        }
    }

    /// Returns the number of cached bytes.
    pub fn cached_len(&self) -> usize {
        self.cache.len()
    }

    /// Returns the current read position in the cache.
    pub fn position(&self) -> usize {
        self.position
    }
}

impl<T: Read> Read for ReadBufferFilter<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Read from cache first if available
        if self.position < self.cache.len() {
            let available = &self.cache[self.position..];
            let n = std::cmp::min(buf.len(), available.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.position = self.position.saturating_add(n);
            self.stats.record_read(n);
            return Ok(n);
        }

        // Otherwise read from inner and cache
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.cache.extend_from_slice(&buf[..n]);
            self.position = self.position.saturating_add(n);
            self.stats.record_read(n);
        }
        Ok(n)
    }
}

/// Builder for constructing filter chains, replacing C `BIO_push()` chains.
///
/// Provides a fluent API to compose filter BIOs.
#[derive(Debug)]
pub struct FilterChainBuilder;

impl FilterChainBuilder {
    /// Wraps the inner BIO with a buffer filter.
    pub fn with_buffer<T: Read + Write>(inner: T) -> BufferFilter<T> {
        BufferFilter::new(inner)
    }

    /// Wraps the inner BIO with a line buffer filter.
    pub fn with_line_buffer<T: Read + Write>(inner: T) -> LineBufferFilter<T> {
        LineBufferFilter::new(inner)
    }

    /// Wraps the inner BIO with a prefix filter.
    pub fn with_prefix<T: Read + Write>(inner: T, prefix: &str) -> PrefixFilter<T> {
        PrefixFilter::with_prefix(inner, prefix)
    }

    /// Wraps the inner BIO with a null (pass-through) filter.
    pub fn with_null<T: Read + Write>(inner: T) -> NullFilter<T> {
        NullFilter::new(inner)
    }
}
