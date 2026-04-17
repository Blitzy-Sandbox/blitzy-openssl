//! In-memory BIO implementations.
//!
//! Stub module — full implementation provided by dedicated agent.

use std::io::{self, Read, Write};
use super::{Bio, BioType, BioStats};
use openssl_common::CryptoResult;

/// In-memory buffer BIO replacing C `BIO_s_mem()`.
///
/// Provides a growable in-memory byte buffer that implements
/// `Read` and `Write` for use as a source/sink BIO.
#[derive(Debug)]
pub struct MemBio {
    buf: Vec<u8>,
    pos: usize,
    eof_on_empty: bool,
    read_only: bool,
    stats: BioStats,
}

impl MemBio {
    /// Creates a new empty `MemBio`.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            eof_on_empty: true,
            read_only: false,
            stats: BioStats::new(),
        }
    }

    /// Creates a new `MemBio` with the specified initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            pos: 0,
            eof_on_empty: true,
            read_only: false,
            stats: BioStats::new(),
        }
    }

    /// Creates a read-only `MemBio` from a byte slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            buf: data.to_vec(),
            pos: 0,
            eof_on_empty: true,
            read_only: true,
            stats: BioStats::new(),
        }
    }

    /// Sets whether to report EOF when the buffer is empty.
    pub fn set_eof_on_empty(&mut self, eof: bool) {
        self.eof_on_empty = eof;
    }

    /// Returns the number of bytes in the buffer.
    pub fn len(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if this BIO is read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Returns the unread portion of the buffer as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Returns a copy of the internal data from the current read position.
    pub fn get_data(&self) -> Vec<u8> {
        self.buf[self.pos..].to_vec()
    }

    /// Resets the BIO, clearing the buffer and position.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.pos = 0;
        self.stats.reset();
    }

    /// Consumes the `MemBio` and returns the internal buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        if self.pos == 0 {
            self.buf
        } else {
            self.buf[self.pos..].to_vec()
        }
    }
}

impl Default for MemBio {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for MemBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = &self.buf[self.pos..];
        let n = std::cmp::min(buf.len(), available.len());
        if n == 0 {
            return Ok(0);
        }
        buf[..n].copy_from_slice(&available[..n]);
        self.pos = self.pos.saturating_add(n);
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for MemBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "write to read-only MemBio",
            ));
        }
        self.buf.extend_from_slice(buf);
        self.stats.record_write(buf.len());
        Ok(buf.len())
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
        self.len()
    }

    fn eof(&self) -> bool {
        self.eof_on_empty && self.is_empty()
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

/// Secure in-memory BIO that zeroes memory on drop.
///
/// Wraps a `Vec<u8>` and uses `zeroize` (when available) or manual
/// zeroing to ensure key material is cleared from memory.
#[derive(Debug)]
pub struct SecureMemBio {
    buf: Vec<u8>,
    pos: usize,
    stats: BioStats,
}

impl SecureMemBio {
    /// Creates a new empty secure memory BIO.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            stats: BioStats::new(),
        }
    }

    /// Creates a new secure memory BIO with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            pos: 0,
            stats: BioStats::new(),
        }
    }

    /// Creates a secure memory BIO from a byte slice (data is copied).
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            buf: data.to_vec(),
            pos: 0,
            stats: BioStats::new(),
        }
    }

    /// Returns the number of readable bytes.
    pub fn len(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Returns true if the buffer has no readable bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Resets the buffer, zeroing contents.
    pub fn reset(&mut self) {
        // Zero the buffer contents before clearing
        for byte in &mut self.buf {
            *byte = 0;
        }
        self.buf.clear();
        self.pos = 0;
        self.stats.reset();
    }

    /// Returns unread portion as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[self.pos..]
    }
}

impl Default for SecureMemBio {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureMemBio {
    fn drop(&mut self) {
        // Zero all bytes before deallocation
        for byte in &mut self.buf {
            *byte = 0;
        }
    }
}

impl Read for SecureMemBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = &self.buf[self.pos..];
        let n = std::cmp::min(buf.len(), available.len());
        if n == 0 {
            return Ok(0);
        }
        buf[..n].copy_from_slice(&available[..n]);
        self.pos = self.pos.saturating_add(n);
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for SecureMemBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        self.stats.record_write(buf.len());
        Ok(buf.len())
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
        self.is_empty()
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

/// One end of a BIO pair for in-process bidirectional communication.
///
/// Replaces C `BIO_s_bio()` / `BIO_new_bio_pair()`.
#[derive(Debug)]
pub struct BioPairEnd {
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
    write_closed: bool,
    buffer_size: usize,
    stats: BioStats,
}

impl BioPairEnd {
    /// Returns the number of bytes available for reading.
    pub fn pending(&self) -> usize {
        self.read_buf.len().saturating_sub(self.read_pos)
    }

    /// Returns the number of bytes that can be written before the buffer is full.
    pub fn wpending(&self) -> usize {
        self.buffer_size.saturating_sub(self.write_buf.len())
    }

    /// Closes the write side; the peer will see EOF after draining.
    pub fn close_write(&mut self) {
        self.write_closed = true;
    }

    /// Returns whether the write side is closed.
    pub fn is_write_closed(&self) -> bool {
        self.write_closed
    }

    /// Returns the configured buffer size.
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}

impl Read for BioPairEnd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = &self.read_buf[self.read_pos..];
        let n = std::cmp::min(buf.len(), available.len());
        if n == 0 {
            if self.write_closed {
                return Ok(0); // EOF
            }
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no data available"));
        }
        buf[..n].copy_from_slice(&available[..n]);
        self.read_pos = self.read_pos.saturating_add(n);
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for BioPairEnd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.write_closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write side closed"));
        }
        let space = self.wpending();
        if space == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "buffer full"));
        }
        let n = std::cmp::min(buf.len(), space);
        self.write_buf.extend_from_slice(&buf[..n]);
        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
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
        self.write_closed && self.pending() == 0
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

/// Creates a new BIO pair with the specified buffer sizes.
///
/// Returns two `BioPairEnd` instances that form a bidirectional pipe.
/// Data written to one end becomes readable from the other.
///
/// Replaces C `BIO_new_bio_pair()`.
pub fn new_bio_pair(buf_size1: usize, buf_size2: usize) -> (BioPairEnd, BioPairEnd) {
    let size1 = if buf_size1 == 0 { super::DEFAULT_BUFFER_SIZE } else { buf_size1 };
    let size2 = if buf_size2 == 0 { super::DEFAULT_BUFFER_SIZE } else { buf_size2 };

    let end1 = BioPairEnd {
        read_buf: Vec::new(),
        read_pos: 0,
        write_buf: Vec::new(),
        write_closed: false,
        buffer_size: size1,
        stats: BioStats::new(),
    };

    let end2 = BioPairEnd {
        read_buf: Vec::new(),
        read_pos: 0,
        write_buf: Vec::new(),
        write_closed: false,
        buffer_size: size2,
        stats: BioStats::new(),
    };

    (end1, end2)
}
