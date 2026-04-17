//! File and file-descriptor BIO implementations.
//!
//! Stub module — full implementation provided by dedicated agent.

use super::{Bio, BioStats, BioType};
use openssl_common::CryptoResult;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// File open mode flags, replacing C `BIO_read_filename()` / `BIO_CLOSE` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Open for reading (`"r"`).
    Read,
    /// Open for writing, truncating (`"w"`).
    Write,
    /// Open for appending (`"a"`).
    Append,
    /// Open for reading in binary mode (`"rb"`).
    ReadBinary,
    /// Open for writing in binary mode, truncating (`"wb"`).
    WriteBinary,
    /// Open for appending in binary mode (`"ab"`).
    AppendBinary,
    /// Open for reading and writing in binary mode (`"r+b"`).
    ReadWriteBinary,
}

impl OpenMode {
    /// Parses an `OpenMode` from a C-style mode string.
    pub fn from_mode_str(s: &str) -> Option<Self> {
        match s {
            "r" => Some(OpenMode::Read),
            "w" => Some(OpenMode::Write),
            "a" => Some(OpenMode::Append),
            "rb" => Some(OpenMode::ReadBinary),
            "wb" => Some(OpenMode::WriteBinary),
            "ab" => Some(OpenMode::AppendBinary),
            "r+b" | "rb+" => Some(OpenMode::ReadWriteBinary),
            _ => None,
        }
    }

    /// Converts this mode to `std::fs::OpenOptions`.
    pub fn to_open_options(&self) -> fs::OpenOptions {
        let mut opts = fs::OpenOptions::new();
        match self {
            OpenMode::Read | OpenMode::ReadBinary => {
                opts.read(true);
            }
            OpenMode::Write | OpenMode::WriteBinary => {
                opts.write(true).create(true).truncate(true);
            }
            OpenMode::Append | OpenMode::AppendBinary => {
                opts.append(true).create(true);
            }
            OpenMode::ReadWriteBinary => {
                opts.read(true).write(true).create(true);
            }
        }
        opts
    }
}

/// File-backed BIO, replacing C `BIO_s_file()`.
///
/// Wraps a `std::fs::File` and provides `Read`/`Write` via the filesystem.
#[derive(Debug)]
pub struct FileBio {
    file: fs::File,
    path: Option<PathBuf>,
    stats: BioStats,
}

impl FileBio {
    /// Opens a file at the given path with the specified mode.
    pub fn new<P: AsRef<Path>>(path: P, mode: OpenMode) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = mode.to_open_options().open(&path)?;
        Ok(Self {
            file,
            path: Some(path),
            stats: BioStats::new(),
        })
    }

    /// Wraps an existing `File` handle.
    pub fn from_file(file: fs::File) -> Self {
        Self {
            file,
            path: None,
            stats: BioStats::new(),
        }
    }

    /// Returns the path of the file, if known.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Resets (seeks to beginning).
    pub fn reset(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    /// Returns the current position in the file.
    pub fn tell(&mut self) -> io::Result<u64> {
        self.file.stream_position()
    }

    /// Consumes the `FileBio` and returns the inner `File`.
    pub fn into_inner(self) -> fs::File {
        self.file
    }
}

impl Read for FileBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for FileBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Bio for FileBio {
    fn bio_type(&self) -> BioType {
        BioType::File
    }

    fn reset(&mut self) -> CryptoResult<()> {
        FileBio::reset(self).map_err(openssl_common::CryptoError::Io)
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "file"
    }
}

/// File-descriptor BIO for stdout/stderr, replacing C `BIO_s_fd()`.
///
/// Wraps a raw file descriptor (or platform abstraction thereof).
#[derive(Debug)]
pub struct FdBio {
    inner: Box<dyn FdInner>,
    stats: BioStats,
}

trait FdInner: std::fmt::Debug + Read + Write + Send {
    fn fd_type(&self) -> &'static str;
}

#[derive(Debug)]
struct StdoutFd;

impl Read for StdoutFd {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot read from stdout",
        ))
    }
}

impl Write for StdoutFd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stdout().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

impl FdInner for StdoutFd {
    fn fd_type(&self) -> &'static str {
        "stdout"
    }
}

#[derive(Debug)]
struct StderrFd;

impl Read for StderrFd {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot read from stderr",
        ))
    }
}

impl Write for StderrFd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stderr().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

impl FdInner for StderrFd {
    fn fd_type(&self) -> &'static str {
        "stderr"
    }
}

#[derive(Debug)]
struct RawFd {
    file: fs::File,
}

impl Read for RawFd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for RawFd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl FdInner for RawFd {
    fn fd_type(&self) -> &'static str {
        "fd"
    }
}

impl FdBio {
    /// Creates an `FdBio` wrapping a file handle.
    pub fn new(file: fs::File) -> Self {
        Self {
            inner: Box::new(RawFd { file }),
            stats: BioStats::new(),
        }
    }

    /// Creates an `FdBio` writing to stdout.
    pub fn stdout() -> Self {
        Self {
            inner: Box::new(StdoutFd),
            stats: BioStats::new(),
        }
    }

    /// Creates an `FdBio` writing to stderr.
    pub fn stderr() -> Self {
        Self {
            inner: Box::new(StderrFd),
            stats: BioStats::new(),
        }
    }

    /// Consumes the `FdBio` and returns a string description.
    pub fn into_inner(self) -> String {
        self.inner.fd_type().to_string()
    }
}

impl Read for FdBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for FdBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Bio for FdBio {
    fn bio_type(&self) -> BioType {
        BioType::FileDescriptor
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "file descriptor"
    }
}

/// Null sink BIO — discards all writes, returns empty reads.
///
/// Replaces C `BIO_s_null()`.
#[derive(Debug)]
pub struct NullBio {
    stats: BioStats,
}

impl NullBio {
    /// Creates a new null BIO.
    pub fn new() -> Self {
        Self {
            stats: BioStats::new(),
        }
    }
}

impl Default for NullBio {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for NullBio {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0) // Always EOF
    }
}

impl Write for NullBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stats.record_write(buf.len());
        Ok(buf.len()) // Discard all data
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Bio for NullBio {
    fn bio_type(&self) -> BioType {
        BioType::Null
    }

    fn eof(&self) -> bool {
        true
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "NULL"
    }
}

/// Logging BIO that writes to the `tracing` log subsystem.
///
/// Replaces C syslog BIO.
#[derive(Debug)]
pub struct LogBio {
    level: LogLevel,
    stats: BioStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogBio {
    /// Creates a new log BIO at the default (info) level.
    pub fn new() -> Self {
        Self {
            level: LogLevel::Info,
            stats: BioStats::new(),
        }
    }

    /// Sets the logging level.
    pub fn set_level(&mut self, level: &str) {
        self.level = match level {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        };
    }
}

impl Default for LogBio {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for LogBio {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0) // Log BIO does not support reading
    }
}

impl Write for LogBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let msg = String::from_utf8_lossy(buf);
        match self.level {
            LogLevel::Trace => tracing::trace!("{}", msg),
            LogLevel::Debug => tracing::debug!("{}", msg),
            LogLevel::Info => tracing::info!("{}", msg),
            LogLevel::Warn => tracing::warn!("{}", msg),
            LogLevel::Error => tracing::error!("{}", msg),
        }
        self.stats.record_write(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Bio for LogBio {
    fn bio_type(&self) -> BioType {
        BioType::Log
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn method_name(&self) -> &str {
        "log"
    }
}
