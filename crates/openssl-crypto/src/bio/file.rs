//! File-based BIO implementations for the OpenSSL Rust workspace.
//!
//! Provides file, file descriptor, null sink, and log sink I/O wrappers.
//! Translates the C file BIOs (`bss_file.c`, `bss_fd.c`, `bss_null.c`,
//! `bss_log.c`) into idiomatic Rust types built on [`std::fs::File`]
//! and the [`std::io`] trait family.
//!
//! # C-to-Rust Type Mapping
//!
//! | C Type / Function                | Rust Equivalent                          |
//! |----------------------------------|------------------------------------------|
//! | `BIO_s_file()` / `BIO_new_file`  | [`FileBio::new`] / [`FileBio::from_file`]|
//! | `BIO_s_fd()` / `BIO_new_fd`      | [`FdBio::new`] / [`FdBio::stdout`] etc.  |
//! | `BIO_s_null()` / `BIO_new(null)` | [`NullBio::new`]                         |
//! | `BIO_s_log()` / `BIO_new(log)`   | [`LogBio::new`] (via [`tracing`])        |
//! | `BIO_s_mem()` / `BIO_s_socket()` | See [`super::mem`] / [`super::socket`]   |
//! | `FILE *` (from `<stdio.h>`)      | [`std::fs::File`]                        |
//! | POSIX file descriptor (`int`)    | [`std::fs::File`] / [`io::Stdout`]       |
//! | `fopen` mode string              | [`OpenMode`] enum                        |
//! | `BIO_CTRL_RESET`                 | [`FileBio::reset`] / [`Bio::reset`]      |
//! | `BIO_CTRL_INFO` (file tell)      | [`FileBio::tell`]                        |
//! | `syslog` / `EventLog` / `OPCOM`  | [`tracing`] macros                       |
//!
//! # Design Principles
//!
//! - **Zero `unsafe`** (Rule R8) — every BIO wraps a safe
//!   [`std::fs::File`] or an owned stdio handle; there is no
//!   `FromRawFd` / `IntoRawFd` juggling.
//! - **Nullability over sentinels** (Rule R5) — file paths are
//!   [`Option<&Path>`], open modes are typed via [`OpenMode`],
//!   constructors return [`CryptoResult`].
//! - **Lossless casts** (Rule R6) — byte counters use `u64`,
//!   file positions use `u64`, and `usize → u64` widening is always
//!   lossless on supported platforms.
//! - **Observability-first** (AAP §0.8.5) — [`LogBio`] integrates
//!   with the workspace-wide [`tracing`] infrastructure.
//!
//! # Consistency Delta (C → Rust)
//!
//! The C BIOs support a `BIO_NOCLOSE` flag that prevents the BIO from
//! closing the underlying descriptor when freed. In safe Rust, a
//! [`File`] always closes on [`Drop`]. Callers that need to retain
//! ownership of the underlying handle should obtain it via
//! [`FileBio::into_inner`] / [`FdBio::into_inner`] **before** dropping
//! the BIO. The [`FileBio::close_on_drop`] / [`FdBio::close_on_drop`]
//! flags record the caller's stated intent and are exposed for
//! diagnostic parity with C's `BIO_get_close()`.

use super::{Bio, BioStats, BioType};
use openssl_common::{CryptoError, CryptoResult};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// OpenMode — typed replacement for C fopen mode strings
// ---------------------------------------------------------------------------

/// File open mode, replacing C-style `fopen` mode strings.
///
/// In C, file modes are passed as short strings such as `"r"`, `"wb"`,
/// or `"r+b"`. Rust's [`OpenOptions`] is richer but more verbose; this
/// enum provides a small, typed vocabulary that mirrors the common
/// cases used by OpenSSL callers while forwarding to [`OpenOptions`]
/// under the hood. Each variant has one unambiguous meaning, eliminating
/// the classic `fopen` pitfalls around mode-string misspellings.
///
/// # Mapping to C fopen Modes
///
/// | C mode     | `OpenMode`               | Behaviour                              |
/// |------------|--------------------------|----------------------------------------|
/// | `"r"`      | [`OpenMode::Read`]       | Read only, file must exist             |
/// | `"w"`      | [`OpenMode::Write`]      | Write only, create/truncate            |
/// | `"a"`      | [`OpenMode::Append`]     | Write only, create, append             |
/// | `"rb"`     | [`OpenMode::ReadBinary`] | Read only (binary — no-op on POSIX)    |
/// | `"wb"`     | [`OpenMode::WriteBinary`]| Write only, create/truncate (binary)   |
/// | `"ab"`     | [`OpenMode::AppendBinary`]| Write only, create, append (binary)   |
/// | `"r+b"`    | [`OpenMode::ReadWriteBinary`]| Read+write, file must exist        |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Read-only text mode (C `"r"`).
    Read,
    /// Write-only text mode, truncates on open (C `"w"`).
    Write,
    /// Append text mode, creates if missing (C `"a"`).
    Append,
    /// Read-only binary mode (C `"rb"`).
    ReadBinary,
    /// Write-only binary mode, truncates on open (C `"wb"`).
    WriteBinary,
    /// Append binary mode, creates if missing (C `"ab"`).
    AppendBinary,
    /// Read-write binary mode, file must exist (C `"r+b"`).
    ReadWriteBinary,
}

impl OpenMode {
    /// Parses a C-style `fopen` mode string into an [`OpenMode`].
    ///
    /// Replaces the mode-string parser implicit in C `BIO_new_file()`
    /// from `crypto/bio/bss_file.c` (lines 62-85). Accepts the common
    /// OpenSSL mode strings and returns [`None`] for unrecognized input
    /// rather than signaling an error via a magic value (Rule R5).
    ///
    /// Mode characters may appear in any order (`"rb"` and `"br"` are
    /// both valid), matching the permissive parsing of libc fopen on
    /// most platforms.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::bio::file::OpenMode;
    ///
    /// assert_eq!(OpenMode::from_str("rb"), Some(OpenMode::ReadBinary));
    /// assert_eq!(OpenMode::from_str("w"),  Some(OpenMode::Write));
    /// assert_eq!(OpenMode::from_str("r+b"),Some(OpenMode::ReadWriteBinary));
    /// assert_eq!(OpenMode::from_str("zz"), None);
    /// ```
    // `from_str` is an inherent method that intentionally mirrors the
    // AAP-mandated API; the return type (`Option<Self>`) differs from
    // the `std::str::FromStr` contract (`Result<Self, E>`), so we
    // deliberately do not implement that trait.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn from_str(mode: &str) -> Option<Self> {
        let has_read = mode.contains('r');
        let has_write = mode.contains('w');
        let has_append = mode.contains('a');
        let has_binary = mode.contains('b');
        let has_plus = mode.contains('+');

        // Exactly one of read/write/append must be set.
        match (has_read, has_write, has_append, has_plus, has_binary) {
            // "r+b" / "rb+" / "r+" (treat text+ as binary+) — read+write, must exist
            (true, false, false, true, _) => Some(OpenMode::ReadWriteBinary),
            // "rb"
            (true, false, false, false, true) => Some(OpenMode::ReadBinary),
            // "r"
            (true, false, false, false, false) => Some(OpenMode::Read),
            // "wb"
            (false, true, false, false, true) => Some(OpenMode::WriteBinary),
            // "w"
            (false, true, false, false, false) => Some(OpenMode::Write),
            // "ab"
            (false, false, true, false, true) => Some(OpenMode::AppendBinary),
            // "a"
            (false, false, true, false, false) => Some(OpenMode::Append),
            _ => None,
        }
    }

    /// Converts this mode into [`OpenOptions`] suitable for
    /// [`OpenOptions::open`].
    ///
    /// Replaces the bitwise OR of `O_RDONLY` / `O_WRONLY` / `O_APPEND`
    /// / `O_CREAT` / `O_TRUNC` flags assembled by C `BIO_new_file()`.
    /// Note that on Unix the binary flag is a no-op (all I/O is
    /// byte-level); it is retained for Windows parity and
    /// self-documenting call sites.
    #[must_use]
    pub fn to_open_options(self) -> OpenOptions {
        let mut opts = OpenOptions::new();
        match self {
            OpenMode::Read | OpenMode::ReadBinary => {
                opts.read(true);
            }
            OpenMode::Write | OpenMode::WriteBinary => {
                opts.write(true).create(true).truncate(true);
            }
            OpenMode::Append | OpenMode::AppendBinary => {
                opts.write(true).create(true).append(true);
            }
            OpenMode::ReadWriteBinary => {
                // C "r+b" semantics: read+write, file must exist,
                // no truncate, no create. Do NOT set create(true).
                opts.read(true).write(true);
            }
        }
        opts
    }

    /// Returns `true` if the mode is a binary-oriented mode.
    #[must_use]
    pub fn is_binary(self) -> bool {
        matches!(
            self,
            OpenMode::ReadBinary
                | OpenMode::WriteBinary
                | OpenMode::AppendBinary
                | OpenMode::ReadWriteBinary
        )
    }

    /// Returns `true` if the mode grants read access.
    #[must_use]
    pub fn is_readable(self) -> bool {
        matches!(
            self,
            OpenMode::Read | OpenMode::ReadBinary | OpenMode::ReadWriteBinary
        )
    }

    /// Returns `true` if the mode grants write access.
    #[must_use]
    pub fn is_writable(self) -> bool {
        matches!(
            self,
            OpenMode::Write
                | OpenMode::WriteBinary
                | OpenMode::Append
                | OpenMode::AppendBinary
                | OpenMode::ReadWriteBinary
        )
    }
}

// ---------------------------------------------------------------------------
// FileBio — C BIO_s_file() / BIO_new_file() equivalent
// ---------------------------------------------------------------------------

/// File-based BIO wrapping a [`std::fs::File`] handle.
///
/// Replaces the C `BIO_s_file()` method set from `crypto/bio/bss_file.c`
/// (lines 42-55) and the convenience constructor `BIO_new_file()`
/// (lines 145-206). Provides buffered file I/O with typed open modes,
/// seeking support, and RAII close-on-drop semantics.
///
/// # Read / Write / Seek Semantics
///
/// [`FileBio`] delegates [`Read`], [`Write`], and [`Seek`] directly to
/// the underlying [`File`]. I/O byte counts are tracked in the embedded
/// [`BioStats`], matching the `num_read` / `num_write` counters on the
/// C `bio_st` struct.
///
/// # Example
///
/// ```no_run
/// use openssl_crypto::bio::file::{FileBio, OpenMode};
/// use std::path::Path;
/// use std::io::Write;
///
/// let mut bio = FileBio::new(Path::new("output.txt"), OpenMode::Write)
///     .expect("open failed");
/// bio.write_all(b"hello openssl-rs\n").expect("write failed");
/// ```
#[derive(Debug)]
pub struct FileBio {
    /// The underlying OS file handle.
    file: File,
    /// Path to the file, if known (used for error messages and diagnostics).
    ///
    /// `None` when the [`FileBio`] was constructed from a pre-opened
    /// [`File`] via [`FileBio::from_file`].
    path: Option<PathBuf>,
    /// Mode that was used to open the file, retained for diagnostics.
    mode: OpenMode,
    /// Whether this BIO "owns" closing the file handle.
    ///
    /// In safe Rust, [`File`] always closes on [`Drop`], so this flag
    /// primarily records the caller's stated intent and is surfaced via
    /// [`FileBio::close_on_drop`] for parity with C's `BIO_get_close()`.
    close_on_drop: bool,
    /// Cumulative I/O byte counters.
    stats: BioStats,
}

impl FileBio {
    /// Opens `path` with the given [`OpenMode`] and wraps the resulting
    /// file handle in a new [`FileBio`].
    ///
    /// Replaces C `BIO_new_file(filename, mode)` from `bss_file.c`
    /// (lines 145-206). Returns [`Err`] with a
    /// [`CryptoError::Io`] wrapping the underlying OS error on failure
    /// (e.g., file not found, permission denied, mode incompatibility),
    /// rather than C's `NULL` sentinel (Rule R5).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Io`] if the underlying OS `open` call
    /// fails. The error preserves the original [`io::Error`] for
    /// diagnostic inspection via [`CryptoError::source`](std::error::Error::source).
    pub fn new(path: &Path, mode: OpenMode) -> CryptoResult<Self> {
        let file = mode.to_open_options().open(path).map_err(CryptoError::Io)?;
        Ok(Self {
            file,
            path: Some(path.to_path_buf()),
            mode,
            close_on_drop: true,
            stats: BioStats::new(),
        })
    }

    /// Wraps an already-opened [`File`] in a new [`FileBio`].
    ///
    /// Replaces C `BIO_set_fp(bio, fp, flags)` from `bss_file.c`
    /// (lines 208-268). The `close_on_drop` flag mirrors the C
    /// `BIO_CLOSE` / `BIO_NOCLOSE` distinction and is exposed via
    /// [`FileBio::close_on_drop`] for diagnostic parity; however, in
    /// safe Rust, the underlying [`File`] always closes on [`Drop`]
    /// (see module-level consistency delta).
    ///
    /// The resulting BIO defaults to [`OpenMode::ReadWriteBinary`]
    /// since the actual open flags of the supplied [`File`] are not
    /// inspectable without platform-specific APIs.
    #[must_use]
    pub fn from_file(file: File, close_on_drop: bool) -> Self {
        Self {
            file,
            path: None,
            mode: OpenMode::ReadWriteBinary,
            close_on_drop,
            stats: BioStats::new(),
        }
    }

    /// Returns the path this BIO was opened with, if known.
    ///
    /// Returns [`None`] when the BIO was constructed via
    /// [`FileBio::from_file`] from a pre-opened handle whose path is
    /// not recorded (Rule R5 — nullability over empty-string sentinels).
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns the [`OpenMode`] that was used to open this file.
    #[must_use]
    pub fn mode(&self) -> OpenMode {
        self.mode
    }

    /// Returns the `close_on_drop` flag recorded at construction time.
    ///
    /// Parity with C `BIO_get_close(bio)`. See the module-level
    /// consistency delta for an explanation of the safe-Rust semantics.
    #[must_use]
    pub fn close_on_drop(&self) -> bool {
        self.close_on_drop
    }

    /// Rewinds the file to offset 0.
    ///
    /// Replaces C `BIO_CTRL_RESET` / `BIO_reset(bio)` on file BIOs,
    /// which invokes `fseek(fp, 0, SEEK_SET)` (see `bss_file.c`
    /// `file_ctrl()`, line 317).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] on seek failure
    /// (e.g., seeking on a pipe or unseekable device).
    pub fn reset(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0)).map(|_| ())
    }

    /// Returns the current byte offset into the file.
    ///
    /// Replaces C `BIO_CTRL_INFO` / `BIO_tell(bio)` (see `bss_file.c`
    /// `file_ctrl()`, line 330). The offset is expressed as a `u64`
    /// matching [`std::io::Seek::stream_position`] — no narrowing cast
    /// to `long` as in C (Rule R6).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the underlying seek
    /// syscall fails (e.g., on an unseekable handle).
    pub fn tell(&mut self) -> io::Result<u64> {
        self.file.stream_position()
    }

    /// Consumes this BIO and returns the wrapped [`File`].
    ///
    /// Useful for callers who want to retain ownership of the
    /// underlying handle after the BIO is no longer needed
    /// (analogous to C `BIO_get_fp(bio, &fp); BIO_set_close(bio, BIO_NOCLOSE);`).
    #[must_use]
    pub fn into_inner(self) -> File {
        // Safe move: FileBio has no Drop impl, so the File is moved
        // out without triggering a premature close.
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

impl Seek for FileBio {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

impl Bio for FileBio {
    fn bio_type(&self) -> BioType {
        BioType::File
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }

    fn reset(&mut self) -> CryptoResult<()> {
        // Delegates to the inherent FileBio::reset (io::Result<()>),
        // converting its error into CryptoError::Io per the Bio trait
        // contract.
        FileBio::reset(self).map_err(CryptoError::Io)
    }
}

// ---------------------------------------------------------------------------
// FdBio — C BIO_s_fd() equivalent (without `unsafe` raw-fd handling)
// ---------------------------------------------------------------------------

/// Internal discriminant that decouples `FdBio` from the concrete
/// std stream type, allowing both owned [`File`] handles and process
/// stdio ([`io::Stdout`] / [`io::Stderr`]) without `unsafe` fd
/// manipulation.
#[derive(Debug)]
enum FdKind {
    /// Owned file handle (the common case — replaces C `BIO_new_fd`
    /// on a regular fd).
    File(File),
    /// Shared stdout handle — replaces `BIO_new_fd(1, ...)`.
    Stdout(io::Stdout),
    /// Shared stderr handle — replaces `BIO_new_fd(2, ...)`.
    Stderr(io::Stderr),
}

/// File descriptor BIO, replacing C `BIO_s_fd()` from
/// `crypto/bio/bss_fd.c` (lines 42-55).
///
/// In C, `BIO_s_fd()` wraps a raw POSIX `int` file descriptor. In Rust,
/// raw file descriptors are `unsafe` territory (lifetime/ownership
/// cannot be tracked by the compiler). This type accepts only **owned**
/// [`File`] handles — which wrap an already-validated fd — plus the
/// specialized [`FdBio::stdout`] and [`FdBio::stderr`] constructors
/// for the process-level standard streams. This eliminates the
/// `BIO_set_fd()` / `FromRawFd` trap while providing the same
/// user-visible API (Rule R8).
///
/// # Example
///
/// ```no_run
/// use openssl_crypto::bio::file::FdBio;
/// use std::io::Write;
///
/// let mut bio = FdBio::stdout();
/// writeln!(bio, "log line via FdBio").expect("write failed");
/// ```
#[derive(Debug)]
pub struct FdBio {
    inner: FdKind,
    /// Informational flag recording the caller's intent for fd
    /// ownership. See the module-level consistency delta.
    close_on_drop: bool,
    stats: BioStats,
}

impl FdBio {
    /// Wraps an owned [`File`] in a new [`FdBio`].
    ///
    /// Replaces C `BIO_new_fd(fd, close_flag)` from `bss_fd.c`
    /// (lines 92-110). The `close_on_drop` flag mirrors the C
    /// `BIO_CLOSE` / `BIO_NOCLOSE` distinction and is exposed via
    /// [`FdBio::close_on_drop`] for parity with C `BIO_get_close()`.
    #[must_use]
    pub fn new(file: File, close_on_drop: bool) -> Self {
        Self {
            inner: FdKind::File(file),
            close_on_drop,
            stats: BioStats::new(),
        }
    }

    /// Creates an [`FdBio`] wrapping process stdout.
    ///
    /// Equivalent to C `BIO_new_fd(fileno(stdout), BIO_NOCLOSE)`.
    /// Writes go to the process's standard output via [`io::stdout`].
    /// The fd is **not** closed when this BIO is dropped
    /// (`close_on_drop = false`), preserving the process's standard
    /// streams.
    #[must_use]
    pub fn stdout() -> Self {
        Self {
            inner: FdKind::Stdout(io::stdout()),
            close_on_drop: false,
            stats: BioStats::new(),
        }
    }

    /// Creates an [`FdBio`] wrapping process stderr.
    ///
    /// Equivalent to C `BIO_new_fd(fileno(stderr), BIO_NOCLOSE)`.
    /// Writes go to the process's standard error via [`io::stderr`].
    /// The fd is **not** closed when this BIO is dropped, preserving
    /// the process's standard streams.
    #[must_use]
    pub fn stderr() -> Self {
        Self {
            inner: FdKind::Stderr(io::stderr()),
            close_on_drop: false,
            stats: BioStats::new(),
        }
    }

    /// Returns the `close_on_drop` flag recorded at construction time
    /// (C `BIO_get_close` parity). See the module-level consistency
    /// delta for an explanation of the safe-Rust semantics.
    #[must_use]
    pub fn close_on_drop(&self) -> bool {
        self.close_on_drop
    }

    /// Returns `true` if this BIO wraps an owned [`File`] (as opposed
    /// to one of the standard streams).
    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self.inner, FdKind::File(_))
    }

    /// Returns `true` if this BIO wraps process stdout.
    #[must_use]
    pub fn is_stdout(&self) -> bool {
        matches!(self.inner, FdKind::Stdout(_))
    }

    /// Returns `true` if this BIO wraps process stderr.
    #[must_use]
    pub fn is_stderr(&self) -> bool {
        matches!(self.inner, FdKind::Stderr(_))
    }

    /// Consumes this BIO and returns the wrapped [`File`] if it was
    /// constructed from an owned handle.
    ///
    /// Returns [`None`] when the BIO was constructed via
    /// [`FdBio::stdout`] or [`FdBio::stderr`], since process standard
    /// streams are not owned [`File`] handles and cannot be unwrapped
    /// into one (Rule R5 — nullability over empty-handle sentinels).
    #[must_use]
    pub fn into_inner(self) -> Option<File> {
        match self.inner {
            FdKind::File(file) => Some(file),
            FdKind::Stdout(_) | FdKind::Stderr(_) => None,
        }
    }
}

impl Read for FdBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = match &mut self.inner {
            FdKind::File(file) => file.read(buf)?,
            FdKind::Stdout(_) | FdKind::Stderr(_) => {
                // Matches C bss_fd.c semantics: writing to stdout/stderr
                // works, but reading is not supported on these streams.
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "FdBio: cannot read from stdout/stderr",
                ));
            }
        };
        self.stats.record_read(n);
        Ok(n)
    }
}

impl Write for FdBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = match &mut self.inner {
            FdKind::File(file) => file.write(buf)?,
            FdKind::Stdout(stdout) => stdout.write(buf)?,
            FdKind::Stderr(stderr) => stderr.write(buf)?,
        };
        self.stats.record_write(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            FdKind::File(file) => file.flush(),
            FdKind::Stdout(stdout) => stdout.flush(),
            FdKind::Stderr(stderr) => stderr.flush(),
        }
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

    fn reset(&mut self) -> CryptoResult<()> {
        // Seeking only makes sense for owned file handles. For stdio
        // streams, match C bss_fd.c which returns an error on
        // BIO_CTRL_RESET for non-seekable fds.
        match &mut self.inner {
            FdKind::File(file) => file
                .seek(SeekFrom::Start(0))
                .map(|_| ())
                .map_err(CryptoError::Io),
            FdKind::Stdout(_) | FdKind::Stderr(_) => Err(CryptoError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "FdBio: cannot reset stdout/stderr",
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// NullBio — C BIO_s_null() equivalent (`/dev/null` BIO)
// ---------------------------------------------------------------------------

/// Null source/sink BIO — the in-memory equivalent of `/dev/null`.
///
/// Replaces C `BIO_s_null()` from `crypto/bio/bss_null.c`:
/// - Reads always return `Ok(0)` (EOF), matching C `null_read()` at
///   `bss_null.c` line 39 which returns `0`.
/// - Writes always succeed fully (silently discarding the data),
///   matching C `null_write(b, in, inl)` at `bss_null.c` line 47
///   which returns `inl`.
/// - [`Bio::eof`] returns `true` — the read side is always at EOF
///   (matches C `null_ctrl` `BIO_CTRL_EOF` returning 1).
///
/// Useful as a placeholder sink in tests, as a no-op destination in
/// filter chains, or wherever a BIO is required but I/O is undesired.
///
/// # Example
///
/// ```
/// use openssl_crypto::bio::file::NullBio;
/// use std::io::{Read, Write};
///
/// let mut bio = NullBio::new();
/// assert_eq!(bio.write(b"discarded").unwrap(), 9);
///
/// let mut buf = [0u8; 16];
/// assert_eq!(bio.read(&mut buf).unwrap(), 0); // always EOF
/// ```
#[derive(Debug, Default)]
pub struct NullBio {
    /// Byte counters — writes increment `bytes_written` even though
    /// the data is discarded, matching the semantics of `num_write`
    /// on a C NULL BIO.
    stats: BioStats,
}

impl NullBio {
    /// Creates a new [`NullBio`].
    ///
    /// Replaces C `BIO_new(BIO_s_null())`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Read for NullBio {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        // C null_read returns 0 regardless of buffer size.
        Ok(0)
    }
}

impl Write for NullBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // C null_write: data is discarded, but the length is returned
        // as successfully written.
        self.stats.record_write(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // C null_ctrl BIO_CTRL_FLUSH returns 1 (success) — no-op here.
        Ok(())
    }
}

impl Bio for NullBio {
    fn bio_type(&self) -> BioType {
        BioType::Null
    }

    fn eof(&self) -> bool {
        // C null_ctrl BIO_CTRL_EOF returns 1. The null BIO is always
        // at EOF from the read side.
        true
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }
}

// ---------------------------------------------------------------------------
// LogLevel — syslog severity replacement
// ---------------------------------------------------------------------------

/// Syslog-style log severity for [`LogBio`], replacing the C `LOG_*`
/// priority constants from `<syslog.h>` used by `crypto/bio/bss_log.c`.
///
/// The eight variants map directly to the RFC 5424 severity values
/// (0 = most severe, 7 = least severe) and to the five [`tracing`]
/// macros at emission time:
///
/// | `LogLevel`                 | Syslog | tracing macro       |
/// |----------------------------|:------:|---------------------|
/// | [`LogLevel::Emergency`]    | `0`    | [`tracing::error!`] |
/// | [`LogLevel::Alert`]        | `1`    | [`tracing::error!`] |
/// | [`LogLevel::Critical`]     | `2`    | [`tracing::error!`] |
/// | [`LogLevel::Error`]        | `3`    | [`tracing::error!`] |
/// | [`LogLevel::Warning`]      | `4`    | [`tracing::warn!`]  |
/// | [`LogLevel::Notice`]       | `5`    | [`tracing::info!`]  |
/// | [`LogLevel::Info`]         | `6`    | [`tracing::info!`]  |
/// | [`LogLevel::Debug`]        | `7`    | [`tracing::debug!`] |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogLevel {
    /// System is unusable (syslog `LOG_EMERG`).
    Emergency,
    /// Action must be taken immediately (syslog `LOG_ALERT`).
    Alert,
    /// Critical condition (syslog `LOG_CRIT`).
    Critical,
    /// Error condition (syslog `LOG_ERR`).
    Error,
    /// Warning condition (syslog `LOG_WARNING`).
    Warning,
    /// Normal but significant condition (syslog `LOG_NOTICE`).
    Notice,
    /// Informational message (syslog `LOG_INFO`).
    Info,
    /// Debug-level message (syslog `LOG_DEBUG`).
    Debug,
}

impl LogLevel {
    /// Returns the numeric syslog severity code (`0` for
    /// [`LogLevel::Emergency`] … `7` for [`LogLevel::Debug`]).
    ///
    /// Matches the values defined by `<syslog.h>` and used by
    /// `bss_log.c` `xopenlog()`.
    #[must_use]
    pub fn as_syslog_priority(self) -> u8 {
        match self {
            LogLevel::Emergency => 0,
            LogLevel::Alert => 1,
            LogLevel::Critical => 2,
            LogLevel::Error => 3,
            LogLevel::Warning => 4,
            LogLevel::Notice => 5,
            LogLevel::Info => 6,
            LogLevel::Debug => 7,
        }
    }

    /// Returns a short uppercase label for the severity
    /// (e.g. `"EMERG"`, `"WARN"`, `"DBG"`), matching the tags that C
    /// `slg_write()` in `bss_log.c` recognizes at the start of a
    /// written line.
    #[must_use]
    pub fn as_short_label(self) -> &'static str {
        match self {
            LogLevel::Emergency => "EMERG",
            LogLevel::Alert => "ALERT",
            LogLevel::Critical => "CRIT",
            LogLevel::Error => "ERR",
            LogLevel::Warning => "WARN",
            LogLevel::Notice => "NOTE",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DBG",
        }
    }
}

// ---------------------------------------------------------------------------
// LogBio — C BIO_s_log() equivalent (tracing-based log sink)
// ---------------------------------------------------------------------------

/// Default tag used when a [`LogBio`] is constructed via [`Default`]
/// or when an empty tag is supplied to [`LogBio::new`].
const DEFAULT_LOG_TAG: &str = "openssl";

/// Log sink BIO that emits writes as [`tracing`] events.
///
/// Replaces C `BIO_s_log()` from `crypto/bio/bss_log.c`, which in C
/// writes to syslog (POSIX), the Windows Event Log (`ReportEvent`), or
/// VMS OPCOM, depending on the platform. The Rust replacement funnels
/// all writes into the workspace-wide [`tracing`] infrastructure so
/// that subscribers configured elsewhere (e.g., `tracing-subscriber`
/// with JSON formatting, OpenTelemetry span export, …) receive the
/// data uniformly across all platforms. This satisfies the
/// observability-first rule from AAP §0.8.5.
///
/// # Line Buffering
///
/// Writes that do not end in a newline (`\n`) are buffered internally
/// until a newline is encountered, at which point the complete line is
/// emitted as a single tracing event. This mirrors the line-oriented
/// behaviour of syslog and avoids emitting fragmented events when a
/// caller performs several partial writes for a single logical line.
/// [`Write::flush`] drains any remaining partial line buffer.
///
/// # Read Side
///
/// Reads always return `Ok(0)` (EOF). Unlike file BIOs, the C
/// `BIO_s_log()` method table omits the `bread` / `bgets` function
/// pointers (see `bss_log.c` `methods_slg`, line 54), making it
/// effectively write-only.
///
/// # Example
///
/// ```
/// use openssl_crypto::bio::file::{LogBio, LogLevel};
/// use std::io::Write;
///
/// let mut bio = LogBio::new("demo-subsystem", LogLevel::Info);
/// writeln!(bio, "hello from LogBio").expect("log write failed");
/// // Tracing subscribers (configured by the application) now see the
/// // event at info level.
/// ```
#[derive(Debug)]
pub struct LogBio {
    /// Current severity level; all complete lines are emitted at this
    /// level unless an inline severity prefix overrides it.
    level: LogLevel,
    /// Subsystem tag attached to every emitted event (matches the
    /// `ident` argument of C `openlog(ident, …)`).
    tag: String,
    /// Partial-line buffer accumulating writes until a newline.
    line_buf: String,
    /// I/O byte counters.
    stats: BioStats,
}

impl LogBio {
    /// Creates a new [`LogBio`] with the given subsystem tag and
    /// default severity.
    ///
    /// If `tag` is empty, a default tag (`"openssl"`) is used. The
    /// `level` controls the [`tracing`] macro selected for each
    /// emitted event.
    ///
    /// Replaces C `BIO_new(BIO_s_log())` followed by `openlog(tag, …)`.
    #[must_use]
    pub fn new(tag: &str, level: LogLevel) -> Self {
        let tag_owned = if tag.is_empty() {
            DEFAULT_LOG_TAG.to_string()
        } else {
            tag.to_string()
        };
        // Trace-level visibility into LogBio construction — lets
        // diagnostics subscribers observe how many LogBios are being
        // instantiated and with which tags, without polluting the
        // default log stream.
        tracing::trace!(
            tag = %tag_owned,
            level = ?level,
            "LogBio created"
        );
        Self {
            level,
            tag: tag_owned,
            line_buf: String::new(),
            stats: BioStats::new(),
        }
    }

    /// Updates the severity level at which subsequent complete lines
    /// will be emitted.
    ///
    /// Takes an [`LogLevel`] enum rather than a string (Rule R5 —
    /// typed over stringly-typed).
    pub fn set_level(&mut self, level: LogLevel) {
        self.level = level;
    }

    /// Returns the current severity level.
    #[must_use]
    pub fn level(&self) -> LogLevel {
        self.level
    }

    /// Returns the subsystem tag attached to emitted events.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Emits `line` via [`tracing`] at this BIO's configured severity.
    ///
    /// Internal helper factored out of the [`Write`] impl so that
    /// both mid-write line splitting and [`Write::flush`] can reuse
    /// the same dispatch logic.
    fn emit_line(&self, line: &str) {
        // Skip emitting a fully empty line — matches the
        // conventional behaviour of syslog which ignores empty
        // records.
        if line.is_empty() {
            return;
        }
        match self.level {
            LogLevel::Emergency | LogLevel::Alert | LogLevel::Critical | LogLevel::Error => {
                tracing::error!(
                    tag = %self.tag,
                    severity = self.level.as_short_label(),
                    "{line}"
                );
            }
            LogLevel::Warning => {
                tracing::warn!(
                    tag = %self.tag,
                    severity = self.level.as_short_label(),
                    "{line}"
                );
            }
            LogLevel::Notice | LogLevel::Info => {
                tracing::info!(
                    tag = %self.tag,
                    severity = self.level.as_short_label(),
                    "{line}"
                );
            }
            LogLevel::Debug => {
                tracing::debug!(
                    tag = %self.tag,
                    severity = self.level.as_short_label(),
                    "{line}"
                );
            }
        }
    }
}

impl Default for LogBio {
    fn default() -> Self {
        Self::new(DEFAULT_LOG_TAG, LogLevel::Info)
    }
}

impl Read for LogBio {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        // C BIO_s_log() has no bread method (bss_log.c methods_slg
        // line 54). Return EOF to callers that erroneously attempt
        // to read from a log BIO.
        Ok(0)
    }
}

impl Write for LogBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Append the new bytes to the line buffer as UTF-8, lossily
        // replacing invalid sequences. Tracing emits structured
        // fields that require valid UTF-8; the original C BIO_s_log
        // also treats input as text and would mis-render non-text
        // data through syslog.
        let chunk = String::from_utf8_lossy(buf);
        self.line_buf.push_str(chunk.as_ref());

        // Drain complete lines (up to and including each '\n') and
        // emit them as tracing events.
        while let Some(newline_idx) = self.line_buf.find('\n') {
            // Extract the line without its trailing newline. Also
            // strip a trailing CR so Windows CRLF inputs don't leave
            // a stray '\r' in the emitted line.
            let mut line: String = self.line_buf.drain(..=newline_idx).collect();
            line.pop(); // remove '\n'
            if line.ends_with('\r') {
                line.pop();
            }
            self.emit_line(&line);
        }

        self.stats.record_write(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Drain any buffered partial line as a final event.
        if !self.line_buf.is_empty() {
            let line = std::mem::take(&mut self.line_buf);
            self.emit_line(&line);
        }
        Ok(())
    }
}

impl Drop for LogBio {
    fn drop(&mut self) {
        // Best-effort flush of the tail partial line so that data
        // written without a terminating newline is not lost. Errors
        // are impossible from this flush (LogBio::flush never returns
        // Err), but we discard the Result for explicitness.
        let _ = self.flush();
    }
}

impl Bio for LogBio {
    fn bio_type(&self) -> BioType {
        BioType::Log
    }

    fn wpending(&self) -> usize {
        // The partial-line buffer represents bytes written but not
        // yet emitted as a tracing event. Expose via BIO_CTRL_WPENDING
        // parity.
        self.line_buf.len()
    }

    fn stats(&self) -> &BioStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BioStats {
        &mut self.stats
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use .unwrap() on values guaranteed to be Some/Ok.
#[allow(clippy::expect_used)] // Tests use .expect() on known-good Results.
#[allow(clippy::panic)] // Tests use panic! to fail on unexpected Err variants.
#[allow(clippy::panic_in_result_fn)] // Not applicable — tests return ().
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};

    // ----- OpenMode ---------------------------------------------------------

    #[test]
    fn open_mode_from_str_basic() {
        assert_eq!(OpenMode::from_str("r"), Some(OpenMode::Read));
        assert_eq!(OpenMode::from_str("w"), Some(OpenMode::Write));
        assert_eq!(OpenMode::from_str("a"), Some(OpenMode::Append));
        assert_eq!(OpenMode::from_str("rb"), Some(OpenMode::ReadBinary));
        assert_eq!(OpenMode::from_str("wb"), Some(OpenMode::WriteBinary));
        assert_eq!(OpenMode::from_str("ab"), Some(OpenMode::AppendBinary));
        assert_eq!(OpenMode::from_str("r+b"), Some(OpenMode::ReadWriteBinary));
        assert_eq!(OpenMode::from_str("rb+"), Some(OpenMode::ReadWriteBinary));
    }

    #[test]
    fn open_mode_from_str_rejects_unknown() {
        assert_eq!(OpenMode::from_str(""), None);
        assert_eq!(OpenMode::from_str("x"), None);
        assert_eq!(OpenMode::from_str("rw"), None); // 'r' + 'w' without '+' is invalid
        assert_eq!(OpenMode::from_str("zz"), None);
    }

    #[test]
    fn open_mode_trait_helpers() {
        assert!(OpenMode::Read.is_readable());
        assert!(!OpenMode::Read.is_writable());
        assert!(!OpenMode::Read.is_binary());

        assert!(OpenMode::WriteBinary.is_binary());
        assert!(OpenMode::WriteBinary.is_writable());
        assert!(!OpenMode::WriteBinary.is_readable());

        assert!(OpenMode::ReadWriteBinary.is_readable());
        assert!(OpenMode::ReadWriteBinary.is_writable());
        assert!(OpenMode::ReadWriteBinary.is_binary());

        assert!(OpenMode::Append.is_writable());
        assert!(!OpenMode::Append.is_readable());
    }

    #[test]
    fn open_mode_to_open_options_produces_usable_options() {
        // Smoke-test that each mode produces OpenOptions without
        // panicking and that the resulting options compile cleanly.
        let _ = OpenMode::Read.to_open_options();
        let _ = OpenMode::Write.to_open_options();
        let _ = OpenMode::Append.to_open_options();
        let _ = OpenMode::ReadBinary.to_open_options();
        let _ = OpenMode::WriteBinary.to_open_options();
        let _ = OpenMode::AppendBinary.to_open_options();
        let _ = OpenMode::ReadWriteBinary.to_open_options();
    }

    // ----- FileBio ----------------------------------------------------------

    /// Creates a unique temp path inside the OS temp directory.
    /// Uses the thread ID + a random u64 from std to avoid collisions
    /// without requiring the `tempfile` crate.
    fn unique_temp_path(suffix: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tid = std::thread::current().id();
        let raw = format!("openssl_rs_file_bio_test_{n}_{tid:?}_{suffix}");
        let sanitized: String = raw
            .chars()
            .map(|c| if matches!(c, ' ' | '(' | ')') { '_' } else { c })
            .collect();
        let mut p = std::env::temp_dir();
        p.push(sanitized);
        p
    }

    #[test]
    fn file_bio_write_and_read_roundtrip() {
        let path = unique_temp_path("rw");
        {
            let mut bio = FileBio::new(&path, OpenMode::Write).unwrap();
            bio.write_all(b"openssl-rs FileBio test").unwrap();
            bio.flush().unwrap();
            assert_eq!(bio.path(), Some(path.as_path()));
            assert_eq!(bio.mode(), OpenMode::Write);
            assert!(bio.close_on_drop());
            assert_eq!(bio.bio_type(), BioType::File);
            assert_eq!(bio.method_name(), "FILE pointer");
            assert!(bio.stats().bytes_written() > 0);
        }
        {
            let mut bio = FileBio::new(&path, OpenMode::Read).unwrap();
            let mut out = String::new();
            bio.read_to_string(&mut out).unwrap();
            assert_eq!(out, "openssl-rs FileBio test");
            assert!(bio.stats().bytes_read() > 0);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_bio_reset_rewinds() {
        let path = unique_temp_path("reset");
        {
            let mut bio = FileBio::new(&path, OpenMode::Write).unwrap();
            bio.write_all(b"0123456789").unwrap();
        }
        let mut bio = FileBio::new(&path, OpenMode::Read).unwrap();
        let mut first = [0u8; 4];
        bio.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"0123");
        assert_eq!(bio.tell().unwrap(), 4);

        // Inherent reset
        bio.reset().unwrap();
        assert_eq!(bio.tell().unwrap(), 0);

        // Trait reset
        let mut again = [0u8; 4];
        bio.read_exact(&mut again).unwrap();
        assert_eq!(&again, b"0123");
        <FileBio as Bio>::reset(&mut bio).unwrap();
        assert_eq!(bio.tell().unwrap(), 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_bio_seek_and_tell() {
        let path = unique_temp_path("seek");
        {
            let mut bio = FileBio::new(&path, OpenMode::Write).unwrap();
            bio.write_all(b"ABCDEFGHIJ").unwrap();
        }
        let mut bio = FileBio::new(&path, OpenMode::Read).unwrap();
        bio.seek(SeekFrom::Start(5)).unwrap();
        assert_eq!(bio.tell().unwrap(), 5);
        let mut rest = String::new();
        bio.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "FGHIJ");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_bio_from_file_and_into_inner() {
        let path = unique_temp_path("from_file");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(b"hello").unwrap();
        }
        let f = File::open(&path).unwrap();
        let bio = FileBio::from_file(f, false);
        assert_eq!(bio.path(), None);
        assert!(!bio.close_on_drop());
        assert_eq!(bio.mode(), OpenMode::ReadWriteBinary);
        let unwrapped = bio.into_inner();
        // After into_inner, the File is still usable.
        drop(unwrapped);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_bio_new_on_missing_file_returns_err() {
        let mut path = std::env::temp_dir();
        path.push("openssl_rs_file_bio_nonexistent_dir_12345/does_not_exist");
        let result = FileBio::new(&path, OpenMode::Read);
        assert!(result.is_err(), "Expected Err for missing file, got Ok");
        match result {
            Err(CryptoError::Io(_)) => {}
            Err(other) => panic!("Expected CryptoError::Io, got {other:?}"),
            Ok(_) => panic!("Expected Err, got Ok"),
        }
    }

    // ----- FdBio ------------------------------------------------------------

    #[test]
    fn fd_bio_stdout_properties() {
        let bio = FdBio::stdout();
        assert!(bio.is_stdout());
        assert!(!bio.is_stderr());
        assert!(!bio.is_file());
        assert!(!bio.close_on_drop());
        assert_eq!(bio.bio_type(), BioType::FileDescriptor);
        assert_eq!(bio.method_name(), "file descriptor");
        assert!(bio.into_inner().is_none());
    }

    #[test]
    fn fd_bio_stderr_properties() {
        let bio = FdBio::stderr();
        assert!(bio.is_stderr());
        assert!(!bio.is_stdout());
        assert!(!bio.is_file());
        assert!(!bio.close_on_drop());
        assert!(bio.into_inner().is_none());
    }

    #[test]
    fn fd_bio_stdout_read_unsupported() {
        let mut bio = FdBio::stdout();
        let mut buf = [0u8; 4];
        let err = bio.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn fd_bio_from_file_write_and_into_inner() {
        let path = unique_temp_path("fd_wr");
        let file = File::create(&path).unwrap();
        let mut bio = FdBio::new(file, true);
        assert!(bio.is_file());
        assert!(bio.close_on_drop());
        bio.write_all(b"fd write").unwrap();
        bio.flush().unwrap();

        let unwrapped = bio.into_inner();
        assert!(unwrapped.is_some());
        drop(unwrapped);

        // Verify data actually hit disk.
        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "fd write");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fd_bio_file_reset_rewinds() {
        let path = unique_temp_path("fd_reset");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(b"abcdef").unwrap();
        }
        let file = File::open(&path).unwrap();
        let mut bio = FdBio::new(file, true);
        let mut first = [0u8; 3];
        bio.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"abc");
        <FdBio as Bio>::reset(&mut bio).unwrap();
        let mut second = [0u8; 3];
        bio.read_exact(&mut second).unwrap();
        assert_eq!(&second, b"abc");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fd_bio_stdout_reset_errors() {
        let mut bio = FdBio::stdout();
        let err = <FdBio as Bio>::reset(&mut bio).unwrap_err();
        match err {
            CryptoError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            other => panic!("Expected CryptoError::Io, got {other:?}"),
        }
    }

    // ----- NullBio ----------------------------------------------------------

    #[test]
    fn null_bio_read_returns_eof() {
        let mut bio = NullBio::new();
        let mut buf = [0u8; 16];
        assert_eq!(bio.read(&mut buf).unwrap(), 0);
        assert_eq!(bio.read(&mut buf).unwrap(), 0); // repeatable
    }

    #[test]
    fn null_bio_write_discards_all() {
        let mut bio = NullBio::new();
        assert_eq!(bio.write(b"anything").unwrap(), 8);
        assert_eq!(bio.write(&[]).unwrap(), 0);
        bio.flush().unwrap();
        assert_eq!(bio.stats().bytes_written(), 8);
        assert_eq!(bio.stats().bytes_read(), 0);
    }

    #[test]
    fn null_bio_bio_trait_methods() {
        let bio = NullBio::new();
        assert_eq!(bio.bio_type(), BioType::Null);
        assert!(bio.eof());
        assert_eq!(bio.pending(), 0);
        assert_eq!(bio.method_name(), "NULL");
    }

    #[test]
    fn null_bio_default_impl_matches_new() {
        let a = NullBio::default();
        let b = NullBio::new();
        assert_eq!(a.stats().bytes_read(), b.stats().bytes_read());
        assert_eq!(a.stats().bytes_written(), b.stats().bytes_written());
    }

    // ----- LogLevel / LogBio -----------------------------------------------

    #[test]
    fn log_level_syslog_priorities() {
        assert_eq!(LogLevel::Emergency.as_syslog_priority(), 0);
        assert_eq!(LogLevel::Alert.as_syslog_priority(), 1);
        assert_eq!(LogLevel::Critical.as_syslog_priority(), 2);
        assert_eq!(LogLevel::Error.as_syslog_priority(), 3);
        assert_eq!(LogLevel::Warning.as_syslog_priority(), 4);
        assert_eq!(LogLevel::Notice.as_syslog_priority(), 5);
        assert_eq!(LogLevel::Info.as_syslog_priority(), 6);
        assert_eq!(LogLevel::Debug.as_syslog_priority(), 7);
    }

    #[test]
    fn log_level_short_labels() {
        assert_eq!(LogLevel::Emergency.as_short_label(), "EMERG");
        assert_eq!(LogLevel::Alert.as_short_label(), "ALERT");
        assert_eq!(LogLevel::Critical.as_short_label(), "CRIT");
        assert_eq!(LogLevel::Error.as_short_label(), "ERR");
        assert_eq!(LogLevel::Warning.as_short_label(), "WARN");
        assert_eq!(LogLevel::Notice.as_short_label(), "NOTE");
        assert_eq!(LogLevel::Info.as_short_label(), "INFO");
        assert_eq!(LogLevel::Debug.as_short_label(), "DBG");
    }

    #[test]
    fn log_bio_writes_complete_line_at_info() {
        let mut bio = LogBio::new("unit-test", LogLevel::Info);
        assert_eq!(bio.bio_type(), BioType::Log);
        assert_eq!(bio.level(), LogLevel::Info);
        assert_eq!(bio.tag(), "unit-test");
        assert_eq!(bio.method_name(), "syslog");

        // Writing a complete line should drain line_buf.
        let n = bio.write(b"hello world\n").unwrap();
        assert_eq!(n, 12);
        assert_eq!(bio.wpending(), 0, "line_buf should be drained after '\\n'");
        assert_eq!(bio.stats().bytes_written(), 12);
    }

    #[test]
    fn log_bio_buffers_partial_line() {
        let mut bio = LogBio::new("unit-test", LogLevel::Info);
        bio.write_all(b"partial ").unwrap();
        assert_eq!(bio.wpending(), 8);
        bio.write_all(b"line").unwrap();
        assert_eq!(bio.wpending(), 12);
        // Flush emits the partial line.
        bio.flush().unwrap();
        assert_eq!(bio.wpending(), 0);
    }

    #[test]
    fn log_bio_multi_line_in_single_write() {
        let mut bio = LogBio::new("multi", LogLevel::Warning);
        bio.write_all(b"line1\nline2\nline3").unwrap();
        // Two complete lines consumed; "line3" retained.
        assert_eq!(bio.wpending(), 5);
        bio.flush().unwrap();
        assert_eq!(bio.wpending(), 0);
    }

    #[test]
    fn log_bio_strips_cr_from_crlf() {
        let mut bio = LogBio::new("crlf", LogLevel::Info);
        bio.write_all(b"windows-line\r\n").unwrap();
        assert_eq!(bio.wpending(), 0);
        // Second write with just LF to exercise the non-CR path.
        bio.write_all(b"unix-line\n").unwrap();
        assert_eq!(bio.wpending(), 0);
    }

    #[test]
    fn log_bio_read_returns_eof() {
        let mut bio = LogBio::new("r", LogLevel::Info);
        let mut buf = [0u8; 16];
        assert_eq!(bio.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn log_bio_set_level_changes_level() {
        let mut bio = LogBio::new("tag", LogLevel::Info);
        assert_eq!(bio.level(), LogLevel::Info);
        bio.set_level(LogLevel::Error);
        assert_eq!(bio.level(), LogLevel::Error);
        bio.set_level(LogLevel::Debug);
        assert_eq!(bio.level(), LogLevel::Debug);
    }

    #[test]
    fn log_bio_default_uses_default_tag() {
        let bio = LogBio::default();
        assert_eq!(bio.tag(), "openssl");
        assert_eq!(bio.level(), LogLevel::Info);
    }

    #[test]
    fn log_bio_empty_tag_substituted_with_default() {
        let bio = LogBio::new("", LogLevel::Warning);
        assert_eq!(bio.tag(), "openssl");
        assert_eq!(bio.level(), LogLevel::Warning);
    }

    #[test]
    fn log_bio_exercises_all_severities() {
        // Exercises every severity so each tracing macro
        // (error!, warn!, info!, debug!) is traversed at least once.
        for level in [
            LogLevel::Emergency,
            LogLevel::Alert,
            LogLevel::Critical,
            LogLevel::Error,
            LogLevel::Warning,
            LogLevel::Notice,
            LogLevel::Info,
            LogLevel::Debug,
        ] {
            let mut bio = LogBio::new("sev-test", level);
            bio.write_all(b"message\n").unwrap();
            assert_eq!(bio.wpending(), 0);
        }
    }

    #[test]
    fn log_bio_drop_flushes_partial_line() {
        let mut bio = LogBio::new("drop-flush", LogLevel::Info);
        bio.write_all(b"tail-line-without-newline").unwrap();
        assert_ne!(bio.wpending(), 0);
        drop(bio);
        // The Drop impl must not panic; the actual flush output goes
        // to the tracing subscriber (none in tests), so we only verify
        // drop runs cleanly.
    }

    // ----- Module-level sanity ---------------------------------------------

    #[test]
    fn all_bio_types_expose_distinct_method_names() {
        let file_method = BioType::File.name();
        let fd_method = BioType::FileDescriptor.name();
        let null_method = BioType::Null.name();
        let log_method = BioType::Log.name();
        assert_ne!(file_method, fd_method);
        assert_ne!(file_method, null_method);
        assert_ne!(file_method, log_method);
        assert_ne!(fd_method, null_method);
        assert_ne!(fd_method, log_method);
        assert_ne!(null_method, log_method);
    }
}
