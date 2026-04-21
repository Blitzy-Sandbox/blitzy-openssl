//! BIO (Basic I/O) abstraction layer for the OpenSSL Rust workspace.
//!
//! This module provides a trait-based I/O abstraction that replaces the C
//! `BIO` system from `crypto/bio/`. In the original C codebase, BIO is an
//! abstracted I/O layer using function-pointer dispatch (`BIO_METHOD`)
//! supporting source/sink backends (memory, file, socket) and filter chains
//! (buffering, line-buffering, prefix).
//!
//! In Rust, the BIO pattern maps naturally to [`std::io::Read`]/[`std::io::Write`]
//! traits with type-specific extensions via the [`Bio`] trait. Filter BIOs become
//! generic wrappers around inner `Read + Write` implementors.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
//! │ Application  │───▶│ Filter Chain │───▶│ Source/Sink  │
//! │  (Read+Write)│    │ (BufferFilter)│    │ (MemBio,File)│
//! └──────────────┘    └──────────────┘    └──────────────┘
//! ```
//!
//! # Submodules
//!
//! - [`mem`] — In-memory BIOs ([`MemBio`], [`SecureMemBio`], [`BioPairEnd`])
//! - [`file`] — File and file-descriptor BIOs ([`FileBio`], [`FdBio`], [`NullBio`], [`LogBio`])
//! - [`socket`] — Socket BIOs ([`SocketBio`], [`ConnectBio`], [`AcceptBio`], [`DatagramBio`])
//! - [`filter`] — Filter chain BIOs ([`BufferFilter`], [`LineBufferFilter`], [`PrefixFilter`])
//!
//! # C-to-Rust Mapping
//!
//! | C Concept | Rust Equivalent |
//! |-----------|----------------|
//! | `BIO_METHOD` function pointers | [`Bio`] trait + [`Read`](std::io::Read)/[`Write`](std::io::Write) |
//! | `BIO_new()` / `BIO_free()` | Constructor + [`Drop`] (RAII) |
//! | `BIO_read()` / `BIO_write()` | [`Read::read()`](std::io::Read::read) / [`Write::write()`](std::io::Write::write) |
//! | `BIO_ctrl(PENDING)` | [`Bio::pending()`] |
//! | `BIO_push()` / `BIO_pop()` | Generic filter nesting |
//! | `BIO_TYPE_*` constants | [`BioType`] enum |
//! | `BIO_FLAGS_*` bitmask | [`BioFlags`] bitflags |
//! | `bio->num_read` / `bio->num_write` | [`BioStats`] counters |
//! | `BIO_debug_callback_ex()` | [`BioCallback`] / `tracing` integration |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** [`BioType::None`] and [`BioRetryReason::None`] are explicit
//!   enum variants, not zero sentinels. Optional data uses [`Option<T>`].
//! - **R6 (Lossless Casts):** [`BioStats`] counters use [`u64::saturating_add`].
//! - **R7 (Concurrency):** [`Bio`] trait is `Send`-bound. No global locks.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module or submodules.
//! - **R9 (Warning-Free):** All public items have `///` documentation.
//! - **R10 (Wiring):** Reachable via PEM, X.509, ASN.1, SSL, and CLI entry points.

use std::fmt;
use std::io::{self, Write};

use bitflags::bitflags;
use openssl_common::{CryptoError, CryptoResult};

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

pub mod file;
pub mod filter;
pub mod mem;
pub mod socket;

// ---------------------------------------------------------------------------
// Re-exports from submodules for convenience access
// ---------------------------------------------------------------------------

pub use self::file::{FdBio, FileBio, LogBio, LogLevel, NullBio, OpenMode};
pub use self::filter::{
    BufferFilter, FilterChainBuilder, LineBufferFilter, NullFilter, PrefixFilter, ReadBufferFilter,
};
pub use self::mem::{new_bio_pair, BioPairEnd, MemBio, SecureMemBio};
pub use self::socket::{AcceptBio, BioAddr, ConnectBio, DatagramBio, SocketBio};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default buffer size for buffered BIO operations (4096 bytes).
///
/// Matches the default buffer sizing used across the C BIO subsystem.
/// This value is the default read/write buffer capacity for
/// [`BufferFilter`] and related buffered types.
pub const DEFAULT_BUFFER_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// BioType — classification of BIO types
// ---------------------------------------------------------------------------

/// Classification of BIO types, replacing C `BIO_TYPE_*` constants from
/// `include/openssl/bio.h.in` and `crypto/bio/bio_local.h`.
///
/// In the C codebase, BIO types are integer constants composed of
/// category flags (`BIO_TYPE_SOURCE_SINK` 0x0400, `BIO_TYPE_FILTER` 0x0200,
/// `BIO_TYPE_DESCRIPTOR` 0x0100) OR'd with a unique index. In Rust, we use
/// an enum for type safety with exhaustive matching.
///
/// # Categories
///
/// BIO types fall into two main categories:
///
/// - **Source/Sink** — Endpoints that produce or consume data (memory, file, socket).
/// - **Filter** — Transformers that sit between application and source/sink
///   (buffering, line-buffering, prefix injection, SSL encryption).
///
/// Some source/sink types are additionally descriptor-backed (file descriptor, socket).
///
/// # Custom Types
///
/// User-defined BIO types are represented by [`BioType::Custom`], carrying the
/// type index allocated by the equivalent of C `BIO_get_new_index()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BioType {
    /// No specific type (sentinel, replaces `BIO_TYPE_NONE` = 0).
    None,

    // === Source/Sink Types (BIO_TYPE_SOURCE_SINK | ...) ===
    /// In-memory buffer (`BIO_TYPE_MEM` = 0x0401).
    Memory,
    /// File pointer (`BIO_TYPE_FILE` = 0x0402).
    File,
    /// File descriptor (`BIO_TYPE_FD` = 0x0505, includes `BIO_TYPE_DESCRIPTOR`).
    FileDescriptor,
    /// TCP stream socket (`BIO_TYPE_SOCKET` = 0x0505, includes `BIO_TYPE_DESCRIPTOR`).
    Socket,
    /// TCP connect client (`BIO_TYPE_CONNECT` = 0x050c, includes `BIO_TYPE_DESCRIPTOR`).
    Connect,
    /// TCP accept server (`BIO_TYPE_ACCEPT` = 0x050d, includes `BIO_TYPE_DESCRIPTOR`).
    Accept,
    /// Datagram/UDP socket (`BIO_TYPE_DGRAM` = 0x0512, includes `BIO_TYPE_DESCRIPTOR`).
    Datagram,
    /// Datagram pair for in-process testing (`BIO_TYPE_DGRAM_PAIR` = 0x0518).
    DatagramPair,
    /// In-process BIO pair pipe (`BIO_TYPE_BIO` = 0x0413).
    BioPair,
    /// Null sink/source — `/dev/null` equivalent (`BIO_TYPE_NULL` = 0x0406).
    Null,
    /// Core-to-provider bridge BIO (`BIO_TYPE_CORE_TO_PROV`).
    CoreToProvider,

    // === Filter Types (BIO_TYPE_FILTER | ...) ===
    /// General buffering filter (`BIO_TYPE_BUFFER` = 0x0201).
    Buffer,
    /// Line-buffering filter (flushes on newline).
    LineBuffer,
    /// Read-only caching filter (enables seek/tell on non-seekable sources).
    ReadBuffer,
    /// Write-side prefix/indent injection filter.
    Prefix,
    /// Null filter / transparent pass-through (`BIO_TYPE_NULL_FILTER` = 0x0211).
    NullFilter,
    /// Non-blocking I/O test filter (`BIO_TYPE_NBIO_TEST` = 0x0210).
    NbioTest,
    /// SSL/TLS protocol filter (`BIO_TYPE_SSL` = 0x0207).
    Ssl,
    /// Log/syslog output sink (`BIO_TYPE_LOG`).
    Log,

    /// Custom/user-defined BIO type, created via dynamic type registration.
    ///
    /// The inner `u32` is the type index allocated by the equivalent of
    /// C `BIO_get_new_index()` from `crypto/bio/bio_meth.c`.
    Custom(u32),
}

impl BioType {
    /// Returns `true` if this BIO type is a source/sink endpoint.
    ///
    /// Source/sink BIOs are the terminal endpoints in a BIO chain — they
    /// produce or consume data directly (memory buffers, files, sockets).
    /// Corresponds to the C `BIO_TYPE_SOURCE_SINK` (0x0400) flag.
    pub fn is_source_sink(&self) -> bool {
        matches!(
            self,
            BioType::Memory
                | BioType::File
                | BioType::FileDescriptor
                | BioType::Socket
                | BioType::Connect
                | BioType::Accept
                | BioType::Datagram
                | BioType::DatagramPair
                | BioType::BioPair
                | BioType::Null
                | BioType::CoreToProvider
                | BioType::Log
        )
    }

    /// Returns `true` if this BIO type is a filter.
    ///
    /// Filter BIOs sit between the application and a source/sink, transforming
    /// data in transit (buffering, prefix injection, SSL encryption).
    /// Corresponds to the C `BIO_TYPE_FILTER` (0x0200) flag.
    pub fn is_filter(&self) -> bool {
        matches!(
            self,
            BioType::Buffer
                | BioType::LineBuffer
                | BioType::ReadBuffer
                | BioType::Prefix
                | BioType::NullFilter
                | BioType::NbioTest
                | BioType::Ssl
        )
    }

    /// Returns `true` if this BIO type is backed by a file descriptor or
    /// network socket.
    ///
    /// Descriptor-backed BIOs support additional operations like
    /// `set_nonblocking()`, `set_read_timeout()`, and `shutdown()`.
    /// Corresponds to the C `BIO_TYPE_DESCRIPTOR` (0x0100) flag.
    pub fn is_descriptor(&self) -> bool {
        matches!(
            self,
            BioType::FileDescriptor
                | BioType::Socket
                | BioType::Connect
                | BioType::Accept
                | BioType::Datagram
        )
    }

    /// Returns a human-readable name for this BIO type.
    ///
    /// Replaces the `name` field of C `struct bio_method_st` from
    /// `crypto/bio/bio_local.h` and `BIO_method_name()`.
    pub fn name(&self) -> &'static str {
        match self {
            BioType::None => "NONE",
            BioType::Memory => "memory buffer",
            BioType::File => "FILE pointer",
            BioType::FileDescriptor => "file descriptor",
            BioType::Socket => "socket",
            BioType::Connect => "connect",
            BioType::Accept => "accept",
            BioType::Datagram => "datagram",
            BioType::DatagramPair => "datagram pair",
            BioType::BioPair => "BIO pair",
            BioType::Null => "NULL",
            BioType::CoreToProvider => "core to provider",
            BioType::Buffer => "buffer",
            BioType::LineBuffer => "line buffer",
            BioType::ReadBuffer => "read buffer",
            BioType::Prefix => "prefix",
            BioType::NullFilter => "null filter",
            BioType::NbioTest => "non-blocking IO test",
            BioType::Ssl => "ssl",
            BioType::Log => "syslog",
            BioType::Custom(_) => "custom",
        }
    }
}

impl fmt::Display for BioType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// BioFlags — state flags for BIO instances
// ---------------------------------------------------------------------------

bitflags! {
    /// BIO state flags, replacing C `BIO_FLAGS_*` bitmask from
    /// `include/openssl/bio.h.in` and `crypto/bio/bio_local.h`.
    ///
    /// These flags control retry behavior, I/O readiness, and special
    /// operational modes. They are stored per-BIO instance and queried
    /// via the equivalent of C `BIO_test_flags()` / `BIO_should_retry()`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BioFlags: u32 {
        /// BIO should retry read operation (`BIO_FLAGS_READ` = 0x01).
        const READ = 0x01;
        /// BIO should retry write operation (`BIO_FLAGS_WRITE` = 0x02).
        const WRITE = 0x02;
        /// BIO encountered I/O special condition (`BIO_FLAGS_IO_SPECIAL` = 0x04).
        const IO_SPECIAL = 0x04;
        /// Combined read/write/special retry flags (`READ | WRITE | IO_SPECIAL`).
        const RWS = Self::READ.bits() | Self::WRITE.bits() | Self::IO_SPECIAL.bits();
        /// BIO should retry the last operation (`BIO_FLAGS_SHOULD_RETRY` = 0x08).
        const SHOULD_RETRY = 0x08;
        /// Memory BIO is in read-only mode (`BIO_FLAGS_MEM_RDONLY` = 0x200).
        const MEM_RDONLY = 0x200;
        /// Non-clear reset mode (`BIO_FLAGS_NONCLEAR_RST` = 0x400).
        const NONCLEAR_RST = 0x400;
        /// BIO has reached end-of-file (`BIO_FLAGS_IN_EOF` = 0x800).
        const IN_EOF = 0x800;
        /// Automatically report EOF when buffer is empty (`BIO_FLAGS_AUTO_EOF`).
        const AUTO_EOF = 0x1000;
    }
}

// ---------------------------------------------------------------------------
// BioRetryReason — reason for non-blocking retry
// ---------------------------------------------------------------------------

/// Reason for a BIO retry, replacing C `BIO_RR_*` constants from
/// `include/openssl/bio.h.in`.
///
/// When a BIO operation returns `WouldBlock`, this enum indicates why
/// the operation could not complete immediately and what action the
/// caller should take before retrying.
///
/// # C Mapping
///
/// | C Constant | Rust Variant |
/// |------------|-------------|
/// | (none) | [`None`](BioRetryReason::None) |
/// | `BIO_RR_SSL_X509_LOOKUP` | [`SslX509Lookup`](BioRetryReason::SslX509Lookup) |
/// | `BIO_RR_CONNECT` | [`Connect`](BioRetryReason::Connect) |
/// | `BIO_RR_ACCEPT` | [`Accept`](BioRetryReason::Accept) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BioRetryReason {
    /// No retry needed — the operation completed or failed permanently.
    None,
    /// An SSL/TLS X.509 certificate lookup is in progress.
    /// The caller should provide the certificate and retry.
    SslX509Lookup,
    /// A non-blocking TCP connect is in progress.
    /// The caller should wait for the socket to become writable and retry.
    Connect,
    /// A non-blocking TCP accept is in progress.
    /// The caller should wait for the listener socket to become readable and retry.
    Accept,
}

impl fmt::Display for BioRetryReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BioRetryReason::None => write!(f, "none"),
            BioRetryReason::SslX509Lookup => write!(f, "SSL X509 lookup"),
            BioRetryReason::Connect => write!(f, "connect in progress"),
            BioRetryReason::Accept => write!(f, "accept in progress"),
        }
    }
}

// ---------------------------------------------------------------------------
// BioStats — I/O statistics counters
// ---------------------------------------------------------------------------

/// I/O statistics counters for a BIO instance.
///
/// Tracks cumulative bytes read and written over the lifetime of the BIO,
/// replacing the `num_read` (`uint64_t`) and `num_write` (`uint64_t`)
/// fields from C `struct bio_st` in `crypto/bio/bio_local.h` (lines 107-108).
///
/// Counter updates use [`u64::saturating_add`] to prevent overflow
/// (Rule R6 — lossless numeric operations).
#[derive(Debug, Clone, Default)]
pub struct BioStats {
    /// Total bytes read through this BIO (replaces `bio->num_read`).
    bytes_read: u64,
    /// Total bytes written through this BIO (replaces `bio->num_write`).
    bytes_written: u64,
}

impl BioStats {
    /// Creates a new `BioStats` instance with all counters initialized to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total number of bytes read through this BIO.
    ///
    /// Replaces C `BIO_number_read(bio)`.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Returns the total number of bytes written through this BIO.
    ///
    /// Replaces C `BIO_number_written(bio)`.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Records `n` bytes read, incrementing the read counter.
    ///
    /// Uses [`u64::saturating_add`] to prevent overflow per Rule R6.
    /// The `usize` to `u64` conversion is always lossless since `usize`
    /// is at most 64 bits on all supported platforms.
    pub(crate) fn record_read(&mut self, n: usize) {
        self.bytes_read = self.bytes_read.saturating_add(n as u64);
    }

    /// Records `n` bytes written, incrementing the write counter.
    ///
    /// Uses [`u64::saturating_add`] to prevent overflow per Rule R6.
    /// The `usize` to `u64` conversion is always lossless since `usize`
    /// is at most 64 bits on all supported platforms.
    pub(crate) fn record_write(&mut self, n: usize) {
        self.bytes_written = self.bytes_written.saturating_add(n as u64);
    }

    /// Resets both counters to zero.
    pub fn reset(&mut self) {
        self.bytes_read = 0;
        self.bytes_written = 0;
    }
}

// ---------------------------------------------------------------------------
// Bio trait — THE CORE ABSTRACTION
// ---------------------------------------------------------------------------

/// Core BIO trait replacing the C `BIO_METHOD` dispatch table from
/// `crypto/bio/bio_local.h` (lines 55-73).
///
/// Every BIO type implements this trait alongside [`std::io::Read`] and/or
/// [`std::io::Write`]. The trait provides BIO-specific control operations,
/// type identification, and lifecycle management that go beyond what the
/// standard I/O traits offer.
///
/// # Design Rationale
///
/// In C, `struct bio_method_st` defines function pointers for `bread`,
/// `bwrite`, `bputs`, `bgets`, `ctrl`, `create`, `destroy`, and
/// `callback_ctrl`. In Rust:
///
/// - `bread` / `bwrite` map to [`Read::read`](std::io::Read::read) /
///   [`Write::write`](std::io::Write::write) (standard traits)
/// - `bputs` / `bgets` map to [`Write::write_all`](std::io::Write::write_all) /
///   [`BufRead::read_line`](std::io::BufRead::read_line)
/// - `ctrl(FLUSH)` maps to [`Write::flush`](std::io::Write::flush)
/// - `create` / `destroy` map to Rust constructor / [`Drop`] (RAII)
/// - Remaining `ctrl` commands become typed methods on this trait
///
/// # Thread Safety
///
/// The `Bio` trait requires [`Send`], meaning BIO instances can be moved between
/// threads. For shared concurrent access, callers should wrap in
/// `Arc<Mutex<dyn Bio>>` with a `// LOCK-SCOPE:` justification comment
/// per Rule R7.
///
/// # C-to-Rust Method Mapping
///
/// | C Method / Control | Rust Equivalent |
/// |--------------------|-----------------|
/// | `bread` / `bwrite` | `Read::read()` / `Write::write()` |
/// | `ctrl(BIO_CTRL_PENDING)` | [`Bio::pending()`] |
/// | `ctrl(BIO_CTRL_WPENDING)` | [`Bio::wpending()`] |
/// | `ctrl(BIO_CTRL_EOF)` | [`Bio::eof()`] |
/// | `ctrl(BIO_CTRL_RESET)` | [`Bio::reset()`] |
/// | `ctrl(BIO_CTRL_FLUSH)` | `Write::flush()` |
/// | `BIO_method_type()` | [`Bio::bio_type()`] |
/// | `BIO_method_name()` | [`Bio::method_name()`] |
/// | `BIO_number_read()` | [`Bio::stats()`]`.bytes_read()` |
/// | `BIO_number_written()` | [`Bio::stats()`]`.bytes_written()` |
pub trait Bio: Send {
    /// Returns the BIO type classification.
    ///
    /// Replaces `BIO_method_type(bio)` / the `type` field of `bio_method_st`.
    fn bio_type(&self) -> BioType;

    /// Returns the number of bytes available for reading without blocking.
    ///
    /// For buffered BIOs, this returns the number of bytes currently in
    /// the read buffer. For socket BIOs, this typically returns 0.
    ///
    /// Replaces `BIO_ctrl_pending(bio)` /
    /// `BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL)`.
    fn pending(&self) -> usize {
        0
    }

    /// Returns the number of bytes buffered for writing (not yet flushed).
    ///
    /// Replaces `BIO_ctrl_wpending(bio)` /
    /// `BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL)`.
    fn wpending(&self) -> usize {
        0
    }

    /// Returns `true` if the BIO has reached end-of-file.
    ///
    /// Replaces `BIO_eof(bio)` / `BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL)`.
    fn eof(&self) -> bool {
        false
    }

    /// Resets the BIO to its initial state.
    ///
    /// The exact behavior depends on the BIO type:
    /// - **Memory BIO**: Clears the buffer (or rewinds read position if read-only).
    /// - **File BIO**: Seeks to the beginning of the file.
    /// - **Socket BIO**: No-op (connections cannot be "reset").
    ///
    /// Replaces `BIO_reset(bio)` / `BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL)`.
    fn reset(&mut self) -> CryptoResult<()> {
        Ok(())
    }

    /// Returns a reference to the I/O statistics counters for this BIO.
    ///
    /// The counters track cumulative bytes read and written over the
    /// BIO's lifetime.
    fn stats(&self) -> &BioStats;

    /// Returns a mutable reference to the I/O statistics counters.
    ///
    /// Primarily used by BIO implementations to update counters after
    /// read/write operations via [`BioStats::record_read`] and
    /// [`BioStats::record_write`].
    fn stats_mut(&mut self) -> &mut BioStats;

    /// Returns the human-readable name of this BIO method.
    ///
    /// Replaces `BIO_method_name(bio)` / the `name` field of `bio_method_st`.
    /// Defaults to the display name of the [`BioType`].
    fn method_name(&self) -> &str {
        self.bio_type().name()
    }
}

// ---------------------------------------------------------------------------
// BioCallbackOp — operation types for BIO callbacks
// ---------------------------------------------------------------------------

/// BIO callback operation type, replacing C `BIO_CB_*` constants
/// from `include/openssl/bio.h.in`.
///
/// Used with the [`BioCallback`] trait to identify which I/O operation
/// triggered the callback. The C implementation defines these as integer
/// constants combined with a `BIO_CB_RETURN` flag for post-operation callbacks;
/// in Rust, before/after semantics are handled by separate trait methods.
///
/// # C Mapping
///
/// | C Constant | Value | Rust Variant |
/// |------------|-------|-------------|
/// | `BIO_CB_FREE` | 0x01 | [`Free`](BioCallbackOp::Free) |
/// | `BIO_CB_READ` | 0x02 | [`Read`](BioCallbackOp::Read) |
/// | `BIO_CB_WRITE` | 0x03 | [`Write`](BioCallbackOp::Write) |
/// | `BIO_CB_PUTS` | 0x04 | [`Puts`](BioCallbackOp::Puts) |
/// | `BIO_CB_GETS` | 0x05 | [`Gets`](BioCallbackOp::Gets) |
/// | `BIO_CB_CTRL` | 0x06 | [`Ctrl`](BioCallbackOp::Ctrl) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BioCallbackOp {
    /// Read operation (`BIO_CB_READ` = 0x02).
    Read,
    /// Write operation (`BIO_CB_WRITE` = 0x03).
    Write,
    /// Puts (write string) operation (`BIO_CB_PUTS` = 0x04).
    Puts,
    /// Gets (read line) operation (`BIO_CB_GETS` = 0x05).
    Gets,
    /// Control operation (`BIO_CB_CTRL` = 0x06).
    Ctrl,
    /// Free/drop operation (`BIO_CB_FREE` = 0x01).
    Free,
}

impl fmt::Display for BioCallbackOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BioCallbackOp::Read => write!(f, "read"),
            BioCallbackOp::Write => write!(f, "write"),
            BioCallbackOp::Puts => write!(f, "puts"),
            BioCallbackOp::Gets => write!(f, "gets"),
            BioCallbackOp::Ctrl => write!(f, "ctrl"),
            BioCallbackOp::Free => write!(f, "free"),
        }
    }
}

// ---------------------------------------------------------------------------
// BioCallback — debug/tracing callback trait
// ---------------------------------------------------------------------------

/// Trait for BIO operation callbacks, replacing C `BIO_callback_fn_ex`
/// from `crypto/bio/bio_cb.c`.
///
/// Implementors can observe all I/O operations on a BIO for debugging,
/// logging, performance monitoring, or interception. The default
/// implementation emits structured events via the [`tracing`] crate,
/// replacing the C `BIO_debug_callback_ex()` function.
///
/// # Thread Safety
///
/// Callbacks must be [`Send`] to match the [`Bio`] trait's thread-safety
/// requirements.
pub trait BioCallback: Send {
    /// Called before a BIO operation begins.
    ///
    /// Returns `true` to proceed with the operation, `false` to abort.
    /// The default implementation logs the operation via [`tracing::trace!`]
    /// and always returns `true`.
    ///
    /// # Parameters
    ///
    /// - `op` — The type of operation about to be performed.
    /// - `bio_type` — The [`BioType`] of the BIO the operation targets.
    /// - `len` — The requested byte length, or 0 for length-less operations.
    fn before_op(&self, op: BioCallbackOp, bio_type: BioType, len: usize) -> bool {
        tracing::trace!(
            op = %op,
            bio_type = %bio_type,
            len = len,
            "BIO operation starting"
        );
        true
    }

    /// Called after a BIO operation completes.
    ///
    /// The default implementation logs the result via [`tracing::trace!`].
    ///
    /// # Parameters
    ///
    /// - `op` — The type of operation that was performed.
    /// - `bio_type` — The [`BioType`] of the BIO the operation targeted.
    /// - `result` — The outcome (bytes transferred or I/O error).
    fn after_op(&self, op: BioCallbackOp, bio_type: BioType, result: &io::Result<usize>) {
        tracing::trace!(
            op = %op,
            bio_type = %bio_type,
            result = ?result,
            "BIO operation completed"
        );
    }
}

// ---------------------------------------------------------------------------
// BioError — BIO-specific error types
// ---------------------------------------------------------------------------

/// BIO-specific error types replacing C `BIO_R_*` reason codes
/// from `crypto/bio/bio_err.c`.
///
/// These errors represent failure conditions specific to BIO operations.
/// They integrate with the broader [`CryptoError`] framework via the
/// [`From`] trait implementation, enabling transparent `?` propagation
/// across the crypto layer.
///
/// # C Mapping
///
/// | C Reason Code | Rust Variant |
/// |---------------|-------------|
/// | `BIO_R_UNINITIALIZED` | [`Uninitialized`](BioError::Uninitialized) |
/// | `BIO_R_UNSUPPORTED_METHOD` | [`UnsupportedMethod`](BioError::UnsupportedMethod) |
/// | `BIO_R_WRITE_TO_READ_ONLY_BIO` | [`WriteToReadOnly`](BioError::WriteToReadOnly) |
/// | `BIO_R_CONNECT_ERROR` | [`ConnectionError`](BioError::ConnectionError) |
/// | `BIO_R_ACCEPT_ERROR` | [`AcceptError`](BioError::AcceptError) |
/// | `BIO_R_LOOKUP_RETURNED_NOTHING` | [`AddrLookupFailed`](BioError::AddrLookupFailed) |
/// | `BIO_R_INVALID_ARGUMENT` | [`InvalidArgument`](BioError::InvalidArgument) |
/// | `BIO_R_BROKEN_PIPE` | [`BrokenPipe`](BioError::BrokenPipe) |
/// | (I/O errors) | [`Io`](BioError::Io) |
#[derive(Debug, thiserror::Error)]
pub enum BioError {
    /// BIO has not been initialized (`BIO_R_UNINITIALIZED`).
    #[error("BIO not initialized")]
    Uninitialized,

    /// Unsupported or unknown BIO method (`BIO_R_UNSUPPORTED_METHOD`).
    #[error("unsupported BIO method: {0}")]
    UnsupportedMethod(String),

    /// Attempted to write to a read-only BIO (`BIO_R_WRITE_TO_READ_ONLY_BIO`).
    #[error("write to read-only BIO")]
    WriteToReadOnly,

    /// TCP connection error (`BIO_R_CONNECT_ERROR` / `BIO_R_NBIO_CONNECT_ERROR`).
    #[error("connection error: {0}")]
    ConnectionError(String),

    /// TCP accept error (`BIO_R_ACCEPT_ERROR`).
    #[error("accept error: {0}")]
    AcceptError(String),

    /// DNS / address lookup failure (`BIO_R_LOOKUP_RETURNED_NOTHING`).
    #[error("address lookup failed: {0}")]
    AddrLookupFailed(String),

    /// Invalid argument passed to a BIO operation (`BIO_R_INVALID_ARGUMENT`).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Broken pipe or connection reset by peer (`BIO_R_BROKEN_PIPE`).
    #[error("broken pipe")]
    BrokenPipe,

    /// Underlying I/O error from the operating system.
    ///
    /// Wraps [`std::io::Error`] for transparent propagation via the `?` operator.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Conversion from [`BioError`] to [`CryptoError`] for propagation
/// through the crypto layer error chain.
///
/// I/O errors are forwarded directly to [`CryptoError::Io`]. All other
/// BIO-specific errors are wrapped in [`CryptoError::Io`] with
/// [`io::ErrorKind::Other`] since BIO errors fundamentally represent
/// I/O-level failures.
impl From<BioError> for CryptoError {
    fn from(err: BioError) -> Self {
        match err {
            BioError::Io(io_err) => CryptoError::Io(io_err),
            other => CryptoError::Io(io::Error::new(io::ErrorKind::Other, other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Utility functions — bio_dump, bio_indent
// ---------------------------------------------------------------------------

/// Number of hex bytes per dump line, matching C `DUMP_WIDTH` in
/// `crypto/bio/bio_dump.c`.
const DUMP_WIDTH: usize = 16;

/// Maximum allowed indent in [`bio_dump`] and [`bio_indent`], preventing
/// runaway whitespace output.
const MAX_INDENT: usize = 128;

/// Hex-dump bytes to a writer, replacing C `BIO_dump_indent()` from
/// `crypto/bio/bio_dump.c` (155 lines).
///
/// Produces output in the standard OpenSSL hex dump format:
///
/// ```text
/// 0000 - 48 65 6c 6c 6f 20 57 6f-72 6c 64 21 0a 00       Hello World!..
/// ```
///
/// Each line shows:
/// 1. An offset in 4-digit hexadecimal
/// 2. A dash separator
/// 3. Up to 16 hex bytes with a dash separator at byte index 7
/// 4. Printable ASCII representation (non-printable bytes shown as `.`)
///
/// # Parameters
///
/// - `writer` — Output destination (any [`Write`] implementor).
/// - `data` — The byte slice to hex-dump.
/// - `indent` — Number of leading spaces on each line (clamped to [`MAX_INDENT`]).
///
/// # Errors
///
/// Returns [`io::Error`] if writing to the output fails.
pub fn bio_dump(writer: &mut dyn Write, data: &[u8], indent: usize) -> io::Result<()> {
    let indent = indent.min(MAX_INDENT);
    let indent_str: String = " ".repeat(indent);
    let total = data.len();

    let mut offset: usize = 0;
    while offset < total {
        // Number of bytes to display on this line
        let line_len = DUMP_WIDTH.min(total.saturating_sub(offset));

        // Write indent + 4-digit hex offset + dash separator
        write!(writer, "{indent_str}{offset:04x} - ")?;

        // Write hex bytes: 16 columns, dash separator between bytes 7 and 8
        for i in 0..DUMP_WIDTH {
            if i < line_len {
                write!(writer, "{:02x}", data[offset + i])?;
            } else {
                // Pad incomplete last line with spaces
                write!(writer, "  ")?;
            }
            // Column separator: dash after column 7, space after others
            if i == 7 {
                write!(writer, "-")?;
            } else if i < DUMP_WIDTH - 1 {
                write!(writer, " ")?;
            }
        }

        // Two-space gap between hex and ASCII columns
        write!(writer, "  ")?;

        // Write ASCII representation (printable: 0x20 through 0x7E, else '.')
        for i in 0..line_len {
            let byte = data[offset + i];
            if (0x20..=0x7e).contains(&byte) {
                write!(writer, "{}", byte as char)?;
            } else {
                write!(writer, ".")?;
            }
        }

        writeln!(writer)?;
        // Rule R6: saturating_add for offset advancement
        offset = offset.saturating_add(DUMP_WIDTH);
    }

    Ok(())
}

/// Write `indent` spaces to a writer, replacing C `BIO_indent()` from
/// `crypto/bio/bio_lib.c`.
///
/// Writes up to `max` spaces to the output. If `indent` exceeds `max`,
/// it is clamped to `max`.
///
/// # Parameters
///
/// - `writer` — Output destination.
/// - `indent` — Number of spaces to write.
/// - `max` — Maximum number of spaces allowed.
///
/// # Errors
///
/// Returns [`io::Error`] if writing to the output fails.
pub fn bio_indent(writer: &mut dyn Write, indent: usize, max: usize) -> io::Result<()> {
    let count = indent.min(max);
    for _ in 0..count {
        write!(writer, " ")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- BioType tests ----

    #[test]
    fn test_bio_type_source_sink_classification() {
        assert!(BioType::Memory.is_source_sink());
        assert!(BioType::File.is_source_sink());
        assert!(BioType::FileDescriptor.is_source_sink());
        assert!(BioType::Socket.is_source_sink());
        assert!(BioType::Connect.is_source_sink());
        assert!(BioType::Accept.is_source_sink());
        assert!(BioType::Datagram.is_source_sink());
        assert!(BioType::DatagramPair.is_source_sink());
        assert!(BioType::BioPair.is_source_sink());
        assert!(BioType::Null.is_source_sink());
        assert!(BioType::CoreToProvider.is_source_sink());
        assert!(BioType::Log.is_source_sink());

        assert!(!BioType::Buffer.is_source_sink());
        assert!(!BioType::Ssl.is_source_sink());
        assert!(!BioType::NullFilter.is_source_sink());
        assert!(!BioType::None.is_source_sink());
        assert!(!BioType::Custom(42).is_source_sink());
    }

    #[test]
    fn test_bio_type_filter_classification() {
        assert!(BioType::Buffer.is_filter());
        assert!(BioType::LineBuffer.is_filter());
        assert!(BioType::ReadBuffer.is_filter());
        assert!(BioType::Prefix.is_filter());
        assert!(BioType::NullFilter.is_filter());
        assert!(BioType::NbioTest.is_filter());
        assert!(BioType::Ssl.is_filter());

        assert!(!BioType::Memory.is_filter());
        assert!(!BioType::Socket.is_filter());
        assert!(!BioType::None.is_filter());
        assert!(!BioType::Log.is_filter());
        assert!(!BioType::Custom(1).is_filter());
    }

    #[test]
    fn test_bio_type_descriptor_classification() {
        assert!(BioType::FileDescriptor.is_descriptor());
        assert!(BioType::Socket.is_descriptor());
        assert!(BioType::Connect.is_descriptor());
        assert!(BioType::Accept.is_descriptor());
        assert!(BioType::Datagram.is_descriptor());

        assert!(!BioType::Memory.is_descriptor());
        assert!(!BioType::File.is_descriptor());
        assert!(!BioType::Buffer.is_descriptor());
        assert!(!BioType::BioPair.is_descriptor());
        assert!(!BioType::None.is_descriptor());
    }

    #[test]
    fn test_bio_type_name() {
        assert_eq!(BioType::Memory.name(), "memory buffer");
        assert_eq!(BioType::File.name(), "FILE pointer");
        assert_eq!(BioType::FileDescriptor.name(), "file descriptor");
        assert_eq!(BioType::Socket.name(), "socket");
        assert_eq!(BioType::Connect.name(), "connect");
        assert_eq!(BioType::Accept.name(), "accept");
        assert_eq!(BioType::Datagram.name(), "datagram");
        assert_eq!(BioType::DatagramPair.name(), "datagram pair");
        assert_eq!(BioType::BioPair.name(), "BIO pair");
        assert_eq!(BioType::Null.name(), "NULL");
        assert_eq!(BioType::CoreToProvider.name(), "core to provider");
        assert_eq!(BioType::Buffer.name(), "buffer");
        assert_eq!(BioType::LineBuffer.name(), "line buffer");
        assert_eq!(BioType::ReadBuffer.name(), "read buffer");
        assert_eq!(BioType::Prefix.name(), "prefix");
        assert_eq!(BioType::NullFilter.name(), "null filter");
        assert_eq!(BioType::NbioTest.name(), "non-blocking IO test");
        assert_eq!(BioType::Ssl.name(), "ssl");
        assert_eq!(BioType::Log.name(), "syslog");
        assert_eq!(BioType::None.name(), "NONE");
        assert_eq!(BioType::Custom(99).name(), "custom");
    }

    #[test]
    fn test_bio_type_display() {
        assert_eq!(format!("{}", BioType::Memory), "memory buffer");
        assert_eq!(format!("{}", BioType::Null), "NULL");
        assert_eq!(format!("{}", BioType::Custom(1)), "custom");
    }

    #[test]
    fn test_bio_type_equality_and_hash() {
        assert_eq!(BioType::Memory, BioType::Memory);
        assert_ne!(BioType::Memory, BioType::File);
        assert_eq!(BioType::Custom(42), BioType::Custom(42));
        assert_ne!(BioType::Custom(1), BioType::Custom(2));

        // Verify Hash works via HashMap
        let mut map = std::collections::HashMap::new();
        map.insert(BioType::Memory, "mem");
        map.insert(BioType::Socket, "sock");
        assert_eq!(map.get(&BioType::Memory), Some(&"mem"));
        assert_eq!(map.get(&BioType::Socket), Some(&"sock"));
        assert_eq!(map.get(&BioType::File), Option::None);
    }

    #[test]
    fn test_bio_type_none_is_neither() {
        assert!(!BioType::None.is_source_sink());
        assert!(!BioType::None.is_filter());
        assert!(!BioType::None.is_descriptor());
    }

    #[test]
    fn test_bio_type_custom_is_neither() {
        let custom = BioType::Custom(0xABCD);
        assert!(!custom.is_source_sink());
        assert!(!custom.is_filter());
        assert!(!custom.is_descriptor());
    }

    // ---- BioFlags tests ----

    #[test]
    fn test_bio_flags_composition() {
        let flags = BioFlags::READ | BioFlags::WRITE;
        assert!(flags.contains(BioFlags::READ));
        assert!(flags.contains(BioFlags::WRITE));
        assert!(!flags.contains(BioFlags::IO_SPECIAL));

        let rws = BioFlags::RWS;
        assert!(rws.contains(BioFlags::READ));
        assert!(rws.contains(BioFlags::WRITE));
        assert!(rws.contains(BioFlags::IO_SPECIAL));
    }

    #[test]
    fn test_bio_flags_bit_values() {
        assert_eq!(BioFlags::READ.bits(), 0x01);
        assert_eq!(BioFlags::WRITE.bits(), 0x02);
        assert_eq!(BioFlags::IO_SPECIAL.bits(), 0x04);
        assert_eq!(BioFlags::RWS.bits(), 0x07);
        assert_eq!(BioFlags::SHOULD_RETRY.bits(), 0x08);
        assert_eq!(BioFlags::MEM_RDONLY.bits(), 0x200);
        assert_eq!(BioFlags::NONCLEAR_RST.bits(), 0x400);
        assert_eq!(BioFlags::IN_EOF.bits(), 0x800);
        assert_eq!(BioFlags::AUTO_EOF.bits(), 0x1000);
    }

    #[test]
    fn test_bio_flags_empty() {
        let flags = BioFlags::empty();
        assert!(!flags.contains(BioFlags::READ));
        assert_eq!(flags.bits(), 0);
    }

    #[test]
    fn test_bio_flags_set_clear() {
        let mut flags = BioFlags::empty();
        flags.insert(BioFlags::SHOULD_RETRY);
        assert!(flags.contains(BioFlags::SHOULD_RETRY));
        flags.remove(BioFlags::SHOULD_RETRY);
        assert!(!flags.contains(BioFlags::SHOULD_RETRY));
    }

    // ---- BioRetryReason tests ----

    #[test]
    fn test_bio_retry_reason_display() {
        assert_eq!(format!("{}", BioRetryReason::None), "none");
        assert_eq!(
            format!("{}", BioRetryReason::SslX509Lookup),
            "SSL X509 lookup"
        );
        assert_eq!(
            format!("{}", BioRetryReason::Connect),
            "connect in progress"
        );
        assert_eq!(format!("{}", BioRetryReason::Accept), "accept in progress");
    }

    #[test]
    fn test_bio_retry_reason_clone_copy() {
        let reason = BioRetryReason::Connect;
        let cloned = reason;
        assert_eq!(reason, cloned);
    }

    // ---- BioStats tests ----

    #[test]
    fn test_bio_stats_new() {
        let stats = BioStats::new();
        assert_eq!(stats.bytes_read(), 0);
        assert_eq!(stats.bytes_written(), 0);
    }

    #[test]
    fn test_bio_stats_default() {
        let stats = BioStats::default();
        assert_eq!(stats.bytes_read(), 0);
        assert_eq!(stats.bytes_written(), 0);
    }

    #[test]
    fn test_bio_stats_record_and_read() {
        let mut stats = BioStats::new();
        stats.record_read(100);
        stats.record_write(200);
        assert_eq!(stats.bytes_read(), 100);
        assert_eq!(stats.bytes_written(), 200);

        stats.record_read(50);
        stats.record_write(75);
        assert_eq!(stats.bytes_read(), 150);
        assert_eq!(stats.bytes_written(), 275);
    }

    #[test]
    fn test_bio_stats_saturating_add_read() {
        let mut stats = BioStats::new();
        stats.bytes_read = u64::MAX - 10;
        stats.record_read(100);
        assert_eq!(stats.bytes_read(), u64::MAX);
    }

    #[test]
    fn test_bio_stats_saturating_add_write() {
        let mut stats = BioStats::new();
        stats.bytes_written = u64::MAX - 5;
        stats.record_write(50);
        assert_eq!(stats.bytes_written(), u64::MAX);
    }

    #[test]
    fn test_bio_stats_reset() {
        let mut stats = BioStats::new();
        stats.record_read(1000);
        stats.record_write(2000);
        stats.reset();
        assert_eq!(stats.bytes_read(), 0);
        assert_eq!(stats.bytes_written(), 0);
    }

    #[test]
    fn test_bio_stats_zero_record() {
        let mut stats = BioStats::new();
        stats.record_read(0);
        stats.record_write(0);
        assert_eq!(stats.bytes_read(), 0);
        assert_eq!(stats.bytes_written(), 0);
    }

    // ---- BioCallbackOp tests ----

    #[test]
    fn test_bio_callback_op_display() {
        assert_eq!(format!("{}", BioCallbackOp::Read), "read");
        assert_eq!(format!("{}", BioCallbackOp::Write), "write");
        assert_eq!(format!("{}", BioCallbackOp::Puts), "puts");
        assert_eq!(format!("{}", BioCallbackOp::Gets), "gets");
        assert_eq!(format!("{}", BioCallbackOp::Ctrl), "ctrl");
        assert_eq!(format!("{}", BioCallbackOp::Free), "free");
    }

    #[test]
    fn test_bio_callback_op_equality() {
        assert_eq!(BioCallbackOp::Read, BioCallbackOp::Read);
        assert_ne!(BioCallbackOp::Read, BioCallbackOp::Write);
    }

    // ---- BioCallback default impl tests ----

    /// A test callback verifying default implementations.
    struct TestCallback;
    impl BioCallback for TestCallback {}

    #[test]
    fn test_bio_callback_defaults_do_not_panic() {
        let cb = TestCallback;
        // before_op should return true by default
        assert!(cb.before_op(BioCallbackOp::Read, BioType::Memory, 1024));
        assert!(cb.before_op(BioCallbackOp::Write, BioType::File, 512));
        assert!(cb.before_op(BioCallbackOp::Free, BioType::Socket, 0));

        // after_op should not panic on success or error
        cb.after_op(BioCallbackOp::Write, BioType::File, &Ok(512));
        cb.after_op(
            BioCallbackOp::Read,
            BioType::Socket,
            &Err(io::Error::new(io::ErrorKind::WouldBlock, "would block")),
        );
    }

    // ---- BioError tests ----

    #[test]
    fn test_bio_error_display() {
        assert_eq!(
            format!("{}", BioError::Uninitialized),
            "BIO not initialized"
        );
        assert_eq!(
            format!("{}", BioError::UnsupportedMethod("test".into())),
            "unsupported BIO method: test"
        );
        assert_eq!(
            format!("{}", BioError::WriteToReadOnly),
            "write to read-only BIO"
        );
        assert_eq!(
            format!("{}", BioError::ConnectionError("refused".into())),
            "connection error: refused"
        );
        assert_eq!(
            format!("{}", BioError::AcceptError("bind failed".into())),
            "accept error: bind failed"
        );
        assert_eq!(
            format!("{}", BioError::AddrLookupFailed("dns".into())),
            "address lookup failed: dns"
        );
        assert_eq!(
            format!("{}", BioError::InvalidArgument("null".into())),
            "invalid argument: null"
        );
        assert_eq!(format!("{}", BioError::BrokenPipe), "broken pipe");
    }

    #[test]
    fn test_bio_error_io_from() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let bio_err: BioError = io_err.into();
        match bio_err {
            BioError::Io(ref e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            _ => panic!("expected BioError::Io"),
        }
    }

    #[test]
    fn test_bio_error_to_crypto_error_io_passthrough() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broken");
        let bio_err = BioError::Io(io_err);
        let crypto_err: CryptoError = bio_err.into();
        match crypto_err {
            CryptoError::Io(ref e) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            _ => panic!("expected CryptoError::Io with BrokenPipe kind"),
        }
    }

    #[test]
    fn test_bio_error_to_crypto_error_non_io() {
        let bio_err = BioError::Uninitialized;
        let crypto_err: CryptoError = bio_err.into();
        match crypto_err {
            CryptoError::Io(ref e) => {
                assert_eq!(e.kind(), io::ErrorKind::Other);
                assert!(e.to_string().contains("BIO not initialized"));
            }
            _ => panic!("expected CryptoError::Io wrapping BioError"),
        }
    }

    #[test]
    fn test_bio_error_write_to_readonly_to_crypto() {
        let bio_err = BioError::WriteToReadOnly;
        let crypto_err: CryptoError = bio_err.into();
        match crypto_err {
            CryptoError::Io(ref e) => {
                assert_eq!(e.kind(), io::ErrorKind::Other);
            }
            _ => panic!("expected CryptoError::Io"),
        }
    }

    // ---- bio_dump tests ----

    #[test]
    fn test_bio_dump_empty() {
        let mut output = Vec::new();
        bio_dump(&mut output, &[], 0).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_bio_dump_single_line() {
        let mut output = Vec::new();
        let data = b"Hello!";
        bio_dump(&mut output, data, 0).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("0000 - "));
        assert!(text.contains("48 65 6c 6c 6f 21"));
        assert!(text.contains("Hello!"));
    }

    #[test]
    fn test_bio_dump_exactly_16_bytes() {
        let mut output = Vec::new();
        let data: Vec<u8> = (0x41..0x51).collect(); // A-P
        bio_dump(&mut output, &data, 0).unwrap();
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(text.contains("ABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn test_bio_dump_multi_line() {
        let mut output = Vec::new();
        let data: Vec<u8> = (0..32).collect();
        bio_dump(&mut output, &data, 0).unwrap();
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("0000 - "));
        assert!(lines[1].starts_with("0010 - "));
    }

    #[test]
    fn test_bio_dump_non_printable() {
        let mut output = Vec::new();
        let data = [0x00, 0x01, 0x1f, 0x7f, 0x80, 0xff];
        bio_dump(&mut output, &data, 0).unwrap();
        let text = String::from_utf8(output).unwrap();
        // All non-printable bytes should show as '.' in ASCII column
        assert!(text.contains("......"));
    }

    #[test]
    fn test_bio_dump_dash_separator_at_byte_7() {
        let mut output = Vec::new();
        let data: Vec<u8> = (0..16).collect();
        bio_dump(&mut output, &data, 0).unwrap();
        let text = String::from_utf8(output).unwrap();
        // After the 8th hex byte there should be a dash
        assert!(text.contains("07-08"));
    }

    #[test]
    fn test_bio_dump_with_indent() {
        let mut output = Vec::new();
        bio_dump(&mut output, b"AB", 4).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("    0000 - "));
    }

    #[test]
    fn test_bio_dump_indent_clamped() {
        let mut output = Vec::new();
        bio_dump(&mut output, b"X", 999).unwrap();
        let text = String::from_utf8(output).unwrap();
        // Indent clamped to MAX_INDENT (128)
        let leading_spaces = text.len() - text.trim_start().len();
        assert!(leading_spaces <= MAX_INDENT);
    }

    // ---- bio_indent tests ----

    #[test]
    fn test_bio_indent_basic() {
        let mut output = Vec::new();
        bio_indent(&mut output, 4, 10).unwrap();
        assert_eq!(output, b"    ");
    }

    #[test]
    fn test_bio_indent_clamped() {
        let mut output = Vec::new();
        bio_indent(&mut output, 20, 5).unwrap();
        assert_eq!(output.len(), 5);
    }

    #[test]
    fn test_bio_indent_zero() {
        let mut output = Vec::new();
        bio_indent(&mut output, 0, 100).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_bio_indent_max_zero() {
        let mut output = Vec::new();
        bio_indent(&mut output, 10, 0).unwrap();
        assert!(output.is_empty());
    }

    // ---- DEFAULT_BUFFER_SIZE test ----

    #[test]
    fn test_default_buffer_size() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 4096);
    }

    // ---- Bio trait implementation test ----

    /// Minimal concrete BIO for testing the trait's default implementations.
    struct MinimalBio {
        stats: BioStats,
    }

    impl MinimalBio {
        fn new() -> Self {
            Self {
                stats: BioStats::new(),
            }
        }
    }

    impl Bio for MinimalBio {
        fn bio_type(&self) -> BioType {
            BioType::Custom(0)
        }

        fn stats(&self) -> &BioStats {
            &self.stats
        }

        fn stats_mut(&mut self) -> &mut BioStats {
            &mut self.stats
        }
    }

    #[test]
    fn test_bio_trait_defaults() {
        let mut bio = MinimalBio::new();
        assert_eq!(bio.bio_type(), BioType::Custom(0));
        assert_eq!(bio.pending(), 0);
        assert_eq!(bio.wpending(), 0);
        assert!(!bio.eof());
        assert!(bio.reset().is_ok());
        assert_eq!(bio.method_name(), "custom");
        assert_eq!(bio.stats().bytes_read(), 0);

        bio.stats_mut().record_read(42);
        assert_eq!(bio.stats().bytes_read(), 42);
    }
}
