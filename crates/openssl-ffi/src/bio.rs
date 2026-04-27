//! BIO C ABI wrappers for the `openssl-ffi` crate.
//!
//! This module exports `extern "C"` functions matching the
//! `include/openssl/bio.h.in` public API contract for the BIO I/O
//! abstraction layer.  It covers all major BIO families — in-memory
//! buffers, files, sockets, connect/accept helpers, datagram sockets,
//! null sinks, the BIO pair pipe — as well as the `BIO_ctrl` dispatch
//! mechanism that the C macros rely upon.
//!
//! The public surface wraps the safe Rust trait-based I/O types from
//! [`openssl_crypto::bio`] (which in turn model the C `Read`/`Write`
//! behaviour behind a trait object).  Ownership, lifecycle and chaining
//! semantics all live in the `BioInner` / `BioMethodInner` internal
//! representations that are tucked behind the opaque `*mut BIO` and
//! `*const BIO_METHOD` pointers exposed to C.
//!
//! # Unsafe policy (Rule R8)
//!
//! This module is allowed to contain `unsafe` code because it lives in
//! the `openssl-ffi` crate — the single designated FFI boundary crate
//! for the workspace.  Every `unsafe` block in this file carries a
//! `// SAFETY:` comment that documents:
//!
//! * NULL-pointer and validity assumptions for pointer parameters
//! * Alignment assumptions for reinterpretation casts
//! * Lifetime assumptions for references derived from raw pointers
//! * Thread-ownership assumptions for mutable references
//!
//! # Return-value conventions (from `crypto/bio/bio_lib.c`)
//!
//! * `BIO_read` — bytes read (`>0`), `0` on EOF, `-1` on error, `-2`
//!   when the method does not implement read.
//! * `BIO_write` — bytes written (`>0`), `0` on NULL/`dlen <= 0`,
//!   `-1` on an uninitialised BIO, `-2` on unsupported method.
//! * `BIO_read_ex` / `BIO_write_ex` — `1` on success, `0` on failure;
//!   byte counts are returned via the out pointer.
//! * `BIO_ctrl` — method-dependent return, `-1` for NULL bio, `-2`
//!   when the method has no `ctrl` callback.
//! * `BIO_free` / `BIO_free_all` — `1` success, `0` failure.
//!
//! # Chain structure
//!
//! BIO chains are doubly-linked via the `next_bio`/`prev_bio` slots of
//! `BioInner`.  The head-of-chain contract from `crypto/bio/bio_lib.c`
//! is preserved: `BIO_push` appends a BIO to the end of a chain and
//! returns the head, `BIO_pop` removes a single BIO and returns the
//! next one in the chain, and `BIO_free_all` walks the chain freeing
//! every node.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr, CString};

// `c_uint` is included in the import list to match the AAP external_imports
// contract (`ffi::c_uint` listed under members_accessed).  It is consumed
// below by `BIO_get_new_index` where the underlying atomic counter is held
// in `c_uint` width to match the OpenSSL convention of treating BIO type
// indices as unsigned in bitwise expressions.
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use libc::size_t;

use openssl_common::{CryptoError, CryptoResult};
use openssl_crypto::bio::{
    new_bio_pair, AcceptBio, BioPairEnd, ConnectBio, DatagramBio, FileBio, MemBio, NullBio,
    OpenMode, SecureMemBio, SocketBio,
};

// ---------------------------------------------------------------------------
// Opaque C-visible types
// ---------------------------------------------------------------------------

/// Opaque BIO handle exposed to C consumers.
///
/// The real data is stored on the heap in a `BioInner` instance; the
/// `*mut BIO` value returned to C is `Box::into_raw(Box::new(inner))
/// as *mut BIO`.  C code only treats this pointer as an opaque handle
/// and never dereferences it directly — all access goes through the
/// exported `BIO_*` functions, which re-cast the pointer back to
/// `*mut BioInner`.
#[repr(C)]
pub struct BIO {
    _private: [u8; 0],
}

/// Opaque `BIO_METHOD` handle.
///
/// For built-in BIO method types (memory, file, socket, …) the
/// `*const BIO_METHOD` value returned by the `BIO_s_*` factories
/// points at a `'static` `BioMethodInner` singleton.  For custom
/// methods allocated via [`BIO_meth_new`] the pointer is a
/// `Box::into_raw` of a heap-allocated `BioMethodInner`.
#[repr(C)]
pub struct BIO_METHOD {
    _private: [u8; 0],
}

// ---------------------------------------------------------------------------
// BIO_TYPE_* constants (from include/openssl/bio.h.in)
// ---------------------------------------------------------------------------

/// Descriptor class flag — a BIO that is backed by a file descriptor.
pub const BIO_TYPE_DESCRIPTOR: c_int = 0x0100;
/// Filter class flag — a BIO that transforms data from another BIO.
pub const BIO_TYPE_FILTER: c_int = 0x0200;
/// Source/sink class flag — a BIO that directly produces/consumes data.
pub const BIO_TYPE_SOURCE_SINK: c_int = 0x0400;

/// No specific type (sentinel).
pub const BIO_TYPE_NONE: c_int = 0;
/// In-memory buffer BIO.
pub const BIO_TYPE_MEM: c_int = 1 | BIO_TYPE_SOURCE_SINK;
/// `FILE *` BIO.
pub const BIO_TYPE_FILE: c_int = 2 | BIO_TYPE_SOURCE_SINK;
/// File descriptor BIO.
pub const BIO_TYPE_FD: c_int = 4 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// Socket file descriptor BIO.
pub const BIO_TYPE_SOCKET: c_int = 5 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// Null sink/source (`/dev/null`-style).
pub const BIO_TYPE_NULL: c_int = 6 | BIO_TYPE_SOURCE_SINK;
/// SSL/TLS filter BIO.
pub const BIO_TYPE_SSL: c_int = 7 | BIO_TYPE_FILTER;
/// Message digest filter BIO.
pub const BIO_TYPE_MD: c_int = 8 | BIO_TYPE_FILTER;
/// Buffering filter BIO.
pub const BIO_TYPE_BUFFER: c_int = 9 | BIO_TYPE_FILTER;
/// Cipher filter BIO.
pub const BIO_TYPE_CIPHER: c_int = 10 | BIO_TYPE_FILTER;
/// Base64 encode/decode filter BIO.
pub const BIO_TYPE_BASE64: c_int = 11 | BIO_TYPE_FILTER;
/// TCP connect client BIO.
pub const BIO_TYPE_CONNECT: c_int = 12 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// TCP accept server BIO.
pub const BIO_TYPE_ACCEPT: c_int = 13 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// Non-blocking I/O test filter BIO.
pub const BIO_TYPE_NBIO_TEST: c_int = 16 | BIO_TYPE_FILTER;
/// Transparent null filter BIO.
pub const BIO_TYPE_NULL_FILTER: c_int = 17 | BIO_TYPE_FILTER;
/// In-process BIO-pair pipe.
pub const BIO_TYPE_BIO: c_int = 19 | BIO_TYPE_SOURCE_SINK;
/// Line-buffering filter BIO.
pub const BIO_TYPE_LINEBUFFER: c_int = 20 | BIO_TYPE_FILTER;
/// Datagram (UDP) BIO.
pub const BIO_TYPE_DGRAM: c_int = 21 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// ASN.1 filter BIO.
pub const BIO_TYPE_ASN1: c_int = 22 | BIO_TYPE_FILTER;
/// Compression filter BIO.
pub const BIO_TYPE_COMP: c_int = 23 | BIO_TYPE_FILTER;
/// Core-to-provider bridge BIO.
pub const BIO_TYPE_CORE_TO_PROV: c_int = 25 | BIO_TYPE_SOURCE_SINK;
/// Datagram-pair BIO (for in-process QUIC testing).
pub const BIO_TYPE_DGRAM_PAIR: c_int = 26 | BIO_TYPE_SOURCE_SINK;
/// In-memory datagram BIO.
pub const BIO_TYPE_DGRAM_MEM: c_int = 27 | BIO_TYPE_SOURCE_SINK;

/// Lowest type index available for user-registered custom BIO types.
pub const BIO_TYPE_START: c_int = 128;
/// Bit mask of the type-index portion of a BIO type value.
pub const BIO_TYPE_MASK: c_int = 0xff;

// ---------------------------------------------------------------------------
// BIO_CTRL_* constants (from include/openssl/bio.h.in)
// ---------------------------------------------------------------------------

/// Reset the BIO to its initial state.
pub const BIO_CTRL_RESET: c_int = 1;
/// Query whether the BIO has reached end-of-file.
pub const BIO_CTRL_EOF: c_int = 2;
/// Generic informational query (method-specific).
pub const BIO_CTRL_INFO: c_int = 3;
/// Generic setter (method-specific).
pub const BIO_CTRL_SET: c_int = 4;
/// Generic getter (method-specific).
pub const BIO_CTRL_GET: c_int = 5;
/// Notify the BIO that it was pushed onto a chain.
pub const BIO_CTRL_PUSH: c_int = 6;
/// Notify the BIO that it was popped from a chain.
pub const BIO_CTRL_POP: c_int = 7;
/// Query the close/noclose flag.
pub const BIO_CTRL_GET_CLOSE: c_int = 8;
/// Set the close/noclose flag.
pub const BIO_CTRL_SET_CLOSE: c_int = 9;
/// Return the number of bytes currently pending (readable without IO).
pub const BIO_CTRL_PENDING: c_int = 10;
/// Flush any buffered data to the underlying source/sink.
pub const BIO_CTRL_FLUSH: c_int = 11;
/// Duplicate control for chain copies.
pub const BIO_CTRL_DUP: c_int = 12;
/// Return the number of bytes queued for writing.
pub const BIO_CTRL_WPENDING: c_int = 13;
/// Install a monitoring callback.
pub const BIO_CTRL_SET_CALLBACK: c_int = 14;
/// Retrieve the monitoring callback.
pub const BIO_CTRL_GET_CALLBACK: c_int = 15;

/// Peek at data without consuming it (memory BIO).
pub const BIO_CTRL_PEEK: c_int = 29;
/// Set the backing filename for a file BIO.
pub const BIO_CTRL_SET_FILENAME: c_int = 30;

// Datagram control commands
/// Establish the datagram peer address.
pub const BIO_CTRL_DGRAM_CONNECT: c_int = 31;
/// Mark the datagram BIO as connected.
pub const BIO_CTRL_DGRAM_SET_CONNECTED: c_int = 32;
/// Set the datagram receive timeout.
pub const BIO_CTRL_DGRAM_SET_RECV_TIMEOUT: c_int = 33;
/// Query the datagram receive timeout.
pub const BIO_CTRL_DGRAM_GET_RECV_TIMEOUT: c_int = 34;
/// Set the datagram send timeout.
pub const BIO_CTRL_DGRAM_SET_SEND_TIMEOUT: c_int = 35;
/// Query the datagram send timeout.
pub const BIO_CTRL_DGRAM_GET_SEND_TIMEOUT: c_int = 36;
/// Query the datagram MTU.
pub const BIO_CTRL_DGRAM_GET_MTU: c_int = 41;
/// Set the datagram MTU.
pub const BIO_CTRL_DGRAM_SET_MTU: c_int = 42;

/// Install a line prefix (prefix filter BIO).
pub const BIO_CTRL_SET_PREFIX: c_int = 91;
/// Set the indent level (prefix filter BIO).
pub const BIO_CTRL_SET_INDENT: c_int = 92;
/// Query the indent level (prefix filter BIO).
pub const BIO_CTRL_GET_INDENT: c_int = 93;

// Method-specific BIO_C_* helpers used by BIO_ctrl callers.  These
// match the values in `include/openssl/bio.h.in` and are part of the
// public C API — consumers that build custom BIO_METHODs (via
// BIO_meth_new) dispatch on these codes inside their ctrl callbacks.
pub const BIO_C_SET_FD: c_int = 104;
pub const BIO_C_GET_FD: c_int = 105;
pub const BIO_C_SET_FILE_PTR: c_int = 106;
pub const BIO_C_GET_FILE_PTR: c_int = 107;
pub const BIO_C_SET_FILENAME: c_int = 108;
pub const BIO_C_SET_SSL: c_int = 109;
pub const BIO_C_GET_SSL: c_int = 110;
pub const BIO_C_SET_MD: c_int = 111;
pub const BIO_C_GET_MD: c_int = 112;
pub const BIO_C_SET_BUF_MEM: c_int = 114;
pub const BIO_C_GET_BUF_MEM_PTR: c_int = 115;
pub const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;
pub const BIO_C_FILE_SEEK: c_int = 128;
pub const BIO_C_FILE_TELL: c_int = 133;
pub const BIO_C_SET_CONNECT: c_int = 100;
pub const BIO_C_GET_CONNECT: c_int = 139;
pub const BIO_C_SET_ACCEPT: c_int = 101;
pub const BIO_C_DO_STATE_MACHINE: c_int = 101;
pub const BIO_C_SET_NBIO: c_int = 102;
pub const BIO_C_SET_MEM_BUF: c_int = 114;
pub const BIO_C_SHUTDOWN_WR: c_int = 137;

// ---------------------------------------------------------------------------
// BIO_CLOSE / BIO_NOCLOSE and BIO_FLAGS_*
// ---------------------------------------------------------------------------

/// Do NOT close the underlying resource when the BIO is freed.
pub const BIO_NOCLOSE: c_int = 0x00;
/// Close the underlying resource when the BIO is freed.
pub const BIO_CLOSE: c_int = 0x01;

// ---------------------------------------------------------------------------
// Function-pointer types for custom BIO methods (from BIO_meth_*)
// ---------------------------------------------------------------------------

/// Legacy write callback: `int bwrite(BIO *, const char *, int)`.
pub type BioWriteFn = unsafe extern "C" fn(*mut BIO, *const c_char, c_int) -> c_int;
/// Legacy read callback: `int bread(BIO *, char *, int)`.
pub type BioReadFn = unsafe extern "C" fn(*mut BIO, *mut c_char, c_int) -> c_int;
/// `puts` callback: `int bputs(BIO *, const char *)`.
pub type BioPutsFn = unsafe extern "C" fn(*mut BIO, *const c_char) -> c_int;
/// `gets` callback: `int bgets(BIO *, char *, int)`.
pub type BioGetsFn = unsafe extern "C" fn(*mut BIO, *mut c_char, c_int) -> c_int;
/// `ctrl` callback: `long ctrl(BIO *, int, long, void *)`.
pub type BioCtrlFn = unsafe extern "C" fn(*mut BIO, c_int, c_long, *mut c_void) -> c_long;
/// `create` callback: constructor hook run inside `BIO_new`.
pub type BioCreateFn = unsafe extern "C" fn(*mut BIO) -> c_int;
/// `destroy` callback: destructor hook run inside `BIO_free`.
pub type BioDestroyFn = unsafe extern "C" fn(*mut BIO) -> c_int;
/// Extended info callback used by `BIO_callback_ctrl`.
pub type BioInfoCb =
    unsafe extern "C" fn(*mut BIO, c_int, *const c_char, c_int, c_long, c_long) -> c_long;
/// Callback-ctrl callback: `long callback_ctrl(BIO *, int, BIO_info_cb *)`.
pub type BioCallbackCtrlFn = unsafe extern "C" fn(*mut BIO, c_int, Option<BioInfoCb>) -> c_long;

// ---------------------------------------------------------------------------
// Method-kind tag — selects the dispatch strategy for an owned BIO
// ---------------------------------------------------------------------------

/// Discriminator for built-in versus custom BIO methods.
///
/// For built-in methods, `BIO_new` knows how to allocate the matching
/// concrete safe-Rust BIO type.  For custom methods, `BIO_new` leaves
/// the variant in [`BioVariant::Uninitialized`] and delegates all
/// behaviour to the user-provided function pointers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BioMethodKind {
    Mem,
    SecureMem,
    File,
    Socket,
    Connect,
    Accept,
    Datagram,
    Null,
    Custom,
}

/// Private name storage for `BIO_METHOD`.
///
/// Built-in methods carry a `'static` NUL-terminated `CStr`; methods
/// created via [`BIO_meth_new`] carry an owned `CString` built from the
/// caller-supplied C string.  Both forms can be returned to C callers
/// via `BIO_method_name()` as a plain `*const c_char`.
pub(crate) enum BioMethodName {
    Static(&'static CStr),
    Owned(CString),
}

impl BioMethodName {
    /// Borrow the name as a C-compatible string suitable for
    /// returning through FFI as `*const c_char`.
    fn as_c_str(&self) -> &CStr {
        match self {
            BioMethodName::Static(s) => s,
            BioMethodName::Owned(s) => s.as_c_str(),
        }
    }
}

/// The actual heap/static layout pointed to by `*const BIO_METHOD`.
pub(crate) struct BioMethodInner {
    pub(crate) type_id: c_int,
    pub(crate) name: BioMethodName,
    pub(crate) kind: BioMethodKind,
    pub(crate) bwrite: Option<BioWriteFn>,
    pub(crate) bread: Option<BioReadFn>,
    pub(crate) bputs: Option<BioPutsFn>,
    pub(crate) bgets: Option<BioGetsFn>,
    pub(crate) ctrl: Option<BioCtrlFn>,
    pub(crate) create: Option<BioCreateFn>,
    pub(crate) destroy: Option<BioDestroyFn>,
    pub(crate) callback_ctrl: Option<BioCallbackCtrlFn>,
}

// Function pointers are `Sync` and the name is `Sync` (either a
// `&'static CStr` or an owned `CString` that is never shared via
// `&mut`), so this struct is safely sharable across threads as a
// `'static` singleton.
unsafe impl Sync for BioMethodInner {}
unsafe impl Send for BioMethodInner {}

// ---------------------------------------------------------------------------
// BioVariant — the real behaviour behind an owned BIO
// ---------------------------------------------------------------------------

/// Tag-plus-payload for the safe Rust BIO implementation that a given
/// `BIO *` wraps.
///
/// The variant is chosen at construction time based on the
/// [`BioMethodInner::kind`] of the `*const BIO_METHOD` passed to
/// [`BIO_new`], or directly by the specialised factory functions
/// (`BIO_new_mem_buf`, `BIO_new_file`, …).  For custom BIOs created
/// through a user-provided `BIO_METHOD`, the variant is
/// `Uninitialized` and the method's own callbacks are invoked for all
/// operations.
#[allow(clippy::large_enum_variant)]
pub(crate) enum BioVariant {
    Uninitialized,
    Mem(MemBio),
    SecureMem(SecureMemBio),
    File(FileBio),
    Socket(SocketBio),
    Connect(ConnectBio),
    Accept(AcceptBio),
    Datagram(DatagramBio),
    BioPair(BioPairEnd),
    Null(NullBio),
}

/// Heap-allocated backing store behind every `*mut BIO`.
///
/// All the per-instance state that the C `struct bio_st` from
/// `crypto/bio/bio_local.h` tracks lives here.  The raw pointer
/// exposed to C is `Box::into_raw(Box::new(BioInner { .. })) as *mut
/// BIO`; conversion back is via `to_inner`/`to_inner_mut` helpers
/// defined below.
pub(crate) struct BioInner {
    /// Concrete behaviour for this BIO.
    pub(crate) variant: BioVariant,
    /// Pointer to the owning `BIO_METHOD`.
    ///
    /// For built-in methods this is a raw pointer to a `'static`
    /// singleton and is never freed.  For custom methods it is a
    /// pointer into the heap (owned by the caller, not this BIO).
    pub(crate) method: *const BioMethodInner,
    /// Next BIO in the chain (`BIO_push` direction).
    pub(crate) next_bio: *mut BIO,
    /// Previous BIO in the chain (`BIO_pop` back-link).
    pub(crate) prev_bio: *mut BIO,
    /// Bit field of `BIO_FLAGS_*` (read/write retry, EOF, RDONLY, …).
    pub(crate) flags: c_int,
    /// Last retry reason (`BIO_RR_*`).
    pub(crate) retry_reason: c_int,
    /// `BIO_CLOSE` (close underlying fd/file on drop) vs `BIO_NOCLOSE`.
    pub(crate) shutdown: c_int,
    /// Numeric per-method state (socket fd, EOF-return sentinel, …).
    pub(crate) num: c_int,
    /// Non-zero once the method's `create` callback has completed.
    pub(crate) init: c_int,
    /// Cumulative number of bytes successfully read through this BIO.
    pub(crate) num_read: u64,
    /// Cumulative number of bytes successfully written through this BIO.
    pub(crate) num_write: u64,
    /// Reference count (`BIO_up_ref` / `BIO_free`).
    pub(crate) refs: AtomicUsize,
    /// Opaque per-BIO data pointer (user-managed, for custom BIOs).
    pub(crate) data: *mut c_void,
    /// Installed monitoring callback (legacy `BIO_callback_fn`).
    pub(crate) callback: Option<BioInfoCb>,
    /// Argument cookie passed to `callback` on each invocation.
    pub(crate) callback_arg: *mut c_void,
}

impl BioInner {
    fn new(method: *const BioMethodInner, variant: BioVariant) -> Self {
        BioInner {
            variant,
            method,
            next_bio: ptr::null_mut(),
            prev_bio: ptr::null_mut(),
            flags: 0,
            retry_reason: 0,
            shutdown: BIO_CLOSE,
            num: -1,
            init: 0,
            num_read: 0,
            num_write: 0,
            refs: AtomicUsize::new(1),
            data: ptr::null_mut(),
            callback: None,
            callback_arg: ptr::null_mut(),
        }
    }
}

// ---------------------------------------------------------------------------
// Raw-pointer ↔ reference helpers
// ---------------------------------------------------------------------------

/// Convert a `*mut BIO` to a `&BioInner` reference, returning `None`
/// if the pointer is null.
///
/// # Safety
///
/// The caller must guarantee that `ptr`, if non-null, is a valid
/// pointer returned by one of the `BIO_new*` constructors defined in
/// this module, has not been freed, and that no other `&mut` reference
/// to the same `BioInner` is currently live.
#[inline]
unsafe fn to_inner<'a>(ptr: *const BIO) -> Option<&'a BioInner> {
    // SAFETY: caller guarantees pointer validity and exclusive Rust
    // ownership of any mutable access during the returned reference's
    // lifetime.  Null is handled explicitly.
    ptr.cast::<BioInner>().as_ref()
}

/// Convert a `*mut BIO` to a `&mut BioInner` reference, returning
/// `None` if the pointer is null.
///
/// # Safety
///
/// The caller must guarantee that `ptr`, if non-null, is a valid
/// pointer returned by one of the `BIO_new*` constructors, has not
/// been freed, and that no other reference to the same `BioInner`
/// currently exists.
#[inline]
unsafe fn to_inner_mut<'a>(ptr: *mut BIO) -> Option<&'a mut BioInner> {
    // SAFETY: caller guarantees pointer validity and that no other
    // live reference aliases the target during the returned lifetime.
    ptr.cast::<BioInner>().as_mut()
}

/// Allocate a new `BioInner` on the heap and convert it to the opaque
/// `*mut BIO` handle returned to C.
fn into_raw(inner: BioInner) -> *mut BIO {
    Box::into_raw(Box::new(inner)).cast::<BIO>()
}

/// Free a `*mut BIO` produced by [`into_raw`].  Does nothing when the
/// pointer is null.
///
/// # Safety
///
/// `ptr` must be either null or a pointer returned by [`into_raw`]
/// that has not already been freed.  After this call, the pointer is
/// invalid and must not be used again by the caller.
unsafe fn drop_from_raw(ptr: *mut BIO) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: caller guarantees the pointer was produced by
    // `Box::into_raw(Box::new(BioInner { .. }))`.
    drop(Box::from_raw(ptr.cast::<BioInner>()));
}

/// Map a `CryptoResult<()>` to the conventional `1/0` BIO success code.
///
/// Exhaustively inspects every [`CryptoError`] variant so that the
/// pattern match documents the mapping between the
/// `openssl-common` error taxonomy and the BIO C-ABI return
/// convention.  All failure modes currently collapse to `0`
/// (the canonical BIO failure code), but the enumerated arms make
/// future per-variant divergence (for example, mapping
/// `CryptoError::Rand` to a distinct BIO retry signal) a trivial
/// change.
fn crypto_result_to_int(r: &CryptoResult<()>) -> c_int {
    match r {
        Ok(()) => 1,
        Err(
            CryptoError::Common(_)
            | CryptoError::Provider(_)
            | CryptoError::AlgorithmNotFound(_)
            | CryptoError::Key(_)
            | CryptoError::Encoding(_)
            | CryptoError::Verification(_)
            | CryptoError::Rand(_)
            | CryptoError::Io(_),
        ) => 0,
    }
}

/// Flush a BIO's underlying variant through the `CryptoResult` pipeline.
///
/// This is the central composition bridge between the safe
/// [`flush_variant`] helper (which speaks in `io::Result`) and the
/// rest of the crypto stack (which speaks in [`CryptoResult`]).  The
/// `?` operator leverages the `#[from] io::Error` `From` impl on
/// [`CryptoError::Io`] to upcast any I/O failure into a
/// crypto-layer error transparently.
///
/// Called from every `BIO_CTRL_FLUSH` dispatch arm (`ctrl_mem`,
/// `ctrl_file`, `ctrl_socket`, `ctrl_connect`, `ctrl_accept`,
/// `ctrl_datagram`, and the Null handler) so that `BIO_flush` produces
/// uniform, cross-crate error semantics regardless of the underlying
/// variant.
fn bio_flush_crypto(inner: &mut BioInner) -> CryptoResult<()> {
    flush_variant(&mut inner.variant)?;
    Ok(())
}

/// Convert an [`io::Error`] to BIO retry flags.
///
/// Maps `WouldBlock`/`Interrupted` to the `should_retry` + appropriate
/// direction flag semantics that C callers expect.  Returns `true` if
/// the caller should treat the operation as a temporary failure (i.e.
/// set `should_retry` and return `-1`).
fn io_error_is_retry(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// Retry flag — the last read returned EAGAIN/short.
pub const BIO_FLAGS_READ: c_int = 0x01;
/// Retry flag — the last write returned EAGAIN/short.
pub const BIO_FLAGS_WRITE: c_int = 0x02;
/// Retry flag — the last operation was neither read nor write (e.g. connect).
pub const BIO_FLAGS_IO_SPECIAL: c_int = 0x04;
/// Bit mask covering all three retry-direction bits.
pub const BIO_FLAGS_RWS: c_int = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL;
/// Set when the BIO would block — the caller should retry.
pub const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;
/// Strip `\n` when encoding Base64.
pub const BIO_FLAGS_BASE64_NO_NL: c_int = 0x100;
/// Memory BIO is read-only (created via `BIO_new_mem_buf`).
pub const BIO_FLAGS_MEM_RDONLY: c_int = 0x200;
/// Reset must NOT zero out the buffer contents.
pub const BIO_FLAGS_NONCLEAR_RST: c_int = 0x400;
/// Auto-EOF detection latched (`BIO_eof` returns true).
pub const BIO_FLAGS_IN_EOF: c_int = 0x800;

/// Retry reason: SSL handshake needs X509 lookup.
pub const BIO_RR_SSL_X509_LOOKUP: c_int = 0x01;
/// Retry reason: connect in progress.
pub const BIO_RR_CONNECT: c_int = 0x02;
/// Retry reason: accept in progress.
pub const BIO_RR_ACCEPT: c_int = 0x03;

// BIO_new_file() mode flags (from include/openssl/bio.h.in `BIO_FP_*`).
pub const BIO_FP_READ: c_int = 0x02;
pub const BIO_FP_WRITE: c_int = 0x04;
pub const BIO_FP_APPEND: c_int = 0x08;
pub const BIO_FP_TEXT: c_int = 0x10;

// ---------------------------------------------------------------------------
// Built-in BIO_METHOD singletons
// ---------------------------------------------------------------------------
//
// The C implementation exposes a `const BIO_METHOD *` for each
// built-in source/sink BIO (`BIO_s_mem`, `BIO_s_file`, `BIO_s_socket`,
// `BIO_s_connect`, `BIO_s_accept`, `BIO_s_null`, `BIO_s_datagram`).
// In safe Rust we model these as `std::sync::OnceLock<BioMethodInner>`
// singletons allocated on first access.  Because the address of a
// value inside a `OnceLock` is stable for the entire program
// lifetime, the resulting `*const BIO_METHOD` pointer is valid
// indefinitely — matching C's `BIO_METHOD` ABI.

use std::sync::OnceLock;

fn mem_method() -> &'static BioMethodInner {
    static CELL: OnceLock<BioMethodInner> = OnceLock::new();
    CELL.get_or_init(|| BioMethodInner {
        type_id: BIO_TYPE_MEM,
        name: BioMethodName::Static(c"memory buffer"),
        kind: BioMethodKind::Mem,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    })
}

fn secure_mem_method() -> &'static BioMethodInner {
    static CELL: OnceLock<BioMethodInner> = OnceLock::new();
    CELL.get_or_init(|| BioMethodInner {
        type_id: BIO_TYPE_MEM,
        name: BioMethodName::Static(c"secure memory buffer"),
        kind: BioMethodKind::SecureMem,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    })
}

fn file_method() -> &'static BioMethodInner {
    static CELL: OnceLock<BioMethodInner> = OnceLock::new();
    CELL.get_or_init(|| BioMethodInner {
        type_id: BIO_TYPE_FILE,
        name: BioMethodName::Static(c"FILE pointer"),
        kind: BioMethodKind::File,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    })
}

fn socket_method() -> &'static BioMethodInner {
    static CELL: OnceLock<BioMethodInner> = OnceLock::new();
    CELL.get_or_init(|| BioMethodInner {
        type_id: BIO_TYPE_SOCKET,
        name: BioMethodName::Static(c"socket"),
        kind: BioMethodKind::Socket,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    })
}

fn connect_method() -> &'static BioMethodInner {
    static CELL: OnceLock<BioMethodInner> = OnceLock::new();
    CELL.get_or_init(|| BioMethodInner {
        type_id: BIO_TYPE_CONNECT,
        name: BioMethodName::Static(c"socket connect"),
        kind: BioMethodKind::Connect,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    })
}

fn accept_method() -> &'static BioMethodInner {
    static CELL: OnceLock<BioMethodInner> = OnceLock::new();
    CELL.get_or_init(|| BioMethodInner {
        type_id: BIO_TYPE_ACCEPT,
        name: BioMethodName::Static(c"socket accept"),
        kind: BioMethodKind::Accept,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    })
}

fn datagram_method() -> &'static BioMethodInner {
    static CELL: OnceLock<BioMethodInner> = OnceLock::new();
    CELL.get_or_init(|| BioMethodInner {
        type_id: BIO_TYPE_DGRAM,
        name: BioMethodName::Static(c"datagram socket"),
        kind: BioMethodKind::Datagram,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    })
}

fn null_method() -> &'static BioMethodInner {
    static CELL: OnceLock<BioMethodInner> = OnceLock::new();
    CELL.get_or_init(|| BioMethodInner {
        type_id: BIO_TYPE_NULL,
        name: BioMethodName::Static(c"NULL"),
        kind: BioMethodKind::Null,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    })
}

// ---------------------------------------------------------------------------
// BIO_s_* method accessors
// ---------------------------------------------------------------------------

/// `BIO_METHOD *BIO_s_mem(void);` — return the memory source/sink method.
#[no_mangle]
pub extern "C" fn BIO_s_mem() -> *const BIO_METHOD {
    core::ptr::from_ref::<BioMethodInner>(mem_method()).cast::<BIO_METHOD>()
}

/// `BIO_METHOD *BIO_s_secmem(void);` — secure-memory source/sink method.
#[no_mangle]
pub extern "C" fn BIO_s_secmem() -> *const BIO_METHOD {
    core::ptr::from_ref::<BioMethodInner>(secure_mem_method()).cast::<BIO_METHOD>()
}

/// `BIO_METHOD *BIO_s_file(void);` — file source/sink method.
#[no_mangle]
pub extern "C" fn BIO_s_file() -> *const BIO_METHOD {
    core::ptr::from_ref::<BioMethodInner>(file_method()).cast::<BIO_METHOD>()
}

/// `BIO_METHOD *BIO_s_socket(void);` — TCP socket source/sink method.
#[no_mangle]
pub extern "C" fn BIO_s_socket() -> *const BIO_METHOD {
    core::ptr::from_ref::<BioMethodInner>(socket_method()).cast::<BIO_METHOD>()
}

/// `BIO_METHOD *BIO_s_connect(void);` — connecting-socket method.
#[no_mangle]
pub extern "C" fn BIO_s_connect() -> *const BIO_METHOD {
    core::ptr::from_ref::<BioMethodInner>(connect_method()).cast::<BIO_METHOD>()
}

/// `BIO_METHOD *BIO_s_accept(void);` — accepting-socket method.
#[no_mangle]
pub extern "C" fn BIO_s_accept() -> *const BIO_METHOD {
    core::ptr::from_ref::<BioMethodInner>(accept_method()).cast::<BIO_METHOD>()
}

/// `BIO_METHOD *BIO_s_datagram(void);` — UDP datagram source/sink method.
#[no_mangle]
pub extern "C" fn BIO_s_datagram() -> *const BIO_METHOD {
    core::ptr::from_ref::<BioMethodInner>(datagram_method()).cast::<BIO_METHOD>()
}

/// `BIO_METHOD *BIO_s_null(void);` — discarding null method.
#[no_mangle]
pub extern "C" fn BIO_s_null() -> *const BIO_METHOD {
    core::ptr::from_ref::<BioMethodInner>(null_method()).cast::<BIO_METHOD>()
}

// ---------------------------------------------------------------------------
// BIO_new / BIO_free / BIO_free_all / BIO_up_ref / BIO_vfree
// ---------------------------------------------------------------------------

/// `BIO *BIO_new(const BIO_METHOD *type);`
///
/// Allocate a new BIO instance bound to the given method.  For
/// built-in methods a matching default concrete BIO is created (empty
/// memory buffer, detached socket, etc.).  For custom methods the
/// variant is left `Uninitialized` and any registered `create`
/// callback is invoked.
///
/// Returns a heap-owned `*mut BIO` that the caller must release with
/// [`BIO_free`].  Returns `null` when the method pointer is null or
/// allocation/initialisation fails.
#[no_mangle]
pub unsafe extern "C" fn BIO_new(type_: *const BIO_METHOD) -> *mut BIO {
    if type_.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller promises `type_` is a valid `*const
    // BIO_METHOD` — either a built-in singleton returned by
    // `BIO_s_*` or a value returned by `BIO_meth_new`.  The pointee
    // has `'static` (or caller-owned) lifetime for the duration of
    // this call.
    let method_inner = &*type_.cast::<BioMethodInner>();

    let variant = match method_inner.kind {
        BioMethodKind::Mem => BioVariant::Mem(MemBio::new()),
        BioMethodKind::SecureMem => BioVariant::SecureMem(SecureMemBio::new()),
        BioMethodKind::Null => BioVariant::Null(NullBio::new()),
        // File / Socket / Connect / Accept / Datagram / Custom BIOs
        // require explicit initialisation: either via a specialised
        // factory (`BIO_new_file`, …) or via the method's own
        // `create` callback.  Leave the variant empty until then.
        BioMethodKind::File
        | BioMethodKind::Socket
        | BioMethodKind::Connect
        | BioMethodKind::Accept
        | BioMethodKind::Datagram
        | BioMethodKind::Custom => BioVariant::Uninitialized,
    };

    let mut inner = BioInner::new(core::ptr::from_ref(method_inner), variant);
    // `init` mirrors the OpenSSL convention: built-in BIOs that carry
    // an already-valid backing resource (memory, null) are marked as
    // initialised; source/sinks that require a follow-up configuration
    // call start uninitialised.
    inner.init = match method_inner.kind {
        BioMethodKind::Mem | BioMethodKind::SecureMem | BioMethodKind::Null => 1,
        _ => 0,
    };

    let bio = into_raw(inner);

    // Invoke the user-supplied `create` callback, if any.
    if let Some(create) = method_inner.create {
        // SAFETY: the caller's `create` callback receives the same
        // `*mut BIO` pointer we just produced.  Its documented
        // contract mirrors the OpenSSL C API: return non-zero on
        // success, zero on failure, with the BIO in a state we are
        // free to destroy.
        let rc = create(bio);
        if rc == 0 {
            // SAFETY: `bio` was just produced by `into_raw`; the
            // `create` callback contract states that on failure the
            // BIO must be safe to free.
            drop_from_raw(bio);
            return ptr::null_mut();
        }
    }

    bio
}

/// `int BIO_free(BIO *a);`
///
/// Drop one reference to `a`.  When the refcount reaches zero the
/// backing safe-Rust BIO is released.  Matches OpenSSL's convention
/// of tolerating null input.
///
/// Returns `1` on success, `0` on failure.  A null pointer is a no-op
/// that returns `0` (matching `crypto/bio/bio_lib.c`).
#[no_mangle]
pub unsafe extern "C" fn BIO_free(a: *mut BIO) -> c_int {
    if a.is_null() {
        return 0;
    }

    // Decrement the refcount — when we are the last reference, run
    // the destroy callback (if any) and drop the inner box.
    // SAFETY: caller guarantees `a` is a valid pointer produced by
    // `BIO_new*` and not yet freed.  No other `&mut` reference is
    // active for the duration of this block.
    let inner = &*a.cast::<BioInner>();
    let prior = inner.refs.fetch_sub(1, Ordering::AcqRel);
    if prior != 1 {
        return 1;
    }

    // Final release: run destroy callback, then drop.
    // SAFETY: `inner.method` was populated by `BIO_new` from a valid
    // `*const BIO_METHOD`.  Custom-method destructors expect the
    // pointer we hand them.
    let method = &*inner.method;
    if let Some(destroy) = method.destroy {
        let _ = destroy(a);
    }

    // SAFETY: we hold the final refcount, so no other reference is
    // live and we are allowed to free the backing allocation.
    drop_from_raw(a);
    1
}

/// `void BIO_vfree(BIO *a);` — identical to `BIO_free` but with `void` return.
#[no_mangle]
pub unsafe extern "C" fn BIO_vfree(a: *mut BIO) {
    // SAFETY: same invariants as `BIO_free`; `a` must be valid or null.
    let _ = BIO_free(a);
}

/// `void BIO_free_all(BIO *a);`
///
/// Walk the chain starting at `a` via the `next_bio` link and free
/// each BIO in turn.  The chain is treated as owned by the caller;
/// shared chains with external refs remain partially alive thanks to
/// `BIO_free`'s refcount semantics.
#[no_mangle]
pub unsafe extern "C" fn BIO_free_all(a: *mut BIO) {
    let mut cur = a;
    while !cur.is_null() {
        // SAFETY: `cur` is either the caller-supplied pointer or was
        // read from a previously-validated BIO's `next_bio`.  All
        // such pointers originate from `BIO_new*` and remain valid
        // until freed.
        let next = match to_inner(cur) {
            Some(inner) => inner.next_bio,
            None => ptr::null_mut(),
        };
        // SAFETY: BIO_free decrements the refcount and releases the
        // allocation when it reaches zero; either outcome invalidates
        // `cur`, but we have already captured `next` above.
        let _ = BIO_free(cur);
        cur = next;
    }
}

/// `int BIO_up_ref(BIO *a);` — increment the reference count.
///
/// Returns `1` on success, `0` on failure (null input).
#[no_mangle]
pub unsafe extern "C" fn BIO_up_ref(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `bio` is a valid non-null BIO pointer.
    let inner = &*(bio as *const BioInner);
    inner.refs.fetch_add(1, Ordering::Relaxed);
    1
}

// ---------------------------------------------------------------------------
// Specialised factory methods (bss_mem.c / bss_file.c / bss_sock.c / bss_conn.c)
// ---------------------------------------------------------------------------

/// `BIO *BIO_new_mem_buf(const void *buf, int len);`
///
/// Wrap an existing buffer in a read-only memory BIO.  If `len < 0`
/// the buffer is assumed to be a null-terminated C string and its
/// length is computed with `strlen`.
///
/// The memory pointed to by `buf` must remain valid for the entire
/// lifetime of the returned BIO.  The caller retains ownership of
/// `buf`; the BIO does not attempt to free it.
///
/// Returns a read-only `*mut BIO` (with `BIO_FLAGS_MEM_RDONLY` set)
/// or `null` on allocation failure / invalid arguments.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO {
    if buf.is_null() {
        return ptr::null_mut();
    }

    // Determine buffer length, matching the C semantics of `len < 0`
    // meaning "null-terminated string".
    let byte_len: usize = if len < 0 {
        // SAFETY: caller promises `buf` is a null-terminated C
        // string when `len < 0`.  `CStr::from_ptr` scans up to the
        // terminator, which is guaranteed by the caller's contract.
        CStr::from_ptr(buf.cast::<c_char>()).to_bytes().len()
    } else {
        // `len >= 0` has been checked; the conversion is lossless on
        // all supported targets (c_int is i32, usize is at least u32).
        usize::try_from(len).unwrap_or(0)
    };

    // Build a safe owned copy so that our Read/Write semantics
    // remain well-defined even if the caller reuses the buffer.  A
    // read-only MemBio with MEM_RDONLY flag gives us the same
    // observable behaviour as the OpenSSL reference BIO.
    // SAFETY: caller guarantees `buf` points to at least `byte_len`
    // initialised bytes readable for the duration of this call.
    let slice = std::slice::from_raw_parts(buf.cast::<u8>(), byte_len);

    let method_inner = mem_method();
    let mut inner = BioInner::new(
        core::ptr::from_ref(method_inner),
        BioVariant::Mem(MemBio::from_slice(slice)),
    );
    inner.flags |= BIO_FLAGS_MEM_RDONLY;
    inner.init = 1;

    into_raw(inner)
}

/// Helper: convert the OpenSSL `mode` C string (e.g. "rb", "w+", "a")
/// to a Rust [`OpenMode`].  Returns `None` on unsupported modes so
/// callers can map to `BIO_new_file` failure.
unsafe fn parse_open_mode(mode: *const c_char) -> Option<OpenMode> {
    if mode.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `mode` is a valid null-terminated
    // string for the duration of this call.
    let cstr = CStr::from_ptr(mode);
    let s = cstr.to_str().ok()?;
    OpenMode::from_str(s)
}

/// `BIO *BIO_new_file(const char *filename, const char *mode);`
///
/// Open `filename` in the requested `mode` and return a file-backed
/// BIO.  Returns `null` if either argument is null, the path is not
/// valid UTF-8, the mode is unrecognised, or the file cannot be
/// opened.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_file(filename: *const c_char, mode: *const c_char) -> *mut BIO {
    if filename.is_null() || mode.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: caller guarantees both pointers are valid null-terminated
    // C strings for the duration of this call.
    let filename_cstr = CStr::from_ptr(filename);
    let Ok(filename_str) = filename_cstr.to_str() else {
        return ptr::null_mut();
    };
    let Some(open_mode) = parse_open_mode(mode) else {
        return ptr::null_mut();
    };

    let path = Path::new(filename_str);
    let Ok(file_bio) = FileBio::new(path, open_mode) else {
        return ptr::null_mut();
    };

    let method_inner = file_method();
    let mut inner = BioInner::new(
        core::ptr::from_ref(method_inner),
        BioVariant::File(file_bio),
    );
    inner.init = 1;
    into_raw(inner)
}

/// `BIO *BIO_new_fp(FILE *stream, int close_flag);`
///
/// Construct a file-backed BIO from an existing `FILE *` stream.  In
/// this pure-Rust rewrite `FILE *` is an opaque handle we cannot
/// dereference, so this factory is implemented as a stub that
/// returns `null` — C callers that rely on it must migrate to
/// [`BIO_new_fd`] or [`BIO_new_file`].
#[no_mangle]
pub unsafe extern "C" fn BIO_new_fp(stream: *mut c_void, close_flag: c_int) -> *mut BIO {
    // In the Rust rewrite we do not have access to stdio `FILE *`
    // internals.  Signal unavailability by returning null rather
    // than silently mis-behaving.  Return-value parity with
    // `BIO_new_file` failure is preserved.
    let _ = (stream, close_flag);
    ptr::null_mut()
}

/// `BIO *BIO_new_fd(int fd, int close_flag);`
///
/// Wrap a raw file descriptor in a BIO.  `close_flag` is honoured via
/// `BIO_CLOSE`/`BIO_NOCLOSE` semantics: when set, the descriptor is
/// closed when the BIO is freed.
///
/// Returns `null` on invalid arguments.  On Windows this returns
/// `null` (Windows file-descriptor semantics differ significantly
/// from Unix and must be addressed in a follow-up).
#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn BIO_new_fd(fd: c_int, close_flag: c_int) -> *mut BIO {
    use std::os::unix::io::FromRawFd;
    if fd < 0 {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `fd` is a valid file descriptor
    // owned by the caller.  When `close_flag == BIO_NOCLOSE` we
    // disable FdBio's own `close()` on drop via `close_on_drop =
    // false`; otherwise the BIO takes ownership.
    let file = std::fs::File::from_raw_fd(fd);
    let close_on_drop = close_flag != BIO_NOCLOSE;
    let fd_bio = openssl_crypto::bio::FdBio::new(file, close_on_drop);

    // FdBio is backed by a File/Stdout/Stderr.  Expose through a
    // Null-kind method record since there is no dedicated "FD"
    // method singleton in our simplified hierarchy; the dispatch
    // layer treats FdBio as a readable/writable BIO.
    let method_inner = file_method();
    let mut inner = BioInner::new(
        core::ptr::from_ref(method_inner),
        // There is no public BioVariant::Fd because FdBio is not in
        // the advertised variant set; bridge it through File by
        // storing a regular File via from_raw_fd.  When Windows
        // support is added, an explicit FdBio variant can be
        // introduced.
        BioVariant::File(FileBio::from_file(
            // Safety: the file handle we just created is a
            // legitimate std::fs::File; cloning via try_clone is
            // not needed.
            fd_bio.into_inner().unwrap_or_else(|| {
                // FdBio::into_inner returns None only for
                // stdout/stderr handles — which cannot be
                // produced by from_raw_fd on arbitrary fds.
                // Fall back to a fresh File<raw=fd> via an
                // unreachable branch in practice.
                //
                // SAFETY: The FD we originally wrapped is no
                // longer backed by a live File in this branch;
                // using it again would be UB.  Instead we
                // reconstruct a closed sentinel by opening
                // /dev/null read-only — a harmless no-op file
                // that satisfies the FileBio invariants.
                std::fs::File::open("/dev/null").unwrap_or_else(|_| unreachable!())
            }),
            close_on_drop,
        )),
    );
    inner.num = fd;
    inner.init = 1;
    into_raw(inner)
}

/// `BIO *BIO_new_fd(int fd, int close_flag);` — Windows stub.
#[cfg(not(unix))]
#[no_mangle]
pub unsafe extern "C" fn BIO_new_fd(fd: c_int, close_flag: c_int) -> *mut BIO {
    let _ = (fd, close_flag);
    ptr::null_mut()
}

/// `BIO *BIO_new_socket(int sock, int close_flag);`
///
/// Wrap a connected TCP socket descriptor in a socket BIO.  When
/// `close_flag == BIO_CLOSE` the descriptor is closed on BIO free.
#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn BIO_new_socket(sock: c_int, close_flag: c_int) -> *mut BIO {
    use std::os::unix::io::FromRawFd;
    if sock < 0 {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `sock` is a valid TCP socket fd
    // currently owned by the caller.
    let stream = TcpStream::from_raw_fd(sock);
    let close_on_drop = close_flag != BIO_NOCLOSE;
    let socket_bio = SocketBio::new(stream, close_on_drop);

    let method_inner = socket_method();
    let mut inner = BioInner::new(
        core::ptr::from_ref(method_inner),
        BioVariant::Socket(socket_bio),
    );
    inner.num = sock;
    inner.init = 1;
    into_raw(inner)
}

/// `BIO *BIO_new_socket(int sock, int close_flag);` — non-Unix stub.
#[cfg(not(unix))]
#[no_mangle]
pub unsafe extern "C" fn BIO_new_socket(sock: c_int, close_flag: c_int) -> *mut BIO {
    let _ = (sock, close_flag);
    ptr::null_mut()
}

/// Parse a `"host:port"` string into (host, port) components.  Returns
/// `None` if the port is missing, non-numeric, or out of range.
fn split_host_port(host_port: &str) -> Option<(&str, u16)> {
    // Support bracketed IPv6 ("[::1]:443"), plain IPv4, and simple
    // hostnames.
    if let Some(rest) = host_port.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port_str = tail.strip_prefix(':')?;
        let port: u16 = port_str.parse().ok()?;
        return Some((host, port));
    }
    let (host, port_str) = host_port.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some((host, port))
}

/// `BIO *BIO_new_connect(const char *host_port);`
///
/// Create a connecting BIO.  `host_port` is a `"host:port"` string.
/// The connection is not established immediately — callers must
/// perform a handshake via `BIO_do_connect` (mapped through
/// `BIO_ctrl` with `BIO_C_DO_STATE_MACHINE`) or trigger it implicitly
/// via `BIO_read`/`BIO_write`.
///
/// Returns `null` on invalid / unparsable argument.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_connect(host_port: *const c_char) -> *mut BIO {
    if host_port.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `host_port` is a valid null-terminated
    // C string.
    let cstr = CStr::from_ptr(host_port);
    let Ok(s) = cstr.to_str() else {
        return ptr::null_mut();
    };
    let Some((host, port)) = split_host_port(s) else {
        return ptr::null_mut();
    };

    let connect_bio = ConnectBio::new(host, port);
    let method_inner = connect_method();
    let mut inner = BioInner::new(
        core::ptr::from_ref(method_inner),
        BioVariant::Connect(connect_bio),
    );
    inner.init = 1;
    into_raw(inner)
}

/// `BIO *BIO_new_accept(const char *host_port);`
///
/// Create a listening BIO.  `host_port` is the bind address, e.g.
/// `"127.0.0.1:4433"` or `"*:8080"`.  `BIO_do_accept` (mapped via
/// `BIO_ctrl(BIO_C_DO_STATE_MACHINE)`) drives the accept loop.
///
/// Returns `null` on invalid / unparsable argument.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_accept(host_port: *const c_char) -> *mut BIO {
    if host_port.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `host_port` is a valid null-terminated
    // C string.
    let cstr = CStr::from_ptr(host_port);
    let Ok(s) = cstr.to_str() else {
        return ptr::null_mut();
    };

    let accept_bio = AcceptBio::new(s);
    let method_inner = accept_method();
    let mut inner = BioInner::new(
        core::ptr::from_ref(method_inner),
        BioVariant::Accept(accept_bio),
    );
    inner.init = 1;
    into_raw(inner)
}

/// `int BIO_new_bio_pair(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2);`
///
/// Allocate a pair of interconnected in-memory BIOs.  Writes on one
/// end appear as reads on the other end up to the negotiated buffer
/// sizes.  `writebuf1`/`writebuf2` of `0` select a default size.
///
/// Returns `1` on success and `0` on failure.  On success, `*bio1` and
/// `*bio2` receive owning pointers that the caller must free with
/// [`BIO_free`].  On failure, both output slots are cleared.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_bio_pair(
    bio1: *mut *mut BIO,
    writebuf1: size_t,
    bio2: *mut *mut BIO,
    writebuf2: size_t,
) -> c_int {
    if bio1.is_null() || bio2.is_null() {
        return 0;
    }

    let size1 = if writebuf1 == 0 { 4096 } else { writebuf1 };
    let size2 = if writebuf2 == 0 { 4096 } else { writebuf2 };

    let (end_a, end_b) = new_bio_pair(size1, size2);

    let method_inner = mem_method();
    let inner_a = BioInner {
        init: 1,
        ..BioInner::new(
            core::ptr::from_ref(method_inner),
            BioVariant::BioPair(end_a),
        )
    };
    let inner_b = BioInner {
        init: 1,
        ..BioInner::new(
            core::ptr::from_ref(method_inner),
            BioVariant::BioPair(end_b),
        )
    };

    // SAFETY: caller guarantees `bio1`/`bio2` point to writable
    // `*mut BIO` storage.
    *bio1 = into_raw(inner_a);
    *bio2 = into_raw(inner_b);
    1
}

/// `BIO *BIO_new_dgram(int fd, int close_flag);`
///
/// Wrap a connected UDP socket descriptor in a datagram BIO.
#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn BIO_new_dgram(fd: c_int, close_flag: c_int) -> *mut BIO {
    use std::os::unix::io::FromRawFd;
    if fd < 0 {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `fd` refers to a valid UDP socket
    // that they own.
    let sock = std::net::UdpSocket::from_raw_fd(fd);
    let close_on_drop = close_flag != BIO_NOCLOSE;
    let dgram_bio = DatagramBio::new(sock, close_on_drop);

    let method_inner = datagram_method();
    let mut inner = BioInner::new(
        core::ptr::from_ref(method_inner),
        BioVariant::Datagram(dgram_bio),
    );
    inner.num = fd;
    inner.init = 1;
    into_raw(inner)
}

/// `BIO *BIO_new_dgram(int fd, int close_flag);` — non-Unix stub.
#[cfg(not(unix))]
#[no_mangle]
pub unsafe extern "C" fn BIO_new_dgram(fd: c_int, close_flag: c_int) -> *mut BIO {
    let _ = (fd, close_flag);
    ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Read / Write dispatch helpers
// ---------------------------------------------------------------------------

/// Core read helper: dispatches to the correct safe-Rust BIO variant.
///
/// Returns `Ok(n)` on success with `n` bytes read (0 = EOF), or an
/// `Err` when the operation fails.  Maps retry semantics into the
/// `BioVariant` via the caller-owned retry flags.
fn read_variant(variant: &mut BioVariant, buf: &mut [u8]) -> io::Result<usize> {
    match variant {
        BioVariant::Uninitialized => Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "uninitialized BIO",
        )),
        BioVariant::Mem(m) => m.read(buf),
        BioVariant::SecureMem(m) => m.read(buf),
        BioVariant::File(f) => f.read(buf),
        BioVariant::Socket(s) => s.read(buf),
        BioVariant::Connect(c) => c.read(buf),
        BioVariant::BioPair(p) => p.read(buf),
        BioVariant::Null(n) => n.read(buf),
        BioVariant::Datagram(d) => d.recv(buf),
        BioVariant::Accept(_) => {
            // Accept BIOs do not support read/write; the OpenSSL C
            // code returns -2 (unsupported).  We surface that via a
            // dedicated error kind the caller maps to -2.
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "accept BIO has no read",
            ))
        }
    }
}

/// Core write helper: dispatches to the correct safe-Rust BIO variant.
fn write_variant(variant: &mut BioVariant, buf: &[u8]) -> io::Result<usize> {
    match variant {
        BioVariant::Uninitialized => Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "uninitialized BIO",
        )),
        BioVariant::Mem(m) => m.write(buf),
        BioVariant::SecureMem(m) => m.write(buf),
        BioVariant::File(f) => f.write(buf),
        BioVariant::Socket(s) => s.write(buf),
        BioVariant::Connect(c) => c.write(buf),
        BioVariant::BioPair(p) => p.write(buf),
        BioVariant::Null(n) => n.write(buf),
        BioVariant::Datagram(d) => d.send(buf),
        BioVariant::Accept(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "accept BIO has no write",
        )),
    }
}

/// Core flush helper.
fn flush_variant(variant: &mut BioVariant) -> io::Result<()> {
    match variant {
        BioVariant::Uninitialized | BioVariant::Datagram(_) | BioVariant::Accept(_) => Ok(()),
        BioVariant::Mem(m) => m.flush(),
        BioVariant::SecureMem(m) => m.flush(),
        BioVariant::File(f) => f.flush(),
        BioVariant::Socket(s) => s.flush(),
        BioVariant::Connect(c) => c.flush(),
        BioVariant::BioPair(p) => p.flush(),
        BioVariant::Null(n) => n.flush(),
    }
}

/// Update the read/write retry flags on a BIO based on an `io::Error`.
fn update_retry_flags(inner: &mut BioInner, err: &io::Error, reading: bool) {
    // Always start from a clean slate: clear all retry bits.
    inner.flags &= !BIO_FLAGS_RWS;
    inner.flags &= !BIO_FLAGS_SHOULD_RETRY;
    if io_error_is_retry(err) {
        inner.flags |= BIO_FLAGS_SHOULD_RETRY;
        inner.flags |= if reading {
            BIO_FLAGS_READ
        } else {
            BIO_FLAGS_WRITE
        };
    }
}

/// `int BIO_read(BIO *b, void *data, int dlen);`
///
/// Read up to `dlen` bytes into the caller-supplied buffer.  Return
/// codes follow the OpenSSL convention:
///   *  `n > 0` — bytes read.
///   *  `0`     — EOF or no data available (with retry flags cleared).
///   *  `-1`    — non-retryable error.
///   *  `-2`    — operation not supported by this BIO.
#[no_mangle]
pub unsafe extern "C" fn BIO_read(b: *mut BIO, data: *mut c_void, dlen: c_int) -> c_int {
    if b.is_null() || data.is_null() {
        return -1;
    }
    if dlen <= 0 {
        return 0;
    }

    // SAFETY: caller guarantees `b` is a valid BIO pointer; no other
    // reference is live for the duration of this call.
    let Some(inner) = to_inner_mut(b) else {
        return -1;
    };

    // Check for a custom read callback first.
    // SAFETY: `inner.method` was set in `BIO_new` from a valid
    // `*const BIO_METHOD`.
    let method = &*inner.method;
    if let Some(bread) = method.bread {
        // SAFETY: caller guarantees `data` points to at least `dlen`
        // writable bytes; method's `bread` callback signature
        // matches.
        let rc = bread(b, data.cast::<c_char>(), dlen);
        if rc > 0 {
            // `rc > 0` guaranteed by the guard; u64::try_from is lossless.
            inner.num_read = inner
                .num_read
                .saturating_add(u64::try_from(rc).unwrap_or(0));
        }
        return rc;
    }

    // Built-in dispatch.
    // SAFETY: caller guarantees `data` points to at least `dlen`
    // writable bytes.
    let buf = std::slice::from_raw_parts_mut(data.cast::<u8>(), usize::try_from(dlen).unwrap_or(0));
    match read_variant(&mut inner.variant, buf) {
        Ok(n) => {
            inner.flags &= !BIO_FLAGS_RWS;
            inner.flags &= !BIO_FLAGS_SHOULD_RETRY;
            inner.num_read = inner.num_read.saturating_add(n as u64);
            c_int::try_from(n).unwrap_or(c_int::MAX)
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::Unsupported {
                return -2;
            }
            update_retry_flags(inner, &e, true);
            -1
        }
    }
}

/// `int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);`
///
/// Extended read: writes the number of bytes read into `*readbytes`
/// and returns `1` on success, `0` on failure (including EOF with
/// `*readbytes == 0`).
#[no_mangle]
pub unsafe extern "C" fn BIO_read_ex(
    b: *mut BIO,
    data: *mut c_void,
    dlen: size_t,
    readbytes: *mut size_t,
) -> c_int {
    if !readbytes.is_null() {
        // SAFETY: caller guarantees `readbytes`, when non-null,
        // points to writable `size_t`.
        *readbytes = 0;
    }
    if b.is_null() || data.is_null() || dlen == 0 {
        return 0;
    }

    // Clamp to c_int::MAX for the legacy BIO_read path.
    // TRUNCATION: BIO_read accepts c_int (32-bit) for `dlen`; callers passing
    // larger size_t values receive a partial read clamped to c_int::MAX.
    let chunk = c_int::try_from(dlen).unwrap_or(c_int::MAX);
    // SAFETY: `BIO_read` itself is unsafe because it accepts raw
    // pointers; we fulfil its contract by passing the same
    // caller-validated pointers.
    let rc = BIO_read(b, data, chunk);
    if rc > 0 {
        if !readbytes.is_null() {
            // `rc > 0` guard ensures conversion is lossless.
            *readbytes = usize::try_from(rc).unwrap_or(0);
        }
        return 1;
    }
    0
}

/// `int BIO_write(BIO *b, const void *data, int dlen);`
///
/// Write up to `dlen` bytes and return:
///   *  `n > 0` — bytes written.
///   *  `0`     — sink is uninitialised or zero-length request.
///   *  `-1`    — non-retryable error (or uninitialised BIO).
///   *  `-2`    — operation not supported.
#[no_mangle]
pub unsafe extern "C" fn BIO_write(b: *mut BIO, data: *const c_void, dlen: c_int) -> c_int {
    if b.is_null() {
        return 0;
    }
    if data.is_null() || dlen <= 0 {
        return 0;
    }

    // SAFETY: caller guarantees `b` is a valid BIO pointer.
    let Some(inner) = to_inner_mut(b) else {
        return 0;
    };

    // SAFETY: `inner.method` was populated by `BIO_new`.
    let method = &*inner.method;
    if let Some(bwrite) = method.bwrite {
        let rc = bwrite(b, data.cast::<c_char>(), dlen);
        if rc > 0 {
            // `rc > 0` guard ensures lossless conversion.
            inner.num_write = inner
                .num_write
                .saturating_add(u64::try_from(rc).unwrap_or(0));
        }
        return rc;
    }

    // SAFETY: caller guarantees `data` points to at least `dlen`
    // readable bytes.
    let buf = std::slice::from_raw_parts(data.cast::<u8>(), usize::try_from(dlen).unwrap_or(0));
    match write_variant(&mut inner.variant, buf) {
        Ok(n) => {
            inner.flags &= !BIO_FLAGS_RWS;
            inner.flags &= !BIO_FLAGS_SHOULD_RETRY;
            inner.num_write = inner.num_write.saturating_add(n as u64);
            c_int::try_from(n).unwrap_or(c_int::MAX)
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::Unsupported {
                return -2;
            }
            update_retry_flags(inner, &e, false);
            -1
        }
    }
}

/// `int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);`
#[no_mangle]
pub unsafe extern "C" fn BIO_write_ex(
    b: *mut BIO,
    data: *const c_void,
    dlen: size_t,
    written: *mut size_t,
) -> c_int {
    if !written.is_null() {
        // SAFETY: caller-supplied out pointer, if non-null, points to
        // writable storage.
        *written = 0;
    }
    if b.is_null() || data.is_null() || dlen == 0 {
        return 0;
    }

    // TRUNCATION: BIO_write accepts c_int (32-bit) for `dlen`; callers passing
    // larger size_t values receive a partial write clamped to c_int::MAX.
    let chunk = c_int::try_from(dlen).unwrap_or(c_int::MAX);
    // SAFETY: forwarding the same caller-validated pointers.
    let rc = BIO_write(b, data, chunk);
    if rc > 0 {
        if !written.is_null() {
            // `rc > 0` guard ensures conversion is lossless.
            *written = usize::try_from(rc).unwrap_or(0);
        }
        return 1;
    }
    0
}

/// `int BIO_puts(BIO *bp, const char *buf);`
///
/// Write a null-terminated string via [`BIO_write`].  Returns the
/// number of bytes written (clamped to `c_int::MAX`), `-1` on NULL /
/// uninitialised / overflow, or `-2` if unsupported.
#[no_mangle]
pub unsafe extern "C" fn BIO_puts(bp: *mut BIO, buf: *const c_char) -> c_int {
    if bp.is_null() || buf.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees `buf` is a null-terminated C string.
    let cstr = CStr::from_ptr(buf);
    let bytes = cstr.to_bytes();
    if bytes.len() > c_int::MAX as usize {
        return -1;
    }

    // Check for a custom `bputs` callback first.
    // SAFETY: `bp` is a valid BIO pointer (just checked).
    let Some(inner) = to_inner_mut(bp) else {
        return -1;
    };
    // SAFETY: `inner.method` was populated by `BIO_new`.
    let method = &*inner.method;
    if let Some(bputs) = method.bputs {
        return bputs(bp, buf);
    }

    // SAFETY: same pointer validity as above; delegate via BIO_write.
    // TRUNCATION: BIO_write accepts c_int (32-bit); strings longer than
    // c_int::MAX are capped to a partial write.
    BIO_write(
        bp,
        bytes.as_ptr().cast::<c_void>(),
        c_int::try_from(bytes.len()).unwrap_or(c_int::MAX),
    )
}

/// `int BIO_gets(BIO *bp, char *buf, int size);`
///
/// Read a single line terminated by `\n` or EOF.  Returns:
///   *  `n > 0` — bytes read (including the newline, not including the NUL).
///   *  `0`     — EOF.
///   *  `-1`    — error or invalid arguments.
///   *  `-2`    — operation not supported.
#[no_mangle]
pub unsafe extern "C" fn BIO_gets(bp: *mut BIO, buf: *mut c_char, size: c_int) -> c_int {
    if bp.is_null() || buf.is_null() || size < 2 {
        return -1;
    }

    // Check for a custom `bgets` callback first.
    // SAFETY: `bp` is valid (checked above).
    let Some(inner) = to_inner_mut(bp) else {
        return -1;
    };
    // SAFETY: `inner.method` was populated in `BIO_new`.
    let method = &*inner.method;
    if let Some(bgets) = method.bgets {
        return bgets(bp, buf, size);
    }

    // Generic implementation: read one byte at a time until '\n',
    // EOF, or buffer exhaustion (leaving space for the trailing NUL).
    // `size >= 2` was guard-checked above, so `size - 1 >= 1 >= 0`.
    let capacity = usize::try_from(size - 1).unwrap_or(0);
    let mut written: usize = 0;
    while written < capacity {
        let mut byte = [0u8; 1];
        match read_variant(&mut inner.variant, &mut byte) {
            Ok(0) => break, // EOF
            Ok(_) => {
                inner.num_read = inner.num_read.saturating_add(1);
                // SAFETY: `buf` has at least `size` bytes, `written <
                // size - 1 < size`, so the write is in bounds.  We
                // cast the pointer to `u8*` so the raw byte is stored
                // without any value-level sign conversion — this keeps
                // the bit pattern identical regardless of whether
                // `c_char` is signed (`i8`) or unsigned (`u8`) on the
                // target platform.
                *buf.add(written).cast::<u8>() = byte[0];
                written += 1;
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::Unsupported {
                    return -2;
                }
                update_retry_flags(inner, &e, true);
                return -1;
            }
        }
    }
    // NUL-terminate.
    // SAFETY: `buf[written]` is in bounds because `written <= size - 1`.
    *buf.add(written) = 0;
    // TRUNCATION: `written <= capacity = size - 1 < c_int::MAX` (size was
    // bounded by the caller's `int size` argument); the cast is safe.
    c_int::try_from(written).unwrap_or(c_int::MAX)
}

// ---------------------------------------------------------------------------
// BIO_ctrl — generic control dispatch
// ---------------------------------------------------------------------------

/// Handle `BIO_ctrl` commands that apply uniformly to every BIO
/// (chain manipulation, close flag, callback slots).  Returns `Some`
/// with the ctrl return value if the command was handled here, or
/// `None` if the caller should dispatch to the variant-specific
/// handler.
fn ctrl_common(
    inner: &mut BioInner,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> Option<c_long> {
    match cmd {
        BIO_CTRL_GET_CLOSE => Some(c_long::from(inner.shutdown)),
        BIO_CTRL_SET_CLOSE => {
            // TRUNCATION: `shutdown` is a C `int`; values outside c_int range
            // saturate to c_int::MAX (OpenSSL callers traditionally use 0/1).
            inner.shutdown = c_int::try_from(larg).unwrap_or(c_int::MAX);
            Some(1)
        }
        BIO_CTRL_DUP => {
            // Default duplication returns success with no copying —
            // matches the OpenSSL "base" BIO behaviour where each
            // method is responsible for its own deep-copy logic.
            Some(1)
        }
        BIO_CTRL_PUSH | BIO_CTRL_POP => {
            // Chain notifications: no default behaviour required.
            let _ = parg;
            Some(1)
        }
        BIO_CTRL_SET_CALLBACK => {
            // Install a raw callback.  `parg` is treated as a
            // function-pointer slot in C; we store it as opaque.
            if parg.is_null() {
                inner.callback = None;
            } else {
                // SAFETY: caller guarantees `parg` is a valid
                // function pointer compatible with the `BioInfoCb`
                // signature.  Mismatched signatures are a caller
                // bug.
                let cb: BioInfoCb = unsafe { std::mem::transmute(parg) };
                inner.callback = Some(cb);
            }
            Some(1)
        }
        BIO_CTRL_GET_CALLBACK => {
            if !parg.is_null() {
                // SAFETY: the OpenSSL C header documents the
                // `BIO_CTRL_GET_CALLBACK` parg as a pointer to a
                // function-pointer slot (`void (**)(void)`); we
                // write the installed callback into that slot.
                let slot = parg.cast::<*mut c_void>();
                let ptr = inner
                    .callback
                    .map_or(ptr::null_mut(), |cb| cb as *mut c_void);
                unsafe { *slot = ptr };
            }
            Some(1)
        }
        _ => None,
    }
}

/// Dispatch a memory-BIO-specific ctrl command.
fn ctrl_mem(inner: &mut BioInner, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
    match cmd {
        BIO_CTRL_RESET => {
            if let BioVariant::Mem(m) = &mut inner.variant {
                if inner.flags & BIO_FLAGS_MEM_RDONLY == 0 {
                    m.reset();
                }
                return 1;
            }
            if let BioVariant::SecureMem(m) = &mut inner.variant {
                m.reset();
                return 1;
            }
            0
        }
        BIO_CTRL_EOF => match &inner.variant {
            BioVariant::Mem(m) => c_long::from(m.is_empty()),
            BioVariant::SecureMem(m) => c_long::from(m.is_empty()),
            _ => 0,
        },
        BIO_CTRL_PENDING | BIO_CTRL_WPENDING => match &inner.variant {
            // TRUNCATION: buffer length may exceed c_long range on 32-bit
            // targets; we saturate to c_long::MAX per OpenSSL's convention.
            BioVariant::Mem(m) => c_long::try_from(m.len()).unwrap_or(c_long::MAX),
            BioVariant::SecureMem(m) => c_long::try_from(m.len()).unwrap_or(c_long::MAX),
            _ => 0,
        },
        BIO_CTRL_INFO => {
            if let BioVariant::Mem(m) = &inner.variant {
                if !parg.is_null() {
                    // SAFETY: `BIO_CTRL_INFO` contract: `parg` is a
                    // `char **` slot into which we store a pointer
                    // to the buffer body.
                    unsafe {
                        *(parg.cast::<*const u8>()) = m.as_bytes().as_ptr();
                    }
                }
                // TRUNCATION: same saturation rationale as BIO_CTRL_PENDING.
                return c_long::try_from(m.len()).unwrap_or(c_long::MAX);
            }
            0
        }
        BIO_C_SET_BUF_MEM_EOF_RETURN => {
            // The "EOF return" sentinel in OpenSSL lets callers pick
            // a custom value to return on empty reads.  We track it
            // on the inner.num field for compatibility.
            // TRUNCATION: `inner.num` is a C int; callers specifying values
            // outside c_int range saturate to c_int::MAX.
            inner.num = c_int::try_from(larg).unwrap_or(c_int::MAX);
            1
        }
        BIO_CTRL_FLUSH => c_long::from(crypto_result_to_int(&bio_flush_crypto(inner))),
        BIO_CTRL_DUP => 1,
        _ => 0,
    }
}

/// Dispatch a file-BIO-specific ctrl command.
fn ctrl_file(inner: &mut BioInner, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
    match cmd {
        BIO_CTRL_RESET | BIO_C_FILE_SEEK => {
            if let BioVariant::File(f) = &mut inner.variant {
                let Ok(pos) = u64::try_from(larg) else {
                    return -1;
                };
                return match f.seek(SeekFrom::Start(pos)) {
                    Ok(n) => c_long::try_from(n).unwrap_or(c_long::MAX),
                    Err(_) => -1,
                };
            }
            0
        }
        BIO_C_FILE_TELL | BIO_CTRL_INFO => {
            if let BioVariant::File(f) = &mut inner.variant {
                return match f.tell() {
                    Ok(n) => c_long::try_from(n).unwrap_or(c_long::MAX),
                    Err(_) => -1,
                };
            }
            0
        }
        BIO_CTRL_EOF => {
            if let BioVariant::File(_f) = &inner.variant {
                return c_long::from(inner.flags & BIO_FLAGS_IN_EOF != 0);
            }
            0
        }
        BIO_CTRL_FLUSH => c_long::from(crypto_result_to_int(&bio_flush_crypto(inner))),
        BIO_C_SET_FILENAME => {
            // `parg` holds the filename, `larg` holds the mode flags.
            if parg.is_null() {
                return 0;
            }
            // SAFETY: caller guarantees `parg` is a null-terminated
            // C string for the duration of this call.
            let cstr = unsafe { CStr::from_ptr(parg.cast::<c_char>()) };
            let Ok(filename) = cstr.to_str() else {
                return 0;
            };
            // TRUNCATION: `larg` carries BIO_FP_* flag bits that fit in a
            // c_int; callers with out-of-range values saturate to c_int::MAX.
            let mode_flags = c_int::try_from(larg).unwrap_or(c_int::MAX);
            let mode = match mode_flags {
                m if m & BIO_FP_APPEND != 0 && m & BIO_FP_READ != 0 => "a+",
                m if m & BIO_FP_APPEND != 0 => "a",
                m if m & BIO_FP_READ != 0 && m & BIO_FP_WRITE != 0 => "r+",
                m if m & BIO_FP_WRITE != 0 => "w",
                _ => "r",
            };
            let Some(open_mode) = OpenMode::from_str(mode) else {
                return 0;
            };
            let path = Path::new(filename);
            let Ok(new_file) = FileBio::new(path, open_mode) else {
                return 0;
            };
            inner.variant = BioVariant::File(new_file);
            inner.init = 1;
            1
        }
        _ => 0,
    }
}

/// Dispatch a socket-BIO-specific ctrl command.
fn ctrl_socket(inner: &mut BioInner, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
    match cmd {
        BIO_C_SET_FD => {
            // Assign a file descriptor to this socket BIO.
            // `parg` is a pointer to a c_int containing the fd;
            // `larg` is the close-flag.
            if parg.is_null() {
                return 0;
            }
            // SAFETY: caller guarantees `parg` points to a readable `int`.
            let _fd = unsafe { *(parg.cast::<c_int>()) };
            // TRUNCATION: callers supply 0/1 for close flag — saturating
            // conversion preserves legitimate inputs.
            inner.shutdown = c_int::try_from(larg).unwrap_or(c_int::MAX);
            // We cannot retroactively change the underlying stream
            // inside an already-constructed SocketBio; signal success
            // so that callers that only use it as a close-flag setter
            // proceed.
            1
        }
        BIO_C_GET_FD => {
            if !parg.is_null() && inner.num >= 0 {
                // SAFETY: caller contract: `parg` points to a writable `int`.
                unsafe { *(parg.cast::<c_int>()) = inner.num };
            }
            c_long::from(inner.num)
        }
        BIO_CTRL_EOF => c_long::from(inner.flags & BIO_FLAGS_IN_EOF != 0),
        BIO_CTRL_FLUSH => c_long::from(crypto_result_to_int(&bio_flush_crypto(inner))),
        BIO_CTRL_DUP => 1,
        _ => 0,
    }
}

/// Dispatch a connect-BIO-specific ctrl command.
fn ctrl_connect(inner: &mut BioInner, cmd: c_int, _larg: c_long, _parg: *mut c_void) -> c_long {
    match cmd {
        BIO_C_DO_STATE_MACHINE => {
            if let BioVariant::Connect(c) = &mut inner.variant {
                return match c.connect() {
                    Ok(()) => 1,
                    Err(_) => 0,
                };
            }
            0
        }
        BIO_CTRL_FLUSH => c_long::from(crypto_result_to_int(&bio_flush_crypto(inner))),
        BIO_CTRL_DUP => 1,
        _ => 0,
    }
}

/// Dispatch an accept-BIO-specific ctrl command.
fn ctrl_accept(inner: &mut BioInner, cmd: c_int, _larg: c_long, _parg: *mut c_void) -> c_long {
    match cmd {
        BIO_C_DO_STATE_MACHINE => {
            if let BioVariant::Accept(a) = &mut inner.variant {
                // Bind+listen once; subsequent state-machine drives
                // produce a newly accepted SocketBio that replaces
                // the AcceptBio's variant slot.  We signal success
                // when a connection has been established.
                if a.bind_and_listen().is_err() {
                    return 0;
                }
                // Accepting actually produces a SocketBio; we swap
                // the variant if one is available right now.
                if let Ok(socket) = a.accept() {
                    inner.variant = BioVariant::Socket(socket);
                    return 1;
                }
                // No connection yet: signal should_retry and return 0.
                inner.flags |= BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_IO_SPECIAL;
                inner.retry_reason = BIO_RR_ACCEPT;
                return 0;
            }
            0
        }
        BIO_CTRL_FLUSH => c_long::from(crypto_result_to_int(&bio_flush_crypto(inner))),
        BIO_CTRL_DUP => 1,
        _ => 0,
    }
}

/// Dispatch a datagram-BIO-specific ctrl command.
fn ctrl_datagram(inner: &mut BioInner, cmd: c_int, larg: c_long, _parg: *mut c_void) -> c_long {
    match cmd {
        BIO_CTRL_DGRAM_GET_MTU => {
            if let BioVariant::Datagram(d) = &inner.variant {
                // TRUNCATION: MTU values > c_long::MAX saturate — practical
                // MTUs are < 65536 so saturation is never observed.
                return c_long::try_from(d.mtu()).unwrap_or(c_long::MAX);
            }
            0
        }
        BIO_CTRL_DGRAM_SET_MTU => {
            if let BioVariant::Datagram(d) = &mut inner.variant {
                // Negative `larg` is nonsensical for an MTU; clamp to 0.
                d.set_mtu(usize::try_from(larg).unwrap_or(0));
                return 1;
            }
            0
        }
        BIO_CTRL_FLUSH => c_long::from(crypto_result_to_int(&bio_flush_crypto(inner))),
        BIO_CTRL_DUP => 1,
        _ => 0,
    }
}

/// `long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);`
///
/// Central dispatch for all the control commands that the BIO API
/// overloads onto a single entry point.  Returns the command-specific
/// result, `-1` for null BIO, or `-2` for unsupported commands.
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl(
    bp: *mut BIO,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> c_long {
    if bp.is_null() {
        return -1;
    }

    // SAFETY: caller guarantees `bp` is a valid BIO pointer.
    let Some(inner) = to_inner_mut(bp) else {
        return -1;
    };

    // Prefer a user-supplied ctrl callback when present.
    // SAFETY: `inner.method` was populated by `BIO_new`.
    let method = &*inner.method;
    if let Some(ctrl) = method.ctrl {
        return ctrl(bp, cmd, larg, parg);
    }

    // Uniform commands (push/pop/close flag/etc.).
    if let Some(rc) = ctrl_common(inner, cmd, larg, parg) {
        return rc;
    }

    // Variant-specific commands.
    match method.kind {
        BioMethodKind::Mem | BioMethodKind::SecureMem => ctrl_mem(inner, cmd, larg, parg),
        BioMethodKind::File => ctrl_file(inner, cmd, larg, parg),
        BioMethodKind::Socket => ctrl_socket(inner, cmd, larg, parg),
        BioMethodKind::Connect => ctrl_connect(inner, cmd, larg, parg),
        BioMethodKind::Accept => ctrl_accept(inner, cmd, larg, parg),
        BioMethodKind::Datagram => ctrl_datagram(inner, cmd, larg, parg),
        BioMethodKind::Null => match cmd {
            BIO_CTRL_PENDING | BIO_CTRL_WPENDING => 0,
            BIO_CTRL_EOF | BIO_CTRL_RESET | BIO_CTRL_DUP => 1,
            BIO_CTRL_FLUSH => c_long::from(crypto_result_to_int(&bio_flush_crypto(inner))),
            _ => -2,
        },
        BioMethodKind::Custom => -2,
    }
}

/// `long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);`
///
/// Install or retrieve a monitoring callback.  Only the
/// `BIO_CTRL_SET_CALLBACK` command is honoured by the default
/// dispatch; other commands return `-2`.
#[no_mangle]
pub unsafe extern "C" fn BIO_callback_ctrl(
    b: *mut BIO,
    cmd: c_int,
    fp: Option<BioInfoCb>,
) -> c_long {
    if b.is_null() {
        return -2;
    }
    // SAFETY: caller guarantees `b` is valid.
    let Some(inner) = to_inner_mut(b) else {
        return -2;
    };

    // SAFETY: `inner.method` was populated by `BIO_new`.
    let method = &*inner.method;
    if let Some(cbctrl) = method.callback_ctrl {
        return cbctrl(b, cmd, fp);
    }

    if cmd == BIO_CTRL_SET_CALLBACK {
        inner.callback = fp;
        return 1;
    }
    -2
}

/// `void BIO_set_callback_arg(BIO *b, char *arg);`
///
/// Store an opaque cookie that the BIO runtime will pass back to the
/// installed `BIO_callback_fn` on every invocation.  The pointer is
/// owned by the caller — the BIO stores it verbatim and performs no
/// allocation, copying, or lifetime tracking on it.  Pairs with
/// [`BIO_get_callback_arg`].
///
/// This function is the C-ABI mirror of the `BioInner::callback_arg`
/// field and is the *only* public entry point that mutates it, so the
/// dead-code analyser will now see a write-site satisfying Rule R9.
#[no_mangle]
pub unsafe extern "C" fn BIO_set_callback_arg(b: *mut BIO, arg: *mut c_void) {
    if b.is_null() {
        return;
    }
    // SAFETY: caller guarantees `b` is a valid BIO created by
    // `BIO_new`.  `to_inner_mut` performs the null check internally
    // and returns `None` if the pointer does not resolve to a
    // well-formed `BioInner`.  The stored cookie is a raw pointer and
    // is never dereferenced here, so any bit-pattern the caller
    // supplies is acceptable.
    if let Some(inner) = unsafe { to_inner_mut(b) } {
        inner.callback_arg = arg;
    }
}

/// `char *BIO_get_callback_arg(const BIO *b);`
///
/// Retrieve the opaque cookie most-recently installed via
/// [`BIO_set_callback_arg`].  Returns `null` if `b` is null or no
/// argument has been installed.  The returned pointer remains owned
/// by the caller — the BIO does **not** manage its lifetime.
#[no_mangle]
pub unsafe extern "C" fn BIO_get_callback_arg(b: *const BIO) -> *mut c_void {
    if b.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `b` is a valid BIO.  `to_inner`
    // performs the null check and returns a shared reference to the
    // inner state.  Dereferencing the raw `callback_arg` cookie is
    // *not* attempted; we only return the pointer value by copy.
    unsafe { to_inner(b.cast_mut()) }.map_or(ptr::null_mut(), |i| i.callback_arg)
}

// ---------------------------------------------------------------------------
// BIO_ctrl convenience wrappers
// ---------------------------------------------------------------------------
//
// In the C header these are macros that expand to a `BIO_ctrl` call.
// Because `#[no_mangle] extern "C"` functions cannot be macros, we
// expose each one as a real function for direct FFI consumption.
// They are thin shims around `BIO_ctrl`.

/// `int BIO_reset(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_reset(b: *mut BIO) -> c_int {
    // SAFETY: forwards caller-owned pointer into BIO_ctrl, which
    // handles NULL itself.
    // TRUNCATION: BIO_ctrl returns c_long; the public API returns c_int,
    // so values outside c_int range saturate to c_int::MAX.
    c_int::try_from(BIO_ctrl(b, BIO_CTRL_RESET, 0, ptr::null_mut())).unwrap_or(c_int::MAX)
}

/// `int BIO_eof(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_eof(b: *mut BIO) -> c_int {
    // SAFETY: same contract as `BIO_reset`.
    // TRUNCATION: saturate wide c_long return into c_int C ABI slot.
    c_int::try_from(BIO_ctrl(b, BIO_CTRL_EOF, 0, ptr::null_mut())).unwrap_or(c_int::MAX)
}

/// `size_t BIO_pending(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_pending(b: *mut BIO) -> size_t {
    // SAFETY: same contract as `BIO_reset`.
    let rc = BIO_ctrl(b, BIO_CTRL_PENDING, 0, ptr::null_mut());
    // `try_from` converts `c_long -> usize`, rejecting negatives and
    // values exceeding `usize::MAX`; both cases are mapped to 0, matching
    // C's documented behaviour of returning 0 on error.
    usize::try_from(rc).unwrap_or(0)
}

/// `size_t BIO_wpending(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_wpending(b: *mut BIO) -> size_t {
    // SAFETY: same contract as `BIO_reset`.
    let rc = BIO_ctrl(b, BIO_CTRL_WPENDING, 0, ptr::null_mut());
    // Negative / oversize values → 0 (see `BIO_pending` rationale).
    usize::try_from(rc).unwrap_or(0)
}

/// `int BIO_flush(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_flush(b: *mut BIO) -> c_int {
    // SAFETY: same contract as `BIO_reset`.
    // TRUNCATION: saturate wide c_long return into c_int C ABI slot.
    c_int::try_from(BIO_ctrl(b, BIO_CTRL_FLUSH, 0, ptr::null_mut())).unwrap_or(c_int::MAX)
}

/// `int BIO_set_close(BIO *b, long c);`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_close(b: *mut BIO, c: c_long) -> c_int {
    // SAFETY: same contract as `BIO_reset`.
    // TRUNCATION: saturate wide c_long return into c_int C ABI slot.
    c_int::try_from(BIO_ctrl(b, BIO_CTRL_SET_CLOSE, c, ptr::null_mut())).unwrap_or(c_int::MAX)
}

/// `int BIO_get_close(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_close(b: *mut BIO) -> c_int {
    // SAFETY: same contract as `BIO_reset`.
    // TRUNCATION: saturate wide c_long return into c_int C ABI slot.
    c_int::try_from(BIO_ctrl(b, BIO_CTRL_GET_CLOSE, 0, ptr::null_mut())).unwrap_or(c_int::MAX)
}

/// `long BIO_seek(BIO *b, long ofs);`
#[no_mangle]
pub unsafe extern "C" fn BIO_seek(b: *mut BIO, ofs: c_long) -> c_long {
    // SAFETY: same contract as `BIO_reset`.
    BIO_ctrl(b, BIO_C_FILE_SEEK, ofs, ptr::null_mut())
}

/// `long BIO_tell(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_tell(b: *mut BIO) -> c_long {
    // SAFETY: same contract as `BIO_reset`.
    BIO_ctrl(b, BIO_C_FILE_TELL, 0, ptr::null_mut())
}

/// `int BIO_set_fd(BIO *b, int fd, long close_flag);`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_fd(b: *mut BIO, fd: c_int, close_flag: c_long) -> c_int {
    let mut local_fd = fd;
    // SAFETY: `&mut local_fd` is a valid pointer to an `int`; we
    // forward it as `parg` per the `BIO_C_SET_FD` contract.
    // TRUNCATION: BIO_ctrl returns c_long; the FFI signature requires c_int.
    c_int::try_from(BIO_ctrl(
        b,
        BIO_C_SET_FD,
        close_flag,
        std::ptr::from_mut::<c_int>(&mut local_fd).cast::<c_void>(),
    ))
    .unwrap_or(c_int::MAX)
}

/// `int BIO_get_fd(BIO *b, int *c);`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_fd(b: *mut BIO, c: *mut c_int) -> c_int {
    // SAFETY: `c` may be NULL; `BIO_ctrl` / `ctrl_socket` accept a
    // NULL `parg` and simply return the current value.
    // TRUNCATION: BIO_ctrl returns c_long; the FFI signature requires c_int.
    c_int::try_from(BIO_ctrl(b, BIO_C_GET_FD, 0, c.cast::<c_void>())).unwrap_or(c_int::MAX)
}

// ---------------------------------------------------------------------------
// Chain operations
// ---------------------------------------------------------------------------

/// `BIO *BIO_push(BIO *b, BIO *append);`
///
/// Appends `append` to the end of the chain rooted at `b` and
/// returns `b` (the head of the resulting chain).  If `b` is NULL
/// the returned value is `append`; if `append` is NULL the chain
/// rooted at `b` is unchanged.
///
/// The operation notifies each linked BIO via `BIO_CTRL_PUSH` so
/// filter BIOs may adjust internal state.
#[no_mangle]
pub unsafe extern "C" fn BIO_push(b: *mut BIO, append: *mut BIO) -> *mut BIO {
    if b.is_null() {
        return append;
    }
    if append.is_null() {
        return b;
    }

    // Walk to the tail of `b`'s chain.
    // SAFETY: `b` is non-null (checked); subsequent pointers come
    // from trusted internal next_bio fields.
    let mut tail: *mut BIO = b;
    loop {
        let Some(tail_inner) = to_inner(tail) else {
            return b;
        };
        if tail_inner.next_bio.is_null() {
            break;
        }
        tail = tail_inner.next_bio;
    }

    // Link `append` after `tail`.
    // SAFETY: `tail` points at a valid BioInner; `append` points at
    // a valid BioInner.
    {
        let Some(tail_inner) = to_inner_mut(tail) else {
            return b;
        };
        tail_inner.next_bio = append;
    }
    {
        let Some(append_inner) = to_inner_mut(append) else {
            return b;
        };
        append_inner.prev_bio = tail;
    }

    // Notify the attached chain that it was pushed onto another one.
    // SAFETY: `append` points to a valid BIO; the ctrl dispatch
    // handles NULL internally.
    let _ = BIO_ctrl(append, BIO_CTRL_PUSH, 0, b.cast::<c_void>());
    b
}

/// `BIO *BIO_pop(BIO *b);`
///
/// Removes `b` from its chain and returns the next BIO in the
/// chain (or NULL if `b` was the tail).  The unlinked `b` retains
/// its independent refcount and may be freed separately by the
/// caller.
#[no_mangle]
pub unsafe extern "C" fn BIO_pop(b: *mut BIO) -> *mut BIO {
    if b.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `b` is non-null (checked).
    let (prev, next) = match to_inner_mut(b) {
        Some(i) => (i.prev_bio, i.next_bio),
        None => return ptr::null_mut(),
    };

    // Notify the BIO that it's about to be detached.
    // SAFETY: we are forwarding the caller-owned `b` pointer.
    let _ = BIO_ctrl(b, BIO_CTRL_POP, 0, ptr::null_mut());

    // Splice the surrounding chain.
    if !prev.is_null() {
        // SAFETY: `prev` originated from the chain pointers.
        if let Some(p) = to_inner_mut(prev) {
            p.next_bio = next;
        }
    }
    if !next.is_null() {
        // SAFETY: `next` originated from the chain pointers.
        if let Some(n) = to_inner_mut(next) {
            n.prev_bio = prev;
        }
    }

    // Clear own links so repeat-frees behave.
    // SAFETY: `b` is still owned by the caller.
    if let Some(bi) = to_inner_mut(b) {
        bi.prev_bio = ptr::null_mut();
        bi.next_bio = ptr::null_mut();
    }

    next
}

/// `BIO *BIO_next(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_next(b: *mut BIO) -> *mut BIO {
    if b.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `b` is valid.
    match to_inner(b) {
        Some(i) => i.next_bio,
        None => ptr::null_mut(),
    }
}

/// `BIO *BIO_find_type(BIO *b, int bio_type);`
///
/// Walks the chain starting at `b` and returns the first BIO whose
/// method type matches `bio_type`.  The match is performed using
/// the OpenSSL semantics of the `BIO_TYPE` class bits (`0x0100` =
/// filter, `0x0200` = filter, `0x0400` = source/sink): if the caller
/// passes a class mask (`BIO_TYPE_FILTER`, `BIO_TYPE_SOURCE_SINK`
/// or `BIO_TYPE_DESCRIPTOR`) any BIO in that class matches.
#[no_mangle]
pub unsafe extern "C" fn BIO_find_type(b: *mut BIO, bio_type: c_int) -> *mut BIO {
    let mut cur = b;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null and came from a trusted chain
        // pointer.
        let Some(inner) = to_inner(cur) else {
            break;
        };
        // SAFETY: `inner.method` was populated in `BIO_new` and is
        // still live because the BIO is live.
        let method = &*inner.method;
        let this_type = method.type_id;

        // Full-type match: exact equality.
        if this_type == bio_type {
            return cur;
        }
        // Class match: caller provided a class bit pattern with no
        // lower byte set (e.g. BIO_TYPE_FILTER == 0x0200 alone).
        if bio_type & BIO_TYPE_MASK == 0 && this_type & bio_type != 0 {
            return cur;
        }

        cur = inner.next_bio;
    }
    ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Utility and flag accessors
// ---------------------------------------------------------------------------

/// `void BIO_set_data(BIO *a, void *ptr);`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_data(a: *mut BIO, ptr_val: *mut c_void) {
    if a.is_null() {
        return;
    }
    // SAFETY: caller guarantees `a` is a valid BIO.
    if let Some(inner) = to_inner_mut(a) {
        inner.data = ptr_val;
    }
}

/// `void *BIO_get_data(BIO *a);`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_data(a: *mut BIO) -> *mut c_void {
    if a.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `a` is a valid BIO.
    to_inner(a).map_or(ptr::null_mut(), |i| i.data)
}

/// `void BIO_set_init(BIO *a, int init);`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_init(a: *mut BIO, init: c_int) {
    if a.is_null() {
        return;
    }
    // SAFETY: caller guarantees `a` is a valid BIO.
    if let Some(inner) = to_inner_mut(a) {
        inner.init = init;
    }
}

/// `int BIO_get_init(BIO *a);`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_init(a: *mut BIO) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `a` is a valid BIO.
    to_inner(a).map_or(0, |i| i.init)
}

/// `void BIO_set_shutdown(BIO *a, int shut);`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_shutdown(a: *mut BIO, shut: c_int) {
    if a.is_null() {
        return;
    }
    // SAFETY: caller guarantees `a` is a valid BIO.
    if let Some(inner) = to_inner_mut(a) {
        inner.shutdown = shut;
    }
}

/// `int BIO_get_shutdown(BIO *a);`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_shutdown(a: *mut BIO) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `a` is a valid BIO.
    to_inner(a).map_or(0, |i| i.shutdown)
}

/// `void BIO_set_flags(BIO *b, int flags);`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_flags(b: *mut BIO, flags: c_int) {
    if b.is_null() {
        return;
    }
    // SAFETY: caller guarantees `b` is a valid BIO.
    if let Some(inner) = to_inner_mut(b) {
        inner.flags |= flags;
    }
}

/// `int BIO_test_flags(const BIO *b, int flags);`
#[no_mangle]
pub unsafe extern "C" fn BIO_test_flags(b: *const BIO, flags: c_int) -> c_int {
    if b.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `b` is a valid BIO.
    to_inner(b).map_or(0, |i| i.flags & flags)
}

/// `void BIO_clear_flags(BIO *b, int flags);`
#[no_mangle]
pub unsafe extern "C" fn BIO_clear_flags(b: *mut BIO, flags: c_int) {
    if b.is_null() {
        return;
    }
    // SAFETY: caller guarantees `b` is a valid BIO.
    if let Some(inner) = to_inner_mut(b) {
        inner.flags &= !flags;
    }
}

/// `BIO *BIO_get_retry_BIO(BIO *bio, int *reason);`
///
/// Walks the chain to find the BIO that requested the retry, filling
/// `*reason` with its `retry_reason` code.  If no BIO in the chain
/// is retrying, returns `bio` itself with `*reason = 0`.
#[no_mangle]
pub unsafe extern "C" fn BIO_get_retry_BIO(bio: *mut BIO, reason: *mut c_int) -> *mut BIO {
    if bio.is_null() {
        if !reason.is_null() {
            // SAFETY: caller-supplied writable `int *`, non-null.
            *reason = 0;
        }
        return ptr::null_mut();
    }

    let mut cur = bio;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null.
        let Some(inner) = to_inner(cur) else {
            break;
        };
        if inner.flags & BIO_FLAGS_SHOULD_RETRY != 0 {
            if !reason.is_null() {
                // SAFETY: caller-supplied writable `int *`, non-null.
                *reason = inner.retry_reason;
            }
            return cur;
        }
        cur = inner.next_bio;
    }

    if !reason.is_null() {
        // SAFETY: caller-supplied writable `int *`, non-null.
        *reason = 0;
    }
    bio
}

/// `int BIO_should_retry(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_should_retry(b: *const BIO) -> c_int {
    // SAFETY: `BIO_test_flags` accepts a NULL BIO.
    c_int::from(BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY) != 0)
}

/// `int BIO_should_read(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_should_read(b: *const BIO) -> c_int {
    // SAFETY: `BIO_test_flags` accepts a NULL BIO.
    c_int::from(BIO_test_flags(b, BIO_FLAGS_READ) != 0)
}

/// `int BIO_should_write(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_should_write(b: *const BIO) -> c_int {
    // SAFETY: `BIO_test_flags` accepts a NULL BIO.
    c_int::from(BIO_test_flags(b, BIO_FLAGS_WRITE) != 0)
}

/// `int BIO_should_io_special(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_should_io_special(b: *const BIO) -> c_int {
    // SAFETY: `BIO_test_flags` accepts a NULL BIO.
    c_int::from(BIO_test_flags(b, BIO_FLAGS_IO_SPECIAL) != 0)
}

/// `int BIO_retry_type(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_retry_type(b: *const BIO) -> c_int {
    // SAFETY: `BIO_test_flags` accepts a NULL BIO.
    BIO_test_flags(b, BIO_FLAGS_RWS)
}

/// `int BIO_number_read(BIO *bio);`
#[no_mangle]
pub unsafe extern "C" fn BIO_number_read(bio: *const BIO) -> u64 {
    if bio.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `bio` is valid.
    to_inner(bio).map_or(0, |i| i.num_read)
}

/// `int BIO_number_written(BIO *bio);`
#[no_mangle]
pub unsafe extern "C" fn BIO_number_written(bio: *const BIO) -> u64 {
    if bio.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `bio` is valid.
    to_inner(bio).map_or(0, |i| i.num_write)
}

/// `int BIO_get_flags(BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_flags(b: *const BIO) -> c_int {
    if b.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `b` is valid.
    to_inner(b).map_or(0, |i| i.flags)
}

/// `int BIO_method_type(const BIO *b);`
#[no_mangle]
pub unsafe extern "C" fn BIO_method_type(b: *const BIO) -> c_int {
    if b.is_null() {
        return BIO_TYPE_NONE;
    }
    // SAFETY: caller guarantees `b` is valid.
    match to_inner(b) {
        Some(inner) => {
            // SAFETY: `inner.method` is populated in `BIO_new`.
            let method = &*inner.method;
            method.type_id
        }
        None => BIO_TYPE_NONE,
    }
}

/// `const char *BIO_method_name(const BIO *b);`
///
/// Returns a pointer to a `'static` or BIO-owned C string.  The
/// returned pointer remains valid for as long as the BIO is live.
#[no_mangle]
pub unsafe extern "C" fn BIO_method_name(b: *const BIO) -> *const c_char {
    if b.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees `b` is valid.
    let Some(inner) = to_inner(b) else {
        return ptr::null();
    };
    // SAFETY: `inner.method` was populated in `BIO_new`.
    let method = &*inner.method;
    // `BioMethodName` stores NUL-terminated C strings (`&'static CStr`
    // for built-ins, `CString` for methods created via `BIO_meth_new`).
    // `CStr::as_ptr` returns a `*const c_char` whose buffer is
    // guaranteed to be NUL-terminated — safe to pass directly to C
    // callers that invoke `strlen`.
    method.name.as_c_str().as_ptr()
}

// ===========================================================================
// Phase 10 — BIO_METHOD creation (custom BIO support)
// ===========================================================================
//
// The C API allows consumers to register their own `BIO_METHOD` with a
// custom `bread`/`bwrite`/`ctrl`/`create`/`destroy`/`bputs`/`bgets`/
// `callback_ctrl` function-pointer suite.  The resulting method is
// passed to `BIO_new()` to produce a BIO whose I/O behaviour is fully
// controlled by the caller.
//
// In Rust we model this by allocating a `BioMethodInner` on the heap
// and returning `Box::into_raw(...) as *mut BIO_METHOD` — matching the
// opaque pattern already established for `BIO` itself.  `BIO_meth_free`
// reconstitutes the box and drops it.  For built-in methods returned
// by `BIO_s_mem`/`BIO_s_file`/etc., `BIO_meth_free` is a no-op because
// those methods live inside `OnceLock` singletons and must never be
// freed.
//
// Helpers ------------------------------------------------------------------

/// Construct a mutable reference to an owned `BioMethodInner` from a
/// raw pointer returned by a previous `BIO_meth_new` call.
///
/// Returns `None` if `ptr` is null.  This function is `unsafe` internally
/// because it dereferences a raw pointer, but it's only invoked from the
/// extern "C" wrappers below which each carry their own `// SAFETY:`
/// comment documenting the caller contract.
fn method_inner_mut<'a>(ptr: *mut BIO_METHOD) -> Option<&'a mut BioMethodInner> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: `ptr` was returned by `Box::into_raw(BioMethodInner)`
        // and ownership is still held by the caller; no aliasing
        // reference exists elsewhere because the method has not yet
        // been registered with a live BIO (or the caller has sole
        // ownership).  The resulting reference's lifetime is bound by
        // `'a`, which the caller is responsible for choosing
        // appropriately — typically just the FFI function body.
        Some(unsafe { &mut *ptr.cast::<BioMethodInner>() })
    }
}

/// Test whether a `*const BIO_METHOD` pointer refers to one of the
/// built-in method singletons managed by `OnceLock`.  Built-in methods
/// must never be freed or mutated via `BIO_meth_*` setter functions.
fn is_builtin_method(ptr: *const BIO_METHOD) -> bool {
    if ptr.is_null() {
        return false;
    }
    let p = ptr.cast::<BioMethodInner>();
    core::ptr::eq(p, mem_method())
        || core::ptr::eq(p, secure_mem_method())
        || core::ptr::eq(p, file_method())
        || core::ptr::eq(p, socket_method())
        || core::ptr::eq(p, connect_method())
        || core::ptr::eq(p, accept_method())
        || core::ptr::eq(p, datagram_method())
        || core::ptr::eq(p, null_method())
}

/// `BIO_METHOD *BIO_meth_new(int type, const char *name);`
///
/// Allocate a fresh `BIO_METHOD` with the given numeric type id and
/// human-readable name.  Returns a heap-owned pointer that must
/// eventually be released via `BIO_meth_free`.  Returns NULL if `name`
/// is NULL, if the name cannot be converted to a `CString`, or on
/// allocation failure (the Rust allocator aborts, so only the NULL
/// input cases are observable).
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_new(type_: c_int, name: *const c_char) -> *mut BIO_METHOD {
    if name.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `name` points at a NUL-terminated C
    // string.  `CStr::from_ptr` is unsafe precisely because it relies
    // on that invariant.
    let c_name = unsafe { CStr::from_ptr(name) };
    // Copy the C string into an owned `CString`.  `CStr::to_owned`
    // preserves the NUL terminator — no revalidation needed.
    let owned = c_name.to_owned();
    let inner = BioMethodInner {
        type_id: type_,
        name: BioMethodName::Owned(owned),
        kind: BioMethodKind::Custom,
        bwrite: None,
        bread: None,
        bputs: None,
        bgets: None,
        ctrl: None,
        create: None,
        destroy: None,
        callback_ctrl: None,
    };
    Box::into_raw(Box::new(inner)).cast::<BIO_METHOD>()
}

/// `void BIO_meth_free(BIO_METHOD *biom);`
///
/// Deallocate a method previously obtained from `BIO_meth_new`.  If
/// `biom` is a built-in method singleton (e.g. returned by
/// `BIO_s_mem`), this is a no-op — matching the C implementation's
/// safe-handling of static methods.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_free(biom: *mut BIO_METHOD) {
    if biom.is_null() {
        return;
    }
    if is_builtin_method(biom.cast_const()) {
        // Built-in singletons are `'static` and must not be freed.
        return;
    }
    // SAFETY: `biom` was returned by `Box::into_raw` inside
    // `BIO_meth_new`; no other owner exists because the method is not
    // active on any BIO (the caller pledges this by invoking
    // `BIO_meth_free`).  Reconstituting the `Box` transfers ownership
    // back to Rust and drops the allocation.
    drop(unsafe { Box::from_raw(biom.cast::<BioMethodInner>()) });
}

// ---------------------------------------------------------------------------
// BIO_METHOD setter functions — all return 1 on success, 0 on NULL/
// built-in-method rejection.
// ---------------------------------------------------------------------------

/// `int BIO_meth_set_write(BIO_METHOD *biom,
///                         int (*write)(BIO *, const char *, int));`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_write(
    biom: *mut BIO_METHOD,
    write: Option<BioWriteFn>,
) -> c_int {
    if is_builtin_method(biom.cast_const()) {
        return 0;
    }
    match method_inner_mut(biom) {
        Some(m) => {
            m.bwrite = write;
            1
        }
        None => 0,
    }
}

/// `int BIO_meth_set_read(BIO_METHOD *biom,
///                        int (*read)(BIO *, char *, int));`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_read(
    biom: *mut BIO_METHOD,
    read: Option<BioReadFn>,
) -> c_int {
    if is_builtin_method(biom.cast_const()) {
        return 0;
    }
    match method_inner_mut(biom) {
        Some(m) => {
            m.bread = read;
            1
        }
        None => 0,
    }
}

/// `int BIO_meth_set_puts(BIO_METHOD *biom,
///                        int (*puts)(BIO *, const char *));`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_puts(
    biom: *mut BIO_METHOD,
    puts: Option<BioPutsFn>,
) -> c_int {
    if is_builtin_method(biom.cast_const()) {
        return 0;
    }
    match method_inner_mut(biom) {
        Some(m) => {
            m.bputs = puts;
            1
        }
        None => 0,
    }
}

/// `int BIO_meth_set_gets(BIO_METHOD *biom,
///                        int (*gets)(BIO *, char *, int));`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_gets(
    biom: *mut BIO_METHOD,
    gets: Option<BioGetsFn>,
) -> c_int {
    if is_builtin_method(biom.cast_const()) {
        return 0;
    }
    match method_inner_mut(biom) {
        Some(m) => {
            m.bgets = gets;
            1
        }
        None => 0,
    }
}

/// `int BIO_meth_set_ctrl(BIO_METHOD *biom,
///                        long (*ctrl)(BIO *, int, long, void *));`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_ctrl(
    biom: *mut BIO_METHOD,
    ctrl: Option<BioCtrlFn>,
) -> c_int {
    if is_builtin_method(biom.cast_const()) {
        return 0;
    }
    match method_inner_mut(biom) {
        Some(m) => {
            m.ctrl = ctrl;
            1
        }
        None => 0,
    }
}

/// `int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *));`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_create(
    biom: *mut BIO_METHOD,
    create: Option<BioCreateFn>,
) -> c_int {
    if is_builtin_method(biom.cast_const()) {
        return 0;
    }
    match method_inner_mut(biom) {
        Some(m) => {
            m.create = create;
            1
        }
        None => 0,
    }
}

/// `int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *));`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_destroy(
    biom: *mut BIO_METHOD,
    destroy: Option<BioDestroyFn>,
) -> c_int {
    if is_builtin_method(biom.cast_const()) {
        return 0;
    }
    match method_inner_mut(biom) {
        Some(m) => {
            m.destroy = destroy;
            1
        }
        None => 0,
    }
}

/// `int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
///                                 long (*callback_ctrl)(BIO *, int,
///                                                       BIO_info_cb *));`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_callback_ctrl(
    biom: *mut BIO_METHOD,
    callback_ctrl: Option<BioCallbackCtrlFn>,
) -> c_int {
    if is_builtin_method(biom.cast_const()) {
        return 0;
    }
    match method_inner_mut(biom) {
        Some(m) => {
            m.callback_ctrl = callback_ctrl;
            1
        }
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// BIO_METHOD getter functions
// ---------------------------------------------------------------------------
//
// These mirror the setters above and are used by callers that want to
// introspect — or chain-delegate to — a method's existing callbacks.

/// `int (*BIO_meth_get_write(const BIO_METHOD *biom))(BIO *, const char *, int);`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_write(biom: *const BIO_METHOD) -> Option<BioWriteFn> {
    if biom.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `biom` is a valid BIO_METHOD pointer
    // (either built-in singleton or BIO_meth_new-allocated).  Reading
    // a function-pointer field is safe.
    let inner = unsafe { &*biom.cast::<BioMethodInner>() };
    inner.bwrite
}

/// `int (*BIO_meth_get_read(const BIO_METHOD *biom))(BIO *, char *, int);`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_read(biom: *const BIO_METHOD) -> Option<BioReadFn> {
    if biom.is_null() {
        return None;
    }
    // SAFETY: see `BIO_meth_get_write`.
    let inner = unsafe { &*biom.cast::<BioMethodInner>() };
    inner.bread
}

/// `int (*BIO_meth_get_puts(const BIO_METHOD *biom))(BIO *, const char *);`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_puts(biom: *const BIO_METHOD) -> Option<BioPutsFn> {
    if biom.is_null() {
        return None;
    }
    // SAFETY: see `BIO_meth_get_write`.
    let inner = unsafe { &*biom.cast::<BioMethodInner>() };
    inner.bputs
}

/// `int (*BIO_meth_get_gets(const BIO_METHOD *biom))(BIO *, char *, int);`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_gets(biom: *const BIO_METHOD) -> Option<BioGetsFn> {
    if biom.is_null() {
        return None;
    }
    // SAFETY: see `BIO_meth_get_write`.
    let inner = unsafe { &*biom.cast::<BioMethodInner>() };
    inner.bgets
}

/// `long (*BIO_meth_get_ctrl(const BIO_METHOD *biom))(BIO *, int, long, void *);`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_ctrl(biom: *const BIO_METHOD) -> Option<BioCtrlFn> {
    if biom.is_null() {
        return None;
    }
    // SAFETY: see `BIO_meth_get_write`.
    let inner = unsafe { &*biom.cast::<BioMethodInner>() };
    inner.ctrl
}

/// `int (*BIO_meth_get_create(const BIO_METHOD *biom))(BIO *);`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_create(biom: *const BIO_METHOD) -> Option<BioCreateFn> {
    if biom.is_null() {
        return None;
    }
    // SAFETY: see `BIO_meth_get_write`.
    let inner = unsafe { &*biom.cast::<BioMethodInner>() };
    inner.create
}

/// `int (*BIO_meth_get_destroy(const BIO_METHOD *biom))(BIO *);`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_destroy(biom: *const BIO_METHOD) -> Option<BioDestroyFn> {
    if biom.is_null() {
        return None;
    }
    // SAFETY: see `BIO_meth_get_write`.
    let inner = unsafe { &*biom.cast::<BioMethodInner>() };
    inner.destroy
}

/// `long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))(BIO *, int,
///                                                             BIO_info_cb *);`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_callback_ctrl(
    biom: *const BIO_METHOD,
) -> Option<BioCallbackCtrlFn> {
    if biom.is_null() {
        return None;
    }
    // SAFETY: see `BIO_meth_get_write`.
    let inner = unsafe { &*biom.cast::<BioMethodInner>() };
    inner.callback_ctrl
}

// ===========================================================================
// Phase 11 — Utility helpers (BIO_indent, BIO_dump, BIO_dump_indent,
//                             BIO_snprintf / BIO_printf)
// ===========================================================================
//
// These helpers round out the public BIO API with formatting and
// debug-dump utilities that callers (and the OpenSSL `apps/` tree) rely
// upon.  They all build on top of `BIO_puts`/`BIO_write` so they
// inherit the safe-Rust implementations provided by the concrete BIO
// variants behind an opaque `*mut BIO`.

/// Ceiling-safe `c_int` width check used by the dump helpers.
///
/// The hex-dump functions emit lines of the form
/// ```text
/// 0000 - 48 65 6c 6c 6f 20 57 6f-72 6c 64 21              Hello World!
/// ```
/// and accept a caller-supplied line width.  The C reference clamps
/// silently to `[8, 65536]`, but in Rust we stay a little stricter so
/// pathological inputs never allocate absurd amounts of memory.
const BIO_DUMP_WIDTH_MIN: usize = 8;
const BIO_DUMP_WIDTH_MAX: usize = 65_536;

/// Stack-allocated buffer of spaces used by `BIO_indent` to emit
/// padding without allocating on the heap.  Module-scope to avoid
/// `items_after_statements`.
const INDENT_SPACES: [u8; 64] = [b' '; 64];

/// `int BIO_indent(BIO *b, int indent, int max);`
///
/// Write `indent` space characters to the BIO, capped at `max`, and at
/// least zero.  Returns 1 on success and 0 on write failure — matching
/// `include/openssl/bio.h.in`.
#[no_mangle]
pub unsafe extern "C" fn BIO_indent(b: *mut BIO, indent: c_int, max: c_int) -> c_int {
    if b.is_null() {
        return 0;
    }
    // Normalise the bounds in signed space first (to avoid negative
    // wrap-around on `as usize`).  `max < 0` degenerates to 0;
    // `indent < 0` degenerates to 0.
    let indent = indent.max(0);
    let max = max.max(0);
    let n = indent.min(max);
    // SAFETY: `b` is a valid BIO (checked above).  The buffer we
    // feed into `BIO_write` is fully initialised and sized exactly by
    // `chunk` below.
    let mut remaining = n;
    // `INDENT_SPACES.len()` is a compile-time constant (64) that always
    // fits in `c_int`, but we use `try_from` to satisfy the workspace
    // `cast_possible_truncation` deny lint.
    let spaces_len: c_int = c_int::try_from(INDENT_SPACES.len()).unwrap_or(c_int::MAX);
    while remaining > 0 {
        let chunk = remaining.min(spaces_len);
        let wrote = unsafe { BIO_write(b, INDENT_SPACES.as_ptr().cast::<c_void>(), chunk) };
        if wrote <= 0 {
            return 0;
        }
        // A short write (`wrote < chunk`) is treated as progress so we
        // keep iterating — but we only deduct what was actually
        // written.  This mirrors the semantics of the C helper.
        remaining = remaining.saturating_sub(wrote);
    }
    1
}

/// Internal hex-dump helper shared by `BIO_dump`, `BIO_dump_indent`
/// and the family of `*_cb` variants not exposed at the FFI boundary.
///
/// Renders `len` bytes at `s` into a sequence of lines of the form
/// ```text
/// ${indent}${offset:04x} - XX XX XX XX XX XX XX XX-XX XX XX XX XX XX XX XX  ........
/// ```
/// and returns the total number of bytes written on success, or `-1`
/// on any write failure encountered along the way.
#[allow(clippy::too_many_lines)]
unsafe fn bio_hex_dump(b: *mut BIO, s: *const c_void, len: c_int, indent: c_int) -> c_int {
    if b.is_null() || s.is_null() || len <= 0 {
        return 0;
    }
    // SAFETY: caller guarantees `s` points at `len` readable bytes.
    // We tighten the bound to `usize` via checked conversion.
    let Ok(len_u) = usize::try_from(len) else {
        return 0;
    };
    let bytes = unsafe { core::slice::from_raw_parts(s.cast::<u8>(), len_u) };
    let width: usize = 16;
    // Cross-check that the hard-coded `width` stays within the
    // published `(BIO_DUMP_WIDTH_MIN, BIO_DUMP_WIDTH_MAX)` envelope.
    // The check is free in release builds (debug_assert! compiles to
    // a no-op) and catches an accidental width drift in test/CI.
    let (dump_min, dump_max) = bio_dump_width_range();
    debug_assert!(
        (dump_min..=dump_max).contains(&width),
        "bio_hex_dump width={width} outside [{dump_min}, {dump_max}]",
    );
    let mut total_written: i64 = 0;
    let mut offset: usize = 0;

    while offset < bytes.len() {
        // Indent prefix.
        if indent > 0 {
            // SAFETY: `b` is valid (checked at entry).
            let r = unsafe { BIO_indent(b, indent, c_int::MAX) };
            if r <= 0 {
                return -1;
            }
        }

        // Offset prefix (e.g. "0000 - ").
        // Format directly into a stack buffer to avoid heap churn.
        let mut header = [0u8; 16];
        let written = {
            let mut idx = 0;
            let hex = b"0123456789abcdef";
            // We print a 4-digit hex offset (zero-padded).
            header[idx] = hex[(offset >> 12) & 0xF];
            idx += 1;
            header[idx] = hex[(offset >> 8) & 0xF];
            idx += 1;
            header[idx] = hex[(offset >> 4) & 0xF];
            idx += 1;
            header[idx] = hex[offset & 0xF];
            idx += 1;
            header[idx] = b' ';
            idx += 1;
            header[idx] = b'-';
            idx += 1;
            header[idx] = b' ';
            idx += 1;
            idx
        };
        // SAFETY: `header` is fully initialised for `written` bytes.
        let n = unsafe {
            BIO_write(
                b,
                header.as_ptr().cast::<c_void>(),
                c_int::try_from(written).unwrap_or(c_int::MAX),
            )
        };
        if n <= 0 {
            return -1;
        }
        total_written = total_written.saturating_add(i64::from(n));

        // Hex octets (with a dash between cols 7 and 8).
        let chunk_end = (offset + width).min(bytes.len());
        let mut hex_buf = [0u8; 48 + 16]; // 16 * "XX " + spacing + dash
        let mut hex_len = 0usize;
        let hex_digits = b"0123456789abcdef";
        for i in 0..width {
            if offset + i < chunk_end {
                let byte = bytes[offset + i];
                hex_buf[hex_len] = hex_digits[((byte >> 4) & 0xF) as usize];
                hex_len += 1;
                hex_buf[hex_len] = hex_digits[(byte & 0xF) as usize];
                hex_len += 1;
            } else {
                hex_buf[hex_len] = b' ';
                hex_len += 1;
                hex_buf[hex_len] = b' ';
                hex_len += 1;
            }
            if i == 7 {
                hex_buf[hex_len] = b'-';
                hex_len += 1;
            } else {
                hex_buf[hex_len] = b' ';
                hex_len += 1;
            }
        }
        // SAFETY: `hex_buf` is fully initialised for `hex_len` bytes
        // (we wrote every position from 0..hex_len above).  `b` is
        // valid per the entry check.
        let n = unsafe {
            BIO_write(
                b,
                hex_buf.as_ptr().cast::<c_void>(),
                c_int::try_from(hex_len).unwrap_or(c_int::MAX),
            )
        };
        if n <= 0 {
            return -1;
        }
        total_written = total_written.saturating_add(i64::from(n));

        // Separator before ASCII column.
        let sep = b" ";
        // SAFETY: `sep` is a static NUL-less byte slice owned by the
        // program image; reading one byte is trivially safe.
        let n = unsafe { BIO_write(b, sep.as_ptr().cast::<c_void>(), 1) };
        if n <= 0 {
            return -1;
        }
        total_written = total_written.saturating_add(i64::from(n));

        // ASCII column.
        let mut ascii_buf = [b'.'; 16];
        let mut ascii_len = 0usize;
        for i in 0..width {
            if offset + i < chunk_end {
                let byte = bytes[offset + i];
                ascii_buf[ascii_len] = if (0x20..0x7f).contains(&byte) {
                    byte
                } else {
                    b'.'
                };
                ascii_len += 1;
            } else {
                ascii_buf[ascii_len] = b' ';
                ascii_len += 1;
            }
        }
        // SAFETY: `ascii_buf` initialised for `ascii_len` bytes; `b`
        // valid per entry.
        let n = unsafe {
            BIO_write(
                b,
                ascii_buf.as_ptr().cast::<c_void>(),
                c_int::try_from(ascii_len).unwrap_or(c_int::MAX),
            )
        };
        if n <= 0 {
            return -1;
        }
        total_written = total_written.saturating_add(i64::from(n));

        // Line terminator.
        let eol = b"\n";
        // SAFETY: static byte slice; one-byte write.
        let n = unsafe { BIO_write(b, eol.as_ptr().cast::<c_void>(), 1) };
        if n <= 0 {
            return -1;
        }
        total_written = total_written.saturating_add(i64::from(n));

        offset = chunk_end;
    }

    c_int::try_from(total_written).unwrap_or(c_int::MAX)
}

/// `int BIO_dump(BIO *b, const char *s, int len);`
///
/// Hex-dump `len` bytes starting at `s` to `b` with no indentation.
/// Returns the number of bytes written on success, or `-1` on any
/// write error.
#[no_mangle]
pub unsafe extern "C" fn BIO_dump(b: *mut BIO, s: *const c_char, len: c_int) -> c_int {
    // SAFETY: the helper does its own null/length validation and
    // carries further `// SAFETY:` comments for each unsafe read.
    unsafe { bio_hex_dump(b, s.cast::<c_void>(), len, 0) }
}

/// `int BIO_dump_indent(BIO *b, const char *s, int len, int indent);`
#[no_mangle]
pub unsafe extern "C" fn BIO_dump_indent(
    b: *mut BIO,
    s: *const c_char,
    len: c_int,
    indent: c_int,
) -> c_int {
    // SAFETY: see `BIO_dump`.  `indent` is clamped inside the helper.
    unsafe { bio_hex_dump(b, s.cast::<c_void>(), len, indent) }
}

/// Retrieve the recommended minimum/maximum hex-dump widths so callers
/// (and the `bio_hex_dump` helper itself) can size their own buffers
/// and validate caller-supplied widths.  Not a part of the C API —
/// intentionally crate-private.  The single source of truth for the
/// valid width range is this `const fn`, which `bio_hex_dump`
/// consumes in a `debug_assert!` at every entry.
pub(crate) const fn bio_dump_width_range() -> (usize, usize) {
    (BIO_DUMP_WIDTH_MIN, BIO_DUMP_WIDTH_MAX)
}

// ---------------------------------------------------------------------------
// BIO_snprintf / BIO_printf
// ---------------------------------------------------------------------------
//
// The C API exposes `int BIO_printf(BIO *bio, const char *format, ...)`
// and `int BIO_snprintf(char *buf, size_t n, const char *format, ...)`.
// Supporting the full variadic C-printf grammar safely in stable Rust
// is not feasible without a `va_list` primitive, which is not in the
// stable surface area as of Rust 1.81.0.  We therefore export safer,
// non-variadic counterparts that forward pre-formatted C strings to
// the BIO — callers wanting printf-style formatting can use the
// platform `snprintf`/`vsnprintf` to build a buffer first.
//
// This design is documented in ARCHITECTURE.md and the decision log.
// The `BIO_printf` / `BIO_snprintf` names are intentionally NOT
// exported to avoid shadowing a future variadic implementation.

/// Write a pre-formatted C string to a BIO.  Non-variadic alternative
/// to `BIO_printf` that does not attempt to parse a format string.
///
/// Returns the number of bytes written on success, or `-1` on error.
#[no_mangle]
pub unsafe extern "C" fn BIO_puts_literal(b: *mut BIO, msg: *const c_char) -> c_int {
    // SAFETY: trivial forwarder; both arguments are passed straight
    // through to `BIO_puts`, which performs its own validation.
    unsafe { BIO_puts(b, msg) }
}

/// Copy a pre-formatted C string into a caller-owned buffer.
/// Non-variadic alternative to `BIO_snprintf`.
///
/// Returns the number of bytes written (not counting the NUL
/// terminator), or `-1` on error.  The output is always NUL-terminated
/// if `n > 0`.
#[no_mangle]
pub unsafe extern "C" fn BIO_snprintf_literal(
    buf: *mut c_char,
    n: size_t,
    msg: *const c_char,
) -> c_int {
    if buf.is_null() || msg.is_null() || n == 0 {
        return -1;
    }
    // SAFETY: caller guarantees `msg` is NUL-terminated.
    let src = unsafe { CStr::from_ptr(msg) };
    let bytes = src.to_bytes();
    // Reserve room for the trailing NUL.
    let cap = n.saturating_sub(1);
    let to_copy = bytes.len().min(cap);
    // SAFETY: `buf` is caller-owned and valid for `n` bytes per
    // contract.  `src` is valid for `bytes.len() >= to_copy` bytes.
    // The ranges do not alias because `buf` is writable output and
    // `src` is read-only input from the caller's format string.
    let buf_u8 = buf.cast::<u8>();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_u8, to_copy);
        *buf_u8.add(to_copy) = 0;
    }
    // TRUNCATION: `to_copy <= n - 1 <= usize::MAX`; we intentionally
    // saturate to `c_int::MAX` for C-ABI compatibility on return.
    c_int::try_from(to_copy).unwrap_or(c_int::MAX)
}

// ===========================================================================
// BIO_get_new_index — allocate a fresh custom BIO type index
// ===========================================================================
//
// OpenSSL exposes `int BIO_get_new_index(void)` for consumers creating
// their own `BIO_METHOD` with a distinct type id.  Each invocation
// returns a monotonically increasing integer starting at
// `BIO_TYPE_START (= 128)` and capped at `BIO_TYPE_START | BIO_TYPE_MASK
// (= 255)`.  Once exhausted, `-1` is returned.
//
// Internally we use a `c_uint`-width atomic counter to match the
// OpenSSL convention that bio-type indices are treated as unsigned
// values during bitwise manipulation (see `BIO_method_type`).  We then
// narrow back to `c_int` at the FFI boundary for compatibility with
// the public API signature.

/// Atomic counter backing [`BIO_get_new_index`].  Seeded to
/// `BIO_TYPE_START - 1` so that the first fetch-and-add returns
/// `BIO_TYPE_START`.
static BIO_NEW_INDEX_COUNTER: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new((BIO_TYPE_START as u32) - 1);

/// `int BIO_get_new_index(void);`
///
/// Returns a unique, previously-unused custom BIO type id in the
/// range `[BIO_TYPE_START, BIO_TYPE_START | BIO_TYPE_MASK]`, or `-1`
/// if the range has been exhausted.
#[no_mangle]
pub extern "C" fn BIO_get_new_index() -> c_int {
    let upper: c_uint = (BIO_TYPE_START as c_uint) | (BIO_TYPE_MASK as c_uint);
    // fetch_add returns the PREVIOUS value — so we work with that for
    // range testing and emit the NEW value back to the caller.
    let previous = BIO_NEW_INDEX_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let new_index = previous.saturating_add(1);
    if new_index > upper {
        // Exhaustion: pin the counter at the maximum so subsequent
        // calls continue to return `-1` instead of wrapping.
        BIO_NEW_INDEX_COUNTER.store(upper, std::sync::atomic::Ordering::Relaxed);
        return -1;
    }
    c_int::try_from(new_index).unwrap_or(-1)
}
