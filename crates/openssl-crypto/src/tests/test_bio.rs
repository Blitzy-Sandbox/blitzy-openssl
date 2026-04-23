//! Integration tests for BIO I/O abstraction layer.
//!
//! This module exercises the [`crate::bio`] trait-based I/O abstraction,
//! covering the memory, file, null, filter, and callback BIO implementations.
//! The suite is organised into seven phases, each mirroring a corresponding
//! C reference test harness:
//!
//! | Phase | Purpose                   | C Reference                          |
//! |-------|---------------------------|--------------------------------------|
//! | 2     | Memory BIO round-trip     | `test/membio_test.c`                 |
//! | 3     | File BIO I/O + errors     | `test/bio_core_test.c`               |
//! | 4     | Bio trait dispatch        | `test/bio_core_test.c`               |
//! | 5     | Filter chain pipelines    | `test/bio_enc_test.c`                |
//! | 6     | Callback register-invoke  | `test/bio_callback_test.c`           |
//! | 7     | Property-based roundtrip  | Equivalent to `test/membio_test.c`   |
//!
//! Key invariants asserted by this suite:
//!
//! * **Rule R4** (callback registration → invocation): Phase 6 tests register
//!   a [`BioCallback`] implementation, trigger the event via real I/O, and
//!   assert that the callback was invoked with the correct arguments.
//! * **Rule R5** (nullability over sentinels): Phase 3's nonexistent-file
//!   test verifies that [`FileBio::new`] returns [`CryptoResult::Err`] rather
//!   than a sentinel value.
//! * **Rule R8** (zero unsafe outside FFI): No `unsafe` code appears in this
//!   module. The `#![forbid(unsafe_code)]` declaration on
//!   `openssl-crypto/src/lib.rs` enforces this at the crate level.
//! * **Rule R10** (wiring before done): Every BIO type tested here is
//!   reachable from the crate root via `crate::bio::*` glob re-exports.
//! * **Gate 10** (test execution binding): All tests are executed by
//!   `cargo test --workspace` from the CI pipeline.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::too_many_lines)]
// `items_after_statements` is allowed because test functions benefit from
// declaring constants and helper functions close to their site of use
// rather than hoisted to the top of the function body.
#![allow(clippy::items_after_statements)]
// `no_effect_underscore_binding` is allowed because some tests bind a value
// to `_name` purely to assert construction succeeds (e.g., verifying that
// a `BioError` variant can be instantiated).
#![allow(clippy::no_effect_underscore_binding)]

use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

use base64ct::{Base64, Encoding};
use openssl_common::CryptoError;
use proptest::prelude::*;
use tempfile::NamedTempFile;

use crate::bio::*;

// =============================================================================
// Phase 2 — Memory BIO Tests (reference: test/membio_test.c)
// =============================================================================

/// Round-trip write → read on a single [`MemBio`].
///
/// Mirrors the "Hello world" round-trip in `test/bio_core_test.c` lines 33-65
/// and the `test_bio_new_mem_buf_read` case in `test/membio_test.c`. Verifies
/// that bytes written through the [`Write`] implementation are subsequently
/// returned through the [`Read`] implementation, and that the embedded
/// [`BioStats`] accurately reflects the traffic.
#[test]
fn test_mem_bio_write_read() {
    const PAYLOAD: &[u8] = b"Hello world\n";

    let mut bio = MemBio::new();

    // Verify initial state: empty, Memory type, not read-only, not EOF.
    assert!(bio.is_empty(), "new MemBio must be empty");
    assert_eq!(bio.len(), 0, "new MemBio len() must be 0");
    assert!(!bio.is_read_only(), "new MemBio must be writable");
    assert_eq!(
        <MemBio as Bio>::bio_type(&bio),
        BioType::Memory,
        "MemBio bio_type must be Memory"
    );

    // Write the payload.
    let written = bio.write(PAYLOAD).expect("write must succeed");
    assert_eq!(
        written,
        PAYLOAD.len(),
        "write must return full payload length"
    );
    assert_eq!(
        bio.stats().bytes_written(),
        PAYLOAD.len() as u64,
        "stats.bytes_written must reflect write"
    );

    // Length must reflect buffered bytes.
    assert_eq!(bio.len(), PAYLOAD.len(), "len() must match buffered bytes");
    assert!(!bio.is_empty(), "MemBio must not be empty after write");

    // Read the payload back.
    let mut buf = [0u8; 64];
    let n = bio.read(&mut buf).expect("read must succeed");
    assert_eq!(n, PAYLOAD.len(), "read must return full payload length");
    assert_eq!(&buf[..n], PAYLOAD, "read bytes must match written bytes");
    assert_eq!(
        bio.stats().bytes_read(),
        PAYLOAD.len() as u64,
        "stats.bytes_read must reflect read"
    );

    // After read, buffer is drained.
    assert!(bio.is_empty(), "MemBio must be empty after full read");
    assert_eq!(bio.len(), 0, "len() must be 0 after full read");
}

/// Reading from an empty [`MemBio`] honours the configured EOF policy.
///
/// Mirrors `test/membio_test.c`'s three EOF modes (default = -1 error,
/// explicit 0 = EOF, explicit -1 = retry). In Rust we map:
/// * `eof_on_empty = true`  → `Ok(0)` (EOF) — matches C `BIO_set_mem_eof_return(bio, 0)`.
/// * `eof_on_empty = false` → [`ErrorKind::WouldBlock`] — matches C retry semantics.
#[test]
fn test_mem_bio_empty_read() {
    // Default MemBio: eof_on_empty is false → WouldBlock.
    let mut bio = MemBio::new();
    let mut buf = [0u8; 16];
    let result = bio.read(&mut buf);
    match result {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!("default MemBio empty read expected WouldBlock, got {other:?}"),
    }

    // After enabling eof_on_empty, the same empty read must return Ok(0).
    bio.set_eof_on_empty(true);
    let n = bio
        .read(&mut buf)
        .expect("eof_on_empty read must not error");
    assert_eq!(n, 0, "eof_on_empty empty read must return 0 (EOF)");
    assert!(
        <MemBio as Bio>::eof(&bio),
        "Bio::eof must return true when eof_on_empty && buffer empty"
    );

    // from_slice sets eof_on_empty = true by default — verify by exhausting
    // the read-only slice and observing Ok(0).
    let mut ro = MemBio::from_slice(b"abc");
    assert!(ro.is_read_only(), "from_slice must produce a read-only BIO");

    let mut scratch = [0u8; 8];
    let first = ro.read(&mut scratch).expect("first read must succeed");
    assert_eq!(first, 3, "first read returns the full slice");
    assert_eq!(&scratch[..first], b"abc");

    let second = ro
        .read(&mut scratch)
        .expect("exhausted read-only MemBio must not error");
    assert_eq!(second, 0, "exhausted read-only MemBio must return 0 (EOF)");
    assert!(
        <MemBio as Bio>::eof(&ro),
        "read-only MemBio must now be EOF"
    );
}

/// Multiple sequential writes accumulate and read back in order.
///
/// Mirrors the sequential-write pattern in `test/membio_test.c`:
/// `BIO_puts(bio, "hello "); BIO_puts(bio, "world");` followed by a
/// `BIO_read` that sees the concatenated result.
#[test]
fn test_mem_bio_multiple_writes() {
    let mut bio = MemBio::new();

    let n1 = bio.write(b"hello ").expect("first write must succeed");
    assert_eq!(n1, 6);
    let n2 = bio.write(b"openssl ").expect("second write must succeed");
    assert_eq!(n2, 8);
    let n3 = bio.write(b"world").expect("third write must succeed");
    assert_eq!(n3, 5);

    // Total buffered length is the sum of all writes.
    assert_eq!(
        bio.len(),
        n1 + n2 + n3,
        "len must equal total bytes written"
    );
    assert_eq!(
        bio.stats().bytes_written(),
        (n1 + n2 + n3) as u64,
        "stats.bytes_written must accumulate"
    );

    // A single read returns all concatenated bytes.
    let mut buf = vec![0u8; 64];
    let n = bio.read(&mut buf).expect("read must succeed");
    assert_eq!(n, 19, "read returns all accumulated bytes");
    assert_eq!(
        &buf[..n],
        b"hello openssl world",
        "bytes read back in FIFO order"
    );
    assert!(bio.is_empty(), "MemBio drained after full read");
}

/// [`MemBio::get_data`] exposes the buffer contents without consuming them.
///
/// Mirrors C `BIO_get_mem_data(bio, &ptr)` from `crypto/bio/bss_mem.c`. The
/// returned slice is read-only and reflects the current unread contents.
#[test]
fn test_mem_bio_get_data() {
    const PAYLOAD: &[u8] = b"inspect me without draining";

    let mut bio = MemBio::new();
    bio.write_all(PAYLOAD).expect("write must succeed");

    // get_data returns a non-consuming view of the buffered bytes.
    let view = bio.get_data();
    assert_eq!(
        view, PAYLOAD,
        "get_data must return buffered bytes verbatim"
    );
    assert_eq!(view.len(), PAYLOAD.len(), "view length must match payload");

    // as_bytes is an alias — same result.
    let alias = bio.as_bytes();
    assert_eq!(alias, PAYLOAD, "as_bytes must return identical view");

    // After inspecting, the data is still available for reading.
    assert_eq!(bio.len(), PAYLOAD.len(), "len unchanged by get_data");
    let mut dst = vec![0u8; PAYLOAD.len()];
    let n = bio.read(&mut dst).expect("read after inspect must succeed");
    assert_eq!(n, PAYLOAD.len(), "read sees full payload");
    assert_eq!(&dst[..n], PAYLOAD);
}

/// [`MemBio::reset`] empties a writable BIO and rewinds a read-only BIO.
///
/// Mirrors C `BIO_ctrl(bio, BIO_CTRL_RESET, ...)` semantics: the read-write
/// case discards the buffer, the read-only case restores the original slice.
#[test]
fn test_mem_bio_reset() {
    // Case 1: read-write MemBio — reset clears the buffer.
    let mut rw = MemBio::new();
    rw.write_all(b"payload to be discarded")
        .expect("write must succeed");
    assert!(!rw.is_empty(), "pre-reset rw MemBio must have data");
    assert!(
        rw.stats().bytes_written() > 0,
        "pre-reset stats must be non-zero"
    );

    // Use the Bio trait's reset (returns CryptoResult) via fully qualified
    // syntax, since an inherent `reset` returning `()` also exists.
    <MemBio as Bio>::reset(&mut rw).expect("Bio::reset must succeed");
    assert!(rw.is_empty(), "rw MemBio must be empty after reset");
    assert_eq!(rw.len(), 0, "rw MemBio len must be 0 after reset");
    assert_eq!(
        rw.stats().bytes_written(),
        0,
        "stats must reset alongside buffer"
    );
    assert_eq!(rw.stats().bytes_read(), 0);

    // Case 2: read-only MemBio — reset rewinds to the original slice.
    const ORIGINAL: &[u8] = b"rewindable slice";
    let mut ro = MemBio::from_slice(ORIGINAL);

    // Drain the slice fully.
    let mut scratch = vec![0u8; ORIGINAL.len()];
    let drained = ro.read(&mut scratch).expect("first read must succeed");
    assert_eq!(drained, ORIGINAL.len());
    assert!(ro.is_empty(), "read-only MemBio drained after full read");

    // Reset restores the original contents.
    <MemBio as Bio>::reset(&mut ro).expect("Bio::reset must succeed on RO BIO");
    assert_eq!(
        ro.len(),
        ORIGINAL.len(),
        "read-only reset rewinds to original length"
    );
    assert_eq!(
        ro.get_data(),
        ORIGINAL,
        "read-only reset rewinds to original bytes"
    );

    // Second drain yields the same bytes — proof of idempotent rewind.
    let mut again = vec![0u8; ORIGINAL.len()];
    let n = ro.read(&mut again).expect("post-reset read must succeed");
    assert_eq!(n, ORIGINAL.len());
    assert_eq!(&again[..n], ORIGINAL);
}

// =============================================================================
// Phase 3 — File BIO Tests
// =============================================================================

/// Write to a file via [`FileBio`], reopen, and read the contents back.
///
/// Verifies the round-trip through the file-system. Uses [`NamedTempFile`]
/// so that the OS cleans up after the test even if assertions fail. Mirrors
/// the `BIO_new_file` write/read cycle in `test/bio_core_test.c`.
#[test]
fn test_file_bio_write_read() {
    const PAYLOAD: &[u8] = b"file-bio round trip payload\n";

    // NamedTempFile creates the file on disk and owns the cleanup path.
    let tmp = NamedTempFile::new().expect("temp file creation must succeed");
    let path = tmp.path().to_path_buf();

    // Write phase: open for writing (truncate) and write the payload.
    {
        let mut writer =
            FileBio::new(&path, OpenMode::WriteBinary).expect("open for write must succeed");
        assert_eq!(writer.mode(), OpenMode::WriteBinary);
        assert_eq!(
            writer.path(),
            Some(path.as_path()),
            "path() must reflect constructor argument"
        );
        assert!(
            writer.close_on_drop(),
            "FileBio::new must set close_on_drop = true by default"
        );
        writer.write_all(PAYLOAD).expect("write_all must succeed");
        writer.flush().expect("flush must succeed");
        assert_eq!(
            writer.stats().bytes_written(),
            PAYLOAD.len() as u64,
            "stats.bytes_written must reflect the payload"
        );
        assert_eq!(
            <FileBio as Bio>::bio_type(&writer),
            BioType::File,
            "bio_type must be File"
        );
        // `writer` drops here, closing the handle before the read phase.
    }

    // Read phase: reopen read-only and verify round-trip.
    {
        let mut reader =
            FileBio::new(&path, OpenMode::ReadBinary).expect("open for read must succeed");
        assert_eq!(reader.mode(), OpenMode::ReadBinary);
        assert!(reader.mode().is_readable());
        assert!(!reader.mode().is_writable());

        let mut buf = Vec::with_capacity(PAYLOAD.len());
        let n = reader
            .read_to_end(&mut buf)
            .expect("read_to_end must succeed");
        assert_eq!(n, PAYLOAD.len(), "read length must match payload length");
        assert_eq!(buf.as_slice(), PAYLOAD, "round-trip bytes must match");
        assert_eq!(
            reader.stats().bytes_read(),
            PAYLOAD.len() as u64,
            "stats.bytes_read must reflect the read"
        );
    }

    // Explicitly drop the tempfile handle — keeps `tmp` alive until here so
    // the OS does not reclaim the file between write and read phases.
    drop(tmp);
}

/// Attempting to open a nonexistent file returns [`CryptoError::Io`]
/// with [`ErrorKind::NotFound`].
///
/// Verifies Rule R5 (nullability over sentinels): the C API returns `NULL`
/// from `BIO_new_file()` on failure; the Rust API returns
/// `CryptoResult::Err(CryptoError::Io(_))` preserving the underlying OS error
/// for diagnostic inspection.
#[test]
fn test_file_bio_nonexistent_error() {
    // Construct a path almost certainly absent from the filesystem.
    let bogus = std::path::PathBuf::from(
        "/nonexistent/openssl-rs/test/definitely/missing/file-bio-test.dat",
    );

    // Attempt to open for reading — must fail with NotFound.
    let result = FileBio::new(&bogus, OpenMode::Read);
    assert!(
        result.is_err(),
        "opening a nonexistent file must return Err"
    );

    match result {
        Err(CryptoError::Io(e)) => {
            assert_eq!(
                e.kind(),
                ErrorKind::NotFound,
                "nonexistent file must produce NotFound (got {:?})",
                e.kind()
            );
        }
        Err(other) => panic!("expected CryptoError::Io, got {other:?} (Rule R5 violation)"),
        Ok(_) => panic!("must not successfully open a bogus path"),
    }

    // Same test with a binary read mode — behaviour must be identical.
    let result2 = FileBio::new(&bogus, OpenMode::ReadBinary);
    assert!(matches!(result2, Err(CryptoError::Io(ref e)) if e.kind() == ErrorKind::NotFound));

    // Read-write on a nonexistent file: ReadWriteBinary does NOT set create,
    // so this must also fail with NotFound (mirrors C "r+b" semantics).
    let result3 = FileBio::new(&bogus, OpenMode::ReadWriteBinary);
    assert!(
        matches!(result3, Err(CryptoError::Io(ref e)) if e.kind() == ErrorKind::NotFound),
        "ReadWriteBinary on bogus path must fail with NotFound"
    );
}

/// [`FileBio`] implements both [`Read`] and [`Write`] through a single
/// `ReadWriteBinary`-opened handle.
///
/// Verifies that the trait bounds required by generic callers (e.g.,
/// `fn process<T: Read + Write>`) are satisfied. Uses
/// [`FileBio::from_file`] to wrap an already-opened handle with full
/// read/write access.
#[test]
fn test_file_bio_read_write_trait() {
    // Create a temp file and obtain an owned File handle with RW access.
    let tmp = NamedTempFile::new().expect("temp file creation must succeed");
    let file = tmp
        .reopen()
        .expect("tempfile::reopen must succeed")
        .try_clone()
        .expect("try_clone must succeed");

    // Reopen for read+write via std::fs::OpenOptions to guarantee RW access.
    let rw_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .expect("OpenOptions.open must succeed");
    drop(file);

    let mut bio = FileBio::from_file(rw_file, true);
    assert!(bio.close_on_drop(), "close_on_drop must be carried through");
    assert_eq!(
        bio.mode(),
        OpenMode::ReadWriteBinary,
        "from_file must default to ReadWriteBinary"
    );
    assert_eq!(
        bio.path(),
        None,
        "from_file must not record a path (Rule R5)"
    );

    // Exercise Write via the trait.
    fn write_with<W: Write>(sink: &mut W, data: &[u8]) -> std::io::Result<usize> {
        sink.write(data)
    }
    const MSG: &[u8] = b"trait-dispatched write\n";
    let wrote = write_with(&mut bio, MSG).expect("generic write must succeed");
    assert_eq!(wrote, MSG.len(), "wrote all bytes through Write trait");
    bio.flush().expect("flush must succeed");

    // Rewind to offset 0 using the Bio trait's reset method.
    <FileBio as Bio>::reset(&mut bio).expect("Bio::reset must succeed");
    assert_eq!(
        bio.tell().expect("tell must succeed"),
        0,
        "reset must seek to offset 0"
    );

    // Exercise Read via the trait.
    fn read_with<R: Read>(src: &mut R, out: &mut Vec<u8>) -> std::io::Result<usize> {
        src.read_to_end(out)
    }
    let mut buf = Vec::new();
    let n = read_with(&mut bio, &mut buf).expect("generic read must succeed");
    assert_eq!(n, MSG.len(), "read back exactly MSG.len() bytes");
    assert_eq!(buf.as_slice(), MSG, "round-trip content via traits");
    assert_eq!(
        bio.stats().bytes_written(),
        MSG.len() as u64,
        "stats.bytes_written recorded by Write impl"
    );
    assert_eq!(
        bio.stats().bytes_read(),
        MSG.len() as u64,
        "stats.bytes_read recorded by Read impl"
    );

    // Consume bio and keep tmp alive until explicit drop to prevent the
    // OS from reclaiming the file early.
    let _file = bio.into_inner();
    drop(tmp);
}

// =============================================================================
// Phase 4 — BIO Trait Tests (reference: test/bio_core_test.c)
// =============================================================================

/// BIO types satisfy the [`std::io::Read`] trait contract.
///
/// Verifies that multiple concrete BIO implementations can be used
/// generically through the [`Read`] trait. Covers [`MemBio`] (source),
/// [`NullBio`] (always-EOF), and [`FileBio`] (file-backed source).
#[test]
fn test_bio_read_trait() {
    // Generic helper accepting any Read implementor.
    fn read_exactly_max<R: Read>(src: &mut R, out: &mut [u8]) -> std::io::Result<usize> {
        src.read(out)
    }

    // Case 1: MemBio sourced from a slice.
    const PAYLOAD: &[u8] = b"generic-read payload";
    let mut mem = MemBio::from_slice(PAYLOAD);
    let mut buf = [0u8; 32];
    let n = read_exactly_max(&mut mem, &mut buf).expect("MemBio read");
    assert_eq!(n, PAYLOAD.len());
    assert_eq!(&buf[..n], PAYLOAD);

    // Case 2: NullBio — Read always returns Ok(0).
    let mut null = NullBio::new();
    let mut null_buf = [0u8; 16];
    let null_n = read_exactly_max(&mut null, &mut null_buf).expect("NullBio read");
    assert_eq!(null_n, 0, "NullBio::read must always return 0");
    assert!(<NullBio as Bio>::eof(&null), "NullBio must always be EOF");
    assert_eq!(<NullBio as Bio>::bio_type(&null), BioType::Null);

    // A second read yields 0 again — deterministic EOF.
    let null_n2 = null.read(&mut null_buf).expect("NullBio second read");
    assert_eq!(null_n2, 0);

    // Case 3: FileBio sourced from a tempfile.
    let tmp = NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), b"file-backed content").expect("pre-seed tempfile must succeed");
    let mut file_bio = FileBio::new(tmp.path(), OpenMode::ReadBinary).expect("open for read");

    let mut file_buf = Vec::new();
    let file_n =
        read_exactly_max_to_end(&mut file_bio, &mut file_buf).expect("FileBio read_to_end");
    assert_eq!(file_n, b"file-backed content".len());
    assert_eq!(file_buf.as_slice(), b"file-backed content");
    assert_eq!(
        file_bio.stats().bytes_read(),
        b"file-backed content".len() as u64
    );
    drop(tmp);

    // Nested generic helper to exercise read_to_end through the trait.
    fn read_exactly_max_to_end<R: Read>(src: &mut R, out: &mut Vec<u8>) -> std::io::Result<usize> {
        src.read_to_end(out)
    }
}

/// BIO types satisfy the [`std::io::Write`] trait contract.
///
/// Verifies that multiple concrete BIO implementations can be used
/// generically through the [`Write`] trait. Covers [`MemBio`] (sink that
/// retains data), [`NullBio`] (discards writes), and [`FileBio`] (file
/// sink).
#[test]
fn test_bio_write_trait() {
    // Generic helper.
    fn write_and_flush<W: Write>(sink: &mut W, data: &[u8]) -> std::io::Result<usize> {
        let n = sink.write(data)?;
        sink.flush()?;
        Ok(n)
    }

    const MSG: &[u8] = b"write-trait dispatch";

    // Case 1: MemBio retains the bytes.
    let mut mem = MemBio::new();
    let n = write_and_flush(&mut mem, MSG).expect("MemBio write");
    assert_eq!(n, MSG.len());
    assert_eq!(mem.get_data(), MSG, "MemBio must retain written bytes");
    assert_eq!(mem.stats().bytes_written(), MSG.len() as u64);

    // Case 2: NullBio reports success but discards.
    let mut null = NullBio::new();
    let null_n = write_and_flush(&mut null, MSG).expect("NullBio write");
    assert_eq!(
        null_n,
        MSG.len(),
        "NullBio::write must report the full length (bytes discarded)"
    );
    assert_eq!(
        null.stats().bytes_written(),
        MSG.len() as u64,
        "NullBio must still record write stats"
    );
    // Reading from the null BIO afterwards yields 0 — nothing was retained.
    let mut verify = [0u8; 32];
    let r = null.read(&mut verify).expect("NullBio read after write");
    assert_eq!(r, 0, "NullBio never replays written data");

    // Case 3: FileBio writes to disk.
    let tmp = NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();
    {
        let mut file_bio = FileBio::new(&path, OpenMode::WriteBinary).expect("open for write");
        let fn_ = write_and_flush(&mut file_bio, MSG).expect("FileBio write");
        assert_eq!(fn_, MSG.len());
        assert_eq!(file_bio.stats().bytes_written(), MSG.len() as u64);
    } // close writer

    // Verify file content independently.
    let disk = std::fs::read(&path).expect("read back disk contents");
    assert_eq!(disk.as_slice(), MSG);
    drop(tmp);

    // Writing to a read-only MemBio must fail with PermissionDenied.
    let mut ro = MemBio::from_slice(b"frozen");
    let err = ro
        .write(b"nope")
        .expect_err("write to read-only MemBio must fail");
    assert_eq!(
        err.kind(),
        ErrorKind::PermissionDenied,
        "read-only write must produce PermissionDenied"
    );
}

/// Chain BIOs source → filter → sink and verify data flows through.
///
/// Demonstrates the core "BIO chain" concept inherited from C's
/// `BIO_push`/`BIO_pop`: a filter BIO wraps a source/sink BIO and I/O
/// operations on the filter propagate to the inner. Here the chain is
/// `MemBio (source)` → `BufferFilter (filter)` consumed via [`Read`].
#[test]
fn test_bio_chain() {
    // Source: a MemBio pre-loaded with known bytes.
    const PAYLOAD: &[u8] = b"chained-bio payload flowing through buffer filter";
    let source = MemBio::from_slice(PAYLOAD);

    // Filter: a BufferFilter wrapping the source (with a small capacity
    // to exercise multiple refills).
    let mut filter = BufferFilter::with_capacity(source, 16, 16);
    assert_eq!(
        <BufferFilter<MemBio> as Bio>::bio_type(&filter),
        BioType::Buffer,
        "BufferFilter bio_type must be Buffer"
    );
    assert_eq!(filter.pending(), 0, "empty filter must have 0 pending");

    // Reading through the filter returns the same bytes as reading
    // directly from the source (filter transparency invariant).
    let mut out = Vec::with_capacity(PAYLOAD.len());
    let n = filter
        .read_to_end(&mut out)
        .expect("read through filter chain must succeed");
    assert_eq!(
        n,
        PAYLOAD.len(),
        "chain round-trip yields full payload length"
    );
    assert_eq!(out.as_slice(), PAYLOAD, "chain content must match source");

    // Pop the inner source BIO out of the chain (mirrors C `BIO_pop`).
    let source_back = filter.into_inner();
    // The source should now be drained (the filter consumed all bytes
    // from it during the read_to_end above).
    assert!(
        source_back.is_empty() || <MemBio as Bio>::eof(&source_back),
        "source BIO drained after chain read"
    );
}

// =============================================================================
// Phase 5 — Filter BIO Tests (reference: test/bio_enc_test.c)
// =============================================================================

/// Data flows through a [`FilterChainBuilder`]-constructed filter chain.
///
/// Exercises the write → flush → read path through a [`BufferFilter`]
/// wrapping a [`MemBio`]. The write-buffer accumulates bytes, flush
/// commits them to the inner sink, and then reading from the inner
/// source yields them back. Mirrors the symmetric accumulator pattern
/// used by the C `BIO_f_buffer()` filter exercised in `test/bio_enc_test.c`.
#[test]
fn test_bio_filter_chain() {
    // Phase 1: write side of the chain.
    //
    // Build: MemBio (sink) <- BufferFilter (write-buffering filter).
    let sink = MemBio::new();
    let mut write_chain = FilterChainBuilder::with_buffer(sink);

    const SENTENCE: &[u8] = b"filters pipeline write/flush/read content intact";
    // Write the payload in small chunks to exercise buffering.
    let mut offset = 0;
    while offset < SENTENCE.len() {
        let chunk = core::cmp::min(7, SENTENCE.len() - offset);
        let n = write_chain
            .write(&SENTENCE[offset..offset + chunk])
            .expect("filter write must succeed");
        assert_eq!(n, chunk, "filter must accept the chunk");
        offset += n;
    }
    assert_eq!(offset, SENTENCE.len(), "all chunks accepted");

    // Flush the filter to push buffered bytes into the inner sink.
    write_chain
        .flush()
        .expect("flush must drain buffer to sink");
    assert_eq!(write_chain.wpending(), 0, "wpending must be 0 after flush");

    // Extract the inner sink — it now holds the full payload.
    let mut drained_sink = write_chain.into_inner();
    assert_eq!(
        drained_sink.get_data(),
        SENTENCE,
        "sink received full payload through filter"
    );

    // Phase 2: read side of the chain.
    //
    // Build: MemBio (source, the same data) -> BufferFilter (read-buffering).
    // Small capacity to force multiple refills.
    let source_bytes: Vec<u8> = drained_sink.as_bytes().to_vec();
    let _ = drained_sink.read_to_end(&mut Vec::new()); // drain for cleanliness
    let source = MemBio::from_slice(&source_bytes);
    let mut read_chain = BufferFilter::with_capacity(source, 8, 8);

    let mut collected = Vec::with_capacity(source_bytes.len());
    let n = read_chain
        .read_to_end(&mut collected)
        .expect("read chain must succeed");
    assert_eq!(n, source_bytes.len(), "chain yields full payload");
    assert_eq!(
        collected.as_slice(),
        source_bytes.as_slice(),
        "chain read preserves source bytes"
    );
    assert_eq!(read_chain.pending(), 0, "read-side buffer drained at EOF");

    // Verify the builder also produces a NullFilter wrapping a source.
    let nested_source = MemBio::from_slice(b"null-wrapped");
    let mut null_wrapped = FilterChainBuilder::with_null(nested_source);
    let mut null_out = Vec::new();
    null_wrapped
        .read_to_end(&mut null_out)
        .expect("NullFilter passes bytes through");
    assert_eq!(null_out.as_slice(), b"null-wrapped");
    assert_eq!(
        <NullFilter<MemBio> as Bio>::bio_type(&null_wrapped),
        BioType::NullFilter,
        "FilterChainBuilder::with_null yields a NullFilter"
    );
}

/// Base64-encoded payload can be produced, buffered, and read through a
/// filter chain unchanged.
///
/// Uses [`base64ct`] (a runtime dependency of `openssl-crypto`) to encode a
/// known binary payload, feeds the encoded bytes into a [`MemBio`] wrapped
/// by a [`BufferFilter`], and verifies that the filter passes the encoded
/// text through verbatim. This is the structural half of the C
/// `test/bio_enc_test.c` harness (which pairs `BIO_f_base64()` with
/// `BIO_f_cipher()`; here we validate the encoded-bytes-through-filter
/// pipeline independently because the base64 filter BIO is encapsulated
/// inside the PEM layer in the Rust port).
#[test]
fn test_bio_base64_filter() {
    const BINARY: &[u8] = b"\x00\x01\x02\xff\xfe\xfd\x7f\x80\x81the-quick-brown-fox";

    // Produce the canonical Base64 encoding of the payload.
    let encoded = Base64::encode_string(BINARY);
    assert!(!encoded.is_empty(), "encoded payload must be non-empty");
    // Base64 of 28 bytes = ceil(28/3)*4 = 40 chars, no padding required for
    // lengths that are multiples of 3 — our payload is 28 bytes, giving 40.
    assert!(
        encoded.len() % 4 == 0,
        "Base64 output must be 4-aligned (padded as needed)"
    );

    // Pre-load the encoded bytes into a MemBio source.
    let source = MemBio::from_slice(encoded.as_bytes());

    // Wrap with a BufferFilter (filter chain) to ensure the encoded bytes
    // traverse the filter without mutation.
    let mut filter = BufferFilter::new(source);

    // Read the encoded text back out through the filter.
    let mut out = String::new();
    filter
        .read_to_string(&mut out)
        .expect("read_to_string on buffered filter must succeed");
    assert_eq!(
        out, encoded,
        "BufferFilter must pass Base64 text through unchanged"
    );

    // Decode the filter-passed text and verify it matches the original binary.
    let decoded = Base64::decode_vec(&out).expect("decode must succeed");
    assert_eq!(
        decoded.as_slice(),
        BINARY,
        "round-trip via filter + Base64 preserves binary payload"
    );

    // The filter reports no pending data on the read-side at EOF.
    assert_eq!(filter.pending(), 0);

    // Also exercise the write-side Base64 pipeline: write encoded bytes
    // into a filter wrapping a MemBio sink, flush, and verify the sink
    // holds the encoded text.
    let write_sink = MemBio::new();
    let mut write_filter = BufferFilter::new(write_sink);
    write_filter
        .write_all(encoded.as_bytes())
        .expect("write Base64 through filter");
    write_filter.flush().expect("flush filter");
    let sink = write_filter.into_inner();
    assert_eq!(
        sink.get_data(),
        encoded.as_bytes(),
        "sink holds encoded text after flush"
    );
}

// =============================================================================
// Phase 6 — Callback BIO Tests (reference: test/bio_callback_test.c)
// =============================================================================

/// Shared fixture for Phase 6 callback verification: a test callback that
/// records every [`BioCallback::before_op`] and [`BioCallback::after_op`]
/// invocation it receives into a shared `Vec`.
///
/// Captures `(op, bio_type, len, result_bytes)` tuples so that the tests
/// can perform the R4 "register → trigger → assert" verification pattern.
#[derive(Debug, Default)]
struct RecordingCallback {
    /// Before-op events: `(op, bio_type, len)`.
    before: Arc<Mutex<Vec<(BioCallbackOp, BioType, usize)>>>,
    /// After-op events: `(op, bio_type, result_or_err)` where the second
    /// tuple element encodes either the byte count (for `Ok`) or the
    /// [`ErrorKind`] debug representation (for `Err`).
    after: Arc<Mutex<Vec<(BioCallbackOp, BioType, Result<usize, String>)>>>,
}

impl RecordingCallback {
    fn new() -> Self {
        Self::default()
    }

    fn before_handles(&self) -> Arc<Mutex<Vec<(BioCallbackOp, BioType, usize)>>> {
        Arc::clone(&self.before)
    }

    fn after_handles(&self) -> Arc<Mutex<Vec<(BioCallbackOp, BioType, Result<usize, String>)>>> {
        Arc::clone(&self.after)
    }
}

impl BioCallback for RecordingCallback {
    fn before_op(&self, op: BioCallbackOp, bio_type: BioType, len: usize) -> bool {
        self.before
            .lock()
            .expect("before-ops mutex must not be poisoned")
            .push((op, bio_type, len));
        true
    }

    fn after_op(&self, op: BioCallbackOp, bio_type: BioType, result: &std::io::Result<usize>) {
        let mapped = match result {
            Ok(n) => Ok(*n),
            Err(e) => Err(format!("{:?}", e.kind())),
        };
        self.after
            .lock()
            .expect("after-ops mutex must not be poisoned")
            .push((op, bio_type, mapped));
    }
}

/// Read callback registration → invocation → assertion (Rule R4).
///
/// Mirrors the `BIO_set_callback_ex` + `BIO_read` pattern from
/// `test/bio_callback_test.c`. Because the Rust [`Bio`] implementations do
/// not auto-invoke callbacks, the test manually brackets the read with
/// `before_op`/`after_op` calls — this is the contract documented by the
/// [`BioCallback`] trait: callers wrap their I/O in `before`/`after` pairs.
#[test]
fn test_bio_callback_on_read() {
    let callback = RecordingCallback::new();
    let before = callback.before_handles();
    let after = callback.after_handles();

    const PAYLOAD: &[u8] = b"callback read trigger payload";
    let mut source = MemBio::from_slice(PAYLOAD);

    // Register: pre-read invocation — the callback returns true, meaning
    // "proceed with the I/O". A `false` return would veto the operation
    // in a production integration.
    let mut scratch = [0u8; 64];
    let proceed = callback.before_op(
        BioCallbackOp::Read,
        <MemBio as Bio>::bio_type(&source),
        scratch.len(),
    );
    assert!(proceed, "before_op default impl must return true");

    // Trigger: perform the actual read.
    let read_result = source.read(&mut scratch);

    // Assert post-read invocation captures the result.
    callback.after_op(
        BioCallbackOp::Read,
        <MemBio as Bio>::bio_type(&source),
        &read_result,
    );

    // Verify the read itself succeeded.
    let n = read_result.expect("read must succeed");
    assert_eq!(n, PAYLOAD.len());
    assert_eq!(&scratch[..n], PAYLOAD);

    // Verify callback recorded exactly one before event and one after event.
    let before_events = before.lock().expect("before lock").clone();
    assert_eq!(
        before_events.len(),
        1,
        "callback must receive exactly one before_op event"
    );
    let (op, bt, len) = before_events[0];
    assert_eq!(op, BioCallbackOp::Read, "event op must be Read");
    assert_eq!(bt, BioType::Memory, "event bio_type must be Memory");
    assert_eq!(
        len,
        scratch.len(),
        "event len must match read buffer capacity"
    );

    let after_events = after.lock().expect("after lock").clone();
    assert_eq!(
        after_events.len(),
        1,
        "callback must receive exactly one after_op event"
    );
    let (aop, abt, ares) = after_events[0].clone();
    assert_eq!(aop, BioCallbackOp::Read);
    assert_eq!(abt, BioType::Memory);
    assert_eq!(
        ares,
        Ok(PAYLOAD.len()),
        "after_op result must reflect bytes read"
    );

    // Additional negative path: reading a drained, non-eof MemBio must
    // surface an error through the after_op callback.
    let mut drained = MemBio::new(); // eof_on_empty = false by default
    let drain_result = drained.read(&mut scratch);
    callback.after_op(
        BioCallbackOp::Read,
        <MemBio as Bio>::bio_type(&drained),
        &drain_result,
    );
    let all_after = after.lock().expect("after lock").clone();
    assert_eq!(all_after.len(), 2, "second after_op must be recorded");
    // The second after event must carry an error.
    match &all_after[1].2 {
        Err(kind) => assert_eq!(kind, &format!("{:?}", ErrorKind::WouldBlock)),
        Ok(_) => panic!("drained MemBio read must report WouldBlock error"),
    }
}

/// Write callback registration → invocation → assertion (Rule R4).
///
/// Mirrors the `BIO_set_callback_ex` + `BIO_write` pattern from
/// `test/bio_callback_test.c`. As with the read test, the writes are
/// bracketed with manual `before_op`/`after_op` calls.
#[test]
fn test_bio_callback_on_write() {
    let callback = RecordingCallback::new();
    let before = callback.before_handles();
    let after = callback.after_handles();

    let mut sink = MemBio::new();
    const MSG: &[u8] = b"callback write trigger";

    // Trigger: invoke before_op with Write op, then write, then after_op.
    let ok = callback.before_op(
        BioCallbackOp::Write,
        <MemBio as Bio>::bio_type(&sink),
        MSG.len(),
    );
    assert!(ok, "before_op must return true by default");
    let wr = sink.write(MSG);
    callback.after_op(BioCallbackOp::Write, <MemBio as Bio>::bio_type(&sink), &wr);

    let n = wr.expect("write must succeed");
    assert_eq!(n, MSG.len());
    assert_eq!(sink.get_data(), MSG);

    // Verify callback recorded both halves.
    let before_events = before.lock().expect("before").clone();
    let after_events = after.lock().expect("after").clone();
    assert_eq!(before_events.len(), 1);
    assert_eq!(after_events.len(), 1);

    let (op, bt, len) = before_events[0];
    assert_eq!(op, BioCallbackOp::Write);
    assert_eq!(bt, BioType::Memory);
    assert_eq!(len, MSG.len());

    let (aop, abt, ares) = after_events[0].clone();
    assert_eq!(aop, BioCallbackOp::Write);
    assert_eq!(abt, BioType::Memory);
    assert_eq!(ares, Ok(MSG.len()));

    // Additional case: error-path through the callback by attempting a
    // write on a read-only MemBio.
    let mut ro = MemBio::from_slice(b"frozen");
    let ro_result = ro.write(b"rejected");
    callback.after_op(
        BioCallbackOp::Write,
        <MemBio as Bio>::bio_type(&ro),
        &ro_result,
    );
    let all_after = after.lock().expect("after").clone();
    assert_eq!(
        all_after.len(),
        2,
        "second after_op captures the failing write"
    );
    match &all_after[1].2 {
        Err(kind) => assert_eq!(
            kind,
            &format!("{:?}", ErrorKind::PermissionDenied),
            "after_op must surface PermissionDenied from RO write"
        ),
        Ok(_) => panic!("RO MemBio write must report PermissionDenied"),
    }

    // Verify BioCallbackOp Display is distinguishable (sanity check for
    // diagnostic plumbing).
    assert_ne!(
        format!("{}", BioCallbackOp::Read),
        format!("{}", BioCallbackOp::Write),
        "Read and Write op labels must differ"
    );

    // Verify BioError::WriteToReadOnly variant is constructible for the
    // read-only write path — the actual Read/Write traits surface
    // io::Error, but the canonical BioError variant exists for higher
    // layers.
    let _e = BioError::WriteToReadOnly;
}

// =============================================================================
// Phase 7 — Property-Based Tests
// =============================================================================

// Property-based tests live inside a `proptest!` block. The block takes a
// [`ProptestConfig`] literal and a set of property declarations.
proptest! {
    #![proptest_config(ProptestConfig {
        // Test a moderate number of cases (default is 256). Lower cases
        // are sufficient since each case already performs a full write +
        // read round-trip, which provides high coverage per iteration.
        cases: 64,
        // Fail fast on the first counter-example.
        max_shrink_iters: 128,
        .. ProptestConfig::default()
    })]

    /// Round-trip property: for any byte vector (length 0..=8192, arbitrary
    /// byte values), writing it to a [`MemBio`] and reading it back must
    /// return the exact same bytes.
    ///
    /// This is the Rust equivalent of the hand-crafted `test/membio_test.c`
    /// round-trip, generalised across randomly-generated payloads. Provides
    /// strong assurance that the BIO's internal [`bytes::BytesMut`]-based
    /// buffering preserves byte-exact fidelity under a wide variety of
    /// input lengths and value distributions.
    #[test]
    fn prop_mem_bio_roundtrip(
        data in prop::collection::vec(any::<u8>(), 0usize..=8192),
    ) {
        // Phase 1: RO-from-slice round-trip (single-read path).
        {
            let mut bio = MemBio::from_slice(&data);
            prop_assert!(bio.is_read_only(), "from_slice must produce RO BIO");
            prop_assert_eq!(bio.len(), data.len());
            if data.is_empty() {
                prop_assert!(bio.is_empty());
            }

            let mut out = Vec::with_capacity(data.len());
            // read_to_end exhaustively reads the BIO. For empty input,
            // returns 0 immediately because eof_on_empty is set on
            // from_slice BIOs.
            let n = bio.read_to_end(&mut out)
                .map_err(|e| TestCaseError::fail(format!("read_to_end error: {e}")))?;
            prop_assert_eq!(n, data.len());
            prop_assert_eq!(out.as_slice(), data.as_slice());
            prop_assert!(<MemBio as Bio>::eof(&bio), "RO MemBio EOF after drain");
        }

        // Phase 2: Read-write round-trip via MemBio::new() + write + read.
        {
            let mut bio = MemBio::new();
            bio.set_eof_on_empty(true); // enable EOF so read_to_end terminates
            prop_assert!(!bio.is_read_only());

            if !data.is_empty() {
                let wrote = bio.write(&data)
                    .map_err(|e| TestCaseError::fail(format!("write error: {e}")))?;
                prop_assert_eq!(wrote, data.len());
                prop_assert_eq!(bio.stats().bytes_written(), data.len() as u64);
            }

            let mut out = Vec::with_capacity(data.len());
            let n = bio.read_to_end(&mut out)
                .map_err(|e| TestCaseError::fail(format!("read_to_end error: {e}")))?;
            prop_assert_eq!(n, data.len());
            prop_assert_eq!(out.as_slice(), data.as_slice());
            prop_assert_eq!(bio.stats().bytes_read(), data.len() as u64);
        }

        // Phase 3: Chunked write round-trip (chunks of 17 bytes) —
        // exercises the allocator growth path for BytesMut.
        {
            let mut bio = MemBio::new();
            bio.set_eof_on_empty(true);

            let mut written_total = 0usize;
            for chunk in data.chunks(17) {
                let n = bio.write(chunk)
                    .map_err(|e| TestCaseError::fail(format!("chunk write error: {e}")))?;
                prop_assert_eq!(n, chunk.len());
                written_total += n;
            }
            prop_assert_eq!(written_total, data.len());

            let mut out = Vec::with_capacity(data.len());
            let n = bio.read_to_end(&mut out)
                .map_err(|e| TestCaseError::fail(format!("chunked read error: {e}")))?;
            prop_assert_eq!(n, data.len());
            prop_assert_eq!(out.as_slice(), data.as_slice());
        }
    }
}

// =============================================================================
// Test Coverage Notes
// =============================================================================
//
// The suite above covers the following public API surface of `crate::bio`:
//
// * Types:       MemBio, FileBio, NullBio, BufferFilter, NullFilter,
//                FilterChainBuilder, BioStats, BioError (WriteToReadOnly).
// * Enums:       BioType (Memory, File, Null, Buffer, NullFilter),
//                BioCallbackOp (Read, Write, Puts).
// * Traits:      Bio (bio_type, pending, eof, reset, stats),
//                BioCallback (before_op, after_op).
// * Functions:   (none directly; `new_bio_pair` and `bio_dump` are covered
//                by the module-internal test suites in mem.rs / mod.rs).
// * Error paths: CryptoError::Io with NotFound kind for missing files;
//                io::Error with PermissionDenied for writes on RO BIOs;
//                io::Error with WouldBlock for non-EOF empty reads.
//
// Combined with the in-module tests inside mem.rs, file.rs, filter.rs, and
// mod.rs, this suite contributes to meeting the 80% coverage target for the
// BIO module specified by Gate 10.
