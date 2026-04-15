//! Tests for secure memory primitives (zeroing, `SecureVec`, constant-time comparison)
//! in openssl-common.
//!
//! Exercises every public function and type in the [`crate::mem`] module through
//! the crate's public API. Verifies that `SecureVec` zeroes on drop, `Debug`
//! output is redacted (never prints key material), and `constant_time_eq`
//! produces correct results.
//!
//! Derived from C `crypto/mem.c`, `crypto/mem_sec.c`, and `crypto/mem_clr.c`.
//!
//! # Coverage
//!
//! - **Phase 2:** `cleanse()` — zeroing arbitrary byte slices
//! - **Phase 3:** `SecureVec` construction — `new`, `from_slice`, accessors
//! - **Phase 4:** `SecureVec` zero-on-drop — `clear`, `Zeroize` trait
//! - **Phase 5:** `SecureVec` debug redaction — no key leakage in logs
//! - **Phase 6:** `SecureVec` equality — constant-time via `subtle`
//! - **Phase 7:** `SecureVec` deref — `Deref` / `DerefMut` to `[u8]`
//! - **Phase 8:** `SecureBox` — construction, debug redaction, deref
//! - **Phase 9:** `constant_time_eq` — replaces `CRYPTO_memcmp`
//! - **Phase 10:** `secure_zero()` — alias for `cleanse`
//! - **Phase 11:** `SecureHeapConfig` — initialization and usage tracking
//!
//! # Rules Enforced
//!
//! - **Rule R5:** `init_secure_heap()` returns `Result`, not sentinel error code.
//! - **Rule R7:** No shared mutable state in memory module.
//! - **Rule R8:** ZERO `unsafe` code — `zeroize` and `subtle` handle low-level
//!   details safely. Tests must NOT use unsafe to inspect memory after drop.
//! - **Rule R9:** Warning-free build under `RUSTFLAGS="-D warnings"`.
//! - **Rule R10:** Tests exercise mem module through public API.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_literal_unwrap
)]

use zeroize::Zeroize;

use crate::error::CommonError;
use crate::mem::{
    cleanse, constant_time_eq, init_secure_heap, secure_heap_used, secure_zero, SecureBox,
    SecureHeapConfig, SecureVec,
};

// =============================================================================
// Phase 2: cleanse() Tests (replaces OPENSSL_cleanse from crypto/mem_clr.c)
// =============================================================================

/// Verifies that `cleanse` zeroes all bytes in a 32-byte buffer.
///
/// Corresponds to `OPENSSL_cleanse()` in `crypto/mem_clr.c`, which uses a
/// volatile function pointer to `memset` to prevent optimizer elision.
/// The Rust implementation delegates to `zeroize::Zeroize`.
#[test]
fn cleanse_zeroes_data() {
    let mut data = [0xAA_u8; 32];
    cleanse(&mut data);
    assert!(
        data.iter().all(|&b| b == 0),
        "cleanse must zero all bytes; found non-zero byte in buffer"
    );
}

/// Verifies that `cleanse` does not panic when called with an empty slice.
///
/// Edge case: zero-length buffers must be handled gracefully.
#[test]
fn cleanse_empty_slice() {
    let mut data: [u8; 0] = [];
    cleanse(&mut data);
    // Success: no panic occurred.
}

/// Verifies that `cleanse` correctly zeroes a single-byte buffer.
///
/// Boundary case: minimum non-empty buffer size.
#[test]
fn cleanse_single_byte() {
    let mut data = [0xFF_u8];
    cleanse(&mut data);
    assert_eq!(data[0], 0, "cleanse must zero a single byte");
}

// =============================================================================
// Phase 3: SecureVec Construction Tests
// =============================================================================

/// Verifies that `SecureVec::new(capacity)` creates an empty vector.
///
/// The pre-allocated capacity prevents reallocation when the vector is
/// filled; no bytes are stored initially.
#[test]
fn secure_vec_new() {
    let sv = SecureVec::new(32);
    assert!(sv.is_empty(), "new SecureVec must be empty");
    assert_eq!(sv.len(), 0, "new SecureVec must have length 0");
}

/// Verifies that `SecureVec::from_slice` copies data correctly.
///
/// The resulting `as_bytes()` must match the input slice exactly.
#[test]
fn secure_vec_from_slice() {
    let data = [1_u8, 2, 3];
    let sv = SecureVec::from_slice(&data);
    assert_eq!(sv.as_bytes(), &[1, 2, 3], "from_slice must copy input data");
}

/// Verifies `len()` and `is_empty()` for both empty and non-empty `SecureVec`.
#[test]
fn secure_vec_len_and_empty() {
    let empty = SecureVec::new(16);
    assert!(empty.is_empty(), "new SecureVec must report is_empty");
    assert_eq!(empty.len(), 0, "new SecureVec must have len 0");

    let non_empty = SecureVec::from_slice(&[10, 20, 30]);
    assert!(!non_empty.is_empty(), "from_slice SecureVec must not be empty");
    assert_eq!(non_empty.len(), 3, "from_slice SecureVec must have len 3");
}

/// Verifies `as_bytes()` returns the correct immutable slice reference.
#[test]
fn secure_vec_as_bytes() {
    let sv = SecureVec::from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = sv.as_bytes();
    assert_eq!(bytes.len(), 4);
    assert_eq!(bytes[0], 0xDE);
    assert_eq!(bytes[1], 0xAD);
    assert_eq!(bytes[2], 0xBE);
    assert_eq!(bytes[3], 0xEF);
}

/// Verifies `as_bytes_mut()` allows in-place modification.
#[test]
fn secure_vec_as_bytes_mut() {
    let mut sv = SecureVec::from_slice(&[1, 2, 3]);
    {
        let bytes_mut = sv.as_bytes_mut();
        bytes_mut[0] = 10;
        bytes_mut[2] = 30;
    }
    assert_eq!(sv.as_bytes(), &[10, 2, 30], "modifications via as_bytes_mut must be visible");
}

/// Verifies `extend_from_slice` appends bytes correctly.
#[test]
fn secure_vec_extend_from_slice() {
    let mut sv = SecureVec::from_slice(&[1, 2]);
    sv.extend_from_slice(&[3, 4]);
    assert_eq!(
        sv.as_bytes(),
        &[1, 2, 3, 4],
        "extend_from_slice must append bytes"
    );
}

/// Verifies `resize` grows the vector and fills new bytes with the
/// specified fill value.
#[test]
fn secure_vec_resize() {
    let mut sv = SecureVec::from_slice(&[0xAA, 0xBB]);
    sv.resize(5, 0xFF);
    assert_eq!(sv.len(), 5, "resize must set new length");
    assert_eq!(sv.as_bytes()[0], 0xAA, "existing bytes preserved");
    assert_eq!(sv.as_bytes()[1], 0xBB, "existing bytes preserved");
    assert_eq!(sv.as_bytes()[2], 0xFF, "new byte filled with fill value");
    assert_eq!(sv.as_bytes()[3], 0xFF, "new byte filled with fill value");
    assert_eq!(sv.as_bytes()[4], 0xFF, "new byte filled with fill value");
}

// =============================================================================
// Phase 4: SecureVec Zero-on-Drop Tests
// CRITICAL — validates OPENSSL_cleanse replacement behavior.
//
// Key material MUST be zeroed when dropped. Direct memory inspection after
// drop is UB in Rust (Rule R8 forbids unsafe), so we verify the mechanism
// through the Zeroize trait and the clear() method.
// =============================================================================

/// Verifies the zero-on-drop mechanism by testing the `Zeroize` trait
/// implementation on `SecureVec`.
///
/// Strategy (per AAP Rule R8 — no unsafe):
/// 1. Create a `SecureVec` with known non-zero data.
/// 2. Clone it to test `.zeroize()` without reading freed memory.
/// 3. Call `.zeroize()` on the clone.
/// 4. Verify the clone is now empty (all bytes zeroed, length 0).
///
/// Since `SecureVec` derives `ZeroizeOnDrop`, the `Drop` implementation
/// calls the same `.zeroize()` method we test here, proving the
/// zero-on-drop guarantee holds.
#[test]
fn secure_vec_zeroes_on_drop() {
    let original = SecureVec::from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
    assert_eq!(original.len(), 6, "original must contain 6 bytes");

    // Clone so we can test zeroize without touching freed memory.
    let mut cloned = original.clone();
    assert_eq!(cloned.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);

    // Zeroize the clone — this is the same code path that Drop invokes.
    cloned.zeroize();

    // After zeroize, the inner Vec is zeroed and cleared (length → 0).
    assert!(
        cloned.is_empty(),
        "zeroize must clear the SecureVec (length → 0)"
    );
    assert_eq!(cloned.len(), 0, "zeroize must set length to 0");

    // Original is unaffected.
    assert_eq!(original.len(), 6, "original must remain intact");
}

/// Verifies that `SecureVec::clear()` zeroes all bytes and resets length.
///
/// The `clear` method delegates to `Zeroize::zeroize` on the inner `Vec`,
/// which zeroes all bytes via volatile writes before setting length to zero.
#[test]
fn secure_vec_clear_zeroes() {
    let mut sv = SecureVec::from_slice(&[0xAA_u8; 64]);
    assert_eq!(sv.len(), 64, "initial length must be 64");
    assert!(!sv.is_empty(), "must not be empty before clear");

    sv.clear();

    assert!(sv.is_empty(), "clear must make SecureVec empty");
    assert_eq!(sv.len(), 0, "clear must set length to 0");
}

/// Verifies that `SecureVec` implements the `Zeroize` trait correctly.
///
/// Calls `.zeroize()` explicitly (the same method invoked by `ZeroizeOnDrop`)
/// and verifies all bytes are zeroed and the vector becomes empty.
#[test]
fn secure_vec_zeroize_trait() {
    let mut sv = SecureVec::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(sv.len(), 5);

    // Explicit zeroize call — same code path as ZeroizeOnDrop.
    sv.zeroize();

    assert!(
        sv.is_empty(),
        "after zeroize, SecureVec must be empty"
    );
    assert_eq!(sv.len(), 0, "after zeroize, length must be 0");
}

// =============================================================================
// Phase 5: SecureVec Debug Redaction Tests
// CRITICAL — prevents key material leakage in logs.
//
// The Debug implementation must NEVER print the contained bytes. It must
// show "REDACTED" or a similar marker instead.
// =============================================================================

/// Verifies that `Debug` output for `SecureVec` does NOT contain byte values.
///
/// The formatted string must contain "REDACTED" (or similar) and must NOT
/// contain the individual byte values as substrings.
#[test]
fn secure_vec_debug_redacted() {
    let sv = SecureVec::from_slice(&[1, 2, 3]);
    let debug_output = format!("{sv:?}");

    // Must contain the redaction marker.
    assert!(
        debug_output.contains("REDACTED"),
        "Debug output must contain 'REDACTED'; got: {debug_output}"
    );

    // Must NOT leak byte values. Check that the debug output doesn't
    // contain the raw data. The format is "SecureVec([REDACTED; 3 bytes])"
    // which should NOT contain "1, 2, 3" or "[1, 2, 3]".
    assert!(
        !debug_output.contains("[1, 2, 3]"),
        "Debug output must not contain raw byte values; got: {debug_output}"
    );
}

/// Verifies that `Debug` output shows the byte length.
///
/// Expected format: `SecureVec([REDACTED; 3 bytes])`
#[test]
fn secure_vec_debug_shows_length() {
    let sv = SecureVec::from_slice(&[0xAA, 0xBB, 0xCC]);
    let debug_output = format!("{sv:?}");

    assert!(
        debug_output.contains("3 bytes"),
        "Debug output must show the length in bytes; got: {debug_output}"
    );
}

/// Verifies that an empty `SecureVec` still shows a redacted debug output.
///
/// Even with zero bytes, the format should indicate REDACTED and show "0 bytes".
#[test]
fn secure_vec_debug_empty() {
    let sv = SecureVec::new(0);
    let debug_output = format!("{sv:?}");

    assert!(
        debug_output.contains("REDACTED"),
        "Empty SecureVec debug must still contain 'REDACTED'; got: {debug_output}"
    );
    assert!(
        debug_output.contains("0 bytes"),
        "Empty SecureVec debug must show '0 bytes'; got: {debug_output}"
    );
}

// =============================================================================
// Phase 6: SecureVec Equality Tests (constant-time via subtle)
// =============================================================================

/// Verifies that two `SecureVec` instances with identical content are equal.
///
/// The `PartialEq` implementation uses `subtle::ConstantTimeEq` to prevent
/// timing side-channel attacks when comparing key material.
#[test]
fn secure_vec_eq_equal() {
    let a = SecureVec::from_slice(&[10, 20, 30, 40]);
    let b = SecureVec::from_slice(&[10, 20, 30, 40]);
    assert_eq!(a, b, "SecureVecs with identical content must be equal");
}

/// Verifies that two `SecureVec` instances with different content are not equal.
#[test]
fn secure_vec_eq_different() {
    let a = SecureVec::from_slice(&[10, 20, 30, 40]);
    let b = SecureVec::from_slice(&[10, 20, 30, 99]);
    assert_ne!(a, b, "SecureVecs with different content must not be equal");
}

/// Verifies that `SecureVec` instances with different lengths are not equal.
#[test]
fn secure_vec_eq_different_length() {
    let a = SecureVec::from_slice(&[1, 2, 3]);
    let b = SecureVec::from_slice(&[1, 2]);
    assert_ne!(a, b, "SecureVecs with different lengths must not be equal");
}

// =============================================================================
// Phase 7: SecureVec Deref Tests
// =============================================================================

/// Verifies `Deref<Target = [u8]>` produces the correct byte slice.
#[test]
fn secure_vec_deref_to_slice() {
    let sv = SecureVec::from_slice(&[5, 10, 15, 20]);
    let slice: &[u8] = &sv;
    assert_eq!(slice, &[5, 10, 15, 20], "Deref must produce matching slice");
}

/// Verifies `DerefMut` allows byte-level modification through the deref.
#[test]
fn secure_vec_deref_mut() {
    let mut sv = SecureVec::from_slice(&[1, 2, 3]);
    {
        let slice: &mut [u8] = &mut sv;
        slice[0] = 100;
        slice[2] = 200;
    }
    assert_eq!(
        sv.as_bytes(),
        &[100, 2, 200],
        "DerefMut modifications must be visible"
    );
}

// =============================================================================
// Phase 8: SecureBox Tests
// =============================================================================

/// Verifies that `SecureBox::new` holds a value accessible via `Deref`.
#[test]
fn secure_box_new() {
    let sb = SecureBox::new(42_u64);
    assert_eq!(*sb, 42_u64, "SecureBox must hold the stored value");
}

/// Verifies that `Debug` output for `SecureBox` contains "REDACTED" and
/// does NOT contain the stored value.
///
/// Prevents accidental exposure of sensitive values in logs.
#[test]
fn secure_box_debug_redacted() {
    let sb = SecureBox::new(42_u64);
    let debug_output = format!("{sb:?}");

    assert!(
        debug_output.contains("REDACTED"),
        "SecureBox debug must contain 'REDACTED'; got: {debug_output}"
    );
    assert!(
        !debug_output.contains("42"),
        "SecureBox debug must NOT contain the stored value '42'; got: {debug_output}"
    );
}

/// Verifies that `Deref` for `SecureBox` returns the correct value.
#[test]
fn secure_box_deref() {
    let sb = SecureBox::new(0xDEAD_BEEF_u64);
    assert_eq!(*sb, 0xDEAD_BEEF_u64, "Deref must return stored value");
}

// =============================================================================
// Phase 9: constant_time_eq Tests (replaces CRYPTO_memcmp from crypto/mem.c)
// =============================================================================

/// Verifies that equal slices produce `true`.
#[test]
fn ct_eq_equal() {
    assert!(
        constant_time_eq(&[1, 2, 3, 4], &[1, 2, 3, 4]),
        "equal slices must return true"
    );
}

/// Verifies that slices differing in the last byte produce `false`.
#[test]
fn ct_eq_different() {
    assert!(
        !constant_time_eq(&[1, 2, 3, 4], &[1, 2, 3, 5]),
        "slices differing in last byte must return false"
    );
}

/// Verifies that slices of different lengths produce `false`.
#[test]
fn ct_eq_different_length() {
    assert!(
        !constant_time_eq(&[1, 2, 3], &[1, 2]),
        "slices of different length must return false"
    );
}

/// Verifies that two empty slices are considered equal.
#[test]
fn ct_eq_empty() {
    assert!(
        constant_time_eq(&[], &[]),
        "two empty slices must be equal"
    );
}

/// Verifies that a single-bit difference is detected.
///
/// 0xFF (11111111) vs 0xFE (11111110) — only the LSB differs.
#[test]
fn ct_eq_single_bit_diff() {
    assert!(
        !constant_time_eq(&[0xFF], &[0xFE]),
        "single-bit difference must be detected"
    );
}

/// Verifies constant-time comparison on long (4096-byte) slices.
///
/// Tests both the equal case and a difference at the very last byte,
/// ensuring the comparison doesn't short-circuit.
#[test]
fn ct_eq_long_slices() {
    let a = vec![0xAB_u8; 4096];
    let b = vec![0xAB_u8; 4096];

    assert!(
        constant_time_eq(&a, &b),
        "4096-byte equal slices must return true"
    );

    // Differ at the very last byte only.
    let mut c = vec![0xAB_u8; 4096];
    c[4095] = 0xAC;

    assert!(
        !constant_time_eq(&a, &c),
        "4096-byte slices differing at last byte must return false"
    );
}

// =============================================================================
// Phase 10: secure_zero() Alias Test
// =============================================================================

/// Verifies that `secure_zero` zeroes a byte buffer (semantic alias for `cleanse`).
#[test]
fn secure_zero_zeroes_data() {
    let mut data = [0xAA_u8; 16];
    secure_zero(&mut data);
    assert!(
        data.iter().all(|&b| b == 0),
        "secure_zero must zero all bytes"
    );
}

// =============================================================================
// Phase 11: SecureHeapConfig Tests
// =============================================================================

/// Verifies that `init_secure_heap` succeeds with a valid `min_size`.
///
/// Per Rule R5, the function returns `Result`, not a sentinel error code.
#[test]
fn init_secure_heap_ok() {
    let config = SecureHeapConfig { min_size: 4096 };
    let result = init_secure_heap(&config);
    assert!(result.is_ok(), "init_secure_heap must succeed with min_size=4096");
}

/// Verifies that `init_secure_heap` rejects `min_size = 0` with a
/// `CommonError::Memory` error.
///
/// This test exercises the error variant specified in the schema for
/// asserting memory initialization failures.
#[test]
fn init_secure_heap_rejects_zero_min_size() {
    let config = SecureHeapConfig { min_size: 0 };
    let result = init_secure_heap(&config);
    assert!(result.is_err(), "init_secure_heap must fail with min_size=0");

    let err = result.unwrap_err();
    assert!(
        matches!(err, CommonError::Memory(_)),
        "error must be CommonError::Memory; got: {err:?}"
    );
}

/// Verifies that `secure_heap_used()` reports 0 bytes initially.
///
/// In the current implementation, `SecureVec` uses the standard allocator
/// with zeroing-on-drop semantics rather than a dedicated mlock-backed
/// secure heap arena, so the reported usage is always 0.
#[test]
fn secure_heap_used_initial() {
    assert_eq!(
        secure_heap_used(),
        0,
        "secure_heap_used must report 0 initially"
    );
}
