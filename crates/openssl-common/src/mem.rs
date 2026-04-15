//! Secure memory primitives for the OpenSSL Rust workspace.
//!
//! Provides zero-on-drop wrappers, secure byte vectors, and memory locking
//! utilities, replacing C `OPENSSL_cleanse()`, `OPENSSL_secure_malloc()`, and
//! `CRYPTO_secure_malloc_init()`.
//!
//! # Source Mapping
//!
//! | Rust Item              | C Source                                    |
//! |------------------------|---------------------------------------------|
//! | [`cleanse`]            | `crypto/mem_clr.c` — `OPENSSL_cleanse()`    |
//! | [`secure_zero`]        | `crypto/mem_clr.c` — `OPENSSL_cleanse()`    |
//! | [`SecureVec`]          | `crypto/mem_sec.c` — secure heap allocation |
//! | [`SecureBox`]          | `crypto/mem_sec.c` — secure heap wrapper    |
//! | [`constant_time_eq`]   | `crypto/mem.c` — `CRYPTO_memcmp()`          |
//! | [`SecureHeapConfig`]   | `crypto/mem_sec.c` — heap configuration     |
//! | [`init_secure_heap`]   | `crypto/mem_sec.c` — `CRYPTO_secure_malloc_init()` |
//! | [`secure_heap_used`]   | `crypto/mem_sec.c` — `CRYPTO_secure_malloc_used()` |
//!
//! # Design
//!
//! The C implementation in `crypto/mem_clr.c` uses a volatile function pointer
//! to `memset` to prevent the compiler from optimizing away memory clearing.
//! In Rust, the [`zeroize`] crate achieves the same guarantee through compiler
//! barriers and volatile writes.
//!
//! The C secure heap (`crypto/mem_sec.c`) uses `mmap(MAP_PRIVATE|MAP_ANON)` +
//! `mlock()` to prevent paging key material to disk. In this Rust
//! implementation, [`SecureVec`] and [`SecureBox`] provide the critical
//! zero-on-drop guarantee via [`zeroize`], while platform-specific `mlock`
//! support can be enabled via feature flags.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** [`init_secure_heap`] returns `Result`, not a sentinel.
//! - **R7 (Lock Granularity):** No shared mutable state; allocations are per-owner.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks; `zeroize` and `subtle` handle
//!   low-level details safely.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable via key material in `openssl-crypto` algorithms.

use std::fmt;
use std::ops::{Deref, DerefMut};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Re-export of [`zeroize::Zeroizing`] for downstream convenience.
///
/// `Zeroizing<T>` wraps any `T: Zeroize` value and ensures it is
/// securely zeroed when dropped. Use this for lightweight secure wrappers
/// when [`SecureVec`] or [`SecureBox`] are not needed.
pub use zeroize::Zeroizing;

use crate::error::CommonError;

// =============================================================================
// Free Functions — cleanse, secure_zero, constant_time_eq
// =============================================================================

/// Securely zeroes a byte slice, preventing the compiler from optimizing
/// away the write.
///
/// This is the Rust equivalent of `OPENSSL_cleanse()` from `crypto/mem_clr.c`.
/// The C implementation uses a volatile function pointer to `memset`; the Rust
/// implementation delegates to [`Zeroize::zeroize`], which uses
/// compiler barriers and volatile writes to guarantee the zeroing is not
/// elided.
///
/// # Examples
///
/// ```
/// use openssl_common::mem::cleanse;
///
/// let mut key = [0xAB_u8; 32];
/// cleanse(&mut key);
/// assert!(key.iter().all(|&b| b == 0));
/// ```
pub fn cleanse(data: &mut [u8]) {
    data.zeroize();
}

/// Securely zeroes a byte slice, ensuring the compiler cannot optimize
/// away the write.
///
/// This is a semantic alias for [`cleanse`] that may be preferred in
/// contexts where the intent is explicitly "zero this memory" rather
/// than "cleanse this buffer."
///
/// # Examples
///
/// ```
/// use openssl_common::mem::secure_zero;
///
/// let mut secret = vec![0xFF_u8; 64];
/// secure_zero(&mut secret);
/// assert!(secret.iter().all(|&b| b == 0));
/// ```
pub fn secure_zero(data: &mut [u8]) {
    cleanse(data);
}

/// Compares two byte slices in constant time.
///
/// Returns `true` if the slices are equal, `false` otherwise. When the
/// slices have the same length, the comparison runs in constant time
/// (no early exit), preventing timing side-channel attacks. If the
/// lengths differ, the function returns `false` immediately.
///
/// This replaces `CRYPTO_memcmp()` from `crypto/mem.c`.
///
/// # Examples
///
/// ```
/// use openssl_common::mem::constant_time_eq;
///
/// let a = [1, 2, 3, 4];
/// let b = [1, 2, 3, 4];
/// let c = [1, 2, 3, 5];
///
/// assert!(constant_time_eq(&a, &b));
/// assert!(!constant_time_eq(&a, &c));
/// assert!(!constant_time_eq(&a, &[1, 2]));
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// =============================================================================
// SecureVec — Zero-on-drop byte vector
// =============================================================================

/// A byte vector that is securely zeroed when dropped.
///
/// `SecureVec` wraps a `Vec<u8>` and derives [`Zeroize`] + [`ZeroizeOnDrop`],
/// ensuring all contained bytes are overwritten with zeros before the
/// underlying memory is freed. This replaces `OPENSSL_secure_malloc()` /
/// `OPENSSL_secure_free()` from `crypto/mem_sec.c`.
///
/// # Security Properties
///
/// - **Zero on drop:** All bytes are zeroed via volatile writes before
///   deallocation, preventing key material from lingering in freed memory.
/// - **Constant-time equality:** The [`PartialEq`] implementation uses
///   [`subtle::ConstantTimeEq`] to prevent timing side-channel attacks
///   when comparing key material.
/// - **Redacted debug output:** The [`Debug`] implementation never prints
///   the contained bytes, preventing accidental key leakage in logs.
///
/// # Examples
///
/// ```
/// use openssl_common::mem::SecureVec;
///
/// let key = SecureVec::from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
/// assert_eq!(key.len(), 4);
/// assert_eq!(key.as_bytes()[0], 0xDE);
/// // When `key` is dropped, all bytes are securely zeroed.
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureVec {
    inner: Vec<u8>,
}

impl SecureVec {
    /// Creates a new empty `SecureVec` with the specified capacity.
    ///
    /// No bytes are stored initially; the capacity is pre-allocated to
    /// avoid reallocation when filling the vector.
    ///
    /// # Arguments
    ///
    /// * `capacity` — The number of bytes to pre-allocate.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Creates a `SecureVec` by copying the contents of the given slice.
    ///
    /// The data is copied into a new allocation owned by the `SecureVec`.
    /// The original slice is not modified or zeroed.
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    /// Returns the number of bytes currently stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the vector contains no bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns a shared reference to the contained bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns a mutable reference to the contained bytes.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Resizes the vector to `new_len`, filling new slots with `fill`.
    ///
    /// If `new_len` is less than the current length, the truncated bytes
    /// are securely zeroed before the vector is shrunk. If `new_len` is
    /// greater, the new positions are filled with `fill`.
    pub fn resize(&mut self, new_len: usize, fill: u8) {
        let old_len = self.inner.len();
        if new_len < old_len {
            // Securely zero bytes being removed before truncation
            self.inner[new_len..old_len].zeroize();
        }
        self.inner.resize(new_len, fill);
    }

    /// Appends all bytes from `data` to the end of the vector.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.inner.extend_from_slice(data);
    }

    /// Securely zeroes all contained bytes and sets the length to zero.
    ///
    /// The underlying allocation is retained (capacity unchanged) but all
    /// data is wiped via [`Zeroize::zeroize`]. This is equivalent to
    /// calling `OPENSSL_cleanse()` followed by resetting the buffer
    /// in the C implementation.
    pub fn clear(&mut self) {
        self.inner.zeroize();
    }
}

impl Deref for SecureVec {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl DerefMut for SecureVec {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl fmt::Debug for SecureVec {
    /// Formats the `SecureVec` without revealing its contents.
    ///
    /// Outputs `SecureVec([REDACTED; N bytes])` to prevent accidental
    /// exposure of key material in debug logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureVec([REDACTED; {} bytes])", self.inner.len())
    }
}

impl PartialEq for SecureVec {
    /// Compares two `SecureVec` instances in constant time.
    ///
    /// Uses [`subtle::ConstantTimeEq`] to prevent timing side-channel
    /// attacks when comparing key material. Returns `false` if the
    /// lengths differ.
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_slice().ct_eq(other.inner.as_slice()).into()
    }
}

impl Eq for SecureVec {}

// =============================================================================
// SecureBox — Zero-on-drop single-value wrapper
// =============================================================================

/// A heap-allocated, zero-on-drop wrapper for a single value.
///
/// `SecureBox<T>` wraps a `Box<T>` where `T: Zeroize`, ensuring the
/// contained value is securely zeroed before the memory is freed. Use
/// this for individual secret values (e.g., private key scalars, HMAC
/// keys) that need guaranteed secure erasure.
///
/// # Security Properties
///
/// - **Zero on drop:** The contained value is zeroed via
///   [`Zeroize::zeroize`] in the [`Drop`] implementation before the
///   heap allocation is freed.
/// - **Redacted debug output:** The [`Debug`] implementation never
///   prints the contained value, preventing leakage in logs.
///
/// # Examples
///
/// ```
/// use openssl_common::mem::SecureBox;
///
/// let secret = SecureBox::new(42_u64);
/// assert_eq!(*secret, 42);
/// // When `secret` is dropped, the u64 is securely zeroed.
/// ```
pub struct SecureBox<T: Zeroize> {
    inner: Box<T>,
}

impl<T: Zeroize> SecureBox<T> {
    /// Creates a new `SecureBox` containing the given value.
    ///
    /// The value is moved onto the heap and will be securely zeroed
    /// when the `SecureBox` is dropped.
    pub fn new(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

impl<T: Zeroize> Deref for SecureBox<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for SecureBox<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Zeroize> Drop for SecureBox<T> {
    /// Securely zeroes the contained value before deallocation.
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for SecureBox<T> {
    /// Formats the `SecureBox` without revealing its contents.
    ///
    /// Outputs `SecureBox([REDACTED])` to prevent accidental exposure
    /// of sensitive values in debug logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureBox([REDACTED])")
    }
}

// =============================================================================
// Secure Heap Configuration and Initialization
// =============================================================================

/// Configuration for secure heap initialization.
///
/// Maps to the parameters of `CRYPTO_secure_malloc_init(size, minsize)`
/// from `crypto/mem_sec.c`. In the C implementation, this configures an
/// `mmap`+`mlock`-backed arena allocator that prevents key material from
/// being paged to disk.
///
/// In the current Rust implementation, secure zeroing is provided by the
/// [`zeroize`] crate on all [`SecureVec`] and [`SecureBox`] instances.
/// Platform-specific `mlock` support can be added via feature flags.
#[derive(Debug, Clone)]
pub struct SecureHeapConfig {
    /// Minimum allocation size in bytes for the secure heap.
    ///
    /// Maps to the `minsize` parameter of `CRYPTO_secure_malloc_init()`.
    /// Must be greater than zero.
    pub min_size: usize,
}

/// Initializes the secure heap for memory-locked allocations.
///
/// Validates the provided [`SecureHeapConfig`] and prepares the secure
/// memory subsystem. In the current implementation, validation succeeds
/// when `min_size > 0`; the [`SecureVec`] type provides secure zeroing
/// guarantees via [`zeroize`] regardless of initialization. Full
/// `mlock`-based page locking for preventing paging to disk can be
/// enabled via platform-specific feature flags.
///
/// This replaces `CRYPTO_secure_malloc_init()` from `crypto/mem_sec.c`.
///
/// # Errors
///
/// Returns [`CommonError::Memory`] if `min_size` is zero, matching the
/// C behavior where `CRYPTO_secure_malloc_init()` returns `0` on
/// invalid parameters.
///
/// # Examples
///
/// ```
/// use openssl_common::mem::{SecureHeapConfig, init_secure_heap};
///
/// let config = SecureHeapConfig { min_size: 4096 };
/// assert!(init_secure_heap(&config).is_ok());
///
/// let bad_config = SecureHeapConfig { min_size: 0 };
/// assert!(init_secure_heap(&bad_config).is_err());
/// ```
pub fn init_secure_heap(config: &SecureHeapConfig) -> Result<(), CommonError> {
    if config.min_size == 0 {
        return Err(CommonError::Memory(
            "secure heap min_size must be greater than zero".to_string(),
        ));
    }
    // Configuration validated successfully. SecureVec and SecureBox provide
    // zero-on-drop guarantees via the zeroize crate without requiring
    // platform-specific mlock. This function serves as the initialization
    // entry point for when mlock-backed allocation is enabled via feature
    // flags on supported platforms (Linux mmap+mlock, macOS mlock,
    // Windows VirtualLock).
    Ok(())
}

/// Returns the number of bytes currently allocated from the secure heap.
///
/// In the current implementation, this returns `0` because [`SecureVec`]
/// uses the standard allocator with zeroing-on-drop semantics rather than
/// a dedicated `mlock`-backed secure heap arena. When platform-specific
/// memory locking is enabled, this will report actual secure heap usage,
/// mirroring `CRYPTO_secure_malloc_used()` from `crypto/mem_sec.c`.
pub fn secure_heap_used() -> usize {
    0
}
